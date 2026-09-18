# coding: utf-8

# Copyright (C) 2026 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

#
# NTLMSSP as it is used by SMB2, see MS-NLMP.
#
# The NTLM implementations that are packaged for python target NTLM over
# HTTP, where the session key is never used for anything, so they tend to
# hardcode the names they put in the CHALLENGE and to not give the caller
# the exported session key. SMB2 needs both: the names end up inside the
# NTLMv2 hash, and the exported session key is what the SMB2 signing and
# encryption keys are derived from. So we do it ourselves.
#

import hashlib
import hmac
import struct
import time

from smb2.timestamps import TimevalToWin

#
# Message types
#
NEGOTIATE_MESSAGE    = 0x00000001
CHALLENGE_MESSAGE    = 0x00000002
AUTHENTICATE_MESSAGE = 0x00000003

SIGNATURE = b'NTLMSSP\x00'

#
# Negotiate flags
#
NTLMSSP_NEGOTIATE_UNICODE                  = 0x00000001
NTLMSSP_NEGOTIATE_OEM                      = 0x00000002
NTLMSSP_REQUEST_TARGET                     = 0x00000004
NTLMSSP_NEGOTIATE_SIGN                     = 0x00000010
NTLMSSP_NEGOTIATE_SEAL                     = 0x00000020
NTLMSSP_NEGOTIATE_DATAGRAM                 = 0x00000040
NTLMSSP_NEGOTIATE_LM_KEY                   = 0x00000080
NTLMSSP_NEGOTIATE_NTLM                     = 0x00000200
NTLMSSP_NEGOTIATE_ANONYMOUS                = 0x00000800
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 0x00001000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN              = 0x00008000
NTLMSSP_TARGET_TYPE_DOMAIN                 = 0x00010000
NTLMSSP_TARGET_TYPE_SERVER                 = 0x00020000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_IDENTIFY                 = 0x00100000
NTLMSSP_REQUEST_NON_NT_SESSION_KEY         = 0x00400000
NTLMSSP_NEGOTIATE_TARGET_INFO              = 0x00800000
NTLMSSP_NEGOTIATE_VERSION                  = 0x02000000
NTLMSSP_NEGOTIATE_128                      = 0x20000000
NTLMSSP_NEGOTIATE_KEY_EXCH                 = 0x40000000
NTLMSSP_NEGOTIATE_56                       = 0x80000000

#
# AV pair ids for the TargetInfo field
#
MSV_AV_EOL              = 0x0000
MSV_AV_NB_COMPUTER_NAME = 0x0001
MSV_AV_NB_DOMAIN_NAME   = 0x0002
MSV_AV_DNS_COMPUTER_NAME = 0x0003
MSV_AV_DNS_DOMAIN_NAME  = 0x0004
MSV_AV_DNS_TREE_NAME    = 0x0005
MSV_AV_FLAGS            = 0x0006
MSV_AV_TIMESTAMP        = 0x0007
MSV_AV_SINGLE_HOST      = 0x0008
MSV_AV_TARGET_NAME      = 0x0009
MSV_AV_CHANNEL_BINDINGS = 0x000a

#
# MSV_AV_FLAGS bits
#
MSV_AV_FLAG_CONSTRAINED     = 0x00000001
MSV_AV_FLAG_MIC             = 0x00000002
MSV_AV_FLAG_UNTRUSTED_SPN   = 0x00000004


def MD4(data):
    """
    MD4 (RFC 1320). It is only still alive because NTLM uses it, so it is
    not in hashlib on a modern openssl and we have to bring our own.
    """
    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def rotl(x, n):
        x = x & 0xffffffff
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    msg = bytearray(data)
    bitlen = (len(data) * 8) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg = msg + struct.pack('<Q', bitlen)

    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    for off in range(0, len(msg), 64):
        X = struct.unpack_from('<16I', msg, off)
        a, b, c, d = h

        # Round 1
        for i in range(16):
            s = (3, 7, 11, 19)[i % 4]
            if i % 4 == 0:
                a = rotl(a + F(b, c, d) + X[i], s)
            elif i % 4 == 1:
                d = rotl(d + F(a, b, c) + X[i], s)
            elif i % 4 == 2:
                c = rotl(c + F(d, a, b) + X[i], s)
            else:
                b = rotl(b + F(c, d, a) + X[i], s)

        # Round 2
        for i in range(16):
            k = (i // 4) + 4 * (i % 4)
            s = (3, 5, 9, 13)[i % 4]
            if i % 4 == 0:
                a = rotl(a + G(b, c, d) + X[k] + 0x5a827999, s)
            elif i % 4 == 1:
                d = rotl(d + G(a, b, c) + X[k] + 0x5a827999, s)
            elif i % 4 == 2:
                c = rotl(c + G(d, a, b) + X[k] + 0x5a827999, s)
            else:
                b = rotl(b + G(c, d, a) + X[k] + 0x5a827999, s)

        # Round 3
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in range(16):
            k = order[i]
            s = (3, 9, 11, 15)[i % 4]
            if i % 4 == 0:
                a = rotl(a + H(b, c, d) + X[k] + 0x6ed9eba1, s)
            elif i % 4 == 1:
                d = rotl(d + H(a, b, c) + X[k] + 0x6ed9eba1, s)
            elif i % 4 == 2:
                c = rotl(c + H(d, a, b) + X[k] + 0x6ed9eba1, s)
            else:
                b = rotl(b + H(c, d, a) + X[k] + 0x6ed9eba1, s)

        h = [(h[0] + a) & 0xffffffff, (h[1] + b) & 0xffffffff,
             (h[2] + c) & 0xffffffff, (h[3] + d) & 0xffffffff]

    return struct.pack('<4I', *h)


def RC4(key, data):
    """
    RC4, used to unwrap the exported session key. Same reason as MD4, it is
    not something a current crypto library wants to offer any more.
    """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]

    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out[n] = data[n] ^ S[(S[i] + S[j]) & 0xff]
    return bytes(out)


def NTOWFv1(password):
    """
    The NT hash of the password.
    """
    return MD4(password.encode('utf-16-le'))


def NTOWFv2(password, user, domain):
    """
    The NTLMv2 hash. Note that the user is uppercased but the domain is
    not, and that both of them are part of the hash, which is why the
    server and the client have to agree on the exact spelling of the
    domain we put in the CHALLENGE.
    """
    key = NTOWFv1(password)
    return hmac.new(key,
                    (user.upper() + domain).encode('utf-16-le'),
                    hashlib.md5).digest()


def encode_av_pairs(pairs):
    """
    Encode a list of (av_id, value) into a TargetInfo blob. Text values are
    encoded as UTF-16, everything else is passed through as bytes.
    """
    buf = bytearray(0)
    for av_id, value in pairs:
        if isinstance(value, str):
            value = value.encode('utf-16-le')
        buf = buf + struct.pack('<HH', av_id, len(value)) + value
    return bytes(buf + struct.pack('<HH', MSV_AV_EOL, 0))


def decode_av_pairs(buf):
    """
    Decode a TargetInfo blob into a dict of av_id -> bytes.
    """
    pairs = {}
    offset = 0
    while offset + 4 <= len(buf):
        av_id, av_len = struct.unpack_from('<HH', buf, offset)
        offset = offset + 4
        if av_id == MSV_AV_EOL:
            break
        pairs.update({av_id: bytes(buf[offset:offset + av_len])})
        offset = offset + av_len
    return pairs


def _field(buf, offset):
    """
    Read a len/maxlen/offset field and return the data it points at.
    """
    _len, _maxlen, _off = struct.unpack_from('<HHI', buf, offset)
    if _len == 0:
        return b''
    return bytes(buf[_off:_off + _len])


def _add_field(buf, offset, payload, data):
    """
    Append data to payload and point the field at offset at it.
    """
    struct.pack_into('<HHI', buf, offset,
                     len(data), len(data), len(buf) + len(payload))
    return payload + data


def decode_negotiate(buf):
    """
    Decode a NTLMSSP NEGOTIATE message
    """
    result = {'message_type': NEGOTIATE_MESSAGE}
    result.update({'negotiate_flags': struct.unpack_from('<I', buf, 12)[0]})
    if len(buf) >= 24:
        result.update({'domain': _field(buf, 16)})
    if len(buf) >= 32:
        result.update({'workstation': _field(buf, 24)})
    return result


def encode_challenge(msg):
    """
    Encode a NTLMSSP CHALLENGE message
    """
    buf = bytearray(48)
    buf[0:8] = SIGNATURE
    struct.pack_into('<I', buf, 8, CHALLENGE_MESSAGE)
    struct.pack_into('<I', buf, 20, msg['negotiate_flags'])
    buf[24:32] = msg['server_challenge']

    payload = b''
    payload = _add_field(buf, 12, payload,
                         msg['target_name'].encode('utf-16-le'))
    payload = _add_field(buf, 40, payload, msg['target_info'])

    return bytes(buf + payload)


def decode_authenticate(buf):
    """
    Decode a NTLMSSP AUTHENTICATE message
    """
    result = {'message_type': AUTHENTICATE_MESSAGE}
    result.update({'lm_challenge_response': _field(buf, 12)})
    result.update({'nt_challenge_response': _field(buf, 20)})
    result.update({'domain': _field(buf, 28).decode('utf-16-le')})
    result.update({'user': _field(buf, 36).decode('utf-16-le')})
    result.update({'workstation': _field(buf, 44).decode('utf-16-le')})
    result.update({'session_key': _field(buf, 52)})
    result.update({'negotiate_flags': struct.unpack_from('<I', buf, 60)[0]})

    #
    # The MIC is only there if the payload starts far enough into the
    # message to leave room for it.
    #
    _first = len(buf)
    for _o in (12, 20, 28, 36, 44, 52):
        _len, _maxlen, _off = struct.unpack_from('<HHI', buf, _o)
        if _len:
            _first = min(_first, _off)
    if _first >= 88:
        result.update({'mic': bytes(buf[72:88])})

    return result


def decode(buf):
    """
    Decode any NTLMSSP message
    """
    if len(buf) < 12 or bytes(buf[0:8]) != SIGNATURE:
        raise ValueError('Not a NTLMSSP message')
    cmd = struct.unpack_from('<I', buf, 8)[0]
    if cmd == NEGOTIATE_MESSAGE:
        return decode_negotiate(buf)
    if cmd == AUTHENTICATE_MESSAGE:
        return decode_authenticate(buf)
    raise ValueError('Can not decode NTLMSSP message %d' % cmd)


def make_target_info(server_name, domain_name):
    """
    The TargetInfo we offer in the CHALLENGE. The client copies these AV
    pairs back into its NTLMv2 response, so they are covered by the hash.
    """
    return encode_av_pairs([
        (MSV_AV_NB_DOMAIN_NAME, domain_name),
        (MSV_AV_NB_COMPUTER_NAME, server_name),
        (MSV_AV_DNS_DOMAIN_NAME, domain_name),
        (MSV_AV_DNS_COMPUTER_NAME, server_name),
        (MSV_AV_TIMESTAMP, struct.pack('<Q', TimevalToWin((int(time.time()), 0, 0)))),
        ])


def verify_ntlmv2(password, auth, server_challenge):
    """
    Verify the NTLMv2 response in an AUTHENTICATE message and return the
    session base key, or None if the response does not match.

    See MS-NLMP 3.3.2. temp is the blob the client appended after the
    NTProofStr, and is fed back into the hash as-is, so we never have to
    agree with the client on how it built it.
    """
    nt = auth['nt_challenge_response']
    if len(nt) < 24:
        return None

    nt_hash = NTOWFv2(password, auth['user'], auth['domain'])

    proof = nt[:16]
    temp = nt[16:]
    expected = hmac.new(nt_hash, server_challenge + temp, hashlib.md5).digest()
    if not hmac.compare_digest(proof, expected):
        return None

    return hmac.new(nt_hash, proof, hashlib.md5).digest()


def exported_session_key(session_base_key, auth):
    """
    Unwrap the session key the client generated, if it sent one. This is
    the key SMB2 derives its signing and encryption keys from.
    """
    flags = auth['negotiate_flags']
    if flags & NTLMSSP_NEGOTIATE_KEY_EXCH and \
       flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL):
        return RC4(session_base_key, auth['session_key'])
    return session_base_key


def compute_mic(session_key, negotiate, challenge, authenticate):
    """
    The MIC covers all three messages, with the MIC field in the
    AUTHENTICATE message zeroed out.
    """
    buf = bytearray(authenticate)
    buf[72:88] = bytes(16)
    return hmac.new(session_key,
                    bytes(negotiate) + bytes(challenge) + bytes(buf),
                    hashlib.md5).digest()


def has_mic(auth):
    """
    Did the client say it computed a MIC?
    """
    nt = auth['nt_challenge_response']
    if len(nt) <= 44 or 'mic' not in auth:
        return False
    pairs = decode_av_pairs(nt[44:])
    if MSV_AV_FLAGS not in pairs:
        return False
    return struct.unpack_from('<I', pairs[MSV_AV_FLAGS], 0)[0] & MSV_AV_FLAG_MIC != 0
