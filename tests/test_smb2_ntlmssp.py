#!/usr/bin/env python
# coding: utf-8

#
# The vectors are the NTLMv2 ones from MS-NLMP 4.2.4.
#

import struct

from smb2.ntlmssp import *

password = 'Password'
user = 'User'
domain = 'Domain'

# 4.2.1 Common values
server_challenge = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])

# 4.2.4.1.1 NTOWFv2
ntowfv2 = bytes([
    0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93,
    0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f
])

# 4.2.4.1.2 Session Base Key
session_base_key = bytes([
    0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82,
    0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3
])

# 4.2.4.2.2 NTLMv2 Response
nt_challenge_response = bytes([
    0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96,
    0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00,
    0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
    0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00,
    0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
    0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

# 4.2.4.2.3 Encrypted Session Key, and the key it unwraps to
encrypted_session_key = bytes([
    0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90,
    0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e
])
exported = bytes([0x55] * 16)

# RFC 1320 A.5
md4_vectors = [
    (b'', '31d6cfe0d16ae931b73c59d7e0c089c0'),
    (b'a', 'bde52cb31de33e46245e05fbdbd6fb24'),
    (b'abc', 'a448017aaf21d8525fc10ae87aa6729d'),
    (b'message digest', 'd9130a8164549fe818874806e1c7014b'),
    (b'abcdefghijklmnopqrstuvwxyz', 'd79e1c308aa5bbcdeea8ed63df412da9'),
    (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
     '043f8582f241db351ce627e153e7f0e4'),
    (b'1234567890' * 8, 'e33b4ddc9c38f2199c3e7b164fcc0536'),
]


def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()


def check(name, got, expected):
    if got != expected:
        print(name, 'mismatch')
        print('Expected:')
        pr(expected)
        print('Got:')
        pr(got)
        exit(1)


def main():
    print('MD4 against the RFC 1320 test suite')
    for data, digest in md4_vectors:
        check('MD4', MD4(data), bytes.fromhex(digest))

    print('RC4 against the RFC 6229 128 bit key vector')
    #
    # key 0102030405060708090a0b0c0d0e0f10, first 16 bytes of the stream
    #
    check('RC4',
          RC4(bytes.fromhex('0102030405060708090a0b0c0d0e0f10'), bytes(16)),
          bytes.fromhex('9ac7cc9a609d1ef7b2932899cde41b97'))

    print('NTOWFv2')
    check('NTOWFv2', NTOWFv2(password, user, domain), ntowfv2)

    print('Verify the NTLMv2 response')
    auth = {
        'user': user,
        'domain': domain,
        'nt_challenge_response': nt_challenge_response,
        'session_key': encrypted_session_key,
        'negotiate_flags': NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_SIGN,
        }
    key = verify_ntlmv2(password, auth, server_challenge)
    if key is None:
        print('NTLMv2 response did not verify')
        exit(1)
    check('Session base key', key, session_base_key)

    print('Unwrap the exported session key')
    check('Exported session key', exported_session_key(key, auth), exported)

    print('A bad password must not verify')
    if verify_ntlmv2('Passw0rd', auth, server_challenge) is not None:
        print('A bad password verified')
        exit(1)

    print('A tampered response must not verify')
    bad = dict(auth)
    bad.update({'nt_challenge_response':
                bytes([nt_challenge_response[0] ^ 0xff]) +
                nt_challenge_response[1:]})
    if verify_ntlmv2(password, bad, server_challenge) is not None:
        print('A tampered response verified')
        exit(1)

    print('Without key exchange the base key is used as it is')
    nokx = dict(auth)
    nokx.update({'negotiate_flags': NTLMSSP_NEGOTIATE_SIGN})
    check('Exported session key', exported_session_key(key, nokx), key)

    print('AV pairs round trip')
    pairs = [(MSV_AV_NB_DOMAIN_NAME, 'Domain'),
             (MSV_AV_NB_COMPUTER_NAME, 'Server')]
    encoded = encode_av_pairs(pairs)
    check('AV pairs', encoded, nt_challenge_response[44:-4])
    decoded = decode_av_pairs(encoded)
    for av_id, value in pairs:
        check('AV pair %d' % av_id, decoded[av_id], value.encode('utf-16-le'))

    print('CHALLENGE round trips through the decoder')
    challenge = encode_challenge({
            'negotiate_flags': NTLMSSP_NEGOTIATE_UNICODE |
                               NTLMSSP_NEGOTIATE_TARGET_INFO,
            'server_challenge': server_challenge,
            'target_name': 'Server',
            'target_info': encoded,
            })
    if challenge[0:8] != SIGNATURE:
        print('CHALLENGE has no NTLMSSP signature')
        exit(1)
    if struct.unpack_from('<I', challenge, 8)[0] != CHALLENGE_MESSAGE:
        print('CHALLENGE has the wrong message type')
        exit(1)
    check('Server challenge', challenge[24:32], server_challenge)
    _len, _maxlen, _off = struct.unpack_from('<HHI', challenge, 12)
    check('Target name', challenge[_off:_off + _len], 'Server'.encode('utf-16-le'))
    _len, _maxlen, _off = struct.unpack_from('<HHI', challenge, 40)
    check('Target info', challenge[_off:_off + _len], encoded)

    print('AUTHENTICATE decodes, with and without a MIC')
    for with_mic in (False, True):
        payload_start = 88 if with_mic else 64
        buf = bytearray(payload_start)
        buf[0:8] = SIGNATURE
        struct.pack_into('<I', buf, 8, AUTHENTICATE_MESSAGE)
        struct.pack_into('<I', buf, 60, NTLMSSP_NEGOTIATE_KEY_EXCH)
        payload = b''
        for offset, value in ((20, nt_challenge_response),
                              (28, domain.encode('utf-16-le')),
                              (36, user.encode('utf-16-le')),
                              (44, 'Client'.encode('utf-16-le')),
                              (52, encrypted_session_key)):
            struct.pack_into('<HHI', buf, offset, len(value), len(value),
                             payload_start + len(payload))
            payload = payload + value
        if with_mic:
            buf[72:88] = bytes(range(16))

        auth = decode(bytes(buf) + payload)
        if auth['message_type'] != AUTHENTICATE_MESSAGE:
            print('Wrong message type')
            exit(1)
        if auth['user'] != user or auth['domain'] != domain:
            print('Wrong user or domain:', auth['user'], auth['domain'])
            exit(1)
        if auth['workstation'] != 'Client':
            print('Wrong workstation:', auth['workstation'])
            exit(1)
        check('NT response', auth['nt_challenge_response'],
              nt_challenge_response)
        check('Encrypted session key', auth['session_key'],
              encrypted_session_key)
        if with_mic:
            check('MIC', auth['mic'], bytes(range(16)))
        elif 'mic' in auth:
            print('Found a MIC in a message that has no room for one')
            exit(1)
        #
        # The response carries no MSV_AV_FLAGS, so no MIC is claimed even
        # when there is room for one in the message.
        #
        if has_mic(auth):
            print('has_mic() is true without MSV_AV_FLAGS')
            exit(1)

    print('All tests passed')

if __name__ == "__main__":
    main()
