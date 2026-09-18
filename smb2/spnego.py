# coding: utf-8

# Copyright (C) 2026 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

#
# Just enough SPNEGO (RFC 4178) to carry NTLMSSP tokens in SMB2 session
# setup. Clients either send us raw NTLMSSP tokens or wrap them in SPNEGO
# depending on what we advertised in the negotiate reply, so we need to be
# able to do both.
#

import struct

SPNEGO_OID  = '1.3.6.1.5.5.2'
NTLMSSP_OID = '1.3.6.1.4.1.311.2.2.10'

#
# negState
#
ACCEPT_COMPLETE   = 0
ACCEPT_INCOMPLETE = 1
REJECT            = 2
REQUEST_MIC       = 3

#
# DER
#
def _encode_length(length):
    if length < 0x80:
        return bytes([length])
    _b = b''
    while length:
        _b = bytes([length & 0xff]) + _b
        length = length >> 8
    return bytes([0x80 | len(_b)]) + _b


def _encode_tlv(tag, value):
    return bytes([tag]) + _encode_length(len(value)) + value


def _decode_tlv(buf, offset):
    """
    Return (tag, value, offset of the next tlv)
    """
    tag = buf[offset]
    length = buf[offset + 1]
    offset = offset + 2
    if length & 0x80:
        _n = length & 0x7f
        length = 0
        for _i in range(_n):
            length = (length << 8) | buf[offset + _i]
        offset = offset + _n
    return tag, bytes(buf[offset:offset + length]), offset + length


def _encode_oid(oid):
    parts = [int(x) for x in oid.split('.')]
    buf = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        _b = bytes([part & 0x7f])
        part = part >> 7
        while part:
            _b = bytes([(part & 0x7f) | 0x80]) + _b
            part = part >> 7
        buf = buf + _b
    return _encode_tlv(0x06, buf)


def _decode_oid(buf):
    parts = [str(buf[0] // 40), str(buf[0] % 40)]
    value = 0
    for _b in buf[1:]:
        value = (value << 7) | (_b & 0x7f)
        if not _b & 0x80:
            parts.append(str(value))
            value = 0
    return '.'.join(parts)


#
# What windows puts in negHints, and what everyone else copies.
#
NEG_HINTS = 'not_defined_in_RFC4178@please_ignore'


def encode_neg_token_init(mechs, mech_token=None, neg_hints=NEG_HINTS):
    """
    The blob we put in the negotiate reply to tell the client which
    mechanisms we support.

    negHints is the NegTokenInit2 field windows sends and that clients
    expect to see. It carries no information, but leaving it out makes
    the blob small enough that some clients reject it, so send it.
    """
    inner = _encode_tlv(0xa0, _encode_tlv(0x30,
                b''.join([_encode_oid(m) for m in mechs])))
    if mech_token is not None:
        inner = inner + _encode_tlv(0xa2, _encode_tlv(0x04, bytes(mech_token)))
    if neg_hints is not None:
        inner = inner + _encode_tlv(0xa3, _encode_tlv(0x30,
                    _encode_tlv(0xa0, _encode_tlv(0x1b,
                        neg_hints.encode('ascii')))))

    return _encode_tlv(0x60,
                _encode_oid(SPNEGO_OID) +
                _encode_tlv(0xa0, _encode_tlv(0x30, inner)))


def encode_neg_token_resp(neg_state, supported_mech=None, response_token=None):
    """
    Our reply to each SPNEGO wrapped token from the client.
    """
    inner = _encode_tlv(0xa0, _encode_tlv(0x0a, bytes([neg_state])))
    if supported_mech is not None:
        inner = inner + _encode_tlv(0xa1, _encode_oid(supported_mech))
    if response_token is not None:
        inner = inner + _encode_tlv(0xa2, _encode_tlv(0x04, bytes(response_token)))

    return _encode_tlv(0xa1, _encode_tlv(0x30, inner))


def decode(buf):
    """
    Decode a SPNEGO token from a client and return a dict describing it.

    A raw NTLMSSP token is passed straight through as the mech token,
    with 'wrapped' set to False, so the caller can treat both the same.
    """
    buf = bytes(buf)
    if buf[:8] == b'NTLMSSP\x00':
        return {'wrapped': False, 'mech_token': buf}

    result = {'wrapped': True, 'mechs': [], 'mech_token': None}

    tag, value, _ = _decode_tlv(buf, 0)
    if tag == 0x60:
        #
        # InitialContextToken, the thisMech OID is followed by the
        # NegTokenInit itself.
        #
        _tag, _oid, _next = _decode_tlv(value, 0)
        if _decode_oid(_oid) != SPNEGO_OID:
            raise ValueError('Not a SPNEGO token')
        tag, value, _ = _decode_tlv(value, _next)

    if tag not in (0xa0, 0xa1):
        raise ValueError('Not a SPNEGO NegToken')
    result.update({'init': tag == 0xa0})

    _tag, seq, _ = _decode_tlv(value, 0)
    offset = 0
    while offset < len(seq):
        tag, value, offset = _decode_tlv(seq, offset)
        if result['init'] and tag == 0xa0:
            #
            # mechTypes
            #
            _tag, mechs, _ = _decode_tlv(value, 0)
            _o = 0
            while _o < len(mechs):
                _tag, _oid, _o = _decode_tlv(mechs, _o)
                result['mechs'].append(_decode_oid(_oid))
        elif not result['init'] and tag == 0xa0:
            #
            # negState
            #
            _tag, _state, _ = _decode_tlv(value, 0)
            result.update({'neg_state': _state[0]})
        elif tag == 0xa2:
            #
            # mechToken / responseToken
            #
            _tag, token, _ = _decode_tlv(value, 0)
            result.update({'mech_token': token})
        elif tag == 0xa3 and not result['init']:
            _tag, mic, _ = _decode_tlv(value, 0)
            result.update({'mech_list_mic': mic})

    return result
