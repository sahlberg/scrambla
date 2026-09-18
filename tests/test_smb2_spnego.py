#!/usr/bin/env python
# coding: utf-8

from smb2.spnego import *
from smb2.spnego import _encode_oid, _decode_oid, _decode_tlv


def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()


def check(name, got, expected):
    if got != expected:
        print(name, 'mismatch')
        print('Expected:', expected)
        print('Got:', got)
        exit(1)


def main():
    print('OID round trip')
    for oid in (SPNEGO_OID, NTLMSSP_OID, '1.2.840.48018.1.2.2'):
        tag, value, _ = _decode_tlv(_encode_oid(oid), 0)
        if tag != 0x06:
            print('OID did not encode as an OID')
            exit(1)
        check('OID', _decode_oid(value), oid)

    print('NegTokenInit round trip')
    blob = encode_neg_token_init([NTLMSSP_OID])
    token = decode(blob)
    if not token['wrapped'] or not token['init']:
        print('Not decoded as a wrapped NegTokenInit:', token)
        exit(1)
    check('mechs', token['mechs'], [NTLMSSP_OID])
    check('mech token', token['mech_token'], None)

    print('NegTokenInit with a mech token round trip')
    mech_token = b'NTLMSSP\x00\x01\x00\x00\x00' + bytes(20)
    token = decode(encode_neg_token_init([NTLMSSP_OID], mech_token))
    check('mechs', token['mechs'], [NTLMSSP_OID])
    check('mech token', token['mech_token'], mech_token)

    print('NegTokenResp round trip')
    response_token = b'NTLMSSP\x00\x02\x00\x00\x00' + bytes(40)
    token = decode(encode_neg_token_resp(ACCEPT_INCOMPLETE, NTLMSSP_OID,
                                         response_token))
    if token['init']:
        print('Decoded a NegTokenResp as a NegTokenInit')
        exit(1)
    check('neg state', token['neg_state'], ACCEPT_INCOMPLETE)
    check('response token', token['mech_token'], response_token)

    token = decode(encode_neg_token_resp(ACCEPT_COMPLETE))
    check('neg state', token['neg_state'], ACCEPT_COMPLETE)
    check('response token', token['mech_token'], None)

    print('Long tokens use a multi byte DER length')
    big = bytes(range(256)) * 10
    token = decode(encode_neg_token_resp(ACCEPT_INCOMPLETE, NTLMSSP_OID, big))
    check('response token', token['mech_token'], big)

    print('A raw NTLMSSP token passes straight through')
    raw = b'NTLMSSP\x00\x03\x00\x00\x00' + bytes(60)
    token = decode(raw)
    if token['wrapped']:
        print('A raw NTLMSSP token was decoded as SPNEGO')
        exit(1)
    check('mech token', token['mech_token'], raw)

    print('The negotiate reply blob is big enough for clients to accept')
    #
    # A NegTokenInit with a single mechanism and no negHints is under the
    # 32 bytes some clients insist on, which is why we send negHints.
    #
    blob = encode_neg_token_init([NTLMSSP_OID])
    if blob[1] < 32:
        print('The negotiate blob is only', blob[1], 'bytes')
        exit(1)

    print('All tests passed')

if __name__ == "__main__":
    main()
