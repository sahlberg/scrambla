#!/usr/bin/env python
# coding: utf-8

from smb2.header import Direction
from smb2.ntlmssp import NTLMSSP

ntlm_negotiate_buf_1 = bytes([
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x27, 0x02, 0x08, 0xa0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

ntlm_challenge_buf_1 = bytes([
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x25, 0x02, 0x8a, 0xe2,
    0x31, 0x95, 0x6b, 0xfb, 0xfb, 0xe9, 0x0d, 0xc9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x34, 0x00, 0x3e, 0x00, 0x00, 0x00,
    0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    0x4e, 0x00, 0x41, 0x00, 0x53, 0x00, 0x02, 0x00,
    0x06, 0x00, 0x4e, 0x00, 0x41, 0x00, 0x53, 0x00,
    0x01, 0x00, 0x06, 0x00, 0x4e, 0x00, 0x41, 0x00,
    0x53, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x06, 0x00, 0x6e, 0x00, 0x61, 0x00,
    0x73, 0x00, 0x07, 0x00, 0x08, 0x00, 0x98, 0xfb,
    0x77, 0x23, 0x31, 0x6d, 0xd6, 0x01, 0x00, 0x00,
    0x00, 0x00
])

ntlm_auth_buf_1 = bytes([
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x60, 0x00, 0x60, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x25, 0x02, 0x88, 0xe0,
    0x84, 0x5c, 0x44, 0x02, 0x21, 0xd1, 0x6f, 0x62,
    0x60, 0x64, 0x7d, 0x18, 0x4e, 0xa6, 0xd6, 0x7b,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0xfb, 0x77, 0x23, 0x31, 0x6d, 0xd6, 0x01,
    0xbd, 0x11, 0x79, 0x27, 0x10, 0xd9, 0xe1, 0xca,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x06, 0x00,
    0x4e, 0x00, 0x41, 0x00, 0x53, 0x00, 0x01, 0x00,
    0x06, 0x00, 0x4e, 0x00, 0x41, 0x00, 0x53, 0x00,
    0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x06, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x73, 0x00,
    0x07, 0x00, 0x08, 0x00, 0x98, 0xfb, 0x77, 0x23,
    0x31, 0x6d, 0xd6, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x73, 0x00, 0x61, 0x00, 0x68, 0x00, 0x6c, 0x00,
    0x62, 0x00, 0x65, 0x00, 0x72, 0x00, 0x67, 0x00,
    0xdb, 0x10, 0xe1, 0x1f, 0x06, 0xed, 0x59, 0xa1,
    0x30, 0x50, 0x4f, 0xb3, 0xa8, 0x4b, 0xcf, 0xd9
])


def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()

def main():
    print('Decode and re-encode a NTLM NEGOTIATE message #1')
    nt = NTLMSSP()
    info = nt.decode(ntlm_negotiate_buf_1)
    buf = nt.encode(info)

    if ntlm_negotiate_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:', len(ntlm_negotiate_buf_1))
        pr(ntlm_negotiate_buf_1)
        print('Encoded:', len(buf))
        pr(buf)
        exit(1)

    print('Decode and re-encode a NTLM CHALLENGE message #1')
    nt = NTLMSSP()
    info = nt.decode(ntlm_challenge_buf_1)
    buf = nt.encode(info)

    if ntlm_challenge_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:', len(ntlm_challenge_buf_1))
        pr(ntlm_challenge_buf_1)
        print('Encoded:', len(buf))
        pr(buf)
        exit(1)
        
    print('Decode and re-encode a NTLM AUTH message #1')
    nt = NTLMSSP()
    info = nt.decode(ntlm_auth_buf_1)
    buf = nt.encode(info)

    if ntlm_auth_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:', len(ntlm_auth_buf_1))
        pr(ntlm_auth_buf_1)
        print('Encoded:', len(buf))
        pr(buf)
        exit(1)
        

if __name__ == "__main__":
    main()
