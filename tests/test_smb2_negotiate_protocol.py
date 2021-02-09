#!/usr/bin/env python
# coding: utf-8

from smb2.header import Direction
from smb2.negotiate_protocol import NegotiateProtocol

negotiate_protocol_req_buf_1 = bytes([
    0x00, 0x00, 0x00, 0x6a,

    0xfe, 0x53, 0x4d, 0x42,  0x40, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x1f, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0xff, 0xfe, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,

    0x24, 0x00, 0x03, 0x00,  0x01, 0x00, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x00,  0x80, 0xaf, 0x0c, 0x35,
    0x0a, 0xf3, 0xe8, 0x11,  0x94, 0x06, 0x00, 0x0c,
    0x29, 0x59, 0x2d, 0x24,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x02, 0x02, 0x10, 0x02,
    0x00, 0x03
])

negotiate_protocol_req_buf_2 = bytes([
    0x00, 0x00, 0x00, 0xd8,

    0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2a, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x24, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x77, 0x00, 0x00, 0x00, 0x34, 0x24, 0x08, 0x6e,
    0x5c, 0xb1, 0x46, 0xab, 0xb0, 0x1a, 0xc1, 0x46,
    0x23, 0x79, 0x15, 0x57, 0x68, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00,
    0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x64, 0xa3,
    0x50, 0x5b, 0xbb, 0x3c, 0xc5, 0x52, 0x04, 0xff,
    0x21, 0x6f, 0x8d, 0x6b, 0x12, 0x27, 0x6a, 0xf7,
    0xfb, 0xc7, 0xce, 0x54, 0xb3, 0x9a, 0x64, 0x19,
    0x22, 0x98, 0xa2, 0xde, 0x6a, 0x5d, 0x00, 0x00,
    0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x93, 0xad, 0x25, 0x50, 0x9c, 0xb4, 0x11, 0xe7,
    0xb4, 0x23, 0x83, 0xde, 0x96, 0x8b, 0xcd, 0x7c
])

negotiate_protocol_rep_buf_1 = bytes([
0x00, 0x00, 0x01, 0x0c,

0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x2a, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x41, 0x00, 0x01, 0x00, 0x11, 0x03, 0x02, 0x00,
0x6e, 0x61, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
0x00, 0xe5, 0x72, 0x23, 0x31, 0x6d, 0xd6, 0x01,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x80, 0x00, 0x4a, 0x00, 0xd0, 0x00, 0x00, 0x00,
0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a,
0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f,
0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43,
0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65,
0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f,
0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0xd3, 0x30,
0x30, 0x84, 0xf7, 0x7a, 0x09, 0x86, 0x7c, 0x6c,
0x08, 0x23, 0xad, 0x37, 0xf7, 0x98, 0xb9, 0x13,
0x5c, 0x23, 0x81, 0x16, 0xb4, 0xab, 0x65, 0x8b,
0xd4, 0x4d, 0xf4, 0x9c, 0x7c, 0x54, 0x00, 0x00,
0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x00, 0x01, 0x00                                          
])

def pr(buf):
    pos = 0
    for i in buf:
        print("%02x " % i, end='')
        pos = pos + 1
        if pos == 8:
            print(' ', end='')
        if pos == 16:
            pos = 0
            print('')
    print()

def main():
    print('Decode and re-encode a NegotiateProtocol Request #1')
    np = NegotiateProtocol()
    cmd = np.decode(Direction.REQUEST, negotiate_protocol_req_buf_1[4 + 64:])
    buf = np.encode(Direction.REQUEST, cmd)

    if negotiate_protocol_req_buf_1[4 + 64:] != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(negotiate_protocol_req_buf_1[4 + 64:])
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a NegotiateProtocol Request #2')
    np = NegotiateProtocol()
    cmd = np.decode(Direction.REQUEST, negotiate_protocol_req_buf_2[4 + 64:])
    buf = np.encode(Direction.REQUEST, cmd)

    if negotiate_protocol_req_buf_2[4 + 64:] != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(negotiate_protocol_req_buf_2[4 + 64:])
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a NegotiateProtocol Reply #1')
    np = NegotiateProtocol()
    cmd = np.decode(Direction.REPLY, negotiate_protocol_rep_buf_1[4 + 64:])
    buf = np.encode(Direction.REPLY, cmd)

    if negotiate_protocol_rep_buf_1[4 + 64:] != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(negotiate_protocol_rep_buf_1[4 + 64:])
        print('Encoded:')
        pr(buf)
        exit(1)

if __name__ == "__main__":
    main()
