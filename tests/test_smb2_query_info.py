#!/usr/bin/env python
# coding: utf-8

from smb2.header import Direction
from smb2.query_info import QueryInfo

query_info_req_buf_1 = bytes([
    0x29, 0x00, 0x01, 0x12, 0x65, 0x20, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
])

query_info_rep_buf_1 = bytes([
    0x09, 0x00, 0x48, 0x00, 0x68, 0x00, 0x00, 0x00,
    0x5c, 0x2b, 0x35, 0x43, 0xb4, 0x40, 0xd3, 0x01,
    0x43, 0x23, 0x9f, 0x70, 0x0c, 0xa9, 0xd6, 0x01,
    0x43, 0x23, 0x9f, 0x70, 0x0c, 0xa9, 0xd6, 0x01,
    0x43, 0x23, 0x9f, 0x70, 0x0c, 0xa9, 0xd6, 0x01,
    0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x95, 0x9d, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00
])


def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()

def main():
    print('Decode and re-encode a QueryInfo Request #1')
    qi = QueryInfo()
    cmd = qi.decode(Direction.REQUEST, query_info_req_buf_1)
    buf = qi.encode(Direction.REQUEST, cmd)

    if query_info_req_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(query_info_req_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a QueryInfo Reply #1')
    qi = QueryInfo()
    cmd = qi.decode(Direction.REPLY, query_info_rep_buf_1)
    buf = qi.encode(Direction.REPLY, cmd)

    if query_info_rep_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(query_info_rep_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)


if __name__ == "__main__":
    main()
