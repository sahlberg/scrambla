#!/usr/bin/env python
# coding: utf-8

from smb2.header import Direction
from smb2.tree_disconnect import TreeDisconnect

tree_disconnect_req_buf_1 = bytes([
    0x04, 0x00, 0x00, 0x00
])

tree_disconnect_rep_buf_1 = bytes([
    0x04, 0x00, 0x00, 0x00
])


def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()

def main():
    print('Decode and re-encode a TreeDisconnect Request #1')
    tc = TreeDisconnect()
    cmd = tc.decode(Direction.REQUEST, tree_disconnect_req_buf_1)
    buf = tc.encode(Direction.REQUEST, cmd)

    if tree_disconnect_req_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(tree_disconnect_req_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a TreeDisconnect Reply #1')
    tc = TreeDisconnect()
    cmd = tc.decode(Direction.REPLY, tree_disconnect_rep_buf_1)
    buf = tc.encode(Direction.REPLY, cmd)

    if tree_disconnect_rep_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(tree_disconnect_rep_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)


if __name__ == "__main__":
    main()
