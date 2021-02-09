#!/usr/bin/env python
# coding: utf-8

import socket

from smb2.header import Direction
from server import Server

def main():
    print('SMB2 server in Python says: Hi there!')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', 445))
        s.listen()
        conn, addr = s.accept()
        with conn:
            Server(conn)
            
if __name__ == "__main__":
    main()
