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
        # For now we only run as a single process and we will terminate once
        # the a client has connected and then disconnected.
        # We should change this to run the master process to only
        # listen to the socket, then immediately accept and fork a slave
        # process to manage the connection.
        # Having one one process for each connected client.
        s.listen()
        while True:
            print('Waiting for connection')
            conn, addr = s.accept()
            with conn:
                try:
                    Server(conn)
                except Exception as e:
                    print(e)
                    True
            
if __name__ == "__main__":
    main()
