# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction

#
# SMB2 Session Logoff
#

class SessionLogoff(object):
    """
    A class for Session Logoff
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Session Logoff PDU
        """
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        return result
    
    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Session Logoff PDU
        """
        result = bytearray(4)
        struct.pack_into('<H', result, 0, 4)
        return result
    
