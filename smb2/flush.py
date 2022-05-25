# coding: utf-8

# Copyright (C) 2022 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin

#
# SMB2 Flush
#

def _decode_request(hdr):
    """
    Decode a Flush request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'file_id': (struct.unpack_from('<Q', hdr,  8)[0],
                               struct.unpack_from('<Q', hdr, 16)[0])})

    return result

def _encode_request(hdr):
    """
    Encode a Flush request
    """
    result = bytearray(24)
    struct.pack_into('<H', result, 0, 24)
    struct.pack_into('<Q', result, 8, hdr['file_id'][0])
    struct.pack_into('<Q', result, 16, hdr['file_id'][1])

    return result

def _decode_reply(hdr):
    """
    Decode a Flush reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        
    return result

def _encode_reply(hdr):
    """
    Encode a Flush reply
    """
    result = bytearray(4)
    struct.pack_into('<H', result, 0, 4)

    return result


class Flush(object):
    """
    A class for Flush
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Flush PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Flush PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
