# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin

#
# SMB2 Close
#

#
# FLAGS
#
SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001


def _decode_request(hdr):
    """
    Decode a Close request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'flags': struct.unpack_from('<H', hdr, 2)[0]})
    result.update({'file_id': (struct.unpack_from('<Q', hdr,  8)[0],
                               struct.unpack_from('<Q', hdr, 16)[0])})

    return result

def _encode_request(hdr):
    """
    Encode a Close request
    """
    result = bytearray(24)
    struct.pack_into('<H', result, 0, 24)
    struct.pack_into('<H', result, 2, hdr['flags'])
    struct.pack_into('<Q', result, 8, hdr['file_id'][0])
    struct.pack_into('<Q', result, 16, hdr['file_id'][1])

    return result

def _decode_reply(hdr):
    """
    Decode a Close reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'flags': struct.unpack_from('<H', hdr, 2)[0]})
    if result['flags'] & SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB:
        result.update({'creation_time': WinToTimeval(struct.unpack_from('<Q', hdr, 8)[0])})
        result.update({'last_access_time': WinToTimeval(struct.unpack_from('<Q', hdr, 16)[0])})
        result.update({'last_write_time': WinToTimeval(struct.unpack_from('<Q', hdr, 24)[0])})
        result.update({'change_time': WinToTimeval(struct.unpack_from('<Q', hdr, 32)[0])})
        result.update({'allocation_size': struct.unpack_from('<Q', hdr, 40)[0]})
        result.update({'end_of_file': struct.unpack_from('<Q', hdr, 48)[0]})
        result.update({'file_attributes': struct.unpack_from('<I', hdr, 56)[0]})
        
    return result

def _encode_reply(hdr):
    """
    Encode a Close reply
    """
    result = bytearray(60)
    struct.pack_into('<H', result, 0, 60)
    struct.pack_into('<H', result, 2, hdr['flags'])
    if hdr['flags'] & SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB:
        struct.pack_into('<Q', result, 8, TimevalToWin(hdr['creation_time']))
        struct.pack_into('<Q', result, 16, TimevalToWin(hdr['last_access_time']))
        struct.pack_into('<Q', result, 24, TimevalToWin(hdr['last_write_time']))
        struct.pack_into('<Q', result, 32, TimevalToWin(hdr['change_time']))
        struct.pack_into('<Q', result, 40, hdr['allocation_size'])
        struct.pack_into('<Q', result, 48, hdr['end_of_file'])
        struct.pack_into('<I', result, 56, hdr['file_attributes'])

    return result


class Close(object):
    """
    A class for Close
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Create PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Create PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
