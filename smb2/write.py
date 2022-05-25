# coding: utf-8

# Copyright (C) 2022 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction

#
# SMB2 Write
#

#
# Flags
#
SMB2_WRITEFLAG_WRITE_THROUGH    = 0x01
SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x02


def _decode_request(hdr):
    """
    Decode a Write request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'length': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'offset': struct.unpack_from('<Q', hdr, 8)[0]})
    result.update({'file_id': (struct.unpack_from('<Q', hdr, 16)[0],
                               struct.unpack_from('<Q', hdr, 24)[0])})
    result.update({'flags': struct.unpack_from('<I', hdr, 44)[0]})
    
    if result['length']:
        _o = struct.unpack_from('<H', hdr, 2)[0] - 64
        result.update({'data': hdr[_o:_o + result['length']]})

    return result

def _encode_request(hdr):
    """
    Encode a Write request
    """
    result = bytearray(48)
    struct.pack_into('<H', result, 0, 49)
    struct.pack_into('<H', result, 2, 48)
    struct.pack_into('<I', result, 4, len(buffer))
    struct.pack_into('<Q', result, 8, hdr['offset'])
    struct.pack_into('<Q', result, 16, hdr['file_id'][0])
    struct.pack_into('<Q', result, 24, hdr['file_id'][1])
    struct.pack_into('<I', result, 44, hdr['flags'])
    result = result + hdr['data']
        
    return result

def _encode_reply(hdr):
    """
    Encode a Write reply
    """
    result = bytearray(16)
    struct.pack_into('<H', result, 0, 17)
    struct.pack_into('<I', result, 4, hdr['count'])
        
    return result

def _decode_reply(hdr):
    """
    Decode a Write reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'count': struct.unpack_from('<I', hdr, 4)[0]})

    return result


class Write(object):
    """
    A class for Write
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Write PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Write PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
