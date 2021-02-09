# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction

#
# SMB2 Read
#

#
# Flags
#
SMB2_READFLAG_READ_UNBUFFERED    = 0x01
SMB2_READFLAG_REQUEST_COMPRESSED = 0x02


def _decode_request(hdr):
    """
    Decode a Read request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'flags': struct.unpack_from('<B', hdr, 3)[0]})
    result.update({'length': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'offset': struct.unpack_from('<Q', hdr, 8)[0]})
    result.update({'file_id': (struct.unpack_from('<Q', hdr, 16)[0],
                               struct.unpack_from('<Q', hdr, 24)[0])})
    result.update({'minimum_count': struct.unpack_from('<I', hdr, 32)[0]})
    result.update({'channel': struct.unpack_from('<I', hdr, 36)[0]})
    result.update({'remaining_bytes': struct.unpack_from('<I', hdr, 40)[0]})
    
    _offset = struct.unpack_from('<H', hdr, 44)[0] - 64
    _len = struct.unpack_from('<H', hdr, 46)[0]
    if _len:
        result.update({'read_channel': hdr[_offset:_offset + _len]})

    return result

def _encode_request(hdr):
    """
    Encode a Read request
    """
    result = bytearray(48)
    struct.pack_into('<H', result, 0, 49)
    struct.pack_into('<B', result, 3, hdr['flags'])
    struct.pack_into('<I', result, 4, hdr['length'])
    struct.pack_into('<Q', result, 8, hdr['offset'])
    struct.pack_into('<Q', result, 16, hdr['file_id'][0])
    struct.pack_into('<Q', result, 24, hdr['file_id'][1])
    struct.pack_into('<I', result, 32, hdr['minimum_count'])
    struct.pack_into('<I', result, 36, hdr['channel'])
    struct.pack_into('<I', result, 40, hdr['remaining_bytes'])

    if 'read_channel' in hdr:
        struct.pack_into('<H', result, 44, len(result) + 64)
        struct.pack_into('<H', result, 46, len(hdr['read_channel']))
        result = result + hdr['read_channel']
        
    return result

def _encode_reply(hdr):
    """
    Encode a Read reply
    """
    result = bytearray(16)
    struct.pack_into('<H', result, 0, 17)
    struct.pack_into('<I', result, 8, hdr['data_remaining'])
    if 'flags' in hdr:
        struct.pack_into('<I', result, 12, hdr['flags'])
    if 'data' in hdr:
        struct.pack_into('<B', result, 2, 16 + 64)
        struct.pack_into('<I', result, 4, len(hdr['data']))
        result = result + hdr['data']
        
    return result

def _decode_reply(hdr):
    """
    Decode a Read reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'data_remaining': struct.unpack_from('<I', hdr, 8)[0]})
    result.update({'flags': struct.unpack_from('<I', hdr, 12)[0]})

    _offset = struct.unpack_from('<B', hdr, 2)[0] - 64
    _len = struct.unpack_from('<I', hdr, 4)[0]
    if _len:
        result.update({'data': hdr[_offset:_offset + _len]})

    return result


class Read(object):
    """
    A class for Read
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Read PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Read PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
