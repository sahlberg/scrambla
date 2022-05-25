# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin

#
# INFO TYPE
#
SMB2_0_INFO_FILE       = 0x01
SMB2_0_INFO_FILESYSTEM = 0x02
SMB2_0_INFO_SECURITY   = 0x03
SMB2_0_INFO_QUOTA      = 0x04

#
# SMB2 Query Info
#
class QueryInfo(object):
    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def _decode_reply(hdr):
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        _offset = struct.unpack_from('<H', hdr, 2)[0] - 64
        _len = struct.unpack_from('<I', hdr, 4)[0]
        if _len:
            result.update({'buffer': hdr[_offset:_offset + _len]})

        return result

    @staticmethod
    def _encode_reply(hdr):
        result = bytearray(8)
        struct.pack_into('<H', result, 0, 9)
        if 'buffer' in hdr:
            struct.pack_into('<H', result, 2, 8 + 64)
            struct.pack_into('<I', result, 4, len(hdr['buffer']))
            result = result + hdr['buffer']
        
        return result

    @staticmethod
    def _decode_request(hdr):
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        result.update({'info_type': struct.unpack_from('<B', hdr, 2)[0]})
        result.update({'file_info_class': struct.unpack_from('<B', hdr, 3)[0]})
        result.update({'output_buffer_length': struct.unpack_from('<I', hdr, 4)[0]})
        result.update({'additional_information': struct.unpack_from('<I', hdr, 16)[0]})
        result.update({'flags': struct.unpack_from('<I', hdr, 20)[0]})
        result.update({'file_id': (struct.unpack_from('<Q', hdr, 24)[0],
                                   struct.unpack_from('<Q', hdr, 32)[0])})

        _offset = struct.unpack_from('<H', hdr, 8)[0] - 64
        _len = struct.unpack_from('<I', hdr, 12)[0]
        if _len:
            result.update({'buffer': hdr[_offset:_offset + _len]})

        return result
        
    @staticmethod
    def _encode_request(hdr):
        result = bytearray(40)
        struct.pack_into('<H', result, 0, 41)
        struct.pack_into('<B', result, 2, hdr['info_type'])
        struct.pack_into('<B', result, 3, hdr['file_info_class'])
        struct.pack_into('<I', result, 4, hdr['output_buffer_length'])
        if 'additional_information' in hdr:
            struct.pack_into('<I', result, 16, hdr['additional_information'])
        struct.pack_into('<I', result, 20, hdr['flags'])
        struct.pack_into('<Q', result, 24, hdr['file_id'][0])
        struct.pack_into('<Q', result, 32, hdr['file_id'][1])

        if 'buffer' in hdr:
            struct.pack_into('<H', result, 8, 40 + 64)
            struct.pack_into('<I', result, 12, len(buffer))
            result = result + buffer
        
        return result

    @staticmethod
    def decode(direction, hdr):
        if direction == Direction.REPLY:
            return QueryInfo._decode_reply(hdr)
        return QueryInfo._decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        if direction == Direction.REPLY:
            return QueryInfo._encode_reply(hdr)
        return QueryInfo._encode_request(hdr)
    
