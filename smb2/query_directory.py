# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# SMB2 Query Directory
#

#
# FLAGS
#
SMB2_RESTART_SCANS       = 0x01
SMB2_RETURN_SINGLE_ENTRY = 0x02
SMB2_INDEX_SPECIFIED     = 0x04
SMB2_REOPEN              = 0x10


class QueryDirectory(object):
    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def _decode_request(hdr):
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        result.update({'info_class': struct.unpack_from('<B', hdr, 2)[0]})
        result.update({'flags': struct.unpack_from('<B', hdr, 3)[0]})
        result.update({'file_index': struct.unpack_from('<I', hdr, 4)[0]})
        result.update({'file_id': (struct.unpack_from('<Q', hdr,  8)[0],
                                   struct.unpack_from('<Q', hdr, 16)[0])})
        result.update({'output_buffer_length': struct.unpack_from('<I', hdr, 28)[0]})

        _offset = struct.unpack_from('<H', hdr, 24)[0] - 64
        _len = struct.unpack_from('<H', hdr, 26)[0]
        if _len:
            result.update({'name': UCS2toUTF8(hdr[_offset:_offset + _len])})

        return result

    @staticmethod
    def _decode_reply(hdr):
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})

        _offset = struct.unpack_from('<H', hdr, 2)[0] - 64
        _len = struct.unpack_from('<I', hdr, 4)[0]
        if _len:
            result.update({'data': hdr[_offset:_offset + _len]})

        return result

    @staticmethod
    def _encode_request(hdr):
        result = bytearray(32)
        struct.pack_into('<H', result, 0, 33)
        struct.pack_into('<B', result, 2, hdr['info_class'])
        struct.pack_into('<B', result, 3, hdr['flags'])
        struct.pack_into('<I', result, 4, hdr['file_index'])
        struct.pack_into('<Q', result,  8, hdr['file_id'][0])
        struct.pack_into('<Q', result, 16, hdr['file_id'][1])
        struct.pack_into('<I', result, 28, hdr['output_buffer_length'])

        if 'name' in hdr:
            _c = UTF8toUCS2(hdr['name'])
            struct.pack_into('<H', result, 24, 32 + 64)
            struct.pack_into('<H', result, 26, len(_c))
            result = result + _c

        return result
    
    @staticmethod
    def _encode_reply(hdr):
        result = bytearray(8)
        struct.pack_into('<H', result, 0, 9)
        struct.pack_into('<H', result, 2, 8 + 64)
        struct.pack_into('<I', result, 4, len(hdr['data']))
        result = result + hdr['data']
            
        return result

    @staticmethod
    def decode(direction, hdr):
        if direction == Direction.REPLY:
            return QueryDirectory._decode_reply(hdr)
        return QueryDirectory._decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        if direction == Direction.REPLY:
            return QueryDirectory._encode_reply(hdr)
        return QueryDirectory._encode_request(hdr)
    
