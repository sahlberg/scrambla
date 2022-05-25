# coding: utf-8

# Copyright (C) 2022 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
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
# SMB2 Set Info
#
class SetInfo(object):
    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def _decode_reply(hdr):
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})

        return result

    @staticmethod
    def _encode_reply(hdr):
        result = bytearray(2)
        struct.pack_into('<H', result, 0, 2)

        return result

    @staticmethod
    def _decode_request(hdr):
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        result.update({'info_type': struct.unpack_from('<B', hdr, 2)[0]})
        result.update({'file_info_class': struct.unpack_from('<B', hdr, 3)[0]})
        result.update({'additional_information': struct.unpack_from('<I', hdr, 12)[0]})
        result.update({'file_id': (struct.unpack_from('<Q', hdr, 16)[0],
                                   struct.unpack_from('<Q', hdr, 24)[0])})

        _len = struct.unpack_from('<I', hdr, 4)[0]
        _offset = struct.unpack_from('<H', hdr, 8)[0] - 64
        result.update({'buffer': hdr[_offset:_offset + _len]})

        return result
        
    @staticmethod
    def _encode_request(hdr):
        result = bytearray(33)
        struct.pack_into('<H', result, 0, 33)
        struct.pack_into('<B', result, 2, hdr['info_type'])
        struct.pack_into('<B', result, 3, hdr['file_info_class'])
        struct.pack_into('<I', result, 4, len(buffer))
        struct.pack_into('<H', result, 8, 32 + 64)
        result = result + buffer
        if 'additional_information' in hdr:
            struct.pack_into('<I', result, 12, hdr['additional_information'])
        struct.pack_into('<Q', result, 16, hdr['file_id'][0])
        struct.pack_into('<Q', result, 24, hdr['file_id'][1])
        
        return result

    @staticmethod
    def decode(direction, hdr):
        if direction == Direction.REPLY:
            return SetInfo._decode_reply(hdr)
        return SetInfo._decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        if direction == Direction.REPLY:
            return SetInfo._encode_reply(hdr)
        return SetInfo._encode_request(hdr)
    
