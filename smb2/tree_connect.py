# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# SMB2 Tree Connect
#

#
# Flags
#
SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x00000001
SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x00000002
SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x00000004

#
# Share Type
#
SMB2_SHARE_TYPE_DISK  = 0x01
SMB2_SHARE_TYPE_PIPE  = 0x02
SMB2_SHARE_TYPE_PRINT = 0x03


def _decode_request(hdr):
    """
    Decode a Tree Connect request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'flags': struct.unpack_from('<H', hdr, 2)[0]})
    if result['flags'] & SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT:
        print('Can not decode TreeConnect extensions')

    _offset = struct.unpack_from('<H', hdr, 4)[0] - 64
    _len = struct.unpack_from('<H', hdr, 6)[0]
    result.update({'path': UCS2toUTF8(hdr[_offset:_offset + _len]).replace(b'\\', b'/')})
    
    return result

def _encode_request(hdr):
    """
    Encode a Tree Connect request
    """
    result = bytearray(8)
    struct.pack_into('<H', result, 0, 9)
    if 'flags' in hdr:
        struct.pack_into('<H', result, 2, hdr['flags'])

    _u = UTF8toUCS2(hdr['path']).replace(b'/', b'\\')
    struct.pack_into('<H', result, 4, 8 + 64)
    struct.pack_into('<H', result, 6, len(_u))
    result = result + _u + bytearray(2)

    return result

def _decode_reply(hdr):
    """
    Decode a Tree Connect reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'share_type': struct.unpack_from('<B', hdr, 2)[0]})
    result.update({'share_flags': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'capabilities': struct.unpack_from('<I', hdr, 8)[0]})
    result.update({'maximal_access': struct.unpack_from('<I', hdr, 12)[0]})
    
    return result

def _encode_reply(hdr):
    """
    Encode a Tree Connect reply
    """
    result = bytearray(16)
    struct.pack_into('<H', result, 0, 16)
    struct.pack_into('<B', result, 2, hdr['share_type'])
    struct.pack_into('<I', result, 4, hdr['share_flags'])
    struct.pack_into('<I', result, 8, hdr['capabilities'])
    struct.pack_into('<I', result, 12, hdr['maximal_access'])

    return result


class TreeConnect(object):
    """
    A class for Tree Connect
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Tree Connect PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Tree Connect PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
