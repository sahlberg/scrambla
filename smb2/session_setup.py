# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction

#
# SMB2 Session Setup
#

#
# Flags
#
SMB2_SESSION_FLAG_BINDING = 0x01

#
# Security Mode
#
SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x01
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x02

#
# Capabilities
#
SMB2_GLOBAL_CAP_DFS = 0x00000001

#
# Session Flags
#
SMB2_SESSION_FLAG_IS_GUEST     = 0x0001
SMB2_SESSION_FLAG_IS_NULL      = 0x0002
SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004


def _decode_request(hdr):
    """
    Decode a Session Setup request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'flags': struct.unpack_from('<B', hdr, 2)[0]})
    result.update({'security_mode': struct.unpack_from('<B', hdr, 3)[0]})
    result.update({'capabilities': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'previous_session_id': hdr[16:16 + 8]})

    _offset = struct.unpack_from('<H', hdr, 12)[0] - 64
    _len = struct.unpack_from('<H', hdr, 14)[0]
    if _len:
        result.update({'security_buffer': hdr[_offset:_offset + _len]})

    return result

def _encode_request(hdr):
    """
    Encode a Session Setup request
    """
    result = bytearray(24)
    struct.pack_into('<H', result, 0, 25)
    struct.pack_into('<B', result, 2, hdr['flags'])
    struct.pack_into('<B', result, 3, hdr['security_mode'])    
    struct.pack_into('<I', result, 4, hdr['capabilities'])
    if 'previous_session_id' in hdr:
        result[16:16 + 8] = hdr['previous_session_id']

    if 'security_buffer' in hdr:
        struct.pack_into('<H', result, 12, 24 + 64)
        struct.pack_into('<H', result, 14, len(hdr['security_buffer']))

        result = result + hdr['security_buffer']

    return result

def _decode_reply(hdr):
    """
    Decode a Session Setup reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'session_flags': struct.unpack_from('<H', hdr, 2)[0]})
    _offset = struct.unpack_from('<H', hdr, 4)[0] - 64
    _len = struct.unpack_from('<H', hdr, 6)[0]
    if _len:
        result.update({'security_buffer': hdr[_offset:_offset + _len]})
    
    return result

def _encode_reply(hdr):
    """
    Encode a Session Setup reply
    """
    result = bytearray(8)
    struct.pack_into('<H', result, 0, 9)
    struct.pack_into('<H', result, 2, hdr['session_flags'])
    struct.pack_into('<H', result, 4, 8 + 64)
    if 'security_buffer' in hdr:
        struct.pack_into('<H', result, 6, len(hdr['security_buffer']))
        result = result + hdr['security_buffer']

    return result


class SessionSetup(object):
    """
    A class for Session Setup
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Session Setup PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Session Setup PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
