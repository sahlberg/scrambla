# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct

from enum import Enum

#
# SMB2 Header and definitions
#

SMB2_MAGIC = 0x424d53fe

class Status(Enum):
    SUCCESS                  = 0x00000000
    NO_MORE_FILES            = 0x80000006
    INVALID_PARAMETER        = 0xc000000d
    END_OF_FILE              = 0xc0000011
    MORE_PROCESSING_REQUIRED = 0xc0000016
    OBJECT_NAME_NOT_FOUND    = 0xc0000034
    BAD_NETWORK_NAME         = 0xc00000cc
    USER_SESSION_DELETED     = 0xc0000203
    
class Direction(Enum):
    REQUEST = 0
    REPLY = 1

class Command(Enum):
    NEGOTIATE_PROTOCOL = 0
    SESSION_SETUP      = 1
    SESSION_LOGOFF     = 2
    TREE_CONNECT       = 3
    TREE_DISCONNECT    = 4
    CREATE             = 5
    CLOSE              = 6
    FLUSH              = 7
    READ               = 8
    WRITE              = 9
    QUERY_DIRECTORY    = 14
    QUERY_INFO         = 16
    SET_INFO           = 17


# Flags
RESPONSE       = 0x00000001
ASYNC          = 0x00000002
RELATED        = 0x00000004
SIGNED         = 0x00000008
PRIORITY_MASK  = 0x00000070
DFS_OPERATIONS = 0x10000000
REPLAY         = 0x20000000

#
# File Attributes
#
FILE_ATTRIBUTE_READONLY            = 0x00000001
FILE_ATTRIBUTE_HIDDEN              = 0x00000002
FILE_ATTRIBUTE_SYSTEM              = 0x00000004
FILE_ATTRIBUTE_DIRECTORY           = 0x00000010
FILE_ATTRIBUTE_ARCHIVE             = 0x00000020
FILE_ATTRIBUTE_NORMAL              = 0x00000080
FILE_ATTRIBUTE_TEMPORARY           = 0x00000100
FILE_ATTRIBUTE_SPARSE_FILE         = 0x00000200
FILE_ATTRIBUTE_REPARSE_POINT       = 0x00000400
FILE_ATTRIBUTE_COMPRESSED          = 0x00000800
FILE_ATTRIBUTE_OFFLINE             = 0x00001000
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
FILE_ATTRIBUTE_ENCRYPTED           = 0x00004000
FILE_ATTRIBUTE_INTEGRITY_STREAM    = 0x00008000
FILE_ATTRIBUTE_NO_SCRUB_DATA       = 0x00020000


class Header(object):
    """
    A class for SMB2 Header and definitions
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(hdr):
        """
        Decode an SMB2 Header
        """
        result = {}
        result.update({'protocol_id': struct.unpack_from('<I', hdr, 0)[0]})
        result.update({'structure_size': struct.unpack_from('<H', hdr, 4)[0]})
        result.update({'credit_charge': struct.unpack_from('<H', hdr, 6)[0]})
        result.update({'command': struct.unpack_from('<H', hdr, 12)[0]})
        result.update({'flags': struct.unpack_from('<I', hdr, 16)[0]})
        result.update({'next_command': struct.unpack_from('<I', hdr, 20)[0]})
        result.update({'message_id': struct.unpack_from('<Q', hdr, 24)[0]})
        result.update({'session_id': struct.unpack_from('<Q', hdr, 40)[0]})
        result.update({'signature': hdr[48:48 + 16]})
        if result['flags'] & RESPONSE:
            result.update({'status': struct.unpack_from('<I', hdr, 8)[0]})
            result.update({'credit_response': struct.unpack_from('<H', hdr, 14)[0]})
        else:
            result.update({'channel_sequence': struct.unpack_from('<I', hdr, 8)[0]})
            result.update({'credit_request': struct.unpack_from('<H', hdr, 14)[0]})
        if result['flags'] & ASYNC:
            result.update({'async_id': struct.unpack_from('<Q', hdr, 32)[0]})
        else:
            result.update({'process_id': struct.unpack_from('<I', hdr, 32)[0]})
            result.update({'tree_id': struct.unpack_from('<I', hdr, 36)[0]})

        return result

    @staticmethod
    def encode(hdr):
        """
        Encode an SMB2 Header
        """
        result = bytearray(64)
        struct.pack_into('<I', result, 0, hdr['protocol_id'])
        struct.pack_into('<H', result, 4, 64)
        struct.pack_into('<H', result, 6, hdr['credit_charge'])
        struct.pack_into('<H', result, 12, hdr['command'])
        struct.pack_into('<I', result, 16, hdr['flags'])
        if 'next_command' in hdr:
            struct.pack_into('<I', result, 20, hdr['next_command'])
        struct.pack_into('<Q', result, 24, hdr['message_id'])
        struct.pack_into('<Q', result, 40, hdr['session_id'])
        if 'signature' in hdr:
            result[48:48 + 16] = hdr['signature']
        if hdr['flags'] & RESPONSE:
            struct.pack_into('<I', result, 8, hdr['status'])
            struct.pack_into('<H', result, 14, hdr['credit_response'])
        else:
            struct.pack_into('<I', result, 8, hdr['channel_sequence'])
            struct.pack_into('<H', result, 14, hdr['credit_request'])
        if hdr['flags'] & ASYNC:
            struct.pack_into('<Q', result, 32, hdr['async_id'])
        else:
            struct.pack_into('<I', result, 32, hdr['process_id'])
            struct.pack_into('<I', result, 36, hdr['tree_id'])

        return result
