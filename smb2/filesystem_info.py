# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# SMB2 FILESYSTEM INFORMATION CLASSES
#
class FSInfoClass(Enum):
    VOLUME         =  1
    DEVICE         =  4
    ATTRIBUTE      =  5
    FULL_SIZE      =  7
    SECTOR_SIZE    = 11

#
# DEVICE TYPES
#
class DeviceType(Enum):
    CD_ROM = 2
    DISK   = 7

#
# CHARACTERISTICS
#
REMOVABLE_MEDIA                     = 0x00000001
READ_ONLY_DEVICE                    = 0x00000002
FLOPPY_DISKETTE                     = 0x00000004
WRITE_ONCE_MEDIA                    = 0x00000008
REMOTE_DEVICE                       = 0x00000010
DEVICE_IS_MOUNTED                   = 0x00000020
VIRTUAL_VOLUME                      = 0x00000040
DEVICE_SECURE_OPEN                  = 0x00000100
CHARACTERISTICS_TS_DEVICE           = 0x00001000
CHARACTERISTICS_WEBDAV_DEVICE       = 0x00001000
DEVICE_ALLOW_APPCONTAINER_TRAVERSAL = 0x00002000
PORTABLE_DEVICE                     = 0x00004000

#
# ATTRIBUTES
#
SUPPORTS_SPARSE_VDL                     = 0x10000000
SUPPORTS_BLOCK_REFCOUNTING              = 0x08000000
SUPPORTS_INTEGRITY_STREAMS              = 0x04000000
SUPPORTS_USN_JOURNAL                    = 0x02000000
SUPPORTS_OPEN_BY_FILE_ID                = 0x01000000
SUPPORTS_EXTENDED_ATTRIBUTES            = 0x00800000
SUPPORTS_HARD_LINKS                     = 0x00400000
SUPPORTS_TRANSACTIONS                   = 0x00200000
SEQUENTIAL_WRITE_ONCE                   = 0x00100000
READ_ONLY_VOLUME                        = 0x00080000
NAMED_STREAMS                           = 0x00040000
SUPPORTS_ENCRYPTION                     = 0x00020000
SUPPORTS_OBJECT_IDS                     = 0x00010000
VOLUME_IS_COMPRESSED                    = 0x00008000
SUPPORTS_REMOTE_STORAGE                 = 0x00000100
SUPPORTS_REPARSE_POINTS                 = 0x00000080
SUPPORTS_SPARSE_FILES                   = 0x00000040
VOLUME_QUOTAS                           = 0x00000020
FILE_COMPRESSION                        = 0x00000010
PERSISTENT_ACLS                         = 0x00000008
UNICODE_ON_DISK                         = 0x00000004
CASE_PRESERVED_NAMES                    = 0x00000002
CASE_SENSITIVE_SEARCH                   = 0x00000001

#
# SECTOR SIZE FLAGS
#
SSINFO_FLAGS_ALIGNED_DEVICE              = 0x00000001
SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE = 0x00000002
SSINFO_FLAGS_NO_SEEK_PENALTY             = 0x00000004
SSINFO_FLAGS_TRIM_ENABLED                = 0x00000008


def decode_attribute_info(buf):
    i = {}
    i.update({'attributes': struct.unpack_from('<I', buf, 0)[0]})
    i.update({'maximum_component_name_length': struct.unpack_from('<I', buf, 4)[0]})
    _len = struct.unpack_from('<I', buf, 8)[0]
    if _len:
        i.update({'file_system_name': UCS2toUTF8(buf[12:12 + _len]).replace(b'\\', b'/')})

    return i

def encode_attribute_info(i):
    _b = bytearray(12)
    struct.pack_into('<I', _b,  0, i['attributes'])
    struct.pack_into('<I', _b,  4, i['maximum_component_name_length'])
    _n = UTF8toUCS2(i['file_system_name']).replace(b'/', b'\\')
    struct.pack_into('<I', _b, 8, len(_n))
    _b = _b + _n

    return _b

def decode_device_info(buf):
    i = {}
    i.update({'device_type': struct.unpack_from('<I', buf, 0)[0]})
    i.update({'characteristics': struct.unpack_from('<I', buf, 4)[0]})

    return i

def encode_device_info(i):
    _b = bytearray(8)
    struct.pack_into('<I', _b,  0, i['device_type'])
    struct.pack_into('<I', _b,  4, i['characteristics'])

    return _b

def decode_volume_info(buf):
    i = {}
    i.update({'creation_time': WinToTimeval(struct.unpack_from('<Q', buf, 0)[0])})
    i.update({'serial_number': struct.unpack_from('<I', buf, 8)[0]})
    i.update({'supports_objects': struct.unpack_from('<B', buf, 16)[0]})
    _len = struct.unpack_from('<I', buf, 12)[0]
    i.update({'label': UCS2toUTF8(buf[18:18 + _len]).replace(b'\\', b'/')})

    return i

def encode_volume_info(i):
    _b = bytearray(18)
    struct.pack_into('<Q', _b,  0, TimevalToWin(i['creation_time']))
    struct.pack_into('<I', _b,  8, i['serial_number'])
    struct.pack_into('<B', _b,  16, i['supports_objects'])
    _lab = UTF8toUCS2(i['label']).replace(b'/', b'\\')
    struct.pack_into('<I', _b,  12, len(_lab))
    _b = _b + _lab
    
    return _b
    
def encode_sector_size_info(i):
    _b = bytearray(28)
    struct.pack_into('<I', _b,  0, i['logical_bytes_per_sector'])
    struct.pack_into('<I', _b,  4, i['physical_bytes_per_sector_for_atomicity'])
    struct.pack_into('<I', _b,  8, i['physical_bytes_per_sector_for_performance'])
    struct.pack_into('<I', _b, 12, i['effective_physical_bytes_per_sector_for_atomicity'])
    struct.pack_into('<I', _b, 16, i['flags'])
    struct.pack_into('<I', _b, 20, i['byte_offset_for_sector_alignment'])
    struct.pack_into('<I', _b, 24, i['byte_offset_for_partition_alignment'])

    return _b

def decode_sector_size_info(buf):
    i = {}
    i.update({'logical_bytes_per_sector': struct.unpack_from('<I', buf, 0)[0]})
    i.update({'physical_bytes_per_sector_for_atomicity': struct.unpack_from('<I', buf, 4)[0]})
    i.update({'physical_bytes_per_sector_for_performance': struct.unpack_from('<I', buf, 8)[0]})
    i.update({'effective_physical_bytes_per_sector_for_atomicity': struct.unpack_from('<I', buf, 12)[0]})
    i.update({'flags': struct.unpack_from('<I', buf, 16)[0]})
    i.update({'byte_offset_for_sector_alignment': struct.unpack_from('<I', buf, 20)[0]})
    i.update({'byte_offset_for_partition_alignment': struct.unpack_from('<I', buf, 24)[0]})

    return i

def encode_full_size_info(i):
    _b = bytearray(32)
    struct.pack_into('<Q', _b,   0, i['total_allocation_units'])
    struct.pack_into('<Q', _b,   8, i['caller_available_allocation_units'])
    struct.pack_into('<Q', _b,  16, i['actual_available_allocation_units'])
    struct.pack_into('<I', _b,  24, i['sectors_per_allocation_unit'])
    struct.pack_into('<I', _b,  28, i['bytes_per_sector'])

    return _b

def decode_full_size_info(buf):
    i = {}
    i.update({'total_allocation_units': struct.unpack_from('<Q', buf, 0)[0]})
    i.update({'caller_available_allocation_units': struct.unpack_from('<Q', buf, 8)[0]})
    i.update({'actual_available_allocation_units': struct.unpack_from('<Q', buf, 16)[0]})
    i.update({'sectors_per_allocation_unit': struct.unpack_from('<I', buf, 24)[0]})
    i.update({'bytes_per_sector': struct.unpack_from('<I', buf, 28)[0]})

    return i

    
dir_coders = {
    FSInfoClass.VOLUME: (encode_volume_info,
                         decode_volume_info),
    FSInfoClass.DEVICE: (encode_device_info,
                         decode_device_info),
    FSInfoClass.ATTRIBUTE: (encode_attribute_info,
                            decode_attribute_info),
    FSInfoClass.SECTOR_SIZE: (encode_sector_size_info,
                              decode_sector_size_info),
    FSInfoClass.FULL_SIZE: (encode_full_size_info,
                            decode_full_size_info),
    }

class FSInfo(object):
    """
    A class for FSInfo
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(dic, buf):
        if dic in dir_coders:
            info = dir_coders[dic][1](buf)
            return info
        
        print('Unknown FSInfoClass', dic)
        return []

    @staticmethod
    def encode(dic, info):
        if dic in dir_coders:
            buf = dir_coders[dic][0](info)
            return buf

        print('Unknown FSInfoClass', dic)
        return bytearray(0)
