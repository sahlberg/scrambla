# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# SMB2 FILE INFORMATION CLASSES
#

#
# INFO CLASS
#
class FileInfoClass(Enum):
    BASIC_INFORMATION             = 0x04
    STANDARD_INFORMATION          = 0x05
    INTERNAL_INFORMATION          = 0x06
    EA_INFORMATION                = 0x07
    ACCESS_INFORMATION            = 0x08
    NAME_INFORMATION              = 0x09
    RENAME_INFORMATION            = 0x0a
    DISPOSITION_INFORMATION       = 0x0d
    POSITION_INFORMATION          = 0x0e
    MODE_INFORMATION              = 0x10
    ALIGNMENT_INFORMATION         = 0x11
    ALL_INFORMATION               = 0x12
    END_OF_FILE_INFORMATION       = 0x14

def decode_basic_info(buf):
    info = {}
    info.update({'creation_time': WinToTimeval(struct.unpack_from('<Q', buf, 0)[0])})
    info.update({'last_access_time': WinToTimeval(struct.unpack_from('<Q', buf, 8)[0])})
    info.update({'last_write_time': WinToTimeval(struct.unpack_from('<Q', buf, 16)[0])})
    info.update({'change_time': WinToTimeval(struct.unpack_from('<Q', buf, 24)[0])})
    info.update({'file_attributes': struct.unpack_from('<I', buf, 32)[0]})
    
    return info

def encode_basic_info(info):
    buf = bytearray(40)
    struct.pack_into('<Q', buf,  0, TimevalToWin(info['creation_time']))
    struct.pack_into('<Q', buf,  8, TimevalToWin(info['last_access_time']))
    struct.pack_into('<Q', buf, 16, TimevalToWin(info['last_write_time']))
    struct.pack_into('<Q', buf, 24, TimevalToWin(info['change_time']))
    struct.pack_into('<I', buf, 32, info['file_attributes'])
    return buf

def decode_standard_info(buf):
    info = {}
    info.update({'allocation_size': struct.unpack_from('<Q', buf, 0)[0]})
    info.update({'end_of_file': struct.unpack_from('<Q', buf, 8)[0]})
    info.update({'number_of_links': struct.unpack_from('<I', buf, 16)[0]})
    info.update({'delete_pending': struct.unpack_from('<B', buf, 20)[0]})
    info.update({'directory': struct.unpack_from('<B', buf, 21)[0]})
    return info

def encode_standard_info(info):
    buf = bytearray(24)
    struct.pack_into('<Q', buf, 0, info['allocation_size'])
    struct.pack_into('<Q', buf, 8, info['end_of_file'])
    struct.pack_into('<I', buf, 16, info['number_of_links'])
    struct.pack_into('<B', buf, 20, info['delete_pending'])
    struct.pack_into('<B', buf, 21, info['directory'])
    return buf

def decode_internal_info(buf):
    info = {}
    info.update({'index_number': struct.unpack_from('<Q', buf, 0)[0]})
    return info

def encode_internal_info(info):
    buf = bytearray(8)
    struct.pack_into('<Q', buf, 0, info['index_number'])
    return buf

def decode_ea_info(buf):
    info = {}
    info.update({'ea_size': struct.unpack_from('<I', buf, 0)[0]})
    return info

def encode_ea_info(info):
    buf = bytearray(4)
    struct.pack_into('<I', buf, 0, info['ea_size'])
    return buf

def decode_access_info(buf):
    info = {}
    info.update({'access_flags': struct.unpack_from('<I', buf, 0)[0]})
    return info

def encode_access_info(info):
    buf = bytearray(4)
    struct.pack_into('<I', buf, 0, info['access_flags'])
    return buf

def decode_rename_info(buf):
    info = {}
    info.update({'replace_if_exists': struct.unpack_from('<B', buf, 0)[0]})
    _len = struct.unpack_from('<I', buf, 16)[0]
    info.update({'filename': UCS2toUTF8(buf[20:20 + _len])})
    return info

def encode_rename_info(info):
    buf = bytearray(20)
    struct.pack_into('<B', buf, 0, info['replace_if_exists'])
    _fn = UTF8toUCS2(info['filename'])
    struct.pack_into('<I', buf, 16, len(_fn))
    buf = buf + _fn
    return buf

def decode_position_info(buf):
    info = {}
    info.update({'current_byte_offset': struct.unpack_from('<Q', buf, 0)[0]})
    return info

def encode_position_info(info):
    buf = bytearray(8)
    struct.pack_into('<Q', buf, 0, info['current_byte_offset'])
    return buf

def decode_mode_info(buf):
    info = {}
    info.update({'mode': struct.unpack_from('<I', buf, 0)[0]})
    return info

def encode_mode_info(info):
    buf = bytearray(4)
    struct.pack_into('<I', buf, 0, info['mode'])
    return buf

def decode_alignment_info(buf):
    info = {}
    info.update({'alignment_requirement': struct.unpack_from('<I', buf, 0)[0]})
    return info

def encode_alignment_info(info):
    buf = bytearray(4)
    struct.pack_into('<I', buf, 0, info['alignment_requirement'])
    return buf

def decode_name_info(buf):
    info = {}
    _len = struct.unpack_from('<I', buf, 0)[0]
    if _len:
        info.update({'name': UCS2toUTF8(buf[4:4 + _len])})
    return info

def encode_name_info(info):
    buf = bytearray(4)
    if 'name' in info:
        _c = UTF8toUCS2(hdr['name'])
        struct.pack_into('<I', buf, 0, len(_c))
        buf = buf + _c
    return buf

def decode_all_info(buf):
    info = {}
    info.update(decode_basic_info(buf[:40]))
    info.update(decode_standard_info(buf[40:64]))
    info.update(decode_internal_info(buf[64:72]))
    info.update(decode_ea_info(buf[72:76]))
    info.update(decode_access_info(buf[76:80]))
    info.update(decode_position_info(buf[80:88]))
    info.update(decode_mode_info(buf[88:92]))
    info.update(decode_alignment_info(buf[92:96]))
    info.update(decode_name_info(buf[96:]))
    return info

def encode_all_info(info):
    buf = bytearray(0)
    buf = buf + encode_basic_info(info)
    buf = buf + encode_standard_info(info)
    buf = buf + encode_internal_info(info)
    buf = buf + encode_ea_info(info)
    buf = buf + encode_access_info(info)
    buf = buf + encode_position_info(info)
    buf = buf + encode_mode_info(info)
    buf = buf + encode_alignment_info(info)
    buf = buf + encode_name_info(info)
    return buf

def decode_disposition_info(buf):
    info = {}
    info.update({'delete_pending': struct.unpack_from('<B', buf, 0)[0]})
    
    return info

def encode_disposition_info(info):
    buf = bytearray(8)
    struct.pack_into('<B', buf, 0, info['delete_pending'])
    return buf

def decode_end_of_file_info(buf):
    info = {}
    info.update({'end_of_file': struct.unpack_from('<Q', buf, 0)[0]})
    
    return info

def encode_end_of_file_info(info):
    buf = bytearray(8)
    struct.pack_into('<Q', buf, 0, info['end_of_file'])
    return buf


file_coders = {
    FileInfoClass.BASIC_INFORMATION: (encode_basic_info, decode_basic_info),
    FileInfoClass.STANDARD_INFORMATION: (encode_standard_info, decode_standard_info),
    FileInfoClass.INTERNAL_INFORMATION: (encode_internal_info, decode_internal_info),
    FileInfoClass.EA_INFORMATION: (encode_ea_info, decode_ea_info),
    FileInfoClass.ACCESS_INFORMATION: (encode_access_info, decode_access_info),
    FileInfoClass.RENAME_INFORMATION: (encode_rename_info, decode_rename_info),
    FileInfoClass.POSITION_INFORMATION: (encode_position_info, decode_position_info),
    FileInfoClass.MODE_INFORMATION: (encode_mode_info, decode_mode_info),
    FileInfoClass.ALIGNMENT_INFORMATION: (encode_alignment_info, decode_alignment_info),
    FileInfoClass.NAME_INFORMATION: (encode_name_info, decode_name_info),
    FileInfoClass.ALL_INFORMATION: (encode_all_info, decode_all_info),
    FileInfoClass.DISPOSITION_INFORMATION: (encode_disposition_info, decode_disposition_info),
    FileInfoClass.END_OF_FILE_INFORMATION: (encode_end_of_file_info, decode_end_of_file_info),
    }

class FileInfo(object):
    """
    A class for FileInfo
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(fic, buf):
        if fic in file_coders:
            return file_coders[fic][1](buf)

        print('Unknown FileInfoClass', fic)
        return {}
        
    @staticmethod
    def encode(fic, info):
        if fic in file_coders:
            return file_coders[fic][0](info)

        print('Unknown FileInfoClass', fic)
        return bytearray(0)
    
