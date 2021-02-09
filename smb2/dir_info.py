# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# SMB2 DIR INFORMATION CLASSES
#

class DirInfoClass(Enum):
    FILE_ID_FULL_INFORMATION = 0x26
    

def encode_file_id_full_dir_info(i):
    _b = bytearray(80)
    struct.pack_into('<I', _b, 4, i['file_index'])
    struct.pack_into('<Q', _b, 8, TimevalToWin(i['creation_time']))
    struct.pack_into('<Q', _b, 16, TimevalToWin(i['last_access_time']))
    struct.pack_into('<Q', _b, 24, TimevalToWin(i['last_write_time']))
    struct.pack_into('<Q', _b, 32, TimevalToWin(i['change_time']))
    struct.pack_into('<Q', _b, 40, i['end_of_file'])
    struct.pack_into('<Q', _b, 48, i['allocation_size'])
    struct.pack_into('<I', _b, 56, i['file_attributes'])
    struct.pack_into('<I', _b, 64, i['ea_size'])
    struct.pack_into('<Q', _b, 72, i['file_id'])

    _fn = UTF8toUCS2(i['file_name'])
    struct.pack_into('<I', _b, 60, len(_fn))
    _b = _b + _fn

    _len = len(_b)
    if _len % 8:
        _pad = ((_len + 7) & 0xfff8) - _len
        _b = _b + bytearray(_pad)

    return _b

def decode_file_id_full_dir_info(buf):
    i = {}
    i.update({'file_index': struct.unpack_from('<I', buf, 4)[0]})
    i.update({'creation_time': WinToTimeval(struct.unpack_from('<Q', buf, 8)[0])})
    i.update({'last_access_time': WinToTimeval(struct.unpack_from('<Q', buf, 16)[0])})
    i.update({'last_write_time': WinToTimeval(struct.unpack_from('<Q', buf, 24)[0])})
    i.update({'change_time': WinToTimeval(struct.unpack_from('<Q', buf, 32)[0])})
    i.update({'end_of_file': struct.unpack_from('<Q', buf, 40)[0]})
    i.update({'allocation_size': struct.unpack_from('<Q', buf, 48)[0]})
    i.update({'file_attributes': struct.unpack_from('<I', buf, 56)[0]})
    i.update({'ea_size': struct.unpack_from('<I', buf, 64)[0]})
    i.update({'file_id': struct.unpack_from('<Q', buf, 72)[0]})

    _fnl = struct.unpack_from('<I', buf, 60)[0]
    i.update({'file_name': UCS2toUTF8(buf[80:80 + _fnl])})

    return i

    
dir_coders = {
    DirInfoClass.FILE_ID_FULL_INFORMATION: (encode_file_id_full_dir_info,
                                            decode_file_id_full_dir_info),
    }

class DirInfo(object):
    """
    A class for DirInfo
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(dic, buf):
        if dic in dir_coders:
            info = []
            while buf:
                _next = struct.unpack_from('<I', buf, 0)[0]

                i = dir_coders[dic][1](buf)
                info.append(i)

                if _next:
                    buf = buf[_next:]
                else:
                    buf = []
            return info
        
        print('Unknown DirInfoClass', dic)
        return {}

    @staticmethod
    def encode_single(dic, info):
        if dic in dir_coders:
            buf = dir_coders[dic][0](info)
            struct.pack_into('<I', buf, 0, len(buf))
            return buf
    
    @staticmethod
    def encode(dic, info):
        if dic in dir_coders:
            buf = bytearray(0)

            while info:
                _i = info[0]
                _b = dir_coders[dic][0](_i)
        
                info = info[1:]
                if info:
                    struct.pack_into('<I', _b, 0, len(_b))
            
                buf = buf + _b

            return buf

        print('Unknown DirInfoClass', dic)
        return bytearray(0)
