# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct

#
# UCS2toUTF8
#

def _ucs2_cp_size(cp):
    if cp > 0x07ff:
        return 3
    if cp > 0x007f:
        return 2
    return 1


def UCS2toUTF8(ucs2):
    def ucs2_to_utf8(cp):
        _len = _ucs2_cp_size(cp)
        utf8 = bytearray(_len)
        if _len == 3:
            struct.pack_into('<BBB', utf8, 0,
                             0xe0 |  (cp >> 12),
                             0x80 | ((cp >>  6) & 0xbf),
                             0x80 | ((cp      ) & 0xbf) )
        if _len == 2:
            struct.pack_into('<BB', utf8, 0,
                             0xc0 |  (cp >> 6),
                             0x80 | ((cp     ) & 0xbf) )
        if _len == 1:
            struct.pack_into('<B', utf8, 0, cp)
            
        return utf8

    _len = len(ucs2) >> 1
    u = struct.unpack_from('<' + 'H' * _len, ucs2, 0)
    
    utf8 = bytearray(0)
    for cp in u:
        utf8 = utf8 + ucs2_to_utf8(cp)

    return utf8

def UTF8toUCS2(utf8):
    def l1(u):
        l = 0
        while u & 0x80:
            l = l + 1
            u = u >> 1

        return l

    def decode_utf8(utf8):
        u = bytearray(2)
        l = l1(utf8[0])
        if l == 0:
            struct.pack_into('<H', u, 0, utf8[0])
            return utf8[1:], u
        if l == 1:
            print('UTF8 cp can not start with a 0x80 byte')
            raise ValueError
        if l == 2:
            v = utf8[0] & 0x1f
            v = (v << 6) | (utf8[1] & 0x3f)
            struct.pack_into('<H', u, 0, v)
            return utf8[2:], u
        if l == 3:
            v = utf8[0] & 0x1f
            v = (v << 6) | (utf8[1] & 0x3f)
            v = (v << 6) | (utf8[2] & 0x3f)
            struct.pack_into('<H', u, 0, v)
            return utf8[3:], u

        return utf8[1:], u
    
    ucs2 = bytearray(0)

    if isinstance(utf8, str):
        utf8 = bytes(utf8, encoding='utf-8')

    while len(utf8):
        utf8, u = decode_utf8(utf8)
        ucs2 = ucs2 + u

    return ucs2
