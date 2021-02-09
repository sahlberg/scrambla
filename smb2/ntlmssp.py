# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.timestamps import WinToTimeval, TimevalToWin
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# NTLMSSP
#

#
# MESSAGE TYPES
#
NTLM_NEGOTIATE    = 0x00000001
NTLM_CHALLENGE    = 0x00000002
NTLM_AUTHENTICATE = 0x00000003

#
# NEGOTIATE FLAGS
#
NEGOTIATE_FLAG_W   = 0x80000000 # 56-bit encryption
NEGOTIATE_FLAG_V   = 0x40000000 # key exchange
NEGOTIATE_FLAG_U   = 0x20000000 # 128-bit session key
NEGOTIATE_FLAG_R1  = 0x10000000
NEGOTIATE_FLAG_R2  = 0x08000000
NEGOTIATE_FLAG_R3  = 0x04000000
NEGOTIATE_FLAG_T   = 0x02000000 # Protocol Version number is present
NEGOTIATE_FLAG_R4  = 0x01000000
NEGOTIATE_FLAG_S   = 0x00800000 # Target Info is present
NEGOTIATE_FLAG_R   = 0x00400000
NEGOTIATE_FLAG_R5  = 0x00200000
NEGOTIATE_FLAG_Q   = 0x00100000
NEGOTIATE_FLAG_P   = 0x00080000 # NTLMv2
NEGOTIATE_FLAG_R6  = 0x00040000
NEGOTIATE_FLAG_O   = 0x00020000 # Target Name is server
NEGOTIATE_FLAG_N   = 0x00010000
NEGOTIATE_FLAG_M   = 0x00008000
NEGOTIATE_FLAG_R7  = 0x00004000
NEGOTIATE_FLAG_L   = 0x00002000
NEGOTIATE_FLAG_K   = 0x00001000
NEGOTIATE_FLAG_J   = 0x00000800
NEGOTIATE_FLAG_R8  = 0x00000400
NEGOTIATE_FLAG_H   = 0x00000200 # NTLMv1
NEGOTIATE_FLAG_R9  = 0x00000100
NEGOTIATE_FLAG_G   = 0x00000080
NEGOTIATE_FLAG_F   = 0x00000040
NEGOTIATE_FLAG_E   = 0x00000020 # Seal
NEGOTIATE_FLAG_D   = 0x00000010
NEGOTIATE_FLAG_R10 = 0x00000008
NEGOTIATE_FLAG_C   = 0x00000004 # Target Name
NEGOTIATE_FLAG_B   = 0x00000002 # OEM character set
NEGOTIATE_FLAG_A   = 0x00000001 # Unicode

#
# NTLM REVISION
#
NTLMSSP_REVISION_W2K3 = 0x0f

#
# AV IDS
#
MS_AV_EOL               = 0x0000
MS_AV_NB_COMPUTER_NAME  = 0x0001
MS_AV_NB_DOMAIN_NAME    = 0x0002
MS_AV_DNS_COMPUTER_NAME = 0x0003
MS_AV_DNS_DOMAIN_NAME   = 0x0004
MS_AV_DNS_TREE_NAME     = 0x0005
MS_AV_FLAGS             = 0x0006
MS_AV_TIMESTAMP         = 0x0007
MS_AV_SINGLE_HOST       = 0x0008
MS_AV_TARGET_NAME       = 0x0009
MS_AV_CHANNEL_BINDINGS  = 0x000a


class NTLMSSP(object):
    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(buf):
        nt = {}
        if not buf[:7].decode() == 'NTLMSSP':
            return nt
        nt.update({'message_type': struct.unpack_from('<I', buf, 8)[0]})
        if nt['message_type'] == NTLM_NEGOTIATE:
            nt.update({'negotiate_flags': struct.unpack_from('<I', buf, 12)[0]})
            _len = struct.unpack_from('<H', buf, 16)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 20)[0]
                nt.update({'domain_name': UCS2toUTF8(buf[_offset:_offset + _len])})
            _len = struct.unpack_from('<H', buf, 24)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 28)[0]
                nt.update({'workstation': UCS2toUTF8(buf[_offset:_offset + _len])})
            if nt['negotiate_flags'] & NEGOTIATE_FLAG_T:
                nt.update({'product_major_version': struct.unpack_from('<B', buf, 32)[0]})
                nt.update({'product_minor_version': struct.unpack_from('<B', buf, 33)[0]})
                nt.update({'product_build': struct.unpack_from('<H', buf, 34)[0]})
                nt.update({'ntlm_revision_current': struct.unpack_from('<B', buf, 39)[0]})

        if nt['message_type'] == NTLM_CHALLENGE:
            _len = struct.unpack_from('<H', buf, 12)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 16)[0]
                nt.update({'target_name': UCS2toUTF8(buf[_offset:_offset + _len])})
            nt.update({'negotiate_flags': struct.unpack_from('<I', buf, 20)[0]})
            nt.update({'server_challenge': buf[24:32]})

            _len = struct.unpack_from('<H', buf, 40)[0]
            if _len:
                _t = {}
                _offset = struct.unpack_from('<I', buf, 44)[0]
                _ti = buf[_offset:_offset + _len]
                while _ti:
                    _id = struct.unpack_from('<H', _ti, 0)[0]
                    _len = struct.unpack_from('<H', _ti, 2)[0]
                    if _id == MS_AV_EOL:
                        break
                    if _id == MS_AV_NB_DOMAIN_NAME:
                        _t.update({'nb_domain_name':
                                   UCS2toUTF8(_ti[4:4 + _len])})
                    if _id == MS_AV_NB_COMPUTER_NAME:
                        _t.update({'nb_computer_name':
                                   UCS2toUTF8(_ti[4:4 + _len])})
                    if _id == MS_AV_DNS_DOMAIN_NAME:
                        _t.update({'dns_domain_name':
                                   UCS2toUTF8(_ti[4:4 + _len])})
                    if _id == MS_AV_DNS_COMPUTER_NAME:
                        _t.update({'dns_computer_name':
                                   UCS2toUTF8(_ti[4:4 + _len])})
                    if _id == MS_AV_DNS_TREE_NAME:
                        _t.update({'dns_tree_name':
                                   UCS2toUTF8(_ti[4:4 + _len])})
                    if _id == MS_AV_TIMESTAMP:
                        _t.update({'timestamp': WinToTimeval(struct.unpack_from('<Q', _ti, 4)[0])})
                    if _id == MS_AV_TARGET_NAME:
                        _t.update({'target_name':
                                   UCS2toUTF8(_ti[4:4 + _len])})
                    if _id == MS_AV_FLAGS:
                        _t.update({'flags': struct.unpack_from('<I', _ti, 4)[0]})
                    if _id == MS_AV_CHANNEL_BINDINGS:
                        _t.update({'channel_bindings': _ti[4:4 + _len]})
                    if _id == MS_AV_SINGLE_HOST:
                        _t.update({'single_host': _ti[4:4 + _len]})

                    _ti = _ti[4 + _len:]
                nt['target_info'] = _t

            if nt['negotiate_flags'] & NEGOTIATE_FLAG_T:
                nt.update({'product_major_version': struct.unpack_from('<B', buf, 48)[0]})
                nt.update({'product_minor_version': struct.unpack_from('<B', buf, 49)[0]})
                nt.update({'product_build': struct.unpack_from('<H', buf, 50)[0]})
                nt.update({'ntlm_revision_current': struct.unpack_from('<B', buf, 55)[0]})

        if nt['message_type'] == NTLM_AUTHENTICATE:
            _len = struct.unpack_from('<H', buf, 12)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 16)[0]
                nt.update({'lm_challenge_response': buf[_offset:_offset + _len]})
            _len = struct.unpack_from('<H', buf, 20)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 24)[0]
                nt.update({'nt_challenge_response': buf[_offset:_offset + _len]})
            _len = struct.unpack_from('<H', buf, 28)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 32)[0]
                nt.update({'domain_name': UCS2toUTF8(buf[_offset:_offset + _len])})
            _len = struct.unpack_from('<H', buf, 36)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 40)[0]
                nt.update({'user_name': UCS2toUTF8(buf[_offset:_offset + _len])})
            _len = struct.unpack_from('<H', buf, 44)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 48)[0]
                nt.update({'workstation': UCS2toUTF8(buf[_offset:_offset + _len])})
            _len = struct.unpack_from('<H', buf, 52)[0]
            if _len:
                _offset = struct.unpack_from('<I', buf, 56)[0]
                nt.update({'encrypted_random_session_key': buf[_offset:_offset + _len]})
            nt.update({'flags': struct.unpack_from('<I', buf, 60)[0]})
            if nt['flags'] & NEGOTIATE_FLAG_T:
                nt.update({'product_major_version': struct.unpack_from('<B', buf, 64)[0]})
                nt.update({'product_minor_version': struct.unpack_from('<B', buf, 65)[0]})
                nt.update({'product_build': struct.unpack_from('<H', buf, 66)[0]})
                nt.update({'ntlm_revision_current': struct.unpack_from('<B', buf, 71)[0]})

        return nt

    @staticmethod
    def encode(nt):
        if nt['message_type'] == NTLM_NEGOTIATE:
            buf = bytearray(40)
            buf[:7] = bytearray('NTLMSSP'.encode())
            struct.pack_into('<I', buf, 8, nt['message_type'])
            struct.pack_into('<I', buf, 12, nt['negotiate_flags'])
            if 'domain_name' in nt:
                _dn = UTF8toUCS2(nt['domain_name'])
                struct.pack_into('<H', buf, 16, len(_dn))
                struct.pack_into('<H', buf, 18, len(_dn))
                struct.pack_into('<I', buf, 20, len(buf))
                buf = buf + _dn
            if 'workstation' in nt:
                _w = UTF8toUCS2(nt['workstation'])
                struct.pack_into('<H', buf, 24, len(_w))
                struct.pack_into('<H', buf, 26, len(_w))
                struct.pack_into('<I', buf, 28, len(buf))
                buf = buf + _w
            if nt['negotiate_flags'] & NEGOTIATE_FLAG_T:
                struct.pack_into('<B', buf, 32, nt['product_major_version'])
                struct.pack_into('<B', buf, 33, nt['product_minor_version'])
                struct.pack_into('<H', buf, 34, nt['product_build'])
                struct.pack_into('<B', buf, 39, nt['ntlm_revision_current'])
            return buf

        if nt['message_type'] == NTLM_CHALLENGE:
            buf = bytearray(56)
            buf[:7] = bytearray('NTLMSSP'.encode())
            struct.pack_into('<I', buf, 8, nt['message_type'])
            if 'target_name' in nt:
                _tn = UTF8toUCS2(nt['target_name'])
                struct.pack_into('<H', buf, 12, len(_tn))
                struct.pack_into('<H', buf, 14, len(_tn))
                struct.pack_into('<I', buf, 16, len(buf))
                buf = buf + _tn
            struct.pack_into('<I', buf, 20, nt['negotiate_flags'])
            buf[24:32] = nt['server_challenge']
            if 'target_info' in nt:
                _ti = bytearray(0)
                if 'nb_domain_name' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = UTF8toUCS2(nt['target_info']['nb_domain_name'])
                    struct.pack_into('<H', _i, 0, MS_AV_NB_DOMAIN_NAME)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'nb_computer_name' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = UTF8toUCS2(nt['target_info']['nb_computer_name'])
                    struct.pack_into('<H', _i, 0, MS_AV_NB_COMPUTER_NAME)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'dns_domain_name' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = UTF8toUCS2(nt['target_info']['dns_domain_name'])
                    struct.pack_into('<H', _i, 0, MS_AV_DNS_DOMAIN_NAME)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'dns_computer_name' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = UTF8toUCS2(nt['target_info']['dns_computer_name'])
                    struct.pack_into('<H', _i, 0, MS_AV_DNS_COMPUTER_NAME)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'dns_tree_name' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = UTF8toUCS2(nt['target_info']['dns_tree_name'])
                    struct.pack_into('<H', _i, 0, MS_AV_DNS_TREE_NAME)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'timestamp' in nt['target_info']:
                    _i = bytearray(12)
                    _nbn = TimevalToWin(nt['target_info']['timestamp'])
                    struct.pack_into('<H', _i, 0, MS_AV_TIMESTAMP)
                    struct.pack_into('<H', _i, 2, 8)
                    struct.pack_into('<Q', _i, 4, _nbn)
                    _ti = _ti + _i
                if 'target_name' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = UTF8toUCS2(nt['target_info']['target_name'])
                    struct.pack_into('<H', _i, 0, MS_AV_TARGET_NAME)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'flags' in nt['target_info']:
                    _i = bytearray(12)
                    _nbn = TimevalToWin(nt['target_info']['flags'])
                    struct.pack_into('<H', _i, 0, MS_AV_FLAGS)
                    struct.pack_into('<H', _i, 2, 4)
                    struct.pack_into('<I', _i, 4, _nbn)
                    _ti = _ti + _i
                if 'channel_bindings' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = nt['target_info']['channel_bindings']
                    struct.pack_into('<H', _i, 0, MS_AV_CHANNEL_BINDINGS)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i
                if 'single_host' in nt['target_info']:
                    _i = bytearray(4)
                    _nbn = nt['target_info']['single_host']
                    struct.pack_into('<H', _i, 0, MS_AV_SINGLE_HOST)
                    struct.pack_into('<H', _i, 2, len(_nbn))
                    _i = _i + _nbn
                    _ti = _ti + _i

                _ti = _ti + bytearray(4)
                
                struct.pack_into('<H', buf, 40, len(_ti))
                struct.pack_into('<H', buf, 42, len(_ti))
                struct.pack_into('<I', buf, 44, len(buf))
                buf = buf + _ti
            if nt['negotiate_flags'] & NEGOTIATE_FLAG_T:
                struct.pack_into('<B', buf, 48, nt['product_major_version'])
                struct.pack_into('<B', buf, 49, nt['product_minor_version'])
                struct.pack_into('<H', buf, 50, nt['product_build'])
                struct.pack_into('<B', buf, 55, nt['ntlm_revision_current'])

            return buf
        
        if nt['message_type'] == NTLM_AUTHENTICATE:
            buf = bytearray(64)
            buf[:7] = bytearray('NTLMSSP'.encode())
            struct.pack_into('<I', buf, 8, nt['message_type'])

            struct.pack_into('<I', buf, 60, nt['flags'])
            if nt['flags'] & NEGOTIATE_FLAG_T:
                buf = buf + bytearray(8)
                struct.pack_into('<B', buf, 64, nt['product_major_version'])
                struct.pack_into('<B', buf, 65, nt['product_minor_version'])
                struct.pack_into('<H', buf, 66, nt['product_build'])
                struct.pack_into('<B', buf, 71, nt['ntlm_revision_current'])

            struct.pack_into('<I', buf, 16, len(buf))
            if 'lm_challenge_response' in nt:
                struct.pack_into('<H', buf, 12, len(nt['lm_challenge_response']))
                struct.pack_into('<H', buf, 14, len(nt['lm_challenge_response']))
                buf = buf + nt['lm_challenge_response']

            struct.pack_into('<I', buf, 24, len(buf))
            if 'nt_challenge_response' in nt:
                struct.pack_into('<H', buf, 20, len(nt['nt_challenge_response']))
                struct.pack_into('<H', buf, 22, len(nt['nt_challenge_response']))
                buf = buf + nt['nt_challenge_response']
                
            struct.pack_into('<I', buf, 32, len(buf))
            if 'domain_name' in nt:
                _nd = UTF8toUCS2(nt['domain_name'])
                struct.pack_into('<H', buf, 28, len(_dn))
                struct.pack_into('<H', buf, 30, len(_dn))
                buf = buf + _dn

            struct.pack_into('<I', buf, 40, len(buf))
            if 'user_name' in nt:
                _nd = UTF8toUCS2(nt['user_name'])
                struct.pack_into('<H', buf, 36, len(_nd))
                struct.pack_into('<H', buf, 38, len(_nd))
                buf = buf + _nd
                
            struct.pack_into('<I', buf, 48, len(buf))
            if 'workstation' in nt:
                _nd = UTF8toUCS2(nt['workstation'])
                struct.pack_into('<H', buf, 44, len(_nd))
                struct.pack_into('<H', buf, 46, len(_nd))
                buf = buf + _nd
                
            struct.pack_into('<I', buf, 56, len(buf))
            if 'encrypted_random_session_key' in nt:
                struct.pack_into('<H', buf, 52, len(nt['encrypted_random_session_key']))
                struct.pack_into('<H', buf, 54, len(nt['encrypted_random_session_key']))
                buf = buf + nt['encrypted_random_session_key']
                
            return buf
