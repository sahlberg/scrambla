# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin

#
# SMB2 Negotiate_Protocol
#

VERSION_0202 = 0x0202
VERSION_0210 = 0x0210
VERSION_0300 = 0x0300
VERSION_0302 = 0x0302
VERSION_0311 = 0x0311

#
# Negotiate Context Types
#
SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
SMB2_ENCRYPTION_CAPABILITIES        = 0x0002
SMB2_COMPRESSION_CAPABILITIES       = 0x0003

#
# Hashes
#
SHA_512 = 0x0001

#
# Encryption Types
#
AES_128_CCM = 0x0001
AES_128_GCM = 0x0002
AES_256_CCM = 0x0003
AES_256_GCM = 0x0004

#
# Compression Types
#
COMPRESSION_NONE       = 0x0000
COMPRESSION_LZNT1      = 0x0001
COMPRESSION_LZ77       = 0x0002
COMPRESSION_LZ77_H     = 0x0003
COMPRESSION_PATTERN_V1 = 0x0004

#
# Capabilities
#
SMB2_GLOBAL_CAP_DFS                = 0x00000001
SMB2_GLOBAL_CAP_LEASING            = 0x00000002
SMB2_GLOBAL_CAP_LARGE_MTU          = 0x00000004
SMB2_GLOBAL_CAP_MULTI_CHANNEL      = 0x00000008
SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
SMB2_GLOBAL_CAP_DIRECTORY_LEASING  = 0x00000020
SMB2_GLOBAL_CAP_ENCRYPTION         = 0x00000040


def _decode_context(context):
    if context['context_type'] == SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
        _count = struct.unpack_from('<H', context['data'], 0)[0]
        _len = struct.unpack_from('<H', context['data'], 2)[0]
        context.update({'hash_algorithms': []})
        for i in range(_count):
            context['hash_algorithms'].append(struct.unpack_from('<H', context['data'], 4 + i * 2)[0])
        context.update({'salt': context['data'][4 + _count * 2:4 + _count * 2 + _len]})
        del context['data']
        return
        
    if context['context_type'] == SMB2_ENCRYPTION_CAPABILITIES:
        _count = struct.unpack_from('<H', context['data'], 0)[0]
        context.update({'ciphers': []})
        for i in range(_count):
            context['ciphers'].append(struct.unpack_from('<H', context['data'], 2 + i * 2)[0])
        del context['data']
        return
        
    if context['context_type'] == SMB2_COMPRESSION_CAPABILITIES:
        _count = struct.unpack_from('<H', context['data'], 0)[0]
        context.update({'flags': struct.unpack_from('<I', context['data'], 4)[0]})
        context.update({'compression_algorithms': []})
        for i in range(_count):
            context['compression_algorithms'].append(struct.unpack_from('<H', context['data'], 8 + i * 2)[0])
        del context['data']
        return

def _decode_contexts(buf, count):
    contexts = {}
    for _ in range(count):
        _type = struct.unpack_from('<H', buf, 0)[0]
        _len = struct.unpack_from('<H', buf, 2)[0]

        context = {}
        context.update({'context_type': _type})
        context.update({'data': buf[8:_len + 8]})
        _decode_context(context)
        contexts.update({_type: context})

        buf = buf[((_len + 7) & 0xfff8) + 8:]
    return contexts

def _encode_context(context):
    if context['context_type'] == SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
        buf = bytearray(8 + 4)
        struct.pack_into('<H', buf, 8, len(context['hash_algorithms']))
        struct.pack_into('<H', buf, 10, len(context['salt']))
        for _a in context['hash_algorithms']:
            _tmp = bytearray(2)
            struct.pack_into('<H', _tmp, 0, _a)
            buf = buf + _tmp

        buf = buf + context['salt']

        struct.pack_into('<H', buf, 0, context['context_type'])
        struct.pack_into('<H', buf, 2, len(buf) - 8)
        return buf

    if context['context_type'] == SMB2_ENCRYPTION_CAPABILITIES:
        buf = bytearray(8 + 2)
        struct.pack_into('<H', buf, 8, len(context['ciphers']))
        for _a in context['ciphers']:
            _tmp = bytearray(2)
            struct.pack_into('<H', _tmp, 0, _a)
            buf = buf + _tmp
        
        struct.pack_into('<H', buf, 0, context['context_type'])
        struct.pack_into('<H', buf, 2, len(buf) - 8)
        return buf

    if context['context_type'] == SMB2_COMPRESSION_CAPABILITIES:
        buf = bytearray(8 + 8)
        struct.pack_into('<H', buf, 8, len(context['compression_algorithms']))
        struct.pack_into('<I', buf, 12, context['flags'])
        
        for _a in context['compression_algorithms']:
            _tmp = bytearray(2)
            struct.pack_into('<H', _tmp, 0, _a)
            buf = buf + _tmp
        
        struct.pack_into('<H', buf, 0, context['context_type'])
        struct.pack_into('<H', buf, 2, len(buf) - 8)
        return buf

    # unknown, just send the 'data' blob as is
    buf = bytearray(8)
    buf = buf + context['data']
    struct.pack_into('<H', buf, 0, context['context_type'])
    struct.pack_into('<H', buf, 2, len(buf) - 8)
    return buf
    
def _encode_contexts(contexts):
    buf = bytearray(0)
    for context in contexts.values():
        # Add padding if we need to
        _len = len(buf)
        if _len % 8:
            _pad = ((_len + 7) & 0xfff8) - _len
            buf = buf + bytearray(_pad)

        buf = buf + _encode_context(context)

    return buf

def _decode_request(hdr):
    """
    Decode a Negotiate_Protocol request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'security_mode': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'capabilities': struct.unpack_from('<I', hdr, 8)[0]})
    result.update({'client_guid': hdr[12:12 + 16]})

    # Dialects
    _num = struct.unpack_from('<H', hdr, 2)[0]
    result.update({'dialects': []})
    for i in range(_num):
        result['dialects'].append(struct.unpack_from('<H', hdr, 36 + i *2)[0])
    if (VERSION_0311 in result['dialects']):
        # Negotiate Context Offset and Count
        _offset = struct.unpack_from('<I', hdr, 28)[0] - 64
        _num = struct.unpack_from('<H', hdr, 32)[0]

        if _num:
            result.update({'contexts': _decode_contexts(hdr[_offset:], _num)})

    return result

def _encode_request(hdr):
    """
    Encode a Negotiate_Protocol request
    """
    result = bytearray(36)
    struct.pack_into('<H', result, 0, 36)
    struct.pack_into('<I', result, 4, hdr['security_mode'])
    struct.pack_into('<I', result, 8, hdr['capabilities'])
    if 'client_guid' in hdr:
        result[12:12 + 16] = hdr['client_guid']

    # Dialects
    _num = len(hdr['dialects'])
    struct.pack_into('<H', result, 2, _num)
    result.extend(bytearray(_num * 2))
    for i in range(_num):
        struct.pack_into('<H', result, 36 + i *2, hdr['dialects'][i])
    
    if 'contexts' in hdr:
        # The contexts are padded to start on 8 byte boundary
        _len = len(result)
        if _len % 8:
            _pad = ((_len + 7) & 0xfff8) - _len
            result.extend(bytearray(_pad))

        # Negotiate Context Offset and Count
        struct.pack_into('<I', result, 28, len(result) + 64)
        struct.pack_into('<H', result, 32, len(hdr['contexts']))

        # Encode the actual contexts
        result = result + _encode_contexts(hdr['contexts'])

    return result

def _decode_reply(hdr):
    """
    Decode a Negotiate_Protocol reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'security_mode': struct.unpack_from('<H', hdr, 2)[0]})
    result.update({'dialect_revision': struct.unpack_from('<H', hdr, 4)[0]})
    result.update({'server_guid': hdr[8:8 + 16]})
    result.update({'capabilities': struct.unpack_from('<I', hdr, 24)[0]})
    result.update({'max_transact_size': struct.unpack_from('<I', hdr, 28)[0]})
    result.update({'max_read_size': struct.unpack_from('<I', hdr, 32)[0]})
    result.update({'max_write_size': struct.unpack_from('<I', hdr, 36)[0]})
    result.update({'system_time': WinToTimeval(struct.unpack_from('<Q', hdr, 40)[0])})
    result.update({'server_start_time': WinToTimeval(struct.unpack_from('<Q', hdr, 48)[0])})

    _sec_offset = struct.unpack_from('<H', hdr, 56)[0]
    _sec_len = struct.unpack_from('<H', hdr, 58)[0]
    if _sec_len:
        result.update({'security_buffer': hdr[_sec_offset - 64:_sec_offset - 64 + _sec_len]})
        
    _context_count = 0
    if result['dialect_revision'] == VERSION_0311:
        _context_count = struct.unpack_from('<H', hdr, 6)[0]
        _context_offset = struct.unpack_from('<I', hdr, 60)[0]
        if _context_count:
            result.update({'contexts': _decode_contexts(hdr[_context_offset - 64:], _context_count)})
    
    return result

def _encode_reply(hdr):
    """
    Encode a Negotiate_Protocol reply
    """
    result = bytearray(64)
    struct.pack_into('<H', result, 0, 65)
    struct.pack_into('<H', result, 2, hdr['security_mode'])
    struct.pack_into('<H', result, 4, hdr['dialect_revision'])
    if 'server_guid' in hdr:
        result[8:8 + 16] = hdr['server_guid']
    struct.pack_into('<I', result, 24, hdr['capabilities'])
    struct.pack_into('<I', result, 28, hdr['max_transact_size'])
    struct.pack_into('<I', result, 32, hdr['max_read_size'])
    struct.pack_into('<I', result, 36, hdr['max_write_size'])
    struct.pack_into('<Q', result, 40, TimevalToWin(hdr['system_time']))
    if 'server_start_time' in hdr:
        struct.pack_into('<Q', result, 48, TimevalToWin(hdr['server_start_time']))
    if 'security_buffer' in hdr:
        # Security buffer is at offset 64(smb2 hdr) + 64(negotiate reply)
        struct.pack_into('<H', result, 56, 64 + 64)
        struct.pack_into('<H', result, 58, len(hdr['security_buffer']))
        result = result + hdr['security_buffer']

    # Encode the actual contexts
    if hdr['dialect_revision'] == VERSION_0311:
        if 'contexts' in hdr:
            # The contexts are padded to start on 8 byte boundary
            _len = len(result)
            if _len % 8:
                _pad = ((_len + 7) & 0xfff8) - _len
                result.extend(bytearray(_pad))

            # Negotiate Context Offset and Count
            struct.pack_into('<I', result, 60, len(result) + 64)
            struct.pack_into('<H', result, 6, len(hdr['contexts']))
                
            result = result + _encode_contexts(hdr['contexts'])
            
    return result


class NegotiateProtocol(object):
    """
    A class for Negotiate_Protocol
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Negotiate_Protocol PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Negotiate_Protocol PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
