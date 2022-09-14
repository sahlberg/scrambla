# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct
from enum import Enum

from smb2.header import Direction
from smb2.timestamps import WinToTimeval, TimevalToWin
from smb2.unicode import UCS2toUTF8, UTF8toUCS2

#
# SMB2 Create
#

#
# Oplock Level
#
class Oplock(Enum):
    LEVEL_NONE      = 0x00
    LEVEL_II        = 0x01
    LEVEL_EXCLUSIVE = 0x08
    LEVEL_BATCH     = 0x09
    LEVEL_LEASE     = 0xff

#
# Impersonation Level
#
class Impersonation(Enum):
    ANONYMOUS      = 0x00000000
    IDENTIFICATION = 0x00000001
    IMPERSONATION  = 0x00000002
    DELEGATE       = 0x00000003

#
# SHARE ACCESS
#
FILE_SHARE_READ   = 0x00000001
FILE_SHARE_WRITE  = 0x00000002
FILE_SHARE_DELETE = 0x00000004

#
# CREATE DISPOSITION
#
class Disposition(Enum):
    SUPERSEDE    = 0x00000000
    OPEN         = 0x00000001
    CREATE       = 0x00000002
    OPEN_IF      = 0x00000003
    OVERWRITE    = 0x00000004
    OVERWRITE_IF = 0x00000005
    
#
# CREATE OPTIONS
#
FILE_DIRECTORY_FILE            = 0x00000001
FILE_WRITE_THROUGH             = 0x00000002
FILE_SEQUENTIAL_ONLY           = 0x00000004
FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
FILE_NON_DIRECTORY_FILE        = 0x00000040
FILE_NO_EA_KNOWLEDGE           = 0x00000200
FILE_RANDOM_ACCESS             = 0x00000800
FILE_DELETE_ON_CLOSE           = 0x00001000
FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000
FILE_NO_COMPRESSION            = 0x00008000
FILE_OPEN_REPARSE_POINT        = 0x00200000
FILE_OPEN_NO_RECALL            = 0x00400000

#
# LEASE STATE
#
SMB2_LEASE_NONE           = 0
SMB2_LEASE_READ_CACHING   = 1
SMB2_LEASE_HANDLE_CACHING = 2
SMB2_LEASE_WRITE_CACHING  = 4

#
# FLAGS
#
SMB2_CREATE_FLAG_REPARSEPOINT = 0x01

#
# CREATE ACTION
#
class Action(Enum):
    SUPERSEDED    = 0x00000000
    OPENED        = 0x00000001
    CREATED       = 0x00000002
    OVERWRITTEN   = 0x00000003

#
# Access
#
FILE_READ_DATA              = 0x00000001
FILE_WRITE_DATA             = 0x00000002
FILE_APPEND_DATA            = 0x00000004
FILE_READ_EA                = 0x00000008
FILE_WRITE_EA               = 0x00000010
FILE_EXECUTE                = 0x00000020
FILE_DELETE_CHILD           = 0x00000040
FILE_READ_ATTRIBUTES        = 0x00000080
FILE_WRITE_ATTRIBUTES       = 0x00000100
FILE_DELETE                 = 0x00010000
FILE_READ_CONTROL           = 0x00020000
FILE_WRITE_DAC              = 0x00040000
FILE_WRITE_OWNER            = 0x00080000
FILE_SYNCHRONIZE            = 0x00100000
FILE_ACCESS_SYSTEM_SECURITY = 0x01000000
FILE_MAXIMUM_ALLOWED        = 0x02000000
FILE_GENERIC_ALL            = 0x10000000
FILE_GENERIC_EXECUTE        = 0x20000000
FILE_GENERIC_WRITE          = 0x40000000
FILE_GENERIC_READ           = 0x80000000


def encode_QFid_reply(context):
    _l = bytearray(32)
    struct.pack_into('<Q', _l, 0, context['disk_file_id'])
    struct.pack_into('<Q', _l, 8, context['volume_id'])
    return _l

def decode_QFid_reply(data):
    context = {}
    context.update({'disk_file_id': struct.unpack_from('<Q', data, 0)[0]})
    context.update({'volume_id': struct.unpack_from('<Q', data, 8)[0]})
    return context

def encode_RqLs_reply(context):
    _l = bytearray(32)
    _l[:16] = context['lease_key']
    struct.pack_into('<I', _l, 16, context['lease_state'])
    if 'parent_lease_key' in context:
        _l = _l + bytearray(20)
        _l[32:48] = context['parent_lease_key']
        struct.pack_into('<H', _l, 48, context['epoch'])
    return _l

def decode_RqLs_reply(data):
    context = {}
    context.update({'lease_key': data[:16]})
    context.update({'lease_state': struct.unpack_from('<I', data, 16)[0]})
    context.update({'lease_flags': struct.unpack_from('<I', data, 20)[0]})
    if len(data) == 52:
        context.update({'parent_lease_key': data[32:48]})
        context.update({'epoch': struct.unpack_from('<H', data, 48)[0]})
    return context

def decode_QFid_request(data):
    return {}

def encode_QFid_request(context):
    return bytearray(0)

reply_contexts = {
    'QFid': (encode_QFid_reply, decode_QFid_reply),
    'RqLs': (encode_RqLs_reply, decode_RqLs_reply),
}

request_contexts = {
    'QFid': (encode_QFid_request, decode_QFid_request),
    # same as the reply RqLs contexts
    'RqLs': (encode_RqLs_reply, decode_RqLs_reply),
}

def _decode_context(context, data, ctx_list):
    if context['name'] in ctx_list:
        context.update(ctx_list[context['name']][1](data))
        return

    print('Unknown Create context', context['name'])

def _decode_contexts(buf, ctx_list):
    contexts = {}

    while buf:
        context = {}
        _next = struct.unpack_from('<I', buf, 0)[0]

        _offset = struct.unpack_from('<H', buf, 4)[0]
        _len = struct.unpack_from('<H', buf, 6)[0]
        _name = buf[_offset:_offset + _len].decode()
        context.update({'name': _name})

        _offset = struct.unpack_from('<H', buf, 10)[0]
        _len = struct.unpack_from('<I', buf, 12)[0]
        _decode_context(context, buf[_offset:_offset + _len], ctx_list)
        
        contexts.update({_name: context})
        
        if _next == 0:
            break
        buf = buf[_next:]
        
    return contexts

def _decode_request(hdr):
    """
    Decode a Create request
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'requested_oplock_level': struct.unpack_from('<B', hdr, 3)[0]})
    result.update({'impersonation_level': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'desired_access': struct.unpack_from('<I', hdr, 24)[0]})
    result.update({'file_attributes': struct.unpack_from('<I', hdr, 28)[0]})
    result.update({'share_access': struct.unpack_from('<I', hdr, 32)[0]})
    result.update({'create_disposition': struct.unpack_from('<I', hdr, 36)[0]})
    result.update({'create_options': struct.unpack_from('<I', hdr, 40)[0]})

    _offset = struct.unpack_from('<H', hdr, 44)[0] - 64
    _len = struct.unpack_from('<H', hdr, 46)[0]
    result.update({'path': UCS2toUTF8(hdr[_offset:_offset + _len]).replace(b'\\', b'/')})

    _offset = struct.unpack_from('<I', hdr, 48)[0] - 64
    _len = struct.unpack_from('<I', hdr, 52)[0]
    result.update({'contexts': {}})
    if _offset:
        result.update({'contexts': _decode_contexts(hdr[_offset:_offset + _len], request_contexts)})

    return result

def _encode_request(hdr):
    """
    Encode a Create request
    """
    result = bytearray(56)
    struct.pack_into('<H', result, 0, 57)
    struct.pack_into('<B', result, 3, hdr['requested_oplock_level'])
    struct.pack_into('<I', result, 4, hdr['impersonation_level'])
    struct.pack_into('<I', result, 24, hdr['desired_access'])
    struct.pack_into('<I', result, 28, hdr['file_attributes'])
    struct.pack_into('<I', result, 32, hdr['share_access'])
    struct.pack_into('<I', result, 36, hdr['create_disposition'])
    struct.pack_into('<I', result, 40, hdr['create_options'])

    _path = UTF8toUCS2(hdr['path'].replace(b'/', b'\\'))
    struct.pack_into('<H', result, 44, 56 + 64)
    if len(_path):
        struct.pack_into('<H', result, 46, len(_path))
        result = result + _path
    else:
        # Windows adds 8 bytes of pad for empty name
        result = result + bytearray(8)

    if 'contexts' in hdr:
        # Add padding if we need to
        _len = len(result)
        if _len % 8:
            _pad = ((_len + 7) & 0xfff8) - _len
            result = result + bytearray(_pad)

        _c = _encode_contexts(hdr['contexts'], request_contexts)
        struct.pack_into('<I', result, 48, len(result) + 64)
        struct.pack_into('<I', result, 52, len(_c))
        result = result + _c
        
    return result

def _decode_reply_contexts(buf, ctx_list):
    contexts = {}

    while buf:
        context = {}
        _next = struct.unpack_from('<I', buf, 0)[0]

        _offset = struct.unpack_from('<H', buf, 4)[0]
        _len = struct.unpack_from('<H', buf, 6)[0]
        _name = buf[_offset:_offset + _len].decode()
        context.update({'name': _name})
        
        _offset = struct.unpack_from('<H', buf, 10)[0]
        _len = struct.unpack_from('<I', buf, 12)[0]
        _decode_context(context, buf[_offset:_offset + _len], ctx_list)
        
        contexts.update({_name: context})
        
        if _next == 0:
            break
        buf = buf[_next:]
        
    return contexts

def _decode_reply(hdr):
    """
    Decode a Create reply
    """
    result = {}
    result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
    result.update({'oplock_level': struct.unpack_from('<B', hdr, 2)[0]})
    result.update({'flags': struct.unpack_from('<B', hdr, 3)[0]})
    result.update({'create_action': struct.unpack_from('<I', hdr, 4)[0]})
    result.update({'creation_time': WinToTimeval(struct.unpack_from('<Q', hdr, 8)[0])})
    result.update({'last_access_time': WinToTimeval(struct.unpack_from('<Q', hdr, 16)[0])})
    result.update({'last_write_time': WinToTimeval(struct.unpack_from('<Q', hdr, 24)[0])})
    result.update({'change_time': WinToTimeval(struct.unpack_from('<Q', hdr, 32)[0])})
    result.update({'allocation_size': struct.unpack_from('<Q', hdr, 40)[0]})
    result.update({'end_of_file': struct.unpack_from('<Q', hdr, 48)[0]})
    result.update({'file_attributes': struct.unpack_from('<I', hdr, 56)[0]})
    result.update({'file_id': (struct.unpack_from('<Q', hdr, 64)[0],
                               struct.unpack_from('<Q', hdr, 72)[0])})

    _offset = struct.unpack_from('<I', hdr, 80)[0] - 64
    _len = struct.unpack_from('<I', hdr, 84)[0]
    result.update({'contexts': {}})
    if _offset:
        result.update({'contexts': _decode_reply_contexts(hdr[_offset:_offset + _len], reply_contexts)})

    return result

def _encode_context(context, ctx_list):
    _c = bytearray(16)
    struct.pack_into('<H', _c, 4, 16)
    struct.pack_into('<H', _c, 6, len(context['name']))
    _c = _c + context['name'].encode()
    
    # Data is aligned to 8 bytes so add padding if we need to
    _len = len(_c)
    if _len % 8:
        _pad = ((_len + 7) & 0xfff8) - _len
        _c = _c + bytearray(_pad)

    if context['name'] in ctx_list:
        _l = ctx_list[context['name']][0](context)

        if _l:
            struct.pack_into('<H', _c, 10, len(_c))
            struct.pack_into('<I', _c, 12, len(_l))
            _c = _c + _l

        return _c
    
    print('Unknown Create reply context', context['name'])
    return _c

def _encode_contexts(contexts, ctx_list):
    _pos = 0
    buf = bytearray(0)

    for name, context in contexts.items():
        context['name'] = name
        
        _pos = len(buf)
        buf = buf + _encode_context(context, ctx_list)

        # Add padding, if we need to
        _len = len(buf)
        if _len % 8:
            _pad = ((_len + 7) & 0xfff8) - _len
            buf = buf + bytearray(_pad)

        # assume we have another context after this so set next accordingly
        struct.pack_into('<I', buf, _pos, len(buf) - _pos)

    # Except next should be 0 for the last context, IF we have contexts
    if len(buf) >= 16:
        struct.pack_into('<I', buf, _pos, 0)

    return buf

def _encode_reply(hdr):
    """
    Encode a Create reply
    """
    result = bytearray(88)
    struct.pack_into('<H', result, 0, 89)
    struct.pack_into('<B', result, 2, hdr['oplock_level'])
    struct.pack_into('<B', result, 3, hdr['flags'])
    struct.pack_into('<I', result, 4, hdr['create_action'])
    struct.pack_into('<Q', result, 8, TimevalToWin(hdr['creation_time']))
    struct.pack_into('<Q', result, 16, TimevalToWin(hdr['last_access_time']))
    struct.pack_into('<Q', result, 24, TimevalToWin(hdr['last_write_time']))
    struct.pack_into('<Q', result, 32, TimevalToWin(hdr['change_time']))
    struct.pack_into('<Q', result, 40, hdr['allocation_size'])
    struct.pack_into('<Q', result, 48, hdr['end_of_file'])
    struct.pack_into('<I', result, 56, hdr['file_attributes'])

    struct.pack_into('<Q', result, 64, hdr['file_id'][0])
    struct.pack_into('<Q', result, 72, hdr['file_id'][1])

    if 'contexts' in hdr:
        # Add padding if we need to
        _len = len(result)
        if _len % 8:
            _pad = ((_len + 7) & 0xfff8) - _len
            result = result + bytearray(_pad)

        _c = _encode_contexts(hdr['contexts'], reply_contexts)
        struct.pack_into('<I', result, 80, len(result) + 64)
        struct.pack_into('<I', result, 84, len(_c))
        result = result + _c
    
    return result


class Create(object):
    """
    A class for Create
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(direction, hdr):
        """
        Decode a Create PDU
        """
        if direction == Direction.REPLY:
            return _decode_reply(hdr)
        return _decode_request(hdr)

    @staticmethod
    def encode(direction, hdr):
        """
        Encode a Create PDU
        """
        if direction == Direction.REPLY:
            return _encode_reply(hdr)
        return _encode_request(hdr)
    
