#!/usr/bin/env python
# coding: utf-8

import os
import secrets
import socket
import stat
import struct
import time
import spnego

try:
    from config import Config
except:
    print('FATAL: No configuration file found.')
    raise
if Config.ntlm_user_file:
    os.environ['NTLM_USER_FILE'] = Config.ntlm_user_file 

from smb2.header import *
from smb2.error_response import *
from smb2.negotiate_protocol import *
from smb2.session_setup import *
from smb2.session_logoff import *
from smb2.tree_connect import *
from smb2.tree_disconnect import *
from smb2.create import *
from smb2.close import *
from smb2.read import *
from smb2.query_info import *
from smb2.query_directory import *
from smb2.file_info import *
from smb2.filesystem_info import *
from smb2.dir_info import *

class File(object):

    def __init__(self, path, flags, at, **kwargs):
        self.path = '.' if not path else path
        self.fd = os.open(self.path, flags, dir_fd=at)
        _st = os.stat(self.fd)
        self.de = []
        if stat.S_ISDIR(_st.st_mode):
            self.scandir()

    def __del__(self):
        if self.fd:
            os.close(self.fd)

    def stat(self):
        return os.fstat(self.fd)

    def scandir(self):
        _dirents = []
        with os.scandir(self.fd) as it:
            for _e in it:
                _st = _e.stat(follow_symlinks=False)
                _a = FILE_ATTRIBUTE_SPARSE_FILE
                if stat.S_ISDIR(_st.st_mode):
                    _a = _a | FILE_ATTRIBUTE_DIRECTORY
                _de = {'file_index': 0,
                       'creation_time': (0, 0, 0),
                       'last_access_time': (int(_st.st_atime), 0, 0),
                       'last_write_time': (int(_st.st_mtime), 0, 0),
                       'change_time': (int(_st.st_ctime), 0, 0),
                       'end_of_file': _st.st_size,
                       'allocation_size': _st.st_size,
                       'file_attributes': _a,
                       'ea_size': 0,
                       'file_id': _st.st_ino,
                       'file_name': bytes(_e.name, encoding='utf=8'),
                       }
                _dirents.append((_e, _de,))
        self.de = _dirents

    def pread(self, length, offset):
        return os.pread(self.fd, length, offset)


class Server(object):
    """
    A class for a SMB2 Server
    """

    sessions = {}
    trees = {}
    files = {}
    dialect = 0
    
    def __init__(self, s, **kwargs):
        self._s = s
        self._sp = spnego.server(socket.gethostname())
        self._guest = False
        self._sesid = 1
        self._treeid = 1
        self._fileid = 1
        self._last_fid = (0, 0)

        print('Socket', self._s)
        self.Run()

    def __del__(self):
        True

    def srv_read(self, hdr, pdu):
        #
        # Read
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        _fid = pdu['file_id']
        if _fid == (0xffffffffffffffff, 0xffffffffffffffff):
            _fid = self._last_fid

        try:
            _f = self.files[_fid]
        except KeyError:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        _st = _f.stat()
        if pdu['offset'] >= _st.st_size:
            self._compound_error = Status.END_OF_FILE
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
            
        _b = _f.pread(pdu['length'], pdu['offset'])
        return (Status.SUCCESS,
                Read.encode(Direction.REPLY,
                       {'data_remaining': 0,
                        'data': _b,
                        }))

        
    def srv_close(self, hdr, pdu):
        #
        # Close
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        _fid = pdu['file_id']
        if _fid == (0xffffffffffffffff, 0xffffffffffffffff):
            _fid = self._last_fid

        try:
            _f = self.files[_fid]
        except KeyError:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        del self.files[_fid]
        del _f
        return (Status.SUCCESS,
                Close.encode(Direction.REPLY,
                       {'flags': 0,
                        }))


    def srv_query_dir(self, hdr, pdu):
        #
        # Query Directory
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        try:
            DirInfoClass(pdu['info_class'])
        except ValueError:
            print('QueryDir: Can not handle info_type', pdu['info_class'])
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        _fid = pdu['file_id']
        if _fid == (0xffffffffffffffff, 0xffffffffffffffff):
            _fid = self._last_fid

        try: 
            _f = self.files[_fid]
        except KeyError:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        if pdu['flags'] & (SMB2_RESTART_SCANS | SMB2_REOPEN):
            _f.scandir()

        if not _f.de:
            self._compound_error = Status.NO_MORE_FILES
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
            
        _b = bytearray(0)
        _obl = pdu['output_buffer_length']
        _pos = 0
        while _f.de:
            _i = DirInfo.encode_single(
                DirInfoClass(pdu['info_class']), _f.de[0][1])
            if len(_i) > _obl:
                break
            _f.de = _f.de[1:]
            
            _obl = _obl - len(_i)
            _pos = len(_b)
            _b = _b + _i
        struct.pack_into('<I', _b, _pos, 0)
        return (Status.SUCCESS,
                QueryDirectory.encode(Direction.REPLY,
                       {'data': _b,
                        }))

    def _query_file_info(self, f, c):
        _st = f.stat()
        _a = FILE_ATTRIBUTE_SPARSE_FILE
        if stat.S_ISDIR(_st.st_mode):
            _a = _a | FILE_ATTRIBUTE_DIRECTORY
            
        _ac = 0
        if stat.S_IRUSR & _st.st_mode:
            _ac = _ac | FILE_READ_DATA
        if stat.S_IWUSR & _st.st_mode:
            _ac = _ac | FILE_WRITE_DATA
        if stat.S_IXUSR & _st.st_mode:
            _ac = _ac | FILE_EXECUTE
        _fi = FileInfo.encode(FileInfoClass(c),
                        {'creation_time': (0, 0, 0),
                         'last_access_time': (int(_st.st_atime), 0, 0),
                         'last_write_time': (int(_st.st_mtime), 0, 0),
                         'change_time': (int(_st.st_ctime), 0, 0),
                         'file_attributes': _a,
                         'allocation_size': _st.st_size,
                         'end_of_file': _st.st_size,
                         'number_of_links': _st.st_nlink,
                         'delete_pending': 0,
                         'directory': 0 if stat.S_ISDIR(_st.st_mode) else 1,
                         'index_number': _st.st_ino,
                         'ea_size': 0,
                         'access_flags': _ac,
                         'current_byte_offset': 0,
                         'mode': 0,
                         'alignment_requirement': 0,
                         })
        if FileInfoClass(c) == FileInfoClass.ALL_INFORMATION:
            # windows adds 4 bytes of junk here
            _fi = _fi + bytearray(4)
            
        return (Status.SUCCESS,
                QueryInfo.encode(Direction.REPLY,
                                {'buffer': _fi,
                                 }))

    def _query_fs_info(self, t, c):
        if FSInfoClass(c) == FSInfoClass.ATTRIBUTE:
            _fi = FSInfo.encode(FSInfoClass.ATTRIBUTE,
                    {'attributes': SUPPORTS_OBJECT_IDS | SUPPORTS_SPARSE_FILES | UNICODE_ON_DISK | CASE_PRESERVED_NAMES | CASE_SENSITIVE_SEARCH,
                     'maximum_component_name_length': 255,
                     'file_system_name': 'pysmb3d'
                     })
            return (Status.SUCCESS,
                QueryInfo.encode(Direction.REPLY,
                    {'buffer': _fi,
                     }))
        if FSInfoClass(c) == FSInfoClass.DEVICE:
            _fi = FSInfo.encode(FSInfoClass.DEVICE,
                    {'device_type': DeviceType.DISK.value,
                     'characteristics': DEVICE_IS_MOUNTED 
                     })
            return (Status.SUCCESS,
                QueryInfo.encode(Direction.REPLY,
                    {'buffer': _fi,
                     }))
        if FSInfoClass(c) == FSInfoClass.VOLUME:
            _fi = FSInfo.encode(FSInfoClass.VOLUME,
                    {'creation_time': (0, 0, 0),
                     'serial_number': 0,
                     'supports_objects': 0,
                     'label': t[1]
                     })
            return (Status.SUCCESS,
                QueryInfo.encode(Direction.REPLY,
                    {'buffer': _fi,
                     }))

        if FSInfoClass(c) == FSInfoClass.SECTOR_SIZE:
            _stfs = os.fstatvfs(t[0])
            _fi = FSInfo.encode(FSInfoClass.SECTOR_SIZE,
                    {'logical_bytes_per_sector': _stfs.f_bsize,
                     'physical_bytes_per_sector_for_atomicity': _stfs.f_bsize,
                     'physical_bytes_per_sector_for_performance': _stfs.f_bsize,
                     'effective_physical_bytes_per_sector_for_atomicity': _stfs.f_bsize,
                     'flags': SSINFO_FLAGS_ALIGNED_DEVICE | SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE,
                     'byte_offset_for_sector_alignment': 0,
                     'byte_offset_for_partition_alignment': 0
                     })
            return (Status.SUCCESS,
                QueryInfo.encode(Direction.REPLY,
                    {'buffer': _fi,
                     }))
        
        if FSInfoClass(c) == FSInfoClass.FULL_SIZE:
            _stfs = os.fstatvfs(t[0])
            _fi = FSInfo.encode(FSInfoClass.FULL_SIZE,
                    {'total_allocation_units': _stfs.f_blocks,
                     'caller_available_allocation_units': _stfs.f_bavail,
                     'actual_available_allocation_units': _stfs.f_bfree,
                     'sectors_per_allocation_unit': 1,
                     'bytes_per_sector': _stfs.f_bsize,
                     })
            return (Status.SUCCESS,
                QueryInfo.encode(Direction.REPLY,
                    {'buffer': _fi,
                     }))

        return (Status.INVALID_PARAMETER,
                ErrorResponse.encode({'error_data' : bytes(1)}))
            
    def srv_query_info(self, hdr, pdu):
        #
        # Query Info
        # can only handle INFO_FILE for now
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        _fid = pdu['file_id']
        if _fid == (0xffffffffffffffff, 0xffffffffffffffff):
            _fid = self._last_fid

        try:
            _f = self.files[_fid]
        except KeyError:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        if pdu['info_type'] == SMB2_0_INFO_FILE:
            return self._query_file_info(_f, pdu['file_info_class'])
        
        if pdu['info_type'] == SMB2_0_INFO_FILESYSTEM:
            return self._query_fs_info(self.trees[hdr['tree_id']], pdu['file_info_class'])
        
        print('QueryInfo: Can not handle info type', pdu['info_type'])
        self._compound_error = Status.INVALID_PARAMETER
        return (self._compound_error,
                ErrorResponse.encode({'error_data' : bytes(1)}))

        
    def srv_create(self, hdr, pdu):
        #
        # Create/Open
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        t = self.trees[hdr['tree_id']]

        flags = 0
        if Disposition(pdu['create_disposition']) != Disposition.OPEN:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        if pdu['desired_access'] & (FILE_GENERIC_READ | FILE_GENERIC_ALL | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA):
            # O_RDONLY is 0
            flags = flags | os.O_RDONLY

        try:
            f = File(pdu['path'].decode(), flags, t[0])
            _st = f.stat()
        except FileNotFoundError:
            self._compound_error = Status.OBJECT_NAME_NOT_FOUND
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        self._last_fid = (self._fileid, self._fileid)
        self._fileid = self._fileid + 1
        self.files.update({self._last_fid: f})

        _a = FILE_ATTRIBUTE_SPARSE_FILE
        if stat.S_ISDIR(_st.st_mode):
            _a = _a | FILE_ATTRIBUTE_DIRECTORY
            
        return (Status.SUCCESS,
                Create.encode(Direction.REPLY,
                       {'oplock_level': Oplock.LEVEL_NONE.value,
                        'flags': 0,
                        'create_action': Action.OPENED.value,
                        'creation_time': (0, 0, 0),
                        'last_access_time': (int(_st.st_atime), 0, 0),
                        'last_write_time': (int(_st.st_mtime), 0, 0),
                        'change_time': (int(_st.st_ctime), 0, 0),
                        'allocation_size': _st.st_size,
                        'end_of_file': _st.st_size,
                        'file_attributes': _a,
                        'file_id': self._last_fid,
                        }))

    def srv_tree_disconn(self, hdr, pdu):
        #
        # Disconnect a share
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        os.close(self.trees[hdr['tree_id']][0])
        del self.trees[hdr['tree_id']]
        return (Status.SUCCESS,
                TreeDisconnect.encode(Direction.REPLY, {}))
        
    def srv_tree_conn(self, hdr, pdu):
        #
        # Connect to a share
        #
        _p = pdu['path'][2:].decode().replace('\\', '/')
        _p = _p[_p.find('/') + 1:]
        if not _p in Config.shares:
            print('Share not found', _p)
            return (Status.BAD_NETWORK_NAME,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        fd = os.open(Config.shares[_p], os.O_RDONLY)

        hdr['tree_id'] = self._treeid
        self.trees.update({self._treeid: (fd, _p,)})
        self._treeid = self._treeid + 1

        return (Status.SUCCESS,
                TreeConnect.encode(Direction.REPLY,
                       {'share_type': SMB2_SHARE_TYPE_DISK,
                        'share_flags': 0,
                        'capabilities': 0,
                        'maximal_access': 0x001f00a9,
                        }))
        
    def srv_sess_setup(self, hdr, pdu):
        try:
            sm = self._sp.step(pdu['security_buffer'])
        except Exception as e:
            if Config.guest_login:
                print('Authentication failed. Logging in as guest')
                self._guest = True
                hdr['session_id'] = self._sesid
                self.sessions.update({self._sesid: (None,)})
                self._sesid = self._sesid + 1
                return (Status.SUCCESS,
                        SessionSetup.encode(Direction.REPLY,
                                {'session_flags': SMB2_SESSION_FLAG_IS_GUEST,
                                 }))
            else:
                print('Exception', e)
                raise

        if not sm:
            # self._sp.complete
            # self._sp.session_key
            # self._sp.negotiated_protocol == 'ntlm'
            print('Authenticated as', self._sp.client_principal)

            #
            # TODO store user/session data in this tuple
            hdr['session_id'] = self._sesid
            self.sessions.update({self._sesid: (None,)})
            self._sesid = self._sesid + 1
        
            return (Status.SUCCESS,
                    SessionSetup.encode(Direction.REPLY,
                        {'session_flags': 0,
                         }))
            
        return (Status.MORE_PROCESSING_REQUIRED,
                SessionSetup.encode(Direction.REPLY,
                                    {'session_flags': 0,
                                     'security_buffer': sm,
                                     }))
        
    def srv_sess_logoff(self, hdr, pdu):
        del self.sessions[hdr['session_id']]
        return (Status.SUCCESS,
                TreeDisconnect.encode(Direction.REPLY, {}))
        
    def srv_neg_prot(self, hdr, pdu):
        # Only allow version 3.02
        if not VERSION_0302 in pdu['dialects']:
            print('No supported dialect in Negotiate Protocol')
            return (Status.INVALID_PARAMETER,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        self.dialect = VERSION_0302
        return (Status.SUCCESS,
                NegotiateProtocol.encode(Direction.REPLY,
                       {'security_mode': 0,
                        'dialect_revision': self.dialect,
                        'capabilities': 0,
                        'max_transact_size': 65536,
                        'max_read_size': 65536,
                        'max_write_size': 65536,
                        'system_time': (int(time.time()), 0, 0)}))
        
    def ProcessCommands(self, cmds):
        r = []
        self._compound_error = Status.SUCCESS
        for cmd in cmds:
            #
            # Decode the command pdu
            #
            h = cmd[0]
            ct = {
                Command.NEGOTIATE_PROTOCOL: (NegotiateProtocol, self.srv_neg_prot),
                Command.SESSION_SETUP: (SessionSetup, self.srv_sess_setup),
                Command.SESSION_LOGOFF: (SessionLogoff, self.srv_sess_logoff),
                Command.TREE_CONNECT: (TreeConnect, self.srv_tree_conn),
                Command.TREE_DISCONNECT: (TreeDisconnect, self.srv_tree_disconn),
                Command.CREATE: (Create, self.srv_create),
                Command.CLOSE: (Close, self.srv_close),
                Command.READ: (Read, self.srv_read),
                Command.QUERY_INFO: (QueryInfo, self.srv_query_info),
                Command.QUERY_DIRECTORY: (QueryDirectory, self.srv_query_dir),
                }

            if self._compound_error != Status.SUCCESS:
                rh = Header.encode({'protocol_id': SMB2_MAGIC,
                                    'credit_charge': h['credit_charge'],
                                    'status': self._compound_error.value,
                                    'command': h['command'],
                                    'credit_response': h['credit_request'],
                                    'flags': RESPONSE,
                                    'message_id': h['message_id'],
                                    'process_id': h['process_id'],
                                    'tree_id': h['tree_id'],
                                    'session_id': h['session_id']})
                r.append((rh,
                          ErrorResponse.encode({'error_data' : bytes(1)})))
                continue

            try:
                c = ct.get(Command(h['command']))
                req = c[0].decode(Direction.REQUEST, cmd[1])
            except:
                print('Can not handle command', h['command'], 'yet.')
                rh = Header.encode({'protocol_id': SMB2_MAGIC,
                                    'credit_charge': h['credit_charge'],
                                    'status': Status.INVALID_PARAMETER.value,
                                    'command': h['command'],
                                    'credit_response': h['credit_request'],
                                    'flags': RESPONSE,
                                    'message_id': h['message_id'],
                                    'process_id': h['process_id'],
                                    'tree_id': h['tree_id'],
                                    'session_id': h['session_id']})
                r.append((rh,
                          ErrorResponse.encode({'error_data' : bytes(1)})))
                continue

            rep = c[1](h, req)

            _f = RESPONSE | (h['flags'] & RELATED)
            rh = Header.encode({'protocol_id': SMB2_MAGIC,
                                'credit_charge': h['credit_charge'],
                                'status': rep[0].value,
                                'command': h['command'],
                                'credit_response': h['credit_request'],
                                'flags': _f,
                                'message_id': h['message_id'],
                                'process_id': h['process_id'],
                                'tree_id': h['tree_id'],
                                'session_id': h['session_id']})
            r.append((rh, rep[1]))

            # next command need special handling to write straight into the
            # encoded buffer and adding padding
        return r

    def SplitBuffer(self, buf):
        cmds = []
        while buf:
            _h = Header.decode(buf[:64])
            if _h['protocol_id'] != SMB2_MAGIC:
                print('Not a SMB2 header')
                raise ValueError
            if _h['next_command']:
                cmds.append((_h, buf[64:_h['next_command']]))
                buf = buf[_h['next_command']:]
            else:
                cmds.append((_h, buf[64:]))
                buf = []
        return cmds

    def Run(self):
        while True:
            #
            # Read the SPL and data from the socket
            #
            spl = bytes(0)
            while len(spl) < 4:
                _b = self._s.recv(4 - len(spl))
                if not _b:
                    print('Socket closed by client')
                    return
                spl = spl + _b
            _spl = struct.unpack_from('>I', spl, 0)[0]

            buf = bytes(0)
            while len(buf) < _spl:
                _b = self._s.recv(_spl - len(buf))
                if not _b:
                    print('Socket closed by client')
                    return
                buf = buf + _b

            #
            # Split the buffer into a list of (header, command) tuples
            #
            cmds = self.SplitBuffer(buf)

            #
            # Process the commands
            #
            rep = self.ProcessCommands(cmds)

            #
            # Concatenate them into a single bytearray, take care of padding
            # and next command
            #
            buf = bytearray(0)
            _pos = 0
            _last_pos = 0
            for r in rep:
                buf = buf + r[0] + r[1]
                _len = len(buf)
                if _len % 8:
                    _pad = ((_len + 7) & 0xfff8) - _len
                    buf = buf + bytearray(_pad)

                struct.pack_into('<I', buf, _pos + 20, len(buf) - _pos)
                _last_pos = _pos
                _pos = len(buf)

            struct.pack_into('<I', buf, _last_pos + 20, 0)
            spl = bytearray(4)
            struct.pack_into('>I', spl, 0, len(buf))
            while len(spl):
                l = self._s.send(spl)
                spl = spl[l:]
            while len(buf):
                l = self._s.send(buf)
                buf = buf[l:]
        
