#!/usr/bin/env python
# coding: utf-8

#
# pycryptodome installs as Cryptodome when the ancient pycrypto owns the
# Crypto name, so look for it there first.
#
try:
    from Cryptodome.Hash import CMAC
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES
import hashlib
import hmac
import os
import secrets
import stat
import struct
import time
try:
    from config import Config
except:
    print('FATAL: No configuration file found.')
    raise

from smb2.header import *
from smb2.error_response import *
from smb2.negotiate_protocol import *
from smb2.session_setup import *
from smb2.session_logoff import *
from smb2 import ntlmssp
from smb2 import spnego
from smb2.tree_connect import *
from smb2.tree_disconnect import *
from smb2.create import *
from smb2.close import *
from smb2.flush import *
from smb2.read import *
from smb2.write import *
from smb2.set_info import *
from smb2.query_info import *
from smb2.query_directory import *
from smb2.file_info import *
from smb2.filesystem_info import *
from smb2.dir_info import *

SMB2_KEY_SIZE = 16

class File(object):

    def __init__(self, path, flags, at, **kwargs):
        self.path = '.' if not path else path
        self.flags = flags
        self.fd = os.open(self.path, flags, dir_fd=at)
        _st = os.stat(self.fd)
        self.de = []
        self.delete_on_close = False
        if stat.S_ISDIR(_st.st_mode):
            self.scandir()

    def __del__(self):
        if hasattr(self, 'fd') and self.fd:
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
        self._ntlm_negotiate = None
        self._ntlm_challenge = None
        self._ntlm_server_challenge = None
        self._guest = False
        self._sesid = 1
        self._treeid = 1
        self._fileid = 1
        self._last_fid = (0, 0)
        self.signing_key = None
        self._use_signing = False

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

        
    def srv_write(self, hdr, pdu):
        #
        # Write
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

        _len = os.pwrite(_f.fd, pdu['data'], pdu['offset'])
        return (Status.SUCCESS,
                Write.encode(Direction.REPLY,
                             {'count': _len,
                              }))

    def srv_close(self, hdr, pdu):
        #
        # Close
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        t = self.trees[hdr['tree_id']]

        _fid = pdu['file_id']
        if _fid == (0xffffffffffffffff, 0xffffffffffffffff):
            _fid = self._last_fid

        try:
            _f = self.files[_fid]
        except KeyError:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        if _f.delete_on_close:
            if _f.flags & os.O_DIRECTORY:
                try:
                    os.rmdir(_f.path, dir_fd=t[0])
                except OSError:
                    del self.files[_fid]
                    del _f
                    return (Status.DIRECTORY_NOT_EMPTY,
                            Close.encode(Direction.REPLY,
                                         {'flags': 0,
                                          }))
            else:
                os.unlink(_f.path, dir_fd=t[0])
        del self.files[_fid]
        del _f
        return (Status.SUCCESS,
                Close.encode(Direction.REPLY,
                       {'flags': 0,
                        }))


    def srv_flush(self, hdr, pdu):
        #
        # Flush
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
        os.fsync(_f.fd)
        return (Status.SUCCESS,
                Flush.encode(Direction.REPLY,
                       {}))


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
        try:
            _ = FileInfoClass(c)
        except:
            print('FileInfoClass', c, 'not yet implemented')
            return (Status.INVALID_PARAMETER,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

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
        try:
            _ = FSInfoClass(c)
        except:
            print('FSInfoClass', c, 'not yet implemented')
            return (Status.INVALID_PARAMETER,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

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

        print('QueryInfo: FSInfoClass', FSInfoClass(c), 'not yet implemented') 
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


    def _set_file_info(self, f, t, pdu):
        c = pdu['file_info_class']
        try:
            _ = FileInfoClass(c)
        except:
            print('FileInfoClass', c, 'not yet implemented')
            return (Status.INVALID_PARAMETER,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        buffer = FileInfo.decode(FileInfoClass(c), pdu['buffer'])
        if FileInfoClass(c) == FileInfoClass.END_OF_FILE_INFORMATION:
            os.truncate(f.fd, buffer['end_of_file'])
            return (Status.SUCCESS,
                    SetInfo.encode(Direction.REPLY,
                                     {}))
        if FileInfoClass(c) == FileInfoClass.DISPOSITION_INFORMATION:
            f.delete_on_close = buffer['delete_pending']
            return (Status.SUCCESS,
                    SetInfo.encode(Direction.REPLY,
                                     {}))
        if FileInfoClass(c) == FileInfoClass.BASIC_INFORMATION:
            a = (buffer['last_access_time'][0], buffer['last_write_time'][0])
            if a[0] == 0:
                a = (int(time.time()), a[1])
            os.utime(f.fd, times=a)
            return (Status.SUCCESS,
                    SetInfo.encode(Direction.REPLY,
                                     {}))
        if FileInfoClass(c) == FileInfoClass.RENAME_INFORMATION:
            os.rename(f.path, buffer['filename'], src_dir_fd=t[0], dst_dir_fd=t[0])
            return (Status.SUCCESS,
                    SetInfo.encode(Direction.REPLY,
                                     {}))

        print('SetInfo: FileInfoClass', FileInfoClass(c), 'not yet implemented') 
        return (Status.INVALID_PARAMETER,
                ErrorResponse.encode({'error_data' : bytes(1)}))
    
    def srv_set_info(self, hdr, pdu):
        #
        # Set Info
        #
        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        t = self.trees[hdr['tree_id']]

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
            return self._set_file_info(_f, t, pdu)
        
        print('SetInfo: Can not handle info type', pdu['info_type'])
        self._compound_error = Status.INVALID_PARAMETER
        return (self._compound_error,
                ErrorResponse.encode({'error_data' : bytes(1)}))

        
    def srv_create(self, hdr, pdu):
        #
        # Create/Open
        #
        # Error injection for libsmb2 issue 484:
        # Silently swallow the create for this name and never send any
        # reply at all, so that the client is forced down its timeout
        # path for a pdu that is still in flight.
        #
        if pdu['path'].decode().split('/')[-1] == 'libsmb2_issue_484':
            print('Dropping CREATE for', pdu['path'].decode())
            return None

        if not hdr['tree_id'] in self.trees:
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        t = self.trees[hdr['tree_id']]

        flags = 0
        if hasattr(os, 'O_BINARY'): # Windows needs O_BINARY
            flags |= os.O_BINARY
        _r = False
        _w = False
        if pdu['desired_access'] & (FILE_GENERIC_WRITE | FILE_GENERIC_ALL | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_WRITE_DATA):
            _w = True
        if pdu['desired_access'] & (FILE_GENERIC_READ | FILE_GENERIC_ALL | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA):
            _r = True
        if _r and not _w:
            flags = flags | os.O_RDONLY
        if _r and _w:
            flags = flags | os.O_RDWR
        if not _r and _w:
            flags = flags | os.O_WRONLY

        if Disposition(pdu['create_disposition']) == Disposition.OPEN:
            True
        elif Disposition(pdu['create_disposition']) == Disposition.CREATE:
            flags = flags | os.O_CREAT | os.O_EXCL
        elif Disposition(pdu['create_disposition']) == Disposition.OPEN_IF:
            flags = flags | os.O_CREAT
        elif Disposition(pdu['create_disposition']) == Disposition.OVERWRITE:
            flags = flags | os.O_TRUNC
        else:
            print('Create disposition', pdu['create_disposition'], 'not yet supported')
            self._compound_error = Status.INVALID_PARAMETER
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        if pdu['create_options'] & FILE_DIRECTORY_FILE:
            flags = flags | os.O_DIRECTORY
            if flags & os.O_CREAT:
                os.mkdir(pdu['path'].decode(), dir_fd=t[0])
                flags = os.O_RDONLY

        try:
            f = File(pdu['path'].decode(), flags, t[0])
            _st = f.stat()
        except FileNotFoundError:
            self._compound_error = Status.OBJECT_NAME_NOT_FOUND
            return (self._compound_error,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        if pdu['create_options'] & FILE_DELETE_ON_CLOSE:
            f.delete_on_close = True
        self._last_fid = (self._fileid, self._fileid)
        self._fileid = self._fileid + 1
        self.files.update({self._last_fid: f})

        _a = FILE_ATTRIBUTE_SPARSE_FILE
        if stat.S_ISDIR(_st.st_mode):
            _a = _a | FILE_ATTRIBUTE_DIRECTORY

        contexts = {}
        for ctx in pdu['contexts']:
            if ctx == 'QFid':
                contexts.update({'QFid': {'disk_file_id': _st.st_ino,
                                          'volume_id': _st.st_dev}})
            else:
                print('Can not handle Create context', ctx, 'yet')

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
                        'contexts': contexts,
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
        
    def generate_keys(self, session_key):
        def derive_key(session_key, label, context):
            input_key = session_key[:16]

            hm = hmac.new(input_key, None, hashlib.sha256)
            counter=bytearray(4)
            struct.pack_into('>I', counter, 0, 1)
            hm.update(counter)
            hm.update(label)
            hm.update(bytes(1))
            hm.update(context)
            keylen=bytearray(4)
            struct.pack_into('>I', keylen, 0, SMB2_KEY_SIZE * 8)
            hm.update(keylen)
            return hm.digest()

        if self.dialect <= VERSION_0210:
            self.signing_key = session_key
        elif self.dialect <= VERSION_0302:
            self.signing_key = derive_key(session_key,
                    bytes('SMB2AESCMAC', encoding='ascii') + bytes(1),
                    bytes('SmbSign', encoding='ascii') + bytes(1),
                    )[:SMB2_KEY_SIZE]
        else: # dialect >= VERSION_0311
            self.signing_key = derive_key(session_key,
                    bytes('SMBSigningKey', encoding='ascii') + bytes(1),
                    self.preauth_hash,
                    )[:SMB2_KEY_SIZE]

    def ntlm_password(self, domain, user):
        """
        Look up the password for domain\\user in the NTLM_USER_FILE. The
        file has one 'domain:user:password' entry per line. We match the
        domain the client sent us, which is the target name we put in the
        CHALLENGE, so an entry for Config.server_name is what a client
        that has not been told a domain will end up asking for.
        """
        if not Config.ntlm_user_file:
            print('No ntlm_user_file configured, can not authenticate')
            return None

        try:
            with open(Config.ntlm_user_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.count(':') != 2:
                        continue
                    _domain, _user, _password = line.split(':')
                    if _user.upper() != user.upper():
                        continue
                    if domain and _domain.upper() != domain.upper():
                        continue
                    return _password
        except OSError as e:
            print('Can not read', Config.ntlm_user_file, e)
            return None

        print('No entry for', domain + '\\' + user, 'in', Config.ntlm_user_file)
        return None

    def ntlmssp_negotiate(self, msg):
        """
        Answer a NTLMSSP NEGOTIATE with a CHALLENGE.

        The names we put in here are not cosmetic. The client copies the
        target info into its response and the target name becomes the
        domain it hashes the password with, so they have to be the names
        we expect to find in the NTLM_USER_FILE.
        """
        flags = msg['negotiate_flags'] & (
                ntlmssp.NTLMSSP_NEGOTIATE_SIGN |
                ntlmssp.NTLMSSP_NEGOTIATE_SEAL |
                ntlmssp.NTLMSSP_NEGOTIATE_KEY_EXCH |
                ntlmssp.NTLMSSP_NEGOTIATE_128 |
                ntlmssp.NTLMSSP_NEGOTIATE_56 |
                ntlmssp.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        #
        # We only do unicode strings, and we always send a target info
        # since that is what a NTLMv2 client needs.
        #
        flags = flags | (ntlmssp.NTLMSSP_NEGOTIATE_UNICODE |
                         ntlmssp.NTLMSSP_REQUEST_TARGET |
                         ntlmssp.NTLMSSP_NEGOTIATE_NTLM |
                         ntlmssp.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                         ntlmssp.NTLMSSP_NEGOTIATE_TARGET_INFO |
                         ntlmssp.NTLMSSP_TARGET_TYPE_SERVER)

        self._ntlm_server_challenge = secrets.token_bytes(8)
        self._ntlm_challenge = ntlmssp.encode_challenge({
                'negotiate_flags': flags,
                'server_challenge': self._ntlm_server_challenge,
                'target_name': Config.server_name,
                'target_info': ntlmssp.make_target_info(Config.server_name,
                                                        Config.domain_name),
                })
        return self._ntlm_challenge

    def ntlmssp_authenticate(self, auth, blob):
        """
        Verify a NTLMSSP AUTHENTICATE and return the session key.
        Raises if the client does not check out.
        """
        if self._ntlm_challenge is None:
            raise ValueError('AUTHENTICATE without a CHALLENGE')

        if not auth['user'] or not auth['nt_challenge_response']:
            raise ValueError('Anonymous authentication is not supported')

        password = self.ntlm_password(auth['domain'], auth['user'])
        if password is None:
            raise ValueError('No password for ' + auth['domain'] + '\\' +
                             auth['user'])

        session_base_key = ntlmssp.verify_ntlmv2(password, auth,
                                                 self._ntlm_server_challenge)
        if session_base_key is None:
            raise ValueError('Bad password for ' + auth['domain'] + '\\' +
                             auth['user'])

        session_key = ntlmssp.exported_session_key(session_base_key, auth)

        #
        # If the client computed a MIC then it covers all three messages
        # and proves that nobody downgraded the flags on the way here.
        #
        if ntlmssp.has_mic(auth):
            mic = ntlmssp.compute_mic(session_key, self._ntlm_negotiate,
                                      self._ntlm_challenge, blob)
            if not hmac.compare_digest(mic, auth['mic']):
                raise ValueError('Bad MIC in AUTHENTICATE')

        print('Authenticated as', auth['domain'] + '\\' + auth['user'])
        return session_key

    def authentication_failed(self, hdr, e):
        if not Config.guest_login:
            print('Authentication failed:', e)
            return (Status.LOGON_FAILURE,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        if Config.signing_required:
            print('Authentication failed, and guest login is unavailable '
                  'when signing is required:', e)
            return (Status.LOGON_FAILURE,
                    ErrorResponse.encode({'error_data' : bytes(1)}))

        print('Authentication failed, logging in as guest:', e)
        self._use_signing = False
        self._guest = True
        hdr['session_id'] = self._sesid
        self.sessions.update({self._sesid: (None,)})
        self._sesid = self._sesid + 1
        return (Status.SUCCESS,
                SessionSetup.encode(Direction.REPLY,
                        {'session_flags': SMB2_SESSION_FLAG_IS_GUEST,
                         }))

    def srv_sess_setup(self, hdr, pdu):
        #
        # The token is either a raw NTLMSSP message or one wrapped in
        # SPNEGO, depending on what the client made of the blob we sent
        # in the negotiate reply. Reply in whichever form we were asked.
        #
        try:
            token = spnego.decode(pdu['security_buffer'])
            msg = ntlmssp.decode(token['mech_token'])
        except Exception as e:
            return self.authentication_failed(hdr, e)

        if msg['message_type'] == ntlmssp.NEGOTIATE_MESSAGE:
            self._ntlm_negotiate = token['mech_token']
            challenge = self.ntlmssp_negotiate(msg)
            if token['wrapped']:
                challenge = spnego.encode_neg_token_resp(
                        spnego.ACCEPT_INCOMPLETE, spnego.NTLMSSP_OID,
                        challenge)

            return (Status.MORE_PROCESSING_REQUIRED,
                    SessionSetup.encode(Direction.REPLY,
                                        {'session_flags': 0,
                                         'security_buffer': challenge,
                                         }))

        try:
            session_key = self.ntlmssp_authenticate(msg, token['mech_token'])
        except Exception as e:
            return self.authentication_failed(hdr, e)

        self.generate_keys(session_key)
        #
        # TODO store user/session data in this tuple
        hdr['session_id'] = self._sesid
        self.sessions.update({self._sesid: (None,)})
        self._sesid = self._sesid + 1

        reply = {'session_flags': 0}
        if token['wrapped']:
            reply.update({'security_buffer':
                    spnego.encode_neg_token_resp(spnego.ACCEPT_COMPLETE)})

        return (Status.SUCCESS,
                SessionSetup.encode(Direction.REPLY, reply))
        
    def srv_sess_logoff(self, hdr, pdu):
        del self.sessions[hdr['session_id']]
        return (Status.SUCCESS,
                TreeDisconnect.encode(Direction.REPLY, {}))
        
    def srv_neg_prot(self, hdr, pdu):
        if Config.signing_required:
            if pdu['security_mode'] & SMB2_NEGOTIATE_SIGNING_ENABLED == 0:
                print('Signing required but client does not offer signing')
                raise ValueError
        if Config.signing_enabled:
            if pdu['security_mode'] & SMB2_NEGOTIATE_SIGNING_ENABLED != 0:
                self._use_signing = True
        else:
            if pdu['security_mode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED != 0:
                print('Signing disabled but client requires it')
                raise ValueError

        # Only allow version 3.02
        if not VERSION_0302 in pdu['dialects']:
            print('No supported dialect in Negotiate Protocol')
            return (Status.INVALID_PARAMETER,
                    ErrorResponse.encode({'error_data' : bytes(1)}))
        self.dialect = VERSION_0302
        #
        # Tell the client that NTLMSSP is all we have. Without this a
        # client that was built with kerberos will try kerberos against
        # us and get nowhere.
        #
        return (Status.SUCCESS,
                NegotiateProtocol.encode(Direction.REPLY,
                       {'security_mode': SMB2_NEGOTIATE_SIGNING_ENABLED,
                        'dialect_revision': self.dialect,
                        'capabilities': 0,
                        'max_transact_size': 65536,
                        'max_read_size': 65536,
                        'max_write_size': 65536,
                        'security_buffer': spnego.encode_neg_token_init(
                                [spnego.NTLMSSP_OID]),
                        'system_time': (int(time.time()), 0, 0)}))

    def VerifySignature(self, hdr, cmd):
        if self.dialect == VERSION_0202:
            print('Can not compute signature for 2.02 yet')
            raise ValueError
        else:
            mac = cmd[48:64]
            zsc = cmd[:48] + bytes(16) + cmd[64:]
            co = CMAC.new(self.signing_key, ciphermod=AES)
            co.update(zsc)
            co.verify(mac)

    def ComputeSignature(self, buf):
        if self.dialect == VERSION_0202:
            print('Can not compute signature for 2.02 yet')
            raise ValueError
        else:
            co = CMAC.new(self.signing_key, ciphermod=AES)
            co.update(buf)
            d = co.digest()
            return d

    def ProcessCommands(self, cmds):
        r = []
        self._compound_error = Status.SUCCESS
        for cmd in cmds:
            #
            # Decode the command pdu
            #
            h = cmd[0]
            if h['flags'] & SIGNED:
                self.VerifySignature(cmd[0], cmd[1])
            ct = {
                Command.NEGOTIATE_PROTOCOL: (NegotiateProtocol, self.srv_neg_prot),
                Command.SESSION_SETUP: (SessionSetup, self.srv_sess_setup),
                Command.SESSION_LOGOFF: (SessionLogoff, self.srv_sess_logoff),
                Command.TREE_CONNECT: (TreeConnect, self.srv_tree_conn),
                Command.TREE_DISCONNECT: (TreeDisconnect, self.srv_tree_disconn),
                Command.CREATE: (Create, self.srv_create),
                Command.CLOSE: (Close, self.srv_close),
                Command.FLUSH: (Flush, self.srv_flush),
                Command.READ: (Read, self.srv_read),
                Command.WRITE: (Write, self.srv_write),
                Command.QUERY_INFO: (QueryInfo, self.srv_query_info),
                Command.QUERY_DIRECTORY: (QueryDirectory, self.srv_query_dir),
                Command.SET_INFO: (SetInfo, self.srv_set_info),
                }

            f = RESPONSE
            f = f | (h['flags'] & RELATED)
            _sign = self._use_signing
            if h['command'] == Command.NEGOTIATE_PROTOCOL.value:
                _sign = False
            if h['command'] == Command.SESSION_SETUP.value:
                _sign = False
            if _sign:
                f = f | SIGNED

            if self._compound_error != Status.SUCCESS:
                rh = Header.encode({'protocol_id': SMB2_MAGIC,
                                    'credit_charge': h['credit_charge'],
                                    'status': self._compound_error.value,
                                    'command': h['command'],
                                    'credit_response': h['credit_request'],
                                    'flags': f,
                                    'message_id': h['message_id'],
                                    'process_id': h['process_id'],
                                    'tree_id': h['tree_id'],
                                    'session_id': h['session_id']})
                r.append((rh,
                    ErrorResponse.encode({'error_data' : bytes(1)})))
                continue

            try:
                c = ct.get(Command(h['command']))
                req = c[0].decode(Direction.REQUEST, cmd[1][64:])
            except:
                print('Can not handle command', h['command'], 'yet.')
                rh = Header.encode({'protocol_id': SMB2_MAGIC,
                                    'credit_charge': h['credit_charge'],
                                    'status': Status.INVALID_PARAMETER.value,
                                    'command': h['command'],
                                    'credit_response': h['credit_request'],
                                    'flags': f,
                                    'message_id': h['message_id'],
                                    'process_id': h['process_id'],
                                    'tree_id': h['tree_id'],
                                    'session_id': h['session_id']})
                r.append((rh,
                          ErrorResponse.encode({'error_data' : bytes(1)})))
                continue

            rep = c[1](h, req)

            #
            # A command handler that returns None wants this command
            # dropped without any reply at all. Nothing does that during
            # normal operation, it is there for the reproducers that need
            # a client to sit and wait for a reply that never arrives.
            #
            if rep is None:
                continue

            if h['command'] == Command.SESSION_SETUP.value and self._use_signing and rep[0].value == 0:
                f = f | SIGNED

            rh = Header.encode({'protocol_id': SMB2_MAGIC,
                                'credit_charge': h['credit_charge'],
                                'status': rep[0].value,
                                'command': h['command'],
                                'credit_response': h['credit_request'],
                                'flags': f,
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
                cmds.append((_h, buf[:_h['next_command']]))
                buf = buf[_h['next_command']:]
            else:
                cmds.append((_h, buf[:]))
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
            # Every command in this chain was dropped, so there is nothing
            # to reply with. Do not send an empty pdu back.
            #
            if not rep:
                continue

            #
            # Concatenate them into a single bytearray, take care of padding
            # and next command
            #
            buf = bytearray(0)
            _pos = 0
            _last_pos = 0
            _num = len(rep)
            for idx, r in enumerate(rep):
                buf = buf + r[0] + r[1]
                _len = len(buf)
                if _len % 8:
                    _pad = ((_len + 7) & 0xfff8) - _len
                    buf = buf + bytearray(_pad)

                if idx + 1 != _num:
                    struct.pack_into('<I', buf, _pos + 20, len(buf) - _pos)
                if buf[_pos + 16] & SIGNED:
                    buf[_pos + 48:_pos + 64] = self.ComputeSignature(buf[_pos:])

                _last_pos = _pos
                _pos = len(buf)

            spl = bytearray(4)
            struct.pack_into('>I', spl, 0, len(buf))
            while len(spl):
                l = self._s.send(spl)
                spl = spl[l:]
            while len(buf):
                l = self._s.send(buf)
                buf = buf[l:]
        
