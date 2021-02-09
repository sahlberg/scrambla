#!/usr/bin/env python
# coding: utf-8

from smb2.filesystem_info import FSInfo, FSInfoClass

fs_sector_size_buf_1 = bytes([
    0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

fs_volume_buf_1 = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x82, 0x24, 0x31, 0x60, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x53, 0x00, 0x4e, 0x00, 0x41, 0x00,
    0x50, 0x00, 0x2d, 0x00, 0x34, 0x00
])

fs_device_buf_1 = bytes([
    0x07, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00
])

fs_attribute_buf_1 = bytes([
    0x6f, 0x00, 0x01, 0x00, 0xff, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x54, 0x00,
    0x46, 0x00, 0x53, 0x00
])

fs_full_size_buf_1 = bytes([
    0x70, 0x30, 0x7f, 0x5a, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x7b, 0xe4, 0x4d, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x7b, 0xe4, 0x4d, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
])

def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()

def main():
    print('Decode and re-encode a FileSystem SectorSize info structure #1')
    fs = FSInfo()
    info = fs.decode(FSInfoClass.SECTOR_SIZE, fs_sector_size_buf_1)
    buf = fs.encode(FSInfoClass.SECTOR_SIZE, info)

    if fs_sector_size_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(fs_sector_size_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a FileSystem Volume info structure #1')
    fs = FSInfo()
    info = fs.decode(FSInfoClass.VOLUME, fs_volume_buf_1)
    buf = fs.encode(FSInfoClass.VOLUME, info)

    if fs_volume_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(fs_volume_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a FileSystem Device info structure #1')
    fs = FSInfo()
    info = fs.decode(FSInfoClass.DEVICE, fs_device_buf_1)
    buf = fs.encode(FSInfoClass.DEVICE, info)

    if fs_device_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(fs_device_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)
        
    print('Decode and re-encode a FileSystem Attribute info structure #1')
    fs = FSInfo()
    info = fs.decode(FSInfoClass.ATTRIBUTE, fs_attribute_buf_1)
    buf = fs.encode(FSInfoClass.ATTRIBUTE, info)

    if fs_attribute_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(fs_attribute_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)

    print('Decode and re-encode a FileSystem Full Size info structure #1')
    fs = FSInfo()
    info = fs.decode(FSInfoClass.FULL_SIZE, fs_full_size_buf_1)
    buf = fs.encode(FSInfoClass.FULL_SIZE, info)

    if fs_full_size_buf_1 != buf:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(fs_full_size_buf_1)
        print('Encoded:')
        pr(buf)
        exit(1)
        

if __name__ == "__main__":
    main()
