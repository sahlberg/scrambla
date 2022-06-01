#!/usr/bin/env python
# coding: utf-8

from smb2.unicode import UCS2toUTF8, UTF8toUCS2

ucs2_buf_1 = bytes([
    0x5c, 0x00, 0x5c, 0x00, 0x77, 0x00, 0x69, 0x00,
    0x6e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00,
    0x31, 0x00, 0x5c, 0x00, 0x53, 0x00, 0x68, 0x00,
    0x61, 0x00, 0x72, 0x00, 0x65, 0x00
])

utf8_buf_1 = bytes('/abc/def/', encoding='utf=8')

def pr(buf):
    for i in buf:
        print("%02x " % i, end='')
    print()

def main():
    print('Decode and re-encode a UCS2 string #1')
    utf8 = UCS2toUTF8(ucs2_buf_1)
    ucs2 = UTF8toUCS2(utf8)
    
    if ucs2_buf_1 != ucs2:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(ucs2_buf_1)
        print('Encoded:')
        pr(ucs2)
        exit(1)

    print('Decode and re-encode a UTF8 path #1')
    ucs2 = UTF8toUCS2(utf8_buf_1).replace(b'/', b'\\')
    utf8 = UCS2toUTF8(ucs2).replace(b'\\', b'/')

    if utf8_buf_1 != utf8:
        print('Re-encoded content mismatch')
        print('Original:')
        pr(utf8_buf_1)
        print('Encoded:')
        pr(utf8)
        exit(1)
        

if __name__ == "__main__":
    main()
