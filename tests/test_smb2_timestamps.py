#!/usr/bin/env python
# coding: utf-8

from smb2.timestamps import WinToTimeval, TimevalToWin

time_1 = 1234567890123456780

def main():
    print('Convert a WIN timestamp to timeval and back #1')
    tv = WinToTimeval(time_1)
    win = TimevalToWin(tv)
    
    if win != time_1:
        print('Re-conversion mismatch')
        print('Original win value', time_1)
        print('Re-encoded value', win)
        exit(1)


if __name__ == "__main__":
    main()
