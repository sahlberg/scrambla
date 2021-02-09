# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct

#
# WinToTimeval
#

#
# [0] : sec
# [1] : usec
# [2] : 0-9 in units off 100ns
#
def WinToTimeval(win):
    if win == 0:
        return (0, 0, 0)
    return (int((win - 116444736000000000) / 10000000),
            int((win % 10000000) / 10),
            win % 10)

def TimevalToWin(win):
    if win[0] == 0 and win[1] == 0 and win[2] == 0:
        return 0
    return win[0] * 10000000 + 116444736000000000 + win[1] * 10 + win[2];
