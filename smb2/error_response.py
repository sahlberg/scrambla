# coding: utf-8

# Copyright (C) 2020 by Ronnie Sahlberg<ronniesahlberg@gmail.com>
#

import struct

#
# SMB2 Error Response
#


class ErrorResponse(object):
    """
    A class for ErrorResponse
    """

    def __init__(self, **kwargs):
        True

    def __del__(self):
        True

    @staticmethod
    def decode(hdr):
        """
        Decode an Error Response
        """
        result = {}
        result.update({'structure_size': struct.unpack_from('<H', hdr, 0)[0]})
        if struct.unpack_from('<B', hdr, 2)[0]:
            # TODO handle error_context_count for 3.1.1
            print('We do not handle error_contexts yet')
        
        result.update({'error_data': hdr[8:]})

        return result

    @staticmethod
    def encode(hdr):
        """
        Encode an Error Response
        """
        result = bytearray(8)
        struct.pack_into('<H', result, 0, 9)
        # TODO handle error_context_count for 3.1.1
        if 'error_data' in hdr:
            result = result + hdr['error_data']

        return result
