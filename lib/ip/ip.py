# -*- coding: utf-8 -*-

import os
import socket
import struct
try:
    import mmap
except ImportError:
    mmap = None

__all__ = ['IPv4Database', 'find']

_unpack_V = lambda b: struct.unpack("<L", b)[0]
_unpack_N = lambda b: struct.unpack(">L", b)[0]


def _unpack_C(b):
    if isinstance(b, int):
        return b
    return struct.unpack("B", b)[0]


datfile = os.path.join(os.path.dirname(__file__), "17monipdb.dat")


class IPv4Database(object):
    """Database for search IPv4 address.

    The 17mon dat file format in bytes::

        -----------
        | 4 bytes |                     <- offset number
        -----------------
        | 256 * 4 bytes |               <- first ip number index
        -----------------------
        | offset - 1028 bytes |         <- ip index
        -----------------------
        |    data  storage    |
        -----------------------
    """
    def __init__(self, filename=None, use_mmap=True):
        if filename is None:
            filename = datfile
        with open(filename, 'rb') as f:
            if use_mmap and mmap is not None:
                buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            else:
                buf = f.read()
                use_mmap = False

        self._use_mmap = use_mmap
        self._buf = buf

        self._offset = _unpack_N(buf[:4])
        self._is_closed = False

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self._use_mmap:
            self._buf.close()
        self._is_closed = True

    def _lookup_ipv4(self, ip):
        nip = socket.inet_aton(ip)

        # first IP number
        fip = bytearray(nip)[0]
        # 4 + (fip - 1) * 4
        fip_offset = fip * 4 + 4

        # position in the index block
        count = _unpack_V(self._buf[fip_offset:fip_offset + 4])
        pos = count * 8

        offset = pos + 1028

        data_length = 0
        data_pos = 0

        lo, hi = 0, (self._offset - offset) // 8

        while lo < hi:
            mid = (lo + hi) // 2
            mid_offset = pos + 1028 + 8 * mid
            mid_val = self._buf[mid_offset: mid_offset+4]

            if mid_val < nip:
                lo = mid + 1
            else:
                hi = mid

        offset = pos + 1028 + 8 * lo
        if offset == self._offset:
            return None

        data_pos = _unpack_V(self._buf[offset + 4:offset + 7] + b'\0')
        data_length = _unpack_C(self._buf[offset + 7])

        offset = self._offset + data_pos - 1024
        value = self._buf[offset:offset + data_length]
        return value.decode('utf-8').strip()

    def find(self, ip):
        if self._is_closed:
            raise ValueError('I/O operation on closed dat file')

        return self._lookup_ipv4(ip)


def find(ip):
    # keep find for compatibility
    try:
        ip = socket.gethostbyname(ip)
    except socket.gaierror:
        return

    with IPv4Database() as db:
        return db.find(ip)
