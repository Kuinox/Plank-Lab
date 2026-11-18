#!/usr/bin/env python3
"""Dump Thrift compact-protocol structures from a Parquet file.

  tdump.py <file.parquet>              the footer (FileMetaData)
  tdump.py <file.parquet> <offset>     one struct starting at <offset> (a page header,
                                       an OffsetIndex, a ColumnIndex, ...)
A leading fuzz selector byte is not stripped; pass the bare Parquet file.
"""
import struct
import sys

NAMES = {1: 'true', 2: 'false', 3: 'i8', 4: 'i16', 5: 'i32', 6: 'i64', 7: 'double', 8: 'binary',
         9: 'list', 10: 'set', 11: 'map', 12: 'struct', 13: 'uuid'}


class R:
    def __init__(self, data, pos):
        self.d, self.p = data, pos

    def byte(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def varint(self):
        v = s = 0
        while True:
            b = self.byte()
            v |= (b & 0x7F) << s
            s += 7
            if b < 0x80:
                return v

    def zigzag(self):
        v = self.varint()
        return (v >> 1) ^ -(v & 1)

    def value(self, t, depth):
        pad = '  ' * depth
        if t in (1, 2):
            return t == 1
        if t == 3:
            return struct.unpack('b', bytes([self.byte()]))[0]
        if t in (4, 5, 6):
            return self.zigzag()
        if t == 7:
            v = struct.unpack('<d', self.d[self.p:self.p + 8])[0]
            self.p += 8
            return v
        if t == 8:
            n = self.varint()
            v = self.d[self.p:self.p + n]
            self.p += n
            return v if n <= 32 else v[:32] + b'...(%d bytes)' % n
        if t == 13:
            v = self.d[self.p:self.p + 16]
            self.p += 16
            return v.hex()
        if t in (9, 10):
            h = self.byte()
            n, et = h >> 4, h & 15
            if n == 15:
                n = self.varint()
            items = []
            for _ in range(n):
                items.append(self.value(et, depth + 1) if et not in (1, 2) else bool(self.byte() == 1))
            return items
        if t == 11:
            n = self.varint()
            if n == 0:
                return {}
            kv = self.byte()
            return [(self.value(kv >> 4, depth + 1), self.value(kv & 15, depth + 1)) for _ in range(n)]
        if t == 12:
            return self.struct(depth + 1)
        raise ValueError(f'type {t} at {self.p}')

    def struct(self, depth=0):
        out = []
        last = 0
        while True:
            start = self.p
            h = self.byte()
            if h == 0:
                return out
            t, delta = h & 15, h >> 4
            fid = last + delta if delta else self.zigzag()
            last = fid
            out.append((start, fid, NAMES.get(t, t), self.value(t, depth)))


def show(fields, depth=0):
    for start, fid, t, v in fields:
        pad = '  ' * depth
        if t == 'struct':
            print(f'{pad}@{start} {fid}: struct')
            show(v, depth + 1)
        elif t == 'list' and v and isinstance(v[0], list):
            print(f'{pad}@{start} {fid}: list[{len(v)}] of struct')
            for i, item in enumerate(v):
                print(f'{pad}  [{i}]')
                show(item, depth + 2)
        else:
            print(f'{pad}@{start} {fid}: {t} = {v}')


def main():
    data = open(sys.argv[1], 'rb').read()
    if len(sys.argv) > 2:
        offset = int(sys.argv[2], 0)
    else:
        footer_len = struct.unpack('<I', data[-8:-4])[0]
        offset = len(data) - 8 - footer_len
        print(f'footer at {offset}, {footer_len} bytes, file {len(data)} bytes')
    r = R(data, offset)
    show(r.struct())
    print(f'end at {r.p}')


if __name__ == '__main__':
    main()
