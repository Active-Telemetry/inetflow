#!/usr/bin/env python3
"""Write each frame of the pcap files as a fuzz input, with a flags byte."""
import os
import struct
import sys

# Ethernet with every parse option, as in fuzz_flow.c
FLAGS = 0x33


def frames(path):
    with open(path, 'rb') as f:
        data = f.read()
    magic = struct.unpack('<I', data[:4])[0]
    endian = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    offset = 24
    while offset + 16 <= len(data):
        incl = struct.unpack(endian + 'IIII', data[offset:offset + 16])[2]
        offset += 16
        yield data[offset:offset + incl]
        offset += incl


def main():
    if len(sys.argv) < 3:
        sys.exit('usage: pcap_to_corpus.py OUTDIR PCAP...')
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    count = 0
    for path in sys.argv[2:]:
        for frame in frames(path):
            with open(os.path.join(outdir, 'seed%04d' % count), 'wb') as f:
                f.write(bytes([FLAGS]) + frame)
            count += 1
    print('%d inputs written to %s' % (count, outdir))


if __name__ == '__main__':
    main()
