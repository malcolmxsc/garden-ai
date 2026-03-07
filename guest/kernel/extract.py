import sys
import os

def extract(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    # Search for gzip magic: 1F 8B 08 00
    gzip_idx = data.find(b'\x1f\x8b\x08\x00')
    if gzip_idx != -1:
        print(f"Found gzip stream at byte offset {gzip_idx}")
        with open('kernel.gz', 'wb') as f:
            f.write(data[gzip_idx:])
        os.system('gunzip -f kernel.gz')
        print("Successfully extracted kernel.gz to kernel")
        return

    # Search for zstd magic: 28 B5 2F FD
    zstd_idx = data.find(b'\x28\xb5\x2f\xfd')
    if zstd_idx != -1:
        print(f"Found zstd stream at byte offset {zstd_idx}")
        with open('kernel.zst', 'wb') as f:
            f.write(data[zstd_idx:])
        os.system('unzstd -f kernel.zst')
        print("Successfully extracted kernel.zst to kernel")
        return

    # Search for LZ4 magic: 02 21 4C 18
    lz4_idx = data.find(b'\x02\x21\x4c\x18')
    if lz4_idx != -1:
        print(f"Found lz4 stream at byte offset {lz4_idx}")
        with open('kernel.lz4', 'wb') as f:
            f.write(data[lz4_idx:])
        os.system('lz4 -d -f kernel.lz4 kernel')
        print("Successfully extracted kernel.lz4 to kernel")
        return

    print("Could not find any known compression signatures (gzip, zstd, lz4)")

extract('vmlinuz-virt')
