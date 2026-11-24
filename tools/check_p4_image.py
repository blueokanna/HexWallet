"""Verify the factory programming image and its partition table before distribution."""

import hashlib
import struct
import sys
from pathlib import Path


def verify(build, flash_mib=32):
    prefix = build / 'HexWallet.ino'
    image = Path(f'{prefix}.merged.bin').read_bytes()
    app = Path(f'{prefix}.bin').read_bytes()
    table = Path(f'{prefix}.partitions.bin').read_bytes()
    elf_hash = hashlib.sha256(Path(f'{prefix}.elf').read_bytes()).digest()
    if len(image) != 0x800000 or app[0xb0:0xd0] != elf_hash:
        raise ValueError('Factory size or embedded ELF digest mismatch')

    assets_offset, assets_size = {8: (0x7d0000, 0x20000), 32: (0x800000, 0x1800000)}[flash_mib]
    bootloader = Path(f'{prefix}.bootloader.bin').read_bytes()
    for component in (bootloader, app):
        if len(component) < 24 or component[0] != 0xe9 or 1 << (component[3] >> 4) != flash_mib:
            raise ValueError('Component flash capacity differs from the selected board profile')
    expected = [
        ('nvs', 1, 2, 0x9000, 0x5000, 0), ('otadata', 1, 0, 0xe000, 0x2000, 0),
        ('app0', 0, 0x10, 0x10000, 0x3c0000, 0), ('spiffs', 1, 0x82, 0x3d0000, 0x20000, 0),
        ('nvs_keys', 1, 4, 0x400000, 0x1000, 1), ('app1', 0, 0x11, 0x410000, 0x3c0000, 0),
        ('assets', 1, 0x83, assets_offset, assets_size, 0),
    ]
    for index, partition in enumerate(expected):
        magic, kind, subtype, start, size, name, flags = struct.unpack_from('<HBBII16sI', table, 32 * index)
        if magic != 0x50aa or (name.rstrip(b'\0').decode(), kind, subtype, start, size, flags) != partition:
            raise ValueError(f'Unexpected binary partition at index {index}')
    end = len(expected) * 32
    checksum = b'\xeb\xeb' + b'\xff' * 14 + hashlib.md5(table[:end]).digest()
    if table[end:end + 32] != checksum or table[end + 32:].strip(b'\xff'):
        raise ValueError('Partition table checksum or terminator mismatch')
    if len(app) > 0x3c0000 or len(app) < 0xd0:
        raise ValueError('App size outside OTA slot')

    factory = bytearray(b'\xff') * len(image)
    for offset, limit, blob in [(0x2000, 0x8000, bootloader),
                                (0x8000, 0x9000, table), (0xe000, 0x10000, (build / 'boot_app0.bin').read_bytes()),
                                (0x10000, 0x3d0000, app)]:
        if not blob or offset + len(blob) > limit:
            raise ValueError(f'Component outside programming range at {offset:#x}')
        factory[offset:offset + len(blob)] = blob
    if factory != image:
        raise ValueError('Factory image contains unexpected contents or offsets')
    print(f'factory={len(image)} bytes sha256={hashlib.sha256(image).hexdigest()}')
    print(f'app={len(app)} bytes sha256={hashlib.sha256(app).hexdigest()} elf_sha256={elf_hash.hex()}')
    print(f'flash={flash_mib} MiB ota_slots=3932160 bytes each '
          f'assets={assets_offset:#x}..{assets_offset + assets_size - 1:#x} ({assets_size} bytes)')


if __name__ == '__main__':
    verify(Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 32)
