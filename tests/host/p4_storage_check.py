"""Exercise the Board 7 partition geometry and LittleFS commit sequence on simulated flash."""

import hashlib
import struct
import sys
from pathlib import Path

from littlefs import LittleFS, UserContext


class Flash(UserContext):
    def __init__(self, memory):
        super().__init__(buffer=memory)
        self.journal = None

    def read(self, cfg, block, off, size):
        start = block * cfg.block_size + off
        return bytearray(self.buffer[start:start + size])

    def prog(self, cfg, block, off, data):
        start = block * cfg.block_size + off
        if self.journal is not None:
            self.journal.append((start, bytes(data)))
        assert all((a & b) == b for a, b in zip(self.buffer[start:start + len(data)], data))
        self.buffer[start:start + len(data)] = data
        return 0

    def erase(self, cfg, block):
        start = block * cfg.block_size
        erased = b'\xff' * cfg.block_size
        if self.journal is not None:
            self.journal.append((start, erased))
        self.buffer[start:start + cfg.block_size] = erased
        return 0


def volume(context):
    return LittleFS(context=context, mount=False, block_count=6144, block_size=4096, block_cycles=512,
                    read_size=128, prog_size=128, lookahead_size=128, cache_size=512, name_max=63)


def table(count):
    records = bytearray(b'HXCT' + bytes([2, count]))
    for i in range(count):
        records.extend(struct.pack('<16sB32sB32sB13s12s24sB', b'eth', 0, bytes([i + 1]) * 20, 20,
                                   b'', 0, b'', f'T{i}'.encode(), f'Token {i}'.encode(), 18))
    return records + hashlib.sha256(records).digest()[:8]


def read_table(context):
    fs = volume(context)
    fs.mount()
    with fs.open('tokens', 'rb') as file:
        result = file.read()
    fs.unmount()
    return result


def check_upgrade_ranges(build, memory, assets):
    table_bytes = (build / 'HexWallet.ino.partitions.bin').read_bytes()
    parts = {}
    for magic, _, _, offset, size, label, _ in struct.iter_unpack('<HBBII16sI', table_bytes):
        if magic != 0x50aa:
            break
        parts[label.rstrip(b'\0').decode()] = (offset, size)

    def program(start, data, limit):
        end = start + (len(data) + 4095) // 4096 * 4096
        assert start % 4096 == 0 and start < end <= limit <= len(memory)
        memory[start:end] = b'\xff' * (end - start)
        memory[start:start + len(data)] = data

    # These are the locations of user records in the old layout.
    saved = {}
    for i, (start, length) in enumerate([(0x9000, 0x5000), (0x3d0000, 0x20000), (0x400000, 0x1000)]):
        saved[start] = bytes([0xa0 + i]) * length
        memory[start:start + length] = saved[start]

    assets_digest = hashlib.sha256(assets).digest()
    flags, *images = (build / 'flash_args').read_text().splitlines()
    assert '--flash-size 32MB' in flags
    written = []
    for line in images:
        addr, name = line.split()
        start = int(addr, 0)
        program(start, (build / name).read_bytes(), len(memory))
        written.append(start)
    assert written == [0x2000, 0x8000, 0xe000, 0x10000]
    assert all(memory[start:start + len(data)] == data for start, data in saved.items())
    assert hashlib.sha256(assets).digest() == assets_digest

    app = (build / 'HexWallet.ino.bin').read_bytes()
    for slot in ('app1', 'app0'):
        start, size = parts[slot]
        end = start + size
        before = hashlib.sha256(memory[:start]).digest(), hashlib.sha256(memory[end:]).digest()
        memory[start:end] = b'\xff' * size
        program(start, app, end)
        assert memory[start:start + len(app)] == app
        assert (hashlib.sha256(memory[:start]).digest(), hashlib.sha256(memory[end:]).digest()) == before
    assert hashlib.sha256(assets).digest() == assets_digest


def check(build):
    factory = (build / 'HexWallet.ino.merged.bin').read_bytes()
    assert len(factory) == 8 * 1024**2
    memory = bytearray(b'\xff') * (32 * 1024**2)
    memory[:len(factory)] = factory
    assets = memoryview(memory)[len(factory):]
    chip = Flash(assets)
    fs = volume(chip)
    fs.format()
    fs.mount()
    old, new = table(3), table(64)
    with fs.open('tokens', 'wb') as file:
        file.write(old)
    # Exercise addresses on both sides of 0x1000000 with independently verifiable data.
    chunk = bytes(range(256)) * 256
    with fs.open('catalog-data', 'wb') as file:
        for i in range(272):
            file.write(struct.pack('<I', i) + chunk[4:])
    fs.unmount()
    assert read_table(chip) == old
    fs.mount()
    initial = bytearray(assets)
    chip.journal = []
    with fs.open('tokens.tmp', 'wb') as file:
        file.write(new)
        file.flush()
    fs.rename('tokens.tmp', 'tokens')
    fs.unmount()
    assert read_table(chip) == new

    # Replay loss of power halfway through and immediately after every erase/program.
    replay = Flash(initial)
    for start, data in chip.journal:
        mid = len(data) // 2
        initial[start:start + mid] = data[:mid]
        assert read_table(replay) in (old, new)
        initial[start + mid:start + len(data)] = data[mid:]
        assert read_table(replay) in (old, new)
    assert read_table(replay) == new
    assert memory[:len(factory)] == factory
    check_upgrade_ranges(build, memory, assets)
    # Factory programming also stops at the assets boundary. It erases the old NVS range.
    before = hashlib.sha256(assets).digest()
    memory[:len(factory)] = factory
    assert hashlib.sha256(assets).digest() == before
    assert read_table(chip) == new
    fs.mount()
    with fs.open('catalog-data', 'rb') as file:
        for i in range(272):
            assert file.read(len(chunk)) == struct.pack('<I', i) + chunk[4:]
        assert not file.read(1)
    fs.unmount()
    print(f'24 MiB LittleFS simulation passed: 17 MiB readback, {2 * len(chip.journal)} interrupted writes, '
          'migration with retained NVS/SPIFFS/keys, both OTA slot ranges and factory programming')


if __name__ == '__main__':
    check(Path(sys.argv[1]))
