#!/usr/bin/env python3
"""Build the ZEC4 review payload accepted by `zec inspect` on HexWallet.

Only Overwinter/Sapling v4 transparent transactions are accepted. The tool
parses the unsigned transaction, validates that every scriptSig is empty and
that every output is a t1/t3 script, then appends the per-input prevout data
the device needs for the ZIP-243 digest.

Example:
  python tools/build_zcash_review_payload.py \
    --tx-hex 0400008085202f89... \
    --input 50000000:76a914...88ac:0:0:0

Input values are zats (1 ZEC = 100,000,000 zats). For each input the script
must be the previous output's 25-byte P2PKH scriptPubKey. The tool also prints
the ZIP-243 SIGHASH_ALL digest for every input so an independent implementation
can compare before the device signs.
"""
import argparse
import hashlib
import struct
import sys

MAGIC = b"ZEC4"
V4_VERSION = 0x80000004
SAPLING_VERSION_GROUP_ID = 0x892F2085
DEFAULT_BRANCH_ID = 0x5437F330  # Zcash mainnet NU6.2
MAX_ZATS = 21_000_000 * 100_000_000
SIGHASH_ALL = 1


def read_compact(data, offset):
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    if first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def parse_transaction(data):
    offset = 0
    version, version_group = struct.unpack_from("<II", data, offset)
    offset += 8
    if version != V4_VERSION or version_group != SAPLING_VERSION_GROUP_ID:
        raise ValueError("expected a Sapling/Overwinter v4 transaction")
    input_count, offset = read_compact(data, offset)
    inputs = []
    for _ in range(input_count):
        prevout = data[offset:offset + 36]
        offset += 36
        script_size, offset = read_compact(data, offset)
        script_sig = data[offset:offset + script_size]
        offset += script_size
        sequence = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if script_size != 0:
            raise ValueError("unsigned transaction must have empty scriptSigs")
        inputs.append((prevout, sequence))
    output_count, offset = read_compact(data, offset)
    outputs = []
    for _ in range(output_count):
        value = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
        script_size, offset = read_compact(data, offset)
        script = data[offset:offset + script_size]
        offset += script_size
        outputs.append((value, script))
    lock_time, expiry_height = struct.unpack_from("<II", data, offset)
    offset += 8
    value_balance = struct.unpack_from("<q", data, offset)[0]
    offset += 8
    shielded_spends, offset = read_compact(data, offset)
    offset += shielded_spends * 384
    shielded_outputs, offset = read_compact(data, offset)
    offset += shielded_outputs * 948
    joinsplits, offset = read_compact(data, offset)
    offset += joinsplits * 1698
    if joinsplits:
        offset += 96
    if shielded_spends or shielded_outputs:
        offset += 64
    if value_balance != 0 or shielded_spends or shielded_outputs or joinsplits:
        raise ValueError("only transparent v4 transactions are supported")
    if offset != len(data):
        raise ValueError("trailing bytes after the v4 transaction")
    return inputs, outputs, lock_time, expiry_height


def personal_hash(person, payload):
    return hashlib.blake2b(payload, digest_size=32, person=person).digest()


def zip243_digest(tx, inputs, outputs, lock_time, expiry_height, values,
                  scripts, index, branch_id):
    prevouts = b"".join(prevout for prevout, _ in inputs)
    sequences = b"".join(struct.pack("<I", sequence) for _, sequence in inputs)
    output_bytes = b"".join(
        struct.pack("<Q", value) + bytes([len(script)]) + script
        for value, script in outputs
    )
    preimage = struct.pack("<II", V4_VERSION, SAPLING_VERSION_GROUP_ID)
    preimage += personal_hash(b"ZcashPrevoutHash", prevouts)
    preimage += personal_hash(b"ZcashSequencHash", sequences)
    preimage += personal_hash(b"ZcashOutputsHash", output_bytes)
    preimage += b"\x00" * 32 * 3  # JoinSplits, shielded spends, shielded outputs
    preimage += struct.pack("<IIqI", lock_time, expiry_height, 0, SIGHASH_ALL)
    prevout, sequence = inputs[index]
    preimage += prevout
    preimage += bytes([len(scripts[index])]) + scripts[index]
    preimage += struct.pack("<Q", values[index])
    preimage += struct.pack("<I", sequence)
    person = b"ZcashSigHash" + struct.pack("<I", branch_id)
    return personal_hash(person, preimage)


def parse_input(text):
    parts = text.split(":")
    if len(parts) != 5:
        raise argparse.ArgumentTypeError(
            "input must be VALUE:SCRIPT:ACCOUNT:CHANGE:INDEX")
    value = int(parts[0], 0)
    script = bytes.fromhex(parts[1])
    account = int(parts[2], 0)
    change = int(parts[3], 0)
    index = int(parts[4], 0)
    if not 0 <= value <= MAX_ZATS:
        raise argparse.ArgumentTypeError("input value is out of range")
    if len(script) != 25 or script[:3] != b"\x76\xa9\x14" or script[-2:] != b"\x88\xac":
        raise argparse.ArgumentTypeError("input script must be a 25-byte P2PKH script")
    if not 0 <= account < 0x80000000 or change not in (0, 1) or not 0 <= index < 0x80000000:
        raise argparse.ArgumentTypeError("invalid derivation path component")
    return value, script, account, change, index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tx-hex", required=True, help="unsigned v4 transaction hex")
    parser.add_argument("--branch-id", type=lambda value: int(value, 0),
                        default=DEFAULT_BRANCH_ID,
                        help=f"consensus branch id (default 0x{DEFAULT_BRANCH_ID:08x})")
    parser.add_argument("--input", action="append", type=parse_input, required=True,
                        dest="inputs",
                        help="VALUE_ZATS:SCRIPT_HEX:ACCOUNT:CHANGE:INDEX")
    args = parser.parse_args()

    tx = bytes.fromhex(args.tx_hex)
    inputs, outputs, lock_time, expiry_height = parse_transaction(tx)
    if len(args.inputs) != len(inputs):
        raise SystemExit(f"transaction has {len(inputs)} inputs, "
                         f"but {len(args.inputs)} --input records were supplied")
    if not outputs:
        raise SystemExit("transaction has no outputs")
    for value, script in outputs:
        if not ((len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac")
                or (len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87")):
            raise SystemExit("every output must be a t1 P2PKH or t3 P2SH script")
        if value > MAX_ZATS:
            raise SystemExit("output value is out of range")

    values = [entry[0] for entry in args.inputs]
    scripts = [entry[1] for entry in args.inputs]
    if sum(values) < sum(value for value, _ in outputs):
        raise SystemExit("inputs do not cover the outputs")

    payload = bytearray()
    payload += MAGIC
    payload += struct.pack("<I", args.branch_id)
    payload += struct.pack("<I", len(tx))
    payload += tx
    payload += bytes([len(args.inputs)])
    for value, script, account, change, index in args.inputs:
        payload += struct.pack("<Q", value)
        payload += bytes([len(script)]) + script
        payload += struct.pack("<I", account)
        payload += bytes([change])
        payload += struct.pack("<I", index)

    print(payload.hex())
    for index, (value, script, _, _, _) in enumerate(args.inputs):
        digest = zip243_digest(tx, inputs, outputs, lock_time, expiry_height,
                               values, scripts, index, args.branch_id)
        print(
            f"input[{index}] value={value} sighash={digest.hex()} "
            f"fee={sum(values) - sum(item[0] for item in outputs)}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
