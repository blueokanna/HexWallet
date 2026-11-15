"""Independent v0 Kaspa wire/hash/signature regression; no node acceptance claim.

Uses Google's Protobuf runtime with descriptors read from the pinned upstream
schema. Hash/mass equations follow rusty-kaspa's tx.rs, sighash.rs and mass/mod.rs.
Only public, deterministic test keys and synthetic outpoints are used.
"""
import argparse
import hashlib
import re
import struct
import subprocess
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/kaspa"
U16 = lambda n: struct.pack("<H", n)
U32 = lambda n: struct.pack("<I", n)
U64 = lambda n: struct.pack("<Q", n)
ZERO = bytes(32)


def transaction_class():
    # This schema has only flat messages and scalar/message fields. Reject any
    # unparsed declaration instead of silently inventing an incomplete schema.
    source = (FIXTURES / "p2p.proto").read_text(encoding="utf-8")
    expected = "4b7e0a1d4123cda5b5ca2257d04e61d0a6b25fe244a7a19d8bb588535a702f3f"
    if hashlib.sha256(source.encode()).hexdigest() != expected:
        raise ValueError("Pinned upstream p2p.proto changed")
    source = re.sub(r"//[^\n]*", "", source)
    fd = descriptor_pb2.FileDescriptorProto(name="p2p.proto", package="protowire", syntax="proto3")
    types = {"uint32": 13, "uint64": 4, "int64": 3, "bytes": 12, "bool": 8, "string": 9}
    for name, body in re.findall(r"message\s+(\w+)\s*\{([^{}]*)\}", source):
        message = fd.message_type.add(name=name)
        for declaration in body.split(";"):
            if not declaration.strip():
                continue
            match = re.fullmatch(r"\s*(repeated\s+)?(\w+)\s+(\w+)\s*=\s*(\d+)\s*", declaration)
            if not match:
                raise ValueError(f"Unsupported schema declaration: {declaration}")
            repeated, kind, field, number = match.groups()
            spec = message.field.add(name=field, number=int(number), label=3 if repeated else 1,
                                     type=types.get(kind, 11))
            if kind not in types:
                spec.type_name = f".protowire.{kind}"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fd)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("protowire.TransactionMessage"))


Transaction = transaction_class()


def hash_bytes(data, key=b"TransactionSigningHash"):
    return hashlib.blake2b(data, digest_size=32, key=key).digest()


def outpoint(value):
    return value.previousOutpoint.transactionId.bytes + U32(value.previousOutpoint.index)


def spk(value):
    return U16(value.version) + U64(len(value.script)) + value.script


def output(value):
    return U64(value.value) + spk(value.scriptPublicKey)


def txid(tx):
    preimage = U16(tx.version) + U64(len(tx.inputs))
    preimage += b"".join(outpoint(i) + U64(0) + U64(i.sequence) for i in tx.inputs)
    preimage += U64(len(tx.outputs)) + b"".join(map(output, tx.outputs))
    preimage += U64(tx.lockTime) + tx.subnetworkId.bytes + U64(tx.gas) + U64(len(tx.payload)) + tx.payload
    return hash_bytes(preimage, b"TransactionID")


def sighash(tx, index, hash_type, amount, input_script):
    base, anyone = hash_type & 7, bool(hash_type & 0x80)
    prev = ZERO if anyone else hash_bytes(b"".join(map(outpoint, tx.inputs)))
    seq = ZERO if anyone or base != 1 else hash_bytes(b"".join(U64(i.sequence) for i in tx.inputs))
    sigops = ZERO if anyone else hash_bytes(bytes(i.compute_commit for i in tx.inputs))
    outputs = ZERO
    if base == 1:
        outputs = hash_bytes(b"".join(map(output, tx.outputs)))
    elif base == 4 and index < len(tx.outputs):
        outputs = hash_bytes(output(tx.outputs[index]))
    current = tx.inputs[index]
    preimage = U16(tx.version) + prev + seq + sigops + outpoint(current)
    preimage += U16(0) + U64(len(input_script)) + input_script + U64(amount)
    preimage += U64(current.sequence) + bytes([current.compute_commit]) + outputs
    preimage += U64(tx.lockTime) + tx.subnetworkId.bytes + U64(tx.gas)
    preimage += hash_bytes(U64(len(tx.payload)) + tx.payload) if tx.payload else ZERO
    return hash_bytes(preimage + bytes([hash_type]))


def masses(tx, amounts):
    # These cases use ordinary P2PK scripts (plurality 1) throughout.
    size = 94 + sum(52 + len(i.signatureScript) for i in tx.inputs)
    size += sum(18 + len(o.scriptPublicKey.script) for o in tx.outputs) + len(tx.payload)
    compute = size + sum(2 + len(o.scriptPublicKey.script) for o in tx.outputs) * 10
    compute += sum(i.compute_commit for i in tx.inputs) * 1000
    constant = 10**12
    harmonic_out = sum(constant // o.value for o in tx.outputs)
    if len(tx.outputs) == 1 or len(amounts) == 1 or len(amounts) == len(tx.outputs) == 2:
        ins = sum(constant // amount for amount in amounts)
    else:
        ins = len(amounts) * (constant // max(1, sum(amounts) // len(amounts)))
    return compute, size * 4, max(0, harmonic_out - ins)


def reference_case(variant):
    tx = Transaction()
    tx.subnetworkId.bytes = bytes(20)
    tx.lockTime = 1615462089000 if variant else 0
    tx.payload = b"KAS" if variant == 3 else b""
    inputs, outputs = (8, 16) if variant == 2 else ((2, 2) if variant == 1 else (1, 1))
    for index in range(inputs):
        item = tx.inputs.add()
        item.previousOutpoint.transactionId.bytes = bytes([index + 1]) * 32
        item.previousOutpoint.index = index + 7
        item.sequence = 2**64 - 1 - index if variant else 0
        item.signatureScript = b"\x41" + bytes([0x11 + index]) * 64 + b"\x01"
        item.compute_commit = 1
    for index in range(outputs):
        item = tx.outputs.add(value=100000)
        item.scriptPublicKey.script = b"\x20" + bytes([0x21 + index]) * 32 + b"\xac"
    tx.storage_mass = masses(tx, [100000000] * inputs)[2]
    return tx


# Test-only, variable-time secp256k1 arithmetic: independent BIP340 verification.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a
    u, v = b
    if x == u and (y != v or y == 0): return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if a == b else (v - y) * pow(u - x, -1, P)) % P
    rx = (slope * slope - x - u) % P
    return rx, (slope * (x - rx) - y) % P


def mul(k, point):
    result = None
    while k:
        if k & 1: result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def verify_schnorr(public, message, signature):
    x = int.from_bytes(public, "big")
    r, s = (int.from_bytes(signature[i:i + 32], "big") for i in (0, 32))
    if x >= P or r >= P or s >= N: return False
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x**3 + 7) % P: return False
    if y & 1: y = P - y
    tag = hashlib.sha256(b"BIP0340/challenge").digest()
    e = int.from_bytes(hashlib.sha256(tag + tag + signature[:32] + public + message).digest(), "big") % N
    point = add(mul(s, G), mul(N - e, (x, y)))
    return point is not None and point[1] % 2 == 0 and point[0] == r


def selftest_wire():
    tx = Transaction()
    item = tx.inputs.add(compute_commit=1)
    item.previousOutpoint.transactionId.bytes = bytes.fromhex("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3")
    item.signatureScript = b"\x41" + b"\x11" * 64 + b"\x01"
    tx.outputs.add(value=1000).scriptPublicKey.script = bytes.fromhex("208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac")
    tx.subnetworkId.bytes = bytes(20)
    return tx.SerializeToString(deterministic=True)


def run(probe):
    lines = subprocess.check_output([str(probe), "signing-audit", "kaspa-reference"], text=True).splitlines()
    seen = 0
    while lines:
        case = lines.pop(0)
        if not case.startswith("case="): raise AssertionError(case)
        variant = int(case.split("=")[1])
        tx = reference_case(variant)
        expected_mass = masses(tx, [100000000] * len(tx.inputs))
        assert lines.pop(0) == "masses=" + ",".join(map(str, expected_mass))
        assert lines.pop(0) == "wire=" + tx.SerializeToString(deterministic=True).hex()
        assert lines.pop(0) == "id=" + txid(tx).hex()
        for index in range(len(tx.inputs)):
            for hash_type in (1, 2, 4, 0x81, 0x82, 0x84):
                expected = sighash(tx, index, hash_type, 100000000, b"\x20" + b"\x11" * 32 + b"\xac")
                assert lines.pop(0) == "sighash=" + expected.hex()
        seen += 1
    assert seen == 4
    values = dict(line.split("=", 1) for line in subprocess.check_output([str(probe), "signing-audit", "kaspa"], text=True).splitlines())
    tx = Transaction.FromString(bytes.fromhex(values["kaspa-signed"]))
    public = bytes.fromhex(values["kaspa-key"])
    assert len(tx.inputs) == len(tx.outputs) == 1 and tx.subnetworkId.bytes == bytes(20)
    assert tx.inputs[0].compute_commit == 1 and tx.inputs[0].signatureScript[:1] == b"\x41"
    assert len(tx.inputs[0].signatureScript) == 66 and tx.inputs[0].signatureScript[-1] == 1
    assert tx.outputs[0].value == 1999000 and tx.outputs[0].scriptPublicKey.script == b"\x20" + public + b"\xac"
    assert masses(tx, [2000000]) == (1624, 1056, tx.storage_mass) and tx.storage_mass == 250
    digest = sighash(tx, 0, 1, 2000000, b"\x20" + public + b"\xac")
    signature = tx.inputs[0].signatureScript[1:65]
    assert verify_schnorr(public, digest, signature)
    assert not verify_schnorr(public, bytes([digest[0] ^ 1]) + digest[1:], signature)
    expected = bytes.fromhex((FIXTURES / "selftest-wire.hex").read_text().strip())
    assert expected == selftest_wire()
    print("kaspa-reference=pass cases=4 sighashes=72 real-schnorr=pass schema=5417ed03")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--print-selftest", action="store_true")
    args = parser.parse_args()
    if args.print_selftest:
        print(selftest_wire().hex())
    elif args.probe:
        run(args.probe.resolve())
    else:
        parser.error("--probe is required")
