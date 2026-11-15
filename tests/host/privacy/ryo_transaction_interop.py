"""Ryo type-3 transaction codec, proof binding and MLSAG integration tests.

Fixture construction is independent Python code using pinned upstream ref10
and Keccak. This is not a node integration test or a wallet signing command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from privacy_interop import Oracle, ROOT, L, IDENTITY, scalar, fixture_scalar, reference_sign

FIXTURES = ROOT / "tests/fixtures/privacy/ryo-transactions.json"
H = bytes.fromhex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
SOURCES = {
    'src/cryptonote_config.h': '388f0f8311319b753dc38fcefa2fe79c1996857292254b97fd9606da715d8fee',
    'src/cryptonote_basic/cryptonote_basic.h': '57a13661f5a4a4da7967d7a4e2e26bf4399e9e4ac7c2f7f8fe90dfd299b0b159',
    'src/cryptonote_basic/cryptonote_format_utils.cpp': '40d951c84928d45d4cf3e743546437d8b934db9710c21529f35d8258f9c979d3',
    'src/ringct/rctTypes.h': '1eaf43f1132ffaf009d997eef4257cda092311cb7bacac80c5c020a2b32227d7',
    'src/ringct/rctSigs.cpp': 'd59f92e548c61f0e7e8991e2d0f3768b3c9bda6a30a9344d43ffea57df9d85d2',
}


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def build(o, version, inputs, ring_size, outputs):
    proof_case = next(c for c in json.loads((FIXTURES.parent / "ryo-bulletproofs.json").read_text())['cases']
                      if c['name'] == (f"independent-{outputs}-123456" if outputs > 1 else "independent-1-0"))
    bp = bytes.fromhex(proof_case['data'])
    assert bp[0] == outputs
    commitments = [o.mul(bp[1 + 32*i:33 + 32*i], 8) for i in range(outputs)]
    proof = bp[1 + 32*outputs:]
    rounds = proof[192]
    fee = 1000000
    pseudo_sum = o.mul(H, fee)
    for commitment in commitments: pseudo_sum = o.add(pseudo_sum, commitment)
    pseudos = [o.mul(o.G, i + 1) for i in range(inputs - 1)]
    for pseudo in pseudos: pseudo_sum = o.sub(pseudo_sum, pseudo)
    pseudos.append(pseudo_sum)
    label = f"public Ryo transaction/{version}/{inputs}/{ring_size}/{outputs}"
    rings, witnesses = [], []
    for index, pseudo in enumerate(pseudos):
        x = fixture_scalar(label + f"/spend/{index}")
        z = fixture_scalar(label + f"/mask/{index}")
        real = index % ring_size
        ring = []
        for j in range(ring_size):
            spend = x if j == real else fixture_scalar(label + f"/decoy/{index}/{j}")
            mask = z if j == real else fixture_scalar(label + f"/decoy-mask/{index}/{j}")
            ring.append(o.mul(o.G, spend) + o.add(pseudo, o.mul(o.G, mask)))
        rings.append(b"".join(ring))
        witnesses.append((x, z, real, o.mul(o.hp(ring[real][:32]), x)))
    prefix = bytes([version, 0]) + varint(inputs)
    locations = {"input_count": 2, "images": [], "offset_counts": [], "offsets": []}
    for i, (_, _, _, image) in enumerate(witnesses):
        prefix += b"\x02\x00"
        locations['offset_counts'].append(len(prefix))
        prefix += varint(ring_size)
        locations['offsets'].append(len(prefix))
        prefix += varint(0) + varint(1) * (ring_size - 1)
        locations['images'].append(len(prefix))
        prefix += image
    locations['output_count'] = len(prefix)
    prefix += varint(outputs)
    for i in range(outputs):
        prefix += b"\x00\x02" + o.mul(o.G, fixture_scalar(label + f"/destination/{i}"))
    locations['extra_length'] = len(prefix)
    extra = b"\x01" + o.mul(o.G, fixture_scalar(label + "/tx-key"))
    prefix += varint(len(extra)) + extra
    locations['rct_type'] = len(prefix)
    base = b"\x03" + varint(fee)
    locations['ecdh'] = len(prefix) + len(base)
    # Legacy ECDH encoding for the public range-proof fixture amounts/masks.
    amounts = [123456 + i for i in range(outputs)] if outputs > 1 else [0]
    proof_label = "public Ryo Bulletproof fixture/" + str(amounts)
    for i in range(outputs):
        mask = fixture_scalar(proof_label + f"/mask/{i}")
        key = fixture_scalar(label + f"/amount-key/{i}")
        h1 = o.hs(scalar(key)); h2 = o.hs(scalar(h1))
        base += scalar(mask + h1) + scalar(amounts[i] + h2)
        assert o.combine(o.G, mask, H, amounts[i]) == commitments[i]
    base += b"".join(commitments)
    prefix_hash = o.hash((b"ryo-currency" if version == 3 else b"") + prefix)
    base_hash = o.hash(base)
    proof_fields = proof[:192] + proof[193:193 + 32*rounds] + proof[194 + 32*rounds:]
    signing_hash = o.hash(prefix_hash + base_hash + o.hash(proof_fields))
    prunable = struct.pack("<I", 1) + proof
    locations['proof_count'] = len(prefix) + len(base)
    locations['proof'] = locations['proof_count'] + 4
    locations['signatures'] = locations['proof'] + len(proof)
    for i, (x, z, real, image) in enumerate(witnesses):
        request = b"HRYO" + struct.pack("<II", ring_size, real) + signing_hash + bytes(32)
        request += scalar(x) + scalar(z) + pseudos[i] + rings[i]
        signature = reference_sign(o, request)
        assert o.verify(request, signature) and signature[32:64] == image
        prunable += signature[64:] + signature[:32]
    locations['pseudo_outs'] = len(prefix) + len(base) + len(prunable)
    prunable += b"".join(pseudos)
    prunable_hash = o.hash(prunable)
    return dict(name=f"v{version}-in{inputs}-ring{ring_size}-out{outputs}",
        wire=(prefix + base + prunable).hex(), rings=b"".join(rings).hex(), locations=locations,
        hashes=dict(prefix=prefix_hash.hex(), base=base_hash.hex(), prunable=prunable_hash.hex(),
                    transaction=o.hash(prefix_hash + base_hash + prunable_hash).hex(), signing=signing_hash.hex()))


def run(args):
    if args.write_fixtures:
        if not args.oracle or not args.ryo_source: raise ValueError("Regeneration requires pinned upstream oracle and Ryo source")
        for name, expected in SOURCES.items():
            data = (args.ryo_source / name).read_bytes().replace(b'\r\n', b'\n')
            if hashlib.sha256(data).hexdigest() != expected: raise ValueError(f'Upstream source changed: {name}')
        o = Oracle(args.oracle)
        cases = [build(o, *shape) for shape in [(3, 1, 25, 2), (2, 2, 2, 1), (3, 8, 25, 16), (3, 1, 241, 3)]]
        FIXTURES.write_text(json.dumps(dict(ryo_commit="185dd1fa33ba88c88bb22df9069ad368c0f9a27e",
            description="Independent synthetic transactions with public witnesses; never broadcast or fund.", cases=cases), indent=2) + "\n")
    else:
        cases = json.loads(FIXTURES.read_text())['cases']
    calls = 0
    with tempfile.TemporaryDirectory(prefix="ryo-tx-") as folder:
        wire_path, rings_path = Path(folder) / "tx.bin", Path(folder) / "rings.bin"
        def check(wire, ring, accepted, parse_only=False):
            nonlocal calls
            wire_path.write_bytes(wire); rings_path.write_bytes(ring)
            mode = "privacy-ryo-parse" if parse_only else "privacy-ryo-transaction"
            command = [str(args.probe.resolve()), mode, str(wire_path)]
            if not parse_only: command.append(str(rings_path))
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            assert result.returncode == (0 if accepted else 1), (result.returncode, result.stdout, result.stderr)
            calls += 1
            return dict(line.split("=", 1) for line in result.stdout.splitlines())
        for case in cases:
            wire, ring = bytes.fromhex(case['wire']), bytes.fromhex(case['rings'])
            actual = check(wire, ring, True)
            assert all(actual[k] == v for k, v in case['hashes'].items()) and actual['mlsag'] == 'pass'
            print(case['name'] + ': hashes/proof/balance/MLSAG pass', flush=True)
            subprocess.run([str(args.probe.resolve()), 'privacy-ryo-parser-stress', str(wire_path)], check=True, timeout=120)
            locations = case['locations']
            cuts = {0, 1, 2, len(wire) - 1}
            for value in locations.values():
                cuts.update(value if isinstance(value, list) else [value])
            for cut in sorted(cuts): check(wire[:cut], ring, False, True)
            check(wire + b"\0", ring, False, True)
            check(b"\x83\0" + wire[1:], ring, False, True)
            for name in ('input_count', 'output_count', 'offset_counts', 'proof_count'):
                offsets = locations[name]
                for offset in offsets if isinstance(offsets, list) else [offsets]:
                    for replacement in (b"\0", b"\xff\xff\xff\xff\x0f"):
                        check(wire[:offset] + replacement + wire[offset + 1:], ring, False, True)
            offset = locations['offsets'][0] + 1
            check(wire[:offset] + b"\0" + wire[offset + 1:], ring, False, True)
            offset = locations['offsets'][0]
            check(wire[:offset] + varint(2**64 - 1) + wire[offset + 1:], ring, False, True)
            offset = locations['proof'] + 192
            check(wire[:offset] + b"\x0b" + wire[offset + 1:], ring, False, True)
            # All these still parse, but must fail the cryptographic checks.
            offsets = [locations['images'][0], locations['ecdh'], locations['proof'],
                       locations['signatures'], locations['pseudo_outs'], locations['rct_type'] + 1,
                       locations['extra_length'] + 2]
            for offset in offsets:
                changed = bytearray(wire); changed[offset] ^= 1
                check(changed, ring, False)
            for offset in (locations['ecdh'], locations['signatures']):
                changed = wire[:offset] + L.to_bytes(32, 'little') + wire[offset + 32:]
                check(changed, ring, False)
            for offset in locations['images'] + [locations['pseudo_outs']]:
                check(wire[:offset] + IDENTITY + wire[offset + 32:], ring, False)
            if len(locations['images']) > 1:
                first, second = locations['images'][:2]
                check(wire[:second] + wire[first:first + 32] + wire[second + 32:], ring, False, True)
            changed_ring = bytearray(ring); changed_ring[0] ^= 1
            check(wire, changed_ring, False)
        print(f"Ryo transactions: {len(cases)} fixtures, {calls} firmware invocations passed", flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--oracle', type=Path)
    parser.add_argument('--ryo-source', type=Path)
    parser.add_argument('--write-fixtures', action='store_true')
    run(parser.parse_args())
