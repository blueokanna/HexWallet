"""Public outgoing-payment fixtures for Ryo v3 and post-HF6 Zano."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from privacy_interop import IDENTITY, L, Oracle, ROOT, fixture_scalar, scalar, reference_sign
from ryo_transaction_interop import H, varint

FIXTURES = ROOT / 'tests/fixtures/privacy/payment-outputs.json'
NATIVE = bytes.fromhex('d6329b5b1f7c0805b5c345f4957554002a2f557845f64d7645dae0e051a6498a')


def zano(o, index, amount, payment, asset, explicit):
    secret = fixture_scalar('Zano public output fixture')
    spend, view = o.mul(o.G, 5), o.mul(o.G, 17)
    h = o.hs(o.mul(view, 8 * secret) + varint(index))

    def mask(domain):
        return o.hs(domain.encode().ljust(31, b'_') + b'\0' + scalar(h))

    protection = scalar(mask('ZANO_HDS_OUT_AMOUNT_MASK'))
    blinded = asset if explicit else o.add(asset, o.mul(o.X, mask('ZANO_HDS_OUT_ASSET_BLIND_MASK')))
    inv8 = pow(8, -1, L)
    req = scalar(secret) + spend + view + asset + struct.pack('<QQQB', index, amount, payment, explicit)
    expected = dict(stealth=o.add(spend, o.mul(o.G, h)).hex(),
        concealing=o.mul(view, mask('ZANO_HDS_OUT_CONCEALING_POINT')).hex(),
        asset=o.mul(blinded, inv8).hex(),
        commitment=o.mul(o.combine(blinded, amount, o.G, mask('ZANO_HDS_OUT_AMOUNT_BLIND_MASK')), inv8).hex(),
        amount=str(amount ^ int.from_bytes(protection[:8], 'little')),
        payment_id=str(payment ^ int.from_bytes(protection[8:16], 'little')))
    scan = scalar(17) + spend + o.mul(o.G, secret) + struct.pack('<Q', index)
    scan += b''.join(bytes.fromhex(expected[field]) for field in ('stealth', 'concealing', 'commitment', 'asset'))
    scan += struct.pack('<QQ', int(expected['amount']), int(expected['payment_id']))
    return dict(request=req.hex(), expected=expected, scan=scan.hex(),
                received=dict(asset=asset.hex(), amount=str(amount), payment_id=str(payment),
                              amount_mask=scalar(mask('ZANO_HDS_OUT_AMOUNT_BLIND_MASK')).hex(),
                              asset_mask=scalar(0 if explicit else mask('ZANO_HDS_OUT_ASSET_BLIND_MASK')).hex()))


def ryo(o, has_id, spend=19, view=23):
    template = json.loads((FIXTURES.parent / 'ryo-transactions.json').read_text())['cases'][0]
    tx, ring = bytes.fromhex(template['wire']), bytes.fromhex(template['rings'])
    loc = template['locations']
    secret = fixture_scalar('Ryo public payment fixture')
    recipient = o.mul(o.G, 7) + o.mul(o.G, 11)
    wallet = o.mul(o.G, spend) + o.mul(o.G, view)
    destinations = [wallet, recipient] if has_id else [recipient, wallet]
    prefix = tx[:loc['output_count'] + 1]
    ecdh = b''
    for i, address in enumerate(destinations):
        key = o.hs(o.mul(address[32:], 8 * secret) + varint(i))
        prefix += b'\0\x02' + o.add(address[:32], o.mul(o.G, key))
        first = o.hs(scalar(key))
        mask = fixture_scalar(f'public Ryo Bulletproof fixture/[123456, 123457]/mask/{i}')
        ecdh += scalar(mask + first) + scalar(123456 + i + o.hs(scalar(first)))

    payment_id = bytes(range(32))
    plain = bytes(8) + payment_id if has_id else b'\xff' * 8 + bytes(32)
    pad = ctypes.create_string_buffer(40)
    destination = recipient if has_id else wallet
    assert o.dll.oracle_payment_pad(o.mul(destination[32:], 8 * secret), pad) == 1
    extra = b'\x01' + o.mul(o.G, secret) + b'\x05' + bytes(a ^ b for a, b in zip(plain, pad.raw, strict=True))
    prefix += varint(len(extra)) + extra
    base = tx[loc['rct_type']:loc['ecdh']] + ecdh + tx[loc['ecdh'] + 128:loc['proof_count']]
    proof = tx[loc['proof']:loc['signatures']]
    rounds = proof[192]
    fields = proof[:192] + proof[193:193 + 32 * rounds] + proof[194 + 32 * rounds:]
    prehash = o.hash(o.hash(b'ryo-currency' + prefix) + o.hash(base) + o.hash(fields))
    label = 'public Ryo transaction/3/1/25/2'
    pseudo = tx[loc['pseudo_outs']:]
    request = b'HRYO' + struct.pack('<II', 25, 0) + prehash + bytes(32)
    request += scalar(fixture_scalar(label + '/spend/0')) + scalar(fixture_scalar(label + '/mask/0')) + pseudo + ring
    sig = reference_sign(o, request)
    assert o.verify(request, sig)
    wire = prefix + base + struct.pack('<I', 1) + proof + sig[64:] + sig[:32] + pseudo
    expected = dict(amount=str(123456 + int(has_id)), change=str(123457 - int(has_id)), fee='1000000')
    if has_id: expected['payment_id'] = payment_id.hex()
    return dict(wire=wire.hex(), keys=(scalar(secret) + recipient + wallet).hex(), expected=expected,
                extra=loc['extra_length'] + 1, ecdh=len(prefix) + loc['ecdh'] - loc['rct_type'])


def spend_case(o, payment, count, fee_delta=0, spend=19, view=23):
    template = json.loads((FIXTURES.parent / 'ryo-transactions.json').read_text())['cases'][0]
    loc = template['locations']
    payment_wire = bytes.fromhex(payment['wire'])
    proof_size = loc['signatures'] - loc['proof']
    base_start = payment['ecdh'] - (loc['ecdh'] - loc['rct_type'])
    base_end = base_start + loc['proof_count'] - loc['rct_type']
    base = payment_wire[base_start:base_end]
    proof = payment_wire[base_end + 4:base_end + 4 + proof_size]
    # The size of these fixtures depends only on the input count and fee
    # varint width. Solve the floor using the final serialized byte count.
    original_fee = int(payment['expected']['fee'])
    old_fee_bytes = len(varint(original_fee))
    # Each new input uses a 3-byte initial offset and 24 two-byte deltas.
    prefix_size = 3 + 86 * count + base_start - loc['output_count']
    size_without_fee = prefix_size + len(base) - old_fee_bytes + 4 + len(proof) + count * (1632 + 32)
    fee = original_fee
    while True:
        computed = 25 * 500000 + (size_without_fee + len(varint(fee))) * 500000 // 1024 + fee_delta
        if computed == fee: break
        fee = computed
    base = base[:1] + varint(fee) + base[1 + old_fee_bytes:]
    total = int(payment['expected']['amount']) + int(payment['expected']['change']) + fee
    total_mask = sum(fixture_scalar(f'public Ryo Bulletproof fixture/[123456, 123457]/mask/{j}') for j in range(2))
    inputs = []
    for i in range(count):
        amount = total if count == 1 else (470000 if i == 0 else total - 470000)
        pseudo_mask = total_mask if count == 1 else (97 if i == 0 else total_mask - 97)
        funding, index = 67 + i, 128 + i
        key = o.hs(o.mul(o.G, 8 * view * funding) + varint(index))
        private = (key + spend) % L
        mask = fixture_scalar(f'public Ryo funding mask/{i}')
        first = o.hs(scalar(key))
        real = 7 + i
        ring = bytearray.fromhex(template['rings'])
        dest = o.mul(o.G, private)
        ring[real*64:(real+1)*64] = dest + o.combine(o.G, mask, H, amount)
        image = o.mul(o.hp(dest), private)
        indices = [40000 * (i + 1) + 130 * j for j in range(25)]
        vin = b'\x02\x00\x19' + varint(indices[0]) + varint(130)*24 + image
        src = struct.pack('<IQ', real, index) + o.mul(o.G, funding) + scalar(mask + first)
        src += scalar(amount + o.hs(scalar(first))) + scalar(pseudo_mask)
        src += b''.join(struct.pack('<Q', v) + ring[j*64:(j+1)*64] for j, v in enumerate(indices))
        inputs.append((image, vin, src, o.combine(o.G, pseudo_mask % L, H, amount)))
    inputs.sort(reverse=True)
    prefix = bytes([3, 0, count]) + b''.join(v[1] for v in inputs) + payment_wire[loc['output_count']:base_start]
    head = prefix + base + struct.pack('<I', 1) + proof
    wire = head + bytes(count * 1632) + b''.join(v[3] for v in inputs)
    assert fee == 25 * 500000 + len(wire) * 500000 // 1024 + fee_delta
    context = scalar(spend) + scalar(view) + bytes.fromhex(payment['keys'])[:96] + b'\0' + b''.join(v[2] for v in inputs)
    rounds = proof[192]
    proof_fields = proof[:192] + proof[193:193 + 32*rounds] + proof[194 + 32*rounds:]
    message = o.hash(o.hash(b'ryo-currency' + prefix) + o.hash(base) + o.hash(proof_fields))
    return dict(wire=wire.hex(), context=context.hex(), sig_offset=len(head), digest=message.hex(),
                expected={k: v for k, v in payment['expected'].items() if k != 'payment_id'} | {'total': str(total), 'fee': str(fee)})


def run(args):
    if args.write_fixtures:
        o = Oracle(args.oracle)
        cases = dict(ryo=[ryo(o, True), ryo(o, False)], zano=[
            zano(o, 0, 1, 7, NATIVE, True), zano(o, 127, 2**64 - 1, 0, NATIVE, False),
            zano(o, 128, 0, 2**64 - 1, o.mul(o.G, 43), False)])
        cases['spends'] = [spend_case(o, p, i + 1) for i, p in enumerate(cases['ryo'])]
        underpaid = spend_case(o, cases['ryo'][0], 1, fee_delta=-1)
        cases['below_relay_floor'] = {k: underpaid[k] for k in ('wire', 'context')}
    else:
        cases = json.loads(FIXTURES.read_text())
    calls = 0
    with tempfile.TemporaryDirectory() as folder:
        def check(mode, inputs, expected):
            nonlocal calls
            args_ = [str(args.probe.resolve()), 'privacy-' + mode]
            for i, data in enumerate(inputs):
                path = Path(folder) / str(i)
                path.write_bytes(data)
                args_.append(str(path))
            r = subprocess.run(args_, capture_output=True, text=True, timeout=120)
            assert r.returncode == (1 if expected is None else 0), (mode, r.returncode, r.stdout, r.stderr)
            if expected is not None:
                fields = dict(line.split('=', 1) for line in r.stdout.splitlines())
                assert expected.items() <= fields.items(), (expected, fields)
            calls += 1
            return fields if expected is not None else {}

        rings = bytes.fromhex(json.loads((FIXTURES.parent / 'ryo-transactions.json').read_text())['cases'][0]['rings'])
        for case in cases['ryo']:
            wire, keys = bytes.fromhex(case['wire']), bytes.fromhex(case['keys'])
            check('ryo-transaction', [wire, rings], {'mlsag': 'pass'})
            check('ryo-payment', [wire, keys], case['expected'])
            for index in (1, case['extra'], case['extra'] + 1, case['extra'] + 33,
                          case['extra'] + 34, case['ecdh'], case['ecdh'] + 32, case['ecdh'] + 64):
                corrupt = bytearray(wire)
                corrupt[index] ^= 1
                check('ryo-payment', [corrupt, keys], None)
            for index in (0, 32, 64, 96, 128):
                corrupt = bytearray(keys)
                corrupt[index:index + 32] = bytes(32)
                check('ryo-payment', [wire, corrupt], None)
        for case in cases['zano']:
            req = bytes.fromhex(case['request'])
            check('zano-output', [req], case['expected'])
            for index in (0, 32, 64, 96):
                corrupt = bytearray(req)
                corrupt[index:index + 32] = bytes(32) if index == 0 else IDENTITY
                check('zano-output', [corrupt], None)
            if req[96:128] != NATIVE: check('zano-output', [req[:-1] + b'\x01'], None)
            scan = bytes.fromhex(case['scan'])
            check('zano-scan', [scan], case['received'])
            for offset in (0, 32, 64, 96, 104, 136, 168, 200, 232):
                changed = bytearray(scan)
                changed[offset] ^= 1
                check('zano-scan', [changed], None)
            check('zano-scan', [scan[:240] + bytes(8)], dict(case['received'], payment_id='0'))
            collision = int(case['received']['payment_id']) ^ int(case['expected']['payment_id'])
            if collision:
                check('zano-output', [req[:144] + struct.pack('<Q', collision) + req[152:]], None)
        for case in cases['spends']:
            wire, ctx = bytes.fromhex(case['wire']), bytes.fromhex(case['context'])
            signed = bytes.fromhex(check('ryo-spend', [wire, ctx], case['expected'])['signed'])
            pos = case['sig_offset']
            count = wire[2]
            assert int(case['expected']['fee']) == 25 * 500000 + len(wire) * 500000 // 1024
            end = pos + count * 1632
            assert signed[:pos] == wire[:pos] and signed[end:] == wire[end:]
            digest = hashlib.sha256(signed).hexdigest()
            if args.write_fixtures or args.oracle:
                verifier = o if args.write_fixtures else Oracle(args.oracle)
                for i in range(count):
                    src = ctx[161+i*1940:161+(i+1)*1940]
                    ring = b''.join(src[148+j*72:212+j*72] for j in range(25))
                    image = wire[3 + i*86 + 54:3 + (i+1)*86]
                    response = signed[pos+i*1632:pos+(i+1)*1632]
                    assert verifier.dll.oracle_ryo(bytes.fromhex(case['digest']), ring, 25, signed[end+i*32:end+(i+1)*32],
                                                   image, response[-32:], response[:-32]) == 1
            if args.write_fixtures: case['signed_sha256'] = digest
            assert digest == case['signed_sha256']
            for field in (0, 32, 64, 96, 128, 161, 165, 173, 205, 237, 269, 301):
                changed = bytearray(ctx)
                changed[field] ^= 1
                check('ryo-spend', [wire, changed], None)
            for mode in (1, 2, 3):
                check('ryo-spend', [wire, ctx[:160] + bytes([mode]) + ctx[161:]], None)
            if count == 2:
                swapped = wire[:3] + wire[89:175] + wire[3:89] + wire[175:]
                check('ryo-spend', [swapped, ctx[:161] + ctx[2101:] + ctx[161:2101]], None)
        low = cases['below_relay_floor']
        check('ryo-spend', [bytes.fromhex(low['wire']), bytes.fromhex(low['context'])], None)
    if args.write_fixtures: FIXTURES.write_text(json.dumps(cases, indent=2) + '\n')
    print(f'Ryo payment decoding and spending / Zano output construction and scanning: {calls} checks passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--oracle', type=Path)
    parser.add_argument('--write-fixtures', action='store_true')
    run(parser.parse_args())
