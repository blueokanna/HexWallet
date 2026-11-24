"""Exercise the phone payment protocol using the public BIP39 host wallet."""
import argparse
import ctypes
import json
import os
import secrets
from pathlib import Path
import struct
import subprocess
import tempfile

from payment_interop import L, Oracle, ROOT, ryo, scalar, spend_case, varint
from native_rpc_check import offline_node


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True, help='TEST_RYO_PHONE_PAYMENTS=ON probe')
    parser.add_argument('--release-probe', type=Path, required=True, help='default catalog probe')
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--ryod', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('Checks require Python assertions')
    oracle = Oracle(args.oracle)
    oracle.dll.oracle_bulletproof.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    # ethers HDNodeWallet, "abandon" x 11 + "about", m/44'/382'/0'/0/3.
    spend = oracle.hs(bytes.fromhex('069b4a88474010274fa4f911c93ce869a3af8f253f172c96eb73e23be3dd4863'))
    view = oracle.hs(scalar(spend))
    with tempfile.TemporaryDirectory() as folder, offline_node(args.ryod, True) as port:
        for n in (1, 2):
            payment = ryo(oracle, n == 1, spend, view)
            case = spend_case(oracle, payment, n, spend=spend, view=view)
            if n == 1:
                # A fully balanced, over-cap payment. The same owned source
                # funds a valid maximum-frame payment at the exact fee cap.
                excess = 100000001 - int(case['expected']['fee'])
                over = spend_case(oracle, payment, n, fee_delta=excess, spend=spend, view=view)
                assert int(over['expected']['fee']) == 100000001
                ctx = bytes.fromhex(over['context'])
                src = ctx[161:]
                above_cap = (b'\x01' + struct.pack('<H', len(bytes.fromhex(over['wire']))) + bytes.fromhex(over['wire'])
                             + ctx[64:160] + src[:2] + src[4:])
            wire, ctx = bytes.fromhex(case['wire']), bytes.fromhex(case['context'])
            sources, images = [], []
            for i in range(n):
                src = ctx[161 + 1940*i:161 + 1940*(i+1)]
                real, index = struct.unpack_from('<IQ', src)
                ring = []
                for j in range(25):
                    record = src[140 + 72*j:212 + 72*j]
                    ring.append(dict(index=str(int.from_bytes(record[:8], 'little')), destination='0x'+record[8:40].hex(),
                                     commitment='0x'+record[40:].hex()))
                sources.append(dict(realIndex=real, outputIndex=str(index), fundingPublic='0x'+src[12:44].hex(),
                                    ecdh='0x'+src[44:108].hex(), pseudoMask='0x'+src[108:140].hex(), ring=ring))
                # Reconstruct the payer image from the owned funding output independently of the wire.
                destination = bytes.fromhex(ring[real]['destination'][2:])
                derivation = oracle.mul(src[12:44], view * 8)
                key = oracle.hs(derivation + varint(index))
                sources[-1]['amount'] = str((int.from_bytes(src[76:108], 'little') - oracle.hs(scalar(oracle.hs(scalar(key))))) % L)
                secret = (key + spend) % L
                hp = oracle.hp(destination)
                image = oracle.mul(hp, secret)
                nonce = secrets.randbelow(L - 1) + 1
                challenge = oracle.hs(image + oracle.mul(oracle.G, nonce) + oracle.mul(hp, nonce))
                images.append('0x' + image.hex())
                sources[-1].update(keyImage=images[-1], keyImageSignature='0x' + (
                    scalar(challenge) + scalar(nonce - challenge * secret)).hex())
            request = dict(unsigned='0x'+wire.hex(), txSecret='0x'+ctx[64:96].hex(), viewSecret='0x'+scalar(view).hex(),
                           recipient=dict(spend='0x'+ctx[96:128].hex(), view='0x'+ctx[128:160].hex()), sources=sources)
            fixture = Path(folder)/'case.json'
            output = Path(folder)/'signed'
            fixture.write_text(json.dumps(dict(request=request, payment=payment['expected'] | {'fee': case['expected']['fee']},
                                              sigOffset=case['sig_offset'], wallet=payment['keys'][192:],
                                              aboveCap=above_cap.hex() if n == 1 else None)))
            subprocess.run(['node', str(Path(__file__).with_name('phone_payment_check.cjs')), str(args.probe.resolve()),
                            str(args.release_probe.resolve()), str(fixture), str(output), port], check=True, timeout=150,
                           env={**os.environ, 'NODE_PATH': str(ROOT / 'tests/host/protocol-oracles/node_modules')})
            for path, outputs in ((output, 2), (output.with_suffix('.built'), n)):
                signed = path.read_bytes()
                fields = dict(line.split('=', 1) for line in subprocess.check_output(
                    [str(args.probe.resolve()), 'privacy-ryo-parse', str(path)], text=True).splitlines())
                if path == output: assert case['digest'] == fields['signing']
                start = len(signed) - n*(1632+32)
                proof_start = start - (290 + 64*(6 if outputs == 1 else 7))
                assert signed[proof_start-4:proof_start] == bytes([1,0,0,0])
                commitments = signed[proof_start-4-32*outputs:proof_start-4]
                compressed = b''.join(oracle.mul(commitments[i:i+32],pow(8,-1,L)) for i in range(0,len(commitments),32))
                proof = bytes([outputs]) + compressed + signed[proof_start:start]
                assert oracle.dll.oracle_bulletproof(proof,len(proof)) == 1
                for i, src in enumerate(sources):
                    ring = b''.join(bytes.fromhex(m['destination'][2:] + m['commitment'][2:]) for m in src['ring'])
                    pos = start + 1632*i
                    signature = signed[pos:pos+1632]
                    pseudo = signed[start+1632*n+32*i:][:32]
                    assert oracle.dll.oracle_ryo(bytes.fromhex(fields['signing']), ring, 25, pseudo,
                                                 bytes.fromhex(images[i][2:]), signature[-32:], signature[:-32]) == 1
    print('Pinned upstream verified 4 Bulletproofs and 6 MLSAGs from approved phone requests')


if __name__ == '__main__':
    main()
