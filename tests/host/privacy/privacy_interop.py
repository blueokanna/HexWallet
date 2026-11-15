"""Ryo MLSAG / Zano GGX interoperability and adversarial regression tests.

The optional oracle DLL contains the pinned upstream verifier bodies and ref10,
not HexWallet arithmetic. Python signing here is an independent TEST generator;
its public fixture secrets and deterministic nonces must never protect funds.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

L = 2**252 + 27742317777372353535851937790883648493
IDENTITY = bytes([1]) + bytes(31)
ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests/fixtures/privacy/ring-signatures.json"


def scalar(n):
    return (n % L).to_bytes(32, "little")


def fixture_scalar(label):
    return int.from_bytes(hashlib.sha512(label.encode()).digest(), "little") % L


class Oracle:
    def __init__(self, path):
        self.dll = C.CDLL(str(path.resolve()))
        self.dll.oracle_ryo.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t] + [C.c_char_p] * 4
        self.dll.oracle_zano.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t] + [C.c_char_p] * 8
        self.dll.oracle_hash.argtypes = [C.c_char_p, C.c_size_t, C.c_void_p]
        self.dll.oracle_mul.argtypes = [C.c_char_p, C.c_char_p, C.c_void_p]
        self.dll.oracle_add.argtypes = [C.c_char_p, C.c_char_p, C.c_void_p]
        self.dll.oracle_hp.argtypes = [C.c_char_p, C.c_void_p]
        self.G = self.call("g")
        self.X = self.call("x")
        assert self.G.hex() == "58" + "66" * 31
        assert self.X.hex() == "3a25bcdb43f5d2c9dd063dc39a9e0987bafc6fcf2df1bc76322d75884a4a3820"

    def call(self, name, *args):
        out = C.create_string_buffer(32)
        result = getattr(self.dll, "oracle_" + name)(*args, out)
        if name in ("mul", "add"):
            assert result == 1, name
        return out.raw

    def mul(self, point, n):
        return self.call("mul", point, scalar(n))

    def add(self, p, q):
        return self.call("add", p, q)

    def sub(self, p, q):
        return self.add(p, self.mul(q, -1))

    def hash(self, data):
        return self.call("hash", data, len(data))

    def hs(self, data):
        return int.from_bytes(self.hash(data), "little") % L

    def hp(self, p):
        return self.call("hp", p)

    def combine(self, p, a, q, b):
        return self.add(self.mul(p, a), self.mul(q, b))

    def verify(self, request, signature):
        d = decode(request)
        n = d["n"]
        if d["ryo"]:
            assert len(signature) == 64 + 64 * n
            return self.dll.oracle_ryo(d["message"], b"".join(d["ring"]), n,
                d["pseudo"][0], signature[32:64], signature[:32], signature[64:]) == 1
        assert len(signature) == 128 + 64 * n
        return self.dll.oracle_zano(d["message"], b"".join(d["ring"]), n,
            *d["pseudo"], signature[32:64], signature[64:96], signature[96:128],
            signature[:32], signature[128:128 + n * 32], signature[128 + n * 32:]) == 1


def decode(request):
    ryo = request[:4] == b"HRYO"
    n, index = struct.unpack_from("<II", request, 4)
    width, header = (64, 172) if ryo else (96, 236)
    secret_count = 2 if ryo else 3
    return dict(ryo=ryo, n=n, index=index, message=request[12:44],
        secrets=[int.from_bytes(request[76 + i * 32:108 + i * 32], "little") for i in range(secret_count)],
        pseudo=[request[i:i + 32] for i in range(76 + secret_count * 32, header, 32)],
        ring=[request[header + i * width:header + (i + 1) * width] for i in range(n)])


def make_request(o, ryo, n, index, zero=False):
    label = f"public fixture/{ryo}/{n}/{index}/{zero}"
    x, z, t = [fixture_scalar(label + f"/secret/{i}") for i in range(3)]
    if zero:
        z = t = 0
    amount = o.combine(o.G, 73, bytes.fromhex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"), 1000000)
    asset = o.combine(o.G, 41, o.X, 57)
    ring = []
    inv8 = pow(8, -1, L)
    for i in range(n):
        dest = o.mul(o.G, x if i == index else fixture_scalar(label + f"/dest/{i}"))
        cm = o.add(amount, o.mul(o.G, z if i == index else fixture_scalar(label + f"/mask/{i}")))
        if ryo:
            ring.append(dest + cm)
        else:
            tag = o.add(asset, o.mul(o.X, t if i == index else fixture_scalar(label + f"/asset/{i}")))
            ring.append(dest + o.mul(cm, inv8) + o.mul(tag, inv8))
    secrets = [x, z] if ryo else [x, z, t]
    pseudo = [amount] if ryo else [o.mul(amount, inv8), o.mul(asset, inv8)]
    return ((b"HRYO" if ryo else b"HZAN") + struct.pack("<II", n, index)
        + o.hash(label.encode()) + bytes(32) + b"".join(map(scalar, secrets))
        + b"".join(pseudo) + b"".join(ring))


def zano_context(o, d, image, k1, k2):
    h = o.hash(d["message"] + b"".join(d["ring"]) + b"".join(d["pseudo"]) + image + k1 + k2)
    domains = [b"ZANO_HDS_CLSAG_GGX_LAYER_ZERO__\0", b"ZANO_HDS_CLSAG_GGX_LAYER_ONE___\0", b"ZANO_HDS_CLSAG_GGX_LAYER_TWO___\0"]
    mu = [o.hs(domain + h) for domain in domains]
    amount, asset = [o.mul(p, 8) for p in d["pseudo"]]
    wg = [o.combine(r[:32], mu[0], o.sub(o.mul(r[32:64], 8), amount), mu[1]) for r in d["ring"]]
    wx = [o.mul(o.sub(o.mul(r[64:], 8), asset), mu[2]) for r in d["ring"]]
    ig, ix = o.combine(image, mu[0], o.mul(k1, 8), mu[1]), o.mul(k2, 8 * mu[2])
    def challenge(points):
        return o.hs(b"ZANO_HDS_CLSAG_GGX_CHALLENGE___\0" + h + b"".join(points))
    return mu, wg, wx, ig, ix, challenge


def reference_sign(o, request):
    d = decode(request)
    n, index = d["n"], d["index"]
    x, z = d["secrets"][:2]
    hp = [o.hp(r[:32]) for r in d["ring"]]
    image = o.mul(hp[index], x)
    a, b = [fixture_scalar(f"public test nonce/{i}/{request.hex()}") for i in range(2)]
    r0 = [fixture_scalar(f"public test response/0/{i}/{request.hex()}") for i in range(n)]
    r1 = [fixture_scalar(f"public test response/1/{i}/{request.hex()}") for i in range(n)]
    challenges = [0] * n
    if d["ryo"]:
        delta = [o.sub(r[32:], d["pseudo"][0]) for r in d["ring"]]
        def challenge(i, l0, rr0, l1):
            return o.hs(d["message"] + d["ring"][i][:32] + l0 + rr0 + delta[i] + l1)
        challenges[(index + 1) % n] = challenge(index, o.mul(o.G, a), o.mul(hp[index], a), o.mul(o.G, b))
        for j in range(1, n):
            i = (index + j) % n
            c = challenges[i]
            challenges[(i + 1) % n] = challenge(i, o.combine(o.G, r0[i], d["ring"][i][:32], c),
                o.combine(hp[i], r0[i], image, c), o.combine(o.G, r1[i], delta[i], c))
        r0[index], r1[index] = (a - challenges[index] * x) % L, (b - challenges[index] * z) % L
        return scalar(challenges[0]) + image + b"".join(scalar(s) for pair in zip(r0, r1) for s in pair)
    t = d["secrets"][2]
    k1, k2 = o.mul(hp[index], z * pow(8, -1, L)), o.mul(hp[index], t * pow(8, -1, L))
    mu, wg, wx, ig, ix, challenge = zano_context(o, d, image, k1, k2)
    challenges[(index + 1) % n] = challenge([o.mul(o.G, a), o.mul(hp[index], a), o.mul(o.X, b), o.mul(hp[index], b)])
    for j in range(1, n):
        i = (index + j) % n
        c = challenges[i]
        challenges[(i + 1) % n] = challenge([o.combine(o.G, r0[i], wg[i], c), o.combine(hp[i], r0[i], ig, c),
            o.combine(o.X, r1[i], wx[i], c), o.combine(hp[i], r1[i], ix, c)])
    r0[index] = (a - challenges[index] * (mu[0] * x + mu[1] * z)) % L
    r1[index] = (b - challenges[index] * mu[2] * t) % L
    return scalar(challenges[0]) + image + k1 + k2 + b"".join(map(scalar, r0 + r1))


def recover_nonce(o, request, sig):
    """Recover real nonce from PUBLIC TEST witnesses to detect nonce reuse."""
    d = decode(request)
    c = int.from_bytes(sig[:32], "little")
    image = sig[32:64]
    x, z = d["secrets"][:2]
    if d["ryo"]:
        for i in range(d["index"]):
            p = d["ring"][i][:32]
            delta = o.sub(d["ring"][i][32:], d["pseudo"][0])
            r0, r1 = [int.from_bytes(sig[64 + 64 * i + j:96 + 64 * i + j], "little") for j in (0, 32)]
            c = o.hs(d["message"] + p + o.combine(o.G, r0, p, c) + o.combine(o.hp(p), r0, image, c) + delta + o.combine(o.G, r1, delta, c))
        real = int.from_bytes(sig[64 + d["index"] * 64:96 + d["index"] * 64], "little")
        return (real + c * x) % L
    mu, wg, wx, ig, ix, challenge = zano_context(o, d, image, sig[64:96], sig[96:128])
    for i in range(d["index"]):
        hp = o.hp(d["ring"][i][:32])
        rg = int.from_bytes(sig[128 + i * 32:160 + i * 32], "little")
        rx = int.from_bytes(sig[128 + (d["n"] + i) * 32:160 + (d["n"] + i) * 32], "little")
        c = challenge([o.combine(o.G, rg, wg[i], c), o.combine(hp, rg, ig, c), o.combine(o.X, rx, wx[i], c), o.combine(hp, rx, ix, c)])
    real = int.from_bytes(sig[128 + d["index"] * 32:160 + d["index"] * 32], "little")
    return (real + c * (mu[0] * x + mu[1] * z)) % L


class Probe:
    def __init__(self, exe, directory):
        self.exe, self.directory = str(exe.resolve()), Path(directory)
        self.checks = 0

    def run(self, command, request, signature=None, expect=0):
        req, sig = self.directory / "request.bin", self.directory / "signature.bin"
        req.write_bytes(request)
        if signature is not None:
            sig.write_bytes(signature)
        elif sig.exists():
            sig.unlink()
        run = subprocess.run([self.exe, command, str(req), str(sig)], capture_output=True, timeout=120)
        assert run.returncode == expect, (command, run.returncode, expect, run.stdout, run.stderr)
        self.checks += 1
        return sig.read_bytes() if command == "privacy-sign" and expect == 0 else None


def mutated(data, offset, replacement=None):
    copy = bytearray(data)
    if replacement is None:
        copy[offset] ^= 1
    else:
        copy[offset:offset + len(replacement)] = replacement
    return bytes(copy)


def negative_tests(probe, request, signature):
    d = decode(request)
    n, index = d["n"], d["index"]
    header, width, sighead = (172, 64, 64) if d["ryo"] else (236, 96, 128)
    # Every signature component is bound; canonical scalar encodings matter.
    for off in (0, 32, sighead, len(signature) - 1):
        probe.run("privacy-verify", request, mutated(signature, off), expect=1)
    for off in (0, sighead):
        value = int.from_bytes(signature[off:off + 32], "little") + L
        probe.run("privacy-verify", request, mutated(signature, off, value.to_bytes(32, "little")), expect=1)
    if not d["ryo"]:
        for off in (64, 96):
            probe.run("privacy-verify", request, mutated(signature, off), expect=1)
    probe.run("privacy-verify", mutated(request, 12), signature, expect=1)
    for off in range(76, 76 + len(d["secrets"]) * 32, 32):
        probe.run("privacy-sign", mutated(request, off), expect=1)
        probe.run("privacy-sign", mutated(request, off, L.to_bytes(32, "little")), expect=1)
    probe.run("privacy-sign", mutated(request, 8, struct.pack("<I", n)), expect=1)
    for badpoint in (bytes(32), IDENTITY, (2**255 - 20).to_bytes(32, "little"), bytes([255]) * 32):
        probe.run("privacy-sign", mutated(request, header + index * width, badpoint), expect=1)
    if n > 1:
        probe.run("privacy-sign", mutated(request, header + width, request[header:header + 32]), expect=1)
    # A valid but wrong pseudo commitment must fail witness matching.
    pseudo_offset = 76 + len(d["secrets"]) * 32
    probe.run("privacy-sign", mutated(request, pseudo_offset, request[header:header + 32]), expect=1)
    probe.run("privacy-verify", mutated(request, pseudo_offset, request[header:header + 32]), signature, expect=1)
    for cut in (0, 11, header - 1, len(request) - 1):
        probe.run("privacy-sign", request[:cut], expect=2)


def main():
    if not __debug__:
        raise SystemExit("Run without -O/PYTHONOPTIMIZE: this regression suite uses assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--write-fixtures", action="store_true")
    parser.add_argument("--large-rings", action="store_true")
    args = parser.parse_args()
    oracle = Oracle(args.oracle) if args.oracle else None
    if args.write_fixtures and not oracle:
        parser.error("--write-fixtures requires the independently compiled upstream oracle")
    if oracle:
        specs = [(True, 2, 0, True), (True, 2, 1, False), (True, 25, 0, False),
            (True, 25, 12, False), (True, 25, 24, False), (False, 1, 0, True),
            (False, 16, 0, False), (False, 16, 7, False), (False, 16, 15, False)]
        if args.large_rings:
            specs += [(True, 241, 240, False), (False, 256, 255, False)]
        cases = [dict(name=f"{'ryo' if r else 'zano'}-n{n}-i{i}-zero{z}",
                      request=make_request(oracle, r, n, i, z).hex()) for r, n, i, z in specs]
    else:
        cases = json.loads(FIXTURES.read_text(encoding="utf-8"))["cases"]
    with tempfile.TemporaryDirectory(prefix="privacy-interop-") as temporary:
        probe = Probe(args.probe, temporary)
        for case in cases:
            request = bytes.fromhex(case["request"])
            wallet_sig = probe.run("privacy-sign", request)
            assert probe.run("privacy-sign", request) == wallet_sig, "determinism with identical hedge"
            probe.run("privacy-verify", request, wallet_sig)
            if oracle:
                assert oracle.verify(request, wallet_sig), (case["name"], "upstream rejected firmware signature")
                ref = reference_sign(oracle, request)
                assert oracle.verify(request, ref), "upstream rejected independent test signature"
                changed_request = mutated(request, 12)
                changed_sig = probe.run("privacy-sign", changed_request)
                assert oracle.verify(changed_request, changed_sig)
                assert recover_nonce(oracle, request, wallet_sig) != recover_nonce(oracle, changed_request, changed_sig), "reused nonce under repeated entropy"
                d = decode(request)
                if d["n"] > 1:
                    # Keep message, witnesses, real member and entropy fixed;
                    # changing a decoy must still change the real nonce.
                    header, width = (172, 64) if d["ryo"] else (236, 96)
                    decoy = (d["index"] + 1) % d["n"]
                    replacement = oracle.mul(oracle.G, fixture_scalar(case["name"] + "/different-decoy"))
                    changed_ring = mutated(request, header + decoy * width, replacement)
                    changed_ring_sig = probe.run("privacy-sign", changed_ring)
                    assert oracle.verify(changed_ring, changed_ring_sig)
                    assert recover_nonce(oracle, request, wallet_sig) != recover_nonce(oracle, changed_ring, changed_ring_sig), "reused nonce across rings"
                case.update(wallet_signature=wallet_sig.hex(), reference_signature=ref.hex())
            else:
                assert wallet_sig.hex() == case["wallet_signature"], "known-answer signature changed"
                ref = bytes.fromhex(case["reference_signature"])
            probe.run("privacy-verify", request, ref)
            negative_tests(probe, request, wallet_sig)
            print(case["name"] + ": pass", flush=True)
        print(f"privacy interoperability: {len(cases)} cases, {probe.checks} firmware invocations passed", flush=True)
    if args.write_fixtures:
        FIXTURES.parent.mkdir(parents=True, exist_ok=True)
        data = dict(description="Public test witnesses; NOT transactions or wallet seeds. Firmware and independent Python signatures both pass the unmodified upstream verifier bodies.",
            ryo_commit="185dd1fa33ba88c88bb22df9069ad368c0f9a27e", zano_commit="b543053953f74c38a32d29a087ec586943b4a321", cases=cases)
        FIXTURES.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
