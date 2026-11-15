"""Original Ryo Bulletproof: pinned upstream vectors and independent prover.

The prover below is ONLY a fixture generator with public deterministic masks.
Firmware provides verification, not this prover. No fixture can protect funds.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from privacy_interop import Oracle, L, IDENTITY, ROOT, scalar, fixture_scalar, mutated

FIXTURES = ROOT / "tests/fixtures/privacy/ryo-bulletproofs.json"
H = bytes.fromhex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")


def upstream_vectors(root):
    data = (root / "tests/unit_tests/bulletproofs.cpp").read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(data).hexdigest() != "1695137eddd9cff0bbfafac57993999d3af14a13278fcae9bb9f4c40fd82e78f":
        raise ValueError("Ryo upstream test source hash mismatch")
    text = data.decode()
    cases = []
    for name, body in re.findall(r"TEST_F\(bp_blobs, (\w+)\)(.*?)(?=\nTEST_F|\nstatic const)", text, re.S):
        values = re.findall(r"(?:main|commit)_blob = cryptonote::blobdata\((.*?)\);", body, re.S)
        proof, commitment = [bytes.fromhex("".join(re.findall(r"\\x([0-9a-fA-F]{2})", v))) for v in values]
        expected = "VERIFY_BULLETPROOF(true)" in body
        cases.append(dict(name=name, expected=expected, data=(bytes([1]) + commitment + proof).hex()))
    return cases, text[:text.index("#include")]


def prove(o, amounts):
    n = len(amounts)
    m = 1 << (n - 1).bit_length()
    mn = m * 64
    inv8 = pow(8, -1, L)
    label = "public Ryo Bulletproof fixture/" + str(amounts)
    rnd = lambda role: fixture_scalar(label + "/" + role)
    masks = [rnd(f"mask/{i}") for i in range(n)]
    v = [o.mul(o.combine(o.G, masks[i], H, amounts[i]), inv8) for i in range(n)]
    gs = [o.call("bp_generator", 2 * i + 1) for i in range(mn)]
    hs = [o.call("bp_generator", 2 * i) for i in range(mn)]

    def multiexp(points, scalars):
        acc = IDENTITY
        for p, s in zip(points, scalars, strict=True):
            acc = o.add(acc, o.mul(p, s))
        return acc

    def inner(a, b):
        return sum(x * y for x, y in zip(a, b, strict=True)) % L

    cache = scalar(o.hs(b"".join(v)))

    def challenge(*parts):
        nonlocal cache
        value = o.hs(cache + b"".join(parts))
        assert value
        cache = scalar(value)
        return value

    al = [((amounts[i // 64] if i // 64 < n else 0) >> (i % 64)) & 1 for i in range(mn)]
    ar = [(a - 1) % L for a in al]
    alpha, rho, tau1, tau2 = [rnd(role) for role in ("alpha", "rho", "tau1", "tau2")]
    a_point = o.mul(o.add(multiexp(gs + hs, al + ar), o.mul(o.G, alpha)), inv8)
    sl, sr = [[rnd(f"{role}/{i}") for i in range(mn)] for role in ("sl", "sr")]
    s_point = o.mul(o.add(multiexp(gs + hs, sl + sr), o.mul(o.G, rho)), inv8)
    y = challenge(a_point, s_point)
    z = o.hs(scalar(y)); cache = scalar(z)
    yp = [pow(y, i, L) for i in range(mn)]
    l0 = [(a - z) % L for a in al]
    r0 = [((ar[i] + z) * yp[i] + pow(z, 2 + i // 64, L) * 2**(i % 64)) % L for i in range(mn)]
    r1 = [yp[i] * sr[i] % L for i in range(mn)]
    t1, t2 = (inner(l0, r1) + inner(sl, r0)) % L, inner(sl, r1)
    t1_point, t2_point = o.mul(o.combine(o.G, tau1, H, t1), inv8), o.mul(o.combine(o.G, tau2, H, t2), inv8)
    x = challenge(scalar(z), t1_point, t2_point)
    taux = (tau1 * x + tau2 * x * x + sum(pow(z, i + 2, L) * masks[i] for i in range(n))) % L
    mu = (alpha + x * rho) % L
    a = [(l0[i] + x * sl[i]) % L for i in range(mn)]
    b = [(r0[i] + x * r1[i]) % L for i in range(mn)]
    t = inner(a, b)
    xip = challenge(scalar(x), scalar(taux), scalar(mu), scalar(t))
    hs = [o.mul(hs[i], pow(yp[i], -1, L)) for i in range(mn)]
    left, right = [], []
    while len(a) > 1:
        half = len(a) // 2
        cl, cr = inner(a[:half], b[half:]), inner(a[half:], b[:half])
        lp = o.mul(o.add(multiexp(gs[half:] + hs[:half], a[:half] + b[half:]), o.mul(H, cl * xip)), inv8)
        rp = o.mul(o.add(multiexp(gs[:half] + hs[half:], a[half:] + b[:half]), o.mul(H, cr * xip)), inv8)
        w = challenge(lp, rp); wi = pow(w, -1, L)
        left.append(lp); right.append(rp)
        gs = [o.combine(gs[i], wi, gs[half + i], w) for i in range(half)]
        hs = [o.combine(hs[i], w, hs[half + i], wi) for i in range(half)]
        a = [(a[i] * w + a[half + i] * wi) % L for i in range(half)]
        b = [(b[i] * wi + b[half + i] * w) % L for i in range(half)]
    proof = (a_point + s_point + t1_point + t2_point + scalar(taux) + scalar(mu)
             + bytes([len(left)]) + b"".join(left) + bytes([len(right)]) + b"".join(right)
             + scalar(a[0]) + scalar(b[0]) + scalar(t))
    return bytes([n]) + b"".join(v) + proof


def main():
    if not __debug__:
        raise SystemExit("Run without -O/PYTHONOPTIMIZE")
    p = argparse.ArgumentParser()
    p.add_argument("--probe", type=Path, required=True)
    p.add_argument("--oracle", type=Path)
    p.add_argument("--ryo-source", type=Path)
    p.add_argument("--write-fixtures", action="store_true")
    args = p.parse_args()
    if bool(args.oracle) != bool(args.ryo_source) or (args.write_fixtures and not args.oracle):
        p.error("Source regeneration requires both --oracle and --ryo-source")
    o = Oracle(args.oracle) if args.oracle else None
    if o:
        o.dll.oracle_bp_generator.argtypes = [C.c_size_t, C.c_void_p]
        o.dll.oracle_bulletproof.argtypes = [C.c_char_p, C.c_size_t]
        cases, license_text = upstream_vectors(args.ryo_source)
        shapes = [[0], [2**64 - 1]] + [[123456 + i for i in range(n)] for n in (2, 3, 4, 5, 8, 9, 16)]
        for amounts in shapes:
            wire = prove(o, amounts)
            assert o.dll.oracle_bulletproof(wire, len(wire)) == 1, "upstream rejected independent proof"
            cases.append(dict(name=f"independent-{len(amounts)}-{amounts[0]}", expected=True, data=wire.hex()))
            print(f"Generated and upstream-verified proof: {len(amounts)} outputs", flush=True)
    else:
        doc = json.loads(FIXTURES.read_text(encoding="utf-8"))
        cases, license_text = doc["cases"], doc["upstream_fixture_license"]
    checks = 0
    with tempfile.TemporaryDirectory(prefix="ryo-bulletproof-") as directory:
        path = Path(directory) / "proof.bin"
        def check(wire, expected):
            nonlocal checks
            path.write_bytes(wire)
            result = subprocess.run([str(args.probe.resolve()), "privacy-bulletproof", str(path)], capture_output=True, timeout=120)
            assert result.returncode == expected, (result.returncode, expected, result.stdout, result.stderr)
            checks += 1
        for case in cases:
            wire = bytes.fromhex(case["data"])
            check(wire, 0 if case["expected"] else 1)
            if o:
                assert bool(o.dll.oracle_bulletproof(wire, len(wire))) == case["expected"]
            print(case["name"] + ": pass", flush=True)
        valid = bytes.fromhex(cases[0]["data"])
        assert cases[0]["expected"] and valid[0] == 1
        base, rounds = 33, valid[33 + 192]
        fields = [1] + [base + i * 32 for i in range(6)]
        fields += [base + 193 + i * 32 for i in range(rounds)]
        fields += [base + 194 + (rounds + i) * 32 for i in range(rounds)]
        fields += [base + 194 + 2 * rounds * 32 + i * 32 for i in range(3)]
        for offset in fields:
            wire = mutated(valid, offset)
            check(wire, 1)
            if o:
                assert o.dll.oracle_bulletproof(wire, len(wire)) == 0
        for offset in [base + 128, base + 160] + fields[-3:]:
            check(mutated(valid, offset, L.to_bytes(32, "little")), 1)
        for cut in (0, 1, 32, base + 191, len(valid) - 1):
            check(valid[:cut], 2)
        check(mutated(valid, base + 192, b"\x05"), 2)
        check(mutated(valid, 0, b"\x11"), 2)
        check(valid + b"\0", 2)
    if args.write_fixtures:
        FIXTURES.write_text(json.dumps(dict(ryo_commit="185dd1fa33ba88c88bb22df9069ad368c0f9a27e",
            description="Original 64-bit Ryo Bulletproofs. Public fixtures, not real transactions.",
            upstream_fixture_license=license_text, cases=cases), indent=2) + "\n", encoding="utf-8")
    print(f"Ryo Bulletproof: {len(cases)} vectors, {checks} firmware invocations passed", flush=True)


if __name__ == "__main__":
    main()
