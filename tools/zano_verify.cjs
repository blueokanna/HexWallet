'use strict';
// Verification of a single ordinary v4 payment. Equations and transcripts
// follow Zano b5430539, crypto/{one_out_of_many_proofs,range_proof_bpp,
// zarcanum,clsag} and currency_core/currency_format_utils_transactions.
const {Buffer} = require('buffer');
const {getBytes} = require('ethers');
const {ed25519} = require('@noble/curves/ed25519');
const {imageGenerator, hash, hs, sc, le} = require('./ryo_bulletproof.cjs');
const {parseZanoPayment} = require('./zano_transaction.cjs');
const Point = ed25519.Point, F = Point.Fn;
const X = Point.fromHex('3a25bcdb43f5d2c9dd063dc39a9e0987bafc6fcf2df1bc76322d75884a4a3820');
const U = Point.fromHex('d0268e419f56175b91c243df3bf25ad42f43a7f018f580e31cc60b7d904ac9a1');
const nativeAsset = Point.fromHex('d6329b5b1f7c0805b5c345f4957554002a2f557845f64d7645dae0e051a6498a');

function check(ok, field) { if (!ok) throw new Error(`Invalid Zano ${field}`); }
function scalar(bytes) {
  const value = le(bytes);
  check(value < F.ORDER, 'scalar');
  return value;
}
function point(bytes, allowZero = false) {
  const p = Point.fromBytes(getBytes(bytes), false);
  check(p.isTorsionFree() && (allowZero || !p.is0()), 'point');
  return p;
}
const full = bytes => point(bytes).clearCofactor();
const mul = (p, s) => p.multiplyUnsafe(F.create(s));
const enc = p => p.toBytes();
const sum = points => points.reduce((a, b) => a.add(b), Point.ZERO);
const domain = text => Buffer.from(text.padEnd(31, '_') + '\0', 'ascii');

function verifyInput(message, input, signature, ring) {
  check(Array.isArray(ring) && ring.length === input.offsets.length, 'ring size');
  const members = ring.map((member, j) => {
    check(BigInt(member.index) === input.offsets[j], 'ring index');
    return [member.destination, member.commitment, member.asset].map(value => point(value));
  });
  check(new Set(members.map(m => m[0].toHex())).size === members.length, 'duplicate ring member');
  const binding = hash(sc(le(message)), ...members.flatMap(m => m.map(enc)), signature.amount, signature.asset,
    input.image, signature.k1, signature.k2);
  const mu = ['ZERO', 'ONE', 'TWO'].map(layer => hs(domain('ZANO_HDS_CLSAG_GGX_LAYER_' + layer), binding));
  const imageG = mul(point(input.image), mu[0]).add(mul(point(signature.k1, true), 8n * mu[1]));
  const imageX = mul(point(signature.k2, true), 8n * mu[2]);
  const pseudoAmount = point(signature.amount), pseudoAsset = point(signature.asset);
  const initial = scalar(signature.c);
  let c = initial;
  for (const [j, [dest, commitment, asset]] of members.entries()) {
    const wg = mul(dest, mu[0]).add(mul(commitment.subtract(pseudoAmount), 8n * mu[1]));
    const wx = mul(asset.subtract(pseudoAsset), 8n * mu[2]);
    const hp = imageGenerator(enc(dest));
    const rg = scalar(signature.rg[j]), rx = scalar(signature.rx[j]);
    c = hs(domain('ZANO_HDS_CLSAG_GGX_CHALLENGE'), binding,
      enc(mul(Point.BASE, rg).add(mul(wg, c))), enc(mul(hp, rg).add(mul(imageG, c))),
      enc(mul(X, rx).add(mul(wx, c))), enc(mul(hp, rx).add(mul(imageX, c))));
  }
  check(c === initial, 'CLSAG_GGX');
}

function generators(label) {
  const seed = sc(hs(Buffer.from(label, 'ascii'))), cache = [];
  return index => {
    if (!cache[index]) cache[index] = imageGenerator(Buffer.concat([seed, sc(BigInt(index))]));
    return cache[index];
  };
}
const bgeGenerator = generators('Zano BGE generator');
const bpGenerator = generators('Zano BP+ generator');

function verifyAsset(message, output, sigs, proof) {
  const blinded = point(output.asset);
  const ring = sigs.map(sig => point(sig.asset).subtract(blinded));
  const x = hs(message, ...ring.map(enc), proof.a, proof.b, ...proof.pk);
  const rows = [];
  let first = full(proof.a).add(mul(full(proof.b), x)).subtract(mul(X, scalar(proof.y)));
  for (let j = 0; j < proof.pk.length; ++j) {
    const row = proof.f.slice(3*j, 3*j+3).map(scalar);
    row.unshift(F.create(row.reduce((s, f) => s - f, x)));
    rows.push(row);
    for (const [digit, f] of row.entries()) {
      const k = 2*(4*j + digit);
      first = first.subtract(mul(bgeGenerator(k), f)).subtract(mul(bgeGenerator(k+1), f*(x-f)));
    }
  }
  check(first.is0(), 'asset proof commitment');
  let second = Point.ZERO;
  for (let i = 0; i < 4 ** rows.length; ++i) {
    let digits = i, weight = 1n;
    for (const row of rows) { weight = F.mul(weight, row[digits % 4]); digits = Math.floor(digits / 4); }
    second = second.add(mul(ring[Math.min(i, ring.length-1)], 8n * weight));
  }
  let power = 1n;
  for (const pk of proof.pk) { second = second.subtract(mul(full(pk), power)); power = F.mul(power, x); }
  check(second.equals(mul(X, scalar(proof.z))), 'asset membership proof');
}

function verifyAggregation(message, outputs, proof) {
  const amounts = outputs.map(o => full(o.commitment)), aggregated = proof.commitments.map(full);
  const prefix = [message, ...amounts.map(enc), ...aggregated.map(enc)];
  const w = hs(...prefix), c = scalar(proof.c);
  const nonces = outputs.map((o, i) => {
    const tag = full(o.asset).add(mul(U, w));
    const amount = amounts[i].add(mul(aggregated[i], w));
    return enc(mul(tag, scalar(proof.y0[i])).add(mul(Point.BASE, scalar(proof.y1[i]))).add(mul(amount, c)));
  });
  check(hs(...prefix, ...nonces) === c, 'range aggregation proof');
}

// Single-proof specialization of bpp_verify. Each equation is checked on its
// own, so the upstream batch multiplier is one. Values are 64-bit amounts.
function verifyRange(commitments, proof) {
  const rounds = proof.left.length, n = 2 ** rounds;
  const initial = hs(sc(hs(Buffer.from('Zano BP+ initial transcript'))), ...commitments);
  const y = hs(sc(initial), proof.a0), z = hs(sc(y)), z2 = F.sqr(z);
  let challenge = z;
  const folds = proof.left.map((l, j) => {
    challenge = hs(sc(challenge), l, proof.right[j]);
    return challenge;
  });
  const e = hs(sc(challenge), proof.a, proof.b), e2 = F.sqr(e);
  const r = scalar(proof.r), s = scalar(proof.s);
  let weights = [1n];
  for (const fold of folds) {
    const inv = F.inv(fold);
    weights = weights.flatMap(w => [F.mul(w, inv), F.mul(w, fold)]);
  }
  const yInv = F.inv(y), yNext = F.pow(y, BigInt(n + 1));
  let yInversePower = 1n, yForward = 1n, sumY = 0n, sumD = 0n;
  let zPower = 1n, d = 0n;
  const points = [], factors = [];
  for (let i = 0; i < n; ++i) {
    if (i % 64 === 0) { zPower = F.mul(zPower, z2); d = zPower; }
    else d = F.add(d, d);
    sumD = F.add(sumD, d);
    points.push(bpGenerator(2*i), bpGenerator(2*i+1));
    factors.push(F.create(r*e*yInversePower*weights[i] + e2*z),
      F.create(s*e*weights[n-i-1] - e2*z - e2*yNext*yInv*yInversePower*d));
    yForward = F.mul(yForward, y);
    sumY = F.add(sumY, yForward);
    yInversePower = F.mul(yInversePower, yInv);
  }
  function term(p, factor) { points.push(p); factors.push(F.create(factor)); }
  term(U, r*y*s + e2*yNext*sumD*z - e2*(z-z2)*sumY);
  term(Point.BASE, scalar(proof.delta));
  term(full(proof.a0), -e2);
  zPower = 1n;
  for (const c of commitments) { zPower = F.mul(zPower, z2); term(full(c), -e2*yNext*zPower); }
  folds.forEach((f, i) => {
    term(full(proof.left[i]), -e2*F.sqr(f));
    term(full(proof.right[i]), -e2*F.sqr(F.inv(f)));
  });
  term(full(proof.a), -e); term(full(proof.b), -1n);
  check(Point.msm(points, factors).is0(), 'Bulletproof+');
}

function verifyZanoPayment(wire, rings) {
  const tx = parseZanoPayment(wire), message = Buffer.from(tx.id, 'hex');
  check(Array.isArray(rings) && rings.length === tx.inputs.length, 'ring count');
  for (const [i, input] of tx.inputs.entries()) verifyInput(message, input, tx.signatures[i], rings[i]);
  for (const [i, output] of tx.outputs.entries()) {
    point(output.stealth); point(output.concealing);
    verifyAsset(message, output, tx.signatures, tx.assets[i]);
  }
  verifyAggregation(message, tx.outputs, tx.aggregation);
  verifyRange(tx.aggregation.commitments, tx.range);
  const zero = sum(tx.signatures.map(s => full(s.amount))).subtract(sum(tx.outputs.map(o => full(o.commitment))))
    .subtract(mul(nativeAsset, tx.fee));
  const c = scalar(tx.balance.c), key = point(tx.publicKey);
  check(c === hs(message, enc(zero), enc(key), enc(mul(X, scalar(tx.balance.y0)).add(mul(zero, c))),
    enc(mul(Point.BASE, scalar(tx.balance.y1)).add(mul(key, c)))), 'balance proof');
  return tx.id;
}

module.exports = {verifyZanoPayment, X, U, nativeAsset, bpGenerator, bgeGenerator, domain, point, check};
