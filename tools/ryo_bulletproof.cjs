'use strict';
// Original Ryo padded 64-bit Bulletproof, with one or two ordinary outputs.
const {ed25519} = require('@noble/curves/ed25519');
const {randomBytes} = require('@noble/hashes/utils');
const {getBytes, keccak256} = require('ethers');
const {Buffer} = require('buffer');
const Point = ed25519.Point, Fn = Point.Fn;
const H = Point.fromHex('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94');
const le = b => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
const hash = (...parts) => Buffer.from(getBytes(keccak256(Buffer.concat(parts))));
const hs = (...parts) => Fn.create(le(hash(...parts)));
const sc = n => Buffer.from(Fn.toBytes(Fn.create(n)));
const randomScalar = () => {
  let n;
  do { n = Fn.create(le(randomBytes(64))); } while (!n);
  return n;
};
function varint(n) {
  const out = [];
  n = BigInt(n);
  if (n < 0n || n >= 1n << 64n) throw new RangeError('Ryo uint64');
  while (n >= 128n) { out.push(Number(n & 127n) | 128); n >>= 7n; }
  return Buffer.from([...out, Number(n)]);
}

// CryptoNote ge_fromfe_frombytes_vartime. The square Montgomery RHS selects
// the Edwards y coordinate and x parity. All 256 Keccak bits enter the field.
function imageGenerator(destination) {
  const F = Point.Fp, A = 486662n;
  const u = F.create(le(hash(destination)));
  const v = F.create(2n * u * u), w = F.add(1n, v);
  const d = F.create(w * w - A * A * v);
  const first = F.pow(F.mul(w, d), (F.ORDER - 1n) / 2n) === 1n;
  const z = F.create(first ? -A * v : -A);
  const y = F.div(F.sub(z, w), F.add(z, w));
  const encoded = Buffer.from(F.toBytes(y));
  if (!first) encoded[31] |= 128;
  return Point.fromBytes(encoded, false).clearCofactor();
}

const generators = [];
const inv8 = Fn.inv(8n);
const msm = (points, scalars) => Point.msm(points, scalars.map(s => Fn.create(s)));
const inner = (a, b) => Fn.create(a.reduce((s, x, i) => s + x * b[i], 0n));

function proveAmounts(outputs) {
  if (outputs.length !== 1 && outputs.length !== 2) throw new Error('Ryo proof output count');
  const n = outputs.length * 64;
  while (generators.length < 2*n) generators.push(imageGenerator(hash(H.toBytes(), Buffer.from('bulletproof'), varint(generators.length))));
  let gs = Array.from({length:n}, (_, i) => generators[2*i+1]);
  let hsPoints = Array.from({length:n}, (_, i) => generators[2*i]);
  let cache = sc(hs(...outputs.map(o => o.commitment.multiply(inv8).toBytes())));
  function challenge(...parts) {
    const n = hs(cache, ...parts);
    if (!n) throw new Error('Ryo zero proof challenge');
    cache = sc(n);
    return n;
  }
  const al = gs.map((_, i) => (outputs[Math.floor(i/64)].amount >> BigInt(i%64)) & 1n);
  const ar = al.map(v => v-1n);
  const alpha = randomScalar(), rho = randomScalar(), tau1 = randomScalar(), tau2 = randomScalar();
  const sl = gs.map(randomScalar), sr = gs.map(randomScalar);
  function vectorCommit(a,b,mask) {
    return msm([...gs,...hsPoints,Point.BASE],[...a,...b,mask]).multiply(inv8).toBytes();
  }
  const A = vectorCommit(al,ar,alpha), S = vectorCommit(sl,sr,rho);
  const y = challenge(A,S), z = hs(sc(y));
  if (!z) throw new Error('Ryo zero proof challenge');
  cache = sc(z);
  const yp = al.map((_, i) => Fn.pow(y,BigInt(i)));
  const l0 = al.map(v => v-z);
  const r0 = ar.map((v,i) => Fn.create((v+z)*yp[i] + Fn.pow(z,BigInt(2+Math.floor(i/64))) * (1n << BigInt(i%64))));
  const r1 = sr.map((v,i) => Fn.mul(v,yp[i]));
  const T1 = msm([Point.BASE,H],[tau1,inner(l0,r1)+inner(sl,r0)]).multiply(inv8).toBytes();
  const T2 = msm([Point.BASE,H],[tau2,inner(sl,r1)]).multiply(inv8).toBytes();
  const x = challenge(sc(z),T1,T2);
  const taux = Fn.create(outputs.reduce((s,o,i) => s + Fn.pow(z,BigInt(i+2))*o.mask,tau1*x + tau2*x*x));
  const mu = Fn.create(alpha + x*rho);
  let a = l0.map((v,i) => Fn.create(v+x*sl[i]));
  let b = r0.map((v,i) => Fn.create(v+x*r1[i]));
  const t = inner(a,b), xip = challenge(sc(x),sc(taux),sc(mu),sc(t));
  hsPoints = hsPoints.map((h,i) => h.multiply(Fn.inv(yp[i])));
  const left = [], right = [];
  while (a.length > 1) {
    const half = a.length/2;
    const a0 = a.slice(0,half), a1 = a.slice(half), b0 = b.slice(0,half), b1 = b.slice(half);
    const gl = gs.slice(0,half), gr = gs.slice(half), hl = hsPoints.slice(0,half), hr = hsPoints.slice(half);
    const L = msm([...gr,...hl,H],[...a0,...b1,inner(a0,b1)*xip]).multiply(inv8).toBytes();
    const R = msm([...gl,...hr,H],[...a1,...b0,inner(a1,b0)*xip]).multiply(inv8).toBytes();
    left.push(L); right.push(R);
    const w = challenge(L,R), wi = Fn.inv(w);
    gs = gl.map((g,i) => msm([g,gr[i]],[wi,w]));
    hsPoints = hl.map((h,i) => msm([h,hr[i]],[w,wi]));
    a = a0.map((v,i) => Fn.create(v*w + a1[i]*wi));
    b = b0.map((v,i) => Fn.create(v*wi + b1[i]*w));
  }
  return Buffer.concat([A,S,T1,T2,sc(taux),sc(mu),varint(left.length),...left,varint(right.length),...right,sc(a[0]),sc(b[0]),sc(t)]);
}
module.exports = {proveAmounts, H, imageGenerator, varint, randomScalar, hash, hs, le, sc};
