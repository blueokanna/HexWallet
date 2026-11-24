'use strict';
// Zano transaction v4, ordinary confidential inputs and outputs, full-prefix
// signing and no attachments. A node transaction ID hashes only the prefix.
const {Buffer} = require('buffer');
const {getBytes, keccak256} = require('ethers');

const maxSize = 16384;
function check(ok, field) {
  if (!ok) throw new Error(`Invalid Zano ${field}`);
}

function parseZanoPayment(data) {
  const wire = getBytes(data);
  check(wire.length <= maxSize, 'transaction size');
  const raw = Buffer.from(wire);
  let offset = 0;
  function take(n) {
    check(n <= raw.length - offset, 'transaction length');
    offset += n;
    return raw.subarray(offset - n, offset);
  }
  const byte = () => take(1)[0];
  const tag = expected => check(byte() === expected, `tag (expected ${expected})`);
  const word = () => take(32);
  const uint64 = () => take(8).readBigUInt64LE();
  // All accepted vectors have at most 256 elements. Reject nonminimal LEB128.
  function count(min, max) {
    const first = byte();
    let n = first;
    if (first & 128) {
      const second = byte();
      check(second === 1 || second === 2, 'vector encoding');
      n = (first & 127) + 128 * second;
    }
    check(n >= min && n <= max, 'vector length');
    return n;
  }
  const vector = (min, max, read) => Array.from({length: count(min, max)}, (_, i) => read(i));
  const words = n => vector(n, n, word);
  tag(4);
  const inputs = vector(1, 8, () => {
    tag(37);
    let absolute = 0n;
    const offsets = vector(1, 256, i => {
      tag(26);
      const delta = uint64();
      absolute += delta;
      check((!i || delta !== 0n) && absolute < 1n << 64n, 'ring offset');
      return absolute;
    });
    const image = word();
    tag(0); // empty etc_details
    return {offsets, image};
  });
  check(new Set(inputs.map(i => i.image.toString('hex'))).size === inputs.length, 'duplicate key image');
  let publicKey, fee, hasFlags = false;
  const extra = vector(2, 19, () => {
    const type = byte();
    switch (type) {
      case 22:
        check(!publicKey, 'duplicate transaction key');
        publicKey = word();
        return {type};
      case 23:
        check(!hasFlags && take(2).readUInt16LE() === 0, 'transaction flags');
        hasFlags = true;
        return {type};
      case 11:
        tag(2);
        return {type, hint: take(2)};
      case 39:
        check(fee === undefined, 'duplicate fee');
        fee = uint64();
        return {type};
      default: throw new Error(`Unsupported Zano extra ${type}`);
    }
  });
  check(publicKey && fee !== undefined, 'transaction key or fee');
  const outputs = vector(1, 16, () => {
    tag(63); tag(0);
    const out = {stealth: word(), concealing: word(), commitment: word(), asset: word(),
      encryptedAmount: uint64(), encryptedPaymentId: uint64()};
    tag(0); // ordinary mix attribute
    return out;
  });
  const hardfork = byte();
  check(hardfork === 6 || hardfork === 7, 'hardfork');
  const id = keccak256(raw.subarray(0, offset)).slice(2);
  tag(0); // empty attachments
  const signatures = vector(inputs.length, inputs.length, i => {
    tag(43);
    const n = inputs[i].offsets.length;
    return {amount: word(), asset: word(), c: word(), rg: words(n), rx: words(n), k1: word(), k2: word()};
  });
  tag(3); tag(46);
  const m = Math.max(1, Math.ceil(Math.log(inputs.length) / Math.log(4)));
  const assets = vector(outputs.length, outputs.length, () => ({a: word(), b: word(), pk: words(m),
    f: words(3 * m), y: word(), z: word()}));
  tag(47);
  const rounds = 6 + Math.ceil(Math.log2(outputs.length));
  const range = {left: words(rounds), right: words(rounds), a0: word(), a: word(), b: word(),
    r: word(), s: word(), delta: word()};
  const aggregation = {commitments: words(outputs.length), y0: words(outputs.length), y1: words(outputs.length), c: word()};
  tag(48);
  const balance = {c: word(), y0: word(), y1: word()};
  check(offset === raw.length, 'trailing data');
  return {id, hardfork, inputs, extra, publicKey, fee, outputs, signatures, assets, range, aggregation, balance};
}

function encodePayment(tx, prefixOnly) {
  const parts = [];
  let size = 0;
  function append(b) {
    size += b.length;
    check(size <= maxSize, 'transaction size');
    parts.push(b);
  }
  const tags = (...values) => append(Buffer.from(values));
  function fixed(value, n) {
    const b = getBytes(value);
    check(b.length === n, 'field width');
    append(b);
  }
  const word = value => fixed(value, 32);
  function uint64(n) {
    check(typeof n === 'bigint' && n >= 0n && n < 1n << 64n, 'uint64');
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(n);
    append(b);
  }
  function vector(values, write) {
    check(Array.isArray(values) && values.length <= 256, 'vector');
    const n = values.length;
    if (n < 128) tags(n);
    else tags((n & 127) | 128, n >> 7);
    values.forEach(write);
  }
  const words = values => vector(values, word);
  tags(4);
  vector(tx.inputs, input => {
    tags(37);
    let previous = 0n;
    vector(input.offsets, index => { tags(26); uint64(index - previous); previous = index; });
    word(input.image); tags(0);
  });
  vector(tx.extra, field => {
    switch (field.type) {
      case 22: tags(22); word(tx.publicKey); break;
      case 23: tags(23, 0, 0); break;
      case 11: tags(11, 2); fixed(field.hint, 2); break;
      case 39: tags(39); uint64(tx.fee); break;
      default: throw new Error('Unsupported Zano extra');
    }
  });
  vector(tx.outputs, out => {
    tags(63, 0);
    [out.stealth, out.concealing, out.commitment, out.asset].forEach(word);
    uint64(out.encryptedAmount); uint64(out.encryptedPaymentId); tags(0);
  });
  check(tx.hardfork === 6 || tx.hardfork === 7, 'hardfork');
  tags(tx.hardfork);
  if (prefixOnly) return Buffer.concat(parts);
  tags(0);
  vector(tx.signatures, sig => {
    tags(43); [sig.amount, sig.asset, sig.c].forEach(word);
    words(sig.rg); words(sig.rx); word(sig.k1); word(sig.k2);
  });
  tags(3, 46);
  vector(tx.assets, proof => {
    word(proof.a); word(proof.b); words(proof.pk); words(proof.f); word(proof.y); word(proof.z);
  });
  tags(47);
  const {range, aggregation, balance} = tx;
  words(range.left); words(range.right);
  [range.a0, range.a, range.b, range.r, range.s, range.delta].forEach(word);
  words(aggregation.commitments); words(aggregation.y0); words(aggregation.y1); word(aggregation.c);
  tags(48); [balance.c, balance.y0, balance.y1].forEach(word);
  const wire = Buffer.concat(parts);
  parseZanoPayment(wire); // Enforce the same cross-field counts on both paths.
  return wire;
}

const serializeZanoPrefix = tx => encodePayment(tx, true);
const serializeZanoPayment = tx => encodePayment(tx, false);
module.exports = {parseZanoPayment, serializeZanoPayment, serializeZanoPrefix};
