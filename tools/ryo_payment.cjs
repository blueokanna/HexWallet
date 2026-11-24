'use strict';

const {Buffer} = require('buffer');
const {getBytes} = require('ethers');
const {ed25519} = require('@noble/curves/ed25519');
const {Keccak} = require('@noble/hashes/sha3');
const {randomBytes} = require('@noble/hashes/utils');
const {proveAmounts, H, imageGenerator, varint, randomScalar, hash, hs, le, sc} = require('./ryo_bulletproof.cjs');

const Point = ed25519.Point;
const order = Point.Fn.ORDER;
const mainnetGenesis = '6eb04b6b8c68049a76206fe2805ede5f7465c03b7112850d3262a067b9914dac';
const maxPayload = 16384 - 16;

function requireField(ok, message) {
  if (!ok) throw new Error(`Ryo ${message}`);
}
function bytes(value, length) {
  const b = Buffer.from(getBytes(value));
  requireField(b.length === length, 'field length mismatch');
  return b;
}
function scalar(b) {
  const n = le(b);
  requireField(n < order, 'noncanonical scalar');
  return n;
}
function point(b) {
  const p = Point.fromBytes(b, false);
  requireField(!p.is0() && p.isTorsionFree(), 'invalid ring point');
  return p;
}

function parseWire(wire) {
  requireField(wire.length <= maxPayload, 'transaction exceeds phone frame');
  let pos = 0;
  function take(n) {
    requireField(n <= wire.length - pos, 'truncated transaction');
    const data = wire.subarray(pos, pos + n);
    pos += n;
    return data;
  }
  function varint() {
    let n = 0n;
    for (let shift = 0n; shift <= 63n; shift += 7n) {
      const b = take(1)[0];
      requireField(shift !== 63n || b <= 1, 'varint overflow');
      n |= BigInt(b & 127) << shift;
      if (b < 128) {
        requireField(shift === 0n || b !== 0, 'noncanonical varint');
        return n;
      }
    }
    throw new Error('Ryo varint overflow');
  }
  function expect(value) { requireField(varint() === BigInt(value), 'unexpected transaction field'); }
  expect(3); expect(0);
  const count = Number(varint());
  requireField(count >= 1 && count <= 8, 'input count');
  const inputs = [];
  for (let i = 0; i < count; ++i) {
    expect(2); expect(0);
    const n = Number(varint());
    requireField(n >= 25 && n <= 241 && (!i || n === inputs[0].offsets.length), 'ring size');
    const offsets = [];
    let absolute = 0n;
    for (let j = 0; j < n; ++j) {
      const delta = varint();
      absolute += delta;
      requireField((!j || delta > 0n) && absolute < 1n << 64n, 'ring offset');
      offsets.push(absolute);
    }
    const image = take(32);
    requireField(!i || Buffer.compare(inputs[i - 1].image, image) > 0, 'input order');
    inputs.push({offsets, image});
  }
  const outputs = Number(varint());
  requireField(outputs === 1 || outputs === 2, 'output count');
  const destinations = [];
  for (let i = 0; i < outputs; ++i) { expect(0); expect(2); destinations.push(take(32)); }
  expect(74);
  const extra = take(74);
  requireField(extra[0] === 1 && extra[33] === 5, 'payment extra');
  const prefix = hash(Buffer.from('ryo-currency'), wire.subarray(0, pos));
  const baseStart = pos;
  expect(3); varint();
  const encrypted = take(outputs * 64), commitments = take(outputs * 32);
  const base = hash(wire.subarray(baseStart, pos)), prunableStart = pos;
  requireField(take(4).readUInt32LE() === 1, 'proof count');
  const rounds = outputs === 1 ? 6 : 7;
  const head = take(192);
  expect(rounds);
  const left = take(rounds * 32);
  expect(rounds);
  const right = take(rounds * 32), tail = take(96);
  const message = hash(prefix, base, hash(head, left, right, tail));
  const signaturesStart = pos;
  for (const input of inputs) {
    input.responses = take(input.offsets.length * 64);
    input.challenge = take(32);
  }
  const signaturesEnd = pos;
  for (const input of inputs) input.pseudo = take(32);
  requireField(pos === wire.length, 'trailing bytes');
  return {inputs, message, signaturesStart, signaturesEnd, destinations, encrypted, commitments, extra,
    id: hash(prefix, base, hash(wire.subarray(prunableStart))).toString('hex')};
}

function verifyInput(message, input, members) {
  const image = point(input.image), pseudo = point(input.pseudo);
  const initial = scalar(input.challenge);
  let c = initial;
  for (let j = 0; j < members.length; ++j) {
    const {destination, commitment} = members[j];
    const pub = point(destination), delta = point(commitment).subtract(pseudo);
    const start = j * 64;
    const s0 = scalar(input.responses.subarray(start, start + 32));
    const s1 = scalar(input.responses.subarray(start + 32, start + 64));
    const l0 = Point.BASE.multiplyUnsafe(s0).add(pub.multiplyUnsafe(c));
    const r0 = imageGenerator(destination).multiplyUnsafe(s0).add(image.multiplyUnsafe(c));
    const l1 = Point.BASE.multiplyUnsafe(s1).add(delta.multiplyUnsafe(c));
    c = le(hash(message, destination, l0.toBytes(), r0.toBytes(), delta.toBytes(), l1.toBytes())) % order;
  }
  requireField(c === initial, 'MLSAG verification failed');
}

function encodeRyoPayment({unsigned, txSecret, recipient, sources}) {
  const wire = Buffer.from(getBytes(unsigned));
  const tx = parseWire(wire);
  requireField(tx.inputs.length === sources.length, 'funding input count');
  requireField(wire.subarray(tx.signaturesStart, tx.signaturesEnd).every(b => b === 0), 'expected unsigned transaction');
  const header = Buffer.from([1, wire.length & 255, wire.length >> 8]);
  const chunks = [header, wire, bytes(txSecret, 32), bytes(recipient.spend, 32), bytes(recipient.view, 32)];
  const rings = tx.inputs.map((input, i) => {
    const src = sources[i];
    requireField(input.image.equals(src.image), 'payer key image mismatch');
    requireField(src.ring.length === input.offsets.length && Number.isInteger(src.realIndex) &&
      src.realIndex >= 0 && src.realIndex < src.ring.length, 'funding ring size or index');
    const indices = Buffer.alloc(10);
    indices.writeUInt16LE(src.realIndex);
    indices.writeBigUInt64LE(uint64(src.outputIndex), 2);
    chunks.push(indices, bytes(src.fundingPublic, 32), bytes(src.ecdh, 64), bytes(src.pseudoMask, 32));
    return src.ring.map((member, j) => {
      const offset = Buffer.alloc(8);
      requireField(input.offsets[j] === uint64(member.index), 'funding ring offset mismatch');
      offset.writeBigUInt64LE(input.offsets[j]);
      const destination = bytes(member.destination, 32), commitment = bytes(member.commitment, 32);
      chunks.push(offset, destination, commitment);
      return {destination, commitment};
    });
  });
  const payload = Buffer.concat(chunks);
  requireField(payload.length <= maxPayload, 'review exceeds phone frame');
  function verify(signed) {
    const result = Buffer.from(getBytes(signed));
    requireField(result.length === wire.length && result.subarray(0, tx.signaturesStart).equals(wire.subarray(0, tx.signaturesStart)) &&
      result.subarray(tx.signaturesEnd).equals(wire.subarray(tx.signaturesEnd)), 'reviewed transaction mismatch');
    const parsed = parseWire(result);
    parsed.inputs.forEach((input, i) => verifyInput(parsed.message, input, rings[i]));
    return parsed.id;
  }
  async function broadcast(signed, post) {
    const result = Buffer.from(getBytes(signed));
    const id = verify(result);
    const genesis = await post('/json_rpc', {jsonrpc: '2.0', id: 1, method: 'getblockheaderbyheight', params: {height: 0}});
    requireField(!genesis.error && genesis.result?.status === 'OK' && genesis.result.block_header?.hash === mainnetGenesis,
      'RPC genesis mismatch');
    const response = await post('/sendrawtransaction', {tx_as_hex: result.toString('hex'), do_not_relay: false});
    requireField(response.status === 'OK' && !response.not_relayed, `node rejected ${id}: ${response.reason || response.status}`);
    return id;
  }
  return {payload, verify, broadcast};
}
function uint64(value) {
  requireField(typeof value === 'bigint' || (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) ||
    (typeof value === 'number' && Number.isSafeInteger(value)), 'expected exact integer');
  const n = BigInt(value);
  requireField(n >= 0n && n < 1n << 64n, 'uint64 range');
  return n;
}

function standardAddress(text) {
  requireField(typeof text === 'string' && text.length === 99, 'expected mainnet long standard address');
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const raw = Buffer.alloc(72);
  for (let block = 0; block < 9; ++block) {
    let n = 0n;
    for (const char of text.slice(11*block, 11*block+11)) {
      const digit = alphabet.indexOf(char);
      requireField(digit >= 0, 'invalid Base58 address');
      n = 58n*n + BigInt(digit);
    }
    raw.writeBigUInt64BE(uint64(n),block*8);
  }
  requireField(raw.subarray(0,4).equals(varint(0x2ce192)) && raw.subarray(68).equals(hash(raw.subarray(0,68)).subarray(0,4)),
    'address prefix or checksum');
  const spend = raw.subarray(4,36), view = raw.subarray(36,68);
  point(spend); point(view);
  return {spend,view};
}

function watchWallet(address, viewSecret) {
  const keys = standardAddress(address);
  const view = scalar(bytes(viewSecret, 32));
  requireField(view !== 0n && Buffer.from(Point.BASE.multiply(view).toBytes()).equals(keys.view), 'view key does not match address');
  return {spend: point(keys.spend), view};
}

function scanOutput(wallet, fundingPublic, outputIndex, destination, commitment, ecdh, coinbaseAmount) {
  const derivation = point(fundingPublic).multiply(wallet.view).clearCofactor().toBytes();
  const k = hs(derivation, varint(outputIndex));
  const output = wallet.spend.add(Point.BASE.multiplyUnsafe(k));
  if (!Buffer.from(output.toBytes()).equals(destination)) return null;
  const first = hs(sc(k));
  if (coinbaseAmount !== undefined) {
    // ryod stores miner outputs as zeroCommit(amount) = G + amount*H.
    // Represent that public opening in the device's legacy ECDH source record.
    requireField(ecdh == null, 'ambiguous funding amount');
    ecdh = Buffer.concat([sc(1n + first), sc(uint64(coinbaseAmount) + hs(sc(first)))]);
  } else {
    ecdh = bytes(ecdh, 64);
  }
  const mask = Point.Fn.sub(scalar(ecdh.subarray(0, 32)), first);
  const amount = uint64(Point.Fn.sub(scalar(ecdh.subarray(32)), hs(sc(first))));
  requireField(Point.msm([Point.BASE, H], [mask, amount]).equals(point(commitment)), 'funding amount commitment mismatch');
  return {amount, derivation, ecdh};
}

// wallet2::export_key_images signs the raw key image as a one-member ring.
// Check its proof against the one-time public key independently found by scan.
function checkedSource(wallet, src) {
  requireField(Array.isArray(src.ring) && Number.isInteger(src.realIndex) && src.realIndex >= 0 &&
    src.realIndex < src.ring.length, 'funding ring index');
  const real = src.ring[src.realIndex];
  const dest = bytes(real.destination, 32);
  const owned = scanOutput(wallet, bytes(src.fundingPublic, 32), uint64(src.outputIndex), dest,
    bytes(real.commitment, 32), src.ecdh, src.coinbaseAmount);
  requireField(owned && owned.amount > 0n, 'funding output does not belong to payer');
  const image = bytes(src.keyImage, 32), signature = bytes(src.keyImageSignature, 64);
  const c = scalar(signature.subarray(0, 32)), r = scalar(signature.subarray(32));
  const a = Point.BASE.multiplyUnsafe(r).add(point(dest).multiplyUnsafe(c));
  const b = imageGenerator(dest).multiplyUnsafe(r).add(point(image).multiplyUnsafe(c));
  requireField(hs(image, a.toBytes(), b.toBytes()) === c, 'invalid signed key image');
  return {...src, amount: owned.amount, ecdh: owned.ecdh, image};
}

function prepareRyoPayment({unsigned, txSecret, recipient, sources, payer, viewSecret}) {
  const wallet = watchWallet(payer, viewSecret);
  requireField(Array.isArray(sources) && sources.length >= 1 && sources.length <= 8, 'funding input count');
  return encodeRyoPayment({unsigned, txSecret, recipient, sources: sources.map(src => checkedSource(wallet, src))});
}

function scanRyoPayment({wire, receiver, viewSecret}) {
  const wallet = watchWallet(receiver, viewSecret), tx = parseWire(Buffer.from(getBytes(wire)));
  const received = [];
  for (const [i, destination] of tx.destinations.entries()) {
    const owned = scanOutput(wallet, tx.extra.subarray(1, 33), i, destination,
      tx.commitments.subarray(32*i, 32*i+32), tx.encrypted.subarray(64*i, 64*i+64));
    if (!owned) continue;
    const pad = paymentIdPad(owned.derivation);
    const plain = tx.extra.subarray(34).map((b, j) => b ^ pad[j]);
    received.push({outputIndex: i, amount: owned.amount,
      paymentId: plain.subarray(0,8).every(b => b === 0) ? plain.subarray(8).toString('hex') : null});
  }
  return received;
}

function paymentIdPad(derivation) {
  return new Keccak(136, 1, 40).update(derivation).update(Buffer.from([0x55])).digest();
}

function buildRyoPayment({payer, viewSecret, recipient, amount, paymentId, inputs, fee}) {
  const wallet = standardAddress(payer), destination = standardAddress(recipient);
  requireField(payer !== recipient, 'recipient equals change address');
  const pay = uint64(amount), id = paymentId == null ? null : bytes(paymentId,32);
  requireField(pay > 0n && Array.isArray(inputs) && inputs.length >= 1 && inputs.length <= 8, 'amount or input count');
  const n = inputs[0].ring.length;
  requireField(n >= 25 && n <= 241 && n*inputs.length <= Math.floor(maxPayload/136), 'ring exceeds phone frame');
  const watch = watchWallet(payer, viewSecret);
  const sorted = inputs.map(src => {
    requireField(src.ring.length === n, 'funding ring size');
    return checkedSource(watch, src);
  }).sort((a,b) => Buffer.compare(b.image,a.image));
  const total = uint64(sorted.reduce((s,src) => s+src.amount,0n));
  const vin = [varint(3),varint(0),varint(sorted.length)];
  sorted.forEach((src,i) => {
    requireField(!i || !src.image.equals(sorted[i-1].image), 'duplicate input');
    vin.push(Buffer.from([2,0]),varint(n));
    let previous = 0n;
    src.ring.forEach((member,j) => {
      const index = uint64(member.index);
      requireField(!j || index > previous, 'ring offsets must increase');
      vin.push(varint(index-previous)); previous = index;
    });
    vin.push(src.image);
  });
  const prefixInputs = Buffer.concat(vin);
  // Two sizes are possible because an exact spend removes the change output
  // and one inner-product round. Include fee varint width in the fixed point.
  const wireSize = (count, cost) => prefixInputs.length + 1 + 34*count + 75 + 1 + varint(cost).length + 96*count +
    4 + 290 + 64*(count === 1 ? 6 : 7) + sorted.length*(64*n+64);
  const feeFloor = (count,cost) => BigInt(n)*500000n + BigInt(wireSize(count,cost))*500000n/1024n;
  const available = total-pay;
  requireField(available >= 0n, 'insufficient funds');
  let cost = fee == null ? 0n : uint64(fee);
  if (fee == null) {
    while (cost !== feeFloor(2,cost)) cost = feeFloor(2,cost);
    if (available <= cost) cost = available;
  }
  const change = available-cost, outputCount = change > 0n ? 2 : 1;
  requireField(change >= 0n && cost <= 100000000n && cost >= feeFloor(outputCount,cost), 'fee outside payment policy or insufficient funds');
  const size = wireSize(outputCount,cost);
  requireField(99 + size + sorted.length*(138+72*n) <= maxPayload, 'review exceeds phone frame');
  const secret = randomScalar();
  const outputs = [{address:destination,amount:pay}];
  if (change) {
    outputs.push({address:wallet,amount:change});
    if (randomBytes(1)[0] & 1) outputs.reverse();
  }
  function derivation(address) { return point(address.view).multiply(secret).clearCofactor().toBytes(); }
  const outputKeys = [], ecdh = [];
  for (const [i,o] of outputs.entries()) {
    const k = hs(derivation(o.address),varint(i)), h1 = hs(sc(k)), h2 = hs(sc(h1));
    o.mask = randomScalar();
    o.commitment = Point.BASE.multiply(o.mask).add(H.multiply(o.amount));
    outputKeys.push(Buffer.from([0,2]), point(o.address.spend).add(Point.BASE.multiply(k)).toBytes());
    ecdh.push(sc(o.mask+h1),sc(o.amount+h2));
  }
  const pad = paymentIdPad(derivation(id || !change ? destination : wallet));
  const uid = Buffer.alloc(40);
  if (id) id.copy(uid,8); else uid.fill(0xff,0,8);
  for (let i = 0; i < uid.length; ++i) uid[i] ^= pad[i];
  const extra = Buffer.concat([Buffer.from([1]), Point.BASE.multiply(secret).toBytes(), Buffer.from([5]), uid]);
  const pseudos = [];
  let maskSum = outputs.reduce((s,o) => s + o.mask,0n);
  for (const [i,src] of sorted.entries()) {
    const mask = i === sorted.length-1 ? Point.Fn.create(maskSum) : randomScalar();
    src.pseudoMask = sc(mask);
    maskSum -= mask;
    pseudos.push(Point.msm([Point.BASE,H],[mask,src.amount]).toBytes());
  }
  const proof = proveAmounts(outputs);
  const unsigned = Buffer.concat([prefixInputs,varint(outputCount),...outputKeys,varint(extra.length),extra,Buffer.from([3]),
    varint(cost),...ecdh,...outputs.map(o => o.commitment.toBytes()),Buffer.from([1,0,0,0]),proof,
    Buffer.alloc(sorted.length*(64*n+32)),...pseudos]);
  requireField(unsigned.length === size, 'constructed size mismatch');
  return encodeRyoPayment({unsigned,txSecret:sc(secret),recipient:destination,sources:sorted});
}
module.exports = {prepareRyoPayment, buildRyoPayment, scanRyoPayment};
