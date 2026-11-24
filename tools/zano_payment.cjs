'use strict';
const {Buffer} = require('buffer');
const {getBytes} = require('ethers');
const {ed25519} = require('@noble/curves/ed25519');
const {blake2b} = require('@noble/hashes/blake2b');
const {base58xmr} = require('@scure/base');
const {serializeZanoPayment, serializeZanoPrefix} = require('./zano_transaction.cjs');
const {verifyZanoPayment, check, X, nativeAsset, domain, point} = require('./zano_verify.cjs');
const {proveZanoPayment, encodeCommitment} = require('./zano_proofs.cjs');
const {le, sc, hs, hash, varint, imageGenerator, randomScalar} = require('./ryo_bulletproof.cjs');

const G = ed25519.Point.BASE, F = ed25519.Point.Fn;
const fee = 10000000000n; // TX_DEFAULT_FEE and TX_MINIMUM_FEE
function u64(value) {
  check(typeof value === 'bigint' || Number.isSafeInteger(value) ||
    (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)), 'integer');
  const n = BigInt(value);
  check(n >= 0n && n < 1n << 64n, 'uint64');
  return n;
}
function word64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; }
function key(bytes) { const b = Buffer.from(getBytes(bytes)); check(b.length === 32, 'key size'); return b; }
function standardAddress(address) {
  check(typeof address === 'string' && address.length === 97, 'standard address length');
  const raw = Buffer.from(base58xmr.decode(address));
  check(raw.length === 70 && raw[0] === 0xc5 && raw[1] === 1 &&
    raw.subarray(66).equals(hash(raw.subarray(0,66)).subarray(0,4)), 'standard address checksum or network');
  return {spend:point(raw.subarray(2,34)), view:point(raw.subarray(34,66))};
}
function derivationData(derivation, index) {
  const offset = hs(derivation, varint(index));
  const mask = name => hs(domain(name), sc(offset));
  const pad = sc(mask('ZANO_HDS_OUT_AMOUNT_MASK'));
  const digest = Buffer.from(blake2b(derivation, {dkLen:32}));
  let hint = 0;
  for (let i = 0; i < digest.length; i += 2) hint ^= digest.readUInt16LE(i);
  return {offset, hint, pad, amountMask:mask('ZANO_HDS_OUT_AMOUNT_BLIND_MASK'),
    concealingMask:mask('ZANO_HDS_OUT_CONCEALING_POINT'), assetMask:mask('ZANO_HDS_OUT_ASSET_BLIND_MASK')};
}
function buildOutput(keys, secret, index, amount, paymentId, explicitNative) {
  const d = derivationData(keys.view.multiply(secret).clearCofactor().toBytes(), index);
  const assetMask = explicitNative ? 0n : d.assetMask;
  const asset = nativeAsset.add(X.multiplyUnsafe(assetMask));
  const commitment = asset.multiplyUnsafe(amount).add(G.multiply(d.amountMask));
  const encryptedPaymentId = paymentId ^ d.pad.readBigUInt64LE(8);
  check(!paymentId || encryptedPaymentId, 'payment ID collision');
  const wire = {stealth:keys.spend.add(G.multiply(d.offset)).toBytes(), concealing:keys.view.multiply(d.concealingMask).toBytes(),
    asset:encodeCommitment(asset), commitment:encodeCommitment(commitment), encryptedAmount:amount ^ d.pad.readBigUInt64LE(), encryptedPaymentId};
  return {wire, hint:d.hint, amount, asset, commitment, assetMask, amountMask:d.amountMask};
}
function watch(address, viewSecret) {
  const keys = standardAddress(address), secret = le(key(viewSecret));
  check(secret > 0n && secret < F.ORDER && G.multiply(secret).equals(keys.view), 'payer view key');
  return {...keys, secret};
}
function scan(wallet, fundingPublic, index, output) {
  const d = derivationData(point(fundingPublic).multiply(wallet.secret).clearCofactor().toBytes(), index);
  if (!wallet.spend.add(G.multiply(d.offset)).equals(point(output.stealth))) return null;
  check(wallet.view.multiply(d.concealingMask).equals(point(output.concealing)), 'funding concealing point');
  const amount = u64(output.encryptedAmount) ^ d.pad.readBigUInt64LE();
  const encryptedId = u64(output.encryptedPaymentId);
  const asset = point(output.asset).clearCofactor(), assetMask = asset.equals(nativeAsset) ? 0n : d.assetMask;
  const assetId = asset.subtract(X.multiplyUnsafe(assetMask));
  check(asset.multiplyUnsafe(amount).add(G.multiply(d.amountMask)).equals(point(output.commitment).clearCofactor()), 'funding commitment');
  return {amount, asset, assetMask, assetId, amountMask:d.amountMask, paymentId:encryptedId && (encryptedId ^ d.pad.readBigUInt64LE(8))};
}
function checkedInput(wallet, src) {
  check(Array.isArray(src.ring) && src.ring.length === 16 && Number.isInteger(src.realIndex) &&
    src.realIndex >= 0 && src.realIndex < 16, 'funding ring');
  const ring = src.ring.map(m => ({index:u64(m.index), destination:key(m.destination), commitment:key(m.commitment), asset:key(m.asset)}));
  for (const [j,m] of ring.entries()) {
    check(!j || ring[j-1].index < m.index, 'ordering of ring offsets');
    point(m.destination); point(m.commitment); point(m.asset);
  }
  check(new Set(ring.map(m => m.destination.toString('hex'))).size === ring.length, 'duplicate ring member');
  const real = ring[src.realIndex], index = u64(src.outputIndex), fundingPublic = key(src.fundingPublic);
  const output = {stealth:real.destination, asset:real.asset, commitment:real.commitment, concealing:key(src.concealing),
    encryptedAmount:u64(src.encryptedAmount), encryptedPaymentId:u64(src.encryptedPaymentId)};
  const owned = scan(wallet, fundingPublic, index, output);
  check(owned && owned.amount > 0n && owned.assetId.equals(nativeAsset), 'funding owner or native asset');
  const image = key(src.keyImage), sig = Buffer.from(getBytes(src.keyImageSignature));
  check(sig.length === 64, 'signed key image size');
  const c = le(sig.subarray(0,32)), r = le(sig.subarray(32));
  check(c < F.ORDER && r < F.ORDER && hs(image, G.multiplyUnsafe(r).add(point(real.destination).multiplyUnsafe(c)).toBytes(),
    imageGenerator(real.destination).multiplyUnsafe(r).add(point(image).multiplyUnsafe(c)).toBytes()) === c, 'signed key image');
  return {...owned, index, fundingPublic, ring, realIndex:src.realIndex, image, output};
}

function buildZanoPayment({payer, viewSecret, recipient, amount, inputs, paymentId = 0n, hardfork = 7}) {
  check(hardfork === 6 || hardfork === 7, 'hardfork');
  const wallet = watch(payer, viewSecret), receiver = standardAddress(recipient);
  check(payer !== recipient, 'external recipient');
  amount = u64(amount); paymentId = u64(paymentId);
  check(Array.isArray(inputs) && inputs.length >= 1 && inputs.length <= 2, 'funding input count');
  const sources = inputs.map(src => checkedInput(wallet, src)).sort((a,b) => Buffer.compare(a.image,b.image));
  check(new Set(sources.map(s => s.image.toString('hex'))).size === sources.length, 'duplicate key image');
  const total = u64(sources.reduce((v,s) => v+s.amount, 0n));
  check(amount > 0n && total >= amount + fee, 'insufficient native funds');
  const change = total-amount-fee, secret = randomScalar();
  // The ordinary consensus minimum is two outputs, including exact spends.
  check(change || amount >= 2n, 'two positive outputs');
  const explicit = sources.every(s => s.ring.every(m => point(m.asset).clearCofactor().equals(nativeAsset)));
  const split = change ? amount : 1n + randomScalar() % (amount-1n);
  const destinations = [{keys:receiver, value:split, external:true},
    {keys:change ? wallet : receiver, value:change || amount-split, external:!change}];
  if (randomScalar() & 1n) destinations.reverse();
  const outputs = destinations.map((d,i) => buildOutput(d.keys, secret, i, d.value, d.external ? paymentId : 0n, explicit));
  const hints = new Set(outputs.map(o => o.hint));
  while (hints.size < 2) hints.add(Number(randomScalar() & 65535n));
  const extra = [{type:22}, {type:23}, ...[...hints].sort((a,b) => a-b).map(n => ({type:11,hint:word64(BigInt(n)).subarray(0,2)})), {type:39}];
  let remaining = F.create(outputs.reduce((v,o) => v + o.amountMask, 0n));
  for (const [i,src] of sources.entries()) {
    src.amountBlind = i+1 === sources.length ? remaining : randomScalar();
    remaining = F.sub(remaining,src.amountBlind);
    src.assetBlind = randomScalar();
    src.pseudoAssetMask = F.add(src.assetMask,src.assetBlind);
    src.pseudoAsset = src.asset.add(X.multiply(src.assetBlind));
    src.pseudoAmount = src.asset.multiplyUnsafe(src.amount).add(G.multiplyUnsafe(src.amountBlind));
  }
  const tx = {hardfork, inputs:sources.map(s => ({offsets:s.ring.map(m => m.index),image:s.image})),
    publicKey:G.multiply(secret).toBytes(), extra, fee, outputs:outputs.map(o => o.wire)};
  const prefix = serializeZanoPrefix(tx), message = hash(prefix);
  Object.assign(tx, proveZanoPayment(message, outputs, sources, secret));
  const header = Buffer.alloc(4); header[0] = 1; header[1] = destinations.reduce((v,d,i) => v | (Number(d.external)<<i),0);
  header.writeUInt16LE(prefix.length,2);
  const payload = Buffer.concat([header,prefix,sc(secret),receiver.spend.toBytes(),receiver.view.toBytes(),word64(paymentId),
    ...outputs.map(o => word64(o.amount)), ...sources.flatMap(s => [Buffer.from([s.realIndex]),word64(s.index),s.fundingPublic,
      s.output.concealing,word64(s.output.encryptedAmount),word64(s.output.encryptedPaymentId),sc(s.amountBlind),sc(s.assetBlind),
      ...s.ring.flatMap(m => [m.destination,m.commitment,m.asset])])]);
  function finalize(response) {
    const b = Buffer.from(getBytes(response)), stride = 128+64*16;
    check(b.length === sources.length*stride,'signature response size');
    const signatures = sources.map((s,i) => {
      const part = b.subarray(i*stride,(i+1)*stride), word = j => part.subarray(32*j,32*j+32);
      check(word(1).equals(s.image),'signer key image');
      return {amount:encodeCommitment(s.pseudoAmount),asset:encodeCommitment(s.pseudoAsset),c:word(0),k1:word(2),k2:word(3),
        rg:s.ring.map((_,j) => word(4+j)),rx:s.ring.map((_,j) => word(20+j))};
    });
    const wire = serializeZanoPayment({...tx, signatures});
    check(verifyZanoPayment(wire,sources.map(s => s.ring)) === message.toString('hex'),'signed payment');
    return wire;
  }
  async function broadcast(response, post) {
    const wire = finalize(response);
    const genesis = await post('/json_rpc',{jsonrpc:'2.0',id:1,method:'on_getblockhash',params:[0]});
    check(!genesis.error && genesis.result === 'cc608f59f8080e2fbfe3c8c80eb6e6a953d47cf2d6aebd345bada3a1cab99852', 'RPC genesis');
    const received = await post('/sendrawtransaction',{tx_as_hex:wire.toString('hex')});
    check(received.status === 'OK','node relay');
    return message.toString('hex');
  }
  return {payload, id:message.toString('hex'), finalize, broadcast};
}

function scanZanoPayment(tx, address, viewSecret) {
  const wallet = watch(address, viewSecret);
  return tx.outputs.flatMap((output,i) => {
    const owned = scan(wallet, tx.publicKey, i, output);
    return owned ? [{index:i, amount:owned.amount, paymentId:owned.paymentId, assetId:owned.assetId.toHex()}] : [];
  });
}

module.exports = {buildZanoPayment, scanZanoPayment};
