'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {once} = require('node:events');
const {spawn,execFileSync} = require('node:child_process');
const {createInterface} = require('node:readline');
const phoneRequire = require('node:module').createRequire(require.resolve('../../../tools/package.json'));
const {base58xmr} = phoneRequire('@scure/base');
const {HDNodeWallet,Mnemonic} = phoneRequire('ethers');
const {ed25519} = phoneRequire('@noble/curves/ed25519');
const {hs,sc,hash,imageGenerator,randomScalar,varint} = require('../../../tools/ryo_bulletproof.cjs');
const {parseZanoPayment} = require('../../../tools/zano_transaction.cjs');
const {buildZanoPayment,scanZanoPayment} = require('../../../tools/zano_payment.cjs');
const {nativeAsset,domain,X} = require('../../../tools/zano_verify.cjs');
const {cases} = require('../../fixtures/privacy/zano-mainnet-payments.json');
const [probe,releaseProbe,fundingFile,outputFile] = process.argv.slice(2);
const G = ed25519.Point.BASE, F = ed25519.Point.Fn;
const child = HDNodeWallet.fromSeed(Mnemonic.fromPhrase('abandon '.repeat(11)+'about').computeSeed()).derivePath("m/44'/1018'/0'/0/3");
const spend = hs(Buffer.from(child.privateKey.slice(2),'hex')), view = hs(sc(spend));
const fee = 10000000000n, id = 0x0102030405060708n;
function address(s,v) {
  const body = Buffer.concat([Buffer.from([0xc5,1]),G.multiply(s).toBytes(),G.multiply(v).toBytes()]);
  return base58xmr.encode(Buffer.concat([body,hash(body).subarray(0,4)]));
}
const payer = address(spend,view), fixtureRecipient = address(5n,17n);
const format = n => `${n/1000000000000n}.${(n%1000000000000n).toString().padStart(12,'0')} ZANO`;
function source(funding, ring) {
  const fundingPublic = Buffer.from(funding.publicKey,'hex'), index = funding.outputIndex;
  const derivation = ed25519.Point.fromBytes(fundingPublic).multiply(view).clearCofactor().toBytes();
  const secret = F.add(spend,hs(derivation,varint(index)));
  const dest = G.multiply(secret).toBytes(), realIndex = ring.findIndex(m => m.index === funding.index);
  assert.equal(Buffer.from(dest).toString('hex'),ring[realIndex].destination);
  const hp = imageGenerator(dest), image = hp.multiply(secret).toBytes(), k = randomScalar();
  const c = hs(image,G.multiply(k).toBytes(),hp.multiply(k).toBytes());
  return {fundingPublic,outputIndex:index,ring:ring.map(m => ({...m,destination:'0x'+m.destination,asset:'0x'+m.asset,commitment:'0x'+m.commitment})),realIndex,
    concealing:'0x'+funding.concealing,encryptedAmount:funding.encryptedAmount,encryptedPaymentId:funding.encryptedPaymentId,
    keyImage:image,keyImageSignature:Buffer.concat([sc(c),sc(k-c*secret)])};
}
function synthetic(i,amount) {
  const secret = 47n+BigInt(i), index = i, derivation = G.multiply(8n*secret*view % F.ORDER).toBytes();
  const h = hs(derivation,varint(index)), mask = name => hs(domain(name),sc(h));
  const pad = sc(mask('ZANO_HDS_OUT_AMOUNT_MASK'));
  const toHex = p => Buffer.from(p.toBytes()).toString('hex');
  const real = {index:50+i,destination:toHex(G.multiply(F.add(spend,h))),
    concealing:toHex(G.multiply(F.mul(view,mask('ZANO_HDS_OUT_CONCEALING_POINT')))),
    publicKey:toHex(G.multiply(secret)),outputIndex:index,encryptedAmount:(amount ^ pad.readBigUInt64LE()).toString(),
    encryptedPaymentId:pad.readBigUInt64LE(8).toString()};
  const asset = nativeAsset.add(X.multiply(mask('ZANO_HDS_OUT_ASSET_BLIND_MASK')));
  real.asset = toHex(asset.multiply(F.inv(8n)));
  real.commitment = toHex(asset.multiply(amount).add(G.multiply(mask('ZANO_HDS_OUT_AMOUNT_BLIND_MASK'))).multiply(F.inv(8n)));
  return source(real,[real,...cases[0].rings[0].slice(0,15)]);
}
function begin(payload,index=3) {
  const h = Buffer.from([5,1,0,0,0,4,122,97,110,111,5,0,0,0,0,0,0]);
  h.writeUInt32LE(index,11); h.writeUInt16LE(payload.length,15);
  return Buffer.concat([h,payload]);
}
async function exercise(inputs,amount,change,recipient = fixtureRecipient,recipientView = sc(17n)) {
  const intent = {payer,viewSecret:sc(view),recipient,inputs,amount,paymentId:id};
  assert.throws(() => buildZanoPayment({...intent,viewSecret:sc(9n)}),/view key/);
  assert.throws(() => buildZanoPayment({...intent,inputs:[{...inputs[0],keyImageSignature:Buffer.alloc(64)}]}),/signed key image/);
  const transfer = buildZanoPayment(intent), payload = transfer.payload;
  assert.match(execFileSync(releaseProbe,['phone-app-pipe'],{input:begin(payload).toString('hex')+'\n',encoding:'utf8'}),/response=0100000006/);
  const proc = spawn(probe,['phone-app-pipe'],{stdio:['pipe','pipe','inherit']});
  const closed = once(proc,'close'), lines = createInterface({input:proc.stdout,crlfDelay:Infinity})[Symbol.asyncIterator]();
  const send = cmd => proc.stdin.write((typeof cmd === 'string' ? cmd : cmd.toString('hex'))+'\n');
  const line = async () => { const r = await lines.next(); assert.ok(!r.done); return r.value; };
  async function response(cmd,status) {
    send(cmd); const s = await line(); assert.match(s,/^response=/);
    const b = Buffer.from(s.slice(9),'hex'); assert.deepEqual(b.subarray(0,4),cmd.subarray(1,5)); assert.equal(b[4],status,s);
    return b.subarray(5);
  }
  const result = (ticket,op=6) => Buffer.concat([Buffer.from([op,2,0,0,0]),ticket]);
  async function panel(cmd,expected) { send(cmd); assert.equal(await line(),expected); }
  try {
    await response(begin(payload,4),4);
    await response(begin(payload.subarray(0,-1)),4);
    const prefixLength = payload.readUInt16LE(2), extra = 4+2+179*inputs.length;
    for (const offset of [1,extra+2,extra+46,extra+55+2,extra+55+98,4+prefixLength+32,4+prefixLength+96,4+prefixLength+104]) {
      const bad = Buffer.from(payload); bad[offset] ^= 1; await response(begin(bad),4);
    }
    const cancelled = await response(begin(payload),1); await response(result(cancelled,7),2);
    const denied = await response(begin(payload),1); await panel('reject','panel-decided'); await response(result(denied),2);
    const lost = await response(begin(payload),1); await panel('approve','panel-decided'); await panel('field-lost','review-cleared'); await response(result(lost),5);
    const expired = await response(begin(payload),1); await panel('approve','panel-decided'); await panel('expire','deadline-reached'); await response(result(expired),5);
    const unattended = await response(begin(payload),1); await panel('expire','deadline-reached'); await panel('tick','tick-serviced'); await response(result(unattended),5);
    const ticket = await response(begin(payload),1); await response(result(denied),4); await response(result(ticket),1);
    send('review'); const text = [];
    for (let s; (s = await line()) !== 'review-end';) text.push(s);
    for (const s of ['ZANO',recipient,'EXTERNAL',format(amount),format(fee),format(amount+fee),'Payment ID: 0807060504030201']) assert.ok(text.includes(s),s);
    if (change) for (const s of ['CHANGE',payer,format(change)]) assert.ok(text.includes(s),s);
    await panel('approve','panel-decided'); const reply = await response(result(ticket),0); await response(result(ticket),5);
    const signed = reply.subarray(2); assert.equal(reply.readUInt16LE(),signed.length);
    const wire = transfer.finalize(signed), tx = parseZanoPayment(wire);
    const received = scanZanoPayment(tx,recipient,recipientView);
    assert.equal(received.reduce((s,o) => s+o.amount,0n),amount);
    assert.ok(received.every(o => o.paymentId === id && o.assetId === nativeAsset.toHex()));
    assert.equal(scanZanoPayment(tx,payer,sc(view)).reduce((s,o) => s+o.amount,0n),change);
    const invalid = Buffer.from(signed); invalid[0] ^= 1;
    await assert.rejects(transfer.broadcast(invalid,() => assert.fail('unexpected broadcast')),/CLSAG|scalar/);
    await assert.rejects(transfer.broadcast(signed,async route => {assert.equal(route,'/json_rpc');return {result:'other'};}),/genesis/);
    const requests = [];
    const returned = await transfer.broadcast(signed,async (route,body) => {
      requests.push(route);
      if (route === '/json_rpc') {
        assert.equal(body.method,'on_getblockhash'); assert.deepEqual(body.params,[0]);
        return {result:'cc608f59f8080e2fbfe3c8c80eb6e6a953d47cf2d6aebd345bada3a1cab99852'};
      }
      assert.deepEqual(body,{tx_as_hex:wire.toString('hex')}); return {status:'OK'};
    });
    assert.equal(returned,tx.id); assert.deepEqual(requests,['/json_rpc','/sendrawtransaction']);
    console.log(`Zano ${inputs.length} input(s), ${wire.length} bytes, ${tx.id}, full proof and host approval passed`);
    return {id:tx.id,wire:wire.toString('hex'),amount:amount.toString()};
  } finally { proc.stdin.end(); const [code] = await closed; assert.equal(code,0); }
}
async function main() {
  if (probe === '--addresses') { console.log(JSON.stringify({payer,recipient:fixtureRecipient})); return; }
  if (fundingFile) {
    const records = JSON.parse(fs.readFileSync(fundingFile));
    const receipts = [];
    for (const {funds,amount,recipient,recipientView} of records) {
      const total = funds.reduce((sum,f) => {
        const derivation = ed25519.Point.fromHex(f.publicKey).multiply(view).clearCofactor().toBytes();
        const h = hs(derivation,varint(f.outputIndex));
        return sum + (BigInt(f.encryptedAmount) ^ sc(hs(domain('ZANO_HDS_OUT_AMOUNT_MASK'),sc(h))).readBigUInt64LE());
      },0n);
      receipts.push(await exercise(funds.map(o => source(o,o.ring)),BigInt(amount),total-fee-BigInt(amount),recipient,recipientView));
    }
    fs.writeFileSync(outputFile,JSON.stringify(receipts));
  } else {
    await exercise([synthetic(0,fee+12345678n)],12345678n,0n);
    await exercise([synthetic(0,fee),synthetic(1,1000000000000n)],24691356n,1000000000000n-24691356n);
  }
}
main().catch(e => {console.error(e); process.exitCode=1;});
