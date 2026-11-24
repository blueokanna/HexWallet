'use strict';
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const {once} = require('node:events');
const fs = require('node:fs');
const {createInterface} = require('node:readline');
const {prepareRyoPayment, buildRyoPayment, scanRyoPayment} = require('../../../tools/ryo_payment.cjs');
const {getBytes, keccak256} = require('ethers');
const {base58xmr} = require('@scure/base');
const {ed25519} = require('@noble/curves/ed25519.js');
const [probe, releaseProbe, fixture, output, port] = process.argv.slice(2);
const {request, payment, sigOffset, wallet, aboveCap} = JSON.parse(fs.readFileSync(fixture));
request.payer = address(wallet);
const transfer = prepareRyoPayment(request);
const format = amount => `${BigInt(amount)/1000000000n}.${(BigInt(amount)%1000000000n).toString().padStart(9, '0')} RYO`;
function address(keys) {
  const prefix = Buffer.from([0x92, 0xc3, 0xb3, 0x01]); // Ryo long standard address, varint 0x2ce192
  const data = Buffer.concat([prefix, Buffer.from(keys, 'hex')]);
  return base58xmr.encode(Buffer.concat([data, Buffer.from(getBytes(keccak256(data))).subarray(0, 4)]));
}
function begin(payload = transfer.payload, index = 3) {
  const header = Buffer.from([5,1,0,0,0,3,114,121,111,5,0,0,0,0,0,0]);
  header.writeUInt32LE(index, 10);
  header.writeUInt16LE(payload.length, 14);
  return Buffer.concat([header, payload]);
}
async function main() {
  assert.equal(execFileSync(releaseProbe, ['phone-app-pipe'], {input: begin().toString('hex')+'\n', encoding:'utf8'}).trim(),
    'response=0100000006');
  const child = spawn(probe, ['phone-app-pipe'], {stdio:['pipe','pipe','inherit']});
  const closed = once(child, 'close');
  const lines = createInterface({input:child.stdout, crlfDelay:Infinity})[Symbol.asyncIterator]();
  const line = async () => { const r = await lines.next(); assert.equal(r.done, false); return r.value; };
  const send = cmd => child.stdin.write((typeof cmd === 'string' ? cmd : cmd.toString('hex'))+'\n');
  async function response(cmd, status) {
    send(cmd);
    const text = await line(); assert.match(text, /^response=/);
    const b = Buffer.from(text.slice(9),'hex');
    assert.ok(b.subarray(0,4).equals(cmd.subarray(1,5)));
    assert.equal(b[4],status);
    if (status !== 0 && !(cmd[0] === 5 && status === 1)) assert.equal(b.length,5);
    return b.subarray(5);
  }
  const result = id => Buffer.concat([Buffer.from([6,2,0,0,0]), id]);
  const panel = async (event, expected) => { send(event); assert.equal(await line(), expected); };
  try {
    const zano = Buffer.concat([Buffer.from([5,1,0,0,0,4]), Buffer.from('zano'), begin().subarray(9)]);
    await response(zano,6);
    await response(begin(transfer.payload.subarray(0,-1)),4);
    await response(begin(Buffer.concat([transfer.payload, Buffer.from([0])])),4);
    await response(begin(transfer.payload,4),4);
    const damaged = Buffer.from(transfer.payload); damaged[damaged.length-1] ^= 1;
    await response(begin(damaged),4);
    await response(begin(Buffer.alloc(16384 - 16)),4);
    if (aboveCap) await response(begin(Buffer.from(aboveCap, 'hex')),4);
    const first = await response(begin(),1); assert.equal(first.length,8);
    await response(result(first),1);
    await panel('reject','panel-decided'); await response(result(first),2);
    const second = await response(begin(),1); assert.notDeepEqual(second,first);
    await response(result(first),4);
    await panel('approve','panel-decided'); await panel('field-lost','review-cleared');
    await response(result(second),5);
    const cancelled = await response(begin(),1);
    const cancel = result(cancelled); cancel[0] = 7;
    await response(cancel,2); await response(result(cancelled),2);
    const expired = await response(begin(),1);
    await panel('approve','panel-decided'); await panel('expire','deadline-reached');
    await response(result(expired),5);
    const third = await response(begin(),1);
    send('review'); const review = [];
    for (let s; (s = await line()) !== 'review-end';) review.push(s);
    for (const field of ['RYO','FEE','EXTERNAL','CHANGE',format(payment.amount),format(payment.change),format(payment.fee),
      format(BigInt(payment.amount)+BigInt(payment.fee)),`Payment ID: ${payment.payment_id || 'none'}`,
      address(request.recipient.spend.slice(2)+request.recipient.view.slice(2)), address(wallet)]) assert.ok(review.includes(field),field);
    await panel('approve','panel-decided');
    const reply = await response(result(third),0);
    const wire = reply.subarray(2); assert.equal(reply.readUInt16LE(), wire.length);
    await response(result(third),5);
    function firstChanged(overrides) {
      return [{...request.sources[0], ...overrides}, ...request.sources.slice(1)];
    }
    assert.throws(() => prepareRyoPayment({...request, sources:firstChanged({keyImageSignature:Buffer.alloc(64)})}), /signed key image/);
    assert.throws(() => prepareRyoPayment({...request, sources:firstChanged({outputIndex:0})}), /belong to payer/);
    assert.throws(() => prepareRyoPayment({...request, sources:firstChanged({ecdh:Buffer.alloc(64)})}));
    assert.throws(() => prepareRyoPayment({...request, viewSecret:Buffer.alloc(32)}), /view key/);
    const noPost = () => assert.fail('unexpected RPC');
    for (const offset of [2,sigOffset,wire.length-1]) {
      const altered = Buffer.from(wire); altered[offset] ^= 1;
      await assert.rejects(transfer.broadcast(altered,noPost),/Ryo/);
    }
    let calls = 0;
    await assert.rejects(transfer.broadcast(wire, async route => {
      assert.equal(route,'/json_rpc'); ++calls; return {result:{status:'OK',block_header:{hash:'other'}}};
    }), /genesis/); assert.equal(calls,1);
    const id = transfer.verify(wire);
    const rpc = async (route, params) => {
      const reply = await fetch(`http://127.0.0.1:${port}${route}`, {method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(params), signal:AbortSignal.timeout(10000)});
      assert.equal(reply.status,200); return reply.json();
    };
    await assert.rejects(transfer.broadcast(wire,rpc),/invalid output/);
    const pool = await rpc('/get_transaction_pool',{}); assert.equal(pool.status,'OK'); assert.equal(pool.transactions?.length || 0,0);
    fs.writeFileSync(output,wire);
    console.log(`${request.sources.length} input(s), ${id}: panel, single-use approval, phone MLSAGs and genesis rejection passed`);
    const payer = address(wallet), recipient = address(request.recipient.spend.slice(2)+request.recipient.view.slice(2));
    const inputs = [...request.sources];
    const total = inputs.reduce((sum,s) => sum+BigInt(s.amount),0n);
    const one = inputs.length === 1;
    const intent = {payer,viewSecret:request.viewSecret,recipient,amount:one ? total-BigInt(payment.fee) : 3579n, inputs:inputs.reverse(),
      fee:one ? payment.fee : undefined, paymentId: one ? null : '0x'+'9e'.repeat(32)};
    if (one) {
      // Preserve the owned destination and its valid key-image signature.
      // The over-cap fixture supplies the matching higher amount commitment.
      const high = Buffer.from(aboveCap, 'hex');
      const record = 3 + high.readUInt16LE(1) + 96;
      const member = record + 138 + inputs[0].realIndex * 72;
      const ring = Array.from({length: 109}, (_, i) => ({index: i < 13 ? 128*(i+1) : 128*13+i-12,
        destination: '0x'+ed25519.Point.BASE.multiply(BigInt(i+1)).toHex(), commitment: inputs[0].ring[0].commitment}));
      ring[inputs[0].realIndex] = {...ring[inputs[0].realIndex], destination: inputs[0].ring[inputs[0].realIndex].destination,
        commitment: high.subarray(member+40, member+72)};
      const source = {...inputs[0], ring, ecdh: high.subarray(record+42, record+106)};
      const limit = {...intent, amount: 1n, fee: 100000000n, inputs: [source]};
      const exact = buildRyoPayment(limit);
      assert.equal(begin(exact.payload).length, 16384);
      const pending = await response(begin(exact.payload), 1);
      await panel('reject', 'panel-decided'); await response(result(pending), 2);
      assert.throws(() => buildRyoPayment({...limit, fee: 100000001n}), /fee outside/);
      ring.at(-1).index += 127;
      assert.throws(() => buildRyoPayment(limit), /exceeds phone frame/);
    }
    assert.throws(() => buildRyoPayment({...intent,amount:total+1n}),/insufficient funds/);
    assert.throws(() => buildRyoPayment({...intent,fee:0}),/fee outside/);
    assert.throws(() => buildRyoPayment({...intent,recipient:recipient.slice(0,-1)+'0'}),/Base58/);
    const built = buildRyoPayment(intent);
    const reviewId = await response(begin(built.payload),1);
    send('review'); const lines = [];
    for (let s; (s = await line()) !== 'review-end';) lines.push(s);
    const cost = BigInt(payment.fee); // equal-sized wires for the two-output case
    for (const s of [format(intent.amount),format(cost),recipient, 'Payment ID: '+(one ? 'none' : '9e'.repeat(32))]) assert.ok(lines.includes(s),s);
    assert.equal(lines.includes('CHANGE'),!one);
    if (!one) for (const s of [payer,format(total-intent.amount-cost)]) assert.ok(lines.includes(s),s);
    await panel('approve','panel-decided');
    const builtResult = await response(result(reviewId),0);
    const builtSigned = builtResult.subarray(2);
    assert.equal(builtResult.readUInt16LE(),builtSigned.length);
    const builtId = built.verify(builtSigned);
    const recipientView = Buffer.alloc(32); recipientView[0] = 11;
    const scanned = scanRyoPayment({wire:builtSigned, receiver:recipient, viewSecret:recipientView});
    assert.equal(scanned.length,1); assert.equal(scanned[0].amount,intent.amount);
    assert.equal(scanned[0].paymentId,one ? null : '9e'.repeat(32));
    const own = scanRyoPayment({wire:builtSigned, receiver:payer, viewSecret:request.viewSecret});
    assert.equal(own.length,one ? 0 : 1);
    if (!one) assert.equal(own[0].amount,total-intent.amount-cost);
    await assert.rejects(built.broadcast(builtSigned,rpc),/invalid output/);
    await response(result(reviewId),5);
    fs.writeFileSync(output+'.built',builtSigned);
    console.log(`Phone constructed and verified ${builtId}, ${inputs.length} input(s), ${one ? 'exact spend' : 'change and payment ID'}`);
  } finally { child.stdin.end(); }
  assert.equal((await closed)[0],0);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
