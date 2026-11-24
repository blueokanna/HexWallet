'use strict';
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {createInterface} = require('node:readline');
const {once} = require('node:events');
const fs = require('node:fs');
const {buildRyoPayment, scanRyoPayment} = require('../../../tools/ryo_payment.cjs');
const [path, mode, wire] = process.argv.slice(2);
const intent = JSON.parse(fs.readFileSync(path));

async function main() {
  if (mode === '--scan') {
    const view = Buffer.alloc(32); view[0] = 11;
    const received = scanRyoPayment({wire:'0x'+wire, receiver:intent.recipient, viewSecret:view});
    assert.equal(received.length,1);
    console.log(JSON.stringify([received[0].amount.toString(),received[0].paymentId]));
    return;
  }
  const payment = buildRyoPayment(intent);
  if (intent.fee) assert.throws(() => buildRyoPayment({...intent, fee: BigInt(intent.fee)+1n}), /fee outside/);
  const child = spawn(mode, ['phone-app-pipe'], {stdio:['pipe','pipe','inherit']});
  const closed = once(child,'close');
  const reader = createInterface({input:child.stdout,crlfDelay:Infinity})[Symbol.asyncIterator]();
  const read = async () => { const item = await reader.next(); assert.equal(item.done,false); return item.value; };
  const send = value => child.stdin.write(value+'\n');
  try {
    const header = Buffer.from([5,1,0,0,0,3,114,121,111,5,3,0,0,0,0,0]);
    header.writeUInt16LE(payment.payload.length,14);
    send(Buffer.concat([header,payment.payload]).toString('hex'));
    const pending = await read(); assert.match(pending,/^response=0100000001[0-9a-f]{16}$/);
    send('review');
    const review = [];
    for (let field; (field=await read()) !== 'review-end';) review.push(field);
    assert.ok(review.includes(intent.recipient) && review.includes(intent.payer));
    if (intent.fee) assert.ok(review.includes('0.100000000 RYO'));
    const amount = BigInt(intent.amount);
    assert.ok(review.includes(`${amount/1000000000n}.${(amount%1000000000n).toString().padStart(9,'0')} RYO`));
    assert.ok(review.includes('Payment ID: '+intent.paymentId.slice(2)));
    send('approve'); assert.equal(await read(),'panel-decided');
    const result = '0602000000'+pending.slice(-16);
    send(result);
    const text = await read(); assert.match(text,/^response=0200000000[0-9a-f]+$/);
    const body = Buffer.from(text.slice(19),'hex'), tx = body.subarray(2);
    assert.equal(body.readUInt16LE(),tx.length);
    const id = payment.verify(tx);
    send(result); assert.equal(await read(),'response=0200000005');
    console.log(JSON.stringify({wire:tx.toString('hex'),id}));
  } finally { child.stdin.end(); }
  assert.equal((await closed)[0],0);
}
main().catch(err => { console.error(err); process.exitCode = 1; });
