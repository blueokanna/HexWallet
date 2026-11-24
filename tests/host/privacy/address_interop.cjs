// Exercise the ADDRESS request and panel callback with the public BIP39 test wallet.
// NODE_PATH points to the locked tests/host/protocol-oracles/node_modules.
'use strict';
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { parseArgs } = require('node:util');
const { HDNodeWallet, Mnemonic, getBytes, keccak256, toBeHex } = require('ethers');
const { ed25519 } = require('@noble/curves/ed25519.js');
const { base58xmr } = require('@scure/base');

const { positionals: [probe], values } = parseArgs({ allowPositionals: true, options: {
  'ryo-validator': { type: 'string' }, 'zano-rpc-port': { type: 'string' },
} });
const root = HDNodeWallet.fromSeed(Mnemonic.fromPhrase('abandon '.repeat(11) + 'about').computeSeed());
const point = ed25519.Point;
const asLE = n => Buffer.from(getBytes(toBeHex(n, 32))).reverse();
const hashScalar = bytes => BigInt('0x' + Buffer.from(getBytes(keccak256(bytes))).reverse().toString('hex')) % point.Fn.ORDER;

function uint32s(...numbers) {
  const bytes = Buffer.alloc(numbers.length * 4);
  numbers.forEach((n, i) => bytes.writeUInt32LE(n, i * 4));
  return bytes;
}

function encodeAddress(prefix, keys) {
  const tag = [];
  while (prefix >= 128) {
    tag.push(128 | (prefix & 127));
    prefix = Math.floor(prefix / 128);
  }
  const body = Buffer.concat([Buffer.from([...tag, prefix]), keys]);
  return base58xmr.encode(Buffer.concat([body, getBytes(keccak256(body)).subarray(0, 4)]));
}

function phoneAddress(coin, account, change, index, sub) {
  const command = Buffer.concat([Buffer.from([4, 1, 0, 0, 0, coin.length]), Buffer.from(coin),
    uint32s(account, change, index), uint32s(...(sub || []))]);
  const output = execFileSync(probe, ['phone-app-pipe'], { input: command.toString('hex') + '\n', encoding: 'utf8' });
  return Object.fromEntries(output.trim().split(/\r?\n/).map(line => line.split('=')));
}

async function check(coin, account, change, index, sub) {
  const result = phoneAddress(coin, account, change, index, sub);
  const response = Buffer.from(result.response, 'hex');
  assert.deepEqual(response.subarray(0, 4), uint32s(1));
  const path = `m/44'/${coin === 'ryo' ? 382 : 1018}'/${account}'/${change}/${index}`;
  const explicitSuffix = sub && coin === 'ryo' && (sub.some(n => n !== 0) || account !== 0 || index !== 0);
  const displayedPath = explicitSuffix ? `${path}+${sub.join('/')}` : path;
  if ((coin === 'zano' && sub?.some(n => n !== 0)) || displayedPath.length >= 48) {
    assert.deepEqual(response.subarray(4), Buffer.from([3]));
    assert.equal(result.address, undefined);
    return;
  }
  const spend = hashScalar(root.derivePath(path).privateKey);
  const view = hashScalar(asLE(spend));
  let spendPub = point.BASE.multiply(spend), viewPub = point.BASE.multiply(view);
  const [major, minor] = sub || [account, index];
  const isSub = coin === 'ryo' && (major !== 0 || minor !== 0);
  if (isSub) {
    const offset = hashScalar(Buffer.concat([Buffer.from('SubAddr\0'), asLE(view), uint32s(major, minor)]));
    spendPub = spendPub.add(point.BASE.multiply(offset));
    viewPub = spendPub.multiply(view);
  }
  const keys = Buffer.concat([spendPub.toBytes(), viewPub.toBytes()]);
  const address = encodeAddress(coin === 'zano' ? 0xc5 : isSub ? 0x2fe192 : 0x2ce192, keys);
  assert.equal(result.address, address);
  assert.equal(result.path, displayedPath);
  assert.deepEqual(response.subarray(4), Buffer.concat([Buffer.from([0, address.length]),
    Buffer.from(address), Buffer.from([displayedPath.length]), Buffer.from(displayedPath)]));
  if (coin === 'ryo' && values['ryo-validator']) {
    const [record] = JSON.parse(execFileSync(values['ryo-validator'], ['-n', 'mainnet', address], { encoding: 'utf8' }));
    assert.equal(record.valid, true);
    assert.equal(record.network, 'mainnet');
    assert.equal(record.address, address);
    assert.equal(record.is_subaddress, isSub);
  }
  if (coin === 'zano' && values['zano-rpc-port']) {
    const paymentId = Buffer.from('0102030405060708', 'hex');
    const response = await fetch(`http://127.0.0.1:${Number(values['zano-rpc-port'])}/json_rpc`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(10000),
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'get_integrated_address',
        params: { regular_address: address, payment_id: paymentId.toString('hex') } }),
    });
    assert.equal(response.status, 200);
    const rpc = await response.json();
    assert.equal(rpc.error, undefined, JSON.stringify(rpc.error));
    assert.equal(rpc.result.status, 'OK');
    assert.equal(rpc.result.payment_id, paymentId.toString('hex'));
    assert.equal(rpc.result.integrated_address, encodeAddress(0x3678, Buffer.concat([keys, paymentId])));
  }
}

async function main() {
  assert.ok(probe, 'Specify the path to chain_probe');
  for (const coin of ['ryo', 'zano']) {
    for (const args of [[0, 0, 0], [0, 0, 3], [1, 1, 2], [0, 0, 0, [0, 0]], [1, 1, 2, [4, 5]],
      [1, 1, 2, [0, 0]], [2147483647, 0, 2147483647, [4294967295, 4294967295]]]) {
      await check(coin, ...args);
    }
  }
  console.log('14 phone address cases passed (Ryo and Zano)');
  if (values['ryo-validator']) console.log('Ryo mainnet validator accepted 6 address responses');
  if (values['zano-rpc-port']) console.log('Zano daemon returned the expected integrated address in all 5 accepted cases');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
