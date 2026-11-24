'use strict';
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {parseZanoPayment, serializeZanoPayment} = require('../../../tools/zano_transaction.cjs');
const {verifyZanoPayment} = require('../../../tools/zano_verify.cjs');
const {cases} = require('../../fixtures/privacy/zano-mainnet-payments.json');

// Run the firmware verifier on the original (unreduced) prefix hash as well.
function checkFirmware(probe, folder, tx, rings) {
  const request = path.join(folder, 'request'), signature = path.join(folder, 'signature');
  tx.inputs.forEach((input, i) => {
    const sig = tx.signatures[i], ring = rings[i];
    const header = Buffer.alloc(12);
    header.write('HZAN'); header.writeUInt32LE(ring.length, 4);
    fs.writeFileSync(request, Buffer.concat([header, Buffer.from(tx.id, 'hex'), Buffer.alloc(128), sig.amount,
      sig.asset, ...ring.flatMap(m => [m.destination, m.commitment, m.asset])]));
    fs.writeFileSync(signature, Buffer.concat([sig.c, input.image, sig.k1, sig.k2, ...sig.rg, ...sig.rx]));
    execFileSync(probe, ['privacy-verify', request, signature]);
  });
}

const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'hexwallet-zano-'));
try {
  for (const sample of cases) {
    const wire = Buffer.from(sample.wire, 'hex'), tx = parseZanoPayment(wire);
    const rings = sample.rings.map(r => r.map(m => ({index: m.index, destination: Buffer.from(m.destination, 'hex'),
      commitment: Buffer.from(m.commitment, 'hex'), asset: Buffer.from(m.asset, 'hex')})));
    assert.equal(wire.length, sample.size);
    assert.equal(createHash('sha256').update(wire).digest('hex'), sample.sha256);
    assert.equal(tx.publicKey.toString('hex'), sample.publicKey);
    assert.equal(tx.fee, BigInt(sample.fee));
    assert.equal(tx.id, sample.id);
    assert.deepEqual(serializeZanoPayment(tx), wire);
    assert.equal(verifyZanoPayment(wire, rings), sample.id);
    if (process.argv[2]) checkFirmware(process.argv[2], folder, tx, rings);
    for (let n = 0; n < wire.length; ++n) assert.throws(() => parseZanoPayment(wire.subarray(0, n)));
    assert.throws(() => parseZanoPayment(Buffer.concat([wire, Buffer.alloc(1)])), /trailing data/);
    assert.throws(() => parseZanoPayment(Buffer.concat([wire.subarray(0, 1), Buffer.from([tx.inputs.length | 128, 0]),
      wire.subarray(2)])), /vector encoding/);
    const wrongRing = rings.map(r => [...r]);
    wrongRing[0][0] = {...rings[0][0], index: rings[0][0].index + 1};
    assert.throws(() => verifyZanoPayment(wire, wrongRing), /ring index/);
    wrongRing[0][0] = {...rings[0][0], commitment: rings[0][1].commitment};
    assert.throws(() => verifyZanoPayment(wire, wrongRing), /CLSAG_GGX/);
    function reject(change, error) {
      const changed = parseZanoPayment(wire);
      change(changed);
      assert.throws(() => verifyZanoPayment(serializeZanoPayment(changed), rings), error);
    }
    reject(t => { t.fee += 1n; }, /CLSAG_GGX/);
    reject(t => { t.signatures.at(-1).rx[0][0] ^= 1; }, /CLSAG_GGX/);
    reject(t => { t.assets.at(-1).y[0] ^= 1; }, /asset proof commitment/);
    reject(t => { t.assets[0].z[0] ^= 1; }, /asset membership proof/);
    reject(t => { t.aggregation.y1[0][0] ^= 1; }, /range aggregation proof/);
    reject(t => { t.range.delta[0] ^= 1; }, /Bulletproof\+/);
    reject(t => { t.balance.y1[0] ^= 1; }, /balance proof/);
    reject(t => { t.balance.c.fill(255); }, /scalar/);
    console.log(`Zano block ${sample.height}, ${tx.id}, ${rings.length} input(s), all proofs and ${wire.length} truncations passed`);
  }
} finally {
  fs.rmSync(folder, {recursive: true, force: true});
}
