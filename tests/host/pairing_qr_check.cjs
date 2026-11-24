'use strict';
const assert = require('node:assert/strict');
const { generateKeyPairSync, createPublicKey, createHash, createHmac, createCipheriv, diffieHellman, hkdfSync, randomBytes, sign, verify } = require('node:crypto');
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const { PairingEnrollment } = require('../../tools/pairing_qr.cjs');

async function main() {
  const probe = spawn(process.argv[2], ['link-pipe'], { stdio: ['pipe', 'pipe', 'inherit'], timeout: 120000 });
  const lines = createInterface({ input: probe.stdout })[Symbol.asyncIterator]();
  const next = async () => {
    const line = await lines.next();
    assert(!line.done, 'probe closed unexpectedly');
    return line.value;
  };
  const command = text => probe.stdin.write(text + '\n');
  const header = (type, size, session = 0, sequence = 0) => {
    const header = Buffer.alloc(18);
    header.write('HWLK'); header[4] = 2; header[5] = type;
    header.writeUInt32LE(session, 8); header.writeUInt32LE(sequence, 12);
    header.writeUInt16LE(size, 16);
    return header;
  };
  const frame = payload => Buffer.concat([header(1, payload.length), payload]).toString('hex');
  const { privateKey } = generateKeyPairSync('ed25519');
  try {
    const identity = (await next()).split(' ')[1];
    command('OFFER');
    const oldOffer = Buffer.from((await next()).slice(6), 'hex');
    const oldPairing = new PairingEnrollment(oldOffer, privateKey);
    command('REJECT'); assert.equal(await next(), 'PAIR rejected');
    command('SCAN ' + oldPairing.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN refused');
    command('OFFER');
    const expiringOffer = Buffer.from((await next()).slice(6), 'hex');
    assert(!oldOffer.equals(expiringOffer));
    const expiringPairing = new PairingEnrollment(expiringOffer, privateKey);
    command('SCAN ' + oldPairing.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN refused');
    command('SCAN ' + expiringPairing.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN ok');
    command('TICK'); assert.equal(await next(), 'PENDING 0');
    command('SCAN ' + expiringPairing.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN refused');
    command('APPROVE'); assert.equal(await next(), 'PAIR none');
    command('OFFER');
    const offer = Buffer.from((await next()).slice(6), 'hex');
    assert(!offer.equals(expiringOffer));
    const pairing = new PairingEnrollment(offer, privateKey);
    assert.equal(pairing.deviceIdentity, identity);
    for (let i = 0; i < offer.length; ++i) {
      const corrupt = Buffer.from(offer); corrupt[i] ^= 1;
      assert.throws(() => new PairingEnrollment(corrupt, privateKey));
    }
    command('FRAME ' + frame(pairing.pairRequest(privateKey)));
    assert.equal(await next(), 'STATUS rejected');
    command('APPROVE'); assert.equal(await next(), 'PAIR none');
    const bad = pairing.replyQrBytes; bad[100] ^= 1;
    command('SCAN ' + bad.toString('hex')); assert.equal(await next(), 'SCAN refused');
    command('SCAN ' + pairing.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN ok');
    const samePhoneNewNonce = new PairingEnrollment(offer, privateKey);
    command('SCAN ' + samePhoneNewNonce.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN refused');
    command('FRAME ' + frame(samePhoneNewNonce.pairRequest(privateKey))); assert.equal(await next(), 'STATUS rejected');
    command('FRAME ' + frame(expiringPairing.pairRequest(privateKey)));
    assert.equal(await next(), 'STATUS rejected');
    const other = new PairingEnrollment(offer, generateKeyPairSync('ed25519').privateKey);
    command('SCAN ' + other.replyQrBytes.toString('hex')); assert.equal(await next(), 'SCAN refused');
    command('FRAME ' + frame(pairing.pairRequest(privateKey)));
    assert.equal(await next(), `CODE ${pairing.comparisonCode} ${pairing.phoneIdentity}`);
    assert.equal(await next(), 'STATUS pending-pairing');
    command('APPROVE'); assert.equal(await next(), 'PAIR ok');
    command('FRAME ' + frame(pairing.pairRequest(privateKey)));
    const response = await next();
    assert(response.startsWith('RESP '), response);
    const payload = Buffer.from(response.slice(5), 'hex').subarray(18);
    assert(pairing.verifyPairResponse(payload));
    for (let i = 0; i < payload.length; ++i) {
      const corrupt = Buffer.from(payload); corrupt[i] ^= 1;
      assert(!pairing.verifyPairResponse(corrupt));
    }
    assert(!other.verifyPairResponse(payload));
    command('OFFER'); assert.equal(await next(), 'OFFER refused');
    console.log('Mutual QR enrollment: Node Ed25519/SHA256 vs native firmware; tampering, key replacement, scan gate, expiry, fresh challenges, old reply/request replay and response pinning passed');

    const rawKey = key => createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(-32);
    const fromRaw = (prefix, raw) => createPublicKey({ key: Buffer.concat([Buffer.from(prefix, 'hex'), raw]), format: 'der', type: 'spki' });
    const domain = (label, data) => Buffer.concat([Buffer.from(label), data]);
    const ephemeral = generateKeyPairSync('x25519');
    const helloFields = Buffer.concat([rawKey(privateKey), rawKey(ephemeral.privateKey), randomBytes(32)]);
    const hello = Buffer.concat([helloFields, sign(null, domain('HWLK1-HELLO', helloFields), privateKey)]);
    command('FRAME ' + Buffer.concat([header(3, hello.length), hello]).toString('hex'));
    const helloLine = await next(); assert(helloLine.startsWith('RESP '), helloLine);
    const helloResponse = Buffer.from(helloLine.slice(5), 'hex');
    assert.deepEqual(helloResponse.subarray(0, 18), header(4, 160));
    const helloPayload = helloResponse.subarray(18);
    assert.equal(helloPayload.subarray(0, 32).toString('hex'), pairing.deviceIdentity);
    const transcript = Buffer.concat([helloFields, helloPayload.subarray(0, 96)]);
    assert(verify(null, domain('HWLK1-RESP', transcript), fromRaw('302a300506032b6570032100', helloPayload.subarray(0, 32)), helloPayload.subarray(96)));
    const transcriptHash = createHash('sha256').update(domain('HWLK1-SESSION', transcript)).digest();
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: fromRaw('302a300506032b656e032100', helloPayload.subarray(32, 64)) });
    const keys = Buffer.from(hkdfSync('sha256', shared, transcriptHash, Buffer.from('HWLK1-KEYS'), 64));
    const session = transcriptHash.readUInt32LE(0);
    const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
    const nonce = (direction, sequence) => {
      const n = Buffer.alloc(12); n.writeUInt32LE(session); n[4] = direction; n.writeUInt32LE(sequence, 5); return n;
    };
    const crypt = (key, n, bytes) => {
      const cipher = createCipheriv('chacha20', hmac(key, Buffer.from('HexWallet Link encryption')), Buffer.concat([Buffer.alloc(4), n]));
      return Buffer.concat([cipher.update(bytes), cipher.final()]);
    };
    const tag = (key, h, n, ciphertext) => hmac(hmac(key, Buffer.from('HexWallet Link authentication')), Buffer.concat([h, n, ciphertext]));
    const seal = (bytes, sequence) => {
      const h = header(0x10, bytes.length, session, sequence), n = nonce(2, sequence);
      const ciphertext = crypt(keys.subarray(0, 32), n, bytes);
      return Buffer.concat([h, ciphertext, tag(keys.subarray(0, 32), h, n, ciphertext)]);
    };
    let sequence = 0;
    for (const size of [1, 4608, 4609, 16384]) {
      const plaintext = Buffer.from(Array.from({ length: size }, (_, i) => i & 255));
      const request = seal(plaintext, sequence);
      command('FRAME ' + request.toString('hex'));
      const line = await next();
      assert(line.startsWith('RESP '), `size=${size}: ${line}`);
      const reply = Buffer.from(line.slice(5), 'hex');
      assert.equal(reply.length, 18 + size + 32);
      const h = reply.subarray(0, 18), ciphertext = reply.subarray(18, -32), n = nonce(1, sequence);
      assert.deepEqual(h, header(0x11, size, session, sequence));
      assert.deepEqual(reply.subarray(-32), tag(keys.subarray(32), h, n, ciphertext));
      assert.deepEqual(crypt(keys.subarray(32), n, ciphertext), plaintext.map(byte => byte ^ 0xa5));
      command('FRAME ' + request.toString('hex')); assert.equal(await next(), 'STATUS replay');
      ++sequence;
    }
    command('FRAME ' + seal(Buffer.alloc(16385), sequence).toString('hex'));
    assert.equal(await next(), 'STATUS invalid-argument');
    const corrupt = seal(Buffer.alloc(16384, 0x39), sequence);
    corrupt[18 + 16383] ^= 1;
    command('FRAME ' + corrupt.toString('hex')); assert.equal(await next(), 'STATUS authentication-failed');
    command('SESSION'); assert.equal(await next(), 'SESSION active=0 id=00000000');
    console.log('Encrypted link: Node X25519/HKDF/ChaCha20/HMAC vs native firmware; 1/4608/4609/16384-byte round trips, full response authentication, replay, oversized frame and final-byte tampering passed');
  } finally {
    command('QUIT'); probe.stdin.end();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
