'use strict';
// Every key here is a published vector or a deterministic public fixture.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { scryptSync, pbkdf2Sync, createCipheriv, createHash, createECDH } = require('node:crypto');
const bs58 = require('bs58');
const probe = process.argv[2];
if (!probe) throw Error('Usage: node key_backup_check.cjs <chain_probe>');
const bytes = text => Buffer.from(text, 'utf8');
const sha = data => createHash('sha256').update(data).digest();
const hash256 = data => sha(sha(data));
const checked = data => bs58.encode(Buffer.concat([data, hash256(data).subarray(0, 4)]));
const scalar = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
function run(operation, input, pass = '', network = 'main', extra = '') {
  const result = spawnSync(probe, ['key-backup', operation, input,
    (Buffer.isBuffer(pass) ? pass : bytes(pass)).toString('hex'), network, extra],
    { encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return Object.fromEntries(result.stdout.trim().split(/\r?\n/).map(line => {
    const pos = line.indexOf('='); return [line.slice(0, pos), line.slice(pos + 1)];
  }));
}
function failed(result, error) {
  assert.equal(result.error, String(error));
  assert.equal(result.key, '00'.repeat(32), 'failure exposed partial key material');
}
// BIP-0038 specification vectors: 0x0142, 0x0143, compression, lot/sequence,
// Greek and the embedded-NUL / supplementary-plane Unicode example.
const vectors = [
  ['TestingOneTwoThree', '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg', '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'],
  ['Satoshi', '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq', '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5'],
  ['\u03d2\u0301\0\u{10400}\u{1f4a9}', '6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn', '5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4'],
  ['TestingOneTwoThree', '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo', 'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP'],
  ['Satoshi', '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7', 'KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7'],
  ['TestingOneTwoThree', '6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX', '5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2'],
  ['Satoshi', '6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd', '5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH'],
  ['MOLON LABE', '6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j', '5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8'],
  ['ΜΟΛΩΝ ΛΑΒΕ', '6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH', '5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D'],
];
for (const [i, [pass, encrypted, wif]] of vectors.entries()) {
  const result = run('decrypt', encrypted, pass);
  assert.equal(result.error, '0', `vector ${i}`);
  assert.equal(result.wif, wif);
  if (i < 5) assert.equal(run('encrypt', wif, pass).encrypted, encrypted);
}
const words = 'abandon '.repeat(11) + 'about';
const { wordlists, Mnemonic } = require('ethers');
for (const [name, list] of [['en', wordlists.en], ['zh-hans', wordlists.zh_cn], ['zh-hant', wordlists.zh_tw]]) {
  for (const size of [16, 20, 24, 28, 32]) {
    const entropy = sha(bytes('Public BIP39 size ' + size)).subarray(0, size);
    const expected = Mnemonic.fromEntropy(entropy, 'TREZOR', list);
    const result = run('mnemonic', name, entropy);
    assert.equal(result.error, '0');
    assert.equal(result.words, bytes(expected.phrase).toString('hex'));
    assert.equal(result.seed, expected.computeSeed().slice(2));
  }
}
const unicode = ['TREZOR', '', ' ', 'é', 'e\u0301', 'a\0中', '中文密码', '㍍ガバヴァぱばぐゞちぢ十人十色', 'ＡＢＣ', '각', 'a'.repeat(128)];
for (const pass of unicode) {
  const seed = pbkdf2Sync(bytes(words), bytes('mnemonic' + pass.normalize('NFKD')), 2048, 64, 'sha512').toString('hex');
  assert.equal(run('seed', words, pass).seed, seed);
  for (const form of ['NFKD', 'NFC']) assert.equal(run('normalize', form.toLowerCase(), pass).normalized, bytes(pass.normalize(form)).toString('hex'));
}
assert.equal(run('seed', words + ' ', '').error, '2');
assert.equal(run('seed', words, 'x'.repeat(129)).error, '1');
for (const invalid of ['c0af', 'eda080', 'f4908080', 'f0808080', 'c3']) {
  const r = run('seed', words, Buffer.from(invalid, 'hex'));
  assert.equal(r.error, '3'); assert.equal(r.seed, '00'.repeat(64));
}
// Independent Node/OpenSSL scrypt, AES and secp256k1 for both Bitcoin networks.
function addressHash(key, compressed, network) {
  const ec = createECDH('secp256k1'); ec.setPrivateKey(key);
  const hash = createHash('ripemd160').update(sha(ec.getPublicKey(null, compressed ? 'compressed' : 'uncompressed'))).digest();
  return hash256(bytes(checked(Buffer.concat([Buffer.from([network === 'main' ? 0 : 111]), hash])))).subarray(0, 4);
}
const xor = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]));
function aes(key, data) {
  const cipher = createCipheriv('aes-256-ecb', key, null); cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
for (const network of ['main', 'test']) for (const compressed of [false, true]) {
  const key = scalar(123456789n), pass = '恢复é\u0301';
  const wif = checked(Buffer.concat([Buffer.from([network === 'main' ? 128 : 239]), key, compressed ? Buffer.from([1]) : Buffer.alloc(0)]));
  const salt = addressHash(key, compressed, network);
  const derived = scryptSync(bytes(pass.normalize('NFC')), salt, 64, { N:16384, r:8, p:8, maxmem:64*1024*1024 });
  const encrypted = checked(Buffer.concat([Buffer.from([1, 0x42, compressed ? 0xe0 : 0xc0]), salt, aes(derived.subarray(32), xor(key, derived))]));
  assert.equal(run('encrypt', wif, pass, network).encrypted, encrypted);
  assert.equal(run('decrypt', encrypted, pass, network).wif, wif);
  failed(run('parse', wif, '', network === 'main' ? 'test' : 'main'), 16);
}
// Independently create EC-multiplied fixtures, including compressed keys that
// the specification's published EC vectors do not cover.
const order = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
for (const lot of [false, true]) for (const compressed of [false, true]) {
  const pass = '中文 EC', entropy = Buffer.from('0102030405060708', 'hex');
  const prefactor = scryptSync(bytes(pass), entropy.subarray(0, lot ? 4 : 8), 32, { N:16384, r:8, p:8, maxmem:64*1024*1024 });
  const passfactor = lot ? hash256(Buffer.concat([prefactor, entropy])) : prefactor;
  const ec = createECDH('secp256k1'); ec.setPrivateKey(passfactor);
  const seed = Buffer.from('112233445566778899aabbccddeeff001122334455667788', 'hex');
  const key = scalar(BigInt('0x' + passfactor.toString('hex')) * BigInt('0x' + hash256(seed).toString('hex')) % order);
  const salt = addressHash(key, compressed, 'main');
  const derived = scryptSync(ec.getPublicKey(null, 'compressed'), Buffer.concat([salt, entropy]), 64, { N:1024, r:1, p:1 });
  const part1 = aes(derived.subarray(32), xor(seed.subarray(0, 16), derived));
  const part2 = aes(derived.subarray(32), xor(Buffer.concat([part1.subarray(8), seed.subarray(16)]), derived.subarray(16)));
  const encrypted = checked(Buffer.concat([Buffer.from([1, 0x43, (compressed ? 32 : 0) | (lot ? 4 : 0)]), salt, entropy, part1.subarray(0, 8), part2]));
  const result = run('decrypt', encrypted, pass);
  assert.equal(result.key, key.toString('hex'));
  assert.equal(result.compressed, compressed ? '1' : '0');
}
const [pass, encrypted] = vectors[0];
assert.equal(run('worker-encrypt', vectors[0][2], pass).encrypted, encrypted);
assert.equal(run('worker-decrypt', encrypted, pass).address, '1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB');
failed(run('worker-decrypt', encrypted, pass, 'main', 'cancel'), 11);
for (const [operation, input] of [['worker-decrypt', encrypted], ['worker-encrypt', vectors[0][2]]]) {
  failed(run(operation, input, pass, 'main', 'oom'), 13);
  failed(run(operation, input, pass, 'main', 'cancel-running'), 11);
  failed(run(operation, input, pass, 'main', 'cancel-finished'), 11);
}
failed(run('decrypt', encrypted, 'incorrect'), 15);
failed(run('decrypt', encrypted, pass, 'test'), 15);
failed(run('decrypt', encrypted, pass, 'main', 'cancel'), 11);
failed(run('decrypt', encrypted.slice(0, -1) + '1', pass), 14);
failed(run('parse', '00'.repeat(32)), 7);
failed(run('parse', 'ff'.repeat(32)), 7);
failed(run('parse', 'bitcoin:' + vectors[0][2]), 17);
const malformed = bs58.decode(encrypted).subarray(0, -4); malformed[2] |= 1;
failed(run('decrypt', checked(malformed), pass), 17);
console.log('key-backup=pass: 9 published BIP38 vectors; independent Node encryption, EC/compression/lot/network cases; WIF/hex; NFC/NFKD, Chinese, embedded NUL; rejection and output erasure');
