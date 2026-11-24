'use strict';

// Enrollment records are binary QR payloads. Only pass bytes obtained from a
// local camera scan of the wallet; a downloaded image is not an authenticated
// physical channel. The wallet identity is pinned for the subsequent link.
const { createHash, createPublicKey, randomBytes, sign, verify, timingSafeEqual } = require('node:crypto');
const HEADER_OFFER = Buffer.from([0x48, 0x57, 0x51, 0x50, 1, 1, 0, 0]);
const HEADER_REPLY = Buffer.from([0x48, 0x57, 0x51, 0x50, 1, 2, 0, 0]);
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const hash = data => createHash('sha256').update(data).digest();
const domain = (label, bytes) => Buffer.concat([Buffer.from(label, 'ascii'), bytes]);
const same = (a, b) => a.length === b.length && timingSafeEqual(a, b);
const publicKey = raw => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' });

class PairingEnrollment {
  #device; #phone; #nonce; #reply; #code;
  constructor(scannedOffer, phonePrivateKey) {
    const offer = Buffer.from(scannedOffer);
    if (offer.length !== 136 || !same(offer.subarray(0, 8), HEADER_OFFER))
      throw new Error('Invalid wallet enrollment record');
    this.#device = Buffer.from(offer.subarray(8, 40));
    if (!verify(null, domain('HWPAIR1-OFFER', offer.subarray(0, 72)), publicKey(this.#device), offer.subarray(72)))
      throw new Error('Invalid wallet enrollment signature');
    if (phonePrivateKey.type !== 'private' || phonePrivateKey.asymmetricKeyType !== 'ed25519')
      throw new Error('An Ed25519 phone identity is required');
    this.#phone = createPublicKey(phonePrivateKey).export({ type: 'spki', format: 'der' }).subarray(-32);
    this.#nonce = randomBytes(32);
    const offerHash = hash(offer);
    const fields = Buffer.concat([HEADER_REPLY, offerHash, this.#phone, this.#nonce]);
    this.#reply = Buffer.concat([fields, sign(null, domain('HWPAIR1-REPLY', fields), phonePrivateKey)]);
    const digest = hash(domain('HWPAIR1-CODE', Buffer.concat([this.#phone, offerHash, this.#nonce])));
    this.#code = String(digest.readUIntBE(0, 3) % 1000000).padStart(6, '0');
  }

  get replyQrBytes() { return Buffer.from(this.#reply); }
  get deviceIdentity() { return this.#device.toString('hex'); }
  get phoneIdentity() { return this.#phone.toString('hex'); }
  get comparisonCode() { return this.#code; }

  pairRequest(phonePrivateKey) {
    const key = createPublicKey(phonePrivateKey).export({ type: 'spki', format: 'der' }).subarray(-32);
    if (!same(key, this.#phone)) throw new Error('Phone identity changed during enrollment');
    const fields = Buffer.concat([this.#phone, this.#nonce]);
    return Buffer.concat([fields, sign(null, domain('HWLK1-PAIR', fields), phonePrivateKey)]);
  }

  verifyPairResponse(payload) {
    const bytes = Buffer.from(payload);
    if (bytes.length !== 160 || !same(bytes.subarray(0, 32), this.#device) ||
        !same(bytes.subarray(32, 64), this.#nonce)) return false;
    const fields = Buffer.concat([this.#phone, bytes.subarray(0, 96)]);
    return verify(null, domain('HWLK1-PAIR-RESP', fields), publicKey(this.#device), bytes.subarray(96));
  }
}

module.exports = { PairingEnrollment };
