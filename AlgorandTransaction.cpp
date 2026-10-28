#include "AlgorandTransaction.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletAltAddresses.h"
#include <stdio.h>
#include <string.h>

#include "src/generated/AlgorandVectorsTest.inc"

namespace hexwallet {
namespace {
// https://dev.algorand.co/concepts/protocol/networks/ (mainnet-v1.0)
constexpr uint8_t kGenesisHash[32] = {
  0xc0,0x61,0xc4,0xd8,0xfc,0x1d,0xbd,0xde,0xd2,0xd7,0x60,0x4b,0xe4,0x56,0x8e,0x3f,
  0x6d,0x04,0x19,0x87,0xac,0x37,0xbd,0xe4,0xb6,0x20,0xb5,0xab,0x39,0x24,0x8a,0xdf};

// Only the scalar types used by admitted transaction fields. This is not a
// permissive object decoder: unknown tags, long forms and aliases fail closed.
class MsgpackReader {
 public:
  MsgpackReader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  uint8_t byte() {
    if (offset_ == size_) { ok_ = false; return 0; }
    return data_[offset_++];
  }
  uint64_t be(size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) value = (value << 8) | byte();
    return value;
  }
  bool bytes(void *out, size_t count) {
    if (count > size_ - offset_) { ok_ = false; return false; }
    memcpy(out, data_ + offset_, count); offset_ += count; return ok_;
  }
  bool string(char *out, size_t capacity) {
    const uint8_t tag = byte();
    if ((tag & 0xe0) != 0xa0) return false; // admitted strings <= 31 bytes
    const size_t length = tag & 31;
    if (!length || length >= capacity || !bytes(out, length)) return false;
    for (size_t i = 0; i < length; ++i) if (!out[i]) return false;
    out[length] = 0; return true;
  }
  bool binary(uint8_t *out, size_t capacity, size_t *length) {
    const uint8_t tag = byte();
    if (tag != 0xc4 && tag != 0xc5) return false;
    const size_t count = static_cast<size_t>(be(tag == 0xc4 ? 1 : 2));
    if (!count || (tag == 0xc5 && count <= 255) || count > capacity) return false;
    *length = count; return bytes(out, count);
  }
  bool fixed(uint8_t *out, size_t width) {
    size_t count = 0;
    return binary(out, width, &count) && count == width;
  }
  bool integer(uint64_t *out) {
    const uint8_t tag = byte();
    if (tag <= 127) *out = tag;
    else {
      size_t width = 0;
      switch (tag) {
        case 0xcc: width = 1; break;
        case 0xcd: width = 2; break;
        case 0xce: width = 4; break;
        case 0xcf: width = 8; break;
        default: return false;
      }
      *out = be(width);
      const uint64_t minimum = width == 1 ? 128 : width == 2 ? 256 : width == 4 ? 65536 : 0x100000000ULL;
      if (*out < minimum) return false;
    }
    // Algorand canonical maps omit zero-valued numeric fields.
    return ok_ && *out != 0;
  }
  bool done() const { return ok_ && offset_ == size_; }
 private:
  const uint8_t *data_; size_t size_; size_t offset_ = 0; bool ok_ = true;
};
void hex(const uint8_t *bytes, size_t count, char *out) {
  constexpr char alphabet[] = "0123456789abcdef";
  for (size_t i = 0; i < count; ++i) {
    out[2*i] = alphabet[bytes[i] >> 4]; out[2*i+1] = alphabet[bytes[i] & 15];
  }
  out[2*count] = 0;
}
bool nonzero(const uint8_t *data, size_t count) {
  uint8_t value = 0;
  for (size_t i = 0; i < count; ++i) value |= data[i];
  return value != 0;
}
AlgorandError parse(const uint8_t *data, size_t size, const uint8_t owner[32], AlgorandTransaction *out) {
  MsgpackReader r(data, size);
  const uint8_t map = r.byte();
  if ((map & 0xf0) != 0x80 || (map & 15) == 0) return AlgorandError::Malformed;
  char previous[8] = {}, key[8], type[6] = {}, genesis_id[16] = {};
  uint8_t sender[32] = {}, recipient[32] = {}, genesis[32] = {};
  // bit assignments are per field, not wire tags. Sorted keys also exclude duplicates.
  enum : uint32_t { Amount=1, AssetAmount=2, AssetReceiver=4, Fee=8, First=16,
    Genesis=32, Last=64, Receiver=128, Sender=256, Type=512, Asset=1024 };
  uint32_t seen = 0;
  AlgorandReview &v = out->review;
  for (unsigned i = 0; i < (map & 15); ++i) {
    if (!r.string(key, sizeof(key)) || strcmp(previous, key) >= 0) return AlgorandError::Malformed;
    strcpy(previous, key);
    bool ok = false;
    if (!strcmp(key,"aamt")) { ok = r.integer(&v.amount); seen |= AssetAmount; }
    else if (!strcmp(key,"amt")) { ok = r.integer(&v.amount); seen |= Amount; }
    else if (!strcmp(key,"arcv")) { ok = r.fixed(recipient,32); seen |= AssetReceiver; }
    else if (!strcmp(key,"fee")) { ok = r.integer(&v.fee); seen |= Fee; }
    else if (!strcmp(key,"fv")) { ok = r.integer(&v.first_valid); seen |= First; }
    else if (!strcmp(key,"gen")) {
      if (!r.string(genesis_id,sizeof(genesis_id))) return AlgorandError::Malformed;
      if (strcmp(genesis_id,"mainnet-v1.0")) return AlgorandError::WrongNetwork;
      ok = true;
    }
    else if (!strcmp(key,"gh")) { ok = r.fixed(genesis,32); seen |= Genesis; }
    else if (!strcmp(key,"lv")) { ok = r.integer(&v.last_valid); seen |= Last; }
    else if (!strcmp(key,"lx")) {
      uint8_t lease[32]; ok = r.fixed(lease,32) && nonzero(lease,32);
      if (ok) hex(lease,32,v.lease_hex);
    }
    else if (!strcmp(key,"note")) {
      uint8_t note[kAlgorandMaxNote]; size_t count = 0;
      ok = r.binary(note,sizeof(note),&count);
      if (ok) hex(note,count,v.note_hex);
    }
    else if (!strcmp(key,"rcv")) { ok = r.fixed(recipient,32); seen |= Receiver; }
    else if (!strcmp(key,"snd")) { ok = r.fixed(sender,32); seen |= Sender; }
    else if (!strcmp(key,"type")) { ok = r.string(type,sizeof(type)); seen |= Type; }
    else if (!strcmp(key,"xaid")) { ok = r.integer(&v.asset_id); seen |= Asset; }
    else return AlgorandError::Unsupported; // includes grp, rekey, close, aclose, asnd
    if (!ok) return AlgorandError::Malformed;
  }
  constexpr uint32_t required = Fee | First | Genesis | Last | Sender | Type;
  if (!r.done() || (seen & required) != required || !nonzero(recipient,32)) return AlgorandError::Malformed;
  if (memcmp(genesis,kGenesisHash,32)) return AlgorandError::WrongNetwork;
  if (memcmp(sender,owner,32)) return AlgorandError::WrongWallet;
  if (v.last_valid < v.first_valid || v.last_valid - v.first_valid > 1000) return AlgorandError::Malformed;
  if (v.fee < 1000 || v.fee > 1000000) return AlgorandError::FeePolicy;
  if (!strcmp(type,"pay")) {
    if ((seen & (Amount | Receiver)) != (Amount | Receiver) ||
        (seen & (AssetAmount | AssetReceiver | Asset))) return AlgorandError::Malformed;
    v.kind = AlgorandKind::Payment;
    snprintf(v.amount_text,sizeof(v.amount_text),"%llu.%06llu ALGO",
        static_cast<unsigned long long>(v.amount/1000000),static_cast<unsigned long long>(v.amount%1000000));
  } else if (!strcmp(type,"axfer")) {
    if ((seen & (AssetReceiver | Asset)) != (AssetReceiver | Asset) || (seen & (Amount | Receiver)))
      return AlgorandError::Malformed;
    if (v.amount == 0 && memcmp(sender,recipient,32)) return AlgorandError::InvalidAmount;
    v.kind = v.amount == 0 ? AlgorandKind::AssetOptIn : AlgorandKind::AssetTransfer;
    snprintf(v.amount_text,sizeof(v.amount_text),"%llu RAW UNITS",static_cast<unsigned long long>(v.amount));
  } else return AlgorandError::Unsupported;
  if (address_algorand(sender,v.sender,sizeof(v.sender)) != WalletError::Ok ||
      address_algorand(recipient,v.recipient,sizeof(v.recipient)) != WalletError::Ok) return AlgorandError::CryptoFailure;
  uint8_t sign_bytes[kAlgorandMaxTransaction + 2] = {'T','X'};
  memcpy(sign_bytes+2,data,size);
  if (!crypto_sha512_256(sign_bytes,size+2,out->transaction_id)) return AlgorandError::CryptoFailure;
  memcpy(out->transaction,data,size); out->transaction_size = static_cast<uint16_t>(size);
  return AlgorandError::Ok;
}
bool same_review(const AlgorandReview &a, const AlgorandReview &b) {
  return a.kind == b.kind && a.amount == b.amount && a.asset_id == b.asset_id && a.fee == b.fee &&
      a.first_valid == b.first_valid && a.last_valid == b.last_valid &&
      !memcmp(a.sender,b.sender,sizeof(a.sender)) && !memcmp(a.recipient,b.recipient,sizeof(a.recipient)) &&
      !memcmp(a.amount_text,b.amount_text,sizeof(a.amount_text)) &&
      !memcmp(a.note_hex,b.note_hex,sizeof(a.note_hex)) && !memcmp(a.lease_hex,b.lease_hex,sizeof(a.lease_hex));
}
}
bool algorand_derivation_path(uint32_t account, uint32_t change, uint32_t index, uint32_t out[5]) {
  constexpr uint32_t h = 0x80000000UL;
  if (!out || account >= h || change >= h || index >= h) return false;
  out[0]=h|44; out[1]=h|283; out[2]=h|account; out[3]=h|change; out[4]=h|index;
  return true;
}
bool algorand_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]) {
  uint32_t path[5];
  if (!out) return false;
  if (seed && algorand_derivation_path(0,0,index,path) && slip10_ed25519_derive(seed,kSeedSize,path,5,out)) return true;
  secure_zero(out,32); return false;
}
AlgorandError algorand_review_transaction(const uint8_t *data, size_t size,
    const uint8_t owner[32], AlgorandTransaction *out) {
  if (!out) return AlgorandError::InvalidArgument;
  memset(out,0,sizeof(*out));
  if (!data || !owner || size == 0 || size > kAlgorandMaxTransaction) return AlgorandError::InvalidArgument;
  const AlgorandError error = parse(data,size,owner,out);
  if (error != AlgorandError::Ok) secure_zero(out,sizeof(*out));
  return error;
}
AlgorandError algorand_sign_transaction(const AlgorandTransaction &tx,
    const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size) {
  if (!in_out_size) return AlgorandError::InvalidArgument;
  const size_t capacity = *in_out_size; *in_out_size = 0;
  if (!seed || !out) return AlgorandError::InvalidArgument;
  uint8_t child[32] = {}, owner[32] = {}, signature[64] = {};
  uint8_t message[kAlgorandMaxTransaction+2] = {'T','X'};
  AlgorandTransaction verified = {};
  AlgorandError error = AlgorandError::CryptoFailure;
  if (algorand_derive_key(seed,tx.address_index,child) && ed25519_public_key(child,owner)) {
    error = algorand_review_transaction(tx.transaction,tx.transaction_size,owner,&verified);
    if (error == AlgorandError::Ok && (!same_review(tx.review,verified.review) ||
        memcmp(tx.transaction_id,verified.transaction_id,32))) error = AlgorandError::Malformed;
    if (error == AlgorandError::Ok) {
      if (capacity < verified.transaction_size + 75U) error = AlgorandError::BufferTooSmall;
      else {
        memcpy(message+2,verified.transaction,verified.transaction_size);
        if (!ed25519_sign(child,message,verified.transaction_size+2,signature) ||
            !ed25519_verify(owner,message,verified.transaction_size+2,signature)) error = AlgorandError::CryptoFailure;
        else {
          const uint8_t head[] = {0x82,0xa3,'s','i','g',0xc4,64};
          const uint8_t tail[] = {0xa3,'t','x','n'};
          memcpy(out,head,sizeof(head)); memcpy(out+7,signature,64);
          memcpy(out+71,tail,sizeof(tail)); memcpy(out+75,verified.transaction,verified.transaction_size);
          *in_out_size = verified.transaction_size+75;
        }
      }
    }
  }
  secure_zero(child,sizeof(child)); secure_zero(signature,sizeof(signature)); secure_zero(&verified,sizeof(verified));
  return error;
}
// Complete SDK known-answer vectors are compiled into the startup test below.
bool run_algorand_self_tests() {
  uint8_t child[32] = {}, owner[32] = {};
  bool ok = algorand_derive_key(kAlgorandTestSeed, 0, child) &&
      ed25519_public_key(child, owner);
  secure_zero(child, sizeof(child));
  AlgorandTransaction tx = {};
  ok = ok && algorand_review_transaction(kAlgorandTestRequest,
      sizeof(kAlgorandTestRequest), owner, &tx) == AlgorandError::Ok &&
      !memcmp(tx.transaction_id, kAlgorandTestTxid, sizeof(kAlgorandTestTxid)) &&
      !strcmp(tx.review.sender, kAlgorandTestSender);
  uint8_t signed_transaction[kAlgorandMaxSigned] = {};
  size_t signed_size = sizeof(signed_transaction);
  ok = ok && algorand_sign_transaction(tx, kAlgorandTestSeed, signed_transaction,
      &signed_size) == AlgorandError::Ok &&
      signed_size == sizeof(kAlgorandTestSigned) &&
      !memcmp(signed_transaction, kAlgorandTestSigned, signed_size);
  // A different owner must not review this transaction, even if signing keys
  // exist for it elsewhere in the wallet.
  uint8_t wrong_owner[32] = {};
  memcpy(wrong_owner, owner, sizeof(wrong_owner));
  wrong_owner[0] ^= 1;
  AlgorandTransaction rejected = {};
  ok = ok && algorand_review_transaction(kAlgorandTestRequest,
      sizeof(kAlgorandTestRequest), wrong_owner, &rejected) == AlgorandError::WrongWallet;
  secure_zero(&tx, sizeof(tx));
  secure_zero(&rejected, sizeof(rejected));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  secure_zero(owner, sizeof(owner));
  secure_zero(wrong_owner, sizeof(wrong_owner));
  return ok;
}
}
