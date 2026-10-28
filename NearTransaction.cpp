#include "NearTransaction.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "base58.h"
#include <stdio.h>
#include <string.h>

#include "src/generated/NearVectorsTest.inc"

namespace hexwallet {
namespace {
class BorshReader {
 public:
  BorshReader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  bool bytes(void *out, size_t count) {
    if (count > size_ - offset_) { ok_ = false; return false; }
    memcpy(out,data_+offset_,count); offset_ += count; return true;
  }
  uint64_t little(size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
      uint8_t byte = 0; bytes(&byte,1); value |= uint64_t(byte) << (8*i);
    }
    return value;
  }
  bool account(char out[65]) {
    const uint64_t length = little(4);
    if (length < 2 || length > 64 || !bytes(out,static_cast<size_t>(length))) return false;
    bool previous_separator = true;
    for (size_t i = 0; i < length; ++i) {
      const char c = out[i];
      const bool separator = c == '.' || c == '-' || c == '_';
      if (separator) { if (previous_separator) return false; }
      else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
      previous_separator = separator;
    }
    if (previous_separator) return false;
    out[length] = 0; return true;
  }
  bool done() const { return ok_ && offset_ == size_; }
 private:
  const uint8_t *data_; size_t size_; size_t offset_ = 0; bool ok_ = true;
};
bool nonzero(const uint8_t *data, size_t size) {
  uint8_t value = 0;
  for (size_t i=0;i<size;++i) value |= data[i];
  return value != 0;
}
bool add_amount(uint8_t sum[16], const uint8_t amount[16]) {
  uint16_t carry = 0;
  for (size_t i=0;i<16;++i) {
    carry += uint16_t(sum[i]) + amount[i];
    sum[i] = static_cast<uint8_t>(carry); carry >>= 8;
  }
  return carry == 0;
}
bool implicit_id(const char *id) {
  if (strlen(id) != 64) return false;
  for (size_t i=0;i<64;++i) if (!((id[i]>='0' && id[i]<='9') || (id[i]>='a' && id[i]<='f'))) return false;
  return true;
}
NearError parse(const uint8_t *data, size_t size, const uint8_t owner[32], NearTransaction *out) {
  BorshReader r(data,size);
  NearReview &v = out->review;
  uint8_t public_key[32], block_hash[32];
  if (!r.account(v.signer)) return NearError::Malformed;
  if (r.little(1) != 0) return NearError::Unsupported; // Ed25519 key enum
  if (!r.bytes(public_key,32)) return NearError::Malformed;
  if (memcmp(public_key,owner,32)) return NearError::WrongWallet;
  // Unlike named accounts, an Ed25519 implicit account binds its identity to
  // the key locally. Never display a foreign implicit signer as wallet-owned.
  if (implicit_id(v.signer)) {
    char own[65];
    if (!near_implicit_address(owner,own,sizeof(own)) || strcmp(own,v.signer)) return NearError::WrongWallet;
  }
  v.nonce = r.little(8);
  if (!v.nonce || !r.account(v.receiver) || !r.bytes(block_hash,32) || !nonzero(block_hash,32))
    return NearError::Malformed;
  v.action_count = static_cast<uint32_t>(r.little(4));
  if (!v.action_count || v.action_count > kNearMaxActions) return NearError::Unsupported;
  for (size_t i=0;i<v.action_count;++i) {
    if (r.little(1) != 3) return NearError::Unsupported; // Action::Transfer
    if (!r.bytes(v.amounts[i],16)) return NearError::Malformed;
    if (!nonzero(v.amounts[i],16) || !add_amount(v.total,v.amounts[i])) return NearError::InvalidAmount;
  }
  if (!r.done()) return NearError::Malformed;
  strcpy(v.public_key,"ed25519:");
  size_t key_size = sizeof(v.public_key)-8, hash_size = sizeof(v.block_hash);
  if (!b58enc(v.public_key+8,&key_size,public_key,32) || !b58enc(v.block_hash,&hash_size,block_hash,32) ||
      !near_format_amount(v.total,v.total_text,sizeof(v.total_text)) ||
      !crypto_sha256(data,size,out->signing_hash)) return NearError::CryptoFailure;
  memcpy(out->transaction,data,size); out->transaction_size = static_cast<uint16_t>(size);
  return NearError::Ok;
}
bool same_review(const NearReview &a, const NearReview &b) {
  return a.nonce==b.nonce && a.action_count==b.action_count &&
      !memcmp(a.signer,b.signer,sizeof(a.signer)) && !memcmp(a.receiver,b.receiver,sizeof(a.receiver)) &&
      !memcmp(a.public_key,b.public_key,sizeof(a.public_key)) && !memcmp(a.block_hash,b.block_hash,sizeof(a.block_hash)) &&
      !memcmp(a.amounts,b.amounts,sizeof(a.amounts)) && !memcmp(a.total,b.total,sizeof(a.total)) &&
      !memcmp(a.total_text,b.total_text,sizeof(a.total_text));
}
}
bool near_derivation_path(uint32_t index, uint32_t out[3]) {
  if (!out || index >= 0x80000000UL) return false;
  out[0]=0x8000002c; out[1]=0x8000018d; out[2]=0x80000000UL|index;
  return true;
}
bool near_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t out[32]) {
  uint32_t path[3];
  if (!out) return false;
  if (seed && near_derivation_path(index,path) && slip10_ed25519_derive(seed,kSeedSize,path,3,out)) return true;
  secure_zero(out,32); return false;
}
bool near_implicit_address(const uint8_t public_key[32], char *out, size_t capacity) {
  if (out && capacity) out[0]=0;
  if (!public_key || !out || capacity<65) return false;
  constexpr char alphabet[]="0123456789abcdef";
  for (size_t i=0;i<32;++i) { out[2*i]=alphabet[public_key[i]>>4]; out[2*i+1]=alphabet[public_key[i]&15]; }
  out[64]=0; return true;
}
bool near_format_amount(const uint8_t amount[16], char *out, size_t capacity) {
  if (out && capacity) out[0]=0;
  if (!amount || !out || !capacity) return false;
  uint8_t work[16]; memcpy(work,amount,16);
  char reversed[40]; size_t digits=0;
  do {
    uint16_t remainder=0;
    for (size_t j=16;j>0;--j) {
      const uint16_t value = (remainder<<8)|work[j-1];
      work[j-1]=static_cast<uint8_t>(value/10); remainder=value%10;
    }
    reversed[digits++]=static_cast<char>('0'+remainder);
  } while (nonzero(work,16));
  char text[72]; size_t n=0;
  if (digits<=24) {
    text[n++]='0'; text[n++]='.';
    for (size_t i=digits;i<24;++i) text[n++]='0';
  }
  for (size_t i=digits;i>0;--i) {
    if (digits>24 && i==24) text[n++]='.';
    text[n++]=reversed[i-1];
  }
  memcpy(text+n," NEAR",6); n+=5;
  if (n+1>capacity) return false;
  memcpy(out,text,n+1); return true;
}
NearError near_review_transaction(const uint8_t *data, size_t size,
    const uint8_t owner[32], NearTransaction *out) {
  if (!out) return NearError::InvalidArgument;
  memset(out,0,sizeof(*out));
  if (!data || !owner || !size || size>kNearMaxTransaction) return NearError::InvalidArgument;
  const NearError error=parse(data,size,owner,out);
  if (error!=NearError::Ok) secure_zero(out,sizeof(*out));
  return error;
}
NearError near_sign_transaction(const NearTransaction &tx, const uint8_t seed[kSeedSize],
    uint8_t *out, size_t *in_out_size) {
  if (!in_out_size) return NearError::InvalidArgument;
  const size_t capacity=*in_out_size; *in_out_size=0;
  if (!seed || !out) return NearError::InvalidArgument;
  uint8_t child[32]={}, owner[32]={}, signature[64]={};
  NearTransaction verified={};
  NearError error=NearError::CryptoFailure;
  if (near_derive_key(seed,tx.address_index,child) && ed25519_public_key(child,owner)) {
    error=near_review_transaction(tx.transaction,tx.transaction_size,owner,&verified);
    if (error==NearError::Ok && (!same_review(tx.review,verified.review) ||
        memcmp(tx.signing_hash,verified.signing_hash,32))) error=NearError::Malformed;
    if (error==NearError::Ok) {
      if (capacity<verified.transaction_size+65U) error=NearError::BufferTooSmall;
      else if (!ed25519_sign(child,verified.signing_hash,32,signature) ||
               !ed25519_verify(owner,verified.signing_hash,32,signature)) error=NearError::CryptoFailure;
      else {
        memcpy(out,verified.transaction,verified.transaction_size);
        out[verified.transaction_size]=0; // Signature::ED25519
        memcpy(out+verified.transaction_size+1,signature,64);
        *in_out_size=verified.transaction_size+65;
      }
    }
  }
  secure_zero(child,sizeof(child)); secure_zero(signature,sizeof(signature)); secure_zero(&verified,sizeof(verified));
  return error;
}
bool run_near_self_tests() {
  uint8_t child[32] = {}, owner[32] = {};
  bool ok = near_derive_key(kNearTestSeed, 0, child) && ed25519_public_key(child, owner);
  secure_zero(child, sizeof(child));
  NearTransaction tx = {};
  ok = ok && near_review_transaction(kNearTestRequest, sizeof(kNearTestRequest),
      owner, &tx) == NearError::Ok &&
      !memcmp(tx.signing_hash, kNearTestHash, sizeof(kNearTestHash)) &&
      !strcmp(tx.review.signer, kNearTestSigner);
  uint8_t signed_transaction[kNearMaxSigned] = {};
  size_t signed_size = sizeof(signed_transaction);
  ok = ok && near_sign_transaction(tx, kNearTestSeed, signed_transaction,
      &signed_size) == NearError::Ok &&
      signed_size == sizeof(kNearTestSigned) &&
      !memcmp(signed_transaction, kNearTestSigned, signed_size);
  uint8_t wrong_owner[32] = {};
  memcpy(wrong_owner, owner, sizeof(wrong_owner));
  wrong_owner[0] ^= 1;
  NearTransaction rejected = {};
  ok = ok && near_review_transaction(kNearTestRequest, sizeof(kNearTestRequest),
      wrong_owner, &rejected) == NearError::WrongWallet;
  secure_zero(&tx, sizeof(tx));
  secure_zero(&rejected, sizeof(rejected));
  secure_zero(signed_transaction, sizeof(signed_transaction));
  secure_zero(owner, sizeof(owner));
  secure_zero(wrong_owner, sizeof(wrong_owner));
  return ok;
}
}
