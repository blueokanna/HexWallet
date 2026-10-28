#include "HederaTransaction.h"
#include <stdio.h>
#include <string.h>
#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {
constexpr uint64_t kSupply = UINT64_C(5000000000000000000);
constexpr uint64_t kFeeLimit = UINT64_C(10000000000);  // 100 HBAR local cap
struct Proto {
  const uint8_t *p; size_t left;
  bool var(uint64_t *v) {
    *v = 0;
    for (unsigned i=0;i<10;++i) {
      if (!left) return false;
      const uint8_t b=*p++; --left;
      if (i==9 && b>1) return false;
      *v |= uint64_t(b & 127) << (7*i);
      if (!(b & 128)) return !i || b != 0;
    }
    return false;
  }
  bool tag(uint8_t field, uint8_t wire) {
    uint64_t v=0; return var(&v) && v == (uint64_t(field)<<3 | wire);
  }
  bool is(uint8_t field, uint8_t wire) const {
    return left && *p == (field<<3 | wire);
  }
  bool number(uint8_t field,uint64_t *v) { return tag(field,0) && var(v); }
  bool sub(uint8_t field, Proto *v) {
    uint64_t n=0;
    if (!tag(field,2) || !var(&n) || n>left) return false;
    *v={p,static_cast<size_t>(n)}; p+=n; left-=static_cast<size_t>(n);
    return true;
  }
};
bool account(Proto p,uint64_t *id) {
  uint64_t shard=0,realm=0;
  if (p.is(1,0) && (!p.number(1,&shard) || shard)) return false;
  if (p.is(2,0) && (!p.number(2,&realm) || realm)) return false;
  return p.number(3,id) && *id && *id<=INT64_MAX && !p.left;
}
struct Parsed {
  uint64_t payer,node,recipient,amount,fee,seconds,nanos,duration;
  char memo[41];
};
ChainError parse(const uint8_t *body,size_t size,Parsed *v) {
  if (!body || !v || !size || size>kChainMaxPayload) return ChainError::InvalidArgument;
  memset(v,0,sizeof(*v));
  Proto r{body,size}, txid{}, start{}, payer{}, node{}, duration{}, transfer{}, list{};
  if (!r.sub(1,&txid) || !txid.sub(1,&start) || !start.number(1,&v->seconds) ||
      !v->seconds || v->seconds>UINT32_MAX) return ChainError::Malformed;
  if (start.left && !start.number(2,&v->nanos)) return ChainError::Malformed;
  if (start.left || v->nanos>=1000000000 || !txid.sub(2,&payer) ||
      !account(payer,&v->payer)) return ChainError::Malformed;
  uint64_t value=0;
  if (txid.is(3,0) && (!txid.number(3,&value) || value)) return ChainError::Unsupported;
  if (txid.is(4,0) && (!txid.number(4,&value) || value)) return ChainError::Unsupported;
  if (txid.left || !r.sub(2,&node) || !account(node,&v->node)) return ChainError::Unsupported;
  if (!r.number(3,&v->fee) || !v->fee || v->fee>kFeeLimit) return ChainError::FeePolicy;
  if (!r.sub(4,&duration) || !duration.number(1,&v->duration) || duration.left ||
      !v->duration || v->duration>120) return ChainError::Malformed;
  if (r.is(5,0) && (!r.number(5,&value) || value)) return ChainError::Unsupported;
  if (r.is(6,2)) {
    Proto memo{};
    if (!r.sub(6,&memo) || memo.left>40) return ChainError::Unsupported;
    for (size_t i=0;i<memo.left;++i) {
      if (memo.p[i]<32 || memo.p[i]>126) return ChainError::Unsupported;
      v->memo[i]=static_cast<char>(memo.p[i]);
    }
  }
  if (!r.sub(14,&transfer) || r.left || !transfer.sub(1,&list) || transfer.left)
    return ChainError::Unsupported;  // rejects token transfers and all other operations
  bool debit=false,credit=false;
  for (unsigned i=0;i<2;++i) {
    Proto entry{}, who{};
    uint64_t id=0,zigzag=0;
    if (!list.sub(1,&entry) || !entry.sub(1,&who) || !account(who,&id) ||
        !entry.number(2,&zigzag) || !zigzag) return ChainError::Malformed;
    if (entry.is(3,0) && (!entry.number(3,&value) || value)) return ChainError::Unsupported;
    if (entry.left) return ChainError::Unsupported;
    const bool negative = (zigzag & 1)!=0;
    const uint64_t amount = (zigzag>>1) + (negative ? 1 : 0);
    if (!amount || amount>kSupply) return ChainError::InvalidAmount;
    if (negative) {
      if (debit || id!=v->payer || (credit && amount!=v->amount)) return ChainError::WrongWallet;
      debit=true;
    } else {
      if (credit || id==v->payer || (debit && amount!=v->amount)) return ChainError::InvalidAmount;
      credit=true; v->recipient=id;
    }
    v->amount=amount;
  }
  if (list.left || !debit || !credit || v->amount>kSupply-v->fee) return ChainError::InvalidAmount;
  return ChainError::Ok;
}
size_t put_var(uint64_t v,uint8_t *out) {
  size_t n=0;
  do { out[n++]=static_cast<uint8_t>((v&127) | (v>127?128:0)); v>>=7; } while(v);
  return n;
}
size_t var_size(size_t n) { size_t s=1; while(n>127){n>>=7;++s;} return s; }
}  // namespace

bool hedera_key_alias(const uint8_t public_key[32], char *out, size_t capacity) {
  // SDK AccountId.toString uses DER Ed25519; AccountID.alias on the wire uses
  // the protobuf Key (12 20 || key). Never pretend a numeric ID derives from a key.
  if (!public_key || !out || capacity<93) return false;
  strcpy(out,"0.0.302a300506032b6570032100");
  chain_hex(public_key,32,out+28,capacity-28);
  return true;
}
ChainError hedera_review_payload(const uint8_t *body,size_t size,
                                 const char *key_alias,ChainReview *review,
                                 uint8_t digest[32]) {
  if (!key_alias || !review || !digest || strlen(key_alias)>=sizeof(review->sender))
    return ChainError::InvalidArgument;
  memset(review,0,sizeof(*review)); memset(digest,0,32);
  Parsed p{};
  const ChainError error=parse(body,size,&p);
  if (error!=ChainError::Ok) return error;
  strcpy(review->symbol,"HBAR"); strcpy(review->sender,key_alias);
  snprintf(review->recipient,sizeof(review->recipient),"0.0.%llu",static_cast<unsigned long long>(p.recipient));
  char max_fee[48]={};
  if (!chain_format_units(p.amount,8,"HBAR",review->amount,sizeof(review->amount)) ||
      !chain_format_units(p.fee,8,"HBAR",max_fee,sizeof(max_fee))) return ChainError::BufferTooSmall;
  snprintf(review->fee,sizeof(review->fee),"MAX %s",max_fee);
  const int n=snprintf(review->extra,sizeof(review->extra),
      "Payer 0.0.%llu; node 0.0.%llu\nStart %llu.%09llu +%llus\nMemo: %s\n"
      "Verify payer key and network on node",
      static_cast<unsigned long long>(p.payer),static_cast<unsigned long long>(p.node),
      static_cast<unsigned long long>(p.seconds),static_cast<unsigned long long>(p.nanos),
      static_cast<unsigned long long>(p.duration),p.memo[0]?p.memo:"(none)");
  if (n<0 || static_cast<size_t>(n)>=sizeof(review->extra)) return ChainError::BufferTooSmall;
  // Review commitment only. Hedera Ed25519 signs the ORIGINAL body, not this hash.
  return crypto_sha256(body,size,digest)?ChainError::Ok:ChainError::CryptoFailure;
}
ChainError hedera_sign_payload(const uint8_t *body,size_t size,
                               const uint8_t private_seed[32],uint8_t *out,
                               size_t *in_out_size) {
  if (!in_out_size) return ChainError::InvalidArgument;
  const size_t capacity=*in_out_size; *in_out_size=0;
  if(out) secure_zero(out,capacity);
  if(!out || !private_seed) return ChainError::InvalidArgument;
  Parsed p{};
  ChainError error=parse(body,size,&p);
  if(error!=ChainError::Ok) return error;
  // SignaturePair = (1:pubKeyPrefix32, 3:ed25519Signature64); map = (1:pair).
  constexpr size_t pair_size=100, map_size=102;
  const size_t signed_size=1+var_size(size)+size+1+var_size(map_size)+map_size;
  const size_t total=1+var_size(signed_size)+signed_size;
  if(capacity<total) return ChainError::BufferTooSmall;
  uint8_t pub[32]={},sig[64]={};
  if(!ed25519_public_key(private_seed,pub) || !ed25519_sign(private_seed,body,size,sig) ||
     !ed25519_verify(pub,body,size,sig)) error=ChainError::CryptoFailure;
  if(error==ChainError::Ok) {
    size_t n=0;
    out[n++]=0x2a; n+=put_var(signed_size,out+n); // Transaction.signedTransactionBytes
    out[n++]=0x0a; n+=put_var(size,out+n);
    memcpy(out+n,body,size); n+=size;
    out[n++]=0x12; n+=put_var(map_size,out+n);
    out[n++]=0x0a; n+=put_var(pair_size,out+n);
    out[n++]=0x0a; out[n++]=32; memcpy(out+n,pub,32); n+=32;
    out[n++]=0x1a; out[n++]=64; memcpy(out+n,sig,64); n+=64;
    *in_out_size=n;
  }
  secure_zero(pub,sizeof(pub)); secure_zero(sig,sizeof(sig));
  return error;
}
}  // namespace hexwallet
