#include "NemTransaction.h"
#include <stdio.h>
#include <string.h>
#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "local_ripemd160.h"

namespace hexwallet {
namespace {
constexpr uint64_t kSupply = UINT64_C(8999999999000000);
bool expand(const uint8_t seed[32], uint8_t hash[64]) {
  if (!seed || !crypto_keccak512(seed,32,hash)) return false;
  hash[0]&=248; hash[31]&=127; hash[31]|=64;
  return true;
}
bool decode_address(const char *text) {
  uint8_t bytes[25]={}; unsigned bits=0, acc=0; size_t n=0;
  for(size_t i=0;i<40;++i) {
    unsigned v;
    if(text[i]>='A' && text[i]<='Z') v=text[i]-'A';
    else if(text[i]>='2' && text[i]<='7') v=text[i]-'2'+26;
    else return false;
    acc=(acc<<5)|v; bits+=5;
    if(bits>=8) {bits-=8; bytes[n++]=static_cast<uint8_t>(acc>>bits);}
  }
  uint8_t sum[32];
  return n==25 && bytes[0]==0x68 && crypto_keccak256(bytes,21,sum) &&
      chain_constant_time_equal(sum,bytes+21,4);
}
struct Parsed {uint64_t amount,fee; uint32_t time,deadline; char recipient[41],memo[65];};
ChainError parse(const uint8_t *p,size_t n,const char *sender,Parsed *v) {
  if(!p || !sender || !v) return ChainError::InvalidArgument;
  memset(v,0,sizeof(*v));
  if(n<116 || n>188) return ChainError::Malformed;
  if(chain_read_u32_le(p)!=257 || chain_read_u32_le(p+4)!=0x68000001)
    return ChainError::Unsupported;
  if(chain_read_u32_le(p+12)!=32 || chain_read_u32_le(p+60)!=40)
    return ChainError::Malformed;
  char owner[41];
  if(nem_address(p+16,owner,sizeof(owner))!=WalletError::Ok || strcmp(owner,sender))
    return ChainError::WrongWallet;
  v->time=static_cast<uint32_t>(chain_read_u32_le(p+8));
  v->deadline=static_cast<uint32_t>(chain_read_u32_le(p+56));
  if(!v->time || v->deadline<=v->time || uint64_t(v->deadline)-v->time>86400)
    return ChainError::Malformed;
  memcpy(v->recipient,p+64,40);
  if(!decode_address(v->recipient)) return ChainError::WrongNetwork;
  v->amount=chain_read_u64_le(p+104); v->fee=chain_read_u64_le(p+48);
  if(!v->amount || v->amount>kSupply) return ChainError::InvalidAmount;
  if(!v->fee || v->fee>UINT64_C(10000000)) return ChainError::FeePolicy;
  const uint32_t message=static_cast<uint32_t>(chain_read_u32_le(p+112));
  if(message==0) return n==116?ChainError::Ok:ChainError::Malformed;
  if(message<9 || message>72 || n!=116+size_t(message) ||
      chain_read_u32_le(p+116)!=1 || chain_read_u32_le(p+120)!=message-8)
    return ChainError::Unsupported;
  for(size_t i=0;i<message-8;++i) {
    const uint8_t c=p[124+i];
    if(c<0x20 || c>0x7e) return ChainError::Unsupported;
    v->memo[i]=static_cast<char>(c);
  }
  return ChainError::Ok;
}
}

bool nem_public_key(const uint8_t seed[32],uint8_t public_key[32]) {
  uint8_t h[64]={};
  const bool ok=public_key && expand(seed,h) && ed25519_public_key_expanded(h,public_key);
  secure_zero(h,sizeof(h)); return ok;
}
WalletError nem_address(const uint8_t public_key[32],char *out,size_t capacity) {
  if(!public_key || !out) return WalletError::InvalidArgument;
  if(capacity<41) return WalletError::BufferTooSmall;
  uint8_t hash[32],bytes[25]={0x68};
  if(!crypto_keccak256(public_key,32,hash)) return WalletError::CryptoFailure;
  local_ripemd160(hash,32,bytes+1);
  if(!crypto_keccak256(bytes,21,hash)) return WalletError::CryptoFailure;
  memcpy(bytes+21,hash,4);
  return base32_encode(bytes,sizeof(bytes),out,capacity,false,false)
      ? WalletError::Ok : WalletError::CryptoFailure;
}
ChainError nem_review_payload(const uint8_t *payload,size_t size,const char *sender,
                              ChainReview *review,uint8_t digest[32]) {
  if(!review || !digest) return ChainError::InvalidArgument;
  memset(review,0,sizeof(*review)); Parsed p{};
  ChainError error=parse(payload,size,sender,&p);
  if(error!=ChainError::Ok) return error;
  strcpy(review->symbol,"XEM"); strcpy(review->sender,sender);
  strcpy(review->recipient,p.recipient);
  if(!chain_format_units(p.amount,6,"XEM",review->amount,sizeof(review->amount)) ||
     !chain_format_units(p.fee,6,"XEM",review->fee,sizeof(review->fee)))
    return ChainError::BufferTooSmall;
  snprintf(review->extra,sizeof(review->extra),"NEM mainnet; transfer v1\nTime %lu; deadline %lu (NEM epoch)\nMemo: %s",
      static_cast<unsigned long>(p.time),static_cast<unsigned long>(p.deadline),p.memo[0]?p.memo:"(none)");
  return crypto_keccak256(payload,size,digest)?ChainError::Ok:ChainError::CryptoFailure;
}
ChainError nem_sign_payload(const uint8_t *payload,size_t size,const uint8_t seed[32],
                            uint8_t *out,size_t *in_out_size) {
  if(!in_out_size) return ChainError::InvalidArgument;
  const size_t capacity=*in_out_size; *in_out_size=0;
  if(out) secure_zero(out,capacity);
  if(!out || !seed) return ChainError::InvalidArgument;
  if(capacity<64) return ChainError::BufferTooSmall;
  uint8_t public_key[32]; char owner[41]; Parsed parsed{};
  if(!nem_public_key(seed,public_key) || nem_address(public_key,owner,sizeof(owner))!=WalletError::Ok)
    return ChainError::CryptoFailure;
  ChainError error=parse(payload,size,owner,&parsed);
  if(error!=ChainError::Ok) return error;
  uint8_t expanded[64]={}, buffer[252]={}, hash[64]={}, nonce[32]={}, challenge[32]={};
  bool ok=expand(seed,expanded);
  if(ok) {
    memcpy(buffer,expanded+32,32); memcpy(buffer+32,payload,size);
    ok=crypto_keccak512(buffer,size+32,hash);
  }
  if(ok) {
    ed25519_scalar_reduce_wide(hash,nonce);
    ok=ed25519_public_key_expanded(nonce,out);
  }
  if(ok) {
    memcpy(buffer,out,32); memcpy(buffer+32,public_key,32); memcpy(buffer+64,payload,size);
    ok=crypto_keccak512(buffer,size+64,hash);
  }
  if(ok) {
    ed25519_scalar_reduce_wide(hash,challenge);
    ed25519_scalar_muladd(out+32,challenge,expanded,nonce); *in_out_size=64;
  } else secure_zero(out,capacity);
  secure_zero(expanded,sizeof(expanded)); secure_zero(buffer,sizeof(buffer));
  secure_zero(hash,sizeof(hash)); secure_zero(nonce,sizeof(nonce)); secure_zero(challenge,sizeof(challenge));
  return ok?ChainError::Ok:ChainError::CryptoFailure;
}
}
