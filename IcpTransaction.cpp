#include "IcpTransaction.h"
#include <stdio.h>
#include <string.h>
#include "ChainCommon.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
namespace hexwallet {
namespace {
constexpr uint8_t kDerPrefix[12]={0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00};
constexpr uint8_t kLedger[10]={0,0,0,0,0,0,0,2,1,1}; // ryjl3-tyaaa-aaaaa-aaaba-cai
// @icp-sdk/core Candid IDL record: to vec nat8; fee {e8s:nat64}; memo nat64;
// from_subaccount opt vec nat8; created_at_time opt {timestamp_nanos:nat64}; amount {e8s:nat64}.
constexpr uint8_t kCandidType[]={0x44,0x49,0x44,0x4c,0x06,0x6d,0x7b,0x6c,0x01,0xe0,0xa9,0xb3,0x02,0x78,0x6e,0x00,0x6c,0x01,0xd6,0xf6,0x8e,0x80,0x01,0x78,0x6e,0x03,0x6c,0x06,0xfb,0xca,0x01,0x00,0xc6,0xfc,0xb6,0x02,0x01,0xba,0x89,0xe5,0xc2,0x04,0x78,0xa2,0xde,0x94,0xeb,0x06,0x02,0x82,0xf3,0xf3,0x91,0x0c,0x04,0xd8,0xa3,0x8c,0xa8,0x0d,0x01,0x01,0x05};
void crc32_bytes(const uint8_t *p,size_t n,uint8_t out[4]) {
  uint32_t crc=0xffffffff;
  for(size_t i=0;i<n;++i){crc^=p[i];for(unsigned j=0;j<8;++j)crc=(crc>>1)^(0xedb88320U & (0U-(crc&1U)));}
  crc^=0xffffffff;
  for(unsigned i=0;i<4;++i)out[i]=static_cast<uint8_t>(crc>>(24-i*8));
}
struct Request {const uint8_t *to;uint64_t amount,fee,memo,created,expiry;};
ChainError parse(const uint8_t *p,size_t n,Request *r) {
  if(!p || !r) return ChainError::InvalidArgument;
  if(n!=76 || memcmp(p,"ICP1",4))return ChainError::Malformed;
  r->to=p+4; r->amount=chain_read_u64_le(p+36);r->fee=chain_read_u64_le(p+44);
  r->memo=chain_read_u64_le(p+52);r->created=chain_read_u64_le(p+60);r->expiry=chain_read_u64_le(p+68);
  uint8_t sum[4];crc32_bytes(r->to+4,28,sum);
  if(!chain_constant_time_equal(sum,r->to,4))return ChainError::Malformed;
  if(!r->amount || r->amount>UINT64_MAX-r->fee)return ChainError::InvalidAmount;
  if(r->fee!=10000)return ChainError::FeePolicy;
  if(!r->created || r->expiry<=r->created || r->expiry-r->created>UINT64_C(300000000000))
    return ChainError::Malformed;
  return ChainError::Ok;
}
size_t candid(const Request &r,uint8_t out[160]) {
  size_t n=sizeof(kCandidType);memcpy(out,kCandidType,n);
  out[n++]=32;memcpy(out+n,r.to,32);n+=32;
  chain_write_u64_le(r.fee,out+n);n+=8;chain_write_u64_le(r.memo,out+n);n+=8;
  out[n++]=0;out[n++]=1;chain_write_u64_le(r.created,out+n);n+=8;
  chain_write_u64_le(r.amount,out+n);n+=8;return n;
}
bool request_hash(const Request &r,const uint8_t principal[29],uint8_t digest[32]) {
  uint8_t arg[160],leb[10],pairs[6][64];const size_t arg_size=candid(r,arg);
  size_t leb_size=0;uint64_t value=r.expiry;
  do{leb[leb_size]=value&127;value>>=7;if(value)leb[leb_size]|=128;++leb_size;}while(value);
  const char *keys[]={"request_type","canister_id","method_name","arg","sender","ingress_expiry"};
  const uint8_t *values[]={reinterpret_cast<const uint8_t *>("call"),kLedger,reinterpret_cast<const uint8_t *>("transfer"),arg,principal,leb};
  const size_t sizes[]={4,sizeof(kLedger),8,arg_size,29,leb_size};
  for(size_t i=0;i<6;++i)if(!crypto_sha256(reinterpret_cast<const uint8_t *>(keys[i]),strlen(keys[i]),pairs[i])||!crypto_sha256(values[i],sizes[i],pairs[i]+32))return false;
  for(size_t i=1;i<6;++i)for(size_t j=i;j>0 && memcmp(pairs[j-1],pairs[j],32)>0;--j){uint8_t tmp[64];memcpy(tmp,pairs[j],64);memcpy(pairs[j],pairs[j-1],64);memcpy(pairs[j-1],tmp,64);}
  return crypto_sha256(&pairs[0][0],sizeof(pairs),digest);
}
struct Cbor {
  uint8_t *p;size_t cap,n=0;bool ok=true;
  void raw(const uint8_t *v,size_t z){if(!ok || z>cap-n){ok=false;return;}memcpy(p+n,v,z);n+=z;}
  void byte(uint8_t v){raw(&v,1);}
  void number(uint8_t major,uint64_t v){if(v<24){byte(static_cast<uint8_t>((major<<5)|v));return;}size_t z=v<=255?1:v<=65535?2:v<=UINT32_MAX?4:8;byte(static_cast<uint8_t>((major<<5)|(z==1?24:z==2?25:z==4?26:27)));for(size_t i=z;i>0;--i)byte(static_cast<uint8_t>(v>>((i-1)*8)));}
  void bytes(const uint8_t *v,size_t z){number(2,z);raw(v,z);}
  void text(const char *s){size_t z=strlen(s);number(3,z);raw(reinterpret_cast<const uint8_t *>(s),z);}
};
}
bool icp_identity(const uint8_t public_key[32],uint8_t principal[29],uint8_t account[32]) {
  if(!public_key || !principal || !account)return false;
  uint8_t der[44],preimage[72]={};memcpy(der,kDerPrefix,12);memcpy(der+12,public_key,32);
  if(!crypto_sha224_local(der,sizeof(der),principal))return false;principal[28]=2;
  preimage[0]=10;memcpy(preimage+1,"account-id",10);memcpy(preimage+11,principal,29);
  if(!crypto_sha224_local(preimage,sizeof(preimage),account+4))return false;
  crc32_bytes(account+4,28,account);return true;
}
WalletError icp_ledger_address(const uint8_t public_key[32],char *out,size_t capacity) {
  if(!public_key || !out)return WalletError::InvalidArgument;
  if(capacity<65)return WalletError::BufferTooSmall;
  uint8_t principal[29],account[32];if(!icp_identity(public_key,principal,account))return WalletError::CryptoFailure;
  chain_hex(account,32,out,capacity);return WalletError::Ok;
}
ChainError icp_review_payload(const uint8_t *payload,size_t size,const uint8_t public_key[32],ChainReview *review,uint8_t digest[32]) {
  if(!public_key || !review || !digest)return ChainError::InvalidArgument;
  memset(review,0,sizeof(*review));Request r{};ChainError error=parse(payload,size,&r);if(error!=ChainError::Ok)return error;
  uint8_t principal[29],account[32];if(!icp_identity(public_key,principal,account) || !request_hash(r,principal,digest))return ChainError::CryptoFailure;
  strcpy(review->symbol,"ICP");chain_hex(account,32,review->sender,sizeof(review->sender));chain_hex(r.to,32,review->recipient,sizeof(review->recipient));
  if(!chain_format_units(r.amount,8,"ICP",review->amount,sizeof(review->amount)) || !chain_format_units(r.fee,8,"ICP",review->fee,sizeof(review->fee)))return ChainError::BufferTooSmall;
  const int written = snprintf(review->extra,sizeof(review->extra),"Ledger ryjl3-tyaaa-aaaaa-aaaba-cai\nMEMO %llu\nCREATED %llu ns\nEXPIRY %llu ns\nSubaccount 0; node validates time/network",static_cast<unsigned long long>(r.memo),static_cast<unsigned long long>(r.created),static_cast<unsigned long long>(r.expiry));
  if (written < 0 || static_cast<size_t>(written) >= sizeof(review->extra))
    return ChainError::BufferTooSmall;
  return ChainError::Ok;
}
ChainError icp_sign_payload(const uint8_t *payload,size_t size,const uint8_t seed[32],uint8_t *out,size_t *in_out_size) {
  if(!in_out_size)return ChainError::InvalidArgument;size_t capacity=*in_out_size;*in_out_size=0;if(out)secure_zero(out,capacity);
  if(!seed || !out)return ChainError::InvalidArgument;Request r{};ChainError error=parse(payload,size,&r);if(error!=ChainError::Ok)return error;
  uint8_t public_key[32],principal[29],account[32],msg[43],sig[64]={},arg[160],der[44];
  memcpy(msg,"\x0a" "ic-request",11);
  if(!ed25519_public_key(seed,public_key) || !icp_identity(public_key,principal,account) || !request_hash(r,principal,msg+11) || !ed25519_sign(seed,msg,sizeof(msg),sig))return ChainError::CryptoFailure;
  const size_t arg_size=candid(r,arg);memcpy(der,kDerPrefix,12);memcpy(der+12,public_key,32);
  Cbor c{out,capacity};c.byte(0xd9);c.byte(0xd9);c.byte(0xf7);c.number(5,3);
  c.text("content");c.number(5,6);c.text("request_type");c.text("call");c.text("canister_id");c.bytes(kLedger,sizeof(kLedger));c.text("method_name");c.text("transfer");c.text("arg");c.bytes(arg,arg_size);c.text("sender");c.bytes(principal,sizeof(principal));c.text("ingress_expiry");c.number(0,r.expiry);
  c.text("sender_pubkey");c.bytes(der,sizeof(der));c.text("sender_sig");c.bytes(sig,sizeof(sig));
  secure_zero(sig,sizeof(sig));secure_zero(msg,sizeof(msg));
  if(!c.ok){secure_zero(out,capacity);return ChainError::BufferTooSmall;}*in_out_size=c.n;return ChainError::Ok;
}
}
