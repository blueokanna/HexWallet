#pragma once
#include "rctTypes.h"
#include "misc_log_ex.h"
namespace rct {
inline key hash2rct(const key &k) { return k; }
inline key d2h(uint64_t v) { key k={}; for(size_t i=0;i<8;++i) k.bytes[i]=uint8_t(v>>(8*i)); return k; }
inline void hash_to_scalar(key &h,const void *p,size_t n) { h=crypto::cn_fast_hash(p,n); sc_reduce32(h.bytes); }
inline key hash_to_scalar(const key &k) { key h; hash_to_scalar(h,k.bytes,32); return h; }
inline key hash_to_scalar(const keyV &v) { key h; hash_to_scalar(h,v.data(),v.size()*32); return h; }
inline void hash_to_p3(ge_p3 &out,const key &k) {
  key h=crypto::cn_fast_hash(k.bytes,32); ge_p2 p; ge_p1p1 q;
  ge_fromfe_frombytes_vartime(&p,h.bytes); ge_mul8(&q,&p); ge_p1p1_to_p3(&out,&q);
}
inline void scalarmult8(ge_p3 &out,const key &k) {
  ge_p3 p; ge_p2 q; ge_p1p1 r;
  CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&p,k.bytes)==0,"point decoding");
  ge_p3_to_p2(&q,&p); ge_mul8(&r,&q); ge_p1p1_to_p3(&out,&r);
}
inline key scalarmultKey(const key &p,const key &s) {
  ge_p3 q; ge_p2 r; key out;
  CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&q,p.bytes)==0,"point decoding");
  ge_scalarmult(&r,s.bytes,&q); ge_tobytes(out.bytes,&r); return out;
}
inline key scalarmultBase(const key &s) { ge_p3 p; key r; ge_scalarmult_base(&p,s.bytes); ge_p3_tobytes(r.bytes,&p); return r; }
inline void addKeys(key &out,const key &a,const key &b) {
  ge_p3 p,q; ge_cached c; ge_p1p1 r;
  CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&p,a.bytes)==0 && ge_frombytes_vartime(&q,b.bytes)==0,"point decoding");
  ge_p3_to_cached(&c,&q); ge_add(&r,&p,&c); ge_p1p1_to_p3(&p,&r); ge_p3_tobytes(out.bytes,&p);
}
inline void addKeys2(key &out,const key &a,const key &b,const key &p) {
  ge_p3 q; ge_p2 r;
  CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&q,p.bytes)==0,"point decoding");
  ge_double_scalarmult_base_vartime(&r,b.bytes,&q,a.bytes); ge_tobytes(out.bytes,&r);
}
// Public deterministic fixture stream, NEVER production randomness. The prover
// and verifier bodies remain unchanged; only their skGen dependency is supplied.
inline uint64_t fixture_counter=0;
inline key skGen() {
  const std::string input="HexWallet independent Monero fixture v1/"+std::to_string(fixture_counter++);
  key r; hash_to_scalar(r,input.data(),input.size()); return r;
}
}
namespace tools {
inline std::string get_varint_data(size_t v) {
  std::string s; do { uint8_t b=v&127; v>>=7; s.push_back(char(b|(v?128:0))); } while(v); return s;
}
}
