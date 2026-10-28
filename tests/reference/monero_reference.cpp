// Compiles the unmodified pinned BP+ source in this TU so the fixture exporter
// can observe its internal transcript helpers. No wallet headers or objects.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include "rctOps.h"
#include "multiexp.h"
namespace rct {
static key last_multiexp;
static key observed_pippenger(const std::vector<MultiexpData> &d,
    const std::shared_ptr<pippenger_cached_data> &c,size_t n,size_t w) {
  return last_multiexp=pippenger(d,c,n,w);
}
static key observed_straus(const std::vector<MultiexpData> &d,
    const std::shared_ptr<straus_cached_data> &c,size_t step) {
  return last_multiexp=straus(d,c,step);
}
}
// Observe actual upstream results without replacing their arithmetic.
#define pippenger observed_pippenger
#define straus observed_straus
#include "bulletproofs_plus.cc"
#undef pippenger
#undef straus

static std::string hex(const rct::key &k) {
  char h[65]; for(size_t i=0;i<32;++i) std::sprintf(h+2*i,"%02x",k.bytes[i]); return h;
}
static void emit(const char *name,const rct::key &k) { std::cout << name << '=' << hex(k) << '\n'; }
static void trace(const rct::BulletproofPlus &p) {
  using namespace rct;
  emit("initial", initial_transcript);
  key t=initial_transcript;
  emit("V_hash",hash_to_scalar(p.V));
  emit("after_V",transcript_update(t,hash_to_scalar(p.V)));
  key y=transcript_update(t,p.A); emit("y",y);
  key z=t=hash_to_scalar(y); emit("z",z);
  for(size_t j=0;j<p.L.size();++j) emit(("challenge_"+std::to_string(j)).c_str(),transcript_update(t,p.L[j],p.R[j]));
  emit("e",transcript_update(t,p.A1,p.B));
  emit("sum_y",sum_of_scalar_powers(y,size_t(1)<<p.L.size()));
  for(size_t i=0;i<(size_t(1)<<p.L.size())*2;++i) {
    key k; ge_p3 g=get_exponent(H,i); ge_p3_tobytes(k.bytes,&g);
    emit(("generator_"+std::to_string(i)).c_str(),k);
  }
}
static rct::key read_key(std::istream &in) {
  std::string h; in>>h;
  if(h.size()!=64 || h.find_first_not_of("0123456789abcdef")!=std::string::npos) throw std::runtime_error("invalid key hex");
  rct::key k; for(size_t i=0;i<32;++i) k.bytes[i]=uint8_t(std::stoul(h.substr(i*2,2),nullptr,16)); return k;
}
int main(int argc,char **argv) {
  try {
    rct::BulletproofPlus p;
    if(argc==3 && (std::string(argv[1])=="--read" || std::string(argv[1])=="--read-commitments")) {
      std::ifstream f(argv[2]); size_t n=0,r=0; f>>n>>r;
      if(!f || n<1 || n>16 || r<6 || r>10) throw std::runtime_error("invalid shape");
      for(size_t i=0;i<n;++i) p.V.push_back(read_key(f));
      if(std::string(argv[1])=="--read-commitments")
        for(auto &v:p.V) v=rct::scalarmultKey(v,rct::INV_EIGHT);
      p.A=read_key(f); p.A1=read_key(f); p.B=read_key(f);
      p.r1=read_key(f); p.s1=read_key(f); p.d1=read_key(f);
      for(size_t i=0;i<r;++i) p.L.push_back(read_key(f));
      for(size_t i=0;i<r;++i) p.R.push_back(read_key(f));
      std::string trailing; if(f>>trailing) throw std::runtime_error("trailing data");
    } else if(argc==2 && std::string(argv[1])=="--review-fixture") {
      // Public review test parameters, matching CryptoNoteReview's fixture.
      // Derivation, commitments and proof generation use only reference ops.
      const rct::key views[2]={{{0x47,0xee}},{{0x33,0x77,0x01,0xe8}}};
      rct::key entropy; rct::hash_to_scalar(entropy,"review-fixture",14);
      uint8_t seed[46]={}; memcpy(seed,"hw-tx-secret",12); memcpy(seed+12,entropy.bytes,32);
      rct::key secret; rct::hash_to_scalar(secret,seed,sizeof(seed));
      emit("tx_secret",secret);
      rct::keyV masks(2);
      for(size_t i=0;i<2;++i) {
        rct::key shared=rct::scalarmultKey(rct::scalarmultBase(views[i]),secret);
        ge_p3 d; rct::scalarmult8(d,shared);
        uint8_t input[33]; ge_p3_tobytes(input,&d); input[32]=uint8_t(i);
        rct::key amount_key; rct::hash_to_scalar(amount_key,input,sizeof(input));
        uint8_t mask_input[47]; memcpy(mask_input,"commitment_mask",15); memcpy(mask_input+15,amount_key.bytes,32);
        rct::hash_to_scalar(masks[i],mask_input,sizeof(mask_input));
        emit(("mask_"+std::to_string(i)).c_str(),masks[i]);
        std::cout<<"amount_"<<i<<"=400000000000\n";
      }
      p=rct::bulletproof_plus_PROVE(std::vector<uint64_t>(2,400000000000ULL),masks);
    } else {
      if(argc!=2) throw std::runtime_error("usage: monero_reference OUTPUT_COUNT | --read proof.txt");
      size_t n=std::stoul(argv[1]); if(n<1 || n>16) throw std::runtime_error("output count");
      std::vector<uint64_t> amounts(n); rct::keyV masks(n);
      for(size_t i=0;i<n;++i) { amounts[i]=i==0?0:(i==1?UINT64_MAX:i*123456789); masks[i]=rct::skGen(); }
      p=rct::bulletproof_plus_PROVE(amounts,masks);
      for(size_t i=0;i<n;++i) {
        std::cout << "amount_"<<i<<'='<<amounts[i]<<'\n'; emit(("mask_"+std::to_string(i)).c_str(),masks[i]);
      }
    }
    bool valid=rct::bulletproof_plus_VERIFY(p);
    emit("multiexp",rct::last_multiexp);
    std::cout<<"accepted="<<valid<<"\ncount="<<p.V.size()<<"\nrounds="<<p.L.size()<<'\n';
    for(size_t i=0;i<p.V.size();++i) {
      emit(("V_"+std::to_string(i)).c_str(),p.V[i]);
      ge_p3 q; rct::scalarmult8(q,p.V[i]); rct::key c; ge_p3_tobytes(c.bytes,&q);
      emit(("commitment_"+std::to_string(i)).c_str(),c);
    }
    emit("A",p.A); emit("A1",p.A1); emit("B",p.B);
    emit("r1",p.r1); emit("s1",p.s1); emit("d1",p.d1);
    for(size_t i=0;i<p.L.size();++i) emit(("L_"+std::to_string(i)).c_str(),p.L[i]);
    for(size_t i=0;i<p.R.size();++i) emit(("R_"+std::to_string(i)).c_str(),p.R[i]);
    trace(p);
    return valid?0:1;
  } catch(const std::exception &e) { std::cerr<<e.what()<<'\n'; return 2; }
}
