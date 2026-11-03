// Independent public-API checks against the unmodified Bitcoin BIP341 vectors.
#include "BitcoinTransaction.h"
#include "ChainCommon.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
using namespace hexwallet;
using Bytes=std::vector<uint8_t>;
static Bytes hex(const std::string &s) {
  Bytes b(s.size()/2); size_t n=0;
  if(!chain_parse_hex(s.c_str(),b.data(),b.size(),&n)||n!=b.size()) throw std::runtime_error("hex");
  return b;
}
struct Reader {
  Bytes b; size_t p=0;
  uint64_t number(unsigned n) { uint64_t v=0; for(unsigned i=0;i<n;++i) v|=uint64_t(b.at(p++))<<(8*i); return v; }
  void bytes(uint8_t *out,size_t n) { for(size_t i=0;i<n;++i) out[i]=b.at(p++); }
};
static unsigned checks=0, failures=0;
static void check(const char *name,bool ok) { ++checks; failures+=!ok; printf("%s: %s\n",name,ok?"PASS":"FAIL"); }
int main(int argc,char **argv) {
  if(argc!=2) return 2;
  try {
    std::ifstream file(argv[1]); std::string tx; file>>tx; Reader reader{hex(tx)};
    BitcoinSigningRequest req={}; req.chain={"btc",nullptr,kBitcoinMainnet,SighashFamily::Bitcoin,0};
    req.version=uint32_t(reader.number(4)); req.input_count=uint8_t(reader.number(1));
    if(req.input_count>kBitcoinMaxInputs) throw std::runtime_error("inputs");
    for(size_t i=0;i<req.input_count;++i) {
      auto &in=req.inputs[i]; reader.bytes(in.previous_txid,32); in.previous_index=uint32_t(reader.number(4));
      if(reader.number(1)!=0) throw std::runtime_error("scriptSig"); in.sequence=uint32_t(reader.number(4));
    }
    req.output_count=uint8_t(reader.number(1));
    if(req.output_count>kBitcoinMaxOutputs) throw std::runtime_error("outputs");
    for(size_t i=0;i<req.output_count;++i) {
      auto &out=req.outputs[i]; out.value=reader.number(8); out.script_size=uint8_t(reader.number(1));
      if(out.script_size>sizeof(out.script)) throw std::runtime_error("script"); reader.bytes(out.script,out.script_size);
    }
    req.lock_time=uint32_t(reader.number(4)); if(reader.p!=reader.b.size()) throw std::runtime_error("trailing");
    for(size_t i=0;i<req.input_count;++i) {
      std::string script; file>>req.inputs[i].value>>script; Bytes b=hex(script); auto &in=req.inputs[i];
      if(b.size()==34 && b[0]==0x51 && b[1]==32) { in.spend_type=BitcoinSpendType::TaprootBip86; memcpy(in.taproot_output_key,b.data()+2,32); }
      else if(b.size()==22 && b[0]==0 && b[1]==20) { in.spend_type=BitcoinSpendType::NativeP2wpkh; memcpy(in.witness_key_hash,b.data()+2,20); }
      else if(b.size()==25 && b[0]==0x76) { in.spend_type=BitcoinSpendType::LegacyP2pkh; memcpy(in.witness_key_hash,b.data()+3,20); }
      else throw std::runtime_error("unsupported vector script");
    }
    size_t index; unsigned type; std::string expected,annex_hex;
    while(file>>index>>type>>expected>>annex_hex) {
      uint8_t digest[32]; Bytes want=hex(expected); char label[80];
      Bytes annex=annex_hex=="-"?Bytes{}:hex(annex_hex);
      snprintf(label,sizeof(label),"BIP341 input=%zu hashType=0x%02x annex=%zu",index,type,annex.size());
      check(label,bitcoin_sighash_taproot(req,index,uint8_t(type),annex.data(),annex.size(),digest)==TransactionError::Ok && want.size()==32 && !memcmp(want.data(),digest,32));
    }
    uint8_t digest[32];
    check("reject undefined hash type 0x80",bitcoin_sighash_taproot(req,0,0x80,nullptr,0,digest)==TransactionError::InvalidArgument);
    check("reject missing SINGLE output",bitcoin_sighash_taproot(req,8,3,nullptr,0,digest)==TransactionError::InvalidArgument);
    const uint8_t annex[]={0x50};
    check("one-byte annex accepted",bitcoin_sighash_taproot(req,0,0,annex,1,digest)==TransactionError::Ok);
    printf("%u checks, %u failures\n",checks,failures); return failures?1:0;
  } catch(const std::exception &e) { fprintf(stderr,"fixture error: %s\n",e.what()); return 2; }
}
