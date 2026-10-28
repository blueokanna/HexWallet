// Diagnostic process for independent reference fixtures; host only.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <ctime>
#include "CryptoNoteBulletproofPlus.h"
#include "CryptoExtended.h"
static size_t challenge_index=0;
static void trace(const char *name,const uint8_t *key,size_t n) {
  if(!strcmp(name,"challenge")) printf("challenge_%zu=",challenge_index++);
  else printf("%s=",name);
  for(size_t i=0;i<n;++i) printf("%02x",key[i]); puts("");
}
static bool read_key(std::istream &in,uint8_t *k) {
  std::string h; in>>h;
  if(h.size()!=64 || h.find_first_not_of("0123456789abcdef")!=std::string::npos) return false;
  for(size_t i=0;i<32;++i) k[i]=uint8_t(std::stoul(h.substr(i*2,2),nullptr,16)); return true;
}
int main(int argc,char **argv) {
  if(argc==2 && !strcmp(argv[1],"--bench-ops")) {
    uint8_t scalar[32]; memset(scalar,0,32); scalar[0]=7; scalar[31]=0x11;
    uint8_t point[32];
    if(!hexwallet::bulletproof_plus_generator(3,point)) return 2;
    uint8_t out[32];
    const clock_t s1=clock();
    for(int i=0;i<40;++i) { if(!hexwallet::ed25519_point_mul_compressed(point,scalar,out)) return 2; }
    const double mul_ms=1000.0*double(clock()-s1)/double(CLOCKS_PER_SEC)/40.0;
    const clock_t s2=clock();
    for(int i=0;i<40;++i) { if(!hexwallet::ed25519_point_add_compressed(point,point,out)) return 2; }
    const double add_ms=1000.0*double(clock()-s2)/double(CLOCKS_PER_SEC)/40.0;
    printf("point_mul_ms=%.3f point_add_ms=%.3f\n",mul_ms,add_ms);
    return 0;
  }
  const bool bench = argc >= 2 && !strcmp(argv[1],"--bench");
  if(bench) { memmove(argv+1, argv+2, sizeof(char*)*(argc-2)); --argc; }
  if(argc < 2 || argc > 3) return 2;
  if(!strcmp(argv[1],"--generators")) {
    for(size_t i=0;i<2048;++i) {
      uint8_t g[32]; if(!hexwallet::bulletproof_plus_generator(i,g)) return 2;
      printf("generator_%zu=",i); for(uint8_t b:g) printf("%02x",b); puts("");
    }
    return 0;
  }
  std::ifstream f(argv[1]); size_t n=0,r=0; f>>n>>r;
  if(!f || n<1 || n>16 || r<6 || r>10) return 2;
  uint8_t v[16][32],fields[6][32],l[10][32],rr[10][32];
  for(size_t i=0;i<n;++i) if(!read_key(f,v[i])) return 2;
  for(auto &k:fields) if(!read_key(f,k)) return 2;
  for(size_t i=0;i<r;++i) if(!read_key(f,l[i])) return 2;
  for(size_t i=0;i<r;++i) if(!read_key(f,rr[i])) return 2;
  std::string trailing; if(f>>trailing) return 2;
  hexwallet::BulletproofPlusView p={v[0],n,fields[0],fields[1],fields[2],fields[3],fields[4],fields[5],l[0],rr[0],r};
  if(bench) {
    const int iterations = argc > 2 ? atoi(argv[2]) : 10;
    const clock_t start = clock();
    bool all_valid = true;
    for(int i=0;i<iterations;++i) all_valid = hexwallet::bulletproof_plus_verify(p,nullptr) && all_valid;
    const double ms = 1000.0*double(clock()-start)/double(CLOCKS_PER_SEC);
    printf("bench outputs=%zu rounds=%zu iterations=%d valid=%d total_ms=%.1f per_verify_ms=%.2f\n",
           n,r,iterations,int(all_valid),ms,ms/double(iterations));
    return all_valid?0:1;
  }
  bool valid=hexwallet::bulletproof_plus_verify(p,trace);
  printf("accepted=%d\n",int(valid));
  for(size_t i=0;i<2*(size_t(1)<<r);++i) {
    uint8_t g[32]; if(!hexwallet::bulletproof_plus_generator(i,g)) return 2;
    printf("generator_%zu=",i); for(uint8_t b:g) printf("%02x",b); puts("");
  }
  return valid?0:1;
}
