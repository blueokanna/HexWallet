#pragma once
static int crypto_verify_32(const unsigned char *a,const unsigned char *b) {
  unsigned int d=0; for(int i=0;i<32;++i) d|=a[i]^b[i]; return d ? -1 : 0;
}
