#ifndef __BASE58_H_
#define __BASE58_H_

bool b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz);
bool ripple_b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz);
bool b58check_dec(uint8_t *bin, size_t *binsz, const char *b58);

#endif
