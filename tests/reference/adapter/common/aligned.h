#pragma once
#include <malloc.h>
inline void aligned_free(void *p) { _aligned_free(p); }
inline void *aligned_realloc(void *p,size_t n,size_t alignment) {
  void *r=_aligned_realloc(p,n,alignment); if(!r) throw std::bad_alloc(); return r;
}
