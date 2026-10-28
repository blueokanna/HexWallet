#pragma once
#include <vector>
namespace epee {
template<class T> class span {
  T *p_; size_t n_;
 public:
  span(T *p,size_t n):p_(p),n_(n){}
  size_t size() const { return n_; }
  T &operator[](size_t i) const { return p_[i]; }
};
template<class T> span<const T> to_span(const std::vector<T> &v) { return {v.data(),v.size()}; }
}
