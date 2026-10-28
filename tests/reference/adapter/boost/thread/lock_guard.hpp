#pragma once
#include <mutex>
namespace boost { template<class T> using lock_guard = std::lock_guard<T>; }
