#pragma once
#include <stdexcept>
#define CHECK_AND_ASSERT_THROW_MES(c,m) do { if (!(c)) throw std::runtime_error(m); } while(0)
#define CHECK_AND_ASSERT_MES(c,r,m) do { if (!(c)) return r; } while(0)
#define MERROR(m) do {} while(0)
#define MINFO(m) do {} while(0)
#define MDEBUG(m) do {} while(0)
#define MWARNING(m) do {} while(0)
