// Redirect the ESP VFS calls in WalletCustomTokensNvs.cpp to a private host directory.
#pragma once
#include <cstddef>
#include <cstdio>
namespace hexwallet {
using ssize_t = std::ptrdiff_t;
FILE *fopen(const char *path, const char *mode);
int open(const char *path, int flags, int mode);
ssize_t write(int fd, const void *data, size_t size);
int fsync(int fd);
int close(int fd);
int rename(const char *from, const char *to);
}
