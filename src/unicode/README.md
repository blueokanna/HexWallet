# Unicode normalization

Vendored from [utf8proc 2.10.0](https://github.com/JuliaStrings/utf8proc/tree/v2.10.0), Unicode 16.0.0. License: [MIT / Unicode](LICENSE.md).

Upstream SHA-256:

| File | SHA-256 |
| --- | --- |
| utf8proc.c | 1f36d14e69e4a5f0658635496f5a9b1f76c418dc36841d2c39d61ab61a258c5d |
| utf8proc.h | d947b38124a9f218631b537dd7a367f6a2a6a992c72caa46b3f3e7c81e6138ee |
| utf8proc_data.c | 6aa28d305d65af54260a3521278715c49c4e2445c9c017e8ebf38da3735422e5 |
| LICENSE.md | 3b510150d34f248a221bb88e1d811238d6c6c18b51231822c42974c39bb07256 |

The data file is renamed to `.h` and its include adjusted, so Arduino does not compile it separately. `UnicodeNormalizer.cpp` uses explicit input sizes, bounded scratch allocation and erases scratch before freeing it. BIP39 uses NFKD; BIP38 uses NFC. The input limit is 128 UTF-8 bytes, including any embedded NUL supplied through a byte-length API.

The character-boundary branch copies its packed grapheme state between the public `int` and the internal `utf8proc_int32_t`. The ESP32-P4 toolchain defines `int32_t` as `long`, which requires a distinct pointer type.

The two decomposition loops pass a null destination when the remaining output capacity is zero. This keeps the length query and short-buffer path free of out-of-bounds pointer arithmetic.
