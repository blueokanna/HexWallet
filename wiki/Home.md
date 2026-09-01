# HexWallet — ESP32 Hardware Wallet Firmware

Offline BIP39/BIP32 wallet core + bounded transaction review, running on ESP32.
Everything here is source-available firmware, **not** a finished hardware
product: see the security boundaries in the README before trusting real funds.

## Why this wiki exists

The README covers usage. This wiki covers the **crypto internals** — the part
that must be right byte-for-byte — and the **verification rig** that proves it.

## Verification status (always current)

- **Host self-test suite**: `extended-crypto=pass`, `alt-addresses=pass`
  (every embedded official vector, compiled with MSVC against the exact ESP32
  mbedtls headers).
- **Device compile check**: `DEVICE COMPILE: all sources OK`
  (pure-C++ crypto core compiled with the ESP32 Xtensa toolchain).
- **CI**: `.github/workflows/ci.yml` runs the host suite, the device compile
  check, and a full `arduino-cli` firmware build for ESP32.

## Pages

| Page | Contents |
| --- | --- |
| [Crypto stack](en/crypto-stack.md) | Ed25519, SLIP-10, EIP-2333/ERC-2333 + BLS12-381 + Chia addresses, alt-address encoders, and the bignum traps found along the way |
| [Host testing](en/host-testing.md) | How the MSVC host suite, the Python oracle, and the device compile check work, and how to run them |

中文版：

| 页面 | 内容 |
| --- | --- |
| [密码学栈](zh/crypto-stack.md) | Ed25519、SLIP-10、EIP-2333/ERC-2333 + BLS12-381 + Chia 地址、备选地址编码器，以及踩过的大数陷阱 |
| [主机测试](zh/host-testing.md) | MSVC 主机套件、Python 校验 oracle、设备端编译检查的原理与运行方法 |
