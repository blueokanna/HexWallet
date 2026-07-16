# HexWallet (BETA) - [中文文档](https://github.com/blueokanna/HexWallet/blob/main/README-zh.md)

ESP32 and LVGL firmware foundation for an offline cryptocurrency hardware
wallet. This repository is experimental and is not suitable for holding funds.

## Current architecture

- `WalletSecurity.*`: BIP39 English validation and seed derivation, BIP32
  private/public derivation, path parsing, and extended-key serialization.
- `WalletAddresses.*`: data-driven Bitcoin P2PKH, BIP13 P2SH-P2WPKH, and BIP173
  P2WPKH address encodings.
- `WalletUi.*`: LVGL 9 lock screen without secret material.
- `WalletBoardPort.*`: the only hardware-specific boundary.

The startup firmware never logs a mnemonic, seed, private key, chain code, or
extended private key. The supplied board port intentionally fails closed until
it is replaced with an implementation for the exact display and input hardware.

## Arduino IDE

Install Espressif ESP32 board support 3.x or later, LVGL 9.x, and a driver for
the exact display panel. Then implement the selected panel's GPIO, bus, LVGL
draw-buffer, flush, touch/buttons, and power sequencing in
`WalletBoardPort.cpp`.

See [HARDWARE_PORTING.md](HARDWARE_PORTING.md) for the LVGL 9 color-panel
template, e-ink constraints, and the pre-release security gate.

## Security status

This project does not yet include a secure-element integration, encrypted
secret storage, PIN retry policy, transaction parser, signing policy, trusted
transaction-review workflow, or authenticated firmware updates. These need
independent implementation and audit before any real assets are used.
