# 2026-11-24 · 配对与钱包加固 / Pairing and wallet hardening

[中文界面审计](UI-Audit-2026-11-24-zh) · [UI audit](UI-Audit-2026-11-24) · [双向配对格式 / Enrollment records](Mutual-Pairing) · [验证记录 / Evidence](validation)

**同日后续更新。** 下文保留较早构建的镜像、字体和协议验证记录。当前 BIP39 支持英文和简繁中文词表，附加密码使用 NFKD。比特币密钥备份覆盖 WIF、十六进制和 BIP38，BIP38 密码使用 NFC，scrypt 主表占用 4 MiB。已复核 166 份图标、66 组中英画面及小尺寸收款码。PN7161 Type 4 读取与恢复手机监听通过主机回归。实物射频、卡内凭据导入及相机扫码仍待贯通。[当前能力](../README_CN.md) · [最新镜像与界面审计](UI-Audit-2026-11-24-zh.md)

本轮完成双向配对的密码学记录和状态机、收款准入保护、显式 passphrase API、横屏收款／图标／DeepSeek 伙伴界面，并修复完整 16 KiB 加密帧无法通过的问题。7 号板已重建；未刷机、提交或发布。生产创建／恢复仍返回 `CustodyUnavailable`，相机扫码与实卡签名未贯通，不能作为独立生产钱包验收。

This iteration implements signed mutual-enrollment records, receive admission, explicit passphrase arguments and landscape UI improvements, and fixes authentication of full-size encrypted frames. The rebuilt board 7 image remains diagnostic. Protected creation/recovery, real camera enrollment and card-backed signing are still incomplete.

## 修改与证据 / Changes and evidence

| Area | Implemented behavior and verification |
| --- | --- |
| 双向配对 / Mutual enrollment | Device offer: 136 bytes; phone reply: 168 bytes. Ed25519 signatures bind the reply to the complete offer hash, phone identity and nonce. Transport requests must match the trusted scan; USB/NFC have no scan-substitution opcode. The service displays all 32 bytes of the phone key. Node verifies firmware records and signed responses independently. See [format and trust boundaries](Mutual-Pairing). |
| 生命周期 / Lifecycle | Tests reject cancellation/expiry replay, replacement identities and nonces, cross-device replies, and missing scans. Service tests inject NVS open/write/commit failures, competing CLI/OTP review, exact 60-second expiry, uint32 timer rollover, NFC field loss, USB/NFC ownership and repeated decisions. Persistence occurs once. These are simulated storage/peripheral failures, not flash power-cut measurements. |
| 加密大帧 / Full encrypted frames | `WalletLinkCrypto.cpp` previously copied authenticated fields into a 4,638-byte stack buffer even though the protocol admits 16,384-byte payloads. Streaming HMAC authenticates the same `header || nonce || ciphertext` bytes without the large copy. Node independently verifies X25519, HKDF, ChaCha20 and HMAC for 1, 4,608, 4,609 and 16,384-byte requests and replies. Replay, a 16,385-byte payload and tampering with the final ciphertext byte are rejected. Wire version remains 2. |
| 收款准入 / Receive admission | `wallet_catalog_can_receive()` requires Address, TransactionReview and Signing together. CLI single/batch/token requests, phone address requests and `wallet_derive_for_display()` use the gate. Production policy reports **211 admitted / 3 blocked** (`hive`, `ryo`, `zano`). These are protocol registrations; custody is separately required. The block is temporary protection, not completion of missing signing support. |
| Passphrase | Creation/import APIs require an explicit argument, including explicit `""` for no passphrase. The host API accepts up to 128 ASCII bytes, preserves spaces, rejects unsupported Unicode and overlong input, and retains the previous session when import is rejected. The `TREZOR` BIP39 vector and distinct `""`/`" "` seeds pass. Device-local choice, entry, confirmation, cancellation and clearing remain unfinished. Serial generation is refused. |
| 本机批准 / Local approval | Device builds reject `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION`. Existing display-commit, review seal, one-time decision, refusal and hold-to-approve tests remain enabled. Simulated host approval is not physical acceptance. |
| 收款与角色 / Receive and companion UI | QR uses full panel height, four-module quiet zones and integer modules of at least two pixels. Full addresses and paths remain scrollable. Each coin icon has its own managed buffer, with abbreviation fallback. DeepSeek has a home entry plus feed/pet/play actions in both languages. |

## 本轮验证 / Validation

| Check | Result |
| --- | --- |
| Real LVGL Release and Clang ASan/UBSan | 7/7 tests pass in each build, including bilingual behavior, frame exports and board display lifecycles. Icon isolation and 16 page rebuilds are covered. |
| Export and QR | 46 states × 2 languages = 92 PNGs; all source PBMs match between builds. ZXing-C++ reads `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` from both receive pages. |
| Gallery | Chromium loads all 92 native 296 × 128 images. Filters return 46 English, 46 Chinese or 92 total. Same-origin iframe layouts at 360/768/1366 px show no horizontal overflow. |
| Font | `generate_ui_font.py --check` reproduces the 314-glyph subset and character list byte-for-byte from the pinned source/converter. |
| Native security and service | `security-regressions`, `phone-pairing-ui`, `phone-pairing-lifecycle`, `phone-storage`, `production_policy` and `cli_auth_storage` pass. The security suite also runs the RFC link-crypto vectors and native link self-test. Pairing, encrypted-frame and service tests also pass under Clang ASan/UBSan. `policy_check.ps1` passes. |
| Legacy host harness | `tests/host/build.ps1` passes, including the simulated PN7161 and worker checks. Its Mbed TLS shim now implements streaming HMAC; Node independently verifies enrollment and full encrypted frames through `tests/host/link_pipe.exe` too. Secure-element, camera and NFC self-test labels in this harness refer to fixtures and mocks, not physical devices. |
| Independent protocol oracles | `pairing_qr_check.cjs`, `signing-audit all` and `protocol_sdk_check.cjs` pass. The SDK check covers 62 EVM profiles / 82 native signatures against ethers, plus Solana, Cosmos and broadcast-adapter checks. `privacy/address_interop.cjs` verifies 14 refused Ryo/Zano phone receive requests and 14 independent encoder cases. No new ledger inclusion is claimed by this run. |
| CI and documentation | The native build runner includes pairing UI/lifecycle tests; CI runs the Node mutual-enrollment and full-frame oracle against both real Mbed TLS and the host shim. All 644 local links in README, font documentation and wiki Markdown resolve. Historical validation entries remain intact. |
| Board 7 | Arduino-ESP32 3.3.13, P4 post-v3, LVGL 9.5.0, 32 MiB Flash. Chip revision, partition/component layout and embedded ELF digest checks pass. Serial enumeration still returns zero ports. |

程序空间 1,514,682 字节；应用文件 1,515,424 字节；静态内存 242,800 字节，构建器报告剩余 84,880 字节。这些数字不是堆、调用栈或长期运行实测。两个 OTA 槽各 3,932,160 字节，后 24 MiB 为公开资产分区。

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `build/hexwallet-p4-32mb/HexWallet.ino.merged.bin` | 8,388,608 | `366ef10a08d4158eab45033cf3f899df50799e0e9dc53d612d9548ab55d340c0` |
| `build/hexwallet-p4-32mb/HexWallet.ino.bin` | 1,515,424 | `ce54049b3857eea835d2ab5d56df351bb859604974e6b2cbecfb7b99b5bcc969` |
| `build/hexwallet-p4-32mb/HexWallet.ino.elf` | 20,777,008 | `13491922c8ff681c284141daa577a0c54965d0851a59d4950e2ecd2c5a57c32f` |
| [UI manifest](ui-gallery/manifest.json) | — | `8115a07667b7979e4631942b7ee60c870f5b03d5d03b0ef42fdc00e2b5ad3557` |

## P4 硬件核对 / Hardware findings

核对的是本机 Arduino 3.3.13 对应 P4 SDK 的 `qio_qspi/include/sdkconfig.h`、`include/hal/include/hal/ecc_types.h` 和最终固件链接图。

| Item | Observed evidence and limit |
| --- | --- |
| AES / GCM / SHA / MPI / ECC | SDK defines `CONFIG_MBEDTLS_HARDWARE_AES/GCM/SHA/MPI/ECC/ECDSA_VERIFY`. `CryptoPrimitives.cpp` SHA/HMAC calls use Mbed TLS. The final application map retains `esp_sha_dma`, `esp_sha_acquire_hardware`, MPI hardware helpers and `esp_ecc_point_multiply`. This establishes configured/linked paths, not measured invocation, speed or side-channel behavior. |
| Curves | The HAL enum lists secp192r1, secp256r1, secp384r1 and SM2; it provides no secp256k1 or Ed25519 selection. This enum is not proof that every listed curve is supported on the target silicon. The wallet's Ed25519/X25519 and link ChaCha20 code are software implementations. |
| AES-XTS | The SoC and SDK provide XTS support. Availability of the peripheral or SDK functions does not enable encrypted production storage. This build does not establish active flash/NVS encryption or runtime AES-XTS use. |
| Secure Boot / encrypted storage | Secure Boot, Flash Encryption and NVS Encryption are not enabled in this precompiled SDK. `board_credential_storage_ready()` continues to refuse production credential storage. Compile-time flags in the sketch cannot substitute for bootloader/eFuse provisioning and runtime verification. |
| NPU claim | Espressif describes CPU AI instruction extensions, PPA and image peripherals. PPA performs pixel operations, not general wallet signing. No independent P4 NPU suitable for these cryptographic operations was verified. |

Sources: [Espressif ESP32-P4](https://www.espressif.com/en/products/socs/esp32-p4) · [PPA driver documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/api-reference/peripherals/ppa.html). Hardware acceleration does not imply non-exportable SE051 custody. No Tangem-equivalent security, formal proof or physical attack resistance is established by these checks.

## 未完成范围 / Outstanding requirements

| Requirement | Blocking work |
| --- | --- |
| 独立创建／恢复及 optional passphrase | Production sessions still return `CustodyUnavailable`. Complete non-exportable SE051 seed/derivation operations and the local backup, mnemonic input and passphrase flow. API enforcement alone does not deliver the requested screen flow. |
| 双向扫码与 NFC 初次配对 | The current board has a shared camera SCCB bus. COM6 returned the OV9281 ID. The trusted camera path for enrollment, offer display, account-address binding and the phone application still require integration. [Camera and backup QR status](Boards-and-Display.md) |
| 全链审阅和卡内签名 | 214/214 covers catalog derivation/registration; 211 receive-admission entries are not 211 verified card adapters. Ryo/Zano production signing, Peercoin, TRON NFTs/batches, Dash special transactions, Lightning, Stacks, Grin and other documented forms remain open. [Per-chain review](Capability-Review) |
| SE051C2HQ1 | Default integration remains disabled. PBKDF2 applet version/permissions/results, non-exportable BIP32 scalar addition and CryptoNote signed key images/MLSAG/CLSAG operations remain unverified on the card. |
| 其他钱包功能 | BIP38, single-key import/export, QRL new-key initialization, all-network NFT home data with trusted network/account binding, and a complete phone application remain unfinished. |
| 实物与安全验收 | Mounted key order, screen orientation, ghosting, shared SPI, NFC, power, concurrency, heap/stack, longevity and real phone-to-card-to-node execution require hardware. Firmware cannot establish anti-relay, side-channel or fault-injection resistance through host tests. |

## 复现 / Reproduction

After building the native probe with `tests/host/chain/CMakeLists.txt`:

```powershell
node tests/host/pairing_qr_check.cjs build/audit-native/Release/chain_probe.exe
build/audit-native/Release/chain_probe.exe phone-pairing-ui
build/audit-native/Release/chain_probe.exe phone-pairing-lifecycle
build/audit-native/Release/chain_probe.exe phone-storage
build/audit-native/Release/chain_probe.exe security-regressions
build/audit-native/Release/production_policy.exe
build/audit-native/Release/cli_auth_storage.exe
build/audit-native/Release/chain_probe.exe signing-audit all
$env:NODE_PATH=(Resolve-Path tests/host/protocol-oracles/node_modules).Path
node tests/host/protocol_sdk_check.cjs build/audit-native/Release/chain_probe.exe
node tests/host/privacy/address_interop.cjs build/audit-native/Release/chain_probe.exe
./tests/host/policy_check.ps1 -ProductionPolicy build/audit-native/Release/production_policy.exe
py -3.10 tools/generate_ui_font.py --check
./tools/build_p4_board.ps1 -ArduinoCli build/audit-arduino/bin/arduino-cli.exe -ConfigFile build/board-sdk-3.3.13/arduino-cli.yaml -Lvgl build/audit-arduino/libraries/lvgl -BuildDirectory build/hexwallet-p4-32mb
```

Logs: `build/audit-logs/enrollment-mutual-link.log`, `enrollment-link-sanitized.log`, `enrollment-native-build.log`, `enrollment-host-build.log`, `enrollment-shim-link.log`, `enrollment-address-policy.log`, `enrollment-signing.log`, `enrollment-protocol-sdk.log`, `enrollment-p4-build.log`; UI CTest results are under each build's `Testing/Temporary/LastTest.log`. [UI reproduction](UI-Audit-2026-11-24#reproduction) records frame/font tooling and sanitizer settings.
