# HexWallet - security

## ESP32-P4 + SE051C2HQ1: safety changes and remaining requirements

*Merged from docs/security-review-2026-10-28.md.*

This is a source review and test record, not a security certification or a claim
of parity with Ledger, Trezor, SafePal, Tangem or Coldcard. No physical board was
tested, provisioned or flashed; no real keys were imported and no funds moved.

### Custody boundary

The board port only probes an I2C response at 0x48. It has no authenticated
T=1/APDU/SCP03 session, identity/OEF verification, sealed seed storage or usable
non-exportable signing-key backend. `active_secure_element_profile()` remains
MCU-only and cannot be promoted by a profile setter.

`SecureElementPort.h` now defines the backend contract that a real driver has to
satisfy, and the gate that enforces it: a backend must supply every operation,
only one may be registered per boot, and a backend that reports a successful
`open()` while `session_authenticated()` is still false is unregistered and the
gate stays closed. `active_secure_element_profile()` returns the SE051C2HQ1
capability description only while such a backend is authenticated, so nothing in
the firmware can turn a part number into a custody claim. ISO 7816-3 CRC16/A,
AES-128 and AES-CMAC are implemented and pinned to their published vectors
because any SCP03 backend needs them; the SCP03 derivation/ICV layout and the
T=1 over I2C framing are **not** written, because neither can be validated
without the part and guessing them would produce a channel that only looks
right. See [se051-plug-and-trust.md](security.md).

The target description now reflects SE051C2HQ1. NXP's
[AN12973, Table 3](https://www.nxp.com/docs/en/application-note/AN12973.pdf)
lists ECDSA/Koblitz and standard Ed25519. This does not mean Cardano expanded
Ed25519-BIP32, NEM Keccak-Ed25519, Ergo Sigma, BLS or XMSS can use the same
signature engine. Those schemes are now classified separately. All current
software derivation paths expose seed/child material to MCU RAM.

`HEXWALLET_REQUIRE_SECURE_CUSTODY=1` is the P4 default. Until the backend exists,
session generation/import and seed/master loading fail with `CustodyUnavailable`;
outputs are cleared and secret export is disabled at the session owner. A
deliberate development override is a software wallet configuration, not SE custody.
This restriction is tested in a separately compiled production-policy executable.

### Admission and algorithm corrections

- DOT/KSM historical SCALE code is not an authenticated modern runtime decoder.
  Production signing is disabled; SS58 addresses remain. Only the host regression
  target enables the explicitly named historical codec gate.
- ERG signing is disabled because multiple outputs/tokens were not fully reviewed
  and fee/context semantics remain incomplete.
- XCH signing is disabled because host AGG_SIG_ME data was not bound to the
  displayed CREATE_COIN outputs. Device address derivation is also blocked:
  current G1/G2 secret arithmetic uses variable-time MPI operations.
- Qubic's old Ed25519/SHA3 substitute cannot produce native FourQ/K12 identities.
  The profile, `AddressEncoding::QubicBase26` case, base26 encoder and its
  self-test vector were removed outright; the production-policy test asserts
  that `find_network_profile("qubic")` is `nullptr`. See the
  [Qubic technical whitepaper](https://whitepaper.qubic.org/file/qubic-whitepaper.pdf).
- QRL legacy XMSS public derivation is compared against qrllib. Index zero
  preserves the original v1 wallet tree; nonzero tree indices use a separate v2
  domain. Older builds ignored nonzero indices, so those paths recover at zero.
  No OTS reservation persistence or signing is implemented. Pure numeric
  high-water helpers do not prevent rollback or seed-restore index reuse.
- EVM signing failures now clear the caller's output range, including a partial
  serialization failure. Tampering/capacity regressions cover this behavior.
- Hive transfer serialization includes only transaction extensions; the compact
  signature is header followed by r/s. STM public keys are not receive addresses.
- CLVM reserves the zero sentinel plus its full node capacity and validates arena
  bounds before traversal. These parser repairs do not enable Chia signing.

### Trusted display and transport

Receive screens show the complete address and derivation path with wrapping.
Catalog descriptions no longer truncate capability limitations; account signing
does not imply a derived deposit address. Fee text wraps on small panels.
Single-address CLI and token-account requests now use the device address screen.

USB CLI, NFC signing, receive-address requests and phone pairing are mutually
excluded while another review owns the display. Production CLI cannot confirm
phone pairing; it requires the local UI decision. Embedded NUL coin identifiers
are rejected. Displaying an address is not proof that the user has compared it,
and this patch does not claim a separate physical address-approval handshake.

There is still no verified P4 display/touch board port. The default is HEADLESS,
which cannot approve signing. Existing S3 display profiles compiling successfully
does not validate P4 wiring or actual pixels on a device.

### Required hardware acceptance

Still required: exact P4 board schematic and panel/touch/controller pins, NXP SDK
integration, device identity and applet/OEF checks, authenticated provisioning,
per-device SCP03 keys, key policies, sealed storage and recovery design, verified
boot/flash encryption/debug policy, fault/side-channel testing, loss-of-power and
rollback tests, watchdog/stack/RAM benchmarks and physical display/input tests.
Never supply seed phrases, private keys or SCP03 secrets in chat or logs.

A software signature test does not demonstrate that an MCU key can never leak.
MCU algorithms need a reviewed implementation and hardware threat assessment;
they cannot inherit SE certification merely because a SE051 is on the board.

### Randomness

Two independent sources, neither trusted blindly:

- **MCU (ESP32-P4).** `RandomSource` is the only way firmware obtains random
  bytes. Raw 32-byte blocks from `esp_fill_random` (the P4 hardware RNG) pass
  continuous health tests before they are used: all-0x00/all-0xFF rejection, a
  set-bit population window of 64..192 per 256 bits (about 8 sigma), and a
  three-in-a-row repetition cutoff. One failure latches the source unhealthy for
  the rest of the boot, `random_fill()` then returns zeroed bytes, and mnemonic
  generation refuses with `CryptoFailure`. Surviving entropy seeds an
  SP 800-90A HMAC-SHA256 DRBG (reseed every 2^20 requests). This is a
  defence-in-depth construction, not a certified module.
- **SE051C2HQ1.** When a custody backend is registered, key generation must
  happen *inside* the card so the card's own TRNG produces the key material. An
  MCU-derived key imported over SCP03 would reintroduce exactly the exposure the
  element is supposed to remove, so the backend contract (`sign_digest`,
  `public_key`) deliberately has no "import private key" operation.

The 32-bit build and the host build compile the same `RandomSource.cpp`; the
host build substitutes a deterministic xoshiro256** stream for `esp_fill_random`
so tests are reproducible while the health tests still run.

## 可信验证（`TrustAnchor`）

“可信验证”被拆成两半，因为它们的失效方式完全不同：设备可信不代表交易是对的，交易对
也不代表固件没被换掉。

### 一、设备信任等级（`TrustAnchor.h`）

| 等级 | 判据 | 含义 |
| --- | --- | --- |
| `verified` | secure boot **且** flash encryption | 代码来源可验、flash 内容加密 |
| `encrypted` | 只有 flash encryption | 数据静止加密，但代码可为攻击者所改 |
| `unprotected` | 两者皆无 | 裸片，仅供台面调试 |
| `unknown` | 平台未回答（主机/未知硅片） | 不做任何宣称 |

数据来源是 eFuse 与应用描述符（`esp_secure_boot_enabled()`、`esp_flash_encryption_enabled()`、
`esp_app_desc_t::app_elf_sha256`），**不是固件自己写的一个字段**。ELF 摘要全零视为“未测量”，
不会被当成“匹配”。

签名路径真的用到了它：

```c
if (!trust_signing_allowed(trust_state())) {
  wallet_signing_clear();
  wallet_ui_set_status("Trusted boot required. Signing refused.");
  return WalletSigningError::Unsupported;
}
```

策略开关是 `HEXWALLET_REQUIRE_VERIFIED_BOOT`，默认 **0**：bring-up 板没烧 eFuse，一上来
就拒绝签名只会让人把保护关掉；量产板必须在构建参数里打开它（
`-DHEXWALLET_REQUIRE_VERIFIED_BOOT=1`）。

### 二、审阅封条（`ReviewSeal`）

签名真正的风险窗口是“用户看到的”和“实际签的”之间。封条把这段窗口钉住：

1. 渲染审阅页时 `review_seal_build()` 把**屏上显示的每一行文字**（带长度前缀、带顺序）
   连同 8 字节 nonce 一起做 SHA-256；
2. 面板确认这一帧真的提交后，`review_seal_mark_displayed()` 才把封条置为已展示；
3. 签名时 `review_seal_authorize()` 重算并对**常量时间**比较；文本变了、过期了、已经用过
   一次，都直接烧掉封条并返回 false。

单次使用是刻意的：一次展示只授权一次签名，重放同一份审阅在密码学上不可行。
自检覆盖了这些情况——多一个尾随空格、两行换序、截断一行、换 nonce、过期、二次使用。

`WalletSigning` 里另外补了一道更粗但更关键的闸：`wallet_signing_sign()` 现在要求
`board_display_review_ready()`，也就是面板必须已经提交完这一帧；一个“批准”如果比它自己
的屏幕活得久，就不再能签任何东西。

### 还没有接上的部分（说清楚）

`ReviewSeal` 已经在库里实现并自检，但 `WalletSigning` 的各 `begin_*` 还没有把各自的
审阅文案交给它——那需要把 14 个链的显示字符串统一进一个结构。当前生效的是“帧已提交 +
单次消费 + 过期”这三层，封条的逐行绑定仍是缺口，不是已完成项。



*Merged from docs/se051-plug-and-trust.md.*

Status: **no backend is registered, so `secure_element_ready()` is false and the
wallet cannot claim secure-element custody.** This page exists so the gap is a
plan with acceptance criteria instead of a claim.

The reference implementation most people reach for is NXP's
[Plug & Trust middleware](https://github.com/NXP/plug-and-trust). It is
separately licensed, it is not vendored in this repository, and its host stack
is far larger than this firmware's entire crypto layer. Nothing below copies it;
the goal is a small, auditable backend that satisfies the same wire protocol.

### What landed

`SecureElementPort.h/.cpp`:

| Piece | Verified by |
| --- | --- |
| ISO/IEC 7816-3 CRC16/A (poly 0x1021, init 0xFFFF) | check value `0x29B1` for `"123456789"` |
| AES-128 forward cipher | FIPS-197 C.1 (`69c4e0d8…b4c55a`) |
| AES-128-CMAC | RFC 4493 §4, all four message lengths |
| Backend contract + gate | host self-tests: unregistered, incomplete, unauthenticated and authenticated paths |

The gate is the part that matters for custody:

- A backend must supply **all** of open, session_authenticated, sign_digest,
  public_key and close, or registration fails.
- Only one backend may be registered per boot.
- If `open()` returns success while `session_authenticated()` is false, the
  backend is **unregistered** and the gate stays closed. This is the exact shape
  of "the card answered but the static keys were wrong", and it must never
  produce a usable custody state.
- `active_secure_element_profile()` returns the SE051C2HQ1 profile only while a
  backend reports an authenticated session, so a profile setter cannot promote
  hardware custody (there is a regression test for that in
  `tests/host/chain/production_policy.cpp`).

### What is deliberately not written yet

| Missing piece | Why it is not here | Accept criteria |
| --- | --- | --- |
| SCP03 key derivation and ICV layout | The derivation-data layout and the command/response ICV conventions have to be validated against the licensed reference implementation or a real card; guessing them would produce a channel that looks right and fails in the field | Golden values for `INITIALIZE UPDATE` + `EXTERNAL AUTHENTICATE` from GPC's own test vectors or from a captured session on the target applet |
| T=1 over I2C framing | NAD/PCB/LEN conventions and the EDC mode are interface-profile facts for this part, not something I can assert from memory | Loopback test on the board: `t1_encode` → card → `t1_decode`, plus abort/resync paths |
| Applet command set (key generate, sign, delete) | This is the NXP applet's private API, not a public spec | Object IDs, key policy, access rules and the exact sign command documented and exercised on hardware |
| Provisioning and SCP03 static keys | Per-device secrets; must never be in git, in chat or in a build log | Factory step with a sealed key store, `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` build, and a provisioning log that records only key IDs |
| Anti-rollback / sealed seed storage | Needs the applet's secure counter and file system | Test that a restored seed cannot reuse a QRL leaf index and that a wiped MCU cannot recover the seed from the card |

Until every row is done, the shipped, tested position stays what the security
review says: MCU-only derivation, `HEXWALLET_REQUIRE_SECURE_CUSTODY=1` refuses
session generation/import, and no coin capability is promoted.

### Wiring a backend (when the parts exist)

1. Implement `SecureElementBackend` in a new translation unit, e.g.
   `se051_backend.cpp`. Keep the static SCP03 keys in a sealed store, never in
   `constexpr` arrays that end up in flash images.
2. `open()` must: power/reset the card, read ATR, `INITIALIZE UPDATE`, verify
   the card cryptogram, `EXTERNAL AUTHENTICATE`, require `0x9000`. Return a
   short ASCII reason otherwise.
3. `session_authenticated()` must re-check the channel, not cache a bool set at
   open time, so a card reset or a failed MAC invalidates it.
4. `sign_digest()` must reject digests the applet policy does not allow, and
   must never return a signature when the card's status word is not `0x9000`.
5. Call `secure_element_register_backend(&backend)` exactly once during boot,
   before `secure_custody_backend_ready()` is consulted.
6. `run_secure_element_self_tests()` must keep passing, and the production
   policy binary must still refuse to open a session without the card.

### Field rules

- The card is the only secret store. The MCU never persists a seed when a
  backend is registered; `HEXWALLET_ENABLE_SECRET_EXPORT` is already forced to 0
  next to `HEXWALLET_REQUIRE_SECURE_CUSTODY`.
- No network code exists in the firmware, and `tests/test_asset_coverage.py`
  fails the build if a WiFi/HTTP/TLS header appears. Transaction data reaches
  the device only through the local USB serial CLI or the NFC phone link.
- Every signing decision is shown on the trusted display first. A card that
  signs whatever it is handed is not a hardware wallet; the review layer is what
  makes the SE useful, and it stays in MCU flash.

## 硬件能力就绪度（由 `tools/hardware_readiness.py` 生成）

*Merged from docs/hardware-readiness.md.*

本表仅搜索去除注释后的源码，提供人工审计入口，不判定硬件能力已经就绪。
`SOURCE_MATCH` 可能是声明、调用或测试；不证明功能、调用链、保密性或实机行为正确。
`NOT_FOUND` 表示当前搜索规则未找到匹配，不能单靠正则表达式证明功能不存在。

| 模块 | 声明 | 状态 | 证据 |
| --- | --- | --- | --- |
| SE051 | I2C presence probe at 0x48 | SOURCE_MATCH | WalletBoardPort.cpp:618 |
| SE051 | SCP03 authenticated session | NOT_FOUND | — |
| SE051 | APDU exchange with the applet | NOT_FOUND | — |
| SE051 | monotonic counter read/increment | NOT_FOUND | — |
| SE051 | PIN verification performed by the element | NOT_FOUND | — |
| SE051 | key object import / non-exportable handle | NOT_FOUND | — |
| SE051 | state sealed by an element-held key | NOT_FOUND | — |
| XMSS | XMSS/WOTS+ signing | NOT_FOUND | — |
| XMSS | Merkle/BDS state held in RAM | NOT_FOUND | — |
| XMSS | BDS state persisted across power loss | NOT_FOUND | — |
| XMSS | anti-rollback leaf index gate (arithmetic only) | SOURCE_MATCH | QrlXmss.cpp:420 |
| XMSS | signature layout pinned to upstream sizes | SOURCE_MATCH | QrlXmss.cpp:410 |
| XMR | address + view/spend key derivation | SOURCE_MATCH | CryptoNoteAddress.cpp:481 |
| XMR | on-device output scan with the view secret | SOURCE_MATCH | CryptoNoteOutputScan.cpp:10 |
| XMR | RCT type-6 parser | SOURCE_MATCH | CryptoNoteBulletproofPlus.cpp:674 |
| XMR | byte-exact transaction rewrite | SOURCE_MATCH | CryptoNoteSigning.cpp:621 |
| XMR | commitment balance check | SOURCE_MATCH | CryptoNoteReview.cpp:342 |
| XMR | CLSAG signing wired into the tx | SOURCE_MATCH | CryptoNoteSigning.cpp:610 |
| XMR | Bulletproofs+ verification | SOURCE_MATCH | CryptoNoteBulletproofPlus.cpp:276 |
| XMR | host-proposed tx review with amount binding | SOURCE_MATCH | CryptoNoteReview.cpp:540 |
| XMR | one-time secret derived per spent output | SOURCE_MATCH | CryptoNoteReview.cpp:467 |
| XMR | view-key export command | NOT_FOUND | — |
| XMR | spend key zeroized after signing | SOURCE_MATCH | WalletSigning.cpp:1061 |
| Platform | second core task pinned | SOURCE_MATCH | WalletWorker.cpp:140 |
| Platform | PSRAM allocator available | SOURCE_MATCH | WalletBoardPort.cpp:45 |
| Platform | decoy matrix / tx context placed in PSRAM | NOT_FOUND | — |
| Platform | P4 low-power core image | NOT_FOUND | — |
| Platform | blocking wait / task yield (not a watchdog guarantee) | SOURCE_MATCH | WalletWorker.cpp:90 |

合计：SOURCE_MATCH 16 / 28。

SE051、可信显示、断电恢复和看门狗等行为仍须核对真实调用链并进行实机验收。

## 开发板接入记录（照片与 E029A182）

*Merged from docs/hardware-e029a182.md.*

### 从照片可以确认的

- 主控：ESP32-S3 模组（板中央偏左，带金属屏蔽罩）。
- 显示：右侧 24-pin 类 FPC 座；面板为 **128×296**、四色（黑/白/红/黄）。
- 输入：四颗丝印 `按键1`–`按键4` 的轻触按键。
- 调试：`MTDI/MTMS/MTDO/MTCK` 测试点，USB-C 在右下。
- 电源：USB-C、充电/保护芯片、电池接口；未见 LoRa/SD 卡座，与之前说明一致。

照片不能给出 GPIO 网络名、按键上拉方式、面板 FPC 引脚顺序、电源轨和电池检测分压。这些
不能靠猜写进固件，否则轻则黑屏，重则把 3.3V/升压脚接错。

### 面板信息的冲突

你提供的是 **英瑞达 E029A182 / SSD1680 / 128×296 / 四色**。公开资料里 SSD1680 常见于
黑白和三色（黑/白/红）2.9 寸屏；四色 2.9 寸屏通常使用 JD79667/UC8151 一类控制器。需要
厂商 demo、datasheet 或 FPC 引脚定义来确认：

1. 控制器真实型号与 4 色 RAM 布局；
2. 初始化命令、LUT、BUSY 极性、最小刷新时间；
3. 四色数据是 2bpp 单平面还是两个 1bpp 平面；
4. 面板 FPC 的 SCK/MOSI/CS/DC/RST/BUSY 与电源脚。

在拿到这些之前，`HEXWALLET_EPD_COLORS=4` 会 fail-closed，不会用黑白/三色序列驱动四色屏。

### 软件侧已经准备好的部分

- `EinkFrame.cpp`：1bpp / 3 色 / 4 色 RGB565 → 原生帧转换，含 MSB-first 2bpp 打包；红色
  先于亮度判断，避免纯红被判成黑色；3 色面板把黄色降级为白色。
- `WalletBoardPort.cpp`：dirty 合并、完整刷新、`powerOn/powerOff`、`board_display_colors()`。
- `WalletUi.cpp`：128 px 宽时使用 12 px 字体和 0.533 缩放；3/4 色主题使用红/黄强调色。
- 这些只是显示管线；面板驱动仍需要上面的硬件证据。

### 下一步需要的文件

- 原理图/PCB 网表（PDF 或 KiCad/AD 工程），至少包含 EPD FPC 和四颗按键的网络名；
- E029A182 的 datasheet、厂商 Arduino/STM32 demo；
- 按键按下时的电平与上拉电阻位置；
- 电池检测分压比和充电状态引脚（如果要在 UI 显示电量）。

