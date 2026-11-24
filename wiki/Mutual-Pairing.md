# 双向配对记录 / Mutual pairing records

[手机链路](Phone-Link-zh) · [Phone link](Phone-Link) · [验收与缺口](Wallet-Hardening-2026-11-24)

初次配对的密码学状态机已实现并通过 Node／原生交叉验证。7 号板相机仍只有探测，没有 CSI 收流与扫码；固件尚未连接本机挑战显示、相机输入和手机应用，因此实机双向扫码及 NFC 初次配对仍未完成。传输层单独提交自签公钥会被拒绝。

The enrollment state machine is implemented and tested against Node crypto. Camera delivery and the panel decision are simulated in the tests. Board 7 still lacks capture and QR decoding, and the local offer display and phone application are not connected. USB/NFC alone cannot enroll a new key.

## 固定字节格式 / Fixed binary records

All sizes below are bytes. Labels are ASCII without a terminating NUL. QR data uses byte mode; implementations must preserve zero bytes and must not convert the records to UTF-8 text. `H` is SHA-256 and signatures are Ed25519.

| Record | Signed fields | Signature | Total |
| --- | --- | --- | ---: |
| Device offer | `HWQP` (4), version `01`, role `01`, reserved `00 00`, device identity (32), fresh random challenge (32) | `Sign(device, "HWPAIR1-OFFER" || fields)` (64) | 136 |
| Phone reply | `HWQP` (4), version `01`, role `02`, reserved `00 00`, `H(complete offer)` (32), phone identity (32), fresh phone nonce (32) | `Sign(phone, "HWPAIR1-REPLY" || fields)` (64) | 168 |

The phone verifies the offer signature and retains its device identity. The device verifies the reply signature and the offer hash. An accepted reply pins both the phone identity and nonce for that attempt. A later reply cannot replace either value. Wrong lengths, versions, roles, reserved bytes, hashes or signatures fail.

手机验证挑战自签名并保存设备身份；设备核对回复签名及完整挑战的哈希。首次有效回复固定本次手机公钥与 nonce，后续不能替换。完整挑战包含设备身份、随机数和签名，回复不能移用于不同挑战或设备。

## 顺序与生命周期 / Sequence and lifetime

1. A trusted local action calls `begin_pairing_offer()`. The device must be initialized, unpaired, and outside an encrypted session or another enrollment attempt. The 60-second deadline starts here.
2. The phone scans the displayed offer and constructs the signed reply. `tools/pairing_qr.cjs` exports `PairingEnrollment` for this binary record logic; it is not a camera or a full phone application.
3. The device camera calls `accept_pairing_scan()` with the reply. No USB/NFC application opcode maps to this function. The service rejects calls during transaction, CLI or OTP review.
4. The phone sends the ordinary v2 `PairRequest` over USB or NFC, using the identity and nonce from the scanned reply. A valid but different request is rejected without replacing the pending identity.
5. The device displays all 32 bytes of the phone identity as 64 hex digits and a comparison code. Both sides compute `BE24(H("HWPAIR1-CODE" || PK_phone || H(offer) || nonce_phone)[0:3]) mod 1000000`, formatted as six digits. Approval still requires the local hold action.
6. The phone retries the pair request and verifies the response against the device identity from the original scan and its retained nonce. It then pins that identity for the signed X25519 session handshake.

Cancellation, reset, timeout and successful persistence clear the temporary enrollment state. Scanning does not extend the deadline. Already paired phones retain the existing reconnect behavior; this change does not retroactively attest how an older pairing was established.

取消、复位、超时及成功保存均清除临时挑战、回复身份和 nonce。扫码不会延长时限。已有配对沿用原有重连流程；新规则不为旧配对补发真实性证明。

## 安全边界 / Security boundary

The physical scan must originate from the wallet and phone that the user intends to pair. A signed offer authenticates possession of a key, not manufacturing provenance. This design has no manufacturer certificate chain, distance bounding, formal proof or measured resistance to optical/NFC relays and side channels. The six-digit code is a comparison aid; it does not replace signatures or the two trusted scans. Addresses remain separately derived and checked on the device per network and path; the enrollment record does not bind an account address.

设备与手机的可信扫描来源是前提。当前没有厂商证书链、距离界定或抗光学／NFC 中继实测，不能宣称达到 Tangem 的整机安全等级。六位码仅用于辅助核对。收款地址仍按网络和路径独立派生及核对，本记录没有绑定账户地址。NFC 承载已认证帧，不会因为距离短而自动获得扫码权限。

## 复现 / Reproduce

```powershell
node tests/host/pairing_qr_check.cjs build/audit-native/Release/chain_probe.exe
build/audit-native/Release/chain_probe.exe security-regressions
build/audit-native/Release/chain_probe.exe phone-pairing-ui
build/audit-native/Release/chain_probe.exe phone-pairing-lifecycle
```

The first command compares independently generated Node signatures/hashes with the real firmware implementation. It exercises offer corruption, reply corruption, replacement identities/nonces, missing scans, cancellation, expiry, fresh challenges, old reply/request replay, and device response pinning. It then verifies the signed X25519 handshake, HKDF, ChaCha20 and HMAC against Node, including complete 16 KiB requests and responses, replay, oversized frames and ciphertext tampering. The native self-test mutates every reply byte. Service tests check the full UI identity, cross-device replies, NVS open/write/commit failure, competing reviews, the exact 60-second boundary, uint32 clock rollover, NFC field loss, USB/NFC ownership and one-time persistence. Storage and peripherals are simulated; flash power-loss behavior still needs hardware testing.
