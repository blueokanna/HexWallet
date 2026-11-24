# Testing

[中文](Testing-zh) · [Home](Home)

There is one rule behind this page: a claim without a test that can fail is not a claim. Everything
below runs locally, and the same commands run in CI.

## The main host suite

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
```

Compiles the firmware sources with MSVC against the mbedTLS headers from the exact ESP32 core, then
runs `host_test.exe`. Each check prints its own result. Typical labels include the following.

```text
crypto-primitives=pass      bip39=pass              bip32=pass
bip84=pass                  evm-derive=pass         address=pass
sighash=pass                kaspa=pass              zcash=pass
dash=pass                   cryptonote-clsag=pass   bulletproof-plus=pass
cryptonote-review=pass      cryptonote-signing=pass cryptonote-mainnet=pass
blake3=pass                 blake2b=pass            groestl512=pass
cli-policy=pass             battery=pass            kangarootwelve=pass
qrl-xmss=pass               qrl-ots=pass            ml-dsa-87=pass
starknet-crypto=pass        solana=pass             xrp=pass
cosmos=pass                 stellar=pass            algorand=pass
near=pass                   tezos=pass              totp=pass
link-crypto=pass            wallet-link=pass        nfc-apdu=pass
se051-apdu=pass             scp03=pass              trust-anchor=pass
random-source=pass          catalog=pass            mining-catalog=pass
```

The suite also builds `link_pipe.exe` (phone-link harness), `nfc_port_test.exe`,
`worker_execution_test.exe`, `catalog_dump.exe` and the per-chain probes. A failure exits non-zero
and names the check.

| Suite | Proves |
| --- | --- |
| `build_clang_ubsan.ps1` | the same sources build under clang with UBSan; undefined behaviour in the exercised paths is reported |
| `build_chain_native.ps1` | the chain code links against a real mbedTLS 3.6.5, not the host shim |
| `device_compile_check.ps1` | every pure-C++ firmware file compiles for Xtensa (S3) and, with `-Target esp32p4`, for RISC-V; `-StackBudget 5120` also fails when a frame that runs on the 32 KB Arduino loop task grows past one sixth of that stack, and the production CLI object is checked for any reference to the self-test suites (that reference is what used to keep 546 KB of test scratch in `.bss`) |
| `p4_runtime_compile_check.ps1` | the worker and signing orchestration compile for the P4 |
| `board_port_compile_check.ps1` | `WalletBoardPort.cpp` + `WalletUi.cpp` compile for every board profile against real LVGL 9.5 headers |
| `epd_driver_compile_check.ps1` | the GxEPD2 path compiles against the pinned commit |
| `se051_port_check.ps1` (+ `-Device`) | SE051 transport fault behaviour, then the real P4/Arduino headers |
| `ui_check.ps1` | LVGL object lifetime, review rendering and mascot regressions |
| `qr_cross_check.ps1` | all version/level/mask matrices match nayuki/QR-Code-generator |
| `evm_access_list_check.ps1` | EIP-2930 vectors produced independently |
| `policy_check.ps1` | 已撤回资产 exclusion, withdrawn-chain pins, mining resolution, no network stack, custody refusal, unbounded-copy baseline |
| `admission=` in the host suite | no refused identity (`WalletAdmission.cpp`) resolves to a network profile or a catalog entry; runs on the device boot self-test too |
| `policy_check_test.ps1` | the policy checker itself fails when it should |
| `tests/host/auth` (CMake) | TOTP, transport matrix and local approval |
| `mining_catalog_test.py` | pinned MiningPoolStats identities |
| `generate_mining_catalog.py --check` | the committed tables and report match the generator |
| `native_coverage.ps1` | regenerates the capability matrix from the compiled objects |

## Independent audit harnesses

These compare the firmware against something that is not the firmware:

| Harness | Oracle |
| --- | --- |
| `tests/host/psbt_audit/run.ps1` | BIP32/Schnorr, BIP371 v0/v2 parsing, change ownership, final witness verification |
| `tests/host/taproot_audit/run.ps1` | the published BIP341 wallet vectors, plus locally derived annex-length cases; source hashes are recorded so a run is rejected if sources move mid-test |
| `tests/host/pearl_audit/run.ps1` | pearl-research-labs/pearl at a pinned commit, executed with Go; six public fixtures, both PSBT versions, negative cases |
| `tests/host/qrl_oracle_check.ps1` | qrllib's `xmss_Signmsg` byte for byte |
| `tests/host/qr_cross_check.cpp` | nayuki QR reference |

## Payment and browser tests

Run `python tests/host/privacy/payment_interop.py --probe <chain_probe.exe>` from the repository root. The 116 checks cover Ryo v3 recipient and change in either order, uniform payment IDs, one- and two-input signing, and Zano post-HF6 output construction and scanning. The Ryo signer checks funding ownership, ring indices, amounts, the range proof and the fork's fee floor. A balanced payment one atomic unit below the floor fails review. The Zano scanner checks the asset ID, amount and commitment for explicit native and blinded assets. Pass `--oracle <privacy_oracle.dll>` to verify each Ryo input with the pinned upstream MLSAG implementation. Release and ASan/UBSan passed.

With the locked `tests/host/protocol-oracles` dependencies installed, `privacy/address_interop.cjs` under `tests/host` checks the phone `ADDRESS` response and panel callback against independently derived keys and CryptoNote Base58. Run `python tests/host/privacy/native_rpc_check.py --probe <chain_probe> --ryod <ryod> --ryo-validator <ryo-address-validator> --zanod <zanod>` to repeat the release-binary checks. It creates temporary offline nodes and checks the Ryo relay refusal and empty mempool at genesis.

For funded Ryo payments, run `python tests/host/privacy/ryo_ledger_check.py --probe <candidate-probe> --oracle <privacy_oracle.dll> --ryod <ryod> --wallet-rpc <ryo-wallet-rpc>`. Build the candidate probe with `TEST_RYO_PHONE_PAYMENTS=ON`. Stock `ryod` confirms one- and two-input payments. Stock `ryo-wallet-rpc` independently recovers their amounts and 32-byte payment IDs with the recipient's view key. `phone_payment_check.py` also exercises rejection, cancellation, expiry, field loss, single-use approval, the fee cap and the 16,384-byte application frame. [Receipts](validation)

With the locked `tools` dependencies installed, run `node tests/host/privacy/zano_ledger_check.cjs <chain_probe>` offline. The fixtures include the original transaction bytes and all 48 ring entries for two mainnet payments. The test checks the node's prefix hash, fee, byte-for-byte encoding, firmware CLSAG_GGX verification and phone proof verification. It rejects every truncated prefix and mutations of the fee, ring, signature or proof. The release catalog exposes addresses for both currencies.

Build a second probe with `-DTEST_ZANO_PHONE_PAYMENTS=ON`. Run `node tests/host/privacy/zano_phone_check.cjs <candidate-probe> <default-probe>` to exercise simulated approval and phone verification of new one- and two-input payments. `zano_private_ledger.py` uses a pinned testnet daemon with accelerated fork heights. It mines mature funds, checks pool admission and block inclusion, and compares the submitted bytes to the node's record. An upstream watch-only wallet independently finds both transactions by their eight-byte payment ID. The setup and exact commands are in `tests/host/privacy/README.md`. [Receipts](validation)

`tests/host/ethereum_ledger_check.cjs <chain_probe> <anvil> [archive-rpc]` submits the approved result to a local Anvil node. Install the locked wallet dependencies with `npm ci --prefix tools --ignore-scripts` and include `tools/node_modules` in `NODE_PATH`. For real browser discovery also install `playwright-core@1.55.0` in a test directory, add its `node_modules` to `NODE_PATH` and set `HEXWALLET_BROWSER` to the Chromium executable. The archive run pins Ethereum block 20,000,000 and checks the ETH balances, Lido shares, USDC output and ERC-721 owner. Rejection, field loss during review and an RPC chain change after signing must yield zero broadcasts. The application pipe models the panel decision and phone transport.

Native-node and SDK coverage varies by currency. Real-card authentication, side-channel resistance, panel timing and phone NFC interoperability require hardware evidence. [Per-chain receipts](validation)

## Adding a test

1. Put the vector in `src/generated/` or `tests/fixtures/` with its source and hash.
2. Add a `run_*_self_tests()` that returns false on the first mismatch, and a named line in the
   host harness.
3. If the code is reachable from host input, add a refusal test for the malformed case, not just the
   happy path.
4. Run `build.ps1` and `policy_check.ps1` before opening a pull request.
