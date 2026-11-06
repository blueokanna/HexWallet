# Testing

[中文](Testing-zh) · [Home](Home)

There is one rule behind this page: a claim without a test that can fail is not a claim. Everything
below runs locally, and the same commands run in CI.

## The main host suite

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/build.ps1
```

Compiles the firmware sources with MSVC against the mbedTLS headers from the exact ESP32 core, then
runs `host_test.exe`. 72 labelled checks print one line each, for example:

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

## What a green run means

It means the code matches the vectors and the reference implementations in this repository. It does
**not** mean:

- a node will accept the transaction; no test in this tree broadcasts anything;
- the device resists a physical attacker;
- the SE051 accepts these APDUs on a real card;
- the panel, touch controller, NFC front end or camera work on your board;
- the byte sequences are free of side-channel leakage.

Those gaps are why the project is described as pre-hardware in [Home](Home).

## Adding a test

1. Put the vector in `src/generated/` or `tests/fixtures/` with its source and hash.
2. Add a `run_*_self_tests()` that returns false on the first mismatch, and a named line in the
   host harness.
3. If the code is reachable from host input, add a refusal test for the malformed case, not just the
   happy path.
4. Run `build.ps1` and `policy_check.ps1` before opening a pull request.
