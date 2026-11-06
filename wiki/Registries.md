# Registries

[中文](Registries-zh) · [Home](Home)

Four compile-time tables decide what the device knows about the world. All four are generated or
audited in the repository; none is fetched at runtime.

| Registry | Size | Source | Generator / check |
| --- | --- | --- | --- |
| Network profiles | 247 | `WalletNetworks.cpp` + `src/generated/WalletForkProfiles.inc` | `tools/fork_registry.json`, checked by `policy_check.ps1` |
| Wallet catalog | 215 entries | `WalletCatalog.cpp` + generated fork catalog | `tests/host/catalog_dump.exe` |
| Token records | 80 across 19 networks | `WalletTokens.cpp` | `tools/token_audit.ps1`, `tests/host/evm_access_list_check.ps1` |
| Mining identities | 121 of 520 listings | `src/generated/WalletMiningCatalog.inc` | `tools/generate_mining_catalog.py --check` |

The cryptographic primitives carry the same rule. `src/generated/Blake3VectorsTest.inc` holds the 35
official BLAKE3 cases (hash, keyed hash and `derive_key`, 131 bytes each) re-encoded from the vendored
`tools/blake3_test_vectors.json`; `tools/generate_blake3_vectors.py --check` fails when the include
drifts from it, and `Blake3Kat.inc` keeps three of those cases in the firmware so the device checks
its own compression function too.

## Networks and the catalog

A network profile is an encoding plus a signing policy. A catalog entry is what a user sees: an id,
a ticker, a name, a coin type, capability bits and a status line. Several entries can share one
profile family (`btc`, `btc49`, `btc44`, `btc86`).

The catalog never advertises a capability the policy does not grant: `resolved_entry()` raises the
review/sign bits only when `find_network_signing_policy()` returns a policy for that network.

Adding a network means adding a profile, a policy if it can sign, and a catalog row — plus tests.
See [Admission-Policy](Admission-Policy).

## Tokens

- **Pinned records** (`WalletTokens.cpp`) bind chain IDs to contracts and display metadata.
  There are 80 records on 19 networks, including the ENS Base Registrar and Name Wrapper.
- **User-declared records**: up to 64 assets (`kCustomTokenMax`), stored in NVS as `HXCT` version 2
  with a digest. They are labelled as declared on the review screen and never change the signed
  bytes. EVM, Stellar and NFT declarations exist; an NFT declaration does not enable NFT transfers,
  because no NFT contract registry exists.
- **No host-supplied decimals.** An unknown token renders its exact base-unit amount, e.g.
  `1500000 raw`, rather than guessing a decimal point.

## Mining identities

`tools/miningpoolstats_snapshot.json` pins the source and its SHA-256; `miningpoolstats_mapping.json`
is the reviewed mapping from source id to wallet profile. The generator refuses a snapshot whose
hash changed, refuses a 已撤回资产 mismatch, and writes both the C++ table and the public coverage
report.

Current numbers: 520 active listings, 121 mapped, 98 distinct wallet profiles, 93 of them with a
signing path. The rest are unmapped on purpose; a mining-site listing is not a wallet-support claim.

## Where to change what

| Task | Edit | Then run |
| --- | --- | --- |
| add a UTXO fork | `tools/fork_registry.json` | regenerate profiles, `policy_check.ps1` |
| add an EVM network | `WalletNetworks.cpp` | `catalog_dump.exe`, `policy_check.ps1` |
| pin a token | `WalletTokens.cpp` | `tests/host/build.ps1`, `token_audit.ps1` |
| update mining data | replace the snapshot + mapping | `generate_mining_catalog.py`, `mining_catalog_test.py` |
| add a native chain | new adapter + profile + policy | vectors, catalog row, admission tests |

Do not hand-edit a generated file. CI runs every generator with `--check`; a stale file fails the
build.
