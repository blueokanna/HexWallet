# HexWallet Serial Protocol

The serial transport uses printable ASCII command lines at 115200 baud. Secret-bearing commands are accepted only after challenge-response authentication. A session expires after five minutes of inactivity and clears the volatile mnemonic and pending transaction.

## Authentication

1. Provision once with `auth provision <pin> <pin>`. The PIN must contain 8 to 64 printable ASCII characters.
2. Run `auth begin` to receive `salt`, `iterations`, and a random `nonce`.
3. Derive `verifier = PBKDF2-HMAC-SHA256(pin, salt, iterations, 32)`.
4. Send `auth unlock <HMAC-SHA256(verifier, nonce)>`.

The nonce is one-use. Failed proofs increment a persistent retry counter and apply exponential backoff. `tools/HexWalletAuth.ps1` calculates the proof without placing the PIN in command history.

## Catalog And Addresses

`coin list`, `coin search <text>`, and `coin show <id>` report the SLIP-0044 number and independent `address`, `review`, and `sign` capabilities. An unsupported catalog entry cannot be passed to address derivation.

After authentication and wallet generation/import, use `wallet address <id> [index]` for one network or `wallet addresses [index]` for every implemented address profile. `wallet secret [index]` deliberately exports the mnemonic, seed, master private key, chain code, xprv, and derived private keys inside `BEGIN SENSITIVE` / `END SENSITIVE` markers.

## Bitcoin Signing

`tx inspect <hex>` accepts a hexadecimal PSBT v0 up to 4096 bytes. The request must contain:

- one unsigned Bitcoin version 1 or 2 transaction;
- 1 to 8 inputs, each with an empty scriptSig;
- a `witness_utxo` native P2WPKH script with `m/84'/0'/account'/change/index`, or a P2SH script with a matching P2WPKH `redeem_script` and `m/49'/0'/account'/change/index`, for every input;
- one matching BIP32 derivation per input under the loaded master fingerprint;
- 1 to 16 P2WPKH, P2PKH, or P2SH outputs;
- optional BIP32 output derivations only when they match a wallet P2WPKH output;
- absent sighash metadata or exactly `SIGHASH_ALL`.

Unknown PSBT fields, duplicate fields, non-canonical CompactSize values, unknown scripts, excessive counts, foreign fingerprints/paths, mismatched public keys, mismatched BIP49 redeem scripts, amount overflow, fees above 1,000,000 sat, or estimated fee rates above 500 sat/vB are rejected.

On success, the device prints `BEGIN TRANSACTION REVIEW`, every output and its ownership, totals, fee, estimated vbytes/rate, and a review ID. It then emits a six-digit confirmation code valid for two minutes. `tx sign <code>` signs once and clears the review whether confirmation or signing succeeds or fails. The result is a complete witness transaction in `signed-transaction=` plus its `wtxid`.

The CLI does not accept raw hashes, arbitrary messages, host-provided private keys, alternative sighash flags, or unreviewed transactions.
