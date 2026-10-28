# ERG / XCH review-to-signature binding

Both chains were closed while the signature could cover data the screen never
showed. This note records what changed, how it is verified, and what still
blocks admission.

## Chia (XCH): the AGG_SIG_ME data field is now computed on the device

chia-blockchain's `make_aggsig_final_message` signs

```
condition_data || coin_name || genesis_challenge      (raw, unhashed)
```

and the standard puzzle fills `condition_data` with
`sha256tree(delegated_puzzle)`. The payload used to carry that value, which meant
a host could hand over a hash for a *different* condition list and the device
would still show — and sign — its own nicely rendered payment.

`ChiaTransaction.cpp` now builds the delegated puzzle itself as
`(q . conditions)` from the CREATE_COIN recipients and amounts it displays,
hashes it with the verified CLVM tree hasher, and uses that hash as the data
field. The payload field was removed (`XCH1` is 141 fixed bytes + reveal +
conditions), so there is no channel left to substitute another condition list.

Verification (all independently computed, then diffed against the firmware):

| Item | Oracle |
| --- | --- |
| `sha256tree((q . conditions))` | `clvm` package tree hash + `chia/wallet/util/curry_and_treehash.py` |
| 96-byte AGG_SIG_ME message | byte-for-byte against the concatenation rule |
| 96-byte signature | `AugSchemeMPL.sign` with the blspy EIP-2333 key |
| coin id, solution, address | blspy + independent bech32m encoder |
| fitness for the probe | `tests/fixtures/chain-sdk.json` case `xch-0` |

**Still closed for signing**: the BLS secret-scalar arithmetic runs on
variable-time `mbedtls_mpi`, so no constant-time backend exists yet. The catalog
therefore keeps XCH at address capability only; the code path is reachable for
tests, not for the UI.

## Ergo (ERG): the review now covers every output and every token

`ergo_review_payload()` used to show one output chosen by a heuristic and a bare
token *count*, so extra outputs and token attachments could be signed unseen.

The rule is now:

* exactly one output may pay a different address; it is the recipient the screen
  names together with its ERG value;
* every token on that output is printed as `T <id8> <amount>`; if the list does
  not fit the 192-byte review area the call fails with `BufferTooSmall` rather
  than truncating;
* a second external output fails with `Unsupported`;
* outputs back to the sending address are summarised as `CHG n`;
* the fee stays `host input total − outputs` and is labelled `HOST`, because an
  offline device cannot know input values — BitTorrent-style UTXO adapters have
  the same property.

Regression payloads in `run_ergo_self_tests()`: the original happy path, a
two-external-output transaction (refused), a payment carrying one token (shown),
and a payment carrying sixteen maximum-size tokens (refused for lack of room).

## QRL: address indices no longer collide

`qrl_seed_from_bip39()` ignored the address index, so every index produced the
same QRL address. The index is now folded into the domain separator
(`HexWallet/QRL/v2`, index as four big-endian bytes) and the self-test asserts
that index 0 and index 1 give different seeds **and** different addresses.

This changes every QRL address derived by this firmware; the previous values were
index-independent and had to be replaced. QRL signing remains unimplemented for
the reasons listed in the QRL section of `chain-signing.md`: no durable
anti-rollback ledger, no BDS state, no independent signature vector.
