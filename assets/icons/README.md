# Coin icons

These are the only images the wallet paints next to a transaction, and they are
shipped as pre-packed pixel data because the firmware has no PNG decoder, no
filesystem and no business decoding untrusted images.

## Provenance

- Upstream: <https://github.com/spothq/cryptocurrency-icons>
- Path used: `32/icon/<ticker>.png` (32x32 PNG with alpha)
- Licence: CC0 1.0 Universal (public domain dedication). The upstream text is
  kept verbatim in [LICENSE](./LICENSE).
- Downloaded on 2026-10-29, one file per ticker listed in
  [icons.txt](./icons.txt). Nothing was redrawn, recoloured or "restored"
  locally: if upstream has no artwork for a ticker, the wallet shows no icon.

Chains without upstream artwork (NEAR, TON, CKB, KAS, SUI, HIVE, OSMO, TIA)
stay in that state. A plausible-looking substitute would be a lie on the one
screen where the user is deciding whether to move money, so the review row
degrades to text.

## Regenerating

```
powershell -ExecutionPolicy Bypass -File tools/pack_coin_icons.ps1
```

The packer rasterises each PNG to 32x32 with high-quality resampling, un-multiplies
the edge alpha GDI+ reports (otherwise transparent edges come out darkened),
converts to RGB565 plus an 8-bit alpha plane, and refuses any icon that covers
less than 20% of the canvas - that check is what catches a mis-mapped or empty
file before it reaches flash.

Output: `src/generated/CoinIcons.inc` (data + key table), consumed by
`CoinIcons.cpp` (repo root, like every other module).
