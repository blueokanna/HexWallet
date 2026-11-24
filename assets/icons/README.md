# Asset icons

The device ships the catalog logos as 32 × 32 monochrome bitmaps. Each logo occupies 128 bytes of flash. Network aliases share artwork. The catalog resolves symbols by exact match and the firmware draws from compiled data.

## Sources

The manifest records the provider, project identifier, URL and SHA-256 of each packaged PNG. For images converted from a different encoding it also records the downloaded file digest. The CC0 license applies to the cryptocurrency-icons collection. Provider-hosted artwork retains its respective rights. [Artwork manifest](sources.json) · [CC0 license](LICENSE)

## Rebuild

Run the following command from the repository root to repack the checked-in files offline.

```powershell
./tools/pack_coin_icons.ps1
```

To restore a missing source file, run `./tools/download_coin_icons.ps1`. It verifies the pinned digest before installing a file and repacks the complete directory. Conversion from WebP or JPEG requires Python and Pillow. A changed upstream image requires identity and artwork review before updating its digest.

The packer resamples each logo, thresholds luminance over opaque pixels and falls back to its alpha silhouette for flat artwork. The output uses MSB-first rows and the display theme supplies the foreground and background colors. [Generated table](../../src/generated/CoinIcons.inc)
