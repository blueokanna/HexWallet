# DS-CHAN display assets

`deepseek-maid-sheet.png` was generated with the built-in image generation tool
from the user's supplied character reference. It is a new interpretation, not
official DeepSeek artwork. The firmware uses only the packed monochrome output;
no image model, image decoder or network service runs on the wallet.

Generation brief: original chibi whale girl, long dark wavy hair, whale-tail hair
curl, maid headband, modest dress, white apron, shoes and whale tail. Black and
white, no lettering, no logos, no dithering. Four columns and two rows, with calm,
blink, happy wave, attentive, sleep, bowl, shy and playful poses in that order.

Run `powershell -ExecutionPolicy Bypass -File tools/pack_maid_sprite.ps1` from the
repository root to reproduce `src/generated/MaidSprite.inc` and the enlarged
preview. Each pose is 64 × 64 pixels, MSB first, eight bytes per row. Eight poses
consume 4096 bytes of read-only pixel data. The script resamples each cell with
bicubic interpolation and thresholds luminance at 160; the final pixels have
exactly two colours. `deepseek-maid-preview.png` shows those exact pixels at 4×.

Only calm/blink animates; other poses are static. Alert, angry and working share
the attentive pose, with their state shown as text. This is an eight-pose asset,
not nine complete animation sequences. A 128-pixel-wide display uses a vertical
home layout. The companion does not appear in transaction review, and approving
or rejecting a transaction never changes affection or level.
