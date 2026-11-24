"""Restore reviewed icon assets and verify both download and local PNG digests."""
import hashlib
import io
import json
import re
import urllib.request
from pathlib import Path
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[1] / "assets/icons"


def restore(row):
    name = row["file"]
    if not re.fullmatch("[a-z0-9]+", name):
        raise ValueError(f"Invalid icon filename {name!r}")
    target = ROOT / "32" / f"{name}.png"
    expected = row["sha256"]
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ValueError(f"{target} differs from its reviewed artwork")
        return
    request = urllib.request.Request(row["url"], headers={"User-Agent": "HexWallet asset restore"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != row.get("source_sha256", expected):
        raise ValueError(f"Provider artwork changed for {name}")
    if hashlib.sha256(raw).hexdigest() != expected:
        from PIL import Image
        with Image.open(io.BytesIO(raw)) as image:
            buf = io.BytesIO()
            image.convert("RGBA").save(buf, format="PNG")
            raw = buf.getvalue()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"PNG conversion differs for {name}. Restore the reviewed PNG from git.")
    with NamedTemporaryFile(dir=target.parent, delete=False) as temp:
        staged = Path(temp.name)
    try:
        staged.write_bytes(raw)
        staged.replace(target)
    finally:
        staged.unlink(missing_ok=True)


if __name__ == "__main__":
    records = json.loads((ROOT / "sources.json").read_bytes())
    manifest = [line.split() for line in (ROOT / 'icons.txt').read_text().splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
    if manifest != [[row['file'], *row['keys']] for row in records]:
        raise ValueError('Icon keys or order differ between icons.txt and sources.json')
    for record in records:
        restore(record)
    print(f'Verified {len(records)} asset images')
