"""Extract upstream verifier bodies without edits, checking normalized SHA-256.

Ryo:  https://github.com/ryo-currency/ryo-currency/tree/185dd1fa33ba88c88bb22df9069ad368c0f9a27e
Zano: https://github.com/hyle-team/zano/tree/b543053953f74c38a32d29a087ec586943b4a321
Pass their source directories and the CMake binary directory. No network access.
"""
import hashlib
from pathlib import Path
import re
import sys

ZANO_HASHES = {
    "src/crypto/clsag.cpp": "92dcb909d2404a392a99416ee90ee477daa1807a8b91d9ba0d4ba6b0e57b4790",
    "src/crypto/crypto-sugar.h": "097ae8e1783303122894ac544d6b55dbd635ee16edb6d7d019a1e4520e99372c",
    "src/crypto/crypto-ops.c": "9c08e2d655566b25ac3374f48a23d1228a1b14ec816dfeca4aba5f46fab81f45",
    "src/crypto/crypto-ops-data.c": "9f6985cea023518d987ee90cd754c5bb964fb2c682e9bec80c8a19c471ac3aa0",
    "src/crypto/crypto-ops.h": "8c05b09b186c8e49547089c7b6ce124b6dfccc39e34cf20b81a6642c51b00a5b",
    "src/crypto/hash.c": "8f6c0c754eb0c631f04d768500ebd4aea6110ff70ab40ea384b63cd9fc5871fa",
    "src/crypto/hash-ops.h": "ab46bc90c5335ab4a1e29b95a38bd7ae118c6ad3507c85f254ae77acf072f933",
    "src/crypto/keccak.c": "fd4d972379721e4aa61c9996538ca50cb6b6c841e625508603805d316ebf52b4",
    "src/crypto/keccak.h": "ecb19d8801657838d28b5b4ec70455e582dc2e04e8f8295b61e6a01abd4cb1c0",
    "src/currency_core/crypto_config.h": "52f9481f26ec1e74089f4c8dcd0c6e182a0eaa594f6c544594a21353d53480a5",
    "contrib/epee/include/warnings.h": "338ac68b899bd295a33399eba9f95e19f0810d4d81a420fdbb2b1b16be867ec4",
    "src/common/int-util.h": "5316946817e8ee2142a681d3bf9bf56d455e7f0375ef346dbc45344d52808704",
}


def checked(root, name, digest):
    data = (root / name).read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f"Upstream source hash mismatch: {root / name}")
    return data.decode("utf-8")


def function(text, name):
    start = text.index(f"bool {name}(")
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    # Preserve the upstream copyright/license header alongside the function.
    header = text[:text.index("#include")]
    return header + "\n" + text[start:end] + "\n"


def main():
    ryo, zano, out = map(Path, sys.argv[1:])
    ryo_text = checked(ryo, "src/ringct/rctSigs.cpp",
                       "d59f92e548c61f0e7e8991e2d0f3768b3c9bda6a30a9344d43ffea57df9d85d2")
    bp_text = checked(ryo, "src/ringct/bulletproofs.cc",
                      "a22370878661c3a2aa6f967a44456f073127bf50caf4cec3b19b82bd94418d2c")
    checked(ryo, "src/ringct/multiexp.cc",
            "57d1d9540046fee71a237bf74e1b396c5fe74d6bf201fb5362c446925d23cf28")
    texts = {p: checked(zano, p, digest) for p, digest in ZANO_HASHES.items()}
    out.mkdir(parents=True, exist_ok=True)
    (out / "ryo_verifier.inc").write_text(function(ryo_text, "MLSAG_Ver"), encoding="utf-8")
    (out / "ryo_bulletproof_verifier.inc").write_text(function(bp_text, "bulletproof_VERIFY"), encoding="utf-8")
    (out / "zano_verifier.inc").write_text(function(texts["src/crypto/clsag.cpp"], "verify_CLSAG_GGX"), encoding="utf-8")
    sugar = texts["src/crypto/crypto-sugar.h"]
    constants = sugar[:sugar.index("#pragma once")]
    for name in ("G", "X"):
        limbs = re.search(r"c_point_" + name + r"\s*\{\{(.*?)\}", sugar).group(1)
        constants += f"\nconst point_t c_point_{name}(ge_p3{{{limbs}}});\n"
    (out / "zano_constants.inc").write_text(constants, encoding="utf-8")
    domains = "\n".join(line for line in texts["src/currency_core/crypto_config.h"].splitlines()
                        if line.startswith("#define CRYPTO_HDS_CLSAG_GGX_"))
    (out / "zano_domains.inc").write_text(domains + "\n", encoding="utf-8")
    print("Pinned Ryo/Zano verifier source hashes: pass")


if __name__ == "__main__":
    main()
