"""Independent SCP03 S8 oracle using the system OpenSSL executable.

No firmware implementation is imported. GP Amendment D 4.1.5 and 6.2 define
the layouts below. These are reproducible derived fixtures, not official GP
conformance vectors and not hardware interoperability evidence.
"""
import subprocess

OPENSSL = r"C:\msys64\usr\bin\openssl.exe"

def run(arguments, data):
    return subprocess.run([OPENSSL] + arguments, input=data, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def mac(key, data):
    result = run(["dgst", "-mac", "CMAC", "-macopt", "cipher:AES-128-CBC",
                  "-macopt", "hexkey:" + key.hex(), "-binary"], data)
    assert len(result) == 16
    return result

def encrypt(key, iv, data):
    return run(["enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(),
                "-nopad", "-nosalt"], data)

def pad(data):
    return data + b"\x80" + bytes(15 - len(data) % 16)

context = bytes(range(1, 9)) + bytes(range(17, 25))
def kdf(key, label, bits):
    return mac(key, bytes(11) + bytes([label, 0]) + bits.to_bytes(2, "big") + b"\x01" + context)

# Pin the oracle's CMAC primitive to RFC4493 example 1 first.
assert mac(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), b"").hex() == "bb1d6929e95937287fa37d129b756746"
enc = kdf(bytes([0x0b]) * 16, 4, 128)
cm = kdf(bytes([0x1c]) * 16, 6, 128)
rm = kdf(bytes([0x1c]) * 16, 7, 128)
card, host = kdf(cm, 0, 64)[:8], kdf(cm, 1, 64)[:8]
auth = bytes.fromhex("8482330010") + host
chain = mac(cm, bytes(16) + auth)
print("enc", enc.hex()); print("mac", cm.hex()); print("rmac", rm.hex())
print("card", card.hex()); print("host", host.hex()); print("auth", (auth + chain[:8]).hex())
for counter in (1, 2):
    block = counter.to_bytes(16, "big")
    command_iv = encrypt(enc, bytes(16), block)
    cipher = encrypt(enc, command_iv, pad(bytes(range(0x40, 0x55))))
    header = bytes.fromhex("8414000028")
    chain = mac(cm, chain + header + cipher)
    print("command" + str(counter), (header + cipher + chain[:8]).hex())
    response_block = bytes([0x80]) + block[1:]
    response_iv = encrypt(enc, bytes(16), response_block)
    response = encrypt(enc, response_iv, pad(bytes.fromhex("deadbeef")))
    response_mac = mac(rm, chain + response + bytes.fromhex("9000"))[:8]
    print("response" + str(counter), (response + response_mac + bytes.fromhex("9000")).hex())
