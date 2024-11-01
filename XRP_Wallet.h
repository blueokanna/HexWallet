#ifndef __XRP_WALLET_H_
#define __XRP_WALLET_H_

void generate_xrp_address(const uint8_t *private_key, char *xrp_address, size_t xrp_address_len) {
  if (!is_private_key_valid(private_key)) {
    Serial.println("Error: Private key is not Vaild.");
    return;
  }

  uint8_t pubkey[33];
  uint8_t sha256_hash[32];
  uint8_t ripemd160_hash[20];
  uint8_t versioned_payload[21];

  // 1. 生成压缩公钥
  if (generate_compressed_pubkey(private_key, pubkey) != 0) {
    Serial.println("Error: Generated Compressed PublicKey failed.");
    return;
  }

  if (pubkey[0] == 0x00) {
    Serial.println("Error: Public Key is zero.");
    return;
  }

  size_t pubkey_len = sizeof(pubkey);
  mbedtls_sha256(pubkey, pubkey_len, sha256_hash, 0);
  local_ripemd160(sha256_hash, 32, ripemd160_hash);

  versioned_payload[0] = 0x00;
  memcpy(versioned_payload + 1, ripemd160_hash, 20);
  if (sizeof(versioned_payload) > 21) {
    Serial.println("Error: Payload is over memory.");
    return;
  }

  if (ripple_base58checkEncode(versioned_payload, sizeof(versioned_payload), xrp_address, &xrp_address_len)) {
    xrp_address[xrp_address_len] = '\0';  // 确保字符串终止
  } else {
    Serial.println("Error: XRP Base58 check encoding failed.");
  }
}
#endif