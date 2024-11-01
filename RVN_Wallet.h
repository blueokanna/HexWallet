#ifndef __RVN_WALLET_H_
#define __RVN_WALLET_H_

void generate_rvn_address(const uint8_t *private_key, char *rvn_address, size_t rvn_address_len) {
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

  // 4. 添加版本字节（0x00 for Bitcoin）
  versioned_payload[0] = 0x3C;
  memcpy(versioned_payload + 1, ripemd160_hash, 20);
  if (sizeof(versioned_payload) > 21) {
    Serial.println("Error: Payload is over memory.");
    return;
  }

  if (base58checkEncode(versioned_payload, sizeof(versioned_payload), rvn_address, &rvn_address_len)) {
    rvn_address[rvn_address_len] = '\0';  // 确保字符串终止
    //Serial.print("Bitcoin Address (Base58): ");
    //Serial.println(btc_address);
  } else {
    Serial.println("Error: RVN Base58 check encoding failed.");
  }
}
#endif