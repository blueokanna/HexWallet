#ifndef __LITE_WALLET_H_
#define __LITE_WALLET_H_

void generate_ltc_address(const uint8_t *private_key, char *lite_address, size_t lite_address_len) {
  uint8_t public_key[33];
  uint8_t sha256_hash[32];
  uint8_t ripemd160_hash[20];
  uint8_t versioned_payload[21];
  size_t pubkey_len = sizeof(public_key);

  int lite_address_return = generate_compressed_pubkey(private_key, public_key);
  if (lite_address_return != 0) {
    Serial.printf("Error generating public key: %d\n", lite_address_return);
    return;
  }

  if (public_key[0] == 0x00) {
    Serial.println("Error: Public Key is zero.");
    return;
  }

  mbedtls_sha256(public_key, pubkey_len, sha256_hash, 0);
  local_ripemd160(sha256_hash, 32, ripemd160_hash);

  versioned_payload[0] = 0x30;
  memcpy(versioned_payload + 1, ripemd160_hash, 20);
  if (sizeof(versioned_payload) > 21) {
    Serial.println("Error: Payload is over memory.");
    return;
  }

  if (base58checkEncode(versioned_payload, sizeof(versioned_payload), lite_address, &lite_address_len)) {
    lite_address[lite_address_len] = '\0';  // 确保字符串终止
  } else {
    Serial.println("Error: LiteCoin Base58 check encoding failed.");
  }
}


#endif