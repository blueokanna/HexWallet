#ifndef __BTC_WALLET_H_
#define __BTC_WALLET_H_



void generate_legacy_btc_address(const uint8_t *private_key, char *btc_address, size_t btc_address_len) {
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

  if (base58checkEncode(versioned_payload, sizeof(versioned_payload), btc_address, &btc_address_len)) {
    btc_address[btc_address_len] = '\0';  // 确保字符串终止
    //Serial.print("Bitcoin Address (Base58): ");
    //Serial.println(btc_address);
  } else {
    Serial.println("Error: BTC Base58 check encoding failed.");
  }
}


void generate_btc_segwit_address(const uint8_t *private_key, char *btc_address, size_t btc_address_len) {
  if (!is_private_key_valid(private_key)) {
    Serial.println("Error: Private key is not valid.");
    return;
  }

  uint8_t pubkey[33];
  uint8_t sha256_hash[32];
  uint8_t ripemd160_hash[20];
  std::vector<uint8_t> witness_program;

  if (generate_compressed_pubkey(private_key, pubkey) != 0) {
    Serial.println("Error: Generated Compressed PublicKey failed.");
    return;
  }

  if (pubkey[0] == 0x00) {
    Serial.println("Error: Public Key is zero.");
    return;
  }

  mbedtls_sha256(pubkey, sizeof(pubkey), sha256_hash, 0);
  local_ripemd160(sha256_hash, sizeof(sha256_hash), ripemd160_hash);

  witness_program.assign(ripemd160_hash, ripemd160_hash + sizeof(ripemd160_hash));

  std::string hrp = "bc";
  std::string local_segwit_address = segwit_address::encode(hrp, 0, witness_program);

  if (local_segwit_address.empty()) {
    Serial.println("Error: Failed to encode SegWit address.");
    return;
  }
  strncpy(btc_address, local_segwit_address.c_str(), btc_address_len);
  btc_address[btc_address_len - 1] = '\0';
}

void btc_message_receive(const uint8_t *tx_message, size_t tx_message_len, uint8_t *output) {
  double_sha256(tx_message, tx_message_len, output);
}

int sign_btc_transaction(const uint8_t *private_key, const uint8_t *tx_hash, uint8_t **signature, size_t *sig_len) {
  int ret;
  mbedtls_ecp_group grp;
  mbedtls_mpi r, s;
  mbedtls_ecp_keypair keypair;
  mbedtls_ecdsa_context ecdsa_ctx;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  size_t sig_buffer_size = MBEDTLS_ECDSA_MAX_LEN;
  const unsigned char *pers = esp32_random_const_seed();
  bool used_psram = false;

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_ecp_keypair_init(&keypair);
  mbedtls_ecdsa_init(&ecdsa_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  if (psramFound()) {
    *signature = (uint8_t *)heap_caps_calloc(sig_buffer_size, sizeof(uint8_t), MALLOC_CAP_SPIRAM);  // Use PSRAM
    used_psram = true;
  } else {
    *signature = (uint8_t *)calloc(sig_buffer_size, sizeof(uint8_t));  // Fallback to regular RAM
    used_psram = false;
  }

  if (*signature == NULL) {
    Serial.println("Error allocating signature buffer.");
    ret = -1;
    goto cleanup;
  }

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, strlen((const char *)pers))) != 0) {
    Serial.printf("Error in mbedtls_ctr_drbg_seed: %d\n", ret);
    goto cleanup;
  }

  if ((ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1)) != 0) {
    Serial.printf("Error loading curve group: %d\n", ret);
    goto cleanup;
  }

  if ((ret = mbedtls_mpi_read_binary(&keypair.private_d, private_key, 32)) != 0) {
    Serial.printf("Error reading private key: %d\n", ret);
    goto cleanup;
  }

  if ((ret = mbedtls_ecdsa_from_keypair(&ecdsa_ctx, &keypair)) != 0) {
    Serial.printf("Error setting ECDSA keypair: %d\n", ret);
    goto cleanup;
  }

  if ((ret = mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256, tx_hash, 32, *signature, sig_buffer_size, sig_len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
    Serial.printf("Error writing DER signature: %d\n", ret);
    goto cleanup;
  }

cleanup:
  mbedtls_ecdsa_free(&ecdsa_ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_keypair_free(&keypair);

  if (ret != 0 && *signature != NULL) {
    if (used_psram) {
      heap_caps_free(*signature);
    } else {
      free(*signature);
    }
    *signature = NULL;
  }

  return ret == 0 ? 0 : -1;
}


#endif