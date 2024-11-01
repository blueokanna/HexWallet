#ifndef __ETH_WALLET_H_
#define __ETH_WALLET_H_

void generate_eth_address(const uint8_t *private_key, char *eth_address, size_t eth_address_len) {
  uint8_t public_key[65];
  int eth_address_return = generate_uncompressed_pubkey(private_key, public_key);
  if (eth_address_return != 0) {
    Serial.printf("Error generating public key: %d\n", eth_address_return);
    return;
  }

  unsigned char public_key_no_prefix[64];
  memcpy(public_key_no_prefix, public_key + 1, 64);  // Remove the first byte (0x04)

  uint8_t keccak_hash[32];  // To hold the Keccak-256 hash output
  SHA3_CTX keccak_ctx;      // Keccak context

  keccak_init(&keccak_ctx);                              // Initialize Keccak context
  keccak_update(&keccak_ctx, public_key_no_prefix, 64);  // Hash the public key (without prefix)
  keccak_final(&keccak_ctx, keccak_hash);                // Get the final Keccak-256 hash

  uint8_t ethereum_address[20];
  memcpy(ethereum_address, keccak_hash + 12, 20);  // Ethereum address is the last 20 bytes of Keccak-256 hash

  char *ethereum_address_hex = address_hex(ethereum_address, 20);        // Convert to hex string
  snprintf(eth_address, eth_address_len, "0x%s", ethereum_address_hex);  // Format with "0x" prefix
  delete[] ethereum_address_hex;
}

void generate_eth_signature(const uint8_t *private_key, const uint8_t *message, size_t message_len, uint8_t *signature, size_t &sig_len) {
  mbedtls_ecp_group grp;
  mbedtls_mpi r, s, d;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  // 初始化所有结构
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char *pers = "ecdsa_sign";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

  // 加载 secp256k1 曲线
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);

  // 导入私钥
  mbedtls_mpi_read_binary(&d, private_key, 32);

  // Step 1: 对消息进行 Keccak-256 哈希


  uint8_t keccak_hash[32];  // To hold the Keccak-256 hash output
  SHA3_CTX keccak_ctx;      // Keccak context

  keccak_init(&keccak_ctx);                          // Initialize Keccak context
  keccak_update(&keccak_ctx, message, message_len);  // Hash the public key (without prefix)
  keccak_final(&keccak_ctx, keccak_hash);

  // Step 2: 使用私钥对哈希值签名
  int ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, keccak_hash, sizeof(keccak_hash), mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("Error signing message: -0x%04X\n", -ret);
    return;
  }

  // Step 3: 将 r 和 s 转换为二进制并存入 signature 中
  size_t r_len = mbedtls_mpi_size(&r);
  size_t s_len = mbedtls_mpi_size(&s);
  mbedtls_mpi_write_binary(&r, signature, r_len);
  mbedtls_mpi_write_binary(&s, signature + r_len, s_len);
  sig_len = r_len + s_len;

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
}

#endif
