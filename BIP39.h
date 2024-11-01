#ifndef __BIP39_H_
#define __BIP39_H_

#define SEED_SIZE 64
#define ENT_BITS 256
#define CHECKSUM_BITS (ENT_BITS / 32)
#define TOTAL_BITS (ENT_BITS + CHECKSUM_BITS)

const char* generate_mnemonic() {
  static char mnemonic[256] = "";
  mnemonic[0] = '\0';

  uint8_t entropy[ENT_BITS / 8];
  esp32_hardware_random_number(NULL, entropy, sizeof(entropy));

  uint8_t mnemonic_hash[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, entropy, sizeof(entropy));
  mbedtls_md_finish(&ctx, mnemonic_hash);
  mbedtls_md_free(&ctx);

  uint8_t checksum = mnemonic_hash[0] >> (8 - CHECKSUM_BITS);
  uint8_t* entropy_with_checksum;

  // 根据是否有PSRAM选择内存分配方式
  if (psramFound()) {
    entropy_with_checksum = (uint8_t*)heap_caps_calloc((TOTAL_BITS + 7) / 8, sizeof(uint8_t), MALLOC_CAP_SPIRAM);
    if (entropy_with_checksum == NULL) {
      Serial.println("Failed to allocate memory from PSRAM for entropy_with_checksum");
      return NULL;  // Memory allocation failed
    }
  } else {
    entropy_with_checksum = (uint8_t*)calloc((TOTAL_BITS + 7) / 8, sizeof(uint8_t));
    if (entropy_with_checksum == NULL) {
      Serial.println("Failed to allocate memory from heap for entropy_with_checksum");
      return NULL;  // Memory allocation failed
    }
  }

  memcpy(entropy_with_checksum, entropy, sizeof(entropy));
  entropy_with_checksum[ENT_BITS / 8] |= checksum << (8 - CHECKSUM_BITS);

  uint32_t accumulator = 0;
  int bits_in_accumulator = 0;

  for (size_t i = 0; i < (TOTAL_BITS + 7) / 8; ++i) {
    accumulator = (accumulator << 8) | entropy_with_checksum[i];
    bits_in_accumulator += 8;

    while (bits_in_accumulator >= 11) {
      bits_in_accumulator -= 11;
      uint16_t word_index = (accumulator >> bits_in_accumulator) & 0x07FF;

      if (mnemonic[0] != '\0') {
        strcat(mnemonic, " ");
      }
      strcat(mnemonic, english_word_list[word_index]);
    }
  }

  // 根据使用的内存类型释放内存
  if (psramFound()) {
    heap_caps_free(entropy_with_checksum);  // Free PSRAM memory
  } else {
    free(entropy_with_checksum);  // Free normal heap memory
  }

  return mnemonic;
}

void mnemonic_to_seed(const char* mnemonic_word, const char* passphrase, uint8_t mnemonic_seed[SEED_SIZE]) {
  const char* salt_prefix = "mnemonic";
  mbedtls_md_context_t sha512_ctx;
  mbedtls_md_type_t md_512_type = MBEDTLS_MD_SHA512;

  size_t salt_len = strlen(salt_prefix) + strlen(passphrase);
  char* salt;

  if (psramFound()) {
    salt = (char*)heap_caps_calloc(salt_len + 1, sizeof(char), MALLOC_CAP_SPIRAM);
    if (salt == NULL) {
      Serial.println("Failed to allocate memory from PSRAM for salt");
      return;  // Memory allocation failed
    }
  } else {
    salt = (char*)calloc(salt_len + 1, sizeof(char));
    if (salt == NULL) {
      Serial.println("Failed to allocate memory from heap for salt");
      return;  // Memory allocation failed
    }
  }

  snprintf(salt, salt_len + 1, "%s%s", salt_prefix, passphrase);

  mbedtls_md_init(&sha512_ctx);
  mbedtls_md_setup(&sha512_ctx, mbedtls_md_info_from_type(md_512_type), 1);

  int hmac_ext = mbedtls_pkcs5_pbkdf2_hmac_ext(md_512_type, (const unsigned char*)mnemonic_word, strlen(mnemonic_word), (const unsigned char*)salt, strlen(salt), 2048, SEED_SIZE, mnemonic_seed);
  if (hmac_ext != 0) {
    Serial.println("Error during PBKDF2-HMAC-SHA512 operation.");
  }

  mbedtls_md_free(&sha512_ctx);

  if (psramFound()) {
    heap_caps_free(salt);  // Free PSRAM memory
  } else {
    free(salt);  // Free normal heap memory
  }
}

#endif
