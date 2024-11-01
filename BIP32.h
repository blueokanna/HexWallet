#ifndef __BIP32_H_
#define __BIP32_H_

#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#define KEY_SIZE 32
#define KEY_RAW_SIZE 78
#define CHAIN_CODE_SIZE 32
#define SHA512_DIGEST_LENGTH 64
#define EXTENDED_KEY_SIZE 112
#define PURPOSE_HARDENED 0x80000000

// 生成主密钥和链码
void generate_master_private_key_and_chaincode(uint8_t seed[SEED_SIZE], const char *hmac_key, uint8_t *master_private_key, uint8_t *master_chain_code) {
  uint8_t hmac_output[SHA512_DIGEST_LENGTH];
  hmac_sha512((uint8_t *)hmac_key, strlen(hmac_key), seed, SEED_SIZE, hmac_output);

  memcpy(master_private_key, hmac_output, KEY_SIZE);
  memcpy(master_chain_code, hmac_output + KEY_SIZE, CHAIN_CODE_SIZE);
}

void generate_xprv(uint8_t depth, uint32_t child_index, const uint8_t *chain_code, const uint8_t *private_key, char *xprv, size_t *xprv_len) {
  uint8_t *xprv_raw;

  if (psramFound()) {
    xprv_raw = (uint8_t *)heap_caps_calloc(KEY_RAW_SIZE, sizeof(uint8_t), MALLOC_CAP_SPIRAM);
    if (xprv_raw == NULL) {
      Serial.println("Failed to allocate memory from PSRAM for xprv_raw");
      return;  // Memory allocation failed
    }
  } else {
    xprv_raw = (uint8_t *)calloc(KEY_RAW_SIZE, sizeof(uint8_t));
    if (xprv_raw == NULL) {
      Serial.println("Failed to allocate memory from heap for xprv_raw");
      return;  // Memory allocation failed
    }
  }

  xprv_raw[0] = 0x04;
  xprv_raw[1] = 0x88;
  xprv_raw[2] = 0xAD;
  xprv_raw[3] = 0xE4;
  xprv_raw[4] = depth;
  memset(xprv_raw + 5, 0, 4);
  xprv_raw[9] = (child_index >> 24) & 0xFF;
  xprv_raw[10] = (child_index >> 16) & 0xFF;
  xprv_raw[11] = (child_index >> 8) & 0xFF;
  xprv_raw[12] = child_index & 0xFF;
  memcpy(xprv_raw + 13, chain_code, 32);
  xprv_raw[45] = 0x00;
  memcpy(xprv_raw + 46, private_key, 32);

  base58checkEncode(xprv_raw, KEY_RAW_SIZE, xprv, xprv_len);

  if (psramFound()) {
    heap_caps_free(xprv_raw);  // Free PSRAM memory
  } else {
    free(xprv_raw);  // Free normal heap memory
  }
}

void generate_xpub(uint8_t depth, uint32_t child_index, const uint8_t *chain_code, const uint8_t *public_key, char *xpub, size_t *xpub_len) {
  uint8_t *xpub_raw;

  if (psramFound()) {
    xpub_raw = (uint8_t *)heap_caps_calloc(KEY_RAW_SIZE, sizeof(uint8_t), MALLOC_CAP_SPIRAM);
    if (xpub_raw == NULL) {
      Serial.println("Failed to allocate memory from PSRAM for xpub_raw");
      return;  // Memory allocation failed
    }
  } else {
    xpub_raw = (uint8_t *)calloc(KEY_RAW_SIZE, sizeof(uint8_t));
    if (xpub_raw == NULL) {
      Serial.println("Failed to allocate memory from heap for xpub_raw");
      return;  // Memory allocation failed
    }
  }

  xpub_raw[0] = 0x04;
  xpub_raw[1] = 0x88;
  xpub_raw[2] = 0xB2;
  xpub_raw[3] = 0x1E;
  xpub_raw[4] = depth;
  memset(xpub_raw + 5, 0, 4);
  xpub_raw[9] = (child_index >> 24) & 0xFF;
  xpub_raw[10] = (child_index >> 16) & 0xFF;
  xpub_raw[11] = (child_index >> 8) & 0xFF;
  xpub_raw[12] = child_index & 0xFF;
  memcpy(xpub_raw + 13, chain_code, 32);
  memcpy(xpub_raw + 45, public_key, 33);

  base58checkEncode(xpub_raw, KEY_RAW_SIZE, xpub, xpub_len);

  if (psramFound()) {
    heap_caps_free(xpub_raw);  // Free PSRAM memory
  } else {
    free(xpub_raw);  // Free normal heap memory
  }
}

void generate_zprv(uint8_t depth, uint32_t child_index, const uint8_t *chain_code, const uint8_t *private_key, char *zprv, size_t *zprv_len) {
  uint8_t *zprv_raw;

  if (psramFound()) {
    zprv_raw = (uint8_t *)heap_caps_calloc(KEY_RAW_SIZE, sizeof(uint8_t), MALLOC_CAP_SPIRAM);
    if (zprv_raw == NULL) {
      Serial.println("Failed to allocate memory from PSRAM for zprv_raw");
      return;  // Memory allocation failed
    }
  } else {
    zprv_raw = (uint8_t *)calloc(KEY_RAW_SIZE, sizeof(uint8_t));
    if (zprv_raw == NULL) {
      Serial.println("Failed to allocate memory from heap for zprv_raw");
      return;  // Memory allocation failed
    }
  }

  // Change the prefix to BIP84's zprv
  zprv_raw[0] = 0x04;
  zprv_raw[1] = 0xB2;
  zprv_raw[2] = 0x43;
  zprv_raw[3] = 0x0C;
  zprv_raw[4] = depth;
  memset(zprv_raw + 5, 0, 4);  // Parent fingerprint (for simplicity, set to 0)
  zprv_raw[9] = (child_index >> 24) & 0xFF;
  zprv_raw[10] = (child_index >> 16) & 0xFF;
  zprv_raw[11] = (child_index >> 8) & 0xFF;
  zprv_raw[12] = child_index & 0xFF;
  memcpy(zprv_raw + 13, chain_code, 32);   // Chain code
  zprv_raw[45] = 0x00;                     // Leading 0 byte for private key
  memcpy(zprv_raw + 46, private_key, 32);  // Private key

  base58checkEncode(zprv_raw, KEY_RAW_SIZE, zprv, zprv_len);

  if (psramFound()) {
    heap_caps_free(zprv_raw);  // Free PSRAM memory
  } else {
    free(zprv_raw);  // Free normal heap memory
  }
}

void generate_zpub(uint8_t depth, uint32_t child_index, const uint8_t *chain_code, const uint8_t *public_key, char *zpub, size_t *zpub_len) {
  uint8_t *zpub_raw;

  if (psramFound()) {
    zpub_raw = (uint8_t *)heap_caps_calloc(KEY_RAW_SIZE, sizeof(uint8_t), MALLOC_CAP_SPIRAM);
    if (zpub_raw == NULL) {
      Serial.println("Failed to allocate memory from PSRAM for zpub_raw");
      return;  // Memory allocation failed
    }
  } else {
    zpub_raw = (uint8_t *)calloc(KEY_RAW_SIZE, sizeof(uint8_t));
    if (zpub_raw == NULL) {
      Serial.println("Failed to allocate memory from heap for zpub_raw");
      return;  // Memory allocation failed
    }
  }

  zpub_raw[0] = 0x04;
  zpub_raw[1] = 0xB2;
  zpub_raw[2] = 0x47;
  zpub_raw[3] = 0x46;
  zpub_raw[4] = depth;
  memset(zpub_raw + 5, 0, 4);  // Parent fingerprint (set to 0)
  zpub_raw[9] = (child_index >> 24) & 0xFF;
  zpub_raw[10] = (child_index >> 16) & 0xFF;
  zpub_raw[11] = (child_index >> 8) & 0xFF;
  zpub_raw[12] = child_index & 0xFF;
  memcpy(zpub_raw + 13, chain_code, 32);  // Chain code
  memcpy(zpub_raw + 45, public_key, 33);  // Public key (33 bytes for compressed public key)

  base58checkEncode(zpub_raw, KEY_RAW_SIZE, zpub, zpub_len);

  if (psramFound()) {
    heap_caps_free(zpub_raw);  // Free PSRAM memory
  } else {
    free(zpub_raw);  // Free normal heap memory
  }
}



// 私钥派生函数
/*
int CKDpriv(const uint8_t *kpar, const uint8_t *cpar, uint32_t index, uint8_t *ki, uint8_t *ci) {
  uint8_t data[37];  // 0x00 + ser256(kpar) + ser32(i)
  uint8_t I[64];
  uint8_t IL[32], IR[32];

  if (index >= 0x80000000) {  // 硬化子密钥
    data[0] = 0x00;
    memcpy(data + 1, kpar, 32);  // ser256(kpar)
  } else {                       // 普通子密钥
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pubkey;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pubkey);

    // 初始化 SECP256K1 曲线
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);

    // 从私钥生成公钥
    mbedtls_mpi kpar_mpi;
    mbedtls_mpi_init(&kpar_mpi);
    mbedtls_mpi_read_binary(&kpar_mpi, kpar, 32);
    mbedtls_ecp_mul(&grp, &pubkey, &kpar_mpi, &grp.G, esp32_hardware_random_number, NULL);

    // 序列化公钥
    size_t olen;
    mbedtls_ecp_point_write_binary(&grp, &pubkey, MBEDTLS_ECP_PF_COMPRESSED, &olen, data, sizeof(data));

    // 清理
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pubkey);
    mbedtls_mpi_free(&kpar_mpi);
  }
  memcpy(data + 33, &index, 4);  // ser32(index)

  // HMAC-SHA512生成子密钥
  hmac_sha512(cpar, 32, data, 37, I);

  // 分割 I 为 IL 和 IR
  memcpy(IL, I, 32);
  memcpy(IR, I + 32, 32);

  // 生成子私钥：ki = (parse256(IL) + kpar) mod n
  mbedtls_mpi il_mpi, kpar_mpi, ki_mpi, N;
  mbedtls_mpi_init(&il_mpi);
  mbedtls_mpi_init(&kpar_mpi);
  mbedtls_mpi_init(&ki_mpi);
  mbedtls_mpi_init(&N);

  // 读取 SECP256K1 群的阶 N
  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_mpi_copy(&N, &grp.N);

  // IL 和 kpar 转换为 MPI
  mbedtls_mpi_read_binary(&il_mpi, IL, 32);
  mbedtls_mpi_read_binary(&kpar_mpi, kpar, 32);

  // ki = (IL + kpar) mod N
  mbedtls_mpi_add_mpi(&ki_mpi, &il_mpi, &kpar_mpi);
  mbedtls_mpi_mod_mpi(&ki_mpi, &ki_mpi, &N);

  // 输出子私钥 ki
  mbedtls_mpi_write_binary(&ki_mpi, ki, 32);

  // 验证子私钥的有效性
  if (mbedtls_mpi_cmp_int(&ki_mpi, 0) == 0 || mbedtls_mpi_cmp_mpi(&ki_mpi, &N) >= 0) {
    // 无效私钥
    mbedtls_mpi_free(&il_mpi);
    mbedtls_mpi_free(&kpar_mpi);
    mbedtls_mpi_free(&ki_mpi);
    mbedtls_mpi_free(&N);
    return 0;
  }

  // 返回子链码
  memcpy(ci, IR, 32);

  // 清理
  mbedtls_mpi_free(&il_mpi);
  mbedtls_mpi_free(&kpar_mpi);
  mbedtls_mpi_free(&ki_mpi);
  mbedtls_mpi_free(&N);
  mbedtls_ecp_group_free(&grp);

  return 1;
}
*/

int derive_child_key(const uint8_t *parent_private_key, const uint8_t *parent_chain_code, uint32_t index, uint8_t *child_private_key, uint8_t *child_chain_code) {
  uint8_t data[37];
  uint8_t I[64];
  uint8_t IL[32], IR[32];
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pubkey;
  mbedtls_mpi kpar_mpi, il_mpi, ki_mpi, N;
  int ret = 1;

  if (index >= PURPOSE_HARDENED) {  // 硬化派生
    data[0] = 0x00;
    memcpy(data + 1, parent_private_key, 32);
  } else {  // 非硬化派生
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pubkey);
    mbedtls_mpi_init(&kpar_mpi);

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    mbedtls_mpi_read_binary(&kpar_mpi, parent_private_key, 32);
    mbedtls_ecp_mul(&grp, &pubkey, &kpar_mpi, &grp.G, esp32_hardware_random_number, NULL);

    size_t len = 33;
    mbedtls_ecp_point_write_binary(&grp, &pubkey, MBEDTLS_ECP_PF_COMPRESSED, &len, data, sizeof(data));

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pubkey);
    mbedtls_mpi_free(&kpar_mpi);
  }
  // 添加索引
  data[33] = (index >> 24) & 0xFF;
  data[34] = (index >> 16) & 0xFF;
  data[35] = (index >> 8) & 0xFF;
  data[36] = index & 0xFF;

  // HMAC-SHA512
  hmac_sha512(parent_chain_code, 32, data, 37, I);

  memcpy(IL, I, 32);       // Child Hash left
  memcpy(IR, I + 32, 32);  //Child Chain code

  // 验证 IL 是否在 [1, n-1]
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_mpi_init(&il_mpi);
  mbedtls_mpi_read_binary(&il_mpi, IL, 32);
  if (mbedtls_mpi_cmp_int(&il_mpi, 0) == 0 || mbedtls_mpi_cmp_mpi(&il_mpi, &grp.N) >= 0) {
    ret = 0;
    goto cleanup;
  }

  // ki = (IL + kpar) mod n
  mbedtls_mpi_init(&kpar_mpi);
  mbedtls_mpi_init(&ki_mpi);
  mbedtls_mpi_init(&N);
  mbedtls_mpi_copy(&N, &grp.N);

  mbedtls_mpi_read_binary(&kpar_mpi, parent_private_key, 32);
  mbedtls_mpi_add_mpi(&ki_mpi, &il_mpi, &kpar_mpi);
  mbedtls_mpi_mod_mpi(&ki_mpi, &ki_mpi, &N);

  // 检查 ki 是否有效
  if (mbedtls_mpi_cmp_int(&ki_mpi, 0) == 0 || mbedtls_mpi_cmp_mpi(&ki_mpi, &N) >= 0) {
    ret = 0;
    goto cleanup;
  }

  // 输出子私钥
  mbedtls_mpi_write_binary(&ki_mpi, child_private_key, 32);
  memcpy(child_chain_code, IR, 32);

cleanup:
  mbedtls_mpi_free(&il_mpi);
  mbedtls_mpi_free(&kpar_mpi);
  mbedtls_mpi_free(&ki_mpi);
  mbedtls_mpi_free(&N);
  mbedtls_ecp_group_free(&grp);
  return ret;
}

bool bip32_parse_extended_key(const char *extended_key, uint8_t *out_version, uint8_t *out_depth, uint32_t *out_fingerprint, uint32_t *out_child_number, uint8_t *out_chain_code, uint8_t *out_key) {
  uint8_t decoded[78];  // 存储解码后的 78 字节
  size_t decoded_len = sizeof(decoded);

  if (!b58check_dec(decoded, &decoded_len, extended_key)) {
    printf("Base58Check 解码失败\n");
    return false;
  }

  // 检查解码后的长度是否为 78 字节
  if (decoded_len != 78) {
    printf("解码长度错误\n");
    return false;
  }

  // 提取版本、深度、父公钥指纹、序号、链码、密钥
  memcpy(out_version, decoded, 4);                 // 版本字节
  *out_depth = decoded[4];                         // 深度
  *out_fingerprint = *((uint32_t *)&decoded[5]);   // 父公钥指纹
  *out_child_number = *((uint32_t *)&decoded[9]);  // 序号
  memcpy(out_chain_code, &decoded[13], 32);        // 链码
  memcpy(out_key, &decoded[45], 33);               // 密钥（私钥或公钥）

  return true;
}

#endif
