#ifndef __UTILS_H_
#define __UTILS_H_

int esp32_hardware_random_number(void *, unsigned char *output, size_t len)
{
  esp_fill_random(output, len);
  return 0;
}

const unsigned char *esp32_random_const_seed()
{
  static unsigned char output[32];
  esp_fill_random(output, 32);
  return (const unsigned char *)output;
}

void extract_private_key(const uint8_t *temp_private_key, uint8_t *local_private_key)
{
  memcpy(local_private_key, temp_private_key + 1, 32);
}

void hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output)
{
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1); // Use HMAC
  mbedtls_md_hmac_starts(&ctx, key, key_len);
  mbedtls_md_hmac_update(&ctx, data, data_len);
  mbedtls_md_hmac_finish(&ctx, output);
  mbedtls_md_free(&ctx);
}

void double_sha256(const uint8_t *data, size_t data_len, uint8_t *output)
{
  uint8_t hash1[32];
  mbedtls_sha256(data, data_len, hash1, 0);
  mbedtls_sha256(hash1, 32, output, 0);
}

bool base58checkEncodeGeneric(const uint8_t *input, size_t input_len, char *output, size_t *output_len, bool (*b58enc_func)(char *, size_t *, const void *, size_t))
{
  uint8_t data_with_checksum[input_len + 4]; // 21 -> 25
  uint8_t checksum[32];
  memcpy(data_with_checksum, input, input_len);
  double_sha256(input, input_len, checksum);
  memcpy(data_with_checksum + input_len, checksum, 4);
  return b58enc_func(output, output_len, data_with_checksum, input_len + 4);
}

bool base58checkEncode(const uint8_t *input, size_t input_len, char *output, size_t *output_len)
{
  return base58checkEncodeGeneric(input, input_len, output, output_len, b58enc);
}

bool ripple_base58checkEncode(const uint8_t *input, size_t input_len, char *output, size_t *output_len)
{
  return base58checkEncodeGeneric(input, input_len, output, output_len, ripple_b58enc);
}

bool is_private_key_valid(const uint8_t private_key[32])
{
  mbedtls_mpi n;
  mbedtls_mpi pk;
  mbedtls_mpi_init(&n);
  mbedtls_mpi_init(&pk);

  const char *SECP256K1_ORDER = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  mbedtls_mpi_read_string(&n, 16, SECP256K1_ORDER);
  mbedtls_mpi_read_binary(&pk, private_key, 32);

  bool valid = mbedtls_mpi_cmp_int(&pk, 1) >= 0 && mbedtls_mpi_cmp_mpi(&pk, &n) < 0;

  mbedtls_mpi_free(&n);
  mbedtls_mpi_free(&pk);

  return valid;
}

char *address_hex(uint8_t *data, size_t len)
{
  char *hex_string = new char[len * 2 + 1];
  for (size_t i = 0; i < len; i++)
  {
    sprintf(&hex_string[i * 2], "%02x", data[i]);
  }
  hex_string[len * 2] = '\0';
  return hex_string;
}

void print_hex(const uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    printf("%02x", data[i]);
  }
  printf("\n");
}

int generate_public_key_from_private(const uint8_t private_key[32], unsigned char public_key[33])
{
  int ret;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q_point;
  mbedtls_mpi private_mpi;
  size_t olen = 0;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q_point);
  mbedtls_mpi_init(&private_mpi);

  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  if (ret != 0)
  {
    Serial.printf("Error in mbedtls_ecp_group_load: %d\n", ret);
    goto cleanup;
  }

  ret = mbedtls_mpi_read_binary(&private_mpi, private_key, 32);
  if (ret != 0)
  {
    Serial.printf("Error in mbedtls_mpi_read_binary: %d\n", ret);
    goto cleanup;
  }

  ret = mbedtls_ecp_mul(&grp, &Q_point, &private_mpi, &grp.G, esp32_hardware_random_number, NULL);
  if (ret != 0)
  {
    Serial.printf("Error in mbedtls_ecp_mul: %d\n", ret);
    goto cleanup;
  }

  ret = mbedtls_ecp_point_write_binary(&grp, &Q_point, MBEDTLS_ECP_PF_COMPRESSED, &olen, public_key, 33);
  if (ret != 0 || olen != 33)
  {
    Serial.printf("Error in mbedtls_ecp_point_write_binary: %d, olen: %zu\n", ret, olen);
    goto cleanup;
  }

  ret = 0;

cleanup:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q_point);
  mbedtls_mpi_free(&private_mpi);

  return ret;
}

int generate_compressed_pubkey(const uint8_t *private_key, uint8_t *compressed_pubkey)
{
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;
  int ret;
  size_t len = 33;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_mpi_read_binary(&d, private_key, 32);
  ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, esp32_hardware_random_number, NULL);
  if (ret != 0)
  {
    Serial.printf("Error in mbedtls_ecp_mul: %d\n", ret);
    goto cleanup;
  }

  ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &len, compressed_pubkey, 33);
  if (ret != 0)
    goto cleanup;

  ret = 0;
cleanup:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);

  return ret;
}

int generate_uncompressed_pubkey(const uint8_t *private_key, uint8_t *uncompressed_pubkey)
{
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;
  int ret;
  size_t len = 65;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);

  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_mpi_read_binary(&d, private_key, 32);
  ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, esp32_hardware_random_number, NULL);
  if (ret != 0)
  {
    Serial.printf("Error in mbedtls_ecp_mul: %d\n", ret);
    goto cleanup;
  }

  ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, uncompressed_pubkey, 65);
  if (ret != 0)
    goto cleanup;

  ret = 0;
cleanup:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);

  return ret;
}

void privateKeyToWIF(const uint8_t *private_key, char *wif_out)
{
  uint8_t wif_data[34];                  // 1字节前缀 + 32字节私钥 + 1字节压缩标志
  wif_data[0] = 0x80;                    // 添加前缀
  memcpy(wif_data + 1, private_key, 32); // 复制私钥
  wif_data[33] = 0x01;                   // 压缩标志

  // Base58编码的结果最大可能需要53字节
  size_t base58size = 53;
  if (base58checkEncode(wif_data, sizeof(wif_data), wif_out, &base58size))
  {
    wif_out[base58size] = '\0'; // 添加字符串结束符
  }
  else
  {
    Serial.println("Base58 encoding failed.");
  }
}

#endif