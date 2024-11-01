#include <Arduino.h>
#include <mbedtls/sha256.h>

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char ripple_b58digits_ordered[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
static const char *B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t b58digits_map[] = {
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  -1,
  17,
  18,
  19,
  20,
  21,
  -1,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  32,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  33,
  34,
  35,
  36,
  37,
  38,
  39,
  40,
  41,
  42,
  43,
  -1,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
  52,
  53,
  54,
  55,
  56,
  57,
  -1,
  -1,
  -1,
  -1,
  -1,
};


bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
  const uint8_t *bin = (const uint8_t *)data;
  int carry;
  size_t i, j, high, zcount = 0;
  size_t size;

  while (zcount < binsz && !bin[zcount])
    ++zcount;

  //Calculating output buffer size
  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t buf[size];
  memset(buf, 0, size);

  //Base58 conversion
  for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
      if (!j) {
        break;
      }
    }
  }

  for (j = 0; j < size && !buf[j]; ++j)
    ;

  if (*b58sz <= zcount + size - j) {
    *b58sz = zcount + size - j + 1;
    return false;
  }

  //Handling leading '1'
  if (zcount)
    memset(b58, '1', zcount);
  for (i = zcount; j < size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i + 1;

  return true;
}

bool ripple_b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz) {
  const uint8_t *data = (const uint8_t *)bin;
  int carry;
  size_t i, j, high, zcount = 0;
  size_t size;

  uint8_t *prefixed_data = (uint8_t *)malloc(binsz + 1);
  if (!prefixed_data) {
    return false;  // 内存分配失败
  }
  prefixed_data[0] = 0x00;                 // 使用传入的 Ripple 前缀 (例如 0x00)
  memcpy(prefixed_data + 1, data, binsz);  // 复制原始数据
  binsz += 1;                              // 调整总长度

  // 计算前导零
  while (zcount < binsz && !prefixed_data[zcount]) {
    ++zcount;
  }

  // 计算输出缓冲区大小
  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t *buf = (uint8_t *)malloc(size);
  if (!buf) {
    free(prefixed_data);
    return false;
  }
  memset(buf, 0, size);

  // Base58 转换
  for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
    for (carry = prefixed_data[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
      if (!j) {
        break;
      }
    }
  }

  free(prefixed_data);  // 释放 prefixed_data 缓冲区

  // 计算有效长度
  for (j = 0; j < size && !buf[j]; ++j)
    ;

  if (*b58sz <= zcount + size - j) {
    *b58sz = zcount + size - j + 1;
    free(buf);
    return false;
  }

  // 只处理一个前导 'r' (Ripple 地址前缀为0x00时应为'r')
  if (zcount) {
    b58[0] = 'r';  // Ripple 地址前缀
    zcount = 1;    // 保证只处理一个 'r'
  }

  for (i = zcount; j < size; ++i, ++j) {
    b58[i] = ripple_b58digits_ordered[buf[j]];  // 使用 Ripple 的 Base58 字母表
  }
  b58[i] = '\0';  // 添加字符串结束符
  *b58sz = i + 1;

  free(buf);  // 释放 buf 缓冲区
  return true;
}



bool b58check_dec(uint8_t *bin, size_t *binsz, const char *b58) {
  size_t len = strlen(b58);
  uint8_t decoded[128];
  size_t decoded_len = 0;

  // Base58解码使用b58digits_map
  for (size_t i = 0; i < len; i++) {
    char c = b58[i];
    if (c < 0 || b58digits_map[(int)c] == -1) {
      return false;  // 无效字符
    }

    int carry = b58digits_map[(int)c];  // 使用b58digits_map来查找字符索引
    for (size_t j = 0; j < decoded_len; j++) {
      carry += 58 * decoded[j];
      decoded[j] = carry % 256;
      carry /= 256;
    }
    while (carry) {
      decoded[decoded_len++] = carry % 256;
      carry /= 256;
    }
  }

  // 反转解码后的字节序列
  for (size_t i = 0; i < decoded_len / 2; i++) {
    uint8_t temp = decoded[i];
    decoded[i] = decoded[decoded_len - 1 - i];
    decoded[decoded_len - 1 - i] = temp;
  }

  *binsz = decoded_len - 4;
  memcpy(bin, decoded, *binsz);

  uint8_t *checksum = &decoded[*binsz];
  uint8_t local_hash[32];

  mbedtls_sha256(bin, *binsz, local_hash, 0);
  mbedtls_sha256(local_hash, 32, local_hash, 0);
  if (memcmp(local_hash, checksum, 4) != 0) {
    return false;
  }

  return true;
}
