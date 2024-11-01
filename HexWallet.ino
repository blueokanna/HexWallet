#include <Arduino.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "esp_heap_caps.h"
#include "esp_random.h"
#include "base58.h"
#include "local_segwit.h"
#include "local_ripemd160.h"
#include "word_list.h"
#include "keccak256.h"
#include "Utils.h"

#include "BIP39.h"
#include "BIP32.h"
#include "BIP44.h"

void setup() {
  Serial.begin(115200);
  if (psramFound()) {
    Serial.println("PSRAM is available!");
  } else {
    Serial.println("PSRAM is not available.");
  }

  const char* my_mnemonic = generate_mnemonic();
  const char* passphrase = "";
  const char* hmac_keys = "Bitcoin seed";
  bool is_bip84 = true;

  Serial.print("Mnemonic: ");
  Serial.println(my_mnemonic);

  uint8_t my_seed[SEED_SIZE];
  uint8_t master_private_key[KEY_SIZE];
  uint8_t master_chain_code[KEY_SIZE];

  mnemonic_to_seed(my_mnemonic, passphrase, my_seed);

  const char* hex_char = address_hex(my_seed, SEED_SIZE);
  Serial.print("My Seed: ");
  Serial.println(hex_char);
  Serial.println();


  generate_master_private_key_and_chaincode(my_seed, hmac_keys, master_private_key, master_chain_code);
  printf("Master Private Key: ");
  for (int i = 0; i < KEY_SIZE; i++) {
    printf("%02x", master_private_key[i]);
  }
  printf("\n");

  printf("Master Chain Code: ");
  for (int i = 0; i < CHAIN_CODE_SIZE; i++) {
    printf("%02x", master_chain_code[i]);
  }
  printf("\n\n");

  char xprv[EXTENDED_KEY_SIZE];
  char xpub[EXTENDED_KEY_SIZE];

  char zprv[EXTENDED_KEY_SIZE];
  char zpub[EXTENDED_KEY_SIZE];

  size_t xprv_len = EXTENDED_KEY_SIZE;
  generate_xprv(0, 0, master_chain_code, master_private_key, xprv, &xprv_len);
  printf("Extended Private Key (xprv): %s\n", xprv);

  uint8_t public_key[33];
  generate_public_key_from_private(master_private_key, public_key);

  size_t xpub_len = EXTENDED_KEY_SIZE;
  generate_xpub(0, 0, master_chain_code, public_key, xpub, &xpub_len);
  printf("Extended Public Key (xpub): %s\n", xpub);


  size_t zprv_len = EXTENDED_KEY_SIZE;
  generate_zprv(0, 0, master_chain_code, master_private_key, zprv, &zprv_len);
  printf("Extended Private Key (zprv): %s\n", zprv);

  uint8_t zprv_public_key[33];
  generate_public_key_from_private(master_private_key, zprv_public_key);

  size_t zpub_len = EXTENDED_KEY_SIZE;
  generate_zpub(0, 0, master_chain_code, public_key, zpub, &zpub_len);
  printf("Extended Public Key (zpub): %s\n", zpub);

  // 存储解析的结果
  uint8_t version[4];
  uint8_t depth;
  uint32_t fingerprint, child_number;
  uint8_t local_chain_code[CHAIN_CODE_SIZE];
  uint8_t local_private_key[33];
  uint8_t local_public_key[33];

  uint8_t bip84_local_chain_code[CHAIN_CODE_SIZE];
  uint8_t bip84_local_private_key[33];
  uint8_t bip84_local_public_key[33];

  // 解析扩展私钥 xprv
  if (bip32_parse_extended_key(xprv, version, &depth, &fingerprint, &child_number, local_chain_code, local_private_key)) {
    printf("\n成功解析 BIP32 Root Key 扩展私钥 (xprv)\n");
    printf("版本字节: %02x%02x%02x%02x\n", version[0], version[1], version[2], version[3]);
    printf("深度: %d\n", depth);
    printf("父密钥指纹: %08x\n", fingerprint);
    printf("序号: %u\n", child_number);
    printf("私钥: ");
    for (int i = 0; i < 33; i++) {
      printf("%02x", local_private_key[i]);
    }
    printf("\n链码: ");
    for (int i = 0; i < CHAIN_CODE_SIZE; i++) {
      printf("%02x", local_chain_code[i]);
    }
    printf("\n\n");
  } else {
    printf("解析 xprv 失败\n");
  }


  // 解析扩展公钥 xpub
  if (bip32_parse_extended_key(xpub, version, &depth, &fingerprint, &child_number, local_chain_code, local_public_key)) {
    printf("\n成功解析 BIP32 Root Key 扩展公钥 (xpub)\n");
    printf("版本字节: %02x%02x%02x%02x\n", version[0], version[1], version[2], version[3]);
    printf("深度: %d\n", depth);
    printf("父公钥指纹: %08x\n", fingerprint);
    printf("序号: %u\n", child_number);
    printf("公钥: ");
    for (int i = 0; i < 33; i++) {
      printf("%02x", local_public_key[i]);
    }
    printf("\n链码: ");
    for (int i = 0; i < CHAIN_CODE_SIZE; i++) {
      printf("%02x", local_chain_code[i]);
    }
    printf("\n\n");
  } else {
    printf("解析 xpub 失败\n");
  }

  if (bip32_parse_extended_key(zprv, version, &depth, &fingerprint, &child_number, bip84_local_chain_code, bip84_local_private_key)) {
    printf("\n成功解析 BIP32 Root Key 扩展私钥 (zprv)\n");
    printf("版本字节: %02x%02x%02x%02x\n", version[0], version[1], version[2], version[3]);
    printf("深度: %d\n", depth);
    printf("父密钥指纹: %08x\n", fingerprint);
    printf("序号: %u\n", child_number);
    printf("私钥: ");
    for (int i = 0; i < 33; i++) {
      printf("%02x", bip84_local_private_key[i]);
    }
    printf("\n链码: ");
    for (int i = 0; i < CHAIN_CODE_SIZE; i++) {
      printf("%02x", bip84_local_chain_code[i]);
    }
    printf("\n\n");
  } else {
    printf("解析 zprv 失败\n");
  }


  // 解析扩展公钥 zpub
  if (bip32_parse_extended_key(zpub, version, &depth, &fingerprint, &child_number, bip84_local_chain_code, bip84_local_public_key)) {
    printf("\n成功解析 BIP32 Root Key 扩展公钥 (zpub)\n");
    printf("版本字节: %02x%02x%02x%02x\n", version[0], version[1], version[2], version[3]);
    printf("深度: %d\n", depth);
    printf("父公钥指纹: %08x\n", fingerprint);
    printf("序号: %u\n", child_number);
    printf("公钥: ");
    for (int i = 0; i < 33; i++) {
      printf("%02x", bip84_local_public_key[i]);
    }
    printf("\n链码: ");
    for (int i = 0; i < CHAIN_CODE_SIZE; i++) {
      printf("%02x", bip84_local_chain_code[i]);
    }
    printf("\n\n");
  } else {
    printf("解析 zpub 失败\n");
  }

  if (is_bip84) {
    generate_bip44_addresses(bip84_local_public_key, bip84_local_private_key, bip84_local_chain_code, 1, is_bip84);
  } else {
    generate_bip44_addresses(local_public_key, local_private_key, local_chain_code, 1, !is_bip84);
  }



  /*
  uint8_t child_private_key[KEY_SIZE];
  uint8_t child_chain_code[CHAIN_CODE_SIZE];
  uint32_t child_index = 0;  // 子地址索引


  int result = CKDpriv(master_private_key, master_chain_code, child_index, child_private_key, child_chain_code);

  if (result) {
    // 输出生成的子私钥和链码
    print_hex(child_private_key, KEY_SIZE);
    print_hex(child_chain_code, CHAIN_CODE_SIZE);
  } else {
    printf("子密钥生成失败。\n");
  }
  */


  /*
  char WIFOutput[54];
  privateKeyToWIF(master_private_key, WIFOutput);
  Serial.print("WIF Output: ");
  Serial.println(WIFOutput);

  char my_address[35];
  generate_btc_address(master_private_key, my_address);
*/


  //char address[35];
  //generate_btc_address(master_private_key, address);

  //generate_bip44_address(my_mnemonic, passphrase);
}

void loop() {
}
