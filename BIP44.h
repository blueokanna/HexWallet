#ifndef __BIP44_H_
#define __BIP44_H_

#include "BTC_Wallet.h"
#include "BTG_Wallet.h"
#include "DASH_Wallet.h"
#include "DOGE_Wallet.h"
#include "ETH_Wallet.h"
#include "LTC_Wallet.h"
#include "RVN_Wallet.h"
#include "TRX_Wallet.h"
#include "XRP_Wallet.h"

// 常量定义
#define MAX_ADDRESS_LEN 45
#define ACCOUNT_INDEX 0 | PURPOSE_HARDENED

// 新增参数 use_legacy_address 以选择生成 Legacy 或 SegWit 地址
void generate_bip44_addresses(const uint8_t* root_public_key, const uint8_t* root_private_key, const uint8_t* root_chain_code, uint32_t max_address, bool is_bip84) {
  uint8_t current_private_key[KEY_SIZE];
  uint8_t current_chain_code[CHAIN_CODE_SIZE];
  uint8_t temp_private_key[KEY_SIZE];
  uint8_t temp_chain_code[CHAIN_CODE_SIZE];
  uint32_t indices[5];
  int result;

  // 提取根私钥和链码
  extract_private_key(root_private_key, current_private_key);  // 去掉 0x00 前导字节
  memcpy(current_chain_code, root_chain_code, CHAIN_CODE_SIZE);

  // 币种结构体定义
  typedef struct {
    const char* name;
    uint32_t coin_type;
    void (*generate_legacy_address)(const uint8_t*, char*, size_t);  // Legacy 地址生成
    void (*generate_address)(const uint8_t*, char*, size_t);         // SegWit 地址生成
  } Coin;

  // 支持的币种列表
  Coin coins[] = {
    { "Bitcoin", 0, generate_legacy_btc_address, generate_btc_segwit_address },
    { "Litecoin", 2, generate_ltc_address, nullptr },
    { "Dogecoin", 3, generate_doge_address, nullptr },
    { "Dash", 5, generate_dash_address, nullptr },
    { "Ethereum", 60, generate_eth_address, nullptr },
    { "Ethereum Classic", 61, generate_eth_address, nullptr },
    { "Ripple", 144, generate_xrp_address, nullptr },
    { "Bitcoin Gold", 156, generate_btg_address, nullptr },
    { "Ravencoin", 175, generate_rvn_address, nullptr },
    { "Tron", 195, generate_trx_address, nullptr },
    { "Matic", 966, generate_eth_address, nullptr },
  };

  size_t num_coins = sizeof(coins) / sizeof(coins[0]);

  // 遍历所有支持的币种
  for (size_t i = 0; i < num_coins; i++) {
    printf("Generating addresses for %s:\n", coins[i].name);
    uint32_t coin_type = coins[i].coin_type;

    // 设置派生路径
    indices[0] = (is_bip84 && strcmp(coins[i].name, "Bitcoin") == 0) ? (84 | PURPOSE_HARDENED) : (44 | PURPOSE_HARDENED);  // 选择 Legacy 或 SegWit
    indices[1] = coin_type | PURPOSE_HARDENED;
    indices[2] = ACCOUNT_INDEX;  // Account 0
    indices[3] = 0;              // Change 0

    // 生成每个地址
    for (uint32_t address_index = 0; address_index <= max_address; address_index++) {
      indices[4] = address_index;

      // 依次派生每一层密钥
      memcpy(temp_private_key, current_private_key, KEY_SIZE);
      memcpy(temp_chain_code, current_chain_code, CHAIN_CODE_SIZE);

      for (int level = 0; level < 5; level++) {
        result = derive_child_key(temp_private_key, temp_chain_code, indices[level], temp_private_key, temp_chain_code);
        if (!result) {
          fprintf(stderr, "Error: Failed to derive key at level %d\n", level);
          break;
        }
      }

      // 生成地址（根据选择生成 SegWit 或 Legacy）
      char address[MAX_ADDRESS_LEN] = { 0 };
      if (strcmp(coins[i].name, "Bitcoin") == 0) {
        // 仅比特币根据 is_bip84 来决定生成 SegWit 或 Legacy 地址
        if (is_bip84) {
          coins[i].generate_address(temp_private_key, address, sizeof(address));
        } else {
          coins[i].generate_legacy_address(temp_private_key, address, sizeof(address));
        }
      } else {
        // 非比特币的币种始终使用 generate_address
        coins[i].generate_legacy_address(temp_private_key, address, sizeof(address));
      }

      // 输出结果
      printf("Derivation path: m/%d'/%d'/0'/0/%d\n", (indices[0] & ~PURPOSE_HARDENED), coin_type, address_index);
      if (strcmp(coins[i].name, "Bitcoin") == 0) {
        if (is_bip84) {
          char private_key_wif[55];
          privateKeyToWIF(temp_private_key, private_key_wif);
          printf("%s Private key (WIF): %s\n", coins[i].name, private_key_wif);
        } else {
          char private_key_wif[55];
          privateKeyToWIF(temp_private_key, private_key_wif);
          printf("%s Private key (WIF): %s\n", coins[i].name, private_key_wif);
        }
      } else {
        printf("%s Private key: ", coins[i].name);
        print_hex(temp_private_key, KEY_SIZE);
      }
      printf("%s Address: %s\n\n", coins[i].name, address);
    }
  }
}

#endif
