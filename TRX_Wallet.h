#ifndef __TRX_WALLET_H_
#define __TRX_WALLET_H_

void generate_trx_address(const uint8_t *private_key, char *trx_address, size_t trx_address_len) {
  if (!is_private_key_valid(private_key)) {
    Serial.println("Error: Private key is not Valid.");
    return;
  }

  uint8_t pubkey[65];
  uint8_t keccak_hash[32];
  uint8_t versioned_payload[21];
  unsigned char public_key_no_prefix[64];

  if (generate_uncompressed_pubkey(private_key, pubkey) != 0) {
    Serial.println("Error: Failed to generate uncompressed public key.");
    return;
  }

  if (pubkey[0] == 0x00) {
    Serial.println("Error: Public Key is zero.");
    return;
  }

  memcpy(public_key_no_prefix, pubkey + 1, 64);

  SHA3_CTX keccak_ctx;
  keccak_init(&keccak_ctx);
  keccak_update(&keccak_ctx, public_key_no_prefix, 64);
  keccak_final(&keccak_ctx, keccak_hash);

  versioned_payload[0] = 0x41;
  memcpy(versioned_payload + 1, keccak_hash + 12, 20);

  if (base58checkEncode(versioned_payload, sizeof(versioned_payload), trx_address, &trx_address_len)) {
    trx_address[trx_address_len] = '\0';
  } else {
    Serial.println("Error: TRX Base58Check encoding failed.");
  }
}

#endif
