#include "ZanoOutput.h"
#include "src/privacy/RingOps.h"

namespace hexwallet {
namespace {
constexpr uint8_t native_asset[32] = {
    0xd6,0x32,0x9b,0x5b,0x1f,0x7c,0x08,0x05,0xb5,0xc3,0x45,0xf4,0x95,0x75,0x54,0x00,
    0x2a,0x2f,0x55,0x78,0x45,0xf6,0x4d,0x76,0x45,0xda,0xe0,0xe0,0x51,0xa6,0x49,0x8a};

bool output_mask(const char (&domain)[32], const uint8_t h[32], uint8_t mask[32]) {
  SensitiveValue<uint8_t[64]> input;
  memcpy(input.get(), domain, 32);
  memcpy(input.get() + 32, h, 32);
  return cryptonote_hash_to_scalar(input.get(), 64, mask);
}

uint64_t load_u64(const uint8_t *bytes) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) value |= uint64_t(bytes[i]) << (8 * i);
  return value;
}

bool recipient_points(const uint8_t h[32], const uint8_t spend[32], const uint8_t view[32],
                      uint8_t stealth[32], uint8_t concealing[32]) {
  using namespace privacy;
  SensitiveValue<uint8_t[32]> offset;
  return mul(kG, h, offset.get()) && ed25519_point_add_compressed(spend, offset.get(), stealth) &&
      output_mask("ZANO_HDS_OUT_CONCEALING_POINT__", h, offset.get()) && mul(view, offset.get(), concealing);
}

bool amount_commitment(const uint8_t blinded[32], uint64_t amount, const uint8_t mask[32], uint8_t wire[32]) {
  using namespace privacy;
  SensitiveValue<uint8_t[32]> amount_scalar, commitment;
  for (size_t i = 0; i < 8; ++i) amount_scalar.get()[i] = static_cast<uint8_t>(amount >> (8 * i));
  return combination(blinded, amount_scalar.get(), kG, mask, commitment.get(), true) &&
      mul(commitment.get(), kInv8, wire);
}
}

bool zano_build_output(const uint8_t tx_secret[32], uint64_t index,
                       const uint8_t spend[32], const uint8_t view[32],
                       const uint8_t asset[32], uint64_t amount, uint64_t payment_id,
                       bool explicit_native, ZanoConfidentialOutput *out) {
  using namespace privacy;
  if (!out) return false;
  *out = {};
  if (!scalar(tx_secret, false) || !point(spend) || !point(view) || !point(asset) ||
      (explicit_native && !equal(asset, native_asset))) return false;

  ZanoConfidentialOutput result{};
  SensitiveValue<uint8_t[32]> derivation, h, mask, blinded;
  if (!cryptonote_generate_key_derivation(view, tx_secret, derivation.get()) ||
      !cryptonote_derivation_to_scalar(derivation.get(), index, h.get()) ||
      !recipient_points(h.get(), spend, view, result.stealth_address, result.concealing_point) ||
      !output_mask("ZANO_HDS_OUT_AMOUNT_MASK_______", h.get(), mask.get())) return false;
  result.encrypted_amount = amount ^ load_u64(mask.get());
  result.encrypted_payment_id = payment_id ^ load_u64(mask.get() + 8);
  // Upstream decode_output_data treats a zero wire field as no payment ID.
  if (payment_id && !result.encrypted_payment_id) return false;
  memcpy(blinded.get(), asset, 32);
  if (!explicit_native) {
    if (!output_mask("ZANO_HDS_OUT_ASSET_BLIND_MASK__", h.get(), mask.get()) ||
        !mul(kZanoX, mask.get(), blinded.get()) ||
        !ed25519_point_add_compressed(asset, blinded.get(), blinded.get())) return false;
  }
  if (!output_mask("ZANO_HDS_OUT_AMOUNT_BLIND_MASK_", h.get(), mask.get()) ||
      !amount_commitment(blinded.get(), amount, mask.get(), result.amount_commitment) ||
      !mul(blinded.get(), kInv8, result.blinded_asset)) return false;
  *out = result;
  return true;
}

bool zano_scan_output(const uint8_t view_secret[32], const uint8_t spend[32],
                      const uint8_t tx_public[32], uint64_t index,
                      const ZanoConfidentialOutput &output, ZanoReceivedOutput *out) {
  using namespace privacy;
  if (!out) return false;
  *out = {};
  if (!scalar(view_secret, false) || !point(spend) || !point(tx_public) || !point(output.blinded_asset))
    return false;
  uint8_t view[32], stealth[32], concealing[32], commitment[32], blinded[32];
  SensitiveValue<uint8_t[32]> derivation, h, mask;
  if (!mul(kG, view_secret, view) || !cryptonote_generate_key_derivation(tx_public, view_secret, derivation.get()) ||
      !cryptonote_derivation_to_scalar(derivation.get(), index, h.get()) ||
      !recipient_points(h.get(), spend, view, stealth, concealing) ||
      !equal(stealth, output.stealth_address) || !equal(concealing, output.concealing_point) ||
      !output_mask("ZANO_HDS_OUT_AMOUNT_MASK_______", h.get(), mask.get()) ||
      !ed25519_point_mul8_compressed(output.blinded_asset, blinded)) return false;
  SensitiveValue<ZanoReceivedOutput> result;
  result.get().amount = output.encrypted_amount ^ load_u64(mask.get());
  if (output.encrypted_payment_id)
    result.get().payment_id = output.encrypted_payment_id ^ load_u64(mask.get() + 8);
  if (!output_mask("ZANO_HDS_OUT_AMOUNT_BLIND_MASK_", h.get(), result.get().amount_mask) ||
      !amount_commitment(blinded, result.get().amount, result.get().amount_mask, commitment) ||
      !equal(commitment, output.amount_commitment)) return false;
  if (equal(blinded, native_asset)) {
    memcpy(result.get().asset_id, native_asset, 32);
  } else {
    SensitiveValue<uint8_t[32]> offset;
    if (!output_mask("ZANO_HDS_OUT_ASSET_BLIND_MASK__", h.get(), result.get().asset_mask) ||
        !mul(kZanoX, result.get().asset_mask, offset.get()) ||
        !ed25519_point_sub_compressed(blinded, offset.get(), result.get().asset_id) ||
        !point(result.get().asset_id)) return false;
  }
  *out = result.get();
  return true;
}
}
