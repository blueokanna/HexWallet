#include "ZanoPhonePayment.h"
#if defined(HEXWALLET_HOST_TEST) && defined(HEXWALLET_TEST_ZANO_PHONE_PAYMENTS)
#include <new>
#include "ChainCommon.h"
#include "RandomSource.h"
#include "ZanoClsag.h"
#include "ZanoOutput.h"
#include "src/privacy/RingOps.h"

namespace hexwallet {
namespace {
using namespace privacy;
constexpr size_t ring_size = 16, member_bytes = 96, source_bytes = 153 + ring_size * member_bytes;
constexpr size_t input_bytes = 179, signature_bytes = 128 + ring_size * 64;
constexpr uint8_t native_asset[32] = {0xd6,0x32,0x9b,0x5b,0x1f,0x7c,0x08,0x05,0xb5,0xc3,0x45,0xf4,0x95,0x75,0x54,0x00,
    0x2a,0x2f,0x55,0x78,0x45,0xf6,0x4d,0x76,0x45,0xda,0xe0,0xe0,0x51,0xa6,0x49,0x8a};

struct Layout {
  size_t count, prefix_size;
  const uint8_t *prefix, *keys, *sources;
};
bool layout(const ZanoPhonePayment &p, Layout &l) {
  if (p.size < 6 || p.size > sizeof(p.payload) || p.payload[0] != 1 ||
      p.payload[1] < 1 || p.payload[1] > 3 || p.payload[4] != 4) return false;
  l.count = p.payload[5];
  l.prefix_size = p.payload[2] | (size_t(p.payload[3]) << 8);
  if ((l.count != 1 && l.count != 2) || l.prefix_size != 352 + l.count * input_bytes ||
      p.size != 4 + l.prefix_size + 120 + l.count * source_bytes) return false;
  l.prefix = p.payload + 4;
  l.keys = l.prefix + l.prefix_size;
  l.sources = l.keys + 120;
  return true;
}

bool add_amount(uint64_t &sum, uint64_t amount) {
  if (!amount || UINT64_MAX - sum < amount) return false;
  sum += amount;
  return true;
}

struct InputSecrets {
  uint8_t secret[32], amount_delta[32], asset_delta[32], pseudo_amount[32], pseudo_asset[32];
  uint64_t amount;
};
bool open_input(const uint8_t *prefix, const uint8_t *record, const uint8_t spend[32], const uint8_t view[32],
                const uint8_t payer[32], ZanoRingMember (&ring)[ring_size], InputSecrets &s) {
  static_assert(sizeof(ZanoRingMember) == member_bytes, "Zano member encoding");
  if (record[0] >= ring_size || prefix[0] != 37 || prefix[1] != ring_size || prefix[input_bytes-1] != 0) return false;
  const uint8_t *amount_blind = record + 89, *asset_blind = record + 121;
  if (!scalar(amount_blind) || !scalar(asset_blind, false)) return false;
  memcpy(ring, record + 153, sizeof(ring));
  uint64_t absolute = 0;
  for (size_t i = 0; i < ring_size; ++i) {
    const uint8_t *index = prefix + 2 + 9*i;
    const uint64_t delta = chain_read_u64_le(index + 1);
    if (index[0] != 26 || (i && !delta) || UINT64_MAX - absolute < delta || !point(ring[i].destination) ||
        !point(ring[i].amount_commitment) || !point(ring[i].blinded_asset)) return false;
    absolute += delta;
    for (size_t j = 0; j < i; ++j) if (equal(ring[i].destination,ring[j].destination)) return false;
  }
  const auto &real = ring[record[0]];
  ZanoConfidentialOutput funding{};
  memcpy(funding.stealth_address,real.destination,32);
  memcpy(funding.concealing_point,record+41,32);
  memcpy(funding.amount_commitment,real.amount_commitment,32);
  memcpy(funding.blinded_asset,real.blinded_asset,32);
  funding.encrypted_amount = chain_read_u64_le(record+73);
  funding.encrypted_payment_id = chain_read_u64_le(record+81);
  const uint64_t index = chain_read_u64_le(record+1);
  SensitiveValue<ZanoReceivedOutput> owned;
  SensitiveValue<uint8_t[32]> derivation, asset, blinded, amount;
  uint8_t image[32];
  if (!zano_scan_output(view,payer,record+9,index,funding,&owned.get()) || !equal(owned.get().asset_id,native_asset) ||
      !cryptonote_generate_key_derivation(record+9,view,derivation.get()) ||
      !cryptonote_derive_secret_key(derivation.get(),index,spend,s.secret) ||
      !cryptonote_generate_key_image(real.destination,s.secret,image) || !equal(image,prefix+146)) return false;
  s.amount = owned.get().amount;
  chain_write_u64_le(s.amount,amount.get());
  ed25519_scalar_mulsub(s.amount_delta,kOne,amount_blind,owned.get().amount_mask);
  ed25519_scalar_mulsub(s.asset_delta,kOne,asset_blind,kZero);
  return ed25519_point_mul8_compressed(real.blinded_asset,asset.get()) &&
      combination(asset.get(),amount.get(),kG,amount_blind,blinded.get(),true) && mul(blinded.get(),kInv8,s.pseudo_amount) &&
      mul(kZanoX,asset_blind,blinded.get()) && ed25519_point_add_compressed(asset.get(),blinded.get(),blinded.get()) &&
      mul(blinded.get(),kInv8,s.pseudo_asset);
}

bool check_output(const uint8_t *out, const uint8_t *tx_secret, size_t index, const uint8_t *spend, const uint8_t *view,
                  uint64_t amount, uint64_t payment_id, const uint8_t *extra) {
  uint8_t explicit_asset[32];
  ZanoConfidentialOutput expected{};
  if (out[0] != 63 || out[1] != 0 || out[146] != 0 || !mul(native_asset,kInv8,explicit_asset) ||
      !zano_build_output(tx_secret,index,spend,view,native_asset,amount,payment_id,equal(explicit_asset,out+98),&expected) ||
      !equal(expected.stealth_address,out+2) || !equal(expected.concealing_point,out+34) ||
      !equal(expected.amount_commitment,out+66) || !equal(expected.blinded_asset,out+98) ||
      expected.encrypted_amount != chain_read_u64_le(out+130) || expected.encrypted_payment_id != chain_read_u64_le(out+138)) return false;
  SensitiveValue<uint8_t[32]> derivation, digest;
  if (!cryptonote_generate_key_derivation(view,tx_secret,derivation.get()) || !crypto_blake2b(derivation.get(),32,digest.get(),32)) return false;
  uint8_t hint[2]{};
  for (size_t i = 0; i < 32; ++i) hint[i%2] ^= digest.get()[i];
  return !memcmp(hint,extra+39,2) || !memcmp(hint,extra+43,2);
}
}

bool zano_phone_review(const ZanoPhonePayment &p, const uint8_t spend[32], const uint8_t view[32], ZanoPaymentReview &r) {
  Layout l;
  if (!layout(p,l)) return false;
  r = {};
  const uint8_t *extra = l.prefix + 2 + input_bytes*l.count;
  uint8_t tx_public[32];
  if (extra[0] != 5 || extra[1] != 22 || !scalar(l.keys,false) || !mul(kG,l.keys,tx_public) || !equal(tx_public,extra+2) ||
      memcmp(extra+34,"\x17\x00\x00\x0b\x02",5) || memcmp(extra+41,"\x0b\x02",2) || !memcmp(extra+39,extra+43,2) ||
      extra[45] != 39 || chain_read_u64_le(extra+46) != kZanoPhoneFee || extra[54] != 2 ||
      (extra[349] != 6 && extra[349] != 7)) return false;
  memcpy(r.recipient_spend,l.keys+32,32); memcpy(r.recipient_view,l.keys+64,32);
  if (!mul(kG,spend,r.payer_spend) || !mul(kG,view,r.payer_view) ||
      (equal(r.recipient_spend,r.payer_spend) && equal(r.recipient_view,r.payer_view))) return false;
  r.payment_id = chain_read_u64_le(l.keys+96);
  uint64_t total = 0;
  ZanoRingMember ring[ring_size];
  for (size_t i = 0; i < l.count; ++i) {
    const auto *in = l.prefix+2+i*input_bytes;
    SensitiveValue<InputSecrets> opened;
    if ((i && memcmp(in-input_bytes+146,in+146,32) >= 0) ||
        !open_input(in,l.sources+i*source_bytes,spend,view,r.payer_spend,ring,opened.get()) || !add_amount(total,opened.get().amount)) return false;
  }
  for (size_t i = 0; i < 2; ++i) {
    const bool external = (p.payload[1] & (1U << i)) != 0;
    const uint64_t amount = chain_read_u64_le(l.keys+104+8*i);
    if (!add_amount(external ? r.amount : r.change,amount) || !check_output(extra+55+147*i,l.keys,i,
        external ? r.recipient_spend : r.payer_spend,external ? r.recipient_view : r.payer_view,
        amount,external ? r.payment_id : 0,extra)) return false;
  }
  Transcript digest;
  return r.amount <= total && r.change <= total-r.amount && total-r.amount-r.change == kZanoPhoneFee &&
         digest.add(l.prefix,l.prefix_size) && digest.hash(r.prefix_hash);
}

bool zano_phone_sign(const ZanoPhonePayment &p, const uint8_t spend[32], const uint8_t view[32], uint8_t *out,size_t *size) {
  SigningOutputGuard guard(out,size);
  Layout l;
  ZanoPaymentReview review{};
  if (!guard.valid() || !layout(p,l) || *size < l.count*signature_bytes || !zano_phone_review(p,spend,view,review) ||
      !equal(review.prefix_hash,p.review.prefix_hash) || review.amount != p.review.amount || review.change != p.review.change ||
      review.payment_id != p.review.payment_id || !equal(review.recipient_spend,p.review.recipient_spend) ||
      !equal(review.recipient_view,p.review.recipient_view)) return false;
  ZanoRingMember ring[ring_size];
  auto *sig = new (std::nothrow) ZanoClsagSignature;
  if (!sig) return false;
  bool ok = true;
  for (size_t i = 0; ok && i < l.count; ++i) {
    const uint8_t *record = l.sources+i*source_bytes;
    SensitiveValue<InputSecrets> opened;
    SensitiveValue<uint8_t[32]> entropy;
    const auto &s = opened.get();
    ok = open_input(l.prefix+2+i*input_bytes,record,spend,view,review.payer_spend,ring,opened.get()) &&
        random_fill_checked(entropy.get(),32) && zano_clsag_ggx_sign(review.prefix_hash,ring,ring_size,record[0],
          s.secret,s.amount_delta,s.asset_delta,s.pseudo_amount,s.pseudo_asset,entropy.get(),sig);
    if (ok) {
      uint8_t *dest = out + i*signature_bytes;
      memcpy(dest,sig->challenge,32); memcpy(dest+32,sig->key_image,32);
      memcpy(dest+64,sig->auxiliary_image_1,32); memcpy(dest+96,sig->auxiliary_image_2,32);
      memcpy(dest+128,sig->responses_g,ring_size*32); memcpy(dest+128+ring_size*32,sig->responses_x,ring_size*32);
    }
  }
  secure_zero(sig,sizeof(*sig)); delete sig;
  if (!ok) return false;
  *size = l.count*signature_bytes;
  return guard.commit();
}
}
#endif
