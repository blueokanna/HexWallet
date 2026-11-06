#include "BeamPayment.h"
#include "RandomSource.h"
#include "WalletSecurity.h"
#include "src/beam/WalletKeys.h"

namespace hexwallet {
namespace {
using namespace ECC;

Point read_point(const uint8_t wire[33]) {
  Point p;
  memcpy(p.m_X.m_pData, wire, 32);
  p.m_Y = wire[32];
  return p;
}

void write_point(uint8_t wire[33], const Point &p) {
  memcpy(wire, p.m_X.m_pData, 32);
  wire[32] = p.m_Y;
}

bool read_endpoint(const uint8_t id[32], Point::Native &point) {
  Point p;
  memcpy(p.m_X.m_pData, id, 32);
  p.m_Y = 0;
  return point.ImportNnz(p);
}

void endpoint_key(HKdf &master, uint64_t index, Scalar::Native &sk, Point &pk) {
  Hash::Value id;
  Key::ID(index, Key::Type::EndPoint).get_Hash(id);
  master.DeriveKey(sk, id);
  pk = Point::Native(Context::get().G * sk);
  if (pk.m_Y) sk = -sk;
}

bool valid_offer(const BeamOffer &o) {
  Point::Native p;
  return o.amount && o.fee >= 28000 && o.min_height >= 3928666 && o.max_height >= o.min_height &&
      o.max_height - o.min_height <= 43200 &&
      read_endpoint(o.sender, p) && read_endpoint(o.receiver, p) &&
      p.ImportNnz(read_point(o.sender_excess)) && p.ImportNnz(read_point(o.sender_nonce));
}

void kernel_id(const BeamOffer &offer, const Point &excess, Hash::Value &id) {
  Hash::Processor() << offer.fee << offer.min_height << offer.max_height << excess
                    << uint64_t(0) << uint8_t(0) << true >> id;
}

void payment_message(const BeamOffer &offer, const Hash::Value &kernel, Hash::Value &message) {
  Hash::Processor() << "PaymentConfirmation" << kernel << beam::Blob(offer.sender, 32)
                    << offer.amount >> message;
}
}

bool beam_decode_offer(const uint8_t (&wire)[kBeamOfferSize], BeamOffer &offer) {
  const uint8_t *cursor = wire;
  auto integer = [&]() {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; ++i) n = (n << 8) | *cursor++;
    return n;
  };
  auto field = [&](auto &dest) { memcpy(dest, cursor, sizeof(dest)); cursor += sizeof(dest); };
  offer.amount = integer();
  offer.fee = integer();
  offer.min_height = integer();
  offer.max_height = integer();
  field(offer.sender);
  field(offer.receiver);
  field(offer.sender_excess);
  field(offer.sender_nonce);
  return valid_offer(offer);
}

void beam_encode_offer(const BeamOffer &offer, uint8_t (&wire)[kBeamOfferSize]) {
  uint8_t *cursor = wire;
  for (uint64_t v : {offer.amount, offer.fee, offer.min_height, offer.max_height}) {
    for (int shift = 56; shift >= 0; shift -= 8) *cursor++ = uint8_t(v >> shift);
  }
  auto field = [&](const auto &src) { memcpy(cursor, src, sizeof(src)); cursor += sizeof(src); };
  field(offer.sender);
  field(offer.receiver);
  field(offer.sender_excess);
  field(offer.sender_nonce);
}

bool beam_endpoint(const uint8_t seed[64], uint64_t index, uint8_t out[32]) {
  if (!out) return false;
  memset(out, 0, 32);
  if (!seed || !index) return false;
  try {
    HKdf master;
    beam_keys::master_key(seed, master);
    Scalar::Native sk;
    Point pk;
    endpoint_key(master, index, sk, pk);
    memcpy(out, pk.m_X.m_pData, 32);
    return true;
  } catch (const std::exception &) { return false; }
}

bool beam_verify_receiver(const BeamOffer &offer, const BeamReceiverReply &reply) {
  try {
    if (!valid_offer(offer) || !beam_verify_output(reply.output)) return false;
    Point::Native excess, nonce, sender_excess, sender_nonce, receiver;
    Signature partial, receipt;
    partial.m_NoncePub = read_point(reply.total_nonce);
    receipt.m_NoncePub = read_point(reply.payment_confirmation);
    memcpy(partial.m_k.m_Value.m_pData, reply.partial_signature, 32);
    memcpy(receipt.m_k.m_Value.m_pData, reply.payment_confirmation + 33, 32);
    Scalar offset;
    memcpy(offset.m_Value.m_pData, reply.offset, 32);
    if (!partial.m_k.IsValid() || !receipt.m_k.IsValid() || !offset.IsValid() ||
        !excess.ImportNnz(read_point(reply.total_excess)) || !nonce.ImportNnz(partial.m_NoncePub) ||
        !sender_excess.ImportNnz(read_point(offer.sender_excess)) ||
        !sender_nonce.ImportNnz(read_point(offer.sender_nonce)) ||
        !read_endpoint(offer.receiver, receiver)) return false;
    Point::Native receipt_nonce;
    if (!receipt_nonce.ImportNnz(receipt.m_NoncePub)) return false;
    Hash::Value kernel, message;
    kernel_id(offer, Point(excess), kernel);
    payment_message(offer, kernel, message);
    if (!receipt.IsValid(message, receiver)) return false;
    excess -= sender_excess;
    nonce -= sender_nonce;
    if (excess == Zero || nonce == Zero || !partial.IsValidPartial(kernel, nonce, excess)) return false;

    Point out;
    memcpy(out.m_X.m_pData, reply.output.commitment_x, 32);
    out.m_Y = reply.output.flags & 1;
    Point::Native sum;
    if (!sum.ImportNnz(out)) return false;
    sum += excess;
    sum += Context::get().G * Scalar::Native(offset);
    return sum == Point::Native(Context::get().H * offer.amount);
  } catch (const std::exception &) { return false; }
}

bool beam_receive(const uint8_t seed[64], uint64_t endpoint_index, const BeamOffer &offer,
                  BeamReceiverReply &reply) {
  reply = {};
  if (!seed || !endpoint_index) return false;
  try {
    if (!valid_offer(offer)) return false;
    HKdf master;
    beam_keys::master_key(seed, master);
    Scalar::Native endpoint_sk;
    Point endpoint_pk;
    endpoint_key(master, endpoint_index, endpoint_sk, endpoint_pk);
    if (memcmp(offer.receiver, endpoint_pk.m_X.m_pData, 32)) return false;

    BeamCoin coin{0, BeamCoinType::Regular, 0, offer.amount};
    if (!random_fill_checked(&coin.index, sizeof(coin.index))) return false;
    BeamReceiverReply candidate{};
    if (!beam_create_output(seed, coin, candidate.output)) return false;
    Point commitment;
    Scalar::Native blind, kernel_sk, nonce_sk;
    beam_keys::switch_commitment(master, coin, blind, commitment);
    Hash::Value initial_kernel;
    kernel_id(offer, read_point(offer.sender_excess), initial_kernel);
    NoLeak<Hash::Value> transcript;
    Hash::Processor() << initial_kernel << read_point(offer.sender_nonce) << false
                      << beam::Blob(offer.sender, 32) << endpoint_index << blind
                      << offer.amount << uint32_t(0) >> transcript.V;
    NonceGenerator nonces("hw-wlt-rcv");
    nonces << transcript.V;
    nonces >> kernel_sk;
    nonces >> nonce_sk;
    Point::Native excess, nonce;
    if (!excess.ImportNnz(read_point(offer.sender_excess)) ||
        !nonce.ImportNnz(read_point(offer.sender_nonce))) return false;
    excess += Context::get().G * kernel_sk;
    nonce += Context::get().G * nonce_sk;
    if (excess == Zero || nonce == Zero) return false;
    write_point(candidate.total_excess, Point(excess));
    write_point(candidate.total_nonce, Point(nonce));
    Hash::Value kernel, message;
    kernel_id(offer, Point(excess), kernel);
    Signature partial;
    partial.m_NoncePub = nonce;
    partial.SignPartial(kernel, kernel_sk, nonce_sk);
    memcpy(candidate.partial_signature, partial.m_k.m_Value.m_pData, 32);
    Scalar::Native offset = blind + kernel_sk;
    offset = -offset;
    Scalar packed(offset);
    memcpy(candidate.offset, packed.m_Value.m_pData, 32);
    payment_message(offer, kernel, message);
    Signature receipt;
    receipt.Sign(message, endpoint_sk);
    write_point(candidate.payment_confirmation, receipt.m_NoncePub);
    memcpy(candidate.payment_confirmation + 33, receipt.m_k.m_Value.m_pData, 32);
    if (!beam_verify_receiver(offer, candidate)) return false;
    reply = candidate;
    return true;
  } catch (const std::exception &) { return false; }
}

void BeamSender::cancel() {
  secure_zero(kernel_secret_, sizeof(kernel_secret_));
  secure_zero(nonce_, sizeof(nonce_));
  secure_zero(offset_, sizeof(offset_));
  offer_ = {};
  change_ = {};
  change_amount_ = 0;
  memset(input_, 0, sizeof(input_));
  has_change_ = active_ = false;
}

bool BeamSender::begin(const uint8_t seed[64], uint64_t index, const uint8_t receiver[32],
                       const BeamOutput &input, uint64_t amount, uint64_t fee, uint64_t min_height,
                       uint64_t max_height, BeamOffer &offer) {
  cancel();
  offer = {};
  if (!seed || !receiver || !index || !amount || !fee || min_height < 3928666 ||
      max_height < min_height || max_height - min_height > 43200 || max_height == UINT64_MAX) return false;
  try {
    Point::Native peer;
    BeamCoin owned{};
    if (!read_endpoint(receiver, peer) || !beam_recover_output(seed, input, owned) ||
        amount > owned.groth || fee > owned.groth - amount) return false;
    HKdf master;
    beam_keys::master_key(seed, master);
    Scalar::Native endpoint_sk, input_sk;
    Point pk, commitment;
    endpoint_key(master, index, endpoint_sk, pk);
    beam_keys::switch_commitment(master, owned, input_sk, commitment);
    input_[0] = commitment.m_Y;
    memcpy(input_ + 1, commitment.m_X.m_pData, 32);
    const uint64_t change_amount = owned.groth - amount - fee;
    if (fee < 10000u + 18000u * (change_amount ? 2u : 1u)) return false;
    change_amount_ = change_amount;
    if (change_amount) {
      BeamCoin change{0, BeamCoinType::Change, 0, change_amount};
      if (!random_fill_checked(&change.index, sizeof(change.index)) ||
          !beam_create_output(seed, change, change_)) return false;
      Scalar::Native change_sk;
      beam_keys::switch_commitment(master, change, change_sk, commitment);
      input_sk -= change_sk;
      has_change_ = true;
    }
    offer_.amount = amount;
    offer_.fee = fee;
    offer_.min_height = min_height;
    offer_.max_height = max_height;
    memcpy(offer_.sender, pk.m_X.m_pData, 32);
    memcpy(offer_.receiver, receiver, 32);
    Scalar::Native kernel_sk, nonce;
    nonce.GenRandomNnz();
    NoLeak<Hash::Value> context;
    Hash::Processor() << "hw-wlt-snd" << nonce << input_sk << index << beam::Blob(receiver, 32)
                      << amount << fee << min_height << max_height >> context.V;
    NonceGenerator keys("hw-wlt-snd");
    keys << context.V;
    keys >> kernel_sk;
    write_point(offer_.sender_excess, Point(Point::Native(Context::get().G * kernel_sk)));
    write_point(offer_.sender_nonce, Point(Point::Native(Context::get().G * nonce)));
    input_sk -= kernel_sk;
    NoLeak<Scalar> s;
    kernel_sk.Export(s.V); memcpy(kernel_secret_, s.V.m_Value.m_pData, 32);
    nonce.Export(s.V); memcpy(nonce_, s.V.m_Value.m_pData, 32);
    input_sk.Export(s.V); memcpy(offset_, s.V.m_Value.m_pData, 32);
    offer = offer_;
    active_ = true;
    return true;
  } catch (const std::exception &) { cancel(); return false; }
}

bool BeamSender::finish(const BeamReceiverReply &reply, BeamSignedTransfer &out) {
  out = {};
  if (!active_) return false;
  active_ = false;
  struct Cleanup { BeamSender &s; ~Cleanup() { s.cancel(); } } cleanup{*this};
  if (!beam_verify_receiver(offer_, reply)) return false;
  try {
    auto unpack = [](const uint8_t bytes[32], Scalar::Native &s) {
      NoLeak<Scalar> temp;
      memcpy(temp.V.m_Value.m_pData, bytes, 32);
      return !s.Import(temp.V);
    };
    Scalar::Native kernel_sk, nonce, offset, peer_offset, peer_sig;
    if (!unpack(kernel_secret_, kernel_sk) || !unpack(nonce_, nonce) || !unpack(offset_, offset) ||
        !unpack(reply.offset, peer_offset) || !unpack(reply.partial_signature, peer_sig)) return false;
    const Point excess = read_point(reply.total_excess);
    Hash::Value kernel;
    kernel_id(offer_, excess, kernel);
    Signature sig;
    sig.m_NoncePub = read_point(reply.total_nonce);
    sig.SignPartial(kernel, kernel_sk, nonce);
    peer_sig += sig.m_k;
    sig.m_k = peer_sig;
    Point::Native aggregate;
    if (!aggregate.ImportNnz(excess) || !sig.IsValid(kernel, aggregate)) return false;
    offset += peer_offset;
    const BeamOutput *first = &reply.output, *second = &change_;
    auto same_input = [&](const BeamOutput &o) {
      return (o.flags & 1) == input_[0] && !memcmp(o.commitment_x, input_ + 1, 32);
    };
    if (same_input(*first) || (has_change_ && same_input(*second))) return false;
    if (has_change_) {
      int cmp = memcmp(first->commitment_x, second->commitment_x, 32);
      if (!cmp) cmp = int(first->flags) - int(second->flags);
      if (!cmp) return false;
      if (cmp > 0) std::swap(first, second);
    }
    static_assert(sizeof(out.bytes) >= 12 + 33 + 2 * sizeof(BeamOutput) + 97 + 27 + 32);
    auto *cursor = out.bytes;
    auto bytes = [&](const void *p, size_t n) { memcpy(cursor, p, n); cursor += n; };
    auto count = [&](uint8_t n) { memset(cursor, 0, 3); cursor += 3; *cursor++ = n; };
    auto compact = [&](uint64_t v) {
      if (v < 128) { *cursor++ = uint8_t(128 | v); return; }
      uint8_t *length = cursor++;
      while (v) { *cursor++ = uint8_t(v); v >>= 8; }
      *length = uint8_t(cursor - length - 1);
    };
    count(1);
    bytes(input_, 33);
    count(has_change_ ? 2 : 1);
    bytes(first, sizeof(*first));
    if (has_change_) bytes(second, sizeof(*second));
    count(1);
    *cursor++ = 14 | excess.m_Y | (sig.m_NoncePub.m_Y << 4);
    bytes(excess.m_X.m_pData, 32);
    bytes(sig.m_NoncePub.m_X.m_pData, 32);
    bytes(sig.m_k.m_Value.m_pData, 32);
    compact(offer_.fee);
    compact(offer_.min_height);
    compact(offer_.max_height - offer_.min_height);
    Scalar encoded_offset(offset);
    bytes(encoded_offset.m_Value.m_pData, 32);
    out.size = size_t(cursor - out.bytes);
    return true;
  } catch (const std::exception &) { out = {}; return false; }
}
}
