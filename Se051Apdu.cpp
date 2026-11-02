#include "Se051Apdu.h"

#include <string.h>

#include "WalletSecurity.h"
#include "src/EcdsaCurve.h"

namespace hexwallet
{
  namespace
  {

    constexpr size_t kHeaderSize = 4;
    constexpr size_t kStatusSize = 2;

    // Short Le (0x00) for the commands plug-and-trust sends through
    // DoAPDUTxRx_s_Case4, and extended Le (0x00 0x00) for the ones it sends
    // through DoAPDUTxRx_s_Case4_ext. Those two helpers are the only difference
    // between the two, so the byte count differs by one.
    constexpr size_t kShortLeSize = 1;
    constexpr size_t kExtendedLeSize = 2;

    size_t tlv_length_size(size_t size)
    {
      if (size < 0x80)
        return 1;
      if (size <= 0xff)
        return 2;
      return 3;
    }

    // Writes header, Lc and data, then Le. `le_size` is 0 for a case-3 command
    // (status word only), 1 for a short Le and 2 for an extended Le. An empty
    // command is case 2 in ISO 7816-4: it carries no Lc byte at all, so the
    // frame is CLA INS P1 P2 Le. Emitting a zero Lc there would produce a
    // six-byte APDU no card reads the way the SDK intends.
    bool build(const uint8_t ins, const uint8_t p1, const uint8_t p2,
               const uint8_t *data, size_t data_size, size_t le_size,
               uint8_t *out, size_t capacity, size_t *out_size)
    {
      if (out == nullptr || out_size == nullptr || data_size > kSe051MaxData)
        return false;
      const bool has_lc = data_size != 0;
      const size_t total =
          kHeaderSize + (has_lc ? 1 + data_size : 0) + le_size;
      if (capacity < total)
        return false;
      out[0] = kSe051Cla;
      out[1] = ins;
      out[2] = p1;
      out[3] = p2;
      size_t offset = kHeaderSize;
      if (has_lc)
      {
        if (data == nullptr)
          return false;
        out[offset++] = static_cast<uint8_t>(data_size);
        memcpy(out + offset, data, data_size);
        offset += data_size;
      }
      for (size_t index = 0; index < le_size; ++index)
        out[offset + index] = 0x00;
      *out_size = total;
      return true;
    }

  } // namespace

  Se051TlvBuilder::Se051TlvBuilder(uint8_t *buffer, size_t capacity)
      : buffer_(buffer), capacity_(buffer == nullptr ? 0 : capacity), size_(0),
        ok_(buffer != nullptr)
  {
  }

  bool Se051TlvBuilder::reserve(uint8_t tag, size_t size)
  {
    if (!ok_)
      return false;
    const size_t length_size = tlv_length_size(size);
    if (size_ + 1 + length_size + size > capacity_)
    {
      ok_ = false;
      return false;
    }
    buffer_[size_++] = tag;
    if (length_size == 1)
    {
      buffer_[size_++] = static_cast<uint8_t>(size);
    }
    else if (length_size == 2)
    {
      buffer_[size_++] = 0x81;
      buffer_[size_++] = static_cast<uint8_t>(size);
    }
    else
    {
      buffer_[size_++] = 0x82;
      buffer_[size_++] = static_cast<uint8_t>(size >> 8);
      buffer_[size_++] = static_cast<uint8_t>(size);
    }
    return true;
  }

  bool Se051TlvBuilder::tag_u8(uint8_t tag, uint8_t value)
  {
    if (!reserve(tag, 1))
      return false;
    buffer_[size_++] = value;
    return true;
  }

  bool Se051TlvBuilder::tag_u16(uint8_t tag, uint16_t value)
  {
    if (!reserve(tag, 2))
      return false;
    buffer_[size_++] = static_cast<uint8_t>(value >> 8);
    buffer_[size_++] = static_cast<uint8_t>(value);
    return true;
  }

  bool Se051TlvBuilder::tag_u32(uint8_t tag, uint32_t value)
  {
    if (!reserve(tag, 4))
      return false;
    buffer_[size_++] = static_cast<uint8_t>(value >> 24);
    buffer_[size_++] = static_cast<uint8_t>(value >> 16);
    buffer_[size_++] = static_cast<uint8_t>(value >> 8);
    buffer_[size_++] = static_cast<uint8_t>(value);
    return true;
  }

  bool Se051TlvBuilder::tag_bytes(uint8_t tag, const uint8_t *value,
                                  size_t size)
  {
    if (size != 0 && value == nullptr)
    {
      ok_ = false;
      return false;
    }
    if (!reserve(tag, size))
      return false;
    if (size != 0)
    {
      memcpy(buffer_ + size_, value, size);
      size_ += size;
    }
    return true;
  }

  bool se051_apdu_get_version(uint8_t *out, size_t capacity, size_t *out_size)
  {
    // se05x_APDU_impl.h: `{{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT,
    // kSE05x_P2_VERSION}}` with an empty command buffer, case 2.
    return build(kSe051InsMgmt, kSe051P1Default, kSe051P2Version, nullptr, 0,
                 kShortLeSize, out, capacity, out_size);
  }

  bool se051_apdu_read_curve_list(uint8_t *out, size_t capacity,
                                  size_t *out_size)
  {
    // se05x_APDU_impl.h: kSE05x_INS_READ / kSE05x_P1_CURVE / kSE05x_P2_LIST,
    // empty command data, case 4. Response is TLV tag 1 with one byte per
    // provisioned curve id.
    return build(kSe051InsRead, kSe051P1Curve, kSe051P2List, nullptr, 0,
                 kShortLeSize, out, capacity, out_size);
  }

  bool se051_apdu_create_ec_curve(uint8_t curve_id, uint8_t *out,
                                  size_t capacity, size_t *out_size)
  {
    uint8_t data[8];
    Se051TlvBuilder builder(data, sizeof(data));
    // TLVSET_ECCurve("curve id", ..., kSE05x_TAG_1, curveID) - the curve id is
    // in the data as TLV tag 1, not in P1 or P2.
    if (!builder.tag_u8(kSe051Tag1, curve_id))
      return false;
    // Case 3: no Le.
    return build(kSe051InsWrite, kSe051P1Curve, kSe051P2Create, data,
                 builder.size(), 0, out, capacity, out_size);
  }

  bool se051_apdu_set_ec_curve_param(uint8_t curve_id, uint8_t param,
                                     const uint8_t *value, size_t value_size,
                                     uint8_t *out, size_t capacity,
                                     size_t *out_size)
  {
    if (value == nullptr || value_size == 0)
      return false;
    // 3 + 3 + (1 + len + value_size); the largest parameter is a 66-byte
    // uncompressed G, so a 96-byte scratch buffer is enough.
    uint8_t data[96];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_u8(kSe051Tag1, curve_id) ||
        !builder.tag_u8(kSe051Tag2, param) ||
        !builder.tag_bytes(kSe051Tag3, value, value_size))
    {
      return false;
    }
    return build(kSe051InsWrite, kSe051P1Curve, kSe051P2Param, data,
                 builder.size(), 0, out, capacity, out_size);
  }

  bool se051_apdu_sign(uint32_t object_id, uint8_t algorithm,
                       const uint8_t *input, size_t input_size, uint8_t *out,
                       size_t capacity, size_t *out_size)
  {
    if (input == nullptr && input_size != 0)
      return false;
    // 6 + 3 + (1 + len + input_size)
    uint8_t data[96];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_u32(kSe051Tag1, object_id) ||
        !builder.tag_u8(kSe051Tag2, algorithm) ||
        !builder.tag_bytes(kSe051Tag3, input, input_size))
    {
      return false;
    }
    return build(kSe051InsCrypto, kSe051P1Signature, kSe051P2Sign, data,
                 builder.size(), kShortLeSize, out, capacity, out_size);
  }

  bool se051_apdu_ecdh(uint32_t object_id, const uint8_t *peer_public,
                       size_t peer_public_size, uint8_t *out, size_t capacity,
                       size_t *out_size)
  {
    if (peer_public == nullptr || peer_public_size == 0)
      return false;
    // 6 + (1 + len + peer size), and a peer key is at most 66 bytes.
    uint8_t data[96];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_u32(kSe051Tag1, object_id) ||
        !builder.tag_bytes(kSe051Tag2, peer_public, peer_public_size))
    {
      return false;
    }
    // Case 4 extended in the SDK (`DoAPDUTxRx_s_Case4_ext`).
    return build(kSe051InsCrypto, kSe051P1Ec, kSe051P2Dh, data, builder.size(),
                 kExtendedLeSize, out, capacity, out_size);
  }

  bool se051_apdu_hmac(uint32_t object_id, uint8_t mac_operation,
                       const uint8_t *data_in, size_t data_size, uint8_t *out,
                       size_t capacity, size_t *out_size)
  {
    if (data_in == nullptr && data_size != 0)
      return false;
    // HMAC over a 64-byte BIP32 seed half plus a 4-byte index fits easily.
    uint8_t data[96];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_u32(kSe051Tag1, object_id) ||
        !builder.tag_u8(kSe051Tag2, mac_operation) ||
        !builder.tag_bytes(kSe051Tag3, data_in, data_size))
    {
      return false;
    }
    return build(kSe051InsCrypto, kSe051P1Mac, kSe051P2GenerateOneShot, data,
                 builder.size(), kShortLeSize, out, capacity, out_size);
  }

  bool se051_apdu_session_create(uint32_t auth_object_id, uint8_t *out,
                                 size_t capacity, size_t *out_size)
  {
    uint8_t data[8];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_u32(kSe051Tag1, auth_object_id))
      return false;
    return build(kSe051InsMgmt, kSe051P1Default, kSe051P2SessionCreate, data,
                 builder.size(), kShortLeSize, out, capacity, out_size);
  }

  bool se051_apdu_session_policy(const uint8_t *policy, size_t policy_size,
                                 uint8_t *out, size_t capacity,
                                 size_t *out_size)
  {
    if (policy == nullptr || policy_size == 0)
      return false;
    uint8_t data[24];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_bytes(kSe051Tag1, policy, policy_size))
      return false;
    return build(kSe051InsMgmt, kSe051P1Default, kSe051P2SessionPolicy, data,
                 builder.size(), kShortLeSize, out, capacity, out_size);
  }

  bool se051_apdu_verify_session_user_id(const uint8_t *user_id,
                                         size_t user_id_size, uint8_t *out,
                                         size_t capacity, size_t *out_size)
  {
    uint8_t data[24];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_bytes(kSe051Tag1, user_id, user_id_size))
      return false;
    return build(kSe051InsMgmt, kSe051P1Default, kSe051P2SessionUserId, data,
                 builder.size(), 0, out, capacity, out_size);
  }

  bool se051_apdu_get_random(uint16_t size, uint8_t *out, size_t capacity,
                             size_t *out_size)
  {
    if (size == 0)
      return false;
    uint8_t data[8];
    Se051TlvBuilder builder(data, sizeof(data));
    if (!builder.tag_u16(kSe051Tag1, size))
      return false;
    // Case 4 extended in the SDK. The response is one byte of padding plus the
    // random bytes; callers must use se051_response_tlv.
    return build(kSe051InsMgmt, kSe051P1Default, kSe051P2Random, data,
                 builder.size(), kExtendedLeSize, out, capacity, out_size);
  }

  bool se051_response_status(uint16_t *status, const uint8_t *response,
                             size_t response_size)
  {
    if (status == nullptr || response == nullptr ||
        response_size < kStatusSize)
    {
      return false;
    }
    *status = static_cast<uint16_t>((static_cast<uint16_t>(
                                         response[response_size - 2])
                                     << 8) |
                                    response[response_size - 1]);
    return true;
  }

  bool se051_response_tlv(uint8_t tag, const uint8_t **value,
                          size_t *value_size, const uint8_t *response,
                          size_t response_size)
  {
    if (value == nullptr || value_size == nullptr || response == nullptr ||
        response_size < kStatusSize)
    {
      return false;
    }
    const size_t body = response_size - kStatusSize;
    size_t offset = 0;
    while (offset < body)
    {
      const uint8_t found_tag = response[offset++];
      if (offset >= body)
        return false;
      size_t length = response[offset++];
      if (length == 0x81 || length == 0x82)
      {
        const size_t bytes = length == 0x81 ? 1 : 2;
        if (offset + bytes > body)
          return false;
        length = 0;
        for (size_t index = 0; index < bytes; ++index)
          length = (length << 8) | response[offset + index];
        offset += bytes;
      }
      else if (length > 0x7f)
      {
        return false;
      }
      if (offset + length > body)
        return false;
      if (found_tag == tag)
      {
        *value = response + offset;
        *value_size = length;
        return true;
      }
      offset += length;
    }
    return false;
  }

  bool se051_response_curve_list_contains(uint8_t curve_id, bool *present,
                                          const uint8_t *response,
                                          size_t response_size)
  {
    if (present == nullptr)
      return false;
    const uint8_t *list = nullptr;
    size_t list_size = 0;
    *present = false;
    if (!se051_response_tlv(kSe051Tag1, &list, &list_size, response,
                            response_size))
    {
      return false;
    }
    for (size_t index = 0; index < list_size; ++index)
    {
      if (list[index] == curve_id)
      {
        *present = true;
        break;
      }
    }
    return true;
  }

  namespace
  {

    // A card that answers with whatever status the test asked for, and records the
    // frames it was sent. Enough to prove a sequence's order, frame count and stop
    // condition without a card.
    struct FakeCard
    {
      uint16_t status;
      uint8_t response[256];
      size_t response_size;
      struct
      {
        uint8_t bytes[kSe051MaxApdu];
        size_t size;
      } frames[16];
      size_t count;
      size_t fail_at;
    };

    bool fake_send(void *context, const uint8_t *command, size_t command_size,
                   uint8_t *response, size_t response_capacity,
                   size_t *response_size)
    {
      FakeCard *card = static_cast<FakeCard *>(context);
      if (card == nullptr || command == nullptr || response == nullptr ||
          response_size == nullptr)
      {
        return false;
      }
      if (card->count < 16 && command_size <= kSe051MaxApdu)
      {
        memcpy(card->frames[card->count].bytes, command, command_size);
        card->frames[card->count].size = command_size;
      }
      ++card->count;
      const bool failing = card->fail_at != 0 && card->count == card->fail_at;
      const uint16_t status = failing ? 0x6985 : card->status;
      const size_t body = card->response_size;
      if (body + 2 > response_capacity)
        return false;
      if (body != 0)
        memcpy(response, card->response, body);
      response[body] = static_cast<uint8_t>(status >> 8);
      response[body + 1] = static_cast<uint8_t>(status);
      *response_size = body + 2;
      return true;
    }

    // Compares a published parameter block against the curve this firmware signs
    // on. Anything that describes a different curve is a provisioning-time bug
    // that would only surface as an unverifiable signature.
    bool se051_curve_params_match_engine(uint8_t curve_id, EcdsaCurve engine)
    {
      const Se051CurveParams *params = se051_curve_params(curve_id);
      const ecdsa_detail::Curve *curve = ecdsa_detail::curve_for(engine);
      if (params == nullptr || curve == nullptr)
        return false;
      uint8_t expected[32];
      ecdsa_detail::write_num(curve->prime, expected);
      bool passed = memcmp(params->prime, expected, 32) == 0;
      ecdsa_detail::write_num(curve->order, expected);
      passed = passed && memcmp(params->order, expected, 32) == 0;
      ecdsa_detail::write_num(curve->curve_b, expected);
      passed = passed && memcmp(params->b, expected, 32) == 0;
      if (curve->a_is_minus_three)
      {
        ecdsa_detail::Num three;
        ecdsa_detail::sub_raw(curve->prime, ecdsa_detail::Num{{3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}},
                              &three);
        ecdsa_detail::write_num(three, expected);
      }
      else
      {
        memset(expected, 0, sizeof(expected));
      }
      passed = passed && memcmp(params->a, expected, 32) == 0;
      passed = passed && params->g[0] == 0x04;
      ecdsa_detail::write_num(curve->gx, expected);
      passed = passed && memcmp(params->g + 1, expected, 32) == 0;
      ecdsa_detail::write_num(curve->gy, expected);
      passed = passed && memcmp(params->g + 33, expected, 32) == 0;
      secure_zero(expected, sizeof(expected));
      return passed;
    }

  } // namespace

  bool run_se051_apdu_self_tests()
  {
    bool passed = true;
    uint8_t apdu[kSe051MaxApdu];
    size_t size = 0;
    static const uint8_t kExpectedVersion[5] = {0x80, 0x04, 0x00, 0x20, 0x00};
    passed = passed && se051_apdu_get_version(apdu, sizeof(apdu), &size) &&
             size == sizeof(kExpectedVersion) &&
             memcmp(apdu, kExpectedVersion, size) == 0;

    // ReadECCurveList: 80 02 0B 25 00.
    static const uint8_t kExpectedList[5] = {0x80, 0x02, 0x0b, 0x25, 0x00};
    passed = passed && se051_apdu_read_curve_list(apdu, sizeof(apdu), &size) &&
             size == sizeof(kExpectedList) &&
             memcmp(apdu, kExpectedList, size) == 0;

    static const uint8_t kExpectedCreate[8] = {0x80, 0x01, 0x0b, 0x04,
                                               0x03, 0x41, 0x01, 0x10};
    passed = passed && se051_apdu_create_ec_curve(kSe051CurveSecp256k1, apdu, sizeof(apdu), &size) &&
             size == sizeof(kExpectedCreate) &&
             memcmp(apdu, kExpectedCreate, size) == 0;

    static const uint8_t kExpectedParam[12] = {0x80, 0x01, 0x0b, 0x40, 0x09,
                                               0x41, 0x01, 0x10, 0x42, 0x01,
                                               0x10, 0x43};
    static const uint8_t kParamValue[1] = {0x01};
    passed = passed && se051_apdu_set_ec_curve_param(kSe051CurveSecp256k1, kSe051EcParamPrime, kParamValue, 1, apdu, sizeof(apdu), &size) &&
             size == sizeof(kExpectedParam) + 2 &&
             memcmp(apdu, kExpectedParam, sizeof(kExpectedParam)) == 0 &&
             apdu[12] == 0x01 && apdu[13] == 0x01;

    uint8_t parameter[32];
    memset(parameter, 0x5a, sizeof(parameter));
    passed = passed && se051_apdu_set_ec_curve_param(kSe051CurveNistP256, kSe051EcParamPrime, parameter, sizeof(parameter), apdu, sizeof(apdu), &size) &&
             size == 5 + 40 && apdu[4] == 40 && apdu[5] == 0x41 &&
             apdu[8] == 0x42 && apdu[11] == 0x43 && apdu[12] == 32 &&
             memcmp(apdu + 13, parameter, sizeof(parameter)) == 0;

    uint8_t digest[32];
    memset(digest, 0xa5, sizeof(digest));
    passed = passed && se051_apdu_sign(0x00000001u, kSe051SignAlgoSha256, digest, sizeof(digest), apdu, sizeof(apdu), &size) &&
             size == 5 + 43 + 1 && apdu[0] == 0x80 && apdu[1] == 0x03 &&
             apdu[2] == 0x0c && apdu[3] == 0x09 && apdu[4] == 43 &&
             apdu[5] == 0x41 && apdu[6] == 0x04 && apdu[10] == 0x01 &&
             apdu[11] == 0x42 && apdu[12] == 0x01 && apdu[13] == 0x21 &&
             apdu[14] == 0x43 && apdu[15] == 32 &&
             memcmp(apdu + 16, digest, sizeof(digest)) == 0 &&
             apdu[size - 1] == 0x00;

    // ECDH uses the extended Le, so the frame ends 00 00.
    static const uint8_t kPeer[33] = {0x03, 0x01};
    passed = passed && se051_apdu_ecdh(0x00000002u, kPeer, sizeof(kPeer), apdu, sizeof(apdu), &size) &&
             size == 5 + (6 + 35) + 2 && apdu[0] == 0x80 && apdu[1] == 0x03 &&
             apdu[2] == 0x01 && apdu[3] == 0x0f && apdu[4] == 41 &&
             apdu[size - 1] == 0x00 && apdu[size - 2] == 0x00;

    // HMAC one-shot: 80 03 0D 45 Lc | 41 04 <obj> | 42 01 <op> | 43 <len> <data>.
    uint8_t mac_input[64];
    memset(mac_input, 0x33, sizeof(mac_input));
    passed = passed && se051_apdu_hmac(0x00000003u, 0x0a, mac_input, sizeof(mac_input), apdu, sizeof(apdu), &size) &&
             size == 5 + (6 + 3 + 66) + 1 && apdu[1] == 0x03 &&
             apdu[2] == 0x0d && apdu[3] == 0x45 && apdu[4] == 75 &&
             apdu[11] == 0x42 && apdu[12] == 0x01 && apdu[13] == 0x0a &&
             apdu[14] == 0x43 && apdu[15] == 64 &&
             memcmp(apdu + 16, mac_input, sizeof(mac_input)) == 0;

    // Session commands. VerifySessionUserID is case 3, so it has no Le.
    passed = passed && se051_apdu_verify_session_user_id(nullptr, 0, apdu, sizeof(apdu), &size) &&
             size == 5 + 2 && apdu[1] == 0x04 && apdu[3] == 0x2c &&
             apdu[4] == 2 && apdu[5] == 0x41 && apdu[6] == 0x00;
    passed = passed && se051_apdu_session_create(0x7fff0207u, apdu, sizeof(apdu), &size) &&
             size == 5 + 6 + 1 && apdu[3] == 0x1b && apdu[5] == 0x41 &&
             apdu[6] == 0x04 && apdu[10] == 0x07;

    // GetRandom: 41 02 <size>, case 4 extended so the frame ends 00 00.
    passed = passed && se051_apdu_get_random(32, apdu, sizeof(apdu), &size) &&
             size == 5 + 4 + 2 && apdu[3] == 0x49 && apdu[5] == 0x41 &&
             apdu[6] == 0x02 && apdu[7] == 0x00 && apdu[8] == 0x20 &&
             apdu[9] == 0x00 && apdu[10] == 0x00;

    {
      uint8_t scratch[300];
      Se051TlvBuilder builder(scratch, sizeof(scratch));
      uint8_t payload[0x80];
      memset(payload, 0x11, sizeof(payload));
      passed = passed && builder.tag_bytes(0x43, payload, 0x7f) &&
               builder.size() == 2 + 0x7f;
      Se051TlvBuilder long_builder(scratch, sizeof(scratch));
      passed = passed && long_builder.tag_bytes(0x43, payload, sizeof(payload)) &&
               long_builder.size() == 3 + sizeof(payload) &&
               scratch[0] == 0x43 && scratch[1] == 0x81 &&
               scratch[2] == 0x80;
      uint8_t tight[4];
      Se051TlvBuilder cramped(tight, sizeof(tight));
      passed = passed && !cramped.tag_bytes(0x43, payload, sizeof(payload)) &&
               !cramped.ok();
    }

    {
      uint8_t huge[300];
      memset(huge, 0x22, sizeof(huge));
      passed = passed && !se051_apdu_sign(1, kSe051SignAlgoPlain, huge,
                                          sizeof(huge), apdu, sizeof(apdu),
                                          &size);
      uint8_t small[4];
      passed = passed && !se051_apdu_create_ec_curve(kSe051CurveNistP256, small,
                                                     sizeof(small), &size);
    }

    static const uint8_t kCurveResponse[7] = {0x41, 0x03, 0x03, 0x10, 0x41,
                                              0x90, 0x00};
    uint16_t status = 0;
    bool present = false;
    passed = passed && se051_response_status(&status, kCurveResponse, sizeof(kCurveResponse)) &&
             status == 0x9000 &&
             se051_response_curve_list_contains(kSe051CurveSecp256k1, &present,
                                                kCurveResponse,
                                                sizeof(kCurveResponse)) &&
             present;
    present = true;
    passed = passed && se051_response_curve_list_contains(kSe051CurveEd25519, &present, kCurveResponse, sizeof(kCurveResponse)) &&
             !present;
    static const uint8_t kTruncated[4] = {0x41, 0x05, 0x03, 0x90};
    static const uint8_t kNonMinimal[7] = {0x41, 0x81, 0x01, 0x03, 0x00,
                                           0x90, 0x00};
    const uint8_t *value = nullptr;
    size_t value_size = 0;
    passed = passed && !se051_response_tlv(kSe051Tag1, &value, &value_size, kTruncated, sizeof(kTruncated)) &&
             se051_response_tlv(kSe051Tag1, &value, &value_size, kNonMinimal,
                                sizeof(kNonMinimal)) &&
             value_size == 1 && value[0] == 0x03;

    secure_zero(apdu, sizeof(apdu));
    secure_zero(digest, sizeof(digest));
    secure_zero(parameter, sizeof(parameter));
    secure_zero(mac_input, sizeof(mac_input));
    passed = passed &&
             se051_curve_params_match_engine(kSe051CurveSecp256k1, EcdsaCurve::Secp256k1) &&
             se051_curve_params_match_engine(kSe051CurveNistP256, EcdsaCurve::Secp256r1);
    passed = passed && se051_curve_params(kSe051CurveEd25519) == nullptr &&
             se051_curve_params(0x00) == nullptr;

    // Installer and PIN sequences against a fake card that records frames.
    {
      FakeCard card = {};
      card.status = 0x9000;
      uint16_t status = 0;
      passed = passed && se051_install_curve(fake_send, &card, kSe051CurveSecp256k1, &status) &&
               status == 0x9000 && card.count == 6 &&
               card.frames[0].size == 8 && card.frames[0].bytes[3] == 0x04 &&
               card.frames[1].bytes[3] == 0x40 && card.frames[1].bytes[8] == 0x42 &&
               card.frames[1].bytes[10] == kSe051EcParamA &&
               card.frames[3].bytes[10] == kSe051EcParamG &&
               card.frames[3].size == 78 &&
               card.frames[5].bytes[10] == kSe051EcParamPrime;
      FakeCard unknown = {};
      unknown.status = 0x9000;
      passed = passed && !se051_install_curve(fake_send, &unknown, 0x7f, &status) &&
               unknown.count == 0;
      FakeCard partial = {};
      partial.status = 0x9000;
      partial.fail_at = 2;
      passed = passed && !se051_install_curve(fake_send, &partial, kSe051CurveNistP256, &status) &&
               status == 0x6985 && partial.count == 2;
    }

    {
      FakeCard card = {};
      card.status = 0x9000;
      static const uint8_t kList[] = {0x41, 0x02, 0x03, 0x10, 0x90, 0x00};
      memcpy(card.response, kList, sizeof(kList));
      card.response_size = sizeof(kList);
      bool present = false;
      uint16_t status = 0;
      passed = passed && se051_curve_present(fake_send, &card, kSe051CurveSecp256k1, &present, &status) &&
               present && status == 0x9000;
      present = true;
      passed = passed && se051_curve_present(fake_send, &card, kSe051CurveEd25519, &present, &status) &&
               !present;
      FakeCard refusing = {};
      refusing.status = 0x6a88;
      present = false;
      passed = passed && !se051_curve_present(fake_send, &refusing, kSe051CurveSecp256k1, &present, &status) &&
               !present && status == 0x6a88;
    }

    {
      FakeCard card = {};
      card.status = 0x9000;
      static const uint8_t kPolicy[8] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00};
      Se051PinSession session;
      se051_pin_reset(&session);
      uint8_t user_id[16];
      memset(user_id, 0x11, sizeof(user_id));
      passed = passed && se051_pin_begin(fake_send, &card, 0x7fff0207u, kPolicy, sizeof(kPolicy), &session) &&
               session.state == Se051PinState::SessionCreated &&
               card.count == 2 && card.frames[0].bytes[3] == 0x1b &&
               card.frames[1].bytes[3] == 0x1f;
      {
        uint8_t unused_mac[8] = {};
        size_t unused_size = 0;
        passed = passed &&
                 !se051_pin_hmac(fake_send, &card, &session, 0x00000003u, 0x0a,
                                 user_id, sizeof(user_id), unused_mac,
                                 sizeof(unused_mac), &unused_size) &&
                 card.count == 2;
      }
      card.status = 0x63c2;
      passed = passed && !se051_pin_verify(fake_send, &card, user_id, sizeof(user_id), &session) &&
               session.attempts_left == 2 &&
               session.state == Se051PinState::SessionCreated;
      card.status = 0x9000;
      passed = passed && se051_pin_verify(fake_send, &card, user_id, sizeof(user_id), &session) &&
               se051_pin_authenticated(&session);
      static const uint8_t kMac[] = {0x41, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
                                     0x90, 0x00};
      memcpy(card.response, kMac, sizeof(kMac));
      card.response_size = sizeof(kMac);
      uint8_t mac[8] = {};
      size_t mac_size = 0;
      passed = passed && se051_pin_hmac(fake_send, &card, &session, 0x00000003u, 0x0a, user_id, sizeof(user_id), mac, sizeof(mac), &mac_size) &&
               mac_size == 4 && mac[0] == 0xaa && mac[3] == 0xdd;
      Se051PinSession locked;
      se051_pin_reset(&locked);
      locked.state = Se051PinState::SessionCreated;
      card.status = 0x63c0;
      passed = passed && !se051_pin_verify(fake_send, &card, user_id, sizeof(user_id), &locked) &&
               locked.state == Se051PinState::Locked &&
               !se051_pin_authenticated(&locked);
    }
    return passed;
  }

}
