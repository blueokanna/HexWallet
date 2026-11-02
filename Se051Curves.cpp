// Curve parameter blocks and the driver sequences that use them.
//
// Kept in its own translation unit so Se051Apdu.cpp stays about encoding and
// this file stays about what is written to a card. The values are the ones the
// NXP SDK's Se05x_API_CreateCurve_* helpers send
// (hostlib/hostLib/inc/se05x_ecc_curves_values.h), big endian, in the command
// order the SDK uses: A, B, G, N, PRIME.

#include "Se051Apdu.h"

#include <string.h>

#include "WalletSecurity.h"
#include "src/EcdsaCurve.h"

namespace hexwallet
{
  namespace
  {

    // secp256k1
    constexpr uint8_t kSecp256k1Prime[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};
    constexpr uint8_t kSecp256k1A[32] = {0};
    constexpr uint8_t kSecp256k1B[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    constexpr uint8_t kSecp256k1G[65] = {
        0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb,
        0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85,
        0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8};
    constexpr uint8_t kSecp256k1Order[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

    // prime256v1 / P-256 (the SDK calls it prime256v1)
    constexpr uint8_t kP256Prime[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    constexpr uint8_t kP256A[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
    constexpr uint8_t kP256B[32] = {
        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd,
        0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53,
        0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b};
    constexpr uint8_t kP256G[65] = {
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
    constexpr uint8_t kP256Order[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
        0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

    constexpr Se051CurveParams kCurves[] = {
        {kSe051CurveSecp256k1, kSecp256k1Prime, kSecp256k1A, kSecp256k1B,
         kSecp256k1G, kSecp256k1Order},
        {kSe051CurveNistP256, kP256Prime, kP256A, kP256B, kP256G, kP256Order},
    };

    constexpr size_t kCurveCount = sizeof(kCurves) / sizeof(kCurves[0]);
    constexpr size_t kMaxResponse = 256;

    // One command round trip: build, send, parse the status word.
    bool run_command(Se051Sender send, void *context, const uint8_t *builder_out,
                     size_t builder_size, uint16_t *status)
    {
      uint8_t response[kMaxResponse];
      size_t response_size = 0;
      if (!send(context, builder_out, builder_size, response, sizeof(response),
                &response_size))
      {
        return false;
      }
      const bool parsed = se051_response_status(status, response, response_size);
      secure_zero(response, sizeof(response));
      return parsed;
    }

  } // namespace

  const Se051CurveParams *se051_curve_params(uint8_t curve_id)
  {
    for (size_t index = 0; index < kCurveCount; ++index)
    {
      if (kCurves[index].curve_id == curve_id)
        return &kCurves[index];
    }
    return nullptr;
  }

  bool se051_install_curve(Se051Sender send, void *context, uint8_t curve_id,
                           uint16_t *status)
  {
    if (send == nullptr || status == nullptr)
      return false;
    const Se051CurveParams *params = se051_curve_params(curve_id);
    if (params == nullptr)
      return false;
    *status = 0x9000;
    uint8_t command[kSe051MaxApdu];
    size_t command_size = 0;
    // CreateECCurve first: the parameter commands reference an existing curve.
    if (!se051_apdu_create_ec_curve(curve_id, command, sizeof(command),
                                    &command_size) ||
        !run_command(send, context, command, command_size, status) ||
        *status != 0x9000)
    {
      secure_zero(command, sizeof(command));
      return false;
    }
    // The SDK's order: A, B, G, N, PRIME. Each parameter is a separate command,
    // so a failure midway leaves a curve that must not be used; the caller keeps
    // the card in that state only until it can be recovered by an operator.
    struct ParamStep
    {
      uint8_t type;
      const uint8_t *value;
      size_t size;
    };
    const ParamStep steps[5] = {
        {kSe051EcParamA, params->a, 32},
        {kSe051EcParamB, params->b, 32},
        {kSe051EcParamG, params->g, 65},
        {kSe051EcParamN, params->order, 32},
        {kSe051EcParamPrime, params->prime, 32},
    };
    for (const ParamStep &step : steps)
    {
      if (!se051_apdu_set_ec_curve_param(curve_id, step.type, step.value,
                                         step.size, command, sizeof(command),
                                         &command_size) ||
          !run_command(send, context, command, command_size, status) ||
          *status != 0x9000)
      {
        secure_zero(command, sizeof(command));
        return false;
      }
    }
    secure_zero(command, sizeof(command));
    return true;
  }

  bool se051_curve_present(Se051Sender send, void *context, uint8_t curve_id,
                           bool *present, uint16_t *status)
  {
    if (send == nullptr || present == nullptr || status == nullptr)
      return false;
    *present = false;
    uint8_t command[kSe051MaxApdu];
    size_t command_size = 0;
    if (!se051_apdu_read_curve_list(command, sizeof(command), &command_size))
      return false;
    uint8_t response[kMaxResponse];
    size_t response_size = 0;
    const bool sent = send(context, command, command_size, response,
                           sizeof(response), &response_size);
    const bool parsed = sent && se051_response_status(status, response, response_size);
    if (!parsed)
    {
      secure_zero(response, sizeof(response));
      return false;
    }
    if (*status != 0x9000)
    {
      secure_zero(response, sizeof(response));
      return false;
    }
    const bool listed =
        se051_response_curve_list_contains(curve_id, present, response,
                                          response_size);
    secure_zero(response, sizeof(response));
    return listed;
  }

  void se051_pin_reset(Se051PinSession *session)
  {
    if (session == nullptr)
      return;
    session->state = Se051PinState::Idle;
    session->attempts_left = 0xff;
    session->last_status = 0;
  }

  bool se051_pin_begin(Se051Sender send, void *context, uint32_t auth_object_id,
                       const uint8_t *policy, size_t policy_size,
                       Se051PinSession *session)
  {
    if (send == nullptr || session == nullptr || policy == nullptr ||
        policy_size == 0)
    {
      return false;
    }
    se051_pin_reset(session);
    uint8_t command[kSe051MaxApdu];
    size_t command_size = 0;
    if (!se051_apdu_session_create(auth_object_id, command, sizeof(command),
                                   &command_size) ||
        !run_command(send, context, command, command_size, &session->last_status))
    {
      secure_zero(command, sizeof(command));
      return false;
    }
    if (session->last_status != 0x9000)
    {
      secure_zero(command, sizeof(command));
      return false;
    }
    session->state = Se051PinState::SessionCreated;
    if (!se051_apdu_session_policy(policy, policy_size, command, sizeof(command),
                                   &command_size) ||
        !run_command(send, context, command, command_size, &session->last_status))
    {
      secure_zero(command, sizeof(command));
      return false;
    }
    if (session->last_status != 0x9000)
    {
      secure_zero(command, sizeof(command));
      return false;
    }
    secure_zero(command, sizeof(command));
    return true;
  }

  bool se051_pin_verify(Se051Sender send, void *context, const uint8_t *user_id,
                        size_t user_id_size, Se051PinSession *session)
  {
    if (send == nullptr || session == nullptr)
      return false;
    if (session->state != Se051PinState::SessionCreated &&
        session->state != Se051PinState::Authenticated)
    {
      return false;
    }
    uint8_t command[kSe051MaxApdu];
    size_t command_size = 0;
    if (!se051_apdu_verify_session_user_id(user_id, user_id_size, command,
                                           sizeof(command), &command_size) ||
        !run_command(send, context, command, command_size, &session->last_status))
    {
      secure_zero(command, sizeof(command));
      return false;
    }
    secure_zero(command, sizeof(command));
    if (session->last_status == 0x9000)
    {
      session->state = Se051PinState::Authenticated;
      return true;
    }
    // ISO 7816-4 0x63Cx: x attempts remain. Only this pattern is interpreted;
    // guessing at any other word could turn a transport fault into a burnt PIN.
    if ((session->last_status & 0xfff0) == 0x63c0)
    {
      session->attempts_left = static_cast<uint8_t>(session->last_status & 0x000f);
      if (session->attempts_left == 0)
        session->state = Se051PinState::Locked;
    }
    return false;
  }

  bool se051_pin_authenticated(const Se051PinSession *session)
  {
    return session != nullptr && session->state == Se051PinState::Authenticated;
  }

  bool se051_pin_hmac(Se051Sender send, void *context,
                      const Se051PinSession *session, uint32_t object_id,
                      uint8_t mac_operation, const uint8_t *data,
                      size_t data_size, uint8_t *out, size_t capacity,
                      size_t *out_size)
  {
    if (send == nullptr || out == nullptr || out_size == nullptr)
      return false;
    // The HMAC has to run inside the authenticated session that owns the key
    // object; issuing it outside would either fail or, worse, prove that the
    // card is willing to use the key without the UserID check.
    if (!se051_pin_authenticated(session))
      return false;
    uint8_t command[kSe051MaxApdu];
    size_t command_size = 0;
    if (!se051_apdu_hmac(object_id, mac_operation, data, data_size, command,
                         sizeof(command), &command_size))
    {
      return false;
    }
    uint8_t response[kMaxResponse];
    size_t response_size = 0;
    bool ok = send(context, command, command_size, response, sizeof(response),
                   &response_size);
    secure_zero(command, sizeof(command));
    if (!ok)
    {
      secure_zero(response, sizeof(response));
      return false;
    }
    uint16_t status = 0;
    ok = se051_response_status(&status, response, response_size) && status == 0x9000;
    if (ok)
    {
      const uint8_t *value = nullptr;
      size_t value_size = 0;
      ok = se051_response_tlv(kSe051Tag1, &value, &value_size, response,
                              response_size) &&
           value_size <= capacity;
      if (ok)
      {
        memcpy(out, value, value_size);
        *out_size = value_size;
      }
    }
    secure_zero(response, sizeof(response));
    return ok;
  }

} // namespace hexwallet
