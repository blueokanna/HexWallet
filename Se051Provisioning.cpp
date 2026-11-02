#include "Se051Provisioning.h"
#include "Se051Apdu.h"
#include <stddef.h>
#include <string.h>
namespace hexwallet
{
  Se051ProvisionResult se051_factory_prepare_curve(
      bool authorized, Se051CurveQuery query, Se051ProvisionCallback provision,
      void *context, uint16_t *status)
  {
    if (status != nullptr)
      *status = 0;
    if (!authorized)
      return Se051ProvisionResult::NotAuthorized;
    if (status == nullptr || query == nullptr)
      return Se051ProvisionResult::QueryFailed;
    Se051CurveState state = Se051CurveState::Unknown;
    if (!query(context, &state, status) || *status != 0x9000)
      return Se051ProvisionResult::QueryFailed;
    if (state == Se051CurveState::Ready)
      return Se051ProvisionResult::Ready;
    if (state != Se051CurveState::Absent)
      return Se051ProvisionResult::QueryFailed;
    *status = 0;
    if (provision == nullptr || !provision(context, status) || *status != 0x9000)
      return Se051ProvisionResult::ProvisionFailed;
    *status = 0;
    state = Se051CurveState::Unknown;
    if (!query(context, &state, status) || *status != 0x9000 || state != Se051CurveState::Ready)
      return Se051ProvisionResult::VerifyFailed;
    return Se051ProvisionResult::Provisioned;
  }

  namespace
  {
    bool provision_send(void *context, const uint8_t *command, size_t command_size,
                        uint8_t *response, size_t response_capacity,
                        size_t *response_size)
    {
      const Se051CurveProvisionContext &curve =
          *static_cast<const Se051CurveProvisionContext *>(context);
      return curve.send == nullptr ? false
                                   : curve.send(curve.transport, command,
                                                command_size, response,
                                                response_capacity, response_size);
    }

  }

  bool se051_curve_query(void *context, Se051CurveState *state,
                         uint16_t *status)
  {
    if (context == nullptr || state == nullptr)
      return false;
    const Se051CurveProvisionContext &curve =
        *static_cast<const Se051CurveProvisionContext *>(context);
    bool present = false;
    if (!se051_curve_present(provision_send, context, curve.curve_id, &present,
                             status))
    {
      return false;
    }
    *state = present ? Se051CurveState::Ready : Se051CurveState::Absent;
    return true;
  }

  bool se051_curve_provision(void *context, uint16_t *status)
  {
    if (context == nullptr)
      return false;
    const Se051CurveProvisionContext &curve =
        *static_cast<const Se051CurveProvisionContext *>(context);
    return se051_install_curve(provision_send, context, curve.curve_id, status);
  }

  namespace
  {
    struct Fixture
    {
      Se051CurveState first, second;
      uint16_t query_status, provision_status;
      unsigned queries, writes;
      bool query_ok, provision_ok;
    };
    bool query(void *context, Se051CurveState *state, uint16_t *status)
    {
      Fixture &f = *static_cast<Fixture *>(context);
      *state = f.queries++ == 0 ? f.first : f.second;
      *status = f.query_status;
      return f.query_ok;
    }
    bool provision(void *context, uint16_t *status)
    {
      Fixture &f = *static_cast<Fixture *>(context);
      ++f.writes;
      *status = f.provision_status;
      return f.provision_ok;
    }

    // A card that keeps one curve, so the adapter can be exercised end to end
    // through se051_factory_prepare_curve instead of against call counting alone.
    struct CurveCard
    {
      uint8_t curve_id;
      uint8_t list[16];
      size_t list_size;
      unsigned writes;
      unsigned reads;
    };

    bool curve_card_send(void *transport, const uint8_t *command,
                         size_t command_size, uint8_t *response,
                         size_t response_capacity, size_t *response_size)
    {
      if (transport == nullptr || command == nullptr || response == nullptr ||
          response_size == nullptr || command_size < 4)
      {
        return false;
      }
      CurveCard &card = *static_cast<CurveCard *>(transport);
      size_t body = 0;
      if (command[1] == kSe051InsRead && command[3] == kSe051P2List)
      {
        ++card.reads;
        response[body++] = kSe051Tag1;
        response[body++] = static_cast<uint8_t>(card.list_size);
        memcpy(response + body, card.list, card.list_size);
        body += card.list_size;
      }
      else if (command[1] == kSe051InsWrite && command[2] == kSe051P1Curve)
      {
        ++card.writes;
        // CreateECCurve plus five SetECCurveParam: the curve becomes usable only
        // after the last one.
        if (card.writes % 6 == 0 && card.list_size < sizeof(card.list))
        {
          card.list[card.list_size++] = card.curve_id;
        }
      }
      else
      {
        return false;
      }
      if (body + 2 > response_capacity)
        return false;
      response[body] = 0x90;
      response[body + 1] = 0x00;
      *response_size = body + 2;
      return true;
    }
  }
  bool run_se051_provisioning_self_tests()
  {
    uint16_t status = 0xffff;
    Fixture f = {Se051CurveState::Absent, Se051CurveState::Ready, 0x9000, 0x9000, 0, 0, true, true};
    bool ok = se051_factory_prepare_curve(false, query, provision, &f, &status) ==
                  Se051ProvisionResult::NotAuthorized &&
              f.queries == 0 && f.writes == 0 && status == 0;
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
             Se051ProvisionResult::Provisioned &&
         f.queries == 2 && f.writes == 1 && ok;
    f.queries = f.writes = 0;
    f.first = Se051CurveState::Ready;
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
             Se051ProvisionResult::Ready &&
         f.queries == 1 && f.writes == 0 && ok;
    const uint16_t words[3] = {0x6a80, 0x6a88, 0x6982};
    for (size_t index = 0; index < sizeof(words) / sizeof(words[0]); ++index)
    {
      f.queries = f.writes = 0;
      f.first = Se051CurveState::Absent;
      f.query_status = words[index];
      ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
               Se051ProvisionResult::QueryFailed &&
           f.writes == 0 && ok;
    }
    f.query_status = 0x9000;
    f.query_ok = false;
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
             Se051ProvisionResult::QueryFailed &&
         f.writes == 0 && ok;
    f.query_ok = true;
    f.queries = 0;
    f.first = Se051CurveState::Incomplete;
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
             Se051ProvisionResult::QueryFailed &&
         f.writes == 0 && ok;
    f.queries = 0;
    f.first = Se051CurveState::Absent;
    f.second = Se051CurveState::Absent;
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
             Se051ProvisionResult::VerifyFailed &&
         f.writes == 1 && f.queries == 2 && ok;
    f.queries = f.writes = 0;
    f.provision_ok = false;
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
             Se051ProvisionResult::ProvisionFailed &&
         f.queries == 1 && f.writes == 1 && ok;

    // The adapter under test: policy + APDU driver over a card that only reports
    // a curve after the sixth command.
    CurveCard card = {};
    card.curve_id = kSe051CurveSecp256k1;
    Se051CurveProvisionContext context = {curve_card_send, &card,
                                          kSe051CurveSecp256k1};
    Se051CurveState state = Se051CurveState::Unknown;
    uint16_t word = 0xffff;
    ok = se051_curve_query(&context, &state, &word) && state == Se051CurveState::Absent &&
         word == 0x9000 && card.reads == 1 && ok;
    ok = se051_curve_provision(&context, &word) && word == 0x9000 &&
         card.writes == 6 && card.list_size == 1 && ok;
    ok = se051_curve_query(&context, &state, &word) &&
         state == Se051CurveState::Ready && ok;
    ok = se051_factory_prepare_curve(true, se051_curve_query,
                                     se051_curve_provision, &context, &word) ==
             Se051ProvisionResult::Ready &&
         card.writes == 6 && ok;

    CurveCard fresh = {};
    fresh.curve_id = kSe051CurveNistP256;
    Se051CurveProvisionContext fresh_context = {curve_card_send, &fresh,
                                                kSe051CurveNistP256};
    ok = se051_factory_prepare_curve(true, se051_curve_query,
                                     se051_curve_provision, &fresh_context,
                                     &word) == Se051ProvisionResult::Provisioned &&
         fresh.writes == 6 && fresh.reads == 2 && fresh.list_size == 1 &&
         fresh.list[0] == kSe051CurveNistP256 && ok;

    // A curve this firmware does not provision must not be installed at all.
    Se051CurveProvisionContext unknown_context = {curve_card_send, &fresh,
                                                  kSe051CurveEd25519};
    ok = !se051_curve_provision(&unknown_context, &word) && fresh.writes == 6 && ok;
    ok = !se051_curve_query(nullptr, &state, &word) &&
         !se051_curve_provision(nullptr, &word) && ok;
    return ok;
  }
} // namespace hexwallet
