#include "Se051Provisioning.h"
#include <stddef.h>
namespace hexwallet {
Se051ProvisionResult se051_factory_prepare_curve(
    bool authorized, Se051CurveQuery query, Se051ProvisionCallback provision,
    void *context, uint16_t *status) {
  if (status != nullptr) *status = 0;
  if (!authorized) return Se051ProvisionResult::NotAuthorized;
  if (status == nullptr || query == nullptr) return Se051ProvisionResult::QueryFailed;
  Se051CurveState state = Se051CurveState::Unknown;
  if (!query(context, &state, status) || *status != 0x9000)
    return Se051ProvisionResult::QueryFailed;
  if (state == Se051CurveState::Ready) return Se051ProvisionResult::Ready;
  if (state != Se051CurveState::Absent) return Se051ProvisionResult::QueryFailed;
  *status = 0;
  if (provision == nullptr || !provision(context, status) || *status != 0x9000)
    return Se051ProvisionResult::ProvisionFailed;
  *status = 0;
  state = Se051CurveState::Unknown;
  if (!query(context, &state, status) || *status != 0x9000 || state != Se051CurveState::Ready)
    return Se051ProvisionResult::VerifyFailed;
  return Se051ProvisionResult::Provisioned;
}
namespace {
struct Fixture {
  Se051CurveState first, second;
  uint16_t query_status, provision_status;
  unsigned queries, writes;
  bool query_ok, provision_ok;
};
bool query(void *context, Se051CurveState *state, uint16_t *status) {
  Fixture &f = *static_cast<Fixture *>(context);
  *state = f.queries++ == 0 ? f.first : f.second;
  *status = f.query_status;
  return f.query_ok;
}
bool provision(void *context, uint16_t *status) {
  Fixture &f = *static_cast<Fixture *>(context);
  ++f.writes;
  *status = f.provision_status;
  return f.provision_ok;
}
}
bool run_se051_provisioning_self_tests() {
  uint16_t status = 0xffff;
  Fixture f = {Se051CurveState::Absent, Se051CurveState::Ready, 0x9000, 0x9000, 0, 0, true, true};
  bool ok = se051_factory_prepare_curve(false, query, provision, &f, &status) ==
      Se051ProvisionResult::NotAuthorized && f.queries == 0 && f.writes == 0 && status == 0;
  ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
      Se051ProvisionResult::Provisioned && f.queries == 2 && f.writes == 1 && ok;
  f.queries = f.writes = 0; f.first = Se051CurveState::Ready;
  ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
      Se051ProvisionResult::Ready && f.queries == 1 && f.writes == 0 && ok;
  const uint16_t words[3] = {0x6a80, 0x6a88, 0x6982};
  for (size_t index = 0; index < sizeof(words) / sizeof(words[0]); ++index) {
    f.queries = f.writes = 0; f.first = Se051CurveState::Absent; f.query_status = words[index];
    ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
        Se051ProvisionResult::QueryFailed && f.writes == 0 && ok;
  }
  f.query_status = 0x9000; f.query_ok = false;
  ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
      Se051ProvisionResult::QueryFailed && f.writes == 0 && ok;
  f.query_ok = true; f.queries = 0; f.first = Se051CurveState::Incomplete;
  ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
      Se051ProvisionResult::QueryFailed && f.writes == 0 && ok;
  f.queries = 0; f.first = Se051CurveState::Absent; f.second = Se051CurveState::Absent;
  ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
      Se051ProvisionResult::VerifyFailed && f.writes == 1 && f.queries == 2 && ok;
  f.queries = f.writes = 0; f.provision_ok = false;
  ok = se051_factory_prepare_curve(true, query, provision, &f, &status) ==
      Se051ProvisionResult::ProvisionFailed && f.queries == 1 && f.writes == 1 && ok;
  return ok;
}
}  // namespace hexwallet
