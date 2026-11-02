#ifndef HEXWALLET_SE051_PROVISIONING_H
#define HEXWALLET_SE051_PROVISIONING_H
#include <stddef.h>
#include <stdint.h>
namespace hexwallet {
// A status word alone cannot identify a missing curve. 6A80 means malformed
// data; 6A88 can name any missing referenced object, including a key.
enum class Se051CurveState : uint8_t { Unknown, Absent, Incomplete, Ready };
using Se051CurveQuery = bool (*)(void *, Se051CurveState *, uint16_t *);
using Se051ProvisionCallback = bool (*)(void *, uint16_t *);
enum class Se051ProvisionResult : uint8_t {
  Ready, Provisioned, NotAuthorized, QueryFailed, ProvisionFailed, VerifyFailed
};
// Factory operation only, never called as an automatic recovery from derive
// or sign errors. query must parse an authenticated ReadECCurveList response
// for the pinned curve/applet. provision must perform CreateECCurve plus all
// SetECCurveParam operations, and fail on ANY unsuccessful command. A ready
// curve is untouched; a partial curve requires explicit operator recovery.
// factory_authorized is a local provisioning policy, never host APDU input.
Se051ProvisionResult se051_factory_prepare_curve(
    bool factory_authorized, Se051CurveQuery query,
    Se051ProvisionCallback provision, void *context, uint16_t *status);

// Adapter that binds the Se051Apdu driver to the two callbacks above, so the
// factory path has one call to make and cannot accidentally forget either the
// authenticated-send requirement or the "every command must answer 0x9000"
// rule. The card answers CreateECCurve/SetECCurveParam inside the caller's
// SCP03 channel, which is what `send` is expected to wrap.
//
// A half-installed curve is reported as Absent, because ReadECCurveList is the
// only public way to ask and it does not distinguish "never created" from
// "created but incomplete". The repeat CreateECCurve then fails, so the caller
// sees ProvisionFailed instead of a curve that quietly signs with a zero G.
struct Se051CurveProvisionContext {
  bool (*send)(void *transport, const uint8_t *command, size_t command_size,
               uint8_t *response, size_t response_capacity,
               size_t *response_size);
  void *transport;
  uint8_t curve_id;
};
bool se051_curve_query(void *context, Se051CurveState *state,
                       uint16_t *status);
bool se051_curve_provision(void *context, uint16_t *status);

bool run_se051_provisioning_self_tests();
}  // namespace hexwallet
#endif
