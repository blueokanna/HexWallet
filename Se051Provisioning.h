#ifndef HEXWALLET_SE051_PROVISIONING_H
#define HEXWALLET_SE051_PROVISIONING_H
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
bool run_se051_provisioning_self_tests();
}  // namespace hexwallet
#endif
