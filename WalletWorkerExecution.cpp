#include "WalletWorker.h"

namespace hexwallet {

WalletWorkerResult wallet_worker_execute(WalletWorkerJob job, void *context,
    uint32_t timeout_ms, uint32_t (*clock_ms)(), void (*service)()) {
  if (job == nullptr || clock_ms == nullptr || service == nullptr ||
      timeout_ms == 0 || timeout_ms > 0x7fffffffUL) {
    return WalletWorkerResult::Unavailable;
  }
  if (!wallet_worker_ready() && !wallet_worker_start()) {
    return WalletWorkerResult::Unavailable;
  }
  const uint32_t started = clock_ms();
  if (!wallet_worker_begin(job, context)) return WalletWorkerResult::Unavailable;
  bool expired = false;
  for (;;) {
    const bool finished = wallet_worker_wait(0);
    // Check after wait as well: the synchronous host backend executes the job
    // inside wait, and completion may arrive just after the deadline on device.
    if (static_cast<uint32_t>(clock_ms() - started) >= timeout_ms) expired = true;
    if (finished) {
      return expired ? WalletWorkerResult::TimedOut : WalletWorkerResult::Completed;
    }
    // Never return while the worker can still access borrowed stack memory,
    // transaction buffers or secrets. There is no safe task-kill cancellation
    // of a curve operation. Keep servicing the display while draining the job.
    service();
  }
}

}  // namespace hexwallet
