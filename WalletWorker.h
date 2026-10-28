#ifndef HEXWALLET_WORKER_H
#define HEXWALLET_WORKER_H

#include <stdint.h>

namespace hexwallet
{
    using WalletWorkerJob = void (*)(void *context);

    bool wallet_worker_start();
    void wallet_worker_stop();
    bool wallet_worker_ready();
    // Called by the single Arduino-loop owner. A successful begin borrows
    // context until wait returns true; a wait timeout does not cancel a job.
    bool wallet_worker_begin(WalletWorkerJob job, void *context);
    bool wallet_worker_wait(uint32_t timeout_ms);

    enum class WalletWorkerResult : uint8_t { Completed, Unavailable, TimedOut };
    // Keeps the borrowed context alive until completion, even after a deadline.
    // A late result must be discarded. service may update the UI/yield, but must
    // not re-enter signing, process host requests, or stop the worker.
    WalletWorkerResult wallet_worker_execute(WalletWorkerJob job, void *context,
        uint32_t timeout_ms, uint32_t (*clock_ms)(), void (*service)());

    uint32_t wallet_worker_stack_free();

}

#endif
