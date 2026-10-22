#ifndef HEXWALLET_WORKER_H
#define HEXWALLET_WORKER_H

#include <stdint.h>

namespace hexwallet {

// Second-core worker.
//
// The ESP32-S3/P4 have two high-performance cores. Long, non-UI work (boot
// self-tests, key derivation) runs here so the main loop keeps servicing the
// panel and the task watchdog.
//
// Contract:
//   * One job at a time. begin() and wait() must be called from the same task;
//     begin() refuses a second job while one is in flight.
//   * The worker task blocks on a semaphore between jobs: it never spins and
//     never starves the idle task that feeds the watchdog.
//   * wait() is bounded. A timed-out job keeps running, so the caller must not
//     reuse or free its argument.
using WalletWorkerJob = void (*)(void *context);

bool wallet_worker_start();
// Only call when no job is in flight.
void wallet_worker_stop();
bool wallet_worker_ready();

bool wallet_worker_begin(WalletWorkerJob job, void *context);
bool wallet_worker_wait(uint32_t timeout_ms);
// begin() + wait(); returns false when the job did not complete in time.
bool wallet_worker_run(WalletWorkerJob job, void *context, uint32_t timeout_ms);

// Minimum free stack seen by the worker in bytes; 0 when unavailable.
uint32_t wallet_worker_stack_free();

}  // namespace hexwallet

#endif
