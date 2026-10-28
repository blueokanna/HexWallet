// Deterministic scheduler double for the real worker execution/lifetime code.
#include "WalletWorker.h"
#include <stdio.h>

namespace {
bool ready = false;
bool allow_start = true;
bool allow_begin = true;
hexwallet::WalletWorkerJob queued = nullptr;
void *borrowed = nullptr;
unsigned waits = 0;
unsigned complete_after = 1;
unsigned services = 0;
uint32_t now = 0;
uint32_t clock_ms() { return now; }
void service() { ++services; now += 10; }
void mark_complete(void *value) { *static_cast<bool *>(value) = true; }
void reset(uint32_t start = 0) {
  ready = false; allow_start = true; allow_begin = true;
  queued = nullptr; borrowed = nullptr; waits = 0; complete_after = 1;
  services = 0; now = start;
}
}

namespace hexwallet {
bool wallet_worker_ready() { return ready; }
bool wallet_worker_start() { ready = allow_start; return ready; }
bool wallet_worker_begin(WalletWorkerJob job, void *context) {
  if (!allow_begin || queued != nullptr) return false;
  queued = job; borrowed = context; return true;
}
bool wallet_worker_wait(uint32_t timeout_ms) {
  if (timeout_ms != 0) return false;  // execution must poll, never block the UI
  if (++waits < complete_after) return false;
  queued(borrowed); queued = nullptr; borrowed = nullptr; return true;
}
}

#define CHECK(condition) do { if (!(condition)) { \
  printf("worker-execution FAIL line %d\n", __LINE__); return 1; } } while (0)

int main() {
  using namespace hexwallet;
  bool completed = false;
  reset(); complete_after = 4;
  CHECK(wallet_worker_execute(mark_complete, &completed, 100, clock_ms, service) ==
        WalletWorkerResult::Completed);
  CHECK(completed && services == 3 && queued == nullptr && borrowed == nullptr);

  reset(); completed = false; complete_after = 7;
  CHECK(wallet_worker_execute(mark_complete, &completed, 20, clock_ms, service) ==
        WalletWorkerResult::TimedOut);
  // Returning at t=20 would leave our stack bool borrowed by the worker.
  CHECK(completed && services == 6 && now == 60 && borrowed == nullptr);

  reset(0xfffffff0u); completed = false; complete_after = 4;
  CHECK(wallet_worker_execute(mark_complete, &completed, 30, clock_ms, service) ==
        WalletWorkerResult::TimedOut);
  CHECK(completed && services == 3);

  reset(); allow_start = false; completed = false;
  CHECK(wallet_worker_execute(mark_complete, &completed, 100, clock_ms, service) ==
        WalletWorkerResult::Unavailable);
  CHECK(!completed && waits == 0 && services == 0);
  reset(); allow_begin = false;
  CHECK(wallet_worker_execute(mark_complete, &completed, 100, clock_ms, service) ==
        WalletWorkerResult::Unavailable);
  CHECK(!completed && waits == 0);
  reset();
  CHECK(wallet_worker_execute(mark_complete, &completed, 0, clock_ms, service) ==
        WalletWorkerResult::Unavailable);
  CHECK(!ready && waits == 0);
  puts("worker-execution=pass");
  return 0;
}
