#include "WalletWorker.h"

#include "WalletConfig.h"

#if defined(HEXWALLET_HOST_TEST) || !defined(ARDUINO_ARCH_ESP32)
namespace hexwallet
{
  namespace
  {
    bool started = false;
    WalletWorkerJob queued_job = nullptr;
    void *queued_context = nullptr;
  }

  bool wallet_worker_start()
  {
    started = true;
    return true;
  }

  void wallet_worker_stop()
  {
    started = false;
    queued_job = nullptr;
    queued_context = nullptr;
  }

  bool wallet_worker_ready()
  {
    return started;
  }

  uint32_t wallet_worker_stack_free()
  {
    return 0;
  }

  bool wallet_worker_begin(WalletWorkerJob job, void *context)
  {
    if (!started || job == nullptr || queued_job != nullptr)
      return false;
    queued_job = job;
    queued_context = context;
    return true;
  }

  bool wallet_worker_wait(uint32_t timeout_ms)
  {
    (void)timeout_ms;
    if (queued_job == nullptr)
      return true;
    const WalletWorkerJob job = queued_job;
    void *context = queued_context;
    queued_job = nullptr;
    queued_context = nullptr;
    job(context);
    return true;
  }

}

#else // ESP32

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

namespace hexwallet
{
  namespace
  {

    constexpr UBaseType_t kWorkerPriority = 2;
    constexpr BaseType_t kWorkerCore = 0;

    TaskHandle_t worker_task = nullptr;
    SemaphoreHandle_t job_ready = nullptr;
    SemaphoreHandle_t job_done = nullptr;
    SemaphoreHandle_t state_lock = nullptr;
    WalletWorkerJob pending_job = nullptr;
    void *pending_context = nullptr;
    bool job_in_flight = false;
    uint32_t min_free_stack = 0;

    void worker_loop(void *)
    {
      for (;;)
      {
        if (xSemaphoreTake(job_ready, portMAX_DELAY) != pdTRUE)
          continue;
        const WalletWorkerJob job = pending_job;
        void *context = pending_context;
        pending_job = nullptr;
        pending_context = nullptr;
        if (job != nullptr)
          job(context);
        const uint32_t free_now = static_cast<uint32_t>(uxTaskGetStackHighWaterMark(nullptr));
        xSemaphoreTake(state_lock, portMAX_DELAY);
        if (min_free_stack == 0 || free_now < min_free_stack)
          min_free_stack = free_now;
        xSemaphoreGive(state_lock);
        xSemaphoreGive(job_done);
      }
    }

    void release_primitives()
    {
      if (job_ready != nullptr)
      {
        vSemaphoreDelete(job_ready);
        job_ready = nullptr;
      }
      if (job_done != nullptr)
      {
        vSemaphoreDelete(job_done);
        job_done = nullptr;
      }
      if (state_lock != nullptr)
      {
        vSemaphoreDelete(state_lock);
        state_lock = nullptr;
      }
    }

  } // namespace

  bool wallet_worker_start()
  {
    if (worker_task != nullptr)
      return true;
    job_ready = xSemaphoreCreateBinary();
    job_done = xSemaphoreCreateBinary();
    state_lock = xSemaphoreCreateMutex();
    if (job_ready == nullptr || job_done == nullptr || state_lock == nullptr)
    {
      release_primitives();
      return false;
    }
    if (xTaskCreatePinnedToCore(worker_loop, "hexwallet-crypto", HEXWALLET_WORKER_STACK_BYTES, nullptr,
                                kWorkerPriority, &worker_task,
                                kWorkerCore) != pdPASS)
    {
      worker_task = nullptr;
      release_primitives();
      return false;
    }
    return true;
  }

  void wallet_worker_stop()
  {
    if (job_in_flight)
      return;
    if (worker_task != nullptr)
    {
      vTaskDelete(worker_task);
      worker_task = nullptr;
    }
    release_primitives();
    pending_job = nullptr;
    pending_context = nullptr;
  }

  bool wallet_worker_ready()
  {
    return worker_task != nullptr;
  }

  uint32_t wallet_worker_stack_free()
  {
    if (state_lock == nullptr) return 0;
    xSemaphoreTake(state_lock, portMAX_DELAY);
    const uint32_t value = min_free_stack;
    xSemaphoreGive(state_lock);
    return value;
  }

  bool wallet_worker_begin(WalletWorkerJob job, void *context)
  {
    if (job == nullptr || worker_task == nullptr)
      return false;
    if (xSemaphoreTake(state_lock, 0) != pdTRUE)
      return false;
    bool accepted = false;
    if (!job_in_flight)
    {
      xSemaphoreTake(job_done, 0);
      pending_job = job;
      pending_context = context;
      job_in_flight = true;
      accepted = xSemaphoreGive(job_ready) == pdTRUE;
      if (!accepted)
      {
        pending_job = nullptr;
        pending_context = nullptr;
        job_in_flight = false;
      }
    }
    xSemaphoreGive(state_lock);
    return accepted;
  }

  bool wallet_worker_wait(uint32_t timeout_ms)
  {
    if (!job_in_flight)
      return true;
    if (xSemaphoreTake(job_done, pdMS_TO_TICKS(timeout_ms)) != pdTRUE)
    {
      return false;
    }
    job_in_flight = false;
    return true;
  }

}

#endif
