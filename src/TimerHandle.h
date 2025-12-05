#pragma once
#include <freertos/FreeRTOS.h>
#include <freertos/timers.h>
#include <Arduino.h>



// Centralized timer handles and creation helpers.
// The timers themselves are defined in Timers.cpp; include this header from
// modules that need to create or reference the timers.

extern TimerHandle_t serverCheckTimer;
extern TimerHandle_t authSyncTimer;
extern TimerHandle_t displayTimer;

// Create and start timers. Callbacks are provided by the caller (typically
// functions defined in main.cpp). `periodTicks` is the timer period in RTOS
// ticks (use pdMS_TO_TICKS(ms) when calling).

bool createServerCheckTimer(TimerCallbackFunction_t callback, TickType_t periodTicks);
bool createAuthSyncTimer(TimerCallbackFunction_t callback, TickType_t periodTicks);
bool createDisplayTimer(TimerCallbackFunction_t callback, TickType_t periodTicks);

// Stop and delete helpers (optional)
void deleteServerCheckTimer();
void deleteAuthSyncTimer();
void deleteDisplayTimer();

