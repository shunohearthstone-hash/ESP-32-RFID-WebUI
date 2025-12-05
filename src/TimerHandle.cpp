#include "TimerHandle.h"
#include <freertos/FreeRTOS.h>
#include <Arduino.h>

TimerHandle_t serverCheckTimer = nullptr;
TimerHandle_t authSyncTimer = nullptr;
TimerHandle_t displayTimer = nullptr;

bool createServerCheckTimer(TimerCallbackFunction_t callback, TickType_t periodTicks) {
    if (serverCheckTimer != nullptr) return true;
    serverCheckTimer = xTimerCreate("ServerCheck", periodTicks, pdTRUE, nullptr, callback);
    if (!serverCheckTimer) return false;
    return xTimerStart(serverCheckTimer, 0) == pdPASS;
}

bool createAuthSyncTimer(TimerCallbackFunction_t callback, TickType_t periodTicks) {
    if (authSyncTimer != nullptr) return true;
    authSyncTimer = xTimerCreate("AuthSync", periodTicks, pdTRUE, nullptr, callback);
    if (!authSyncTimer) return false;
    return xTimerStart(authSyncTimer, 0) == pdPASS;
}

bool createDisplayTimer(TimerCallbackFunction_t callback, TickType_t periodTicks) {
    if (displayTimer != nullptr) return true;
    displayTimer = xTimerCreate("Display", periodTicks, pdTRUE, nullptr, callback);
    if (!displayTimer) return false;
    return xTimerStart(displayTimer, 0) == pdPASS;
}

void deleteServerCheckTimer() {
    if (serverCheckTimer) {
        xTimerStop(serverCheckTimer, 0);
        xTimerDelete(serverCheckTimer, 0);
        serverCheckTimer = nullptr;
    }
}
void deleteAuthSyncTimer() {
    if (authSyncTimer) {
        xTimerStop(authSyncTimer, 0);
        xTimerDelete(authSyncTimer, 0);
        authSyncTimer = nullptr;
    }
}
void deleteDisplayTimer() {
    if (displayTimer) {
        xTimerStop(displayTimer, 0);
        xTimerDelete(displayTimer, 0);
        displayTimer = nullptr;
    }
}

