#pragma once
#include <Arduino.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

class AuthSync {
public:
    AuthSync(const String& serverBase);
    ~AuthSync();                          // frees heap memory

    bool begin();                         // initial sync (call from setup())
    bool update();                        // periodic sync (call from loop or timer)

    // Main function used after every scan
    bool isAuthorized(const String& uid);

    uint32_t getCardCount() const { return max_card_id + 1; }
    size_t   getMemoryUsed() const { return (max_card_id + 7) / 8; }

private:
    String   server_base;
    uint8_t* authorized_bits = nullptr;
    uint32_t max_card_id = 0;
    unsigned long last_sync = 0;
    static const unsigned long SYNC_INTERVAL = 60000;  // 1 minute

    bool syncFromServer();
    int  getCardIdFromServer(const String& uid);
};