#pragma once
#include <Arduino.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <vector>
#include <algorithm>
#include <Preferences.h>
#include <stdint.h>

class AuthSync {
public:
    AuthSync(const String& serverBase);
    ~AuthSync();                          // frees heap memory

    bool begin();                         // initial sync (call from setup())
    bool update();                        // periodic sync (call from loop or timer)

    // Main function used after every scan
    bool isAuthorized(const String& uid);

#ifdef AUTH_TEST_HOOK
    // Test-only helper: set an artificial max_card_id for overflow/safety tests.
    // Not compiled into production unless AUTH_TEST_HOOK is defined.
    void TEST_setMaxCardId(size_t maxCardId);
#endif

    uint32_t getCardCount() const { return max_card_id + 1; }
    size_t   getMemoryUsed() const { return (max_card_id + 7) / 8; }

private:
    String   server_base;
    uint8_t* authorized_bits = nullptr; //Safe null before initialization
    uint32_t max_card_id = 0;
    unsigned long last_sync = 0;
    static const unsigned long SYNC_INTERVAL = 60000;  // 1 minute

    bool syncFromServer();
    int  getCardIdFromServer(const String& uid);
    // Query server for card existence and authorization. Returns true on
    // success and fills card_id and authorized. Returns false on network
    // error or if the server reports the card does not exist.
    bool getCardAuthFromServer(const String& uid, int &card_id, bool &authorized);

    // Offline hashed permissions cache -----------------------------
    static uint64_t hashUid(const String& s);
    void saveToNVS();
    void loadFromNVS();
    void addKnownAuth(const String& uid, bool allowed);

    Preferences prefs_;
    bool prefsOpen_ = false;
    std::vector<uint64_t> allowHashes_;
    std::vector<uint64_t> denyHashes_;
#if 1
    // Bitset safety helpers
    size_t calcBitsetBytes(uint32_t maxId) const;
    bool isBitSet(uint32_t id) const;
    void setBit(uint32_t id);
    void clearBit(uint32_t id);
    bool writeByteAt(size_t idx, uint8_t val);
    bool readByteAt(size_t idx, uint8_t &out) const;
#endif
#ifdef UNIT_TEST
    // Test helper: force internal max card id (test-only)
    void TEST_setMaxCardId(size_t maxCardId);
#endif
};