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
    size_t   getMemoryUsed() const { return calcBitsetBytes(max_card_id); }

private:
    String   server_base;
    uint8_t* authorized_bits = nullptr;
    uint32_t max_card_id = 0;
    unsigned long last_sync = 0;
    static const unsigned long SYNC_INTERVAL = 60000;

    unsigned long last_server_probe = 0;
    bool server_last_ok = false;
    bool serverPreviouslyUnreachable = false;

    bool syncFromServer();
    bool getCardAuthFromServer(const String& uid, int &card_id, bool &authorized);
    int  getCardIdFromServer(const String& uid);
    void addKnownAuth(const String& uid, bool allowed);

    uint64_t hashUid(const String& s);
    void saveToNVS();
    void loadFromNVS();

    Preferences prefs_;
    bool prefsOpen_ = false;
    std::vector<uint64_t> allowHashes_;
    std::vector<uint64_t> denyHashes_;
#if 1
    size_t calcBitsetBytes(uint32_t maxId) const;
    bool isBitSet(uint32_t id) const;
    void setBit(uint32_t id);
    void clearBit(uint32_t id);
    bool writeByteAt(size_t idx, uint8_t val);
    bool readByteAt(size_t idx, uint8_t &out) const;
#endif
};