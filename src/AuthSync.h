#pragma once

#include <Arduino.h>
#include <HTTPClient.h>


#include <Preferences.h>
#include <cstring>
#include <vector>
#include <memory>

class AuthSync {
public:
 AuthSync(const String &serverBase);
 ~AuthSync();
 // frees heap memory
    static constexpr size_t MAX_SAFE_CARDS = 200000UL; // centralized max value
    // Maximum bytes required for the static bitset buffer
    static constexpr size_t MAX_SAFE_BYTES = (MAX_SAFE_CARDS + 7) / 8;
    bool begin();                         // initial sync (call from setup())
    bool update();                        // periodic sync (call from loop or timer)
    bool preloadOffline();                // load NVS caches only (no network attempt)
    // Main function used after every scan
    bool isAuthorized(const String &uid);
    // Dump runtime memory stats to Serial for diagnostics
    void dumpMemoryStats() const;

#ifdef AUTH_TEST_HOOK
    // Test-only helper: set an artificial max_card_id for overflow/safety tests.
    // Not compiled into production unless AUTH_TEST_HOOK is defined.
    void TEST_setMaxCardId(size_t maxCardId);
    // Test hook to dump runtime memory stats (calls dumpMemoryStats())
    void TEST_dumpMemoryStats() const;
#endif

    uint32_t getCardCount() { return max_card_id + 1; }
    size_t   getMemoryUsed() { return calcBitsetBytes(max_card_id); }

private:
    String   server_base;
    // Pointer to the bitset storage. Points at a translation-unit static buffer
    // (no heap allocation) provided by AuthSync.cpp. The code expects this
    // to be a valid byte array of at least calcBitsetBytes(max_card_id) bytes.
    uint8_t *authorized_bits = nullptr;
    uint32_t max_card_id = 0;
    unsigned long last_sync = 0;
    unsigned long SYNC_INTERVAL = 60000;

    unsigned long last_server_probe = 0;
    bool server_last_ok = false;
    bool serverPreviouslyUnreachable = false;

    bool syncFromServer();
    bool getCardAuthFromServer(const String& uid, int &card_id, bool &authorized);
    int  getCardIdFromServer(const String& uid) const;
    void addKnownAuth(const String& uid, bool allowed);
    static uint64_t hashUid(const String& s);

    void saveToNVS();
    void loadFromNVS();
    // Persist/load the bitset snapshot to LittleFS (atomic write/rename)
    bool saveBitsetToFS(size_t bytes);
    bool loadBitsetFromFS();

    Preferences prefs_;
    bool prefsOpen_ = false;
    std::vector<uint64_t> allowHashes_;
    std::vector<uint64_t> denyHashes_;
    // Persisted ETag for the last downloaded bitset (used for If-None-Match)
    String last_etag;
    // Persist allow/deny hash vectors to LittleFS instead of NVS
    bool saveAllowDenyToFS() const;
    bool loadAllowDenyFromFS();
#if 1
     static size_t calcBitsetBytes(uint32_t maxId);
    bool isBitSet(uint32_t id) const;
    void setBit(uint32_t id) const;
    void clearBit(uint32_t id) const;
    bool writeByteAt(size_t idx, uint8_t val) const;
    bool readByteAt(size_t idx, uint8_t &out) const;
#endif
};
