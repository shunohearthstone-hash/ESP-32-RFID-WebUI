#include "AuthSync.h"
#include "HashUtils.h"
#include <algorithm>
#include <Arduino.h>
#include <ArduinoJson.h>
#include <cstdlib>
#include <cstring>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <limits>
#include <vector>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <FS.h>
/* Notes: For actual deployment, enroll mode indicator may not be needed
 Step back server polling delays. This is useful to keep low for testing for
 responsiveness but is not optimizing to minimize server traffic*/


// Translation-unit local static storage for the authorization bitset.
// Allocated in BSS to avoid heap usage. Size driven by AuthSync::MAX_SAFE_BYTES.
// MAX_SAFE_CARDS = 200000 -> bytes = (200000+7)/8 = 25000
namespace {
    uint8_t authorized_bits_storage[25000];
}

/*for each byte in input:
    hash ^= byte        // XOR with current hash
    hash *= prime       // Multiply by FNV prime*/
// -------------------- hashing (FNV-1a 64-bit) --------------------

/*static uint64_t fnv1a64(const uint8_t* data, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;      // FNV offset basis
    const uint64_t prime = 0x100000001b3ULL;     // FNV prime
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= prime;
    }
    return hash;
}*/

uint64_t AuthSync::hashUid(const String& s) {
    return HashUtils::hashUid(s);
  /*  String t = s;  // normalize to uppercase, trimmed
    t.trim();
    t.toUpperCase();
    //Normalise hash for whitespace or case differences
    return fnv1a64(reinterpret_cast<const uint8_t*>(t.c_str()), t.length());
*/}

AuthSync::AuthSync(const String& serverBase) : server_base(serverBase) {

    authorized_bits = authorized_bits_storage;
}

AuthSync::~AuthSync() {
    // authorized_bits points at static storage — don't free. Reset pointer for safety.
    authorized_bits = nullptr;
    if (prefsOpen_) {
        prefs_.end();
        prefsOpen_ = false;
    }
}

// ---------------- Bitset safety helpers ----------------
size_t AuthSync::calcBitsetBytes(uint32_t maxId) {
    // bits = maxId + 1
    size_t bits = (size_t)maxId + 1;
    if (bits == 0) return 0;
    if (bits > std::numeric_limits<size_t>::max() - 7) return 0;
    return (bits + 7) / 8;
}
//Write a byte at index idx in the bitset, return true on success,
//false when out of bounds or uninitialized
bool AuthSync::writeByteAt(size_t idx, uint8_t val) const {
    if (!authorized_bits) return false;
    size_t bytes = calcBitsetBytes(max_card_id);
    if (bytes == 0) return false;
    if (idx >= bytes) return false;
    authorized_bits[idx] = val;
    return true;
}
//Safe read of a byte at index idx in the bitset, return true on success,
//false when out of bounds or uninitialized
bool AuthSync::readByteAt(size_t idx, uint8_t &out) const {
    if (!authorized_bits) return false;
    size_t bytes = calcBitsetBytes(max_card_id);
    if (bytes == 0) return false;
    if (idx >= bytes) return false;
    out = authorized_bits[idx];
    return true;
}
//checks whether a specific card ID’s authorization bit is set in the internal bitset
// and returns true if it is, false otherwise.
bool AuthSync::isBitSet(uint32_t id) const {
    if (!authorized_bits) return false;
    if (id > max_card_id) return false;
    size_t idx = (size_t)id >> 3;
    uint8_t bit = id & 7;
    return ((authorized_bits[idx] >> bit) & 1) != 0;
}
//marks a specific card ID as authorized by setting its corresponding bit in the internal bitset.
//Verify that buffer is allocated and id is within bounds before setting the bit.
void AuthSync::setBit(uint32_t id) const {
    if (!authorized_bits) return;//buffer is initialized
    if (id > max_card_id) return;//bounds check
    size_t idx = (size_t)id >> 3;
    uint8_t bit = id & 7;
    authorized_bits[idx] |= (1u << bit);
}
//Reverse of setBit: clears the authorization bit for a specific card ID,
// marking it as unauthorized. Verify buffer and bounds before clearing.
void AuthSync::clearBit(uint32_t id) const {
    if (!authorized_bits) return;//buffer is initialized
    if (id > max_card_id) return;//bounds check
    size_t idx = (size_t)id >> 3; //divide by 8
    uint8_t bit = id & 7;
    authorized_bits[idx] &= ~(1u << bit);
}

// Open NVS and load any cached hashes first for offline use
bool AuthSync::begin() {
    if (!prefsOpen_) {
        prefsOpen_ = prefs_.begin("auth", false);
    }
    if (prefsOpen_) {
        loadETagFromNVS();
    }
    // Try to load a previously saved bitset snapshot from filesystem
    if (LittleFS.begin()) {
        loadBitsetFromFS();
    }
    return syncFromServer();
}

//     size_t idx = (size_t)id >> 3;

bool AuthSync::preloadOffline() {
    if (!prefsOpen_) {
        prefsOpen_ = prefs_.begin("auth", false);
    }
    if (prefsOpen_) {
        loadETagFromNVS();
        // Load filesystem snapshot if present
        if (LittleFS.begin()) {
            loadBitsetFromFS();
        }
        return true;
    }
    return false;
}

bool AuthSync::update() {
    if (millis() - last_sync > SYNC_INTERVAL) {
        return syncFromServer();
    }
    return true;
}

bool AuthSync::isAuthorized(const String& uid) {
    // Compute and log hash for debugging/offline cache tracking
    uint64_t h = hashUid(uid);
    Serial.printf("[AuthSync] UID: %s -> Hash: 0x%016llX\n", uid.c_str(), h);

    // Priority 1: Check local cache first (deny takes precedence)
    const bool denied = std::binary_search(denyHashes_.begin(), denyHashes_.end(), h);
    if (denied) {
        Serial.println("[AuthSync] Found in deny cache -> DENIED");
        return false;
    }
    const bool allowed = std::binary_search(allowHashes_.begin(), allowHashes_.end(), h);
    if (allowed) {
        Serial.println("[AuthSync] Found in allow cache -> AUTHORIZED");
        return true;
    }

    // Priority 2: Unknown card - query server if online
    Serial.println("[AuthSync] Unknown card; checking server...");
    if (WiFi.status() == WL_CONNECTED && server_base.length() > 0) {
        int card_id = -1;
        bool server_allowed = false;
        if (getCardAuthFromServer(uid, card_id, server_allowed)) {
            // Learn the server result for offline use next time
            addKnownAuth(uid, server_allowed);
            Serial.printf("[AuthSync] Server says: %s\n", server_allowed ? "AUTHORIZED" : "DENIED");
            return server_allowed;
        }
    }

    // Priority 3: Offline and unknown - deny by default
    Serial.println("[AuthSync] Offline + unknown -> DENIED by default");
    return false;
}

bool AuthSync::getCardAuthFromServer(const String& uid, int &card_id, bool &authorized) {
    card_id = -1;
    authorized = false;
    // Guard: need WiFi and a configured server base
    if (WiFi.status() != WL_CONNECTED || server_base.length() == 0) return false;

    // Backoff: only apply if we've actually probed before (last_server_probe != 0)
    if (!server_last_ok && last_server_probe != 0 && (millis() - last_server_probe) < 10000) {
        return false; // use offline cache immediately
    }

    // Periodic lightweight server status probe (cached) to avoid expensive lookups when server down
    if (millis() - last_server_probe > 5000 || last_server_probe == 0) {
        last_server_probe = millis();
        HTTPClient ping;
        // Further reduce probe timeout to minimize per-scan delay when offline.
        // A very short timeout risks false negatives on a slow network; tune if needed.
        ping.setTimeout(250); // was 1000ms
        ping.begin(server_base + "/api/status");
        int sc = ping.GET();
        ping.end();
        server_last_ok = (sc == 200);
        if (!server_last_ok) {
            Serial.println("[AuthSync] Server status probe failed quickly; using offline cache");
            return false; // return immediately to avoid extra delay this scan
        }
    }
    if (!server_last_ok) return false;  // fallback to offline caches

    // Additional quick guard: if probe just failed we already returned
    HTTPClient http;
    http.setTimeout(1200); // reduce per-card lookup timeout
    http.begin(server_base + "/api/cards/" + uid);
    int code = http.GET();
    if (code != 200) {
        http.end();
        return false;
    }
    String payload = http.getString();
    http.end();

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (err) return false;

    bool exists = doc["exists"] | false;
    if (!exists) return false;
    card_id = doc["card_id"] | -1;
    authorized = doc["authorized"] | false;
    return true;
}


    // ---------------------------------------------------------------------------
    // Sync strategy and reachability model
    //
    // `syncFromServer()` performs a full authorization bitset sync from the
    // configured server. To avoid duplicated probes and to centralize network
    // reachability checks the code follows this policy:
    //
    // 1. Bootstrap / initial probe:
    //    - When the device boots `last_server_probe` will be zero. In that
    //      case `syncFromServer()` will perform a single short, synchronous
    //      `/api/status` probe so the initial call (usually from `begin()` in
    //      setup) can decide whether to attempt the first sync immediately.
    //
    // 2. Centralized periodic probes (preferred after boot):
    //    - After boot a single central timer (implemented in `NetworkTask`)
    //      performs periodic `/api/status` probes and updates a shared
    //      reachability flag. That timer also calls `AuthSync::setServerProbeResult`
    //      so AuthSync uses the same cached result and timestamp. This prevents
    //      multiple components from issuing redundant status probes.
    //
    // 3. Backoff after failures:
    //    - If a recent probe indicates the server was unreachable, `syncFromServer`
    //      enforces a short backoff window and skips attempts to avoid hammering
    //      a dead server.
    //
    // 4. ETag and incremental update:
    //    - When the server returns bitset data the response may include an
    //      `ETag`. `syncFromServer()` stores that ETag in NVS and uses it in
    //      future syncs via `If-None-Match` headers to receive HTTP 304 and
    //      avoid re-downloading unchanged data.
    //
    // 5. Allow/deny lists handling:
    //    - If the server returns explicit `allow`/`deny` arrays they are
    //      normalized, hashed, de-duplicated and swapped into the in-memory
    //      vectors. These vectors are persisted (best-effort) by calling
    //      `saveETagToNVS()` (which persists ETag to NVS and writes allow/deny
    //      lists to LittleFS).
    //
    // The combination of a one-time initial probe, a single central periodic
    // probe, and a cached probe result minimizes blocking network calls while
    // keeping all components aligned on server reachability.
    // ---------------------------------------------------------------------------
bool AuthSync::syncFromServer() {
    if (WiFi.status() != WL_CONNECTED || server_base.length() == 0)
        return false;
    // Backoff: only after a failed probe and not on the very first attempt (last_server_probe != 0)
    if (!server_last_ok && last_server_probe != 0 && (millis() - last_server_probe) < 10000) {
        Serial.println("[AuthSync] Backoff active; skipping sync");
        return false;
    }

    // Only perform an inline reachability probe on the very first sync attempt.
    // After the initial probe we rely on the external server-check timer
    // (NetworkTask) to update `server_last_ok` and `last_server_probe` so
    // we don't duplicate probes here.
    if (last_server_probe == 0) {
        // First-time probe: do a quick reachability check so the initial
        // sync (called from setup()) can proceed when no external timer has
        // yet run.
        last_server_probe = millis();
        HTTPClient ping;
        ping.setTimeout(1000); // short probe for initial sync
        ping.begin(server_base + "/api/status");
        int sc = ping.GET();
        ping.end();
        server_last_ok = (sc == 200);
        if (!server_last_ok) {
            Serial.println("[AuthSync] Sync aborted: initial probe failed (server unreachable)");
            return false;
        }
    } else if (!server_last_ok) {
        // An external timer (NetworkTask) has already probed and reported the
        // server as unreachable — skip the sync to avoid redundant network calls.
        Serial.println("[AuthSync] Sync aborted: server unreachable (cached)");
        return false;
    }

    HTTPClient http;
    http.setTimeout(2000);  // shorter sync timeout
    http.begin(server_base + "/api/sync");
    // Send If-None-Match header if we have a saved ETag to allow 304 responses
    if (last_etag.length()) {
        http.addHeader("If-None-Match", last_etag);
    }
    int code = http.GET();

    if (code == 304) {
        // Not modified — nothing to do. Update last_sync and return success.
        last_sync = millis();
        Serial.println("[AuthSync] Sync: 304 Not Modified — skipping update");
        http.end();
        return true;
    }
    if (code != 200) {
        Serial.printf("[AuthSync] Sync failed with code: %d\n", code);
        http.end();
        return false;
    }

    String payload = http.getString();
    http.end();

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (err) {
        Serial.printf("[AuthSync] JSON parse error: %s\n", err.c_str());
        return false;
    }

    // Extract new maximum card ID and bitset hex from server payload
    uint32_t new_max = doc["max_id"] | 0;
    String hex = doc["bits"].as<String>();

    // Save new ETag header from server (if returned)
    String serverEtag = http.header("ETag");
    if (serverEtag.length()) {
        last_etag = serverEtag;
        if (prefsOpen_) prefs_.putString("bitset_etag", last_etag);
    }

    // Use the static storage; validate size fits
    size_t bytes = calcBitsetBytes(new_max);
    if (bytes == 0 || bytes > MAX_SAFE_BYTES) {
        Serial.println("[AuthSync] Sync failed: requested bitset too large for static buffer");
        max_card_id = 0;
        return false;
    }
    // Zero only the required portion
    std::fill_n(authorized_bits, bytes, 0);

    // Decode the hex bitset payload (two characters per byte) into
    // the newly allocated buffer using the bounds-checked writer.
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        String byteStr = hex.substring(i, i + 2);
        auto v = static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16));
        if (!writeByteAt(i / 2, v)) break;
    }

    // Commit the new bitset and record the time of this successful sync.
    max_card_id = new_max;
    last_sync = millis();

    // Persist the bitset snapshot to filesystem for faster boot/offline use
    if (LittleFS.begin()) {
        saveBitsetToFS(bytes);
    }

    // Optionally refresh offline allow/deny UID hash lists when the
    // server includes arrays of UIDs. These are normalized, hashed,
    // de-duplicated, and then swapped into the in-memory caches.
    if (doc["allow"].is<JsonArray>() || doc["allow_uids"].is<JsonArray>() ||
        doc["deny"].is<JsonArray>()  || doc["deny_uids"].is<JsonArray>()) {
        std::vector<uint64_t> allowNew;
        std::vector<uint64_t> denyNew;
// Extract optional allow/deny UID arrays from the sync JSON, normalize + hash
// each UID into 64-bit values, and append to the new vectors.
        auto loadArray = [&](const char* key, std::vector<uint64_t>& out){
            JsonVariant var = doc[key];
            if (!var.is<JsonArray>()) return;
            for (JsonVariant v : var.as<JsonArray>()) {
                String uid = v.as<const char*>();
                out.push_back(hashUid(uid));
            }
        };
//std::sort magic incantation

        loadArray("allow", allowNew);
        loadArray("allow_uids", allowNew);
        loadArray("deny", denyNew);
        loadArray("deny_uids", denyNew);

        std::sort(allowNew.begin(), allowNew.end());//
        allowNew.erase(std::unique(allowNew.begin(), allowNew.end()), allowNew.end());
        std::sort(denyNew.begin(), denyNew.end());
        denyNew.erase(std::unique(denyNew.begin(), denyNew.end()), denyNew.end());

        if (!allowNew.empty() || !denyNew.empty()) {
            allowHashes_.swap(allowNew);
            denyHashes_.swap(denyNew);
            saveETagToNVS();
            //It then saves the new vectors to NVS for persistence across reboots.

        }
    }

    // Log a compact summary of the sync result for debugging.
    Serial.printf("[AuthSync] Synced max_id=%u (%u bytes heap)\n", max_card_id, bytes);
    return true;
}
//Old and uncalled, commented out until verified no longer used
/*int AuthSync::getCardIdFromServer(const String& uid) const {
    // Perform a one-off lookup for a card's numeric ID given its
    // UID string via /api/cards/<uid>. Returns -1 on any network,
    // HTTP, or parsing failure, or when the card does not exist.
    if (WiFiClass::status() != WL_CONNECTED) return -1;

    HTTPClient http;
    http.setTimeout(5000);  // 5 second timeout
    http.begin(server_base + "/api/cards/" + uid);
    int code = http.GET();

    if (code != 200) {
        Serial.printf("[AuthSync] Card lookup failed: %d\n", code);
        http.end();
        return -1;
    }

    String payload = http.getString();
    http.end();

    JsonDocument doc;
    const DeserializationError err = deserializeJson(doc, payload);
    if (err) {
        Serial.printf("[AuthSync] JSON parse error: %s\n", err.c_str());
        return -1;
    }

    // If card exists, return card_id (even if unauthorized) so callers
    // can still correlate the UID with a position in the authorization bitset.
    bool exists = doc["exists"] | false;
    if (!exists) return -1;
    return doc["card_id"] | -1;
}*/

// -------------------- Offline cache helpers --------------------
void AuthSync::addKnownAuth(const String& uid, bool allowed) {
    // Learn a card's authorization status for offline use by

    uint64_t h = hashUid(uid);
    // Ensure sorted insert - helper lambda
    auto insert_sorted = [](std::vector<uint64_t>& vec, uint64_t val){
        auto it = std::lower_bound(vec.begin(), vec.end(), val);
        if (it == vec.end() || *it != val) vec.insert(it, val);
    };

    if (allowed) {
        // Remove from deny if present
        auto it = std::lower_bound(denyHashes_.begin(), denyHashes_.end(), h);
        if (it != denyHashes_.end() && *it == h) denyHashes_.erase(it);
        insert_sorted(allowHashes_, h);
    } else {
        auto it = std::lower_bound(allowHashes_.begin(), allowHashes_.end(), h);
        if (it != allowHashes_.end() && *it == h) allowHashes_.erase(it);
        insert_sorted(denyHashes_, h);
    }
    saveETagToNVS();
}

bool AuthSync::saveAllowDenyToFS() const {
    if (!LittleFS.begin()) return false;
    const char *tmp = "/allow_deny.bin.tmp";
    const char *final = "/allow_deny.bin";
    File f = LittleFS.open(tmp, FILE_WRITE);
    if (!f) return false;
    // Write counts as 32-bit little-endian
    uint32_t an = (uint32_t)allowHashes_.size();
    uint32_t dn = (uint32_t)denyHashes_.size();
    f.write(reinterpret_cast<const uint8_t*>(&an), sizeof(an));
    f.write(reinterpret_cast<const uint8_t*>(&dn), sizeof(dn));
    if (an) f.write(reinterpret_cast<const uint8_t*>(allowHashes_.data()), an * sizeof(uint64_t));
    if (dn) f.write(reinterpret_cast<const uint8_t*>(denyHashes_.data()), dn * sizeof(uint64_t));
    f.close();
    LittleFS.remove(final);
    if (!LittleFS.rename(tmp, final)) {
        LittleFS.remove(tmp);
        return false;
    }
    return true;
}

bool AuthSync::loadAllowDenyFromFS() {
    if (!LittleFS.begin()) return false;
    const char *final = "/allow_deny.bin";
    if (!LittleFS.exists(final)) return false;
    File f = LittleFS.open(final, FILE_READ);
    if (!f) return false;
    if (f.size() < (int)sizeof(uint32_t)*2) { f.close(); return false; }
    uint32_t an = 0, dn = 0;
    f.read(reinterpret_cast<uint8_t*>(&an), sizeof(an));
    f.read(reinterpret_cast<uint8_t*>(&dn), sizeof(dn));
    // Basic sanity check
    size_t expected = sizeof(uint32_t)*2 + (size_t)an * sizeof(uint64_t) + (size_t)dn * sizeof(uint64_t);
    if ((size_t)f.size() < expected) { f.close(); return false; }
    allowHashes_.assign(an, 0);
    denyHashes_.assign(dn, 0);
    // Read hashes
    if (an) f.read(reinterpret_cast<uint8_t*>(allowHashes_.data()), an * sizeof(uint64_t));
    if (dn) f.read(reinterpret_cast<uint8_t*>(denyHashes_.data()), dn * sizeof(uint64_t));
    f.close();
    // Ensure sorted
    std::sort(allowHashes_.begin(), allowHashes_.end());
    std::sort(denyHashes_.begin(), denyHashes_.end());
    return true;
}

// Update saveToNVS to call saveAllowDenyToFS()
void AuthSync::saveETagToNVS() {
    if (!prefsOpen_) return;
    // Persist last_etag only
    if (last_etag.length()) {
        prefs_.putString("bitset_etag", last_etag);
    } else {
        prefs_.remove("bitset_etag");
    }
    // Persist allow/deny vectors to LittleFS (best-effort - log on failure, no retry)
    if (!saveAllowDenyToFS()) {
        Serial.println("[AuthSync] Warning: failed to persist allow/deny to LittleFS");
    }
}

void AuthSync::loadETagFromNVS() {
    if (!prefsOpen_) return;
    // Restore persisted ETag if present
    if (prefs_.isKey("bitset_etag")) {
        last_etag = prefs_.getString("bitset_etag", "");
    } else {
        last_etag = "";
    }
    // Attempt to load allow/deny from LittleFS; if it fails leave vectors empty
    loadAllowDenyFromFS();
}

bool AuthSync::saveBitsetToFS(size_t bytes) {
    if (bytes == 0) return false;
    const char *tmp = "/bits.bin.tmp";
    const char *final = "/bits.bin";
    File f = LittleFS.open(tmp, FILE_WRITE);
    if (!f) {
        Serial.println("[AuthSync] Failed to open tmp file for bitset");
        return false;
    }
    //removed redundant reinterpret_cast<const uint8_t*> from below
    size_t written = f.write((authorized_bits), bytes);
    f.close();
    if (written != bytes) {
        Serial.println("[AuthSync] Failed to write full bitset to tmp file");
        LittleFS.remove(tmp);
        return false;
    }
    LittleFS.remove(final);
    if (!LittleFS.rename(tmp, final)) {
        Serial.println("[AuthSync] Failed to rename bitset tmp file");
        return false;
    }
    if (prefsOpen_) prefs_.putUInt("max_id", max_card_id);
    Serial.printf("[AuthSync] Saved bitset snapshot %u bytes\n", (unsigned)bytes);
    return true;
}

bool AuthSync::loadBitsetFromFS() {
    const char *final = "/bits.bin";
    if (!LittleFS.exists(final)) return false;
    File f = LittleFS.open(final, FILE_READ);
    if (!f) return false;
    size_t bytes = f.size();
    if (bytes == 0 || bytes > MAX_SAFE_BYTES) {
        f.close();
        Serial.println("[AuthSync] Bitset file size invalid or too large");
        return false;
    }
    size_t r = f.read(reinterpret_cast<uint8_t*>(authorized_bits), bytes);
    f.close();
    if (r != bytes) {
        Serial.println("[AuthSync] Failed to read full bitset from file");
        return false;
    }
    if (prefsOpen_) {
        max_card_id = prefs_.getUInt("max_id", (uint32_t)((bytes * 8) - 1));
    } else {
        max_card_id = (uint32_t)((bytes * 8) - 1);
    }
    Serial.printf("[AuthSync] Loaded bitset snapshot %u bytes, max_id=%u\n", (unsigned)bytes, max_card_id);
    return true;
}

#ifdef AUTH_TEST_HOOK
// Test helper to simulate a very large `max_card_id` safely in unit tests.
void AuthSync::TEST_setMaxCardId(size_t maxCardId) {
    // Cap to a sane maximum for a NodeMCU-32S to avoid exhausting device memory.
    // 200k cards -> ~25 KB bitset, which is safe on typical ESP32 dev boards.
    const size_t SAFE_MAX = 200000UL; // 200,000 cards (~25 KB bitset)
    if (maxCardId > SAFE_MAX) maxCardId = SAFE_MAX;

    // Update max_card_id and compute required bytes
    max_card_id = (uint32_t)maxCardId;
    size_t nbytes = calcBitsetBytes(max_card_id);
    if (nbytes == 0) {
        // nothing to allocate
        return;
    }

    if (nbytes > MAX_SAFE_BYTES) {
        // should not happen due to SAFE_MAX cap, but guard anyway
        nbytes = MAX_SAFE_BYTES;
    }

    // Point to the static storage and zero the used portion
    authorized_bits = authorized_bits_storage;
    // avoid C-style memset (tooling may warn); use std::fill_n
    std::fill_n(authorized_bits, nbytes, 0);
}
#endif

void AuthSync::dumpMemoryStats() const {
    // Print free heap
    size_t freeHeap = esp_get_free_heap_size();
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    Serial.printf("[AuthSync] freeHeap=%u largestFreeBlock=%u\n", (unsigned)freeHeap, (unsigned)largest);

    // Hash vectors
    Serial.printf("[AuthSync] allowHashes entries=%u bytes=%u\n", (unsigned)allowHashes_.size(), (unsigned)(allowHashes_.size() * sizeof(uint64_t)));
    Serial.printf("[AuthSync] denyHashes  entries=%u bytes=%u\n", (unsigned)denyHashes_.size(), (unsigned)(denyHashes_.size() * sizeof(uint64_t)));

    // Bitset usage
    size_t bitBytes = calcBitsetBytes(max_card_id);
    Serial.printf("[AuthSync] max_card_id=%u bitset_bytes=%u MAX_SAFE_BYTES=%u\n", max_card_id, (unsigned)bitBytes, (unsigned)MAX_SAFE_BYTES);
}

#ifdef AUTH_TEST_HOOK
void AuthSync::TEST_dumpMemoryStats() const {
    dumpMemoryStats();
}
#endif
void AuthSync::setServerProbeResult(bool ok, unsigned long probeMillis) {
    server_last_ok = ok;
    last_server_probe = probeMillis;
}
