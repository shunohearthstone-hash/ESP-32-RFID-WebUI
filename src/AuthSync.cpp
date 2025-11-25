/* Behaviour summary:
 AuthSync maintains two authorization layers:
  1) Online: If WiFi connected and server_base set, it probes /api/status (cached 5s) then
     queries /api/cards/<uid>. Successful responses update sorted allow/deny hash vectors.
  2) Offline fallback: If server unreachable or lookup fails, it binary_searches cached
     denyHashes_ (deny wins) then allowHashes_. Hashes are 64-bit FNV-1a of normalized UID.

 Bitset (authorized_bits) fetched via /api/sync stores per-card_id bits (heap malloc, freed/replaced each sync).
 Hash caches and counts persist in NVS (Preferences) for offline reuse across reboots.

 All heap allocations guarded; failure leaves structures null and logic safely returns false.
 Server reachability is throttled; no HTTP attempted when previously marked unreachable.
 Prioritizes fresh server authorization when available,
 with secondary binary search authorization offline. */
//.............THIS HAS ORDER HAS BEEN REVERSED....................//
 /* Server > Hash: if we have network connectivity,
        ask the server first for card authorization.

          Connected Example Flow:
        Scan UID: "04A1B2C3"
         ↓
        Hash (FNV-1a 64-bit): 0x8F3A4B2C1D9E7F6A (logged)
         ↓
        WiFi OK && server_base set → probe (every 5s) /api/status
         ↓ (status 200)
        GET /api/cards/04A1B2C3 → { "exists": true, "card_id": 1234, "authorized": true }
         ↓
        addKnownAuth() → hash inserted into allowHashes_ (sorted), removed from deny if present
         ↓
        Return: AUTHORIZED (true)
        (If GET fails or exists=false → fallback to offline hash search sequence)
    ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   
        Offline Example Flow:
        Card scanned: "04A1B2C3"
         ↓
        Hash: 0x8f3a4b2c1d9e7f6a
         ↓
        Binary search denyHashes_  → Not found
         ↓
        Binary search allowHashes_ → Found at index 42
         ↓
        Return: AUTHORIZED
    
   --------------------------------------------------------------------------*/




#include "AuthSync.h"
#include <WiFi.h>
#include <limits>
/*for each byte in input:
    hash ^= byte        // XOR with current hash
    hash *= prime       // Multiply by FNV prime*/
// -------------------- hashing (FNV-1a 64-bit) --------------------
static inline uint64_t fnv1a64(const uint8_t* data, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;      // FNV offset basis
    const uint64_t prime = 0x100000001b3ULL;     // FNV prime
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= prime;
    }
    return hash;
}

uint64_t AuthSync::hashUid(const String& s) {
    String t = s;  // normalize to uppercase, trimmed
    t.trim();
    t.toUpperCase();
    //Normalise hash for whitespace or case differences
    return fnv1a64(reinterpret_cast<const uint8_t*>(t.c_str()), t.length()); 
}

AuthSync::AuthSync(const String& serverBase) : server_base(serverBase) {}

AuthSync::~AuthSync() {
    if (authorized_bits) { free(authorized_bits); authorized_bits = nullptr; }
    if (prefsOpen_) {
        prefs_.end();
        prefsOpen_ = false;
    }
}

// ---------------- Bitset safety helpers ----------------
size_t AuthSync::calcBitsetBytes(uint32_t maxId) const {
    // bits = maxId + 1
    size_t bits = (size_t)maxId + 1;
    // guard against overflow (practically won't happen for uint32_t)
    if (bits == 0) return 0;
    if (bits > std::numeric_limits<size_t>::max() - 7) return 0;
    return (bits + 7) / 8;
}
//Write a byte at index idx in the bitset, return true on success, 
//false when out of bounds or uninitialized
bool AuthSync::writeByteAt(size_t idx, uint8_t val) {
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
void AuthSync::setBit(uint32_t id) {
    if (!authorized_bits) return;
    if (id > max_card_id) return;
    size_t idx = (size_t)id >> 3;
    uint8_t bit = id & 7;
    authorized_bits[idx] |= (1u << bit);
}
//Reverse of setBit: clears the authorization bit for a specific card ID,
// marking it as unauthorized. Verify buffer and bounds before clearing.
void AuthSync::clearBit(uint32_t id) {
    if (!authorized_bits) return;
    if (id > max_card_id) return;
    size_t idx = (size_t)id >> 3;
    uint8_t bit = id & 7;
    authorized_bits[idx] &= ~(1u << bit);
}

// Open NVS and load any cached hashes first for offline use
bool AuthSync::begin() {
    if (!prefsOpen_) {
        prefsOpen_ = prefs_.begin("auth", false);
    }
    if (prefsOpen_) {
        loadFromNVS();
    }
    return syncFromServer();
}

// Load only offline caches from NVS; skip any network sync
bool AuthSync::preloadOffline() {
    if (!prefsOpen_) {
        prefsOpen_ = prefs_.begin("auth", false);
    }
    if (prefsOpen_) {
        loadFromNVS();
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
    bool denied = std::binary_search(denyHashes_.begin(), denyHashes_.end(), h);
    if (denied) {
        Serial.println("[AuthSync] Found in deny cache -> DENIED");
        return false;
    }
    bool allowed = std::binary_search(allowHashes_.begin(), allowHashes_.end(), h);
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

bool AuthSync::syncFromServer() {
    if (WiFi.status() != WL_CONNECTED || server_base.length() == 0) return false;
    // Backoff: only after a failed probe and not on the very first attempt (last_server_probe != 0)
    if (!server_last_ok && last_server_probe != 0 && (millis() - last_server_probe) < 10000) {
        Serial.println("[AuthSync] Backoff active; skipping sync");
        return false;
    }

    if (millis() - last_server_probe > 5000 || last_server_probe == 0) {
        last_server_probe = millis();
        HTTPClient ping;
        ping.setTimeout(300); // faster reachability probe for sync cycle
        ping.begin(server_base + "/api/status");
        int sc = ping.GET();
        ping.end();
        server_last_ok = (sc == 200);
        if (!server_last_ok) {
            Serial.println("[AuthSync] Sync aborted: server unreachable");
            return false;
        }
    }

    HTTPClient http;
    http.setTimeout(2000);  // shorter sync timeout
    http.begin(server_base + "/api/sync");
    int code = http.GET();
    
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

    // Free any existing authorization bitset and allocate a new
    // heap buffer sized for new_max card IDs. If allocation or
    // size calculation fails, reset max_card_id and abort the sync.
    if (authorized_bits) { free(authorized_bits); authorized_bits = nullptr; }

    size_t bytes = calcBitsetBytes(new_max);
    if (bytes == 0) {
        max_card_id = 0;
        return false;
    }
// Allocate new bitset heap buffer and zero it
    authorized_bits = (uint8_t*)malloc(bytes);          
    if (!authorized_bits) {
        max_card_id = 0;
        return false;
    }
    memset(authorized_bits, 0, bytes);

    // Decode the hex bitset payload (two characters per byte) into
    // the newly allocated buffer using the bounds-checked writer.
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        String byteStr = hex.substring(i, i + 2);
        uint8_t v = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
        if (!writeByteAt(i / 2, v)) break;
    }

    // Commit the new bitset and record the time of this successful sync.
    max_card_id = new_max;
    last_sync = millis();

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
//I don´t really understand std::sort, but this magic incantation calls loadArray
// 4 times into temporary vectors, which are then sorted with std::sort and de-duplicated with
//std::unique. Finally, if either vector is non-empty, they are swapped into the class members
    
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
            saveToNVS();
            //It then saves the new vectors to NVS for persistence across reboots. 
            
        }
    }

    // Log a compact summary of the sync result for debugging.
    Serial.printf("[AuthSync] Synced max_id=%u (%u bytes heap)\n", max_card_id, bytes);
    return true;
}

int AuthSync::getCardIdFromServer(const String& uid) {
    // Perform a one-off lookup for a card's numeric ID given its
    // UID string via /api/cards/<uid>. Returns -1 on any network,
    // HTTP, or parsing failure, or when the card does not exist.
    if (WiFi.status() != WL_CONNECTED) return -1;

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
    DeserializationError err = deserializeJson(doc, payload);
    if (err) {
        Serial.printf("[AuthSync] JSON parse error: %s\n", err.c_str());
        return -1;
    }

    // If card exists, return card_id (even if unauthorized) so callers
    // can still correlate the UID with a position in the authorization bitset.
    bool exists = doc["exists"] | false;
    if (!exists) return -1;
    return doc["card_id"] | -1;
}

// -------------------- Offline cache helpers --------------------
void AuthSync::addKnownAuth(const String& uid, bool allowed) {
    // Learn a card's authorization status for offline use by
    // normalizing + hashing the UID, then inserting that hash
    // into either the allow or deny cache and persisting to NVS.
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
    saveToNVS();
}

void AuthSync::saveToNVS() {
    // Persist the current allow/deny hash vectors into NVS. Counts
    // are stored separately from the raw uint64_t blobs so they can
    // be reconstructed on the next boot.
    if (!prefsOpen_) return;
    // Store counts and raw blobs; guard against empty vectors
    prefs_.putUInt("allow_n", (uint32_t)allowHashes_.size());
    prefs_.putUInt("deny_n",  (uint32_t)denyHashes_.size());
    if (!allowHashes_.empty()) {
        prefs_.putBytes("allow", allowHashes_.data(), allowHashes_.size() * sizeof(uint64_t));
    } else {
        prefs_.remove("allow");
    }
    if (!denyHashes_.empty()) {
        prefs_.putBytes("deny", denyHashes_.data(), denyHashes_.size() * sizeof(uint64_t));
    } else {
        prefs_.remove("deny");
    }
}

void AuthSync::loadFromNVS() {
    // Restore allow/deny hash vectors from NVS into memory and
    // ensure they are sorted so that binary_search remains valid.
    if (!prefsOpen_) return;
    uint32_t an = prefs_.getUInt("allow_n", 0);
    uint32_t dn = prefs_.getUInt("deny_n", 0);
    allowHashes_.assign(an, 0);
    denyHashes_.assign(dn, 0);
    if (an) prefs_.getBytes("allow", allowHashes_.data(), an * sizeof(uint64_t));
    if (dn) prefs_.getBytes("deny",  denyHashes_.data(),  dn * sizeof(uint64_t));
    // Ensure sorted for binary_search (in case stored unsorted from older versions)
    std::sort(allowHashes_.begin(), allowHashes_.end());
    std::sort(denyHashes_.begin(),  denyHashes_.end());
}

#ifdef AUTH_TEST_HOOK
// Test helper to simulate a very large `max_card_id` safely in unit tests.
void AuthSync::TEST_setMaxCardId(size_t maxCardId) {
    // Cap to a sane maximum for a NodeMCU-32S to avoid exhausting device memory.
    // 200k cards -> ~25 KB bitset, which is safe on typical ESP32 dev boards.
    const size_t SAFE_MAX = 200000UL; // 200,000 cards (~25 KB bitset)
    if (maxCardId > SAFE_MAX) maxCardId = SAFE_MAX;

    // Free any existing bitset
    if (authorized_bits) {
        free(authorized_bits);
        authorized_bits = nullptr;
    }

    // Update max_card_id and allocate a new bitset (if non-zero)
    max_card_id = (uint32_t)maxCardId;
    size_t nbytes = calcBitsetBytes(max_card_id);
    if (nbytes == 0) {
        // nothing to allocate
        return;
    }

    // Defensive malloc — if allocation fails, leave authorized_bits null
    authorized_bits = (uint8_t*)malloc(nbytes);
    if (authorized_bits) {
        memset(authorized_bits, 0, nbytes);
    }
}
#endif

