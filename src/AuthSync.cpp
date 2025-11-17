#include "AuthSync.h"

AuthSync::AuthSync(const String& serverBase) : server_base(serverBase) {}

AuthSync::~AuthSync() {
    if (authorized_bits) free(authorized_bits);
}

bool AuthSync::begin() {
    return syncFromServer();
}

bool AuthSync::update() {
    if (millis() - last_sync > SYNC_INTERVAL) {
        return syncFromServer();
    }
    return true;
}

bool AuthSync::isAuthorized(const String& uid) {
    int card_id = getCardIdFromServer(uid);
    if (card_id < 0 || card_id > (int)max_card_id) return false;

    return authorized_bits[card_id >> 3] & (1 << (card_id & 7));
}

bool AuthSync::syncFromServer() {
    if (WiFi.status() != WL_CONNECTED) return false;

    HTTPClient http;
    http.setTimeout(5000);  // 5 second timeout
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

    uint32_t new_max = doc["max_id"] | 0;
    String hex = doc["bits"].as<String>();

    // Free old heap memory
    if (authorized_bits) free(authorized_bits);

    size_t bytes = (new_max + 7) / 8;
    authorized_bits = (uint8_t*)malloc(bytes);          // DYNAMIC HEAP ALLOCATION
    if (!authorized_bits) {
        max_card_id = 0;
        return false;
    }
    memset(authorized_bits, 0, bytes);

    for (size_t i = 0; i < hex.length(); i += 2) {
        String byteStr = hex.substring(i, i + 2);
        authorized_bits[i / 2] = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
    }

    max_card_id = new_max;
    last_sync = millis();

    Serial.printf("[AuthSync] Synced %lu cards → %u bytes heap\n", max_card_id + 1, bytes);
    return true;
}

int AuthSync::getCardIdFromServer(const String& uid) {
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

    if (!doc["exists"] || !doc["authorized"]) return -1;
    return doc["card_id"] | -1;
}