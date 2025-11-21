#include <Arduino.h>
#include <unity.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <LittleFS.h>               // added: read config.json from LittleFS

// Include AuthSync implementation directly
#include "../src/AuthSync.h"
#include "../src/AuthSync.cpp"

// Test WiFi credentials (loaded from LittleFS /config.json at runtime)
String TEST_SSID = "";
String TEST_PASS = "";
String TEST_SERVER = "";

// Load network config from LittleFS /config.json
static bool loadNetworkConfigFromLittleFS() {
    if (!LittleFS.begin()) {
        Serial.println("[CFG] LittleFS.mount FAILED");
        return false;
    }
    if (!LittleFS.exists("/config.json")) {
        Serial.println("[CFG] /config.json not found");
        return false;
    }
    File f = LittleFS.open("/config.json", "r");
    if (!f) {
        Serial.println("[CFG] Failed to open /config.json");
        return false;
    }
    size_t sz = f.size();
    if (sz == 0) {
        f.close();
        Serial.println("[CFG] /config.json empty");
        return false;
    }
    std::unique_ptr<char[]> buf(new char[sz + 1]);
    f.readBytes(buf.get(), sz);
    buf[sz] = '\0';
    f.close();

    StaticJsonDocument<512> doc;
    DeserializationError err = deserializeJson(doc, buf.get());
    if (err) {
        Serial.print("[CFG] JSON parse failed: ");
        Serial.println(err.c_str());
        return false;
    }
    TEST_SSID = String(doc["ssid"] | "");
    TEST_PASS = String(doc["password"] | "");
    TEST_SERVER = String(doc["server_base"] | "");
    Serial.printf("[CFG] Loaded ssid='%s' server='%s'\n", TEST_SSID.c_str(), TEST_SERVER.c_str());
    return true;
}

void setUp(void) {
    // Connect to WiFi before each test (if config present)
    if (TEST_SSID.length() > 0) {
        if (WiFi.status() != WL_CONNECTED) {
            WiFi.begin(TEST_SSID.c_str(), TEST_PASS.c_str());
            int timeout = 0;
            while (WiFi.status() != WL_CONNECTED && timeout < 20) {
                delay(500);
                timeout++;
            }
        }
    } else {
        Serial.println("[SETUP] No SSID configured -> network tests will skip");
    }
}

void tearDown(void) {
    // Cleanup after each test
}

// Test 1: Basic construction and destruction
void test_authsync_construction() {
    uint32_t free_before = ESP.getFreeHeap();
    Serial.printf("\n[TEST] Free heap before: %u bytes\n", free_before);
    
    {
        AuthSync auth(TEST_SERVER);
        uint32_t free_during = ESP.getFreeHeap();
        Serial.printf("[TEST] Free heap after construction: %u bytes\n", free_during);
        
        TEST_ASSERT_LESS_OR_EQUAL(free_before, free_during);
    } // auth goes out of scope, destructor should free memory
    
    delay(100); // Give system time to cleanup
    uint32_t free_after = ESP.getFreeHeap();
    Serial.printf("[TEST] Free heap after destruction: %u bytes\n", free_after);
    
    // After destruction, we should have similar or more free heap
    // Allow small variance due to heap fragmentation
    TEST_ASSERT_GREATER_OR_EQUAL(free_before - 100, free_after);
}

// Test 2: Sync operation allocates memory
void test_authsync_sync_allocates() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\n[SKIP] WiFi not connected");
        TEST_IGNORE_MESSAGE("WiFi not connected");
        return;
    }
    
    AuthSync auth(TEST_SERVER);
    
    uint32_t free_before = ESP.getFreeHeap();
    Serial.printf("\n[TEST] Free heap before sync: %u bytes\n", free_before);
    
    bool result = auth.begin();
    
    uint32_t free_after = ESP.getFreeHeap();
    Serial.printf("[TEST] Free heap after sync: %u bytes\n", free_after);
    Serial.printf("[TEST] Synced cards: %lu\n", auth.getCardCount());
    Serial.printf("[TEST] Memory used: %u bytes\n", auth.getMemoryUsed());
    Serial.printf("[TEST] Sync result: %s\n", result ? "SUCCESS" : "FAILED");
    
    if (result) {
        // Sync should have allocated memory (even if 0 cards, we allocate minimum)
        TEST_ASSERT_GREATER_THAN(0, auth.getMemoryUsed());
    } else {
        Serial.println("[TEST] Sync failed - check server connection");
    }
    
    TEST_ASSERT_TRUE(result);
}

// Test 3: Multiple syncs don't leak memory
void test_authsync_no_memory_leak() {
    AuthSync auth(TEST_SERVER);
    
    // Do initial sync
    auth.begin();
    delay(100);
    
    uint32_t free_baseline = ESP.getFreeHeap();
    Serial.printf("\n[TEST] Baseline heap: %u bytes\n", free_baseline);
    
    // Perform multiple syncs
    for (int i = 0; i < 5; i++) {
        bool result = auth.update();
        delay(100);
        uint32_t free_current = ESP.getFreeHeap();
        Serial.printf("[TEST] Sync #%d - Free heap: %u bytes\n", i + 1, free_current);
        
        // Each sync should free old memory before allocating new
        // Allow 200 byte variance for heap fragmentation
        TEST_ASSERT_GREATER_OR_EQUAL(free_baseline - 200, free_current);
    }
    
    uint32_t free_final = ESP.getFreeHeap();
    Serial.printf("[TEST] Final heap: %u bytes\n", free_final);
    
    // Should be close to baseline (within fragmentation tolerance)
    TEST_ASSERT_GREATER_OR_EQUAL(free_baseline - 300, free_final);
}

// Test 4: Bit array size calculation
void test_authsync_memory_size() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\n[SKIP] WiFi not connected");
        TEST_IGNORE_MESSAGE("WiFi not connected");
        return;
    }
    
    AuthSync auth(TEST_SERVER);
    bool sync_ok = auth.begin();
    
    if (!sync_ok) {
        Serial.println("\n[SKIP] Sync failed");
        TEST_IGNORE_MESSAGE("Sync failed");
        return;
    }
    
    uint32_t card_count = auth.getCardCount();
    size_t memory_used = auth.getMemoryUsed();
    
    Serial.printf("\n[TEST] Card count: %lu\n", card_count);
    Serial.printf("[TEST] Memory used: %u bytes\n", memory_used);
    
    // Calculate expected bytes: (card_count + 7) / 8
    size_t expected_bytes = (card_count + 7) / 8;
    
    Serial.printf("[TEST] Expected bytes: %u\n", expected_bytes);
    
    TEST_ASSERT_EQUAL(expected_bytes, memory_used);
}

// Test 5: Authorization check works
void test_authsync_authorization_check() {
    AuthSync auth(TEST_SERVER);
    bool sync_result = auth.begin();
    
    TEST_ASSERT_TRUE(sync_result);
    
    // Test with a known non-existent card
    bool authorized = auth.isAuthorized("FFFFFFFF");
    Serial.printf("\n[TEST] Authorization for FFFFFFFF: %s\n", authorized ? "YES" : "NO");
    
    // This should be false unless you have this card enrolled
    TEST_ASSERT_FALSE(authorized);
}

// Test 6: Stress test - rapid allocations
void test_authsync_stress() {
    uint32_t initial_heap = ESP.getFreeHeap();
    Serial.printf("\n[TEST] Initial heap: %u bytes\n", initial_heap);
    
    // Create and destroy multiple AuthSync objects rapidly
    for (int i = 0; i < 10; i++) {
        AuthSync* auth = new AuthSync(TEST_SERVER);
        auth->begin();
        delay(50);
        delete auth;
        
        uint32_t current_heap = ESP.getFreeHeap();
        Serial.printf("[TEST] Iteration %d - Free heap: %u bytes\n", i, current_heap);
    }
    
    delay(200);
    uint32_t final_heap = ESP.getFreeHeap();
    Serial.printf("[TEST] Final heap: %u bytes\n", final_heap);
    
    // Allow 500 bytes variance
    TEST_ASSERT_GREATER_OR_EQUAL(initial_heap - 500, final_heap);
}

void setup() {
    Serial.begin(115200);
    delay(2000);

    // Load network config from LittleFS so tests use device config instead of hardcoded credentials
    loadNetworkConfigFromLittleFS();

    Serial.println("\n\n========================================");
    Serial.println("AuthSync Heap Allocation Tests");
    Serial.println("========================================\n");

    UNITY_BEGIN();

    RUN_TEST(test_authsync_construction);
    RUN_TEST(test_authsync_sync_allocates);
    RUN_TEST(test_authsync_no_memory_leak);
    RUN_TEST(test_authsync_memory_size);
    RUN_TEST(test_authsync_authorization_check);
    RUN_TEST(test_authsync_stress);

#ifdef AUTH_TEST_HOOK
    RUN_TEST(test_authsync_overflow_safety);
#endif

/*
 * Overflow safety test (test-only).
 *
 * This test requires a test hook in `AuthSync` named
 * `void TEST_setMaxCardId(size_t maxCardId)` which is intentionally
 * excluded from production builds. To enable this test:
 *  - Define `AUTH_TEST_HOOK` when building the test target.
 *  - Add the TEST_setMaxCardId helper to `AuthSync` (see notes below).
 *
 * The test requests an absurdly large card id and verifies the
 * resulting memory size reported by getMemoryUsed() is sensible
 * (didn't wrap or underflow). If the test hook or macro isn't
 * defined, the test is skipped.
 */
#ifdef AUTH_TEST_HOOK
void test_authsync_overflow_safety() {
    AuthSync auth(TEST_SERVER);

    // Ask the implementation to pretend it has a huge max_card_id.
    // The production code should cap allocations; the test hook
    // allows us to simulate pathological server values without
    // changing production behavior.
    auth.TEST_setMaxCardId((size_t)-1);

    size_t mem = auth.getMemoryUsed();
    Serial.printf("\n[TEST] Overflow safety - memory used: %u bytes\n", mem);

    // Sanity checks: non-zero and not absurdly large for test environment
    TEST_ASSERT_GREATER_THAN(0u, mem);
    TEST_ASSERT_LESS_THAN(50u * 1024 * 1024, mem); // <50MB
}
#endif

    UNITY_END();
}

void loop() {
    // Tests run once in setup
    delay(1000);
}
