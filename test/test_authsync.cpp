#include <Arduino.h>
#include <unity.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

// Include AuthSync and ConfigManager implementation
#include "../src/ConfigManager.h"
#include "../src/ConfigManager.cpp"
#include "../src/AuthSync.h"
#include "../src/AuthSync.cpp"

// Test WiFi credentials (loaded from LittleFS /config.json at runtime)
String SSID = "";
String PASS = "";
String SERVER_BASE = "";

// Test results logging
File testLogFile;
const char* TEST_LOG_PATH = "/test_results.txt";

// Load network config from LittleFS /config.json using ConfigManager
static bool loadNetworkConfigFromLittleFS() {
    if (!LittleFS.begin()) {
        Serial.println("[CFG] LittleFS.mount FAILED");
        return false;
    }
    
    bool result = ConfigManager::loadConfig(SSID, PASS, SERVER_BASE);
    
    if (result) {
        Serial.printf("[CFG] Loaded ssid='%s' server='%s'\n", SSID.c_str(), SERVER_BASE.c_str());
    } else {
        Serial.println("[CFG] Failed to load config.json");
    }
    
    return result;
}

void setUp(void) {
    // Connect to WiFi before each test (if config present)
    if (SSID.length() > 0) {
        if (WiFi.status() != WL_CONNECTED) {
            WiFi.begin(SSID.c_str(), PASS.c_str());
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
        AuthSync auth(SERVER_BASE);
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
    
    AuthSync auth(SERVER_BASE);
    
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
    AuthSync auth(SERVER_BASE);
    
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
    
    AuthSync auth(SERVER_BASE);
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




// Test 6: Stress test - rapid allocations
void test_authsync_stress() {
    uint32_t initial_heap = ESP.getFreeHeap();
    Serial.printf("\n[TEST] Initial heap: %u bytes\n", initial_heap);
    
    // Create and destroy multiple AuthSync objects rapidly
    for (int i = 0; i < 10; i++) {
        AuthSync* auth = new AuthSync(SERVER_BASE);
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

// Test 7: Test with 3000 cards using TEST_setMaxCardId
#ifdef AUTH_TEST_HOOK
void test_authsync_3000_cards() {
    Serial.println("\n[TEST] Testing with 3000 cards");
    
    uint32_t initial_heap = ESP.getFreeHeap();
    Serial.printf("[TEST] Initial heap: %u bytes\n", initial_heap);
    
    AuthSync auth(SERVER_BASE);
    
    // Set max card ID to 2999 (3000 cards: 0-2999)
    auth.TEST_setMaxCardId(2999);
    
    uint32_t card_count = auth.getCardCount();
    size_t memory_used = auth.getMemoryUsed();
    
    Serial.printf("[TEST] Card count: %lu\n", card_count);
    Serial.printf("[TEST] Memory used: %u bytes\n", memory_used);
    
    // Verify card count
    TEST_ASSERT_EQUAL(3000, card_count);
    
    // Calculate expected bytes: (3000 + 7) / 8 = 375.875 = 375 bytes
    size_t expected_bytes = (3000 + 7) / 8;
    Serial.printf("[TEST] Expected bytes: %u\n", expected_bytes);
    
    TEST_ASSERT_EQUAL(expected_bytes, memory_used);
    TEST_ASSERT_EQUAL(375, memory_used);  // 3000 cards = 375 bytes
    
    uint32_t heap_used = initial_heap - ESP.getFreeHeap();
    Serial.printf("[TEST] Heap used for 3000 cards: %u bytes\n", heap_used);
    
    // Verify it's reasonable (375 bytes + overhead)
    TEST_ASSERT_LESS_THAN(1000, heap_used);  // Should be under 1KB
}

// Test 8: Overflow safety test
void test_authsync_overflow_safety() {
    AuthSync auth(SERVER_BASE);

    // Ask the implementation to pretend it has a huge max_card_id.
    // The production code should cap allocations; the test hook

    auth.TEST_setMaxCardId((size_t)-1);

    size_t mem = auth.getMemoryUsed();
    Serial.printf("\n[TEST] Overflow safety - memory used: %u bytes\n", mem);

    // Sanity checks: non-zero and not absurdly large for test environment
    TEST_ASSERT_GREATER_THAN(0u, mem);
    TEST_ASSERT_LESS_THAN(50u * 1024 * 1024, mem); // <50MB
}
#endif

void setup() {
    Serial.begin(115200);
    delay(2000);

    // Load network config from LittleFS so tests use device config instead of hardcoded credentials
    loadNetworkConfigFromLittleFS();

    // Open log file for writing test results
    testLogFile = LittleFS.open(TEST_LOG_PATH, "w");
    if (testLogFile) {
        Serial.printf("Test results will be saved to: %s\n", TEST_LOG_PATH);
        
        // Write header to log file
        char timestamp[64];
        snprintf(timestamp, sizeof(timestamp), "Test Run: %lu ms since boot\n", millis());
        testLogFile.print(timestamp);
        testLogFile.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());
        testLogFile.printf("Chip Model: %s\n", ESP.getChipModel());
        testLogFile.printf("CPU Freq: %u MHz\n\n", ESP.getCpuFreqMHz());
    } else {
        Serial.println("Warning: Could not open test log file");
    }

    Serial.println("\n========================================");
    Serial.println("AuthSync Heap Allocation Tests");
    Serial.println("========================================\n");

    UNITY_BEGIN();

    RUN_TEST(test_authsync_construction);
    RUN_TEST(test_authsync_sync_allocates);
    RUN_TEST(test_authsync_no_memory_leak);
    RUN_TEST(test_authsync_memory_size);
  
    RUN_TEST(test_authsync_stress);

#ifdef AUTH_TEST_HOOK
    RUN_TEST(test_authsync_3000_cards);
    RUN_TEST(test_authsync_overflow_safety);
#endif

    UNITY_END();
    
    // Close log file and print summary
    if (testLogFile) {
        testLogFile.print("\n========================================\n");
        testLogFile.printf("Test run completed at: %lu ms\n", millis());
        testLogFile.printf("Final Free Heap: %u bytes\n", ESP.getFreeHeap());
        testLogFile.close();
        
        Serial.println("\n========================================");
        Serial.printf("Test results saved to: %s\n", TEST_LOG_PATH);
        Serial.println("========================================\n");
        
        // Read and display file size
        File checkFile = LittleFS.open(TEST_LOG_PATH, "r");
        if (checkFile) {
            Serial.printf("Log file size: %u bytes\n", checkFile.size());
            checkFile.close();
        }
    }

    // After tests complete in setup(), add:
    File resultsFile = LittleFS.open(TEST_LOG_PATH, "r");
    if (resultsFile) {
        Serial.println("\n\n=== TEST RESULTS FILE CONTENT ===");
        while (resultsFile.available()) {
            Serial.write(resultsFile.read());
        }
        Serial.println("\n=== END OF TEST RESULTS ===");
        resultsFile.close();
    }
}

void loop() {
    // Tests run once in setup
    delay(1000);
}
