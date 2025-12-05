#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <freertos/timers.h>
#include "TimerHandle.h"
#include "AuthSync.h"
#include "ConfigManager.h"
#include "HardwareSerial.h"
#include "HashUtils.h"
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <MFRC522.h>
#include <SPI.h>
#include <U8x8lib.h>
#include <WiFi.h>
#include <Wire.h>
#include <Arduino.h>
#include <cstring>



/*
  Runtime flow (high level)

  1) Boot and setup()
     - Initialize peripherals (display, SPI, RFID).
     - Mount LittleFS and try to read `/config.json`.
       * If present, parse and populate SSID/PASS/SERVER_BASE.
       * If missing or parse fails, the strings remain empty and network/server
         related features are skipped.
     - Create `AuthSync` at runtime if a `server_base` was provided in config.
     - Call `WiFi.begin(SSID, PASS)` using the loaded credentials (may fail if
       no config provided).
     - If Wi‑Fi connects, call `authSync->begin()` (initial server sync) when
       `AuthSync` exists.

  2) Main loop
     - Periodically poll `/api/status` (only when Wi‑Fi connected and
       SERVER_BASE is configured) to update enroll mode.
     - On RFID scan:
       * Post the scan to `/api/last_scan` (if configured/online).
       * Ask `authSync` whether the UID is authorized. `AuthSync` first
         consults its persistent hashed allow/deny caches (offline), then
         falls back to a server lookup / bitset when online. Results are
         learned and persisted for offline use.
     - `AuthSync::update()` runs periodically to refresh the authorization
       bitset from the server when online.

  Notes:
    - Configuration file format: JSON with keys `ssid`, `password`,
      and `server_base`. Place it in the project `data/` folder and use
      `pio run -t uploadfs` to write it to LittleFS as `/config.json`.
    - The app is defensive: if no network/server config exists it still
      runs and accepts scans, but server operations are skipped.

*/

/* RFID pins
#define RST_PIN 17
#define SS_PIN 5*/
constexpr uint8_t RST_PIN = 17;
constexpr uint8_t SS_PIN  = 5;
static constexpr unsigned long ENROLL_POLL_INTERVAL_MS = 5000;
MFRC522 rfid(SS_PIN, RST_PIN);

// Display
U8X8_SSD1315_128X64_NONAME_SW_I2C u8x8(
  /* clock=*/22,
  /* data=*/21,
  /* reset=*/U8X8_PIN_NONE);

// ----------------- CONFIG -----------------
// Network and server configuration are moved out of the firmware and
// loaded from LittleFS at boot. This prevents embedding credentials in
// the binary and allows convenient updates by writing `/config.json` to
// the filesystem (use PlatformIO `uploadfs` from the project `data/` dir).
//
// If the file is missing the strings remain empty and server-related
// functionality is skipped.
String SSID = "";
String PASS = "";
String SERVER_BASE = "";

// Authorization sync (created after config load) — allocated at runtime
// so it can use the runtime `SERVER_BASE` value read from the JSON file.
AuthSync *authSync = nullptr;

// ----------------- State -----------------
String lastUID = "NONE";
String enrollMode = "none";
bool lastAuthorized = false;
uint64_t lastHash = 0;        // Last computed hash for display
bool serverReachable = false; // Track server/database reachability
unsigned long lastDisplayUpdate = 0;
unsigned long enrollBlinkMillis = 0;
bool enrollBlinkState = false;
// Simple millis-based enroll-mode poll

static unsigned long lastEnrollPoll = 0;

// Display state tracking (to avoid unnecessary redraws)
String displayedUID = "";
bool displayedAuth = false;
uint64_t displayedHash = 0;
String displayedEnrollMode = "";
bool displayedEnrollBlink = false;
bool displayedServerReachable = false;

DynamicJsonDocument postLastScan(const String &uid);
String getUidString();
void updateEnrollStatus();
void updateDisplay();
void drawHeader();
void drawEnrollIndicator(bool on);
void NetworkTask(void *pv);

// Queue for deferred network posting of scanned UIDs
struct ScanItem {
  char uid[21];
};
static QueueHandle_t scanQueue = nullptr;
//---------------- FreeRTOS timers -----------------
// AuthSync timer (non-blocking): callback only sets a flag; NetworkTask does
// the work
static volatile bool authSyncRequested = false;
// Display update flag set by timer callback
static volatile bool displayUpdateRequested = false;
static void displayTimerCallback(TimerHandle_t xTimer) { (void)xTimer; displayUpdateRequested = true; }

// ----------------- SETUP -----------------
void setup() {
  Serial.begin(115200);
  vTaskDelay(500 / portTICK_PERIOD_MS);
  Serial.println(" hello world!");

  // Force first auth line to render even if initial authorization is false
  // by priming displayedAuth opposite of lastAuthorized.
  displayedAuth = !lastAuthorized;

  Wire.begin(21, 22);
  u8x8.begin();
  u8x8.setFont(u8x8_font_chroma48medium8_r);
  drawHeader();
  u8x8.drawString(0, 2, "FS Init...");

  SPI.begin();
  rfid.PCD_Init();

  // Ensure FS is mounted before trying to load config
  if (LittleFS.begin()) {
    if (ConfigManager::loadConfig(SSID, PASS, SERVER_BASE)) {
      Serial.println("Config loaded from LittleFS");
      Serial.println("SSID: " + SSID);
      Serial.println("PASS: " + PASS);
      Serial.println("SERVER_BASE: " + SERVER_BASE);
      u8x8.drawString(0, 2, "FS OK   ");
      // Create AuthSync early so we can load offline caches from NVS
      if (SERVER_BASE.length() > 0) {
        authSync = new AuthSync(SERVER_BASE);
        // AuthSync constructed — delay offline preload until after WiFi
        // initialization so any network-related state is stable.
       } else {
         Serial.println("SERVER_BASE empty; offline authorization disabled "
                        "until configured");
       }
     } /* -------------  If failing to flash config.json, run auto-provisioning
         ------------- Replace  this placeholder with your desired network
         details to have the device write config.json on first boot.
         ------------- ------------- ------------- ------------- -------------
         -------------*/
    /*else {
      Serial.println("config.json missing -> auto-provisioning defaults");
      // One-time provisioning: write a default config, then reload.
      if (ConfigManager::saveConfig("SSID", "PASSWORD",
  "http://SERVER_Base")) { if (ConfigManager::loadConfig(SSID, PASS,
  SERVER_BASE)) { Serial.println("Provisioned default config.json");
          Serial.println("SSID: " + SSID);
          Serial.println("PASS: " + PASS);
          Serial.println("SERVER_BASE: " + SERVER_BASE);
          u8x8.drawString(0, 2, "PROVISION");
        } else {
          Serial.println("Provision write ok but reload failed");
          u8x8.drawString(0, 2, "PROV ERR");
        }
      } else {
        Serial.println("Failed to auto-provision config.json");
        u8x8.drawString(0, 2, "PROV FAIL");
      }
    }
    ConfigManager::listFiles();
  } else {
    Serial.println("LittleFS mount failed, formatting...");
    LittleFS.format();
    if (LittleFS.begin()) {
      Serial.println("LittleFS formatted and remounted");
      if (ConfigManager::loadConfig(SSID, PASS, SERVER_BASE)) {
        Serial.println("Config loaded from LittleFS");
        ConfigManager::listFiles();
      }
    } else {
      Serial.println("LittleFS format/remount failed");
      u8x8.drawString(0, 2, "FS FAIL");
    }*/
  }
  vTaskDelay(100 /
             portTICK_PERIOD_MS); // Give some time for LittleFS to stabilize

  WiFi.begin(SSID.c_str(), PASS.c_str());
  // After WiFi initialization, perform the offline preload (loads NVS + FS
  // caches) so AuthSync can have its cached data ready before any network
  // sync attempts. Doing this after WiFi.begin keeps the ordering stable.
  if (authSync) {
    authSync->preloadOffline();
    authSync->dumpMemoryStats();
    Serial.println("[AuthSync] Offline cache preloaded (after WiFi init)");
  }
  int tries = 0;
  while (WiFiClass::status() != WL_CONNECTED && tries < 80) {
    vTaskDelay(500 / portTICK_PERIOD_MS);
    Serial.print(".");
    tries++;
  }

  if (WiFiClass::status() == WL_CONNECTED) {
    Serial.println("");
    Serial.println("WiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    u8x8.drawString(0, 2, "WiFi OK     ");
    // Wifi modem sleep
    WiFi.setSleep(true);
    vTaskDelay(100 / portTICK_PERIOD_MS);

    // Attempt an online sync now that WiFi is connected (we already loaded
    // offline cache)
    bool syncOk = false;
    if (authSync) {
      // Use public begin() to perform an immediate sync (reloads NVS + attempts
      // server sync)
      syncOk = authSync->begin();
    }
    if (syncOk) {
      u8x8.drawString(0, 3, "DB OK");
      serverReachable = true;
      displayedServerReachable = true;
    } else {
      u8x8.drawString(0, 3, "DB OFFLINE  ");
      serverReachable = false;
      displayedServerReachable = false;
      Serial.println(
          "[AuthSync] Using offline cache (sync failed or server unreachable)");
    }
  } else {
    u8x8.drawString(0, 2, "WiFi FAIL");
    serverReachable = false;
    displayedServerReachable = false;
  }
  vTaskDelay(100 / portTICK_PERIOD_MS);

  // Create queue and network task (pin to core 0, lower priority than loop for
  // RFID responsiveness)
  //Note: this was implemented in a phase where there was no NetworkTask yet
  // Could probably just be lower priority
  if (!scanQueue) {
    scanQueue = xQueueCreate(10, sizeof(ScanItem));
    if (scanQueue) {
      xTaskCreatePinnedToCore(
        NetworkTask,
          "net_task",
          4096,
          nullptr,
          0,
          nullptr,
          0
          );
      Serial.println("[Tasks] NetworkTask started on core 0 (priority 0)");
    } else {
      Serial.println("[Tasks] Failed to create scanQueue");
    }
  }
  // Create timers using centralized helpers (Timers.cpp)
  if (!createDisplayTimer(displayTimerCallback, pdMS_TO_TICKS(500))) {
    Serial.println("[Tasks] Failed to create/start display timer");
  } else {
    Serial.println("[Tasks] Display timer started");
  }
}
void loop() {
  // Server reachability check now handled by FreeRTOS timer in NetworkTask

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
        String uid = getUidString();
    Serial.println("Scanned: " + uid);
    lastUID = uid;

    // Compute hash for display (same method as AuthSync) ----------- FOR
    // DEBUGGING ----
    /*String normalized = uid;
    normalized.trim();
    normalized.toUpperCase();
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < normalized.length(); i++) {
      constexpr uint64_t prime = 0x100000001b3ULL;
      hash ^= static_cast<uint8_t>(normalized[i]);
      hash *= prime;
    }*/

    lastHash = HashUtils::hashUid(uid);
    lastAuthorized = authSync ? authSync->isAuthorized(uid) : false;
    updateEnrollStatus(); // Refresh after scan
    updateDisplay();
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    vTaskDelay(100 / portTICK_PERIOD_MS); // Debounce recommended delay
    // Defer network POST of last scan to network task via queue
    if (scanQueue) {
      ScanItem item{};
      uid.toCharArray(item.uid, sizeof(item.uid));
      if (xQueueSend(scanQueue, &item, 0) != pdPASS) {
        Serial.println("[Queue] scanQueue full; dropping UID post");
      } else {
        Serial.printf("[Queue] Enqueued UID=%s\n", item.uid);
      }
    }
  }

  // Periodic sync handled by NetworkTask

  // Display updates are requested by a timer; perform the actual update in
  // loop() context to keep display code single-threaded and safe for the
  // U8x8 library.
  if (displayUpdateRequested) {
    displayUpdateRequested = false;
    updateDisplay();
    lastDisplayUpdate = millis();
  }

  // Blink indicator when waiting for enroll
  if (enrollMode != "none" && millis() - enrollBlinkMillis > 500) {
    enrollBlinkState = !enrollBlinkState;
    enrollBlinkMillis = millis();
    drawEnrollIndicator(enrollBlinkState);
  }

  // Simple millis-based enroll-mode poll
  if (millis() - lastEnrollPoll > ENROLL_POLL_INTERVAL_MS) {
    lastEnrollPoll = millis();
    updateEnrollStatus();
  }

#ifdef AUTH_TEST_HOOK
  // Test hook: press 'm' on serial to print memory stats
  if (Serial.available()) {
    int c = Serial.read();
    if (c == 'm' || c == 'M') {
      if (authSync) authSync->TEST_dumpMemoryStats();
    }
  }
#endif
}

//--------------------------------  helpers  ----------------------------------
String getUidString() {
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10)
      uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void drawHeader() {
  static bool headerDrawn = false;
  if (!headerDrawn) {
    u8x8.clear();
    u8x8.drawString(0, 0, "RFID Access");
    headerDrawn = true;
  }
}

void updateDisplay() {
  drawHeader(); // Only draws once

  // Update DB status if changed
  if (serverReachable != displayedServerReachable) {
    if (serverReachable) {
      u8x8.drawString(0, 3, "DB OK        ");
    } else {
      u8x8.drawString(0, 3, "DB LOST      ");
    }
    displayedServerReachable = serverReachable;
  }

  // Only update UID if changed
  if (lastUID != displayedUID) {
    String line = "UID:" + lastUID;
    if (line.length() > 16)
      line = line.substring(0, 16);
    // Pad with spaces to clear old text
    while (line.length() < 16)
      line += " ";
    u8x8.drawString(0, 1, line.c_str());
    displayedUID = lastUID;
  }

  // Only update auth status if changed
  if (lastAuthorized != displayedAuth) {
    u8x8.drawString(
        0, 4, (String("Auth:") + (lastAuthorized ? "YES" : "NO ")).c_str());
    displayedAuth = lastAuthorized;
  }

  // Update hash display (last 8 hex digits on bottom row)
  if (lastHash != displayedHash) {
    char hashStr[17];
    snprintf(hashStr, sizeof(hashStr), "H:%08X",
             uint32_t(lastHash & 0xFFFFFFFF));
    u8x8.drawString(0, 7, hashStr);
    displayedHash = lastHash;
  }

  // Update enroll indicator if mode changed
  if (enrollMode != displayedEnrollMode) {
    drawEnrollIndicator(enrollMode != "none");
  }
}

void drawEnrollIndicator(bool on) {
  String currentMode = enrollMode;
  bool currentBlink = on;

  // Only redraw if mode or blink state changed - Full redraws are visible
  if (currentMode != displayedEnrollMode ||
      currentBlink != displayedEnrollBlink) {
    if (enrollMode == "none") {
      u8x8.drawString(14, 0, "  ");
    } else if (on) {
      u8x8.drawString(14, 0, enrollMode == "grant" ? "GR" : "RV");
    } else {
      u8x8.drawString(14, 0, "  ");
    }
    displayedEnrollMode = currentMode;
    displayedEnrollBlink = currentBlink;
  }
}

DynamicJsonDocument postLastScan(const String &uid) {
  // Guard: if we're offline or server not configured, return empty doc.
  // This avoids making invalid HTTP calls when no server_base is provided
  // (e.g. on first-boot before provisioning /config.json).
  if (WiFi.status() != WL_CONNECTED)
    return DynamicJsonDocument(0);
  if (SERVER_BASE.length() == 0)
    return DynamicJsonDocument(0);
  // Escape: if we already marked serverReachable false, skip HTTP entirely
  if (!serverReachable) {
    // Uncomment for verbose logging: Serial.println("[postLastScan] Skipped
    // (serverReachable=false)");
    return DynamicJsonDocument(0);
  }
  HTTPClient http;
  http.setTimeout(1500); // shorter timeout to avoid long blocking
  http.begin(String(SERVER_BASE) + "/api/last_scan");
  http.addHeader("Content-Type", "application/json");
  String body = "{\"uid\":\"" + uid + "\"}";
  int code = http.POST(body);
  Serial.printf("[HTTP] POST /api/last_scan -> code=%d, body=%s\n", code, body.c_str());
  if (code < 200 || code >= 300) {
    Serial.printf("postLastScan failed: %d\n", code);
    http.end();
    return DynamicJsonDocument(0);
  }
  String payload = http.getString();
  Serial.printf("[HTTP] /api/last_scan payload: %s\n", payload.c_str());
  http.end();
  // Use a small dynamic document for the expected response
  DynamicJsonDocument doc(512);
  DeserializationError err = deserializeJson(doc, payload);
  if (err) {
    Serial.printf("postLastScan: JSON parse error: %s\n", err.c_str());
    return DynamicJsonDocument(0);
  }
  return doc;
}


void updateEnrollStatus() {
  // Skip poll if offline or no server configured. Keeps display consistent
  // and avoids pointless HTTP requests when not provisioned.
if (WiFi.status() != WL_CONNECTED || SERVER_BASE.length() == 0) {
    enrollMode       = "none";
    serverReachable   = false;
    return;
  }
  // Simple synchronous status poll (called from loop() on a millis timer)
  HTTPClient http;
  http.setTimeout(1500);
  String url = SERVER_BASE + "/api/status";
  http.begin(url);
  int code = http.GET();
  if (code > 0 && code < 400)
    serverReachable = true;
    String payload = http.getString();
    DynamicJsonDocument doc(256);
    DeserializationError err = deserializeJson(doc, payload);
    if (!err) {
    const char* m = doc["enroll_mode"] | nullptr;

    if (m && strlen(m) > 0) {
         enrollMode = m;
       } else {
         enrollMode = "none";
        }
     } else {
    serverReachable = false;
    enrollMode = "none";
  }
  http.end();
}

// Timer callback for server reachability check
void serverCheckTimerCallback(TimerHandle_t xTimer) {
  bool nowReachable = false;
  if (WiFiClass::status() == WL_CONNECTED && SERVER_BASE.length() > 0) {
    HTTPClient http;
    http.setTimeout(1500);
    http.begin(SERVER_BASE + "/api/status");
    int code = http.GET();
    http.end();
    nowReachable = (code == 200);
  }
  if (nowReachable != serverReachable) {
    serverReachable = nowReachable;
    Serial.printf("[DB] Reachable=%d\n", serverReachable);
    // Keep AuthSync's cached probe state in sync with the central timer so
    // both modules make decisions from the same reachability information.
    if (authSync) {
      authSync->setServerProbeResult(nowReachable, millis());
    }
  }
}

// Non-blocking timer callback for triggering AuthSync work.

void authSyncTimerCallback(TimerHandle_t xTimer) { authSyncRequested = true; }

// ----------- Network Task (core 0) ------------
void NetworkTask(void *pv) {
  Serial.printf("[Tasks] NetworkTask running on core %d\n", xPortGetCoreID());


  // Create and start the timer (5000ms period, auto-reload)
  if (!createServerCheckTimer(serverCheckTimerCallback, pdMS_TO_TICKS(5000))) {
    Serial.println("[Tasks] Failed to create/start server check timer");
  } else {
    Serial.println("[Tasks] Server check timer started");
  }

  // Create and start the auth sync timer (non-blocking callback)
  if (!createAuthSyncTimer(authSyncTimerCallback, pdMS_TO_TICKS(5000))) {
    Serial.println("[Tasks] Failed to create/start auth sync timer");
  } else {
    Serial.println("[Tasks] AuthSync timer started");
  }

  for (;;) {

    // AuthSync periodic sync — triggered by timer flag (non-blocking timer
    // callback)
    if (serverReachable && authSync && authSyncRequested) {
      authSyncRequested = false; // clear flag before doing work
      authSync->update();
      Serial.println("[Tasks] Auth sync requested");
    }

    // Drain scan queue: post last_scan events (limit per cycle)
    if (serverReachable && scanQueue) {
      for (int i = 0; i < 3;
           ++i) { // process up to 3 per loop to avoid starving
        ScanItem item;
        if (xQueueReceive(scanQueue, &item, 0) == pdPASS) {
          // Post scan to server and handle enrollment side-effects returned by
          // the server.
          Serial.printf("[Queue] Posting UID=%s\n", item.uid);
          DynamicJsonDocument resp = postLastScan(String(item.uid));
          Serial.printf("[Queue] postLastScan returned size=%u\n", (unsigned)resp.size());
           // If server acknowledged enrollment, clear enroll mode and redraw
           // indicator immediately
           if (resp.size() > 0) {
             bool enrolled = false;
             if  (resp.containsKey("enrolled")) {
               enrolled = resp["enrolled"].as<bool>();
             }
             if (enrolled) {
               enrollMode = "none";
               // Request main loop to redraw the enroll indicator (display
               // operations must run from loop context to be thread-safe).
               displayUpdateRequested = true;
               Serial.println("[Queue] Enrollment cleared (requested display update)");
             }
           }
         } else {
           break;
         }
      }
    } else if (!serverReachable && scanQueue) {
      // When offline, keep queued scans for later (do not drop them).
      // Optionally we could limit queue size elsewhere, but avoid clearing here.
    }

    vTaskDelay(pdMS_TO_TICKS(50));
  }
}
