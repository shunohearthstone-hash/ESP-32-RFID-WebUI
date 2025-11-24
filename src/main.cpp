#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <U8x8lib.h>
#include <ArduinoJson.h>
#include "AuthSync.h"
#include <LittleFS.h>
#include "ConfigManager.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>




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

// RFID pins
#define RST_PIN 17
#define SS_PIN  5
MFRC522 rfid(SS_PIN, RST_PIN);

// Display
U8X8_SSD1315_128X64_NONAME_SW_I2C u8x8(/* clock=*/ 22, /* data=*/ 21, /* reset=*/ U8X8_PIN_NONE);





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
AuthSync* authSync = nullptr;

// ----------------- State -----------------
String lastUID = "NONE";
String enrollMode = "none";
bool lastAuthorized = false;
uint64_t lastHash = 0;  // Last computed hash for display
bool serverReachable = false;  // Track server/database reachability
unsigned long lastDisplayUpdate = 0;
unsigned long enrollBlinkMillis = 0;
bool enrollBlinkState = false;
unsigned long lastServerCheck = 0;  // Last server status check time

// Display state tracking (to avoid unnecessary redraws)
String displayedUID = "";
bool displayedAuth = false;
uint64_t displayedHash = 0;
String displayedEnrollMode = "";
bool displayedEnrollBlink = false;
bool displayedServerReachable = false;

JsonDocument postLastScan(const String &uid);
String getUidString();
void updateEnrollStatus();
void updateDisplay();
void drawheader();
void drawEnrollIndicator(bool on);
void NetworkTask(void* pv);

// Queue for deferred network posting of scanned UIDs
struct ScanItem { char uid[21]; };
static QueueHandle_t scanQueue = nullptr;

// ----------------- SETUP -----------------
void setup() {
  Serial.begin(115200);
  delay(100);

  // Force first auth line to render even if initial authorization is false
  // by priming displayedAuth opposite of lastAuthorized.
  displayedAuth = !lastAuthorized;

  Wire.begin(21, 22);
  u8x8.begin();
  u8x8.setFont(u8x8_font_chroma48medium8_r);
  drawheader();
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
      u8x8.drawString(0, 2, "FS OK");
      // Create AuthSync early so we can load offline caches from NVS
      if (SERVER_BASE.length() > 0) {
        authSync = new AuthSync(SERVER_BASE);
        // Load cached allow/deny hashes only; defer network sync until WiFi is established
        authSync->preloadOffline();
        Serial.println("[AuthSync] Offline cache preloaded (no network yet)");
      } else {
        Serial.println("SERVER_BASE empty; offline authorization disabled until configured");
      }
    } /* -------------  If failing to flash config.json, run auto-provisioning    -------------
                        Replace  this placeholder with your desired network details
                        to have the device write a default config.json on first boot.
         ------------- ------------- ------------- ------------- ------------- -------------*/
    /*else {
      Serial.println("config.json missing -> auto-provisioning defaults");
      // One-time provisioning: write a default config, then reload.
      if (ConfigManager::saveConfig("SSID", "PASS", "SERVER_BASE")) {
        if (ConfigManager::loadConfig(SSID, PASS, SERVER_BASE)) {
          Serial.println("Provisioned default config.json");
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
    }
  }*/
 delay(100);  // Give some time for LittleFS to stabilize
  } 


  WiFi.begin(SSID.c_str(), PASS.c_str());
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 80) {
    delay(500); Serial.print("."); tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("");
    Serial.println("WiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    u8x8.drawString(0, 2, "WiFi OK     ");
    //Wifi modem sleep
    WiFi.setSleep(true);
    delay(100);

    // Attempt an online sync now that WiFi is connected (we already loaded offline cache)
    bool syncOk = false;
    if (authSync) {
      // Use public begin() to perform an immediate sync (reloads NVS + attempts server sync)
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
      Serial.println("[AuthSync] Using offline cache (sync failed or server unreachable)");
    }
  } else {
    u8x8.drawString(0, 2, "WiFi FAIL");
    serverReachable = false;
    displayedServerReachable = false;
  }
  delay(100);

  // Create queue and network task (pin to core 0)
  if (!scanQueue) {
    scanQueue = xQueueCreate(10, sizeof(ScanItem));
    if (scanQueue) {
      xTaskCreatePinnedToCore(NetworkTask, "net_task", 4096, nullptr, 1, nullptr, 0);
      Serial.println("[Tasks] Network task started on core 0");
    } else {
      Serial.println("[Tasks] Failed to create scanQueue");
    }
  }
}
void loop() {
  // Periodic server reachability check (every 5 seconds)
  if (millis() - lastServerCheck > 500) {
    bool nowReachable = false;
    if (WiFi.status() == WL_CONNECTED && SERVER_BASE.length() > 0) {
      // Quick check via status endpoint (lightweight)
      HTTPClient http;
      http.setTimeout(1000);
      http.begin(SERVER_BASE + "/api/status");
      int code = http.GET();
      http.end();
      nowReachable = (code == 200);
    }
    if (nowReachable != serverReachable) {
      serverReachable = nowReachable;
      if (serverReachable) {
        Serial.println("[DB] Server reachable");
      } else {
        Serial.println("[DB] Server unreachable - falling back to offline mode");
      }
      updateDisplay();  // Force display update on status change
    }
    lastServerCheck = millis();
  }
  
  // Enroll status now handled by NetworkTask (removed periodic HTTP here)

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid = getUidString();
    Serial.println("Scanned: " + uid);
    lastUID = uid;

    // Compute hash for display (same method as AuthSync) ----------- FOR DEBUGGING ----
    String normalized = uid;
    normalized.trim();
    normalized.toUpperCase();
    uint64_t hash = 0xcbf29ce484222325ULL;
    const uint64_t prime = 0x100000001b3ULL;
    for (size_t i = 0; i < normalized.length(); i++) {
      hash ^= (uint8_t)normalized[i];
      hash *= prime;
    }
    lastHash = hash;
    lastAuthorized = authSync ? authSync->isAuthorized(uid) : false;
    updateEnrollStatus();  // Refresh after scan
    updateDisplay();
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    vTaskDelay(40 / portTICK_PERIOD_MS); // Debounce recommended delay
    // Defer network POST of last scan to network task via queue
    if (scanQueue) {
      ScanItem item; memset(&item, 0, sizeof(item));
      strncpy(item.uid, uid.c_str(), sizeof(item.uid) - 1);
      if (xQueueSend(scanQueue, &item, 0) != pdPASS) {
        Serial.println("[Queue] scanQueue full; dropping UID post");
      }
    }

  
  }

  // Periodic sync handled by NetworkTask

  if (millis() - lastDisplayUpdate > 500) {  // Update display every 500ms
    updateDisplay();
    lastDisplayUpdate = millis();
  }

  // Blink indicator when waiting for enroll
  if (enrollMode != "none" && millis() - enrollBlinkMillis > 500) {
    enrollBlinkState = !enrollBlinkState;
    enrollBlinkMillis = millis();
    drawEnrollIndicator(enrollBlinkState);
  }
}


 //--------------------------------  helpers  ----------------------------------
String getUidString() {
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void drawheader() {
  static bool headerDrawn = false;
  if (!headerDrawn) {
    u8x8.clear();
    u8x8.drawString(0, 0, "RFID Access");
    headerDrawn = true;
  }
}

void updateDisplay() {
  drawheader();  // Only draws once
  
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
    if (line.length() > 16) line = line.substring(0, 16);
    // Pad with spaces to clear old text
    while (line.length() < 16) line += " ";
    u8x8.drawString(0, 1, line.c_str());
    displayedUID = lastUID;
  }
  
  // Only update auth status if changed
  if (lastAuthorized != displayedAuth) {
    u8x8.drawString(0, 4, (String("Auth:") + (lastAuthorized ? "YES" : "NO ")).c_str());
    displayedAuth = lastAuthorized;
  }
  
  // Update hash display (last 8 hex digits on bottom row)
  if (lastHash != displayedHash) {
    char hashStr[17];
    snprintf(hashStr, sizeof(hashStr), "H:%08X", (uint32_t)(lastHash & 0xFFFFFFFF));
    u8x8.drawString(0, 7, hashStr);
    displayedHash = lastHash;
  }
  
  
}

void drawEnrollIndicator(bool on) {
  String currentMode = enrollMode;
  bool currentBlink = on;
  
  // Only redraw if mode or blink state changed
  if (currentMode != displayedEnrollMode || currentBlink != displayedEnrollBlink) {
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

JsonDocument postLastScan(const String &uid) {
  // Guard: if we're offline or server not configured, return empty doc.
  // This avoids making invalid HTTP calls when no server_base is provided
  // (e.g. on first-boot before provisioning /config.json).
  if (WiFi.status() != WL_CONNECTED) return JsonDocument();
  if (SERVER_BASE.length() == 0) return JsonDocument();
  // Escape: if we already marked serverReachable false, skip HTTP entirely
  if (!serverReachable) {
    // Uncomment for verbose logging: Serial.println("[postLastScan] Skipped (serverReachable=false)");
    return JsonDocument();
  }
  HTTPClient http;
  http.setTimeout(1500); // shorter timeout to avoid long blocking
  http.begin(String(SERVER_BASE) + "/api/last_scan");
  http.addHeader("Content-Type", "application/json");
  String body = "{\"uid\":\"" + uid + "\"}";
  int code = http.POST(body);
  if (code < 200 || code >= 300) { 
    Serial.printf("postLastScan failed: %d\n", code);
    http.end(); 
    return JsonDocument(); 
  }
  String payload = http.getString();
  http.end();
  JsonDocument doc;
  deserializeJson(doc, payload);
  return doc;
}

void updateEnrollStatus() {
  // Skip poll if offline or no server configured. Keeps display consistent
  // and avoids pointless HTTP requests when not provisioned.
  if (WiFi.status() != WL_CONNECTED) { enrollMode = "none"; return; }
  if (SERVER_BASE.length() == 0) { enrollMode = "none"; return; }
  // Escape: rely on periodic reachability check; if server currently unreachable, keep last mode
  if (!serverReachable) { return; }
  HTTPClient http;
  http.setTimeout(1500);
  http.begin(String(SERVER_BASE) + "/api/status");
  int code = http.GET();
  if (code == 200) {
    String payload = http.getString();
    JsonDocument doc;
    deserializeJson(doc, payload);
    const char* m = doc["enroll_mode"] | "";
    enrollMode = (m && strlen(m)) ? String(m) : "none";
  }
  http.end();
}

// ----------- Network Task (core 0) ------------
void NetworkTask(void* pv) {
  Serial.printf("[Tasks] NetworkTask running on core %d\n", xPortGetCoreID());
  unsigned long lastServerCheckLocal = 0;
  unsigned long lastEnrollPoll = 0;
  for (;;) {
    // Periodic server reachability (every 5s)
    if (millis() - lastServerCheckLocal > 5000) {
      bool nowReachable = false;
      if (WiFi.status() == WL_CONNECTED && SERVER_BASE.length() > 0) {
        HTTPClient http;
        http.setTimeout(800);
        http.begin(SERVER_BASE + "/api/status");
        int code = http.GET();
        http.end();
        nowReachable = (code == 200);
      }
      if (nowReachable != serverReachable) {
        serverReachable = nowReachable;
        Serial.printf("[DB] Reachable=%d\n", serverReachable);
      }
      lastServerCheckLocal = millis();
    }

    // Enroll status poll (500ms) only if reachable
    if (serverReachable && (millis() - lastEnrollPoll > 1000)) {
      updateEnrollStatus();
      lastEnrollPoll = millis();
    }

    // AuthSync periodic sync
    if (serverReachable && authSync) {
      authSync->update();
    }

    // Drain scan queue: post last_scan events (limit per cycle)
    if (serverReachable && scanQueue) {
      for (int i=0; i<3; ++i) { // process up to 3 per loop to avoid starving
        ScanItem item;
        if (xQueueReceive(scanQueue, &item, 0) == pdPASS) {
          postLastScan(String(item.uid));
        } else {
          break;
        }
      }
    } else if (!serverReachable && scanQueue) {
      // Optionally clear queue to avoid growth while offline
      ScanItem dummy;
      while (xQueueReceive(scanQueue, &dummy, 0) == pdPASS) {
        // dropped silently
      }
    }

    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

