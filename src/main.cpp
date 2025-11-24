#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <U8x8lib.h>
#include <ArduinoJson.h>
#include "AuthSync.h"
#include <LittleFS.h>
#include <AsyncTelnetSerial.h>
#include <HardwareSerial.h>
#include "ConfigManager.h"




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

// Telnet server for wireless serial monitoring
AsyncTelnetSerial telnet(&Serial);



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

// ----------------- SETUP -----------------
void setup() {
  Serial.begin(115200);
  delay(100);

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
    } /* -------------  If failing to flash config.json, run auto-provisioning    -------------
                        Replace  this placeholder with your desired network details
                        to have the device write a default config.json on first boot.
         ------------- ------------- ------------- ------------- ------------- -------------
    else {
      Serial.println("config.json missing -> auto-provisioning defaults");
      // One-time provisioning: write a default config, then reload.
      /*if (ConfigManager::saveConfig("SSID", "PASS", "http://SERVER_BASE")) {
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
    LittleFS.format();*/
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
  }
 delay(100);  // Give some time for LittleFS to stabilize
    
    // Create AuthSync now that SERVER_BASE is known (only if configured)
  if (authSync) { delete authSync; authSync = nullptr; }
  if (SERVER_BASE.length() > 0) {
    authSync = new AuthSync(SERVER_BASE);
  } else {
    Serial.println("SERVER_BASE not configured; skipping AuthSync creation");
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

    if (telnet.begin(115200, true, false)) {
      Serial.println("Telnet server started on port 23");
      Serial.print("Connect via: telnet ");
      Serial.println(WiFi.localIP());
      
      // Add connection callback to see when clients connect
      telnet.onConnect([](void*, AsyncClient* client) {
        Serial.println("[Telnet] Client connected from " + client->remoteIP().toString());
        client->write("=== ESP32 RFID System ===\r\n");
        client->write("Telnet session active\r\n\r\n");
      });
      
      telnet.onDisconnect([](AsyncClient* client) {
        Serial.println("[Telnet] Client disconnected");
      });
      
      
    } else {
      Serial.println("Telnet server failed to start");
    }
    
    
    if (authSync && authSync->begin()) {  // Initial sync attempt
      u8x8.drawString(0, 2, "DB OK");
      serverReachable = true;
      displayedServerReachable = true;
    } else {
      u8x8.drawString(0, 2, "DB FAIL");
      serverReachable = false;
      displayedServerReachable = false;
    }
  } else {
    u8x8.drawString(0, 2, "WiFi FAIL");
    serverReachable = false;
    displayedServerReachable = false;
  }
  delay(100);
  
}
void loop() {
  // Periodic server reachability check (every 5 seconds)
  if (millis() - lastServerCheck > 5000) {
    bool nowReachable = false;
    if (WiFi.status() == WL_CONNECTED && SERVER_BASE.length() > 0) {
      // Quick check via status endpoint (lightweight)
      HTTPClient http;
      http.setTimeout(2000);
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
  
  static unsigned long lastEnrollCheck = 0;
  if (millis() - lastEnrollCheck > 500) {  // Refresh every 500ms
    updateEnrollStatus();
    lastEnrollCheck = millis();
  }

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

    JsonDocument resp = postLastScan(uid);
    bool enrolled = resp["enrolled"] | false;

  lastAuthorized = authSync ? authSync->isAuthorized(uid) : false;
    updateEnrollStatus();  // Refresh after scan
    updateDisplay();
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(400);
  }

  if (authSync) authSync->update();  // Periodic sync check

  if (millis() - lastDisplayUpdate > 5000) {
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

// Periodic sync check
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
      u8x8.drawString(0, 2, "DB OK        ");
    } else {
      u8x8.drawString(0, 2, "DB LOST      ");
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
    u8x8.drawString(0, 3, (String("Auth:") + (lastAuthorized ? "YES" : "NO ")).c_str());
    displayedAuth = lastAuthorized;
  }
  
  // Update hash display (last 8 hex digits on bottom row)
  if (lastHash != displayedHash) {
    char hashStr[17];
    snprintf(hashStr, sizeof(hashStr), "H:%08X", (uint32_t)(lastHash & 0xFFFFFFFF));
    u8x8.drawString(0, 7, hashStr);
    displayedHash = lastHash;
  }
  
  // Enroll indicator handled separately in drawEnrollIndicator
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
  HTTPClient http;
  http.setTimeout(5000);
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
  HTTPClient http;
  http.setTimeout(5000);
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

