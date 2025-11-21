#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <U8x8lib.h>
#include <ArduinoJson.h>
#include "AuthSync.h"
#include <LittleFS.h>

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
unsigned long lastDisplayUpdate = 0;
unsigned long enrollBlinkMillis = 0;
bool enrollBlinkState = false;

// Display state tracking (to avoid unnecessary redraws)
String displayedUID = "";
bool displayedAuth = false;
String displayedEnrollMode = "";
bool displayedEnrollBlink = false;

JsonDocument postLastScan(const String &uid);
String getUidString();
void updateEnrollStatus();
void updateDisplay();
void drawheader();
void drawEnrollIndicator(bool on);

// LittleFS helpers (implemented at the bottom of this file)
// - saveConfigToLittleFS: write a JSON object to /config.json
// - readConfigJsonString: return the raw JSON string stored on LittleFS
// - loadConfigFromLittleFS: parse the JSON and populate runtime variables
bool saveConfigToLittleFS(const String &ssid, const String &pass, const String &server_base);
String readConfigJsonString();
bool loadConfigFromLittleFS();

// ----------------- SETUP -----------------
void setup() {
  Serial.begin(115200);
  delay(100);

  Wire.begin(21, 22);
  u8x8.begin();
  u8x8.setFont(u8x8_font_chroma48medium8_r);
  drawheader();
  u8x8.drawString(0, 2, "Init...");

  SPI.begin();
  rfid.PCD_Init();

  // Mount LittleFS and attempt to load config.json (optional)
  if (LittleFS.begin()) {
    if (loadConfigFromLittleFS()) {
      Serial.println("Config loaded from LittleFS");
    } else {
      Serial.println("No config.json found on LittleFS, using defaults");
    }
  } else {
    Serial.println("LittleFS mount failed");
  }

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
    Serial.println("\nWiFi connected: " + WiFi.localIP().toString());
    u8x8.drawString(0, 2, "WiFi OK");
    if (authSync) authSync->begin();  // Initial sync
  } else {
    u8x8.drawString(0, 2, "WiFi FAIL");
  }
  delay(1000);
  
}

// ----------------- MAIN LOOP -----------------
void loop() {
  
  static unsigned long lastEnrollCheck = 0;
  if (millis() - lastEnrollCheck > 500) {  // Refresh every 500ms
    updateEnrollStatus();
    lastEnrollCheck = millis();
  }

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid = getUidString();
    Serial.println("Scanned: " + uid);
    lastUID = uid;

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

// ---------------- LittleFS config helpers ----------------
bool saveConfigToLittleFS(const String &ssid, const String &pass, const String &server_base) {
  if (!LittleFS.begin()) return false;
  DynamicJsonDocument doc(512);
  doc["ssid"] = ssid;
  doc["password"] = pass;
  doc["server_base"] = server_base;
  File f = LittleFS.open("/config.json", "w");
  if (!f) return false;
  if (serializeJson(doc, f) == 0) {
    f.close();
    return false;
  }
  f.close();
  return true;
}

String readConfigJsonString() {
  if (!LittleFS.begin()) return String();
  File f = LittleFS.open("/config.json", "r");
  if (!f) return String();
  size_t sz = f.size();
  String contents;
  contents.reserve(sz + 1);
  while (f.available()) {
    contents += (char)f.read();
  }
  f.close();
  return contents;
}

bool loadConfigFromLittleFS() {
  String json = readConfigJsonString();
  if (json.length() == 0) return false;
  DynamicJsonDocument doc(1024);
  DeserializationError err = deserializeJson(doc, json);
  if (err) return false;
  SSID = String(doc["ssid"] | SSID.c_str());
  PASS = String(doc["password"] | PASS.c_str());
  SERVER_BASE = String(doc["server_base"] | SERVER_BASE.c_str());
  return true;
}