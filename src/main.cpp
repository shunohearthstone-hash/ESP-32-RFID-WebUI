#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <U8x8lib.h>
#include <ArduinoJson.h>
#include "AuthSync.h"

// RFID pins
#define RST_PIN 17
#define SS_PIN  5
MFRC522 rfid(SS_PIN, RST_PIN);

// Display
U8X8_SSD1315_128X64_NONAME_SW_I2C u8x8(/* clock=*/ 22, /* data=*/ 21, /* reset=*/ U8X8_PIN_NONE);

// ----------------- CONFIG -----------------
const char* SSID = "Rasmus 2.4 GHz";
const char* PASS = "Frt56789!";
const char* SERVER_BASE = "http://192.168.1.32:5000";

// Authorization sync
AuthSync authSync(SERVER_BASE);

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

  WiFi.begin(SSID, PASS);
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 80) {
    delay(500); Serial.print("."); tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi connected: " + WiFi.localIP().toString());
    u8x8.drawString(0, 2, "WiFi OK");
    authSync.begin();  // Initial sync
  } else {
    u8x8.drawString(0, 2, "WiFi FAIL");
  }
  delay(1000);
  
}

// ----------------- MAIN LOOP -----------------
void loop() {
  // Check enroll status more frequently to show indicator quickly
  static unsigned long lastEnrollCheck = 0;
  if (millis() - lastEnrollCheck > 500) {  // Check every 500ms
    updateEnrollStatus();
    lastEnrollCheck = millis();
  }

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid = getUidString();
    Serial.println("Scanned: " + uid);
    lastUID = uid;

    JsonDocument resp = postLastScan(uid);
    bool enrolled = resp["enrolled"] | false;

    lastAuthorized = authSync.isAuthorized(uid);
    updateEnrollStatus();  // Refresh after scan
    updateDisplay();
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(400);
  }

  authSync.update();  // Periodic sync check

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
  if (WiFi.status() != WL_CONNECTED) return JsonDocument();
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
  if (WiFi.status() != WL_CONNECTED) { enrollMode = "none"; return; }
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