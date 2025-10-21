// ESP32_RFID_u8x8.ino
#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <U8g2lib.h>
#include <ArduinoJson.h>

// ----------------- CONFIG -----------------
const char* SSID = "YOUR_WIFI";
const char* PASS = "YOUR_PASS";
const char* SERVER_BASE = "http://192.168.1.100:5000"; // change to your Flask server IP

// RFID (SPI) pins
#define RST_PIN    4
#define SS_PIN     5
MFRC522 rfid(SS_PIN, RST_PIN);

// u8x8 (SSD1306 I2C text-only) constructor
// If your display is 128x64 SSD1306 on I2C (0x3C), this works:
// U8X8_R0 rotation, reset pin none (U8X8_PIN_NONE)
U8X8_SSD1306_128X64_NONAME_1_HW_I2C u8x8(U8X8_R0, /* reset=*/ U8X8_PIN_NONE);

// small helpers
String lastUID = "NONE";
String enrollMode = "none"; // "grant" | "revoke" | "none"
bool lastAuthorized = false;
unsigned long lastDisplayUpdate = 0;
unsigned long enrollBlinkMillis = 0;
bool enrollBlinkState = false;

// ----------------- SETUP -----------------
void setup() {
  Serial.begin(115200);
  delay(100);

  // init display
  Wire.begin(21, 22); // SDA=21, SCL=22
  u8x8.begin();
  u8x8.setFont(u8x8_font_chroma48medium8_r); // reasonably readable small font
  displayInit();

  // init SPI / RFID
  SPI.begin(); // SCK=18, MOSI=23, MISO=19 (hardware SPI defaults)
  rfid.PCD_Init();
  Serial.println("MFRC522 initialized");

  // connect WiFi
  WiFi.begin(SSID, PASS);
  u8x8.drawString(0,1,"WiFi: connecting");
  Serial.print("Connecting WiFi");
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 60) {
    delay(500);
    Serial.print(".");
    tries++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi connected: " + WiFi.localIP().toString());
    u8x8.clear();
    displayStatus("WiFi OK");
  } else {
    Serial.println("\nWiFi failed");
    displayStatus("WiFi FAILED");
  }
  delay(500);
}

// ----------------- MAIN LOOP -----------------
void loop() {
  // handle RFID scans
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid = getUidString();
    Serial.println("Scanned: " + uid);
    lastUID = uid;

    // report to server (this will perform enroll action if server is in enroll mode)
    DynamicJsonDocument resp = postLastScan(uid);

    if (!resp.isNull()) {
      // server returns {"ok":true,"enrolled":true/false,...} per our API
      bool enrolled = resp["enrolled"] | false;
      if (enrolled) {
        // server applied enroll action (grant/revoke) already
        // show quick feedback: authorized if later GET returns true
        delay(150); // let server settle & rebuild bloom (server does this)
        lastAuthorized = checkAuthorized(uid);
      } else {
        // not enrolled; just check current authorized status
        lastAuthorized = checkAuthorized(uid);
      }
      // update enroll mode too by querying /api/status
      updateEnrollStatus();
    } else {
      // fallback: just check locally via GET
      lastAuthorized = checkAuthorized(uid);
      updateEnrollStatus();
    }

    // update display & small delay
    updateDisplay();
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(400); // debounce
  }

  // periodic status refresh every 5s
  if (millis() - lastDisplayUpdate > 5000) {
    updateEnrollStatus(); // refresh enroll state
    updateDisplay();
    lastDisplayUpdate = millis();
  }

  // handle enroll blink (visual feedback)
  if (enrollMode == "grant" || enrollMode == "revoke") {
    if (millis() - enrollBlinkMillis > 500) {
      enrollBlinkState = !enrollBlinkState;
      enrollBlinkMillis = millis();
      // redraw small indicator
      drawEnrollIndicator(enrollBlinkState);
    }
  }
}

// ----------------- HELPERS -----------------

String getUidString() {
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void displayInit() {
  u8x8.clear();
  u8x8.setContrast(255);
  u8x8.drawString(0,0,"RFID Access");
  u8x8.drawString(0,2,"Init...");
}

void displayStatus(const char* s) {
  u8x8.clear();
  u8x8.drawString(0,0,"RFID Access");
  u8x8.drawString(0,2,s);
}

void updateDisplay() {
  u8x8.clear();
  u8x8.drawString(0,0,"RFID Access");
  // line 1: UID (truncate to 16 chars if necessary)
  String uidLine = "UID:";
  uidLine += lastUID;
  if (uidLine.length() > 16) uidLine = uidLine.substring(0,16);
  u8x8.drawString(0,1, uidLine.c_str());

  // line 2: Auth status
  String a = lastAuthorized ? "YES" : "NO ";
  u8x8.drawString(0,3, ("Auth:" + a).c_str());

  // line 3: enroll mode
  String em = enrollMode;
  if (em.length() == 0) em = "none";
  u8x8.drawString(0,4, ("Enroll:" + em).c_str());

  // small helper status on last line
  u8x8.drawString(0,6, "Press 'Grant' on UI");
  // draw indicator if in enroll mode
  drawEnrollIndicator(true);
}

void drawEnrollIndicator(bool on) {
  // indicator at top-right: a small ">" if waiting
  if (enrollMode == "grant" || enrollMode == "revoke") {
    if (on) {
      u8x8.drawString(14,0, (enrollMode == "grant") ? "GR" : "RV");
    } else {
      // erase by writing spaces
      u8x8.drawString(14,0,"  ");
    }
  } else {
    u8x8.drawString(14,0,"  ");
  }
}

// POST /api/last_scan { uid: "..." }
DynamicJsonDocument postLastScan(const String &uid) {
  if (WiFi.status() != WL_CONNECTED) return DynamicJsonDocument(1);
  HTTPClient http;
  String url = String(SERVER_BASE) + "/api/last_scan";
  http.begin(url);
  http.addHeader("Content-Type","application/json");
  String body = "{\"uid\":\"" + uid + "\"}";
  int code = http.POST(body);
  if (code != 200 && code != 201 && code != 202) {
    Serial.printf("POST last_scan failed: %d\n", code);
    http.end();
    return DynamicJsonDocument(1);
  }
  String resp = http.getString();
  http.end();
  DynamicJsonDocument doc(256);
  DeserializationError err = deserializeJson(doc, resp);
  if (err) {
    Serial.println("JSON parse failed");
    return DynamicJsonDocument(1);
  }
  return doc;
}

// GET /api/cards/<uid> -> {exists:true, authorized:bool}
bool checkAuthorized(const String &uid) {
  if (WiFi.status() != WL_CONNECTED) return false;
  HTTPClient http;
  String url = String(SERVER_BASE) + "/api/cards/" + uid;
  http.begin(url);
  int code = http.GET();
  bool auth = false;
  if (code == 200) {
    String resp = http.getString();
    DynamicJsonDocument doc(128);
    if (!deserializeJson(doc, resp)) {
      if (doc.containsKey("authorized")) auth = doc["authorized"];
    }
  } else {
    // not found or error -> treat as unauthorized
    auth = false;
  }
  http.end();
  return auth;
}

// GET /api/status -> { last_scanned, enroll_mode }
void updateEnrollStatus() {
  if (WiFi.status() != WL_CONNECTED) {
    enrollMode = "none";
    return;
  }
  HTTPClient http;
  String url = String(SERVER_BASE) + "/api/status";
  http.begin(url);
  int code = http.GET();
  if (code == 200) {
    String resp = http.getString();
    DynamicJsonDocument doc(256);
    if (!deserializeJson(doc, resp)) {
      if (doc.containsKey("enroll_mode")) {
        String m = String((const char*)doc["enroll_mode"]);
        if (m == "null" || m.length() == 0) enrollMode = "none";
        else enrollMode = m;
      } else {
        enrollMode = "none";
      }
      if (doc.containsKey("last_scanned")) {
        String ls = String((const char*)doc["last_scanned"]);
        if (ls.length()) lastUID = ls;
      }
    }
  } else {
    enrollMode = "none";
  }
  http.end();
}
