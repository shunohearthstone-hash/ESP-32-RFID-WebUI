#include "ConfigManager.h"
#include <ArduinoJson.h>
// ConfigManager
// -------------
// Small helper for reading and writing the device's JSON configuration
// from LittleFS (/config.json). It loads WiFi SSID/password and the
// server base URL on boot, and can persist updated settings back to
// flash. All methods are static so you don't need to instantiate it.
const char* ConfigManager::CONFIG_FILE = "/config.json";

// loadConfig
// ----------
// Reads /config.json from LittleFS and parses it using ArduinoJson.
// On success, fills the provided ssid/pass/serverBase references with
// values from the file (falling back to their existing contents if a
// field is missing) and returns true. Returns false if the file is
// missing or JSON parsing fails.
bool ConfigManager::loadConfig(String& ssid, String& pass, String& serverBase) {
    String json = readConfigJson();
    if (json.length() == 0) return false;
    
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, json);
    if (err) {
        Serial.printf("Config parse error: %s\n", err.c_str());
        return false;
    }
    
    ssid = String(doc["ssid"] | ssid.c_str());
    pass = String(doc["password"] | pass.c_str());
    serverBase = String(doc["server_base"] | serverBase.c_str());
    
    return true;
}

// saveConfig
// ----------
// Serializes the given ssid/password/serverBase values into JSON and
// writes them to /config.json in LittleFS. Returns true on successful
// write, false if the file can't be opened or the JSON can't be
// serialized to disk.
bool ConfigManager::saveConfig(const String& ssid, const String& pass, const String& serverBase) {
    JsonDocument doc;
    doc["ssid"] = ssid;
    doc["password"] = pass;
    doc["server_base"] = serverBase;
    
    File f = LittleFS.open(CONFIG_FILE, "w");
    if (!f) {
        Serial.println("Failed to open config file for writing");
        return false;
    }
    
    if (serializeJson(doc, f) == 0) {
        f.close();
        Serial.println("Failed to write config JSON");
        return false;
    }
    
    f.close();
    return true;
}

// readConfigJson
// --------------
// Low-level helper that opens /config.json from LittleFS and returns
// its entire contents as a String. If the file doesn't exist or can't
// be opened, logs an error and returns an empty String.
String ConfigManager::readConfigJson() {
    File f = LittleFS.open(CONFIG_FILE, "r");
    if (!f) {
        Serial.println("Config file not found");
        return String();
    }
    
    size_t size = f.size();
    String contents;
    contents.reserve(size + 1);
    
    while (f.available()) {
        contents += (char)f.read();
    }
    
    f.close();
    return contents;
}

// listFiles
// ---------
// Debug utility that lists all files currently stored in LittleFS,
// printing each name and size to the serial console. Useful for
// verifying that /config.json and other assets are present on flash.
void ConfigManager::listFiles() {
    File root = LittleFS.open("/");
    if (!root) {
        Serial.println("LittleFS root open failed");
        return;
    }
    
    Serial.println("LittleFS contents:");
    File f = root.openNextFile();
    
    if (!f) {
        Serial.println("  (empty)");
    }
    
    while (f) {
        Serial.printf("  %s (%u bytes)\n", f.name(), (unsigned)f.size());
        f = root.openNextFile();
    }
}
