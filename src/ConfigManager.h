#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <Arduino.h>
#include <LittleFS.h>

class ConfigManager {
public:
    // Load configuration from LittleFS
    static bool loadConfig(String& ssid, String& pass, String& serverBase);
    
    // Save configuration to LittleFS
    static bool saveConfig(const String& ssid, const String& pass, const String& serverBase);
    
    // Read raw JSON string from config file
    static String readConfigJson();
    
    // List all files on LittleFS (debug helper)
    static void listFiles();
    
private:
    static const char* CONFIG_FILE;
};

#endif
