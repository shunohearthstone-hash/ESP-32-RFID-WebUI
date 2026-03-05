//
// Created by fatta on 2025-12-01.
//
#pragma once



namespace HashUtils {
    // Normalize (trim, uppercase) then return 64-bit FNV-1a hash of the input
    uint64_t hashUid(const String &s);
}


