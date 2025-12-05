#include "HashUtils.h"

static uint64_t fnv1a64_bytes(const uint8_t* data, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    const uint64_t prime = 0x100000001b3ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= prime;
    }
    return hash;
}

namespace HashUtils {
    uint64_t hashUid(const String &s) {
        String t = s;
        t.trim();
        t.toUpperCase();
        return fnv1a64_bytes(reinterpret_cast<const uint8_t*>(t.c_str()), t.length());
    }
}//
// Created by fatta on 2025-12-01.
//