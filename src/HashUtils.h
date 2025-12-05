//
// Created by fatta on 2025-12-01.
//

#ifndef HASHUTILS_H
#define HASHUTILS_H

#include <Arduino.h>
#include <cstdint>
#include <stddef.h>

namespace HashUtils {
    // Normalize (trim, uppercase) then return 64-bit FNV-1a hash of the input
    uint64_t hashUid(const String &s);
}

#endif
