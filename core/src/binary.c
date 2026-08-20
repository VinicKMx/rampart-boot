#include "binary.h"

bool rampart_binary_bytes_equal(const uint8_t *left, const uint8_t *right, size_t len) {
    size_t index = 0u;

    if ((left == NULL) || (right == NULL)) {
        return false;
    }

    for (index = 0u; index < len; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }

    return true;
}

bool rampart_binary_bytes_match(const uint8_t *left, const char *right, size_t len) {
    size_t index = 0u;

    if ((left == NULL) || (right == NULL)) {
        return false;
    }

    for (index = 0u; index < len; ++index) {
        if (left[index] != (uint8_t)right[index]) {
            return false;
        }
    }

    return true;
}

bool rampart_binary_all_zeroes(const uint8_t *bytes, size_t len) {
    size_t index = 0u;

    if (bytes == NULL) {
        return false;
    }

    for (index = 0u; index < len; ++index) {
        if (bytes[index] != 0u) {
            return false;
        }
    }

    return true;
}

bool rampart_binary_range_available(size_t offset, size_t len, size_t total_len, size_t *end) {
    if (offset > total_len) {
        return false;
    }

    if (len > (total_len - offset)) {
        return false;
    }

    if (end != NULL) {
        *end = offset + len;
    }

    return true;
}

rampart_status_t rampart_binary_checked_add_size(size_t left, size_t right, size_t *out) {
    if (out == NULL) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (right > (SIZE_MAX - left)) {
        return RAMPART_ERR_OVERFLOW;
    }

    *out = left + right;
    return RAMPART_OK;
}

rampart_status_t rampart_binary_read_u16_le(const uint8_t *bytes, size_t len, size_t offset,
                                            uint16_t *out) {
    if ((bytes == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (!rampart_binary_range_available(offset, 2u, len, NULL)) {
        return RAMPART_ERR_BOUNDS;
    }

    *out = (uint16_t)((uint16_t)bytes[offset] | ((uint16_t)bytes[offset + 1u] << 8u));
    return RAMPART_OK;
}

rampart_status_t rampart_binary_read_u32_le(const uint8_t *bytes, size_t len, size_t offset,
                                            uint32_t *out) {
    if ((bytes == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (!rampart_binary_range_available(offset, 4u, len, NULL)) {
        return RAMPART_ERR_BOUNDS;
    }

    *out = ((uint32_t)bytes[offset]) | ((uint32_t)bytes[offset + 1u] << 8u) |
           ((uint32_t)bytes[offset + 2u] << 16u) | ((uint32_t)bytes[offset + 3u] << 24u);
    return RAMPART_OK;
}
