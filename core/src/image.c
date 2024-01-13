#include "rampart/image.h"

#include <stdbool.h>

static bool bytes_equal(const uint8_t *left, const uint8_t *right, size_t len) {
    size_t index = 0u;

    for (index = 0u; index < len; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }

    return true;
}

static bool bytes_match(const uint8_t *left, const char *right, size_t len) {
    size_t index = 0u;

    for (index = 0u; index < len; ++index) {
        if (left[index] != (uint8_t)right[index]) {
            return false;
        }
    }

    return true;
}

static bool all_zeroes(const uint8_t *bytes, size_t len) {
    size_t index = 0u;

    for (index = 0u; index < len; ++index) {
        if (bytes[index] != 0u) {
            return false;
        }
    }

    return true;
}

static rampart_status_t checked_add_size(size_t left, size_t right, size_t *out) {
    if (out == NULL) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (right > (SIZE_MAX - left)) {
        return RAMPART_ERR_OVERFLOW;
    }

    *out = left + right;
    return RAMPART_OK;
}

static bool range_available(size_t offset, size_t len, size_t total_len, size_t *end) {
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

static rampart_status_t read_u16_le(const uint8_t *bytes, size_t len, size_t offset,
                                    uint16_t *out) {
    size_t end = 0u;

    if ((bytes == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (!range_available(offset, 2u, len, &end)) {
        return RAMPART_ERR_BOUNDS;
    }

    (void)end;
    *out = (uint16_t)((uint16_t)bytes[offset] | ((uint16_t)bytes[offset + 1u] << 8u));
    return RAMPART_OK;
}

static rampart_status_t read_u32_le(const uint8_t *bytes, size_t len, size_t offset,
                                    uint32_t *out) {
    size_t end = 0u;

    if ((bytes == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (!range_available(offset, 4u, len, &end)) {
        return RAMPART_ERR_BOUNDS;
    }

    (void)end;
    *out = ((uint32_t)bytes[offset]) | ((uint32_t)bytes[offset + 1u] << 8u) |
           ((uint32_t)bytes[offset + 2u] << 16u) | ((uint32_t)bytes[offset + 3u] << 24u);
    return RAMPART_OK;
}

static rampart_status_t require_u16(const uint8_t *bytes, size_t len, size_t offset,
                                    uint16_t expected) {
    uint16_t actual = 0u;
    rampart_status_t status = read_u16_le(bytes, len, offset, &actual);

    if (status != RAMPART_OK) {
        return status;
    }

    if (actual != expected) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    return RAMPART_OK;
}

static rampart_status_t require_u32(const uint8_t *bytes, size_t len, size_t offset,
                                    uint32_t expected) {
    uint32_t actual = 0u;
    rampart_status_t status = read_u32_le(bytes, len, offset, &actual);

    if (status != RAMPART_OK) {
        return status;
    }

    if (actual != expected) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    return RAMPART_OK;
}

static rampart_status_t validate_signature_section(const uint8_t *bytes, size_t len,
                                                   size_t signed_region_offset,
                                                   size_t signed_region_size,
                                                   const struct rampart_manifest_view *manifest,
                                                   struct rampart_signature_view *out) {
    const size_t record_offset = 32u;
    const size_t record_padding_offset = record_offset + 145u;
    const uint8_t *key_id = NULL;
    const uint8_t *signature = NULL;
    const uint8_t *public_key = NULL;
    rampart_status_t status = RAMPART_OK;

    if ((bytes == NULL) || (manifest == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (len != RAMPART_SIGNATURE_SECTION_SIZE_V1) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    if (!bytes_match(bytes, "RPSIGN01", 8u)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status = require_u16(bytes, len, 8u, 1u);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, 10u, 32u);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u32(bytes, len, 12u, (uint32_t)RAMPART_SIGNATURE_SECTION_SIZE_V1);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u32(bytes, len, 16u, (uint32_t)signed_region_offset);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u32(bytes, len, 20u, (uint32_t)signed_region_size);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, 24u, 1u);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, 26u, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, 28u, 160u);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, 30u, 0u);
    if (status != RAMPART_OK) {
        return status;
    }

    key_id = &bytes[record_offset];
    if (!bytes_equal(key_id, manifest->key_id, RAMPART_KEY_ID_SIZE)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status =
        require_u16(bytes, len, record_offset + 8u, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, record_offset + 10u, 1u);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, record_offset + 12u, RAMPART_SIGNATURE_ECDSA_P256_SIZE);
    if (status != RAMPART_OK) {
        return status;
    }
    status = require_u16(bytes, len, record_offset + 14u, RAMPART_PUBLIC_KEY_P256_SEC1_SIZE);
    if (status != RAMPART_OK) {
        return status;
    }

    signature = &bytes[record_offset + 16u];
    public_key = &bytes[record_offset + 80u];

    if (public_key[0] != 0x04u) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    if (!all_zeroes(&bytes[record_padding_offset], len - record_padding_offset)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    out->key_id = key_id;
    out->key_id_len = RAMPART_SIGNATURE_KEY_ID_SIZE;
    out->signature_algorithm = RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256;
    out->signature = signature;
    out->signature_len = RAMPART_SIGNATURE_ECDSA_P256_SIZE;
    out->public_key = public_key;
    out->public_key_len = RAMPART_PUBLIC_KEY_P256_SEC1_SIZE;

    return RAMPART_OK;
}

rampart_status_t rampart_image_parse(const uint8_t *bytes, size_t len,
                                     struct rampart_image_view *out) {
    struct rampart_image_view parsed = {0};
    uint16_t image_version = 0u;
    uint16_t image_kind = 0u;
    uint16_t header_size = 0u;
    uint16_t flags = 0u;
    uint32_t manifest_offset_u32 = 0u;
    uint32_t manifest_size_u32 = 0u;
    uint32_t payload_offset_u32 = 0u;
    uint32_t payload_size_u32 = 0u;
    uint32_t signature_offset_u32 = 0u;
    uint32_t signature_size_u32 = 0u;
    uint32_t signed_region_offset_u32 = 0u;
    uint32_t signed_region_size_u32 = 0u;
    size_t expected_payload_offset = 0u;
    size_t expected_signature_offset = 0u;
    size_t expected_file_len = 0u;
    size_t expected_signed_region_size = 0u;
    rampart_status_t status = RAMPART_OK;

    if ((bytes == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (len < RAMPART_IMAGE_HEADER_SIZE) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    if (!bytes_match(bytes, "RMPIMG01", 8u)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status = read_u16_le(bytes, len, 8u, &image_version);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u16_le(bytes, len, 10u, &image_kind);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u16_le(bytes, len, 12u, &header_size);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u16_le(bytes, len, 14u, &flags);
    if (status != RAMPART_OK) {
        return status;
    }

    if ((image_version != RAMPART_IMAGE_FORMAT_VERSION_1) ||
        (image_kind != RAMPART_IMAGE_KIND_FIRMWARE) || (header_size != RAMPART_IMAGE_HEADER_SIZE) ||
        (flags != 0u)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status = read_u32_le(bytes, len, 16u, &manifest_offset_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 20u, &manifest_size_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 24u, &payload_offset_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 28u, &payload_size_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 32u, &signature_offset_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 36u, &signature_size_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 40u, &signed_region_offset_u32);
    if (status != RAMPART_OK) {
        return status;
    }
    status = read_u32_le(bytes, len, 44u, &signed_region_size_u32);
    if (status != RAMPART_OK) {
        return status;
    }

    if (!all_zeroes(&bytes[48u], RAMPART_IMAGE_HEADER_SIZE - 48u)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    parsed.bytes = bytes;
    parsed.len = len;
    parsed.manifest_offset = (size_t)manifest_offset_u32;
    parsed.manifest_size = (size_t)manifest_size_u32;
    parsed.payload_offset = (size_t)payload_offset_u32;
    parsed.payload_size = (size_t)payload_size_u32;
    parsed.signature_offset = (size_t)signature_offset_u32;
    parsed.signature_size = (size_t)signature_size_u32;
    parsed.signed_region_offset = (size_t)signed_region_offset_u32;
    parsed.signed_region_size = (size_t)signed_region_size_u32;

    if (parsed.manifest_offset != RAMPART_IMAGE_HEADER_SIZE) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status =
        checked_add_size(parsed.manifest_offset, parsed.manifest_size, &expected_payload_offset);
    if (status != RAMPART_OK) {
        return status;
    }
    if (parsed.payload_offset != expected_payload_offset) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status =
        checked_add_size(parsed.payload_offset, parsed.payload_size, &expected_signature_offset);
    if (status != RAMPART_OK) {
        return status;
    }
    if (parsed.signature_offset != expected_signature_offset) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status = checked_add_size(parsed.signature_offset, parsed.signature_size, &expected_file_len);
    if (status != RAMPART_OK) {
        return status;
    }
    if (expected_file_len != len) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    if (parsed.signed_region_offset != parsed.manifest_offset) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status =
        checked_add_size(parsed.manifest_size, parsed.payload_size, &expected_signed_region_size);
    if (status != RAMPART_OK) {
        return status;
    }
    if (parsed.signed_region_size != expected_signed_region_size) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    if (!range_available(parsed.manifest_offset, parsed.manifest_size, len, NULL) ||
        !range_available(parsed.payload_offset, parsed.payload_size, len, NULL) ||
        !range_available(parsed.signature_offset, parsed.signature_size, len, NULL) ||
        !range_available(parsed.signed_region_offset, parsed.signed_region_size, len, NULL)) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status = rampart_manifest_parse_v1(&bytes[parsed.manifest_offset], parsed.manifest_size,
                                       &parsed.manifest);
    if (status != RAMPART_OK) {
        return status;
    }

    if ((size_t)parsed.manifest.payload_size != parsed.payload_size) {
        return RAMPART_ERR_IMAGE_FORMAT;
    }

    status = validate_signature_section(&bytes[parsed.signature_offset], parsed.signature_size,
                                        parsed.signed_region_offset, parsed.signed_region_size,
                                        &parsed.manifest, &parsed.signature);
    if (status != RAMPART_OK) {
        return status;
    }

    *out = parsed;
    return RAMPART_OK;
}
