#ifndef RAMPART_IMAGE_H
#define RAMPART_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "rampart/manifest.h"
#include "rampart/status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_IMAGE_HEADER_SIZE (64u)
#define RAMPART_IMAGE_FORMAT_VERSION_1 (1u)
#define RAMPART_IMAGE_KIND_FIRMWARE (1u)

#define RAMPART_SIGNATURE_SECTION_SIZE_V1 (192u)
#define RAMPART_SIGNATURE_KEY_ID_SIZE (8u)
#define RAMPART_SIGNATURE_ECDSA_P256_SIZE (64u)
#define RAMPART_PUBLIC_KEY_P256_SEC1_SIZE (65u)

struct rampart_signature_view {
    const uint8_t *key_id;
    size_t key_id_len;
    uint16_t signature_algorithm;
    const uint8_t *signature;
    size_t signature_len;
    const uint8_t *public_key;
    size_t public_key_len;
};

struct rampart_image_view {
    const uint8_t *bytes;
    size_t len;
    size_t manifest_offset;
    size_t manifest_size;
    size_t payload_offset;
    size_t payload_size;
    size_t signature_offset;
    size_t signature_size;
    size_t signed_region_offset;
    size_t signed_region_size;
    struct rampart_manifest_view manifest;
    struct rampart_signature_view signature;
};

rampart_status_t rampart_image_parse(const uint8_t *bytes, size_t len,
                                     struct rampart_image_view *out);

#ifdef __cplusplus
}
#endif

#endif
