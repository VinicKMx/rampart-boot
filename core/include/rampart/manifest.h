#ifndef RAMPART_MANIFEST_H
#define RAMPART_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "rampart/status.h"
#include "rampart/target.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_MANIFEST_FORMAT_VERSION_1 (1u)
#define RAMPART_SHA256_DIGEST_SIZE (32u)

struct rampart_manifest_view {
    uint32_t format_version;
    struct rampart_target_id target;
    uint32_t security_epoch;
    uint32_t payload_size;
    const uint8_t *payload_digest;
    size_t payload_digest_len;
};

rampart_status_t rampart_manifest_validate_basic(const struct rampart_manifest_view *manifest,
                                                 const struct rampart_target_id *device_target,
                                                 uint32_t minimum_security_epoch);

#ifdef __cplusplus
}
#endif

#endif
