#ifndef RAMPART_MANIFEST_H
#define RAMPART_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "rampart/crypto.h"
#include "rampart/status.h"
#include "rampart/target.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_MANIFEST_FORMAT_VERSION_1 (1u)
#define RAMPART_MANIFEST_HEADER_SIZE_V1 (128u)
#define RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE (128u)
#define RAMPART_KEY_ID_SIZE (8u)

#define RAMPART_KEY_ROLE_RELEASE (1u)
#define RAMPART_KEY_ROLE_SECURITY (2u)
#define RAMPART_KEY_ROLE_BOOT_MANAGER (3u)
#define RAMPART_KEY_ROLE_RECOVERY (4u)
#define RAMPART_KEY_ROLE_FACTORY (5u)
#define RAMPART_KEY_ROLE_DEVELOPMENT (6u)

#define RAMPART_ROLLBACK_POLICY_NONE (0u)
#define RAMPART_ROLLBACK_POLICY_FALLBACK (1u)

struct rampart_manifest_view {
    uint32_t format_version;
    const uint8_t *artifact_id;
    size_t artifact_id_len;
    struct rampart_target_id target;
    uint32_t hardware_revision_min;
    uint32_t hardware_revision_max;
    uint32_t security_epoch;
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t version_patch;
    uint16_t digest_algorithm;
    uint32_t payload_size;
    const uint8_t *payload_digest;
    size_t payload_digest_len;
    uint16_t signature_algorithm;
    uint16_t required_key_role;
    uint16_t signature_threshold;
    uint16_t signature_count;
    const uint8_t *key_id;
    size_t key_id_len;
    uint16_t trial_max_attempts;
    uint32_t trial_probation_ms;
    uint16_t rollback_policy;
    uint16_t requirement_count;
    uint16_t dependency_count;
    uint16_t health_required_count;
};

rampart_status_t rampart_manifest_parse_v1(const uint8_t *bytes, size_t len,
                                           struct rampart_manifest_view *out);

rampart_status_t rampart_manifest_validate_basic(const struct rampart_manifest_view *manifest,
                                                 const struct rampart_target_id *device_target,
                                                 uint32_t minimum_security_epoch);

#ifdef __cplusplus
}
#endif

#endif
