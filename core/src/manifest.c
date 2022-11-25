#include "rampart/manifest.h"

rampart_status_t rampart_manifest_validate_basic(const struct rampart_manifest_view *manifest,
                                                 const struct rampart_target_id *device_target,
                                                 uint32_t minimum_security_epoch) {
    rampart_status_t target_status = RAMPART_OK;

    if ((manifest == NULL) || (device_target == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (manifest->format_version != RAMPART_MANIFEST_FORMAT_VERSION_1) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    target_status = rampart_target_validate_binding(&manifest->target, device_target);
    if (target_status != RAMPART_OK) {
        return target_status;
    }

    if (manifest->security_epoch < minimum_security_epoch) {
        return RAMPART_ERR_SECURITY_EPOCH;
    }

    if (manifest->payload_size == 0u) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    if ((manifest->payload_digest == NULL) ||
        (manifest->payload_digest_len != RAMPART_SHA256_DIGEST_SIZE)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    return RAMPART_OK;
}
