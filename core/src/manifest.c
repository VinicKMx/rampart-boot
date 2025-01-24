#include "rampart/manifest.h"

#include "binary.h"

static bool valid_key_role(uint16_t role) {
    return (role == RAMPART_KEY_ROLE_RELEASE) || (role == RAMPART_KEY_ROLE_SECURITY) ||
           (role == RAMPART_KEY_ROLE_BOOT_MANAGER) || (role == RAMPART_KEY_ROLE_RECOVERY) ||
           (role == RAMPART_KEY_ROLE_FACTORY) || (role == RAMPART_KEY_ROLE_DEVELOPMENT);
}

static bool valid_rollback_policy(uint16_t policy) {
    return (policy == RAMPART_ROLLBACK_POLICY_NONE) || (policy == RAMPART_ROLLBACK_POLICY_FALLBACK);
}

rampart_status_t rampart_manifest_parse_v1(const uint8_t *bytes, size_t len,
                                           struct rampart_manifest_view *out) {
    struct rampart_manifest_view parsed = {0};
    uint16_t format_version = 0u;
    uint16_t header_size = 0u;
    uint32_t manifest_size = 0u;
    uint16_t artifact_id_len = 0u;
    size_t artifact_id_end = 0u;
    size_t padding_len = 0u;
    size_t canonical_manifest_size = 0u;
    rampart_status_t status = RAMPART_OK;

    if ((bytes == NULL) || (out == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (len < RAMPART_MANIFEST_HEADER_SIZE_V1) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    if (!rampart_binary_bytes_match(bytes, "RPMFST01", 8u)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u32_le(bytes, len, 12u, &manifest_size);
    if (status != RAMPART_OK) {
        return status;
    }

    if ((size_t)manifest_size != len) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u16_le(bytes, len, 8u, &format_version);
    if (status != RAMPART_OK) {
        return status;
    }

    if (format_version != RAMPART_MANIFEST_FORMAT_VERSION_1) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }
    parsed.format_version = (uint32_t)format_version;

    status = rampart_binary_read_u16_le(bytes, len, 10u, &header_size);
    if (status != RAMPART_OK) {
        return status;
    }

    if (header_size != RAMPART_MANIFEST_HEADER_SIZE_V1) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u32_le(bytes, len, 16u, &parsed.target.vendor_id);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u32_le(bytes, len, 20u, &parsed.target.product_id);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u32_le(bytes, len, 24u, &parsed.target.hardware_family);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u32_le(bytes, len, 28u, &parsed.hardware_revision_min);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u32_le(bytes, len, 32u, &parsed.hardware_revision_max);
    if (status != RAMPART_OK) {
        return status;
    }

    if (parsed.hardware_revision_min > parsed.hardware_revision_max) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u32_le(bytes, len, 36u, &parsed.target.component_id);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u32_le(bytes, len, 40u, &parsed.security_epoch);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 44u, &parsed.version_major);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 46u, &parsed.version_minor);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 48u, &parsed.version_patch);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 50u, &parsed.digest_algorithm);
    if (status != RAMPART_OK) {
        return status;
    }

    if (parsed.digest_algorithm != RAMPART_HASH_ALGORITHM_SHA256) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u32_le(bytes, len, 52u, &parsed.payload_size);
    if (status != RAMPART_OK) {
        return status;
    }
    parsed.payload_digest = &bytes[56u];
    parsed.payload_digest_len = RAMPART_SHA256_DIGEST_SIZE;

    status = rampart_binary_read_u16_le(bytes, len, 88u, &parsed.signature_algorithm);
    if (status != RAMPART_OK) {
        return status;
    }

    if (parsed.signature_algorithm != RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u16_le(bytes, len, 90u, &parsed.required_key_role);
    if (status != RAMPART_OK) {
        return status;
    }

    if (!valid_key_role(parsed.required_key_role)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u16_le(bytes, len, 92u, &parsed.signature_threshold);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 94u, &parsed.signature_count);
    if (status != RAMPART_OK) {
        return status;
    }

    if ((parsed.signature_threshold != 1u) || (parsed.signature_count != 1u)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    parsed.key_id = &bytes[96u];
    parsed.key_id_len = RAMPART_KEY_ID_SIZE;

    status = rampart_binary_read_u16_le(bytes, len, 104u, &parsed.trial_max_attempts);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 106u, &parsed.rollback_policy);
    if (status != RAMPART_OK) {
        return status;
    }

    if (!valid_rollback_policy(parsed.rollback_policy)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_read_u32_le(bytes, len, 108u, &parsed.trial_probation_ms);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 112u, &artifact_id_len);
    if (status != RAMPART_OK) {
        return status;
    }

    if ((artifact_id_len == 0u) || (artifact_id_len > RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    status = rampart_binary_checked_add_size(RAMPART_MANIFEST_HEADER_SIZE_V1,
                                             (size_t)artifact_id_len, &artifact_id_end);
    if (status != RAMPART_OK) {
        return status;
    }

    padding_len = (4u - (artifact_id_end % 4u)) % 4u;
    status =
        rampart_binary_checked_add_size(artifact_id_end, padding_len, &canonical_manifest_size);
    if (status != RAMPART_OK) {
        return status;
    }

    if (canonical_manifest_size != len) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    parsed.artifact_id = &bytes[RAMPART_MANIFEST_HEADER_SIZE_V1];
    parsed.artifact_id_len = (size_t)artifact_id_len;

    status = rampart_binary_read_u16_le(bytes, len, 114u, &parsed.requirement_count);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 116u, &parsed.dependency_count);
    if (status != RAMPART_OK) {
        return status;
    }
    status = rampart_binary_read_u16_le(bytes, len, 118u, &parsed.health_required_count);
    if (status != RAMPART_OK) {
        return status;
    }

    if ((parsed.requirement_count != 0u) || (parsed.dependency_count != 0u) ||
        (parsed.health_required_count != 0u)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    if (!rampart_binary_all_zeroes(&bytes[120u], RAMPART_MANIFEST_HEADER_SIZE_V1 - 120u)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    if (!rampart_binary_all_zeroes(&bytes[artifact_id_end], len - artifact_id_end)) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    *out = parsed;
    return RAMPART_OK;
}

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

    if (manifest->digest_algorithm != RAMPART_HASH_ALGORITHM_SHA256) {
        return RAMPART_ERR_MANIFEST_FORMAT;
    }

    if (manifest->signature_algorithm != RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) {
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
