#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/manifest.h"
#include "rampart/status.h"

#define TEST_MANIFEST_CAPACITY                                                                     \
    (RAMPART_MANIFEST_HEADER_SIZE_V1 + RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE)

struct manifest_fixture {
    uint8_t bytes[TEST_MANIFEST_CAPACITY];
    size_t len;
};

struct u16_mutation {
    const char *name;
    size_t offset;
    uint16_t value;
};

static int failures = 0;

static const size_t manifest_format_version_offset = 8u;
static const size_t manifest_header_size_offset = 10u;
static const size_t manifest_size_offset = 12u;
static const size_t hardware_revision_min_offset = 28u;
static const size_t hardware_revision_max_offset = 32u;
static const size_t digest_algorithm_offset = 50u;
static const size_t signature_algorithm_offset = 88u;
static const size_t required_key_role_offset = 90u;
static const size_t signature_threshold_offset = 92u;
static const size_t signature_count_offset = 94u;
static const size_t rollback_policy_offset = 106u;
static const size_t artifact_id_length_offset = 112u;
static const size_t requirement_count_offset = 114u;
static const size_t dependency_count_offset = 116u;
static const size_t health_required_count_offset = 118u;
static const size_t reserved_offset = 120u;

#define EXPECT_TRUE(expression)                                                                    \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            (void)fprintf(stderr, "%s:%d: expected true: %s\n", __FILE__, __LINE__, #expression);  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

#define EXPECT_STATUS(expected, expression)                                                        \
    do {                                                                                           \
        rampart_status_t actual_status = (expression);                                             \
        if (actual_status != (expected)) {                                                         \
            (void)fprintf(stderr, "%s:%d: expected %s, got %s\n", __FILE__, __LINE__,              \
                          rampart_status_string(expected), rampart_status_string(actual_status));  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

static bool write_u16_le(uint8_t *bytes, size_t capacity, size_t offset, uint16_t value) {
    if ((bytes == NULL) || (offset > capacity) || (2u > (capacity - offset))) {
        return false;
    }

    bytes[offset] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8u);
    return true;
}

static bool write_u32_le(uint8_t *bytes, size_t capacity, size_t offset, uint32_t value) {
    if ((bytes == NULL) || (offset > capacity) || (4u > (capacity - offset))) {
        return false;
    }

    bytes[offset] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8u);
    bytes[offset + 2u] = (uint8_t)(value >> 16u);
    bytes[offset + 3u] = (uint8_t)(value >> 24u);
    return true;
}

static bool build_valid_manifest(struct manifest_fixture *fixture, size_t artifact_id_len) {
    static const uint8_t magic[8u] = {'R', 'P', 'M', 'F', 'S', 'T', '0', '1'};
    size_t unpadded_len = 0u;
    size_t padding_len = 0u;
    size_t index = 0u;

    if ((fixture == NULL) || (artifact_id_len == 0u) ||
        (artifact_id_len > RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE)) {
        return false;
    }

    unpadded_len = RAMPART_MANIFEST_HEADER_SIZE_V1 + artifact_id_len;
    padding_len = (4u - (unpadded_len % 4u)) % 4u;
    fixture->len = unpadded_len + padding_len;

    if (fixture->len > sizeof(fixture->bytes)) {
        return false;
    }

    (void)memset(fixture->bytes, 0, sizeof(fixture->bytes));
    (void)memcpy(fixture->bytes, magic, sizeof(magic));

    if (!write_u16_le(fixture->bytes, fixture->len, manifest_format_version_offset,
                      RAMPART_MANIFEST_FORMAT_VERSION_1) ||
        !write_u16_le(fixture->bytes, fixture->len, manifest_header_size_offset,
                      RAMPART_MANIFEST_HEADER_SIZE_V1) ||
        !write_u32_le(fixture->bytes, fixture->len, manifest_size_offset, (uint32_t)fixture->len) ||
        !write_u32_le(fixture->bytes, fixture->len, 16u, 0x52414D50u) ||
        !write_u32_le(fixture->bytes, fixture->len, 20u, 1u) ||
        !write_u32_le(fixture->bytes, fixture->len, 24u, 0x585u) ||
        !write_u32_le(fixture->bytes, fixture->len, hardware_revision_min_offset, 1u) ||
        !write_u32_le(fixture->bytes, fixture->len, hardware_revision_max_offset, 3u) ||
        !write_u32_le(fixture->bytes, fixture->len, 36u, 0x10u) ||
        !write_u32_le(fixture->bytes, fixture->len, 40u, 12u) ||
        !write_u16_le(fixture->bytes, fixture->len, 44u, 2u) ||
        !write_u16_le(fixture->bytes, fixture->len, 46u, 4u) ||
        !write_u16_le(fixture->bytes, fixture->len, 48u, 0u) ||
        !write_u16_le(fixture->bytes, fixture->len, digest_algorithm_offset,
                      RAMPART_HASH_ALGORITHM_SHA256) ||
        !write_u32_le(fixture->bytes, fixture->len, 52u, 32u) ||
        !write_u16_le(fixture->bytes, fixture->len, signature_algorithm_offset,
                      RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) ||
        !write_u16_le(fixture->bytes, fixture->len, required_key_role_offset,
                      RAMPART_KEY_ROLE_RELEASE) ||
        !write_u16_le(fixture->bytes, fixture->len, signature_threshold_offset, 1u) ||
        !write_u16_le(fixture->bytes, fixture->len, signature_count_offset, 1u) ||
        !write_u16_le(fixture->bytes, fixture->len, 104u, 3u) ||
        !write_u16_le(fixture->bytes, fixture->len, rollback_policy_offset,
                      RAMPART_ROLLBACK_POLICY_FALLBACK) ||
        !write_u32_le(fixture->bytes, fixture->len, 108u, 30000u) ||
        !write_u16_le(fixture->bytes, fixture->len, artifact_id_length_offset,
                      (uint16_t)artifact_id_len)) {
        return false;
    }

    for (index = 0u; index < artifact_id_len; ++index) {
        fixture->bytes[RAMPART_MANIFEST_HEADER_SIZE_V1 + index] =
            (uint8_t)('A' + (uint8_t)(index % 26u));
    }

    return true;
}

static struct rampart_manifest_view manifest_output_sentinel(void) {
    static const uint8_t artifact_id[] = {'s', 'e', 'n', 't', 'i', 'n', 'e', 'l'};
    static const uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0xA5u};
    static const uint8_t key_id[RAMPART_KEY_ID_SIZE] = {0x5Au};
    const struct rampart_manifest_view sentinel = {
        .format_version = 0xA5A5A5A5u,
        .artifact_id = artifact_id,
        .artifact_id_len = sizeof(artifact_id),
        .target =
            {
                .vendor_id = 0x11111111u,
                .product_id = 0x22222222u,
                .hardware_family = 0x33333333u,
                .component_id = 0x44444444u,
            },
        .hardware_revision_min = 0x55555555u,
        .hardware_revision_max = 0x66666666u,
        .security_epoch = 0x77777777u,
        .version_major = 0x1111u,
        .version_minor = 0x2222u,
        .version_patch = 0x3333u,
        .digest_algorithm = 0x4444u,
        .payload_size = 0x88888888u,
        .payload_digest = digest,
        .payload_digest_len = sizeof(digest),
        .signature_algorithm = 0x5555u,
        .required_key_role = 0x6666u,
        .signature_threshold = 0x7777u,
        .signature_count = 0x8888u,
        .key_id = key_id,
        .key_id_len = sizeof(key_id),
        .trial_max_attempts = 0x9999u,
        .trial_probation_ms = 0x99999999u,
        .rollback_policy = 0xAAAAu,
        .requirement_count = 0xBBBBu,
        .dependency_count = 0xCCCCu,
        .health_required_count = 0xDDDDu,
    };

    return sentinel;
}

static bool manifest_views_equal(const struct rampart_manifest_view *left,
                                 const struct rampart_manifest_view *right) {
    return (left->format_version == right->format_version) &&
           (left->artifact_id == right->artifact_id) &&
           (left->artifact_id_len == right->artifact_id_len) &&
           (left->target.vendor_id == right->target.vendor_id) &&
           (left->target.product_id == right->target.product_id) &&
           (left->target.hardware_family == right->target.hardware_family) &&
           (left->target.component_id == right->target.component_id) &&
           (left->hardware_revision_min == right->hardware_revision_min) &&
           (left->hardware_revision_max == right->hardware_revision_max) &&
           (left->security_epoch == right->security_epoch) &&
           (left->version_major == right->version_major) &&
           (left->version_minor == right->version_minor) &&
           (left->version_patch == right->version_patch) &&
           (left->digest_algorithm == right->digest_algorithm) &&
           (left->payload_size == right->payload_size) &&
           (left->payload_digest == right->payload_digest) &&
           (left->payload_digest_len == right->payload_digest_len) &&
           (left->signature_algorithm == right->signature_algorithm) &&
           (left->required_key_role == right->required_key_role) &&
           (left->signature_threshold == right->signature_threshold) &&
           (left->signature_count == right->signature_count) && (left->key_id == right->key_id) &&
           (left->key_id_len == right->key_id_len) &&
           (left->trial_max_attempts == right->trial_max_attempts) &&
           (left->trial_probation_ms == right->trial_probation_ms) &&
           (left->rollback_policy == right->rollback_policy) &&
           (left->requirement_count == right->requirement_count) &&
           (left->dependency_count == right->dependency_count) &&
           (left->health_required_count == right->health_required_count);
}

static void expect_rejected(const char *name, const uint8_t *bytes, size_t len) {
    struct rampart_manifest_view output = manifest_output_sentinel();
    const struct rampart_manifest_view original = output;
    rampart_status_t status = RAMPART_OK;

    status = rampart_manifest_parse_v1(bytes, len, &output);
    if (status == RAMPART_OK) {
        (void)fprintf(stderr, "manifest case accepted unexpectedly: %s\n", name);
        ++failures;
        return;
    }

    if (!manifest_views_equal(&output, &original)) {
        (void)fprintf(stderr, "manifest case changed output on rejection: %s\n", name);
        ++failures;
    }
}

static void mutate_u16_and_expect_rejected(const struct u16_mutation *mutation) {
    struct manifest_fixture fixture = {0};

    if (!build_valid_manifest(&fixture, 4u)) {
        (void)fprintf(stderr, "failed to build fixture for %s\n", mutation->name);
        ++failures;
        return;
    }

    EXPECT_TRUE(write_u16_le(fixture.bytes, fixture.len, mutation->offset, mutation->value));
    expect_rejected(mutation->name, fixture.bytes, fixture.len);
}

static void test_manifest_accepts_artifact_id_boundaries(void) {
    static const size_t artifact_id_lengths[] = {
        1u,
        RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE,
    };
    size_t index = 0u;

    for (index = 0u; index < (sizeof(artifact_id_lengths) / sizeof(artifact_id_lengths[0]));
         ++index) {
        struct manifest_fixture fixture = {0};
        struct rampart_manifest_view manifest = {0};

        EXPECT_TRUE(build_valid_manifest(&fixture, artifact_id_lengths[index]));
        EXPECT_STATUS(RAMPART_OK, rampart_manifest_parse_v1(fixture.bytes, fixture.len, &manifest));
        EXPECT_TRUE(manifest.artifact_id == &fixture.bytes[RAMPART_MANIFEST_HEADER_SIZE_V1]);
        EXPECT_TRUE(manifest.artifact_id_len == artifact_id_lengths[index]);
    }
}

static void test_manifest_rejects_invalid_arguments_without_output(void) {
    struct manifest_fixture fixture = {0};
    struct rampart_manifest_view output = manifest_output_sentinel();
    const struct rampart_manifest_view original = output;

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));

    EXPECT_STATUS(RAMPART_ERR_INVALID_ARGUMENT,
                  rampart_manifest_parse_v1(NULL, fixture.len, &output));
    EXPECT_TRUE(manifest_views_equal(&output, &original));
    EXPECT_STATUS(RAMPART_ERR_INVALID_ARGUMENT,
                  rampart_manifest_parse_v1(fixture.bytes, fixture.len, NULL));
}

static void test_manifest_rejects_every_truncated_prefix(void) {
    struct manifest_fixture fixture = {0};
    size_t prefix_len = 0u;

    EXPECT_TRUE(build_valid_manifest(&fixture, RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE));
    for (prefix_len = 0u; prefix_len < fixture.len; ++prefix_len) {
        expect_rejected("truncated manifest prefix", fixture.bytes, prefix_len);
    }
}

static void test_manifest_rejects_invalid_identity_and_lengths(void) {
    struct manifest_fixture fixture = {0};

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    fixture.bytes[0u] ^= 0x01u;
    expect_rejected("invalid manifest magic", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, manifest_size_offset,
                             (uint32_t)(fixture.len - 1u)));
    expect_rejected("declared manifest size is smaller than input", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, manifest_size_offset,
                             (uint32_t)(fixture.len + 1u)));
    expect_rejected("declared manifest size is larger than input", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, hardware_revision_min_offset, 4u));
    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, hardware_revision_max_offset, 3u));
    expect_rejected("hardware revision minimum exceeds maximum", fixture.bytes, fixture.len);
}

static void test_manifest_rejects_unsupported_field_values(void) {
    static const struct u16_mutation mutations[] = {
        {"unknown manifest version", manifest_format_version_offset, 2u},
        {"invalid manifest header size", manifest_header_size_offset, 127u},
        {"unsupported digest algorithm", digest_algorithm_offset, 2u},
        {"unsupported signature algorithm", signature_algorithm_offset, 2u},
        {"missing required key role", required_key_role_offset, 0u},
        {"unknown required key role", required_key_role_offset, 7u},
        {"zero signature threshold", signature_threshold_offset, 0u},
        {"unsupported signature threshold", signature_threshold_offset, 2u},
        {"zero signature count", signature_count_offset, 0u},
        {"unsupported signature count", signature_count_offset, 2u},
        {"unsupported rollback policy", rollback_policy_offset, 2u},
    };
    size_t index = 0u;

    for (index = 0u; index < (sizeof(mutations) / sizeof(mutations[0])); ++index) {
        mutate_u16_and_expect_rejected(&mutations[index]);
    }
}

static void test_manifest_rejects_invalid_artifact_id_lengths(void) {
    struct manifest_fixture fixture = {0};

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    EXPECT_TRUE(write_u16_le(fixture.bytes, fixture.len, artifact_id_length_offset, 0u));
    expect_rejected("empty artifact ID", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    EXPECT_TRUE(write_u16_le(fixture.bytes, fixture.len, artifact_id_length_offset,
                             RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE + 1u));
    expect_rejected("artifact ID exceeds format maximum", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 1u));
    EXPECT_TRUE(write_u16_le(fixture.bytes, fixture.len, artifact_id_length_offset,
                             RAMPART_MANIFEST_ARTIFACT_ID_MAX_SIZE));
    expect_rejected("artifact ID extends beyond manifest", fixture.bytes, fixture.len);
}

static void test_manifest_rejects_nonzero_reserved_and_padding_bytes(void) {
    struct manifest_fixture fixture = {0};
    size_t offset = 0u;

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    fixture.bytes[reserved_offset] = 1u;
    expect_rejected("first manifest reserved byte is nonzero", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 4u));
    fixture.bytes[RAMPART_MANIFEST_HEADER_SIZE_V1 - 1u] = 1u;
    expect_rejected("last manifest reserved byte is nonzero", fixture.bytes, fixture.len);

    EXPECT_TRUE(build_valid_manifest(&fixture, 1u));
    for (offset = RAMPART_MANIFEST_HEADER_SIZE_V1 + 1u; offset < fixture.len; ++offset) {
        EXPECT_TRUE(build_valid_manifest(&fixture, 1u));
        fixture.bytes[offset] = 1u;
        expect_rejected("artifact ID padding byte is nonzero", fixture.bytes, fixture.len);
    }
}

static void test_manifest_rejects_noncanonical_padding_lengths(void) {
    struct manifest_fixture fixture = {0};
    size_t removed_padding = 0u;

    for (removed_padding = 1u; removed_padding <= 3u; ++removed_padding) {
        EXPECT_TRUE(build_valid_manifest(&fixture, 1u));
        fixture.len -= removed_padding;
        EXPECT_TRUE(
            write_u32_le(fixture.bytes, fixture.len, manifest_size_offset, (uint32_t)fixture.len));
        expect_rejected("manifest padding is shorter than canonical", fixture.bytes, fixture.len);
    }

    EXPECT_TRUE(build_valid_manifest(&fixture, 1u));
    fixture.bytes[fixture.len] = 0u;
    ++fixture.len;
    EXPECT_TRUE(
        write_u32_le(fixture.bytes, fixture.len, manifest_size_offset, (uint32_t)fixture.len));
    expect_rejected("manifest padding is longer than canonical", fixture.bytes, fixture.len);
}

static void test_manifest_rejects_unsupported_extension_counts(void) {
    static const struct u16_mutation mutations[] = {
        {"unsupported requirement count", requirement_count_offset, 1u},
        {"unsupported dependency count", dependency_count_offset, 1u},
        {"unsupported health requirement count", health_required_count_offset, 1u},
    };
    size_t index = 0u;

    for (index = 0u; index < (sizeof(mutations) / sizeof(mutations[0])); ++index) {
        mutate_u16_and_expect_rejected(&mutations[index]);
    }
}

int main(void) {
    test_manifest_accepts_artifact_id_boundaries();
    test_manifest_rejects_invalid_arguments_without_output();
    test_manifest_rejects_every_truncated_prefix();
    test_manifest_rejects_invalid_identity_and_lengths();
    test_manifest_rejects_unsupported_field_values();
    test_manifest_rejects_invalid_artifact_id_lengths();
    test_manifest_rejects_nonzero_reserved_and_padding_bytes();
    test_manifest_rejects_noncanonical_padding_lengths();
    test_manifest_rejects_unsupported_extension_counts();

    if (failures != 0) {
        (void)fprintf(stderr, "%d manifest test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
