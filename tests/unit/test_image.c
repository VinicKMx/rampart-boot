#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "rampart/image.h"
#include "rampart/status.h"

#define TEST_IMAGE_CAPACITY (1024u)

struct image_fixture {
    uint8_t bytes[TEST_IMAGE_CAPACITY];
    size_t len;
    size_t manifest_offset;
    size_t signature_offset;
};

struct u16_mutation {
    const char *name;
    size_t offset;
    uint16_t value;
};

struct u32_mutation {
    const char *name;
    size_t offset;
    uint32_t value;
};

static int failures = 0;

static const size_t image_format_version_offset = 8u;
static const size_t image_kind_offset = 10u;
static const size_t image_header_size_offset = 12u;
static const size_t image_flags_offset = 14u;
static const size_t manifest_offset_field = 16u;
static const size_t manifest_size_offset = 20u;
static const size_t payload_offset_field = 24u;
static const size_t payload_size_offset = 28u;
static const size_t signature_offset_field = 32u;
static const size_t signature_size_offset = 36u;
static const size_t signed_region_offset_field = 40u;
static const size_t signed_region_size_offset = 44u;
static const size_t image_reserved_offset = 48u;

static const size_t manifest_payload_size_offset = 52u;

static const size_t signature_version_offset = 8u;
static const size_t signature_header_size_offset = 10u;
static const size_t signature_section_size_offset = 12u;
static const size_t signature_signed_region_offset = 16u;
static const size_t signature_signed_region_size_offset = 20u;
static const size_t signature_count_offset = 24u;
static const size_t signature_algorithm_offset = 26u;
static const size_t signature_record_size_offset = 28u;
static const size_t signature_reserved_offset = 30u;
static const size_t signature_record_key_id_offset = 32u;
static const size_t signature_record_algorithm_offset = 40u;
static const size_t signature_record_public_key_algorithm_offset = 42u;
static const size_t signature_record_signature_size_offset = 44u;
static const size_t signature_record_public_key_size_offset = 46u;
static const size_t signature_record_public_key_offset = 112u;
static const size_t signature_record_padding_offset = 177u;

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

static bool read_u32_le(const uint8_t *bytes, size_t len, size_t offset, uint32_t *out) {
    if ((bytes == NULL) || (out == NULL) || (offset > len) || (4u > (len - offset))) {
        return false;
    }

    *out = ((uint32_t)bytes[offset]) | ((uint32_t)bytes[offset + 1u] << 8u) |
           ((uint32_t)bytes[offset + 2u] << 16u) | ((uint32_t)bytes[offset + 3u] << 24u);
    return true;
}

static bool write_u16_le(uint8_t *bytes, size_t len, size_t offset, uint16_t value) {
    if ((bytes == NULL) || (offset > len) || (2u > (len - offset))) {
        return false;
    }

    bytes[offset] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8u);
    return true;
}

static bool write_u32_le(uint8_t *bytes, size_t len, size_t offset, uint32_t value) {
    if ((bytes == NULL) || (offset > len) || (4u > (len - offset))) {
        return false;
    }

    bytes[offset] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8u);
    bytes[offset + 2u] = (uint8_t)(value >> 16u);
    bytes[offset + 3u] = (uint8_t)(value >> 24u);
    return true;
}

static bool checked_add_size(size_t left, size_t right, size_t *out) {
    if ((out == NULL) || (right > (SIZE_MAX - left))) {
        return false;
    }

    *out = left + right;
    return true;
}

static bool load_valid_image(struct image_fixture *fixture) {
    char path[512u] = {0};
    FILE *file = NULL;
    uint32_t manifest_offset = 0u;
    uint32_t signature_offset = 0u;
    bool read_failed = false;
    bool close_failed = false;
    int written = 0;

    if (fixture == NULL) {
        return false;
    }

    written = snprintf(path, sizeof(path), "%s/%s", RAMPART_TEST_VECTOR_DIR, "valid.rampart");
    if ((written < 0) || ((size_t)written >= sizeof(path))) {
        return false;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return false;
    }

    fixture->len = fread(fixture->bytes, 1u, sizeof(fixture->bytes), file);
    read_failed = ferror(file) != 0;
    close_failed = fclose(file) != 0;
    if (read_failed || close_failed || (fixture->len == 0u) ||
        (fixture->len == sizeof(fixture->bytes))) {
        return false;
    }

    if (!read_u32_le(fixture->bytes, fixture->len, manifest_offset_field, &manifest_offset) ||
        !read_u32_le(fixture->bytes, fixture->len, signature_offset_field, &signature_offset)) {
        return false;
    }

    fixture->manifest_offset = (size_t)manifest_offset;
    fixture->signature_offset = (size_t)signature_offset;
    return true;
}

static struct rampart_image_view image_output_sentinel(void) {
    static const uint8_t sentinel_bytes[] = {0xA5u};
    const struct rampart_image_view sentinel = {
        .bytes = sentinel_bytes,
        .len = SIZE_MAX,
        .manifest_offset = SIZE_MAX,
        .manifest_size = SIZE_MAX,
        .payload_offset = SIZE_MAX,
        .payload_size = SIZE_MAX,
        .signature_offset = SIZE_MAX,
        .signature_size = SIZE_MAX,
        .signed_region_offset = SIZE_MAX,
        .signed_region_size = SIZE_MAX,
        .manifest =
            {
                .format_version = UINT32_MAX,
                .artifact_id = sentinel_bytes,
                .artifact_id_len = SIZE_MAX,
                .payload_digest = sentinel_bytes,
                .payload_digest_len = SIZE_MAX,
                .key_id = sentinel_bytes,
                .key_id_len = SIZE_MAX,
            },
        .signature =
            {
                .key_id = sentinel_bytes,
                .key_id_len = SIZE_MAX,
                .signature_algorithm = UINT16_MAX,
                .signature = sentinel_bytes,
                .signature_len = SIZE_MAX,
                .public_key = sentinel_bytes,
                .public_key_len = SIZE_MAX,
            },
    };

    return sentinel;
}

static void copy_image_view_bytes(const struct rampart_image_view *view, uint8_t *out) {
    const uint8_t *view_bytes = (const uint8_t *)view;
    size_t index = 0u;

    for (index = 0u; index < sizeof(*view); ++index) {
        out[index] = view_bytes[index];
    }
}

static bool image_view_bytes_equal(const struct rampart_image_view *view, const uint8_t *expected) {
    const uint8_t *view_bytes = (const uint8_t *)view;
    size_t index = 0u;

    for (index = 0u; index < sizeof(*view); ++index) {
        if (view_bytes[index] != expected[index]) {
            return false;
        }
    }

    return true;
}

static void expect_rejected(const char *name, const uint8_t *bytes, size_t len) {
    struct rampart_image_view output = image_output_sentinel();
    uint8_t original[sizeof(output)] = {0u};
    rampart_status_t status = RAMPART_OK;

    copy_image_view_bytes(&output, original);
    status = rampart_image_parse(bytes, len, &output);
    if (status == RAMPART_OK) {
        (void)fprintf(stderr, "image case accepted unexpectedly: %s\n", name);
        ++failures;
        return;
    }

    if (!image_view_bytes_equal(&output, original)) {
        (void)fprintf(stderr, "image case changed output on rejection: %s\n", name);
        ++failures;
    }
}

static void mutate_header_u16_and_expect_rejected(const struct u16_mutation *mutation) {
    struct image_fixture fixture = {0};

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load fixture for %s\n", mutation->name);
        ++failures;
        return;
    }

    EXPECT_TRUE(write_u16_le(fixture.bytes, fixture.len, mutation->offset, mutation->value));
    expect_rejected(mutation->name, fixture.bytes, fixture.len);
}

static void mutate_header_u32_and_expect_rejected(const struct u32_mutation *mutation) {
    struct image_fixture fixture = {0};

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load fixture for %s\n", mutation->name);
        ++failures;
        return;
    }

    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, mutation->offset, mutation->value));
    expect_rejected(mutation->name, fixture.bytes, fixture.len);
}

static void mutate_signature_u16_and_expect_rejected(const struct u16_mutation *mutation) {
    struct image_fixture fixture = {0};
    size_t absolute_offset = 0u;

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load fixture for %s\n", mutation->name);
        ++failures;
        return;
    }

    if (!checked_add_size(fixture.signature_offset, mutation->offset, &absolute_offset)) {
        (void)fprintf(stderr, "signature mutation offset overflowed for %s\n", mutation->name);
        ++failures;
        return;
    }

    EXPECT_TRUE(write_u16_le(fixture.bytes, fixture.len, absolute_offset, mutation->value));
    expect_rejected(mutation->name, fixture.bytes, fixture.len);
}

static void mutate_signature_u32_and_expect_rejected(const struct u32_mutation *mutation) {
    struct image_fixture fixture = {0};
    size_t absolute_offset = 0u;

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load fixture for %s\n", mutation->name);
        ++failures;
        return;
    }

    if (!checked_add_size(fixture.signature_offset, mutation->offset, &absolute_offset)) {
        (void)fprintf(stderr, "signature mutation offset overflowed for %s\n", mutation->name);
        ++failures;
        return;
    }

    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, absolute_offset, mutation->value));
    expect_rejected(mutation->name, fixture.bytes, fixture.len);
}

static void mutate_signature_byte_and_expect_rejected(const char *name, size_t relative_offset,
                                                      uint8_t value) {
    struct image_fixture fixture = {0};
    size_t absolute_offset = 0u;

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load fixture for %s\n", name);
        ++failures;
        return;
    }

    if (!checked_add_size(fixture.signature_offset, relative_offset, &absolute_offset) ||
        (absolute_offset >= fixture.len)) {
        (void)fprintf(stderr, "signature byte mutation is out of bounds for %s\n", name);
        ++failures;
        return;
    }

    fixture.bytes[absolute_offset] = value;
    expect_rejected(name, fixture.bytes, fixture.len);
}

static void test_image_accepts_canonical_vector(void) {
    struct image_fixture fixture = {0};
    struct rampart_image_view image = {0};

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load canonical image fixture\n");
        ++failures;
        return;
    }

    EXPECT_STATUS(RAMPART_OK, rampart_image_parse(fixture.bytes, fixture.len, &image));
    EXPECT_TRUE(image.bytes == fixture.bytes);
    EXPECT_TRUE(image.len == fixture.len);
    EXPECT_TRUE(image.manifest_offset == fixture.manifest_offset);
    EXPECT_TRUE(image.signature_offset == fixture.signature_offset);
    EXPECT_TRUE(image.payload_offset == 224u);
    EXPECT_TRUE(image.payload_size == 32u);
    EXPECT_TRUE(image.signed_region_offset == fixture.manifest_offset);
    EXPECT_TRUE(image.signed_region_size == 192u);
}

static void test_image_rejects_invalid_arguments_without_output(void) {
    struct image_fixture fixture = {0};
    struct rampart_image_view output = image_output_sentinel();
    uint8_t original[sizeof(output)] = {0u};

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load invalid-argument fixture\n");
        ++failures;
        return;
    }

    copy_image_view_bytes(&output, original);
    EXPECT_STATUS(RAMPART_ERR_INVALID_ARGUMENT, rampart_image_parse(NULL, fixture.len, &output));
    EXPECT_TRUE(image_view_bytes_equal(&output, original));
    EXPECT_STATUS(RAMPART_ERR_INVALID_ARGUMENT,
                  rampart_image_parse(fixture.bytes, fixture.len, NULL));
}

static void test_image_rejects_every_truncated_prefix(void) {
    struct image_fixture fixture = {0};
    size_t prefix_len = 0u;

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load truncation fixture\n");
        ++failures;
        return;
    }

    for (prefix_len = 0u; prefix_len < fixture.len; ++prefix_len) {
        expect_rejected("truncated image prefix", fixture.bytes, prefix_len);
    }
}

static void test_image_rejects_invalid_header_fields(void) {
    static const struct u16_mutation mutations[] = {
        {"unknown image format version", image_format_version_offset, 2u},
        {"unknown image artifact kind", image_kind_offset, 2u},
        {"invalid image header size", image_header_size_offset, 63u},
        {"unsupported image flags", image_flags_offset, 1u},
    };
    struct image_fixture fixture = {0};
    size_t index = 0u;

    for (index = 0u; index < (sizeof(mutations) / sizeof(mutations[0])); ++index) {
        mutate_header_u16_and_expect_rejected(&mutations[index]);
    }

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load image-header fixture\n");
        ++failures;
        return;
    }
    fixture.bytes[0u] ^= 0x01u;
    expect_rejected("invalid image magic", fixture.bytes, fixture.len);

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to reload image-header fixture\n");
        ++failures;
        return;
    }
    fixture.bytes[image_reserved_offset] = 1u;
    expect_rejected("first image reserved byte is nonzero", fixture.bytes, fixture.len);

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to reload image-header fixture\n");
        ++failures;
        return;
    }
    fixture.bytes[RAMPART_IMAGE_HEADER_SIZE - 1u] = 1u;
    expect_rejected("last image reserved byte is nonzero", fixture.bytes, fixture.len);
}

static void test_image_rejects_noncanonical_section_layouts(void) {
    struct image_fixture reference = {0};
    uint32_t manifest_size = 0u;
    uint32_t payload_offset = 0u;
    uint32_t signature_offset = 0u;
    uint32_t signature_size = 0u;
    uint32_t signed_region_size = 0u;
    size_t index = 0u;

    if (!load_valid_image(&reference) ||
        !read_u32_le(reference.bytes, reference.len, manifest_size_offset, &manifest_size) ||
        !read_u32_le(reference.bytes, reference.len, payload_offset_field, &payload_offset) ||
        !read_u32_le(reference.bytes, reference.len, signature_offset_field, &signature_offset) ||
        !read_u32_le(reference.bytes, reference.len, signature_size_offset, &signature_size) ||
        !read_u32_le(reference.bytes, reference.len, signed_region_size_offset,
                     &signed_region_size)) {
        (void)fprintf(stderr, "failed to read canonical image layout\n");
        ++failures;
        return;
    }

    const struct u32_mutation mutations[] = {
        {"manifest overlaps image header", manifest_offset_field, RAMPART_IMAGE_HEADER_SIZE - 1u},
        {"manifest leaves gap after image header", manifest_offset_field,
         RAMPART_IMAGE_HEADER_SIZE + 1u},
        {"manifest size leaves gap before payload", manifest_size_offset, manifest_size - 1u},
        {"manifest size overlaps payload", manifest_size_offset, manifest_size + 1u},
        {"manifest size reaches u32 boundary", manifest_size_offset, UINT32_MAX},
        {"payload overlaps manifest", payload_offset_field, payload_offset - 1u},
        {"payload leaves gap after manifest", payload_offset_field, payload_offset + 1u},
        {"payload size reaches u32 boundary", payload_size_offset, UINT32_MAX},
        {"signature overlaps payload", signature_offset_field, signature_offset - 1u},
        {"signature leaves gap after payload", signature_offset_field, signature_offset + 1u},
        {"signature section is truncated", signature_size_offset, signature_size - 1u},
        {"signature section is oversized", signature_size_offset, signature_size + 1u},
        {"signature size reaches u32 boundary", signature_size_offset, UINT32_MAX},
        {"signed region starts before manifest", signed_region_offset_field,
         RAMPART_IMAGE_HEADER_SIZE - 1u},
        {"signed region starts after manifest", signed_region_offset_field,
         RAMPART_IMAGE_HEADER_SIZE + 1u},
        {"signed region is truncated", signed_region_size_offset, signed_region_size - 1u},
        {"signed region is oversized", signed_region_size_offset, signed_region_size + 1u},
        {"signed region size reaches u32 boundary", signed_region_size_offset, UINT32_MAX},
    };

    for (index = 0u; index < (sizeof(mutations) / sizeof(mutations[0])); ++index) {
        mutate_header_u32_and_expect_rejected(&mutations[index]);
    }

    if (!load_valid_image(&reference)) {
        (void)fprintf(stderr, "failed to reload image layout fixture\n");
        ++failures;
        return;
    }
    reference.bytes[reference.len] = 0u;
    ++reference.len;
    expect_rejected("trailing bytes after signature section", reference.bytes, reference.len);
}

static void test_image_rejects_manifest_payload_size_disagreement(void) {
    struct image_fixture fixture = {0};
    size_t absolute_offset = 0u;

    if (!load_valid_image(&fixture)) {
        (void)fprintf(stderr, "failed to load manifest payload-size fixture\n");
        ++failures;
        return;
    }

    if (!checked_add_size(fixture.manifest_offset, manifest_payload_size_offset,
                          &absolute_offset)) {
        (void)fprintf(stderr, "manifest payload-size offset overflowed\n");
        ++failures;
        return;
    }

    EXPECT_TRUE(write_u32_le(fixture.bytes, fixture.len, absolute_offset, 31u));
    expect_rejected("manifest payload size differs from image header", fixture.bytes, fixture.len);
}

static void test_image_rejects_invalid_signature_header(void) {
    static const struct u16_mutation u16_mutations[] = {
        {"unknown signature section version", signature_version_offset, 2u},
        {"invalid signature header size", signature_header_size_offset, 31u},
        {"zero signature count", signature_count_offset, 0u},
        {"unsupported signature count", signature_count_offset, 2u},
        {"unsupported signature section algorithm", signature_algorithm_offset, 2u},
        {"truncated signature record size", signature_record_size_offset, 159u},
        {"oversized signature record size", signature_record_size_offset, 161u},
        {"nonzero signature header reserved field", signature_reserved_offset, 1u},
    };
    static const struct u32_mutation u32_mutations[] = {
        {"truncated declared signature section", signature_section_size_offset, 191u},
        {"oversized declared signature section", signature_section_size_offset, 193u},
        {"signature metadata signed region starts early", signature_signed_region_offset, 63u},
        {"signature metadata signed region starts late", signature_signed_region_offset, 65u},
        {"signature metadata signed region is truncated", signature_signed_region_size_offset,
         191u},
        {"signature metadata signed region is oversized", signature_signed_region_size_offset,
         193u},
    };
    size_t index = 0u;

    for (index = 0u; index < (sizeof(u16_mutations) / sizeof(u16_mutations[0])); ++index) {
        mutate_signature_u16_and_expect_rejected(&u16_mutations[index]);
    }
    for (index = 0u; index < (sizeof(u32_mutations) / sizeof(u32_mutations[0])); ++index) {
        mutate_signature_u32_and_expect_rejected(&u32_mutations[index]);
    }

    mutate_signature_byte_and_expect_rejected("invalid signature section magic", 0u, 0u);
}

static void test_image_rejects_invalid_signature_record(void) {
    static const struct u16_mutation mutations[] = {
        {"unsupported signature record algorithm", signature_record_algorithm_offset, 2u},
        {"unsupported public key algorithm", signature_record_public_key_algorithm_offset, 2u},
        {"truncated signature value size", signature_record_signature_size_offset, 63u},
        {"oversized signature value size", signature_record_signature_size_offset, 65u},
        {"truncated public key size", signature_record_public_key_size_offset, 64u},
        {"oversized public key size", signature_record_public_key_size_offset, 66u},
    };
    char name[64u] = {0};
    size_t index = 0u;
    int written = 0;

    mutate_signature_byte_and_expect_rejected("signature key ID differs from manifest",
                                              signature_record_key_id_offset, 0u);

    for (index = 0u; index < (sizeof(mutations) / sizeof(mutations[0])); ++index) {
        mutate_signature_u16_and_expect_rejected(&mutations[index]);
    }

    mutate_signature_byte_and_expect_rejected("invalid uncompressed SEC1 prefix",
                                              signature_record_public_key_offset, 0u);

    for (index = signature_record_padding_offset; index < RAMPART_SIGNATURE_SECTION_SIZE_V1;
         ++index) {
        written = snprintf(name, sizeof(name), "nonzero signature record padding byte %zu",
                           index - signature_record_padding_offset);
        if ((written < 0) || ((size_t)written >= sizeof(name))) {
            (void)fprintf(stderr, "failed to format signature padding case name\n");
            ++failures;
            return;
        }

        mutate_signature_byte_and_expect_rejected(name, index, 1u);
    }
}

int main(void) {
    test_image_accepts_canonical_vector();
    test_image_rejects_invalid_arguments_without_output();
    test_image_rejects_every_truncated_prefix();
    test_image_rejects_invalid_header_fields();
    test_image_rejects_noncanonical_section_layouts();
    test_image_rejects_manifest_payload_size_disagreement();
    test_image_rejects_invalid_signature_header();
    test_image_rejects_invalid_signature_record();

    if (failures != 0) {
        (void)fprintf(stderr, "%d image test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
