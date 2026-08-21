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

static int failures = 0;

static const size_t manifest_offset_field = 16u;
static const size_t signature_offset_field = 32u;

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

int main(void) {
    test_image_accepts_canonical_vector();
    test_image_rejects_invalid_arguments_without_output();
    test_image_rejects_every_truncated_prefix();

    if (failures != 0) {
        (void)fprintf(stderr, "%d image test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
