#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/crypto.h"
#include "rampart/host/openssl_crypto.h"
#include "rampart/image.h"
#include "rampart/status.h"

#define TEST_IMAGE_CAPACITY (1024u)

static int failures = 0;

#define EXPECT_TRUE(expression)                                                                    \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            (void)fprintf(stderr, "%s:%d: expected true: %s\n", __FILE__, __LINE__, #expression);  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

static bool load_image(uint8_t *bytes, size_t capacity, size_t *len) {
    FILE *file = fopen(RAMPART_TEST_VECTOR_DIR "/valid.rampart", "rb");
    bool valid = false;

    if (file == NULL) {
        return false;
    }
    *len = fread(bytes, 1u, capacity, file);
    valid = (*len != 0u) && (fgetc(file) == EOF) && (ferror(file) == 0);
    if (fclose(file) != 0) {
        valid = false;
    }
    return valid;
}

/* Embedded public material is untrusted: these checks establish math only. */
static void check_image_crypto(const uint8_t *bytes, size_t len, bool expected_digest_match,
                               rampart_status_t expected_signature_status) {
    const struct rampart_crypto_provider provider = rampart_host_openssl_provider(NULL);
    struct rampart_image_view image = {0};
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE];
    rampart_status_t status = rampart_image_parse(bytes, len, &image);

    EXPECT_TRUE(status == RAMPART_OK);
    if (status != RAMPART_OK) {
        return;
    }
    EXPECT_TRUE(image.manifest.payload_digest_len == sizeof(digest));
    if (image.manifest.payload_digest_len != sizeof(digest)) {
        return;
    }
    status = rampart_crypto_hash(&provider, image.manifest.digest_algorithm,
                                 image.bytes + image.payload_offset, image.payload_size, digest,
                                 sizeof(digest));
    EXPECT_TRUE(status == RAMPART_OK);
    if (status != RAMPART_OK) {
        return;
    }
    EXPECT_TRUE((memcmp(digest, image.manifest.payload_digest, sizeof(digest)) == 0) ==
                expected_digest_match);
    status = rampart_crypto_verify_signature(
        &provider, image.signature.signature_algorithm, image.bytes + image.signed_region_offset,
        image.signed_region_size, image.signature.public_key, image.signature.public_key_len,
        image.signature.signature, image.signature.signature_len);
    EXPECT_TRUE(status == expected_signature_status);
}

static void check_mutation(const uint8_t *original, size_t len, size_t offset,
                           bool expected_digest_match) {
    uint8_t mutated[TEST_IMAGE_CAPACITY];

    EXPECT_TRUE((len <= sizeof(mutated)) && (offset < len));
    if ((len > sizeof(mutated)) || (offset >= len)) {
        return;
    }
    (void)memcpy(mutated, original, len);
    mutated[offset] ^= 1u;
    check_image_crypto(mutated, len, expected_digest_match, RAMPART_ERR_SIGNATURE);
}

int main(void) {
    uint8_t original[TEST_IMAGE_CAPACITY];
    size_t len = 0u;
    struct rampart_image_view image = {0};
    rampart_status_t status = RAMPART_OK;

    if (!load_image(original, sizeof(original), &len)) {
        (void)fprintf(stderr, "could not read complete canonical image\n");
        return 1;
    }
    status = rampart_image_parse(original, len, &image);
    EXPECT_TRUE(status == RAMPART_OK);
    if (status != RAMPART_OK) {
        return 1;
    }
    check_image_crypto(original, len, true, RAMPART_OK);
    check_mutation(original, len, image.payload_offset, false);
    check_mutation(original, len, (size_t)(image.manifest.artifact_id - original), true);
    check_mutation(original, len, (size_t)(image.signature.signature - original), true);
    check_mutation(original, len,
                   (size_t)(image.signature.public_key - original) +
                       image.signature.public_key_len - 1u,
                   true);

    if (failures != 0) {
        (void)fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }
    return 0;
}
