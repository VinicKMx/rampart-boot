#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rampart/image.h"
#include "rampart/status.h"

/*
 * Host fuzzing bound. This limits what the harness feeds the parser; it does
 * not redefine the on-wire v1 size contract, which remains u32. Inputs that
 * declare very large sizes stay reachable through small structural inputs.
 */
#define RAMPART_FUZZ_MAX_INPUT_SIZE ((size_t)1024u * 1024u)

/* Non-zero fill used to detect any write into the caller-owned output view. */
#define RAMPART_FUZZ_OUTPUT_SENTINEL (0xA5)

/* libFuzzer fixes this entry point name; it cannot follow repository casing. */
/* NOLINTNEXTLINE(readability-identifier-naming) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Forces the sanitizer to perform the loads a caller of the view would make. */
static volatile uint8_t rampart_fuzz_sink = 0u;

static bool span_within(size_t container_len, size_t offset, size_t span_len) {
    return (offset <= container_len) && (span_len <= (container_len - offset));
}

static bool region_within(const uint8_t *base, size_t base_len, const uint8_t *region,
                          size_t region_len) {
    uintptr_t base_address = (uintptr_t)base;
    uintptr_t region_address = (uintptr_t)region;
    size_t region_offset = 0u;

    if (region == NULL) {
        return false;
    }

    if (region_address < base_address) {
        return false;
    }

    region_offset = (size_t)(region_address - base_address);
    if (region_offset > base_len) {
        return false;
    }

    return region_len <= (base_len - region_offset);
}

static void read_region(const uint8_t *region, size_t region_len) {
    uint8_t accumulator = 0u;
    size_t index = 0u;

    for (index = 0u; index < region_len; ++index) {
        accumulator = (uint8_t)(accumulator ^ region[index]);
    }

    rampart_fuzz_sink = accumulator;
}

static bool image_view_is_bounded(const uint8_t *data, size_t size,
                                  const struct rampart_image_view *image) {
    const uint8_t *manifest = NULL;
    const uint8_t *signature = NULL;

    if ((image->bytes != data) || (image->len != size) ||
        !span_within(size, image->manifest_offset, image->manifest_size) ||
        !span_within(size, image->payload_offset, image->payload_size) ||
        !span_within(size, image->signature_offset, image->signature_size) ||
        !span_within(size, image->signed_region_offset, image->signed_region_size)) {
        return false;
    }

    manifest = &data[image->manifest_offset];
    signature = &data[image->signature_offset];

    return region_within(manifest, image->manifest_size, image->manifest.artifact_id,
                         image->manifest.artifact_id_len) &&
           region_within(manifest, image->manifest_size, image->manifest.payload_digest,
                         image->manifest.payload_digest_len) &&
           region_within(manifest, image->manifest_size, image->manifest.key_id,
                         image->manifest.key_id_len) &&
           region_within(signature, image->signature_size, image->signature.key_id,
                         image->signature.key_id_len) &&
           region_within(signature, image->signature_size, image->signature.signature,
                         image->signature.signature_len) &&
           region_within(signature, image->signature_size, image->signature.public_key,
                         image->signature.public_key_len);
}

static void read_image_view(const uint8_t *data, const struct rampart_image_view *image) {
    read_region(&data[image->manifest_offset], image->manifest_size);
    read_region(&data[image->payload_offset], image->payload_size);
    read_region(&data[image->signature_offset], image->signature_size);
    read_region(&data[image->signed_region_offset], image->signed_region_size);
    read_region(image->manifest.artifact_id, image->manifest.artifact_id_len);
    read_region(image->manifest.payload_digest, image->manifest.payload_digest_len);
    read_region(image->manifest.key_id, image->manifest.key_id_len);
    read_region(image->signature.key_id, image->signature.key_id_len);
    read_region(image->signature.signature, image->signature.signature_len);
    read_region(image->signature.public_key, image->signature.public_key_len);
}

/* NOLINTNEXTLINE(readability-identifier-naming) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* No dynamic allocation: the parser is bounded by the caller's buffer. */
    struct rampart_image_view parsed;
    struct rampart_image_view untouched;
    rampart_status_t status = RAMPART_OK;

    if (size > RAMPART_FUZZ_MAX_INPUT_SIZE) {
        return -1;
    }

    (void)memset(&parsed, RAMPART_FUZZ_OUTPUT_SENTINEL, sizeof(parsed));
    (void)memset(&untouched, RAMPART_FUZZ_OUTPUT_SENTINEL, sizeof(untouched));

    status = rampart_image_parse(data, size, &parsed);

    if (status != RAMPART_OK) {
        /* A rejected image must never publish or alter the caller's view. */
        /* NOLINTNEXTLINE(bugprone-suspicious-memory-comparison,cert-exp42-c,cert-flp37-c) */
        if (memcmp(&parsed, &untouched, sizeof(parsed)) != 0) {
            abort();
        }

        return 0;
    }

    if (!image_view_is_bounded(data, size, &parsed)) {
        abort();
    }

    read_image_view(data, &parsed);
    return 0;
}
