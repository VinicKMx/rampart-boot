#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rampart/manifest.h"
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

/* NOLINTNEXTLINE(readability-identifier-naming) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* No dynamic allocation: the parser is bounded by the caller's buffer. */
    struct rampart_manifest_view parsed;
    struct rampart_manifest_view untouched;
    rampart_status_t status = RAMPART_OK;

    if (size > RAMPART_FUZZ_MAX_INPUT_SIZE) {
        return -1;
    }

    (void)memset(&parsed, RAMPART_FUZZ_OUTPUT_SENTINEL, sizeof(parsed));
    (void)memset(&untouched, RAMPART_FUZZ_OUTPUT_SENTINEL, sizeof(untouched));

    status = rampart_manifest_parse_v1(data, size, &parsed);

    if (status != RAMPART_OK) {
        /*
         * A rejected manifest must never publish or alter the caller's view.
         * The object representation is compared on purpose: padding bytes carry
         * the same sentinel in both objects, so any write the parser performs on
         * a failure path is detected, not only writes to named members.
         */
        /* NOLINTNEXTLINE(bugprone-suspicious-memory-comparison,cert-exp42-c,cert-flp37-c) */
        if (memcmp(&parsed, &untouched, sizeof(parsed)) != 0) {
            abort();
        }

        return 0;
    }

    /* An accepted manifest must only expose regions inside the input buffer. */
    if (!region_within(data, size, parsed.artifact_id, parsed.artifact_id_len) ||
        !region_within(data, size, parsed.payload_digest, parsed.payload_digest_len) ||
        !region_within(data, size, parsed.key_id, parsed.key_id_len)) {
        abort();
    }

    read_region(parsed.artifact_id, parsed.artifact_id_len);
    read_region(parsed.payload_digest, parsed.payload_digest_len);
    read_region(parsed.key_id, parsed.key_id_len);

    return 0;
}
