#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/trust.h"

/* The oracle follows docs/security-model.md, Key Authorization Contract.
 * Rows are trusted/revoked/expired/development-only, then development/production,
 * then release/security/boot-manager/recovery/factory/development. Steps 3 and 4
 * take precedence over role agreement and membership (step 5).
 */
static const rampart_status_t status_rules[4u][2u][6u] = {
    {{RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK},
     {RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_ERR_KEY_LIFECYCLE}},
    {{RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED,
      RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED},
     {RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED,
      RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED, RAMPART_ERR_KEY_REVOKED}},
    {{RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED,
      RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED},
     {RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED,
      RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED, RAMPART_ERR_KEY_EXPIRED}},
    {{RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK, RAMPART_OK},
     {RAMPART_ERR_KEY_LIFECYCLE, RAMPART_ERR_KEY_LIFECYCLE, RAMPART_ERR_KEY_LIFECYCLE,
      RAMPART_ERR_KEY_LIFECYCLE, RAMPART_ERR_KEY_LIFECYCLE, RAMPART_ERR_KEY_LIFECYCLE}},
};

/* Manifest role must equal the role independently required by device policy. */
static const bool role_agreement[6u][6u] = {
    {true, false, false, false, false, false}, {false, true, false, false, false, false},
    {false, false, true, false, false, false}, {false, false, false, true, false, false},
    {false, false, false, false, true, false}, {false, false, false, false, false, true},
};

static const uint16_t roles[] = {
    RAMPART_KEY_ROLE_RELEASE,  RAMPART_KEY_ROLE_SECURITY, RAMPART_KEY_ROLE_BOOT_MANAGER,
    RAMPART_KEY_ROLE_RECOVERY, RAMPART_KEY_ROLE_FACTORY,  RAMPART_KEY_ROLE_DEVELOPMENT,
};
static const rampart_trust_key_status_t statuses[] = {
    RAMPART_TRUST_KEY_TRUSTED,
    RAMPART_TRUST_KEY_REVOKED,
    RAMPART_TRUST_KEY_EXPIRED,
    RAMPART_TRUST_KEY_DEVELOPMENT_ONLY,
};
static const rampart_device_lifecycle_t lifecycles[] = {
    RAMPART_LIFECYCLE_DEVELOPMENT,
    RAMPART_LIFECYCLE_PRODUCTION,
};
static const uint32_t membership_divisors[] = {1u, 2u, 4u, 8u, 16u, 32u};

/* Public canonical fixture material, explicitly provisioned by this test. */
static const uint8_t public_key[] = {
    0x04u, 0xCBu, 0x30u, 0x94u, 0x82u, 0x1Eu, 0xF4u, 0x8Au, 0x70u, 0x22u, 0x3Au, 0x81u, 0x91u,
    0x0Eu, 0xDCu, 0x0Fu, 0x09u, 0xF1u, 0xD6u, 0xF1u, 0xF4u, 0x09u, 0x24u, 0x04u, 0x3Eu, 0x14u,
    0x08u, 0x52u, 0x85u, 0x49u, 0x5Cu, 0xE4u, 0x9Cu, 0xF0u, 0xA4u, 0xAEu, 0x2Eu, 0xF4u, 0x7Cu,
    0x49u, 0x8Eu, 0x94u, 0x3Fu, 0x10u, 0x6Au, 0x47u, 0x0Fu, 0xFFu, 0x10u, 0x6Eu, 0xA1u, 0x1Cu,
    0xF2u, 0x74u, 0x3Fu, 0x5Fu, 0x57u, 0x86u, 0x1Du, 0x76u, 0x4Fu, 0x09u, 0x2Du, 0x22u, 0x0Du,
};
static const uint8_t public_key_digest[] = {
    0x75u, 0xABu, 0xDDu, 0xA2u, 0xE9u, 0xE5u, 0x84u, 0xBAu, 0xF7u, 0x7Bu, 0x74u,
    0x80u, 0x88u, 0xF8u, 0x45u, 0x52u, 0x9Bu, 0xFEu, 0xE9u, 0x7Bu, 0xA6u, 0x7Du,
    0x78u, 0x7Au, 0xADu, 0x92u, 0x12u, 0x49u, 0xB8u, 0xDDu, 0x57u, 0x0Fu,
};

/* A fixed-answer dispatch fake; independent real ID derivation has its own test. */
static rampart_status_t fixture_hash(void *context, const uint8_t *message, size_t message_len,
                                     uint8_t digest[RAMPART_SHA256_DIGEST_SIZE]) {
    (void)context;
    if ((message_len != sizeof(public_key)) ||
        (memcmp(message, public_key, sizeof(public_key)) != 0)) {
        return RAMPART_ERR_INTERNAL;
    }
    (void)memcpy(digest, public_key_digest, sizeof(public_key_digest));
    return RAMPART_OK;
}

int main(void) {
    struct rampart_trust_record record = {
        .algorithm = RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
        .key_epoch = UINT32_MAX,
    };
    const struct rampart_trust_record sentinel = {0};
    const struct rampart_trust_store store = {.records = &record, .count = 1u};
    const struct rampart_crypto_provider provider = {.sha256 = fixture_hash};
    struct rampart_trust_request request = {.key_id = record.key_id,
                                            .key_id_len = sizeof(record.key_id)};
    size_t status_index = 0u;
    size_t lifecycle_index = 0u;
    size_t required_index = 0u;
    size_t manifest_index = 0u;
    uint32_t set = 0u;
    size_t cells = 0u;
    size_t failures = 0u;

    (void)memcpy(record.key_id, public_key_digest, sizeof(record.key_id));
    (void)memcpy(record.public_key, public_key, sizeof(record.public_key));
    for (status_index = 0u; status_index < 4u; ++status_index) {
        record.status = statuses[status_index];
        for (lifecycle_index = 0u; lifecycle_index < 2u; ++lifecycle_index) {
            request.lifecycle = lifecycles[lifecycle_index];
            for (required_index = 0u; required_index < 6u; ++required_index) {
                request.required_role = roles[required_index];
                for (manifest_index = 0u; manifest_index < 6u; ++manifest_index) {
                    request.manifest_role = roles[manifest_index];
                    for (set = 1u; set <= 63u; ++set) {
                        struct rampart_trust_result result = {.record = &sentinel};
                        rampart_status_t expected =
                            status_rules[status_index][lifecycle_index][required_index];
                        rampart_status_t actual = RAMPART_OK;
                        const bool member =
                            ((set / membership_divisors[required_index]) % 2u) != 0u;
                        const struct rampart_trust_record *expected_record = NULL;

                        /* Ordinal bits 0..5 map to record role bits 1..6. */
                        record.roles = set * 2u;
                        if ((expected == RAMPART_OK) &&
                            (!role_agreement[required_index][manifest_index] || !member)) {
                            expected = RAMPART_ERR_KEY_ROLE;
                        }
                        expected_record = (expected == RAMPART_OK) ? &record : &sentinel;
                        actual = rampart_trust_authorize(&store, &provider, &request, &result);
                        ++cells;
                        if ((actual != expected) || (result.record != expected_record)) {
                            ++failures;
                            if (failures <= 8u) {
                                (void)fprintf(stderr,
                                              "status=%zu life=%zu required=%zu manifest=%zu "
                                              "set=%u: expected %s, got %s, output preserved=%d\n",
                                              status_index, lifecycle_index, required_index,
                                              manifest_index, (unsigned int)set,
                                              rampart_status_string(expected),
                                              rampart_status_string(actual),
                                              result.record == expected_record);
                            }
                        }
                    }
                }
            }
        }
    }
    (void)printf("authorization matrix: %zu cells, %zu failures\n", cells, failures);
    return ((cells == 18144u) && (failures == 0u)) ? 0 : 1;
}
