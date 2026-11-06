#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/trust.h"

static int failures = 0;

#define EXPECT_TRUE(expression)                                                                    \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            (void)fprintf(stderr, "%s:%d: expected true: %s\n", __FILE__, __LINE__, #expression);  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

#define EXPECT_STATUS(expected, expression)                                                        \
    do {                                                                                           \
        rampart_status_t actual = (expression);                                                    \
        if (actual != (expected)) {                                                                \
            (void)fprintf(stderr, "%s:%d: expected %s, got %s\n", __FILE__, __LINE__,              \
                          rampart_status_string(expected), rampart_status_string(actual));         \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

struct hash_state {
    size_t calls;
    size_t fail_on_call;
    rampart_status_t failure;
};

/* Tag forwarding is a deterministic dispatch fake, not a hash implementation. */
static rampart_status_t fake_hash(void *context, const uint8_t *message, size_t message_len,
                                  uint8_t digest[RAMPART_SHA256_DIGEST_SIZE]) {
    struct hash_state *state = context;
    size_t index = 0u;

    ++state->calls;
    EXPECT_TRUE(message_len == RAMPART_PUBLIC_KEY_P256_SEC1_SIZE);
    if ((message == NULL) || (message_len != RAMPART_PUBLIC_KEY_P256_SEC1_SIZE)) {
        return RAMPART_ERR_INTERNAL;
    }
    for (index = 0u; index < RAMPART_SHA256_DIGEST_SIZE; ++index) {
        digest[index] = (index < RAMPART_KEY_ID_SIZE) ? message[index + 1u] : 0u;
    }
    return (state->calls == state->fail_on_call) ? state->failure : RAMPART_OK;
}

static struct rampart_trust_record make_record(uint8_t tag) {
    struct rampart_trust_record record = {
        .roles = RAMPART_TRUST_ROLE_RELEASE,
        .key_epoch = 0u,
        .algorithm = RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
        .status = RAMPART_TRUST_KEY_TRUSTED,
        .public_key = {0x04u},
    };

    record.public_key[1] = tag;
    record.key_id[0] = tag;
    return record;
}

static void test_store_bounds_and_immutability(void) {
    struct rampart_trust_record records[RAMPART_TRUST_STORE_MAX_KEYS];
    unsigned char snapshot[sizeof(records)];
    const unsigned char *record_bytes = (const unsigned char *)records;
    struct rampart_trust_store store = {.records = records, .count = 1u};
    struct hash_state state = {0};
    const struct rampart_crypto_provider provider = {.context = &state, .sha256 = fake_hash};
    size_t index = 0u;

    for (index = 0u; index < RAMPART_TRUST_STORE_MAX_KEYS; ++index) {
        records[index] = make_record((uint8_t)(index + 1u));
    }
    (void)memcpy(snapshot, records, sizeof(snapshot));
    EXPECT_STATUS(RAMPART_ERR_INVALID_ARGUMENT, rampart_trust_store_validate(NULL, &provider));
    EXPECT_STATUS(RAMPART_ERR_INVALID_ARGUMENT, rampart_trust_store_validate(&store, NULL));
    EXPECT_STATUS(RAMPART_OK, rampart_trust_store_validate(&store, &provider));
    store.count = RAMPART_TRUST_STORE_MAX_KEYS;
    state.calls = 0u;
    EXPECT_STATUS(RAMPART_OK, rampart_trust_store_validate(&store, &provider));
    EXPECT_TRUE(state.calls == RAMPART_TRUST_STORE_MAX_KEYS);
    for (index = 0u; index < sizeof(snapshot); ++index) {
        EXPECT_TRUE(record_bytes[index] == snapshot[index]);
    }
    state.calls = 0u;
    store.count = 0u;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    store.count = RAMPART_TRUST_STORE_MAX_KEYS + 1u;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    store.count = SIZE_MAX;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    store.count = 1u;
    store.records = NULL;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    EXPECT_TRUE(state.calls == 0u);
}

static void test_record_fields(void) {
    struct rampart_trust_record record = make_record(1u);
    const struct rampart_trust_store store = {.records = &record, .count = 1u};
    struct hash_state state = {0};
    const struct rampart_crypto_provider provider = {.context = &state, .sha256 = fake_hash};
    const uint32_t epochs[] = {0u, 1u, UINT32_MAX};
    uint32_t mask = 0u;
    unsigned int bit = 0u;
    size_t index = 0u;

    for (mask = 0u; mask < 128u; ++mask) {
        record.roles = mask;
        EXPECT_STATUS(((mask != 0u) && ((mask & 1u) == 0u)) ? RAMPART_OK : RAMPART_ERR_TRUST_STORE,
                      rampart_trust_store_validate(&store, &provider));
    }
    for (bit = 7u; bit < 32u; ++bit) {
        record.roles = RAMPART_TRUST_ROLE_RELEASE | (UINT32_C(1) << bit);
        EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    }
    record.roles = RAMPART_TRUST_ROLES_ALL;
    for (index = 0u; index < sizeof(epochs) / sizeof(epochs[0]); ++index) {
        record.key_epoch = epochs[index];
        EXPECT_STATUS(RAMPART_OK, rampart_trust_store_validate(&store, &provider));
    }
    for (record.status = 0u; record.status <= 5u; ++record.status) {
        EXPECT_STATUS(((record.status >= 1u) && (record.status <= 4u)) ? RAMPART_OK
                                                                       : RAMPART_ERR_TRUST_STORE,
                      rampart_trust_store_validate(&store, &provider));
    }
    record.status = UINT16_MAX;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    record = make_record(1u);
    record.algorithm = 0u;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    record.algorithm = UINT16_MAX;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    record = make_record(1u);
    for (bit = 0u; bit <= UINT8_MAX; ++bit) {
        record.public_key[0] = (uint8_t)bit;
        EXPECT_STATUS((bit == 4u) ? RAMPART_OK : RAMPART_ERR_TRUST_STORE,
                      rampart_trust_store_validate(&store, &provider));
    }
    record = make_record(1u);
    for (index = 0u; index < RAMPART_KEY_ID_SIZE; ++index) {
        record.key_id[index] ^= 1u;
        EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
        record.key_id[index] ^= 1u;
    }
    record.public_key[1] ^= 1u;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
}

static void test_duplicate_pairs_and_revalidation(void) {
    struct rampart_trust_record records[RAMPART_TRUST_STORE_MAX_KEYS];
    const struct rampart_trust_store store = {.records = records,
                                              .count = RAMPART_TRUST_STORE_MAX_KEYS};
    struct hash_state state = {0};
    const struct rampart_crypto_provider provider = {.context = &state, .sha256 = fake_hash};
    size_t left = 0u;
    size_t right = 0u;
    size_t index = 0u;

    for (index = 0u; index < store.count; ++index) {
        records[index] = make_record((uint8_t)(index + 1u));
    }
    for (left = 0u; left < store.count; ++left) {
        for (right = left + 1u; right < store.count; ++right) {
            records[right] = records[left];
            EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
            records[right] = make_record((uint8_t)(right + 1u));
        }
    }
    EXPECT_STATUS(RAMPART_OK, rampart_trust_store_validate(&store, &provider));
    records[store.count - 1u].roles = 0u;
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
    records[store.count - 1u] = make_record((uint8_t)store.count);
    records[1].public_key[1] = records[0].public_key[1];
    EXPECT_STATUS(RAMPART_ERR_TRUST_STORE, rampart_trust_store_validate(&store, &provider));
}

static void test_provider_failures(void) {
    struct rampart_trust_record records[2u] = {make_record(1u), make_record(2u)};
    const struct rampart_trust_store store = {.records = records, .count = 2u};
    struct hash_state state = {0};
    struct rampart_crypto_provider provider = {.context = &state, .sha256 = fake_hash};
    const rampart_status_t errors[] = {RAMPART_ERR_CRYPTO_PROVIDER, RAMPART_ERR_INTERNAL,
                                       RAMPART_ERR_KEY_REVOKED};
    size_t index = 0u;

    for (index = 0u; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        state.calls = 0u;
        state.fail_on_call = 2u;
        state.failure = errors[index];
        EXPECT_STATUS(RAMPART_ERR_CRYPTO_PROVIDER, rampart_trust_store_validate(&store, &provider));
        EXPECT_TRUE(state.calls == 2u);
    }
    provider.sha256 = NULL;
    EXPECT_STATUS(RAMPART_ERR_CRYPTO_PROVIDER, rampart_trust_store_validate(&store, &provider));
    EXPECT_TRUE(strcmp(rampart_status_string(RAMPART_ERR_TRUST_STORE), "invalid trust store") == 0);
}

int main(void) {
    test_store_bounds_and_immutability();
    test_record_fields();
    test_duplicate_pairs_and_revalidation();
    test_provider_failures();
    return (failures == 0) ? 0 : 1;
}
