#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/crypto.h"
#include "rampart/status.h"

struct fake_provider_state {
    rampart_status_t hash_status;
    size_t hash_calls;
    const uint8_t *message;
    size_t message_len;
};

struct hash_rejection_case {
    const char *name;
    const struct rampart_crypto_provider *provider;
    const uint8_t *message;
    size_t message_len;
    uint8_t *digest;
    size_t digest_len;
    rampart_status_t expected_status;
    rampart_hash_algorithm_t algorithm;
};

static int failures = 0;

#define EXPECT_TRUE_NAMED(expression, name)                                                        \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            (void)fprintf(stderr, "%s:%d: %s: expected true: %s\n", __FILE__, __LINE__, (name),    \
                          #expression);                                                            \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

#define EXPECT_STATUS_NAMED(expected, expression, name)                                            \
    do {                                                                                           \
        rampart_status_t actual_status = (expression);                                             \
        if (actual_status != (expected)) {                                                         \
            (void)fprintf(stderr, "%s:%d: %s: expected %s, got %s\n", __FILE__, __LINE__, (name),  \
                          rampart_status_string(expected), rampart_status_string(actual_status));  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

static void fill_bytes(uint8_t *bytes, size_t len, uint8_t value) {
    size_t index = 0u;

    for (index = 0u; index < len; ++index) {
        bytes[index] = value;
    }
}

static bool bytes_have_value(const uint8_t *bytes, size_t len, uint8_t value) {
    size_t index = 0u;

    for (index = 0u; index < len; ++index) {
        if (bytes[index] != value) {
            return false;
        }
    }

    return true;
}

static rampart_status_t fake_sha256(void *context, const uint8_t *message, size_t message_len,
                                    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE]) {
    struct fake_provider_state *state = context;
    size_t index = 0u;

    ++state->hash_calls;
    state->message = message;
    state->message_len = message_len;

    for (index = 0u; index < RAMPART_SHA256_DIGEST_SIZE; ++index) {
        digest[index] = (uint8_t)(0x80u + index);
    }

    return state->hash_status;
}

static void test_hash_success_forwards_arguments_and_publishes_digest(void) {
    const uint8_t message[3u] = {1u, 2u, 3u};
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};
    struct fake_provider_state state = {.hash_status = RAMPART_OK};
    const struct rampart_crypto_provider provider = {
        .context = &state,
        .sha256 = fake_sha256,
    };

    EXPECT_STATUS_NAMED(RAMPART_OK,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, message,
                                            sizeof(message), digest, sizeof(digest)),
                        "hash success");
    EXPECT_TRUE_NAMED(state.hash_calls == 1u, "hash success");
    EXPECT_TRUE_NAMED(state.message == message, "hash success");
    EXPECT_TRUE_NAMED(state.message_len == sizeof(message), "hash success");
    EXPECT_TRUE_NAMED(digest[0] == 0x80u, "hash success");
    EXPECT_TRUE_NAMED(digest[RAMPART_SHA256_DIGEST_SIZE - 1u] == 0x9Fu, "hash success");

    EXPECT_STATUS_NAMED(RAMPART_OK,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, NULL, 0u,
                                            digest, sizeof(digest)),
                        "empty hash message");
    EXPECT_TRUE_NAMED(state.hash_calls == 2u, "empty hash message");
    EXPECT_TRUE_NAMED(state.message == NULL, "empty hash message");
    EXPECT_TRUE_NAMED(state.message_len == 0u, "empty hash message");
}

static void test_hash_rejects_invalid_requests_before_dispatch(void) {
    const uint8_t message[1u] = {0x5Au};
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};
    struct fake_provider_state state = {.hash_status = RAMPART_OK};
    const struct rampart_crypto_provider provider = {.context = &state, .sha256 = fake_sha256};
    const struct rampart_crypto_provider missing_callback = {.context = &state};
    const struct hash_rejection_case cases[] = {
        {"null provider", NULL, message, sizeof(message), digest, sizeof(digest),
         RAMPART_ERR_INVALID_ARGUMENT, RAMPART_HASH_ALGORITHM_SHA256},
        {"null nonempty message", &provider, NULL, 1u, digest, sizeof(digest),
         RAMPART_ERR_INVALID_ARGUMENT, RAMPART_HASH_ALGORITHM_SHA256},
        {"null digest", &provider, message, sizeof(message), NULL, sizeof(digest),
         RAMPART_ERR_INVALID_ARGUMENT, RAMPART_HASH_ALGORITHM_SHA256},
        {"unsupported hash", &provider, message, sizeof(message), digest, sizeof(digest),
         RAMPART_ERR_UNSUPPORTED_ALGORITHM, 99u},
        {"wrong digest size", &provider, message, sizeof(message), digest, sizeof(digest) - 1u,
         RAMPART_ERR_INVALID_ARGUMENT, RAMPART_HASH_ALGORITHM_SHA256},
        {"missing hash callback", &missing_callback, message, sizeof(message), digest,
         sizeof(digest), RAMPART_ERR_CRYPTO_PROVIDER, RAMPART_HASH_ALGORITHM_SHA256},
    };
    size_t index = 0u;

    for (index = 0u; index < (sizeof(cases) / sizeof(cases[0])); ++index) {
        const struct hash_rejection_case *test_case = &cases[index];

        state.hash_calls = 0u;
        fill_bytes(digest, sizeof(digest), 0xA5u);
        EXPECT_STATUS_NAMED(test_case->expected_status,
                            rampart_crypto_hash(test_case->provider, test_case->algorithm,
                                                test_case->message, test_case->message_len,
                                                test_case->digest, test_case->digest_len),
                            test_case->name);
        EXPECT_TRUE_NAMED(state.hash_calls == 0u, test_case->name);
        EXPECT_TRUE_NAMED(bytes_have_value(digest, sizeof(digest), 0xA5u), test_case->name);
    }
}

static void test_hash_preserves_output_on_provider_failure(void) {
    const uint8_t message[1u] = {0x5Au};
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};
    struct fake_provider_state state = {.hash_status = RAMPART_ERR_CRYPTO_PROVIDER};
    const struct rampart_crypto_provider provider = {.context = &state, .sha256 = fake_sha256};

    fill_bytes(digest, sizeof(digest), 0xA5u);
    EXPECT_STATUS_NAMED(RAMPART_ERR_CRYPTO_PROVIDER,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, message,
                                            sizeof(message), digest, sizeof(digest)),
                        "hash provider failure");
    EXPECT_TRUE_NAMED(state.hash_calls == 1u, "hash provider failure");
    EXPECT_TRUE_NAMED(bytes_have_value(digest, sizeof(digest), 0xA5u), "hash provider failure");

    state.hash_status = RAMPART_ERR_KEY_REVOKED;
    EXPECT_STATUS_NAMED(RAMPART_ERR_CRYPTO_PROVIDER,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, message,
                                            sizeof(message), digest, sizeof(digest)),
                        "unexpected hash status");
    EXPECT_TRUE_NAMED(bytes_have_value(digest, sizeof(digest), 0xA5u), "unexpected hash status");
}

static void test_crypto_status_strings(void) {
    EXPECT_TRUE_NAMED(strcmp(rampart_status_string(RAMPART_ERR_UNSUPPORTED_ALGORITHM),
                             "unsupported algorithm") == 0,
                      "unsupported algorithm status string");
    EXPECT_TRUE_NAMED(
        strcmp(rampart_status_string(RAMPART_ERR_CRYPTO_PROVIDER), "crypto provider failure") == 0,
        "crypto provider status string");
}

int main(void) {
    test_hash_success_forwards_arguments_and_publishes_digest();
    test_hash_rejects_invalid_requests_before_dispatch();
    test_hash_preserves_output_on_provider_failure();
    test_crypto_status_strings();

    if (failures != 0) {
        (void)fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
