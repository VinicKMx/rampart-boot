#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/crypto.h"
#include "rampart/status.h"

struct fake_provider_state {
    rampart_status_t hash_status;
    rampart_status_t verify_status;
    size_t hash_calls;
    size_t verify_calls;
    const uint8_t *message;
    size_t message_len;
    const uint8_t *public_key;
    const uint8_t *signature;
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

struct verify_rejection_case {
    const char *name;
    const struct rampart_crypto_provider *provider;
    const uint8_t *message;
    size_t message_len;
    const uint8_t *public_key;
    size_t public_key_len;
    const uint8_t *signature;
    size_t signature_len;
    rampart_status_t expected_status;
    rampart_signature_algorithm_t algorithm;
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

static rampart_status_t fake_verify_ecdsa_p256_sha256(void *context, const uint8_t *message,
                                                      size_t message_len, const uint8_t *public_key,
                                                      const uint8_t *signature) {
    struct fake_provider_state *state = context;

    ++state->verify_calls;
    state->message = message;
    state->message_len = message_len;
    state->public_key = public_key;
    state->signature = signature;
    return state->verify_status;
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

static void test_verify_success_forwards_arguments(void) {
    const uint8_t message[2u] = {1u, 2u};
    const uint8_t public_key[RAMPART_PUBLIC_KEY_P256_SEC1_SIZE] = {0x04u};
    const uint8_t signature[RAMPART_SIGNATURE_ECDSA_P256_SIZE] = {0x5Au};
    struct fake_provider_state state = {.verify_status = RAMPART_OK};
    const struct rampart_crypto_provider provider = {
        .context = &state,
        .verify_ecdsa_p256_sha256 = fake_verify_ecdsa_p256_sha256,
    };

    EXPECT_STATUS_NAMED(
        RAMPART_OK,
        rampart_crypto_verify_signature(&provider, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
                                        message, sizeof(message), public_key, sizeof(public_key),
                                        signature, sizeof(signature)),
        "verify success");
    EXPECT_TRUE_NAMED(state.verify_calls == 1u, "verify success");
    EXPECT_TRUE_NAMED(state.message == message, "verify success");
    EXPECT_TRUE_NAMED(state.message_len == sizeof(message), "verify success");
    EXPECT_TRUE_NAMED(state.public_key == public_key, "verify success");
    EXPECT_TRUE_NAMED(state.signature == signature, "verify success");

    EXPECT_STATUS_NAMED(RAMPART_OK,
                        rampart_crypto_verify_signature(
                            &provider, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256, NULL, 0u,
                            public_key, sizeof(public_key), signature, sizeof(signature)),
                        "empty verify message");
    EXPECT_TRUE_NAMED(state.verify_calls == 2u, "empty verify message");
    EXPECT_TRUE_NAMED(state.message == NULL, "empty verify message");
    EXPECT_TRUE_NAMED(state.message_len == 0u, "empty verify message");
}

static void test_verify_rejects_invalid_requests_before_dispatch(void) {
    const uint8_t message[1u] = {0x5Au};
    const uint8_t public_key[RAMPART_PUBLIC_KEY_P256_SEC1_SIZE] = {0x04u};
    const uint8_t signature[RAMPART_SIGNATURE_ECDSA_P256_SIZE] = {0x5Au};
    struct fake_provider_state state = {.verify_status = RAMPART_OK};
    const struct rampart_crypto_provider provider = {
        .context = &state,
        .verify_ecdsa_p256_sha256 = fake_verify_ecdsa_p256_sha256,
    };
    const struct rampart_crypto_provider missing_callback = {.context = &state};
    const struct verify_rejection_case cases[] = {
        {"null provider", NULL, message, sizeof(message), public_key, sizeof(public_key), signature,
         sizeof(signature), RAMPART_ERR_INVALID_ARGUMENT,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
        {"null nonempty message", &provider, NULL, 1u, public_key, sizeof(public_key), signature,
         sizeof(signature), RAMPART_ERR_INVALID_ARGUMENT,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
        {"null public key", &provider, message, sizeof(message), NULL, sizeof(public_key),
         signature, sizeof(signature), RAMPART_ERR_INVALID_ARGUMENT,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
        {"null signature", &provider, message, sizeof(message), public_key, sizeof(public_key),
         NULL, sizeof(signature), RAMPART_ERR_INVALID_ARGUMENT,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
        {"unsupported signature algorithm", &provider, message, sizeof(message), public_key,
         sizeof(public_key), signature, sizeof(signature), RAMPART_ERR_UNSUPPORTED_ALGORITHM, 99u},
        {"wrong public key size", &provider, message, sizeof(message), public_key,
         sizeof(public_key) - 1u, signature, sizeof(signature), RAMPART_ERR_SIGNATURE,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
        {"wrong signature size", &provider, message, sizeof(message), public_key,
         sizeof(public_key), signature, sizeof(signature) - 1u, RAMPART_ERR_SIGNATURE,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
        {"missing verify callback", &missing_callback, message, sizeof(message), public_key,
         sizeof(public_key), signature, sizeof(signature), RAMPART_ERR_CRYPTO_PROVIDER,
         RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256},
    };
    size_t index = 0u;

    for (index = 0u; index < (sizeof(cases) / sizeof(cases[0])); ++index) {
        const struct verify_rejection_case *test_case = &cases[index];

        state.verify_calls = 0u;
        EXPECT_STATUS_NAMED(
            test_case->expected_status,
            rampart_crypto_verify_signature(test_case->provider, test_case->algorithm,
                                            test_case->message, test_case->message_len,
                                            test_case->public_key, test_case->public_key_len,
                                            test_case->signature, test_case->signature_len),
            test_case->name);
        EXPECT_TRUE_NAMED(state.verify_calls == 0u, test_case->name);
    }
}

static void test_verify_propagates_only_defined_provider_results(void) {
    const uint8_t public_key[RAMPART_PUBLIC_KEY_P256_SEC1_SIZE] = {0x04u};
    const uint8_t signature[RAMPART_SIGNATURE_ECDSA_P256_SIZE] = {0x5Au};
    struct fake_provider_state state = {.verify_status = RAMPART_ERR_SIGNATURE};
    const struct rampart_crypto_provider provider = {
        .context = &state,
        .verify_ecdsa_p256_sha256 = fake_verify_ecdsa_p256_sha256,
    };

    EXPECT_STATUS_NAMED(RAMPART_ERR_SIGNATURE,
                        rampart_crypto_verify_signature(
                            &provider, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256, NULL, 0u,
                            public_key, sizeof(public_key), signature, sizeof(signature)),
                        "invalid signature result");

    state.verify_status = RAMPART_ERR_CRYPTO_PROVIDER;
    EXPECT_STATUS_NAMED(RAMPART_ERR_CRYPTO_PROVIDER,
                        rampart_crypto_verify_signature(
                            &provider, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256, NULL, 0u,
                            public_key, sizeof(public_key), signature, sizeof(signature)),
                        "verify provider failure");

    state.verify_status = RAMPART_ERR_KEY_REVOKED;
    EXPECT_STATUS_NAMED(RAMPART_ERR_CRYPTO_PROVIDER,
                        rampart_crypto_verify_signature(
                            &provider, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256, NULL, 0u,
                            public_key, sizeof(public_key), signature, sizeof(signature)),
                        "unexpected verify status");
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
    test_verify_success_forwards_arguments();
    test_verify_rejects_invalid_requests_before_dispatch();
    test_verify_propagates_only_defined_provider_results();
    test_crypto_status_strings();

    if (failures != 0) {
        (void)fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
