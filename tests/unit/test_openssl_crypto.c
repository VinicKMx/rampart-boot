#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/provider.h>

#include "rampart/crypto.h"
#include "rampart/host/openssl_crypto.h"
#include "rampart/status.h"

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

static void test_known_answer_digests(void) {
    static const uint8_t empty_digest[RAMPART_SHA256_DIGEST_SIZE] = {
        0xE3u, 0xB0u, 0xC4u, 0x42u, 0x98u, 0xFCu, 0x1Cu, 0x14u, 0x9Au, 0xFBu, 0xF4u,
        0xC8u, 0x99u, 0x6Fu, 0xB9u, 0x24u, 0x27u, 0xAEu, 0x41u, 0xE4u, 0x64u, 0x9Bu,
        0x93u, 0x4Cu, 0xA4u, 0x95u, 0x99u, 0x1Bu, 0x78u, 0x52u, 0xB8u, 0x55u,
    };
    static const uint8_t abc_digest[RAMPART_SHA256_DIGEST_SIZE] = {
        0xBAu, 0x78u, 0x16u, 0xBFu, 0x8Fu, 0x01u, 0xCFu, 0xEAu, 0x41u, 0x41u, 0x40u,
        0xDEu, 0x5Du, 0xAEu, 0x22u, 0x23u, 0xB0u, 0x03u, 0x61u, 0xA3u, 0x96u, 0x17u,
        0x7Au, 0x9Cu, 0xB4u, 0x10u, 0xFFu, 0x61u, 0xF2u, 0x00u, 0x15u, 0xADu,
    };
    static const uint8_t abc[] = {'a', 'b', 'c'};
    const struct rampart_crypto_provider provider = rampart_host_openssl_provider(NULL);
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};

    EXPECT_TRUE_NAMED(provider.sha256 != NULL, "OpenSSL SHA-256 callback");
    EXPECT_TRUE_NAMED(provider.verify_ecdsa_p256_sha256 == NULL,
                      "OpenSSL signature callback remains unavailable");

    EXPECT_STATUS_NAMED(RAMPART_OK,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, NULL, 0u,
                                            digest, sizeof(digest)),
                        "SHA-256 empty known answer");
    EXPECT_TRUE_NAMED(memcmp(digest, empty_digest, sizeof(digest)) == 0,
                      "SHA-256 empty known answer");

    EXPECT_STATUS_NAMED(RAMPART_OK,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, abc,
                                            sizeof(abc), digest, sizeof(digest)),
                        "SHA-256 abc known answer");
    EXPECT_TRUE_NAMED(memcmp(digest, abc_digest, sizeof(digest)) == 0, "SHA-256 abc known answer");
}

static void test_dispatch_rejects_invalid_input_without_output(void) {
    const struct rampart_crypto_provider provider = rampart_host_openssl_provider(NULL);
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};

    fill_bytes(digest, sizeof(digest), 0xA5u);
    EXPECT_STATUS_NAMED(RAMPART_ERR_INVALID_ARGUMENT,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, NULL, 1u,
                                            digest, sizeof(digest)),
                        "OpenSSL null nonempty message");
    EXPECT_TRUE_NAMED(bytes_have_value(digest, sizeof(digest), 0xA5u),
                      "OpenSSL null nonempty message");
}

static void test_backend_failure_preserves_output_and_error_queue(void) {
    static const uint8_t message[] = {'a', 'b', 'c'};
    OSSL_LIB_CTX *library_context = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *null_provider = NULL;
    struct rampart_host_openssl_context context = {.library_context = library_context};
    struct rampart_crypto_provider provider = {0};
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};
    unsigned long preserved_error = 0u;

    EXPECT_TRUE_NAMED(library_context != NULL, "isolated OpenSSL context");
    if (library_context == NULL) {
        return;
    }

    null_provider = OSSL_PROVIDER_load(library_context, "null");
    EXPECT_TRUE_NAMED(null_provider != NULL, "OpenSSL null provider");
    if (null_provider == NULL) {
        OSSL_LIB_CTX_free(library_context);
        return;
    }

    provider = rampart_host_openssl_provider(&context);
    fill_bytes(digest, sizeof(digest), 0xA5u);
    ERR_clear_error();

    EXPECT_STATUS_NAMED(RAMPART_ERR_CRYPTO_PROVIDER,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, message,
                                            sizeof(message), digest, sizeof(digest)),
                        "OpenSSL backend failure with empty error queue");
    EXPECT_TRUE_NAMED(ERR_peek_error() == 0u, "OpenSSL provider error cleanup");
    EXPECT_TRUE_NAMED(bytes_have_value(digest, sizeof(digest), 0xA5u),
                      "OpenSSL backend failure with empty error queue");

    ERR_raise(ERR_LIB_USER, 1);
    preserved_error = ERR_peek_last_error();

    EXPECT_STATUS_NAMED(RAMPART_ERR_CRYPTO_PROVIDER,
                        rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, message,
                                            sizeof(message), digest, sizeof(digest)),
                        "OpenSSL backend failure");
    EXPECT_TRUE_NAMED(bytes_have_value(digest, sizeof(digest), 0xA5u), "OpenSSL backend failure");
    EXPECT_TRUE_NAMED(ERR_peek_last_error() == preserved_error, "OpenSSL provider error isolation");

    ERR_clear_error();
    (void)OSSL_PROVIDER_unload(null_provider);
    OSSL_LIB_CTX_free(library_context);
}

int main(void) {
    test_known_answer_digests();
    test_dispatch_rejects_invalid_input_without_output();
    test_backend_failure_preserves_output_and_error_queue();

    if (failures != 0) {
        (void)fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
