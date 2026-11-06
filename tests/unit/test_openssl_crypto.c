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

/* Public verification vectors from C2SP Wycheproof (Apache-2.0).
 * https://github.com/C2SP/wycheproof/blob/
 * d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_test.json
 * tcId 1 (empty), 2 (Msg), 3 (123400). DER INTEGER values are stored as
 * unsigned, big-endian, 32-byte r || s. No signing material is used.
 */
static const uint8_t wycheproof_public_key[] = {
    0x04u, 0x04u, 0xAAu, 0xECu, 0x73u, 0x63u, 0x57u, 0x26u, 0xF2u, 0x13u, 0xFBu, 0x8Au, 0x9Eu,
    0x64u, 0xDAu, 0x3Bu, 0x86u, 0x32u, 0xE4u, 0x14u, 0x95u, 0xA9u, 0x44u, 0xD0u, 0x04u, 0x5Bu,
    0x52u, 0x2Eu, 0xBAu, 0x72u, 0x40u, 0xFAu, 0xD5u, 0x87u, 0xD9u, 0x31u, 0x57u, 0x98u, 0xAAu,
    0xA3u, 0xA5u, 0xBAu, 0x01u, 0x77u, 0x57u, 0x87u, 0xCEu, 0xD0u, 0x5Eu, 0xAAu, 0xF7u, 0xB4u,
    0xE0u, 0x9Fu, 0xC8u, 0x1Du, 0x6Du, 0x1Au, 0xA5u, 0x46u, 0xE8u, 0x36u, 0x5Du, 0x52u, 0x5Du,
};

static const uint8_t wycheproof_signature_1[] = {
    0xB2u, 0x92u, 0xA6u, 0x19u, 0x33u, 0x9Fu, 0x6Eu, 0x56u, 0x7Au, 0x30u, 0x5Cu, 0x95u, 0x1Cu,
    0x0Du, 0xCBu, 0xCCu, 0x42u, 0xD1u, 0x6Eu, 0x47u, 0xF2u, 0x19u, 0xF9u, 0xE9u, 0x8Eu, 0x76u,
    0xE0u, 0x9Du, 0x87u, 0x70u, 0xB3u, 0x4Au, 0x01u, 0x77u, 0xE6u, 0x04u, 0x92u, 0xC5u, 0xA8u,
    0x24u, 0x2Fu, 0x76u, 0xF0u, 0x7Bu, 0xFEu, 0x36u, 0x61u, 0xBDu, 0xE5u, 0x9Eu, 0xC2u, 0xA1u,
    0x7Cu, 0xE5u, 0xBDu, 0x2Du, 0xABu, 0x2Au, 0xBEu, 0xBDu, 0xF8u, 0x9Au, 0x62u, 0xE2u,
};

static const uint8_t wycheproof_signature_2[] = {
    0x53u, 0x0Bu, 0xD6u, 0xB0u, 0xC9u, 0xAFu, 0x2Du, 0x69u, 0xBAu, 0x89u, 0x7Fu, 0x6Bu, 0x5Fu,
    0xB5u, 0x96u, 0x95u, 0xCFu, 0xBFu, 0x33u, 0xAFu, 0xE6u, 0x6Du, 0xBAu, 0xDCu, 0xF5u, 0xB8u,
    0xD2u, 0xA2u, 0xA6u, 0x53u, 0x8Eu, 0x23u, 0xD8u, 0x5Eu, 0x48u, 0x9Cu, 0xB7u, 0xA1u, 0x61u,
    0xFDu, 0x55u, 0xEDu, 0xEDu, 0xCEu, 0xDBu, 0xF4u, 0xCCu, 0x0Cu, 0x09u, 0x87u, 0xE3u, 0xE3u,
    0xF0u, 0xF2u, 0x42u, 0xCAu, 0xE9u, 0x34u, 0xC7u, 0x2Cu, 0xAAu, 0x3Fu, 0x43u, 0xE9u,
};

static const uint8_t wycheproof_message_2[] = {
    0x4Du,
    0x73u,
    0x67u,
};

static const uint8_t wycheproof_signature_3[] = {
    0xA8u, 0xEAu, 0x15u, 0x0Cu, 0xB8u, 0x01u, 0x25u, 0xD7u, 0x38u, 0x1Cu, 0x4Cu, 0x1Fu, 0x1Du,
    0xA8u, 0xE9u, 0xDEu, 0x27u, 0x11u, 0xF9u, 0x91u, 0x70u, 0x60u, 0x40u, 0x6Au, 0x73u, 0xD7u,
    0x90u, 0x45u, 0x19u, 0xE5u, 0x13u, 0x88u, 0xF3u, 0xABu, 0x9Fu, 0xA6u, 0x8Bu, 0xD4u, 0x79u,
    0x73u, 0xA7u, 0x3Bu, 0x2Du, 0x40u, 0x48u, 0x0Cu, 0x2Bu, 0xA5u, 0x0Cu, 0x22u, 0xC9u, 0xD7u,
    0x6Eu, 0xC2u, 0x17u, 0x25u, 0x72u, 0x88u, 0x29u, 0x32u, 0x85u, 0x44u, 0x9Bu, 0x86u,
};

static const uint8_t wycheproof_message_3[] = {
    0x31u, 0x32u, 0x33u, 0x34u, 0x30u, 0x30u,
};

/* A different valid public point from the same public verification corpus. */
static const uint8_t other_public_key[] = {
    0x04u, 0x29u, 0x27u, 0xB1u, 0x05u, 0x12u, 0xBAu, 0xE3u, 0xEDu, 0xDCu, 0xFEu, 0x46u, 0x78u,
    0x28u, 0x12u, 0x8Bu, 0xADu, 0x29u, 0x03u, 0x26u, 0x99u, 0x19u, 0xF7u, 0x08u, 0x60u, 0x69u,
    0xC8u, 0xC4u, 0xDFu, 0x6Cu, 0x73u, 0x28u, 0x38u, 0xC7u, 0x78u, 0x79u, 0x64u, 0xEAu, 0xACu,
    0x00u, 0xE5u, 0x92u, 0x1Fu, 0xB1u, 0x49u, 0x8Au, 0x60u, 0xF4u, 0x60u, 0x67u, 0x66u, 0xB3u,
    0xD9u, 0x68u, 0x50u, 0x01u, 0x55u, 0x8Du, 0x1Au, 0x97u, 0x4Eu, 0x73u, 0x41u, 0x51u, 0x3Eu,
};

static const uint8_t p256_order[] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xBCu, 0xE6u, 0xFAu, 0xADu, 0xA7u, 0x17u,
    0x9Eu, 0x84u, 0xF3u, 0xB9u, 0xCAu, 0xC2u, 0xFCu, 0x63u, 0x25u, 0x51u,
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
    EXPECT_TRUE_NAMED(provider.verify_ecdsa_p256_sha256 != NULL, "OpenSSL signature callback");

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

/* Every verification class runs with an empty and a pre-existing error queue. */
static void expect_verification(const struct rampart_crypto_provider *provider,
                                const uint8_t *message, size_t message_len,
                                const uint8_t *public_key, const uint8_t *signature,
                                rampart_status_t expected, const char *name) {
    unsigned long first_error = 0u;
    unsigned long last_error = 0u;
    size_t pass = 0u;

    for (pass = 0u; pass < 2u; ++pass) {
        ERR_clear_error();
        if (pass != 0u) {
            ERR_raise(ERR_LIB_USER, 1);
            first_error = ERR_peek_error();
            ERR_raise(ERR_LIB_USER, 2);
            last_error = ERR_peek_last_error();
        }
        EXPECT_STATUS_NAMED(expected,
                            rampart_crypto_verify_signature(
                                provider, RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256, message,
                                message_len, public_key, RAMPART_PUBLIC_KEY_P256_SEC1_SIZE,
                                signature, RAMPART_SIGNATURE_ECDSA_P256_SIZE),
                            name);
        if (pass != 0u) {
            EXPECT_TRUE_NAMED(ERR_get_error() == first_error, name);
            EXPECT_TRUE_NAMED(ERR_get_error() == last_error, name);
        }
        EXPECT_TRUE_NAMED(ERR_get_error() == 0u, name);
    }
}

static void test_signature_vectors_and_mutations(void) {
    const struct rampart_crypto_provider provider = rampart_host_openssl_provider(NULL);
    uint8_t message[sizeof(wycheproof_message_2)];
    uint8_t signature[sizeof(wycheproof_signature_2)];
    uint8_t public_key[sizeof(wycheproof_public_key)];
    size_t scalar_offset = 0u;

    expect_verification(&provider, NULL, 0u, wycheproof_public_key, wycheproof_signature_1,
                        RAMPART_OK, "Wycheproof tcId 1 empty message");
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                        wycheproof_public_key, wycheproof_signature_2, RAMPART_OK,
                        "Wycheproof tcId 2 high s");
    expect_verification(&provider, wycheproof_message_3, sizeof(wycheproof_message_3),
                        wycheproof_public_key, wycheproof_signature_3, RAMPART_OK,
                        "Wycheproof tcId 3 maximum DER size");
    expect_verification(&provider, NULL, 0u, wycheproof_public_key, wycheproof_signature_2,
                        RAMPART_ERR_SIGNATURE, "nonempty signature on empty message");

    (void)memcpy(message, wycheproof_message_2, sizeof(message));
    message[0] ^= 1u;
    expect_verification(&provider, message, sizeof(message), wycheproof_public_key,
                        wycheproof_signature_2, RAMPART_ERR_SIGNATURE, "tampered message");
    (void)memcpy(signature, wycheproof_signature_2, sizeof(signature));
    signature[31] ^= 1u;
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                        wycheproof_public_key, signature, RAMPART_ERR_SIGNATURE,
                        "tampered signature");
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                        other_public_key, wycheproof_signature_2, RAMPART_ERR_SIGNATURE,
                        "different valid public key");

    (void)memcpy(public_key, wycheproof_public_key, sizeof(public_key));
    public_key[0] = 0x02u;
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2), public_key,
                        wycheproof_signature_2, RAMPART_ERR_SIGNATURE, "malformed SEC1 prefix");
    fill_bytes(public_key, sizeof(public_key), 0u);
    public_key[0] = 0x04u;
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2), public_key,
                        wycheproof_signature_2, RAMPART_ERR_SIGNATURE, "point off curve");
    fill_bytes(public_key + 1u, sizeof(public_key) - 1u, 0xFFu);
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2), public_key,
                        wycheproof_signature_2, RAMPART_ERR_SIGNATURE, "coordinates out of range");
    (void)memcpy(public_key, wycheproof_public_key, sizeof(public_key));
    public_key[64] ^= 1u;
    expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2), public_key,
                        wycheproof_signature_2, RAMPART_ERR_SIGNATURE, "tampered public point");

    for (scalar_offset = 0u; scalar_offset < sizeof(signature); scalar_offset += 32u) {
        (void)memcpy(signature, wycheproof_signature_2, sizeof(signature));
        fill_bytes(signature + scalar_offset, 32u, 0u);
        expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                            wycheproof_public_key, signature, RAMPART_ERR_SIGNATURE, "zero scalar");
        (void)memcpy(signature + scalar_offset, p256_order, sizeof(p256_order));
        expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                            wycheproof_public_key, signature, RAMPART_ERR_SIGNATURE, "scalar n");
        signature[scalar_offset + 31u] = (uint8_t)(signature[scalar_offset + 31u] - 1u);
        expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                            wycheproof_public_key, signature, RAMPART_ERR_SIGNATURE, "scalar n-1");
        fill_bytes(signature + scalar_offset, 32u, 0xFFu);
        expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                            wycheproof_public_key, signature, RAMPART_ERR_SIGNATURE,
                            "scalar greater than n");
    }
}

static void test_signature_backend_failure(void) {
    OSSL_LIB_CTX *library_context = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *null_provider = NULL;
    struct rampart_host_openssl_context context = {.library_context = library_context};
    const struct rampart_crypto_provider provider = rampart_host_openssl_provider(&context);

    EXPECT_TRUE_NAMED(library_context != NULL, "signature isolated context");
    if (library_context == NULL) {
        return;
    }
    null_provider = OSSL_PROVIDER_load(library_context, "null");
    EXPECT_TRUE_NAMED(null_provider != NULL, "signature null provider");
    if (null_provider != NULL) {
        expect_verification(&provider, wycheproof_message_2, sizeof(wycheproof_message_2),
                            wycheproof_public_key, wycheproof_signature_2,
                            RAMPART_ERR_CRYPTO_PROVIDER, "signature backend unavailable");
        (void)OSSL_PROVIDER_unload(null_provider);
    }
    OSSL_LIB_CTX_free(library_context);
}

int main(void) {
    test_signature_vectors_and_mutations();
    test_signature_backend_failure();
    test_known_answer_digests();
    test_dispatch_rejects_invalid_input_without_output();
    test_backend_failure_preserves_output_and_error_queue();

    if (failures != 0) {
        (void)fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
