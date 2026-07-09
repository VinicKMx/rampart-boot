#include "rampart/crypto.h"

static void copy_sha256_digest(uint8_t *destination, const uint8_t *source) {
    size_t index = 0u;

    for (index = 0u; index < RAMPART_SHA256_DIGEST_SIZE; ++index) {
        destination[index] = source[index];
    }
}

rampart_status_t rampart_crypto_hash(const struct rampart_crypto_provider *provider,
                                     rampart_hash_algorithm_t algorithm, const uint8_t *message,
                                     size_t message_len, uint8_t *digest, size_t digest_len) {
    uint8_t computed_digest[RAMPART_SHA256_DIGEST_SIZE];
    rampart_status_t status = RAMPART_OK;

    if ((provider == NULL) || (digest == NULL) || ((message == NULL) && (message_len != 0u))) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (algorithm != RAMPART_HASH_ALGORITHM_SHA256) {
        return RAMPART_ERR_UNSUPPORTED_ALGORITHM;
    }

    if (digest_len != RAMPART_SHA256_DIGEST_SIZE) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (provider->sha256 == NULL) {
        return RAMPART_ERR_CRYPTO_PROVIDER;
    }

    status = provider->sha256(provider->context, message, message_len, computed_digest);
    if (status != RAMPART_OK) {
        return RAMPART_ERR_CRYPTO_PROVIDER;
    }

    copy_sha256_digest(digest, computed_digest);
    return RAMPART_OK;
}

rampart_status_t rampart_crypto_verify_signature(const struct rampart_crypto_provider *provider,
                                                 rampart_signature_algorithm_t algorithm,
                                                 const uint8_t *message, size_t message_len,
                                                 const uint8_t *public_key, size_t public_key_len,
                                                 const uint8_t *signature, size_t signature_len) {
    rampart_status_t status = RAMPART_OK;

    if ((provider == NULL) || (public_key == NULL) || (signature == NULL) ||
        ((message == NULL) && (message_len != 0u))) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (algorithm != RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) {
        return RAMPART_ERR_UNSUPPORTED_ALGORITHM;
    }

    if ((public_key_len != RAMPART_PUBLIC_KEY_P256_SEC1_SIZE) ||
        (signature_len != RAMPART_SIGNATURE_ECDSA_P256_SIZE)) {
        return RAMPART_ERR_SIGNATURE;
    }

    if (provider->verify_ecdsa_p256_sha256 == NULL) {
        return RAMPART_ERR_CRYPTO_PROVIDER;
    }

    status = provider->verify_ecdsa_p256_sha256(provider->context, message, message_len, public_key,
                                                signature);
    if ((status == RAMPART_OK) || (status == RAMPART_ERR_SIGNATURE) ||
        (status == RAMPART_ERR_CRYPTO_PROVIDER)) {
        return status;
    }

    return RAMPART_ERR_CRYPTO_PROVIDER;
}
