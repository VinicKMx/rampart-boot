#include "rampart/host/openssl_crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>

static void discard_provider_errors(int error_mark_set) {
    if (error_mark_set == 0) {
        ERR_clear_error();
        return;
    }

    if (ERR_pop_to_mark() != 1) {
        ERR_clear_error();
    }
}

static rampart_status_t openssl_sha256(void *context, const uint8_t *message, size_t message_len,
                                       uint8_t digest[RAMPART_SHA256_DIGEST_SIZE]) {
    static const uint8_t empty_message = 0u;
    const struct rampart_host_openssl_context *openssl_context = context;
    OSSL_LIB_CTX *library_context = NULL;
    const void *input = message;
    size_t digest_len = 0u;
    int error_mark_set = 0;
    int result = 0;

    if ((digest == NULL) || ((message == NULL) && (message_len != 0u))) {
        return RAMPART_ERR_CRYPTO_PROVIDER;
    }

    if (openssl_context != NULL) {
        library_context = openssl_context->library_context;
    }
    if (message == NULL) {
        input = &empty_message;
    }

    error_mark_set = ERR_set_mark();
    result = EVP_Q_digest(library_context, "SHA256", NULL, input, message_len, digest, &digest_len);
    discard_provider_errors(error_mark_set);

    if ((result != 1) || (digest_len != RAMPART_SHA256_DIGEST_SIZE)) {
        return RAMPART_ERR_CRYPTO_PROVIDER;
    }

    return RAMPART_OK;
}

struct rampart_crypto_provider
rampart_host_openssl_provider(struct rampart_host_openssl_context *context) {
    const struct rampart_crypto_provider provider = {
        .context = context,
        .sha256 = openssl_sha256,
        .verify_ecdsa_p256_sha256 = NULL,
    };

    return provider;
}
