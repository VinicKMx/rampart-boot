#include "rampart/host/openssl_crypto.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecerr.h>
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

/* Only input-decoding failures are ordinary signature rejection. */
static rampart_status_t key_import_failure(void) {
    const unsigned long error = ERR_peek_last_error();
    const int reason = ERR_GET_REASON(error);

    if ((ERR_GET_LIB(error) == ERR_LIB_EC) &&
        ((reason == EC_R_POINT_IS_NOT_ON_CURVE) || (reason == EC_R_INVALID_ENCODING) ||
         (reason == EC_R_COORDINATES_OUT_OF_RANGE))) {
        return RAMPART_ERR_SIGNATURE;
    }
    return RAMPART_ERR_CRYPTO_PROVIDER;
}

static rampart_status_t openssl_verify(void *context, const uint8_t *message, size_t message_len,
                                       const uint8_t *public_key, const uint8_t *signature) {
    static const uint8_t empty_message = 0u;
    const struct rampart_host_openssl_context *openssl_context = context;
    OSSL_LIB_CTX *library_context = NULL;
    EVP_PKEY_CTX *key_context = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *digest_context = NULL;
    ECDSA_SIG *ecdsa_signature = NULL;
    BIGNUM *scalar_r = NULL;
    BIGNUM *scalar_s = NULL;
    BIGNUM *order = NULL;
    char group[] = "P-256";
    /* OSSL_PARAM's import API takes mutable storage but does not modify it. */
    uint8_t encoded_key[RAMPART_PUBLIC_KEY_P256_SEC1_SIZE];
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0u),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, encoded_key, sizeof(encoded_key)),
        OSSL_PARAM_END,
    };
    uint8_t der[72u]; /* Maximum DER size of two unsigned 256-bit INTEGERs. */
    unsigned char *der_cursor = der;
    rampart_status_t status = RAMPART_ERR_CRYPTO_PROVIDER;
    int der_len = 0;
    int result = 0;
    int error_mark_set = 0;
    size_t index = 0u;

    if ((public_key == NULL) || (signature == NULL) || ((message == NULL) && (message_len != 0u))) {
        return RAMPART_ERR_CRYPTO_PROVIDER;
    }
    if (public_key[0] != 0x04u) {
        return RAMPART_ERR_SIGNATURE;
    }
    if (openssl_context != NULL) {
        library_context = openssl_context->library_context;
    }
    if (message == NULL) {
        message = &empty_message;
    }
    for (index = 0u; index < sizeof(encoded_key); ++index) {
        encoded_key[index] = public_key[index];
    }

    error_mark_set = ERR_set_mark();
    key_context = EVP_PKEY_CTX_new_from_name(library_context, "EC", NULL);
    if ((key_context == NULL) || (EVP_PKEY_fromdata_init(key_context) != 1)) {
        goto cleanup;
    }
    if (EVP_PKEY_fromdata(key_context, &key, EVP_PKEY_PUBLIC_KEY, parameters) != 1) {
        status = key_import_failure();
        goto cleanup;
    }
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_ORDER, &order) != 1) {
        goto cleanup;
    }
    scalar_r = BN_bin2bn(signature, 32, NULL);
    scalar_s = BN_bin2bn(signature + 32u, 32, NULL);
    if ((scalar_r == NULL) || (scalar_s == NULL)) {
        goto cleanup;
    }
    if (BN_is_zero(scalar_r) || BN_is_zero(scalar_s) || (BN_cmp(scalar_r, order) >= 0) ||
        (BN_cmp(scalar_s, order) >= 0)) {
        status = RAMPART_ERR_SIGNATURE;
        goto cleanup;
    }
    ecdsa_signature = ECDSA_SIG_new();
    if ((ecdsa_signature == NULL) || (ECDSA_SIG_set0(ecdsa_signature, scalar_r, scalar_s) != 1)) {
        goto cleanup;
    }
    scalar_r = NULL; /* Ownership transferred only after successful set0. */
    scalar_s = NULL;
    der_len = i2d_ECDSA_SIG(ecdsa_signature, NULL);
    if ((der_len <= 0) || ((size_t)der_len > sizeof(der)) ||
        (i2d_ECDSA_SIG(ecdsa_signature, &der_cursor) != der_len)) {
        goto cleanup;
    }
    digest_context = EVP_MD_CTX_new();
    if ((digest_context == NULL) ||
        (EVP_DigestVerifyInit_ex(digest_context, NULL, "SHA256", library_context, NULL, key,
                                 NULL) != 1)) {
        goto cleanup;
    }
    result = EVP_DigestVerify(digest_context, der, (size_t)der_len, message, message_len);
    if (result == 1) {
        status = RAMPART_OK;
    } else if (result == 0) {
        status = RAMPART_ERR_SIGNATURE;
    }

cleanup:
    EVP_MD_CTX_free(digest_context);
    ECDSA_SIG_free(ecdsa_signature);
    BN_free(scalar_r);
    BN_free(scalar_s);
    BN_free(order);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_context);
    discard_provider_errors(error_mark_set);
    return status;
}

struct rampart_crypto_provider
rampart_host_openssl_provider(struct rampart_host_openssl_context *context) {
    const struct rampart_crypto_provider provider = {
        .context = context,
        .sha256 = openssl_sha256,
        .verify_ecdsa_p256_sha256 = openssl_verify,
    };

    return provider;
}
