#ifndef RAMPART_CRYPTO_H
#define RAMPART_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "rampart/status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_SHA256_DIGEST_SIZE (32u)
#define RAMPART_SIGNATURE_ECDSA_P256_SIZE (64u)
#define RAMPART_PUBLIC_KEY_P256_SEC1_SIZE (65u)

typedef uint16_t rampart_hash_algorithm_t;
typedef uint16_t rampart_signature_algorithm_t;

#define RAMPART_HASH_ALGORITHM_SHA256 (1u)
#define RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 (1u)

/* Hash callbacks return RAMPART_OK only after writing the complete digest. */
typedef rampart_status_t (*rampart_crypto_sha256_fn)(void *context, const uint8_t *message,
                                                     size_t message_len,
                                                     uint8_t digest[RAMPART_SHA256_DIGEST_SIZE]);

/* Verify callbacks return RAMPART_OK, RAMPART_ERR_SIGNATURE, or provider failure. */
typedef rampart_status_t (*rampart_crypto_ecdsa_p256_sha256_verify_fn)(void *context,
                                                                       const uint8_t *message,
                                                                       size_t message_len,
                                                                       const uint8_t *public_key,
                                                                       const uint8_t *signature);

struct rampart_crypto_provider {
    void *context;
    rampart_crypto_sha256_fn sha256;
    rampart_crypto_ecdsa_p256_sha256_verify_fn verify_ecdsa_p256_sha256;
};

rampart_status_t rampart_crypto_hash(const struct rampart_crypto_provider *provider,
                                     rampart_hash_algorithm_t algorithm, const uint8_t *message,
                                     size_t message_len, uint8_t *digest, size_t digest_len);

rampart_status_t rampart_crypto_verify_signature(const struct rampart_crypto_provider *provider,
                                                 rampart_signature_algorithm_t algorithm,
                                                 const uint8_t *message, size_t message_len,
                                                 const uint8_t *public_key, size_t public_key_len,
                                                 const uint8_t *signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif
