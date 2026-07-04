#ifndef RAMPART_CRYPTO_H
#define RAMPART_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "rampart/status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_SHA256_DIGEST_SIZE (32u)

typedef uint16_t rampart_hash_algorithm_t;

#define RAMPART_HASH_ALGORITHM_SHA256 (1u)

/* Hash callbacks return RAMPART_OK only after writing the complete digest. */
typedef rampart_status_t (*rampart_crypto_sha256_fn)(void *context, const uint8_t *message,
                                                     size_t message_len,
                                                     uint8_t digest[RAMPART_SHA256_DIGEST_SIZE]);

struct rampart_crypto_provider {
    void *context;
    rampart_crypto_sha256_fn sha256;
};

rampart_status_t rampart_crypto_hash(const struct rampart_crypto_provider *provider,
                                     rampart_hash_algorithm_t algorithm, const uint8_t *message,
                                     size_t message_len, uint8_t *digest, size_t digest_len);

#ifdef __cplusplus
}
#endif

#endif
