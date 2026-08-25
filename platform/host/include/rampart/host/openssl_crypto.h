#ifndef RAMPART_HOST_OPENSSL_CRYPTO_H
#define RAMPART_HOST_OPENSSL_CRYPTO_H

#include <openssl/types.h>

#include "rampart/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rampart_host_openssl_context {
    OSSL_LIB_CTX *library_context;
};

struct rampart_crypto_provider
rampart_host_openssl_provider(struct rampart_host_openssl_context *context);

#ifdef __cplusplus
}
#endif

#endif
