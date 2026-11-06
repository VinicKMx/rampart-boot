#ifndef RAMPART_TRUST_H
#define RAMPART_TRUST_H

#include <stddef.h>
#include <stdint.h>

#include "rampart/crypto.h"
#include "rampart/manifest.h"
#include "rampart/status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_TRUST_STORE_MAX_KEYS (16u)

#define RAMPART_TRUST_ROLE_RELEASE (UINT32_C(1) << RAMPART_KEY_ROLE_RELEASE)
#define RAMPART_TRUST_ROLE_SECURITY (UINT32_C(1) << RAMPART_KEY_ROLE_SECURITY)
#define RAMPART_TRUST_ROLE_BOOT_MANAGER (UINT32_C(1) << RAMPART_KEY_ROLE_BOOT_MANAGER)
#define RAMPART_TRUST_ROLE_RECOVERY (UINT32_C(1) << RAMPART_KEY_ROLE_RECOVERY)
#define RAMPART_TRUST_ROLE_FACTORY (UINT32_C(1) << RAMPART_KEY_ROLE_FACTORY)
#define RAMPART_TRUST_ROLE_DEVELOPMENT (UINT32_C(1) << RAMPART_KEY_ROLE_DEVELOPMENT)
#define RAMPART_TRUST_ROLES_ALL                                                                    \
    (RAMPART_TRUST_ROLE_RELEASE | RAMPART_TRUST_ROLE_SECURITY | RAMPART_TRUST_ROLE_BOOT_MANAGER |  \
     RAMPART_TRUST_ROLE_RECOVERY | RAMPART_TRUST_ROLE_FACTORY | RAMPART_TRUST_ROLE_DEVELOPMENT)

typedef uint16_t rampart_trust_key_status_t;

#define RAMPART_TRUST_KEY_TRUSTED (1u)
#define RAMPART_TRUST_KEY_REVOKED (2u)
#define RAMPART_TRUST_KEY_EXPIRED (3u)
#define RAMPART_TRUST_KEY_DEVELOPMENT_ONLY (4u)

/* Provisioned in-memory record, not a persistent encoding. Epoch is not enforced. */
struct rampart_trust_record {
    uint32_t roles;
    uint32_t key_epoch;
    rampart_signature_algorithm_t algorithm;
    rampart_trust_key_status_t status;
    uint8_t key_id[RAMPART_KEY_ID_SIZE];
    uint8_t public_key[RAMPART_PUBLIC_KEY_P256_SEC1_SIZE];
};

/* Caller owns the complete array; keep it valid and immutable while in use. */
struct rampart_trust_store {
    const struct rampart_trust_record *records;
    size_t count;
};

/* Validate all records and derived IDs; success alone authorizes no operation. */
rampart_status_t rampart_trust_store_validate(const struct rampart_trust_store *store,
                                              const struct rampart_crypto_provider *provider);

typedef uint16_t rampart_device_lifecycle_t;

#define RAMPART_LIFECYCLE_DEVELOPMENT (1u)
#define RAMPART_LIFECYCLE_PRODUCTION (2u)

struct rampart_trust_request {
    const uint8_t *key_id;
    size_t key_id_len;
    uint16_t required_role;
    uint16_t manifest_role;
    rampart_device_lifecycle_t lifecycle;
};

struct rampart_trust_result {
    const struct rampart_trust_record *record;
};

/* Revalidate the whole store; publish only on success. The result borrows a
 * record whose caller-owned storage must remain valid and immutable in use.
 * Required role comes from device policy, never from the manifest alone.
 * All inputs remain immutable during the call; result storage is separate.
 * Authority for one role alone is not image authentication or boot eligibility.
 */
rampart_status_t rampart_trust_authorize(const struct rampart_trust_store *store,
                                         const struct rampart_crypto_provider *provider,
                                         const struct rampart_trust_request *request,
                                         struct rampart_trust_result *result);

#ifdef __cplusplus
}
#endif

#endif
