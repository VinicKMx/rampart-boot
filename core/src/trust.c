#include "rampart/trust.h"

#include <stdbool.h>

static bool key_ids_equal(const uint8_t *left, const uint8_t *right) {
    size_t index = 0u;

    for (index = 0u; index < RAMPART_KEY_ID_SIZE; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

static bool valid_record_shape(const struct rampart_trust_record *record) {
    return (record->algorithm == RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) &&
           (record->public_key[0] == 0x04u) && (record->roles != 0u) &&
           ((record->roles & ~RAMPART_TRUST_ROLES_ALL) == 0u) &&
           ((record->status == RAMPART_TRUST_KEY_TRUSTED) ||
            (record->status == RAMPART_TRUST_KEY_REVOKED) ||
            (record->status == RAMPART_TRUST_KEY_EXPIRED) ||
            (record->status == RAMPART_TRUST_KEY_DEVELOPMENT_ONLY));
}

rampart_status_t rampart_trust_store_validate(const struct rampart_trust_store *store,
                                              const struct rampart_crypto_provider *provider) {
    size_t index = 0u;
    size_t previous = 0u;
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE];

    if ((store == NULL) || (provider == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }
    if ((store->records == NULL) || (store->count == 0u) ||
        (store->count > RAMPART_TRUST_STORE_MAX_KEYS)) {
        return RAMPART_ERR_TRUST_STORE;
    }
    for (index = 0u; index < store->count; ++index) {
        const struct rampart_trust_record *record = &store->records[index];
        rampart_status_t status = RAMPART_OK;

        if (!valid_record_shape(record)) {
            return RAMPART_ERR_TRUST_STORE;
        }
        status = rampart_crypto_hash(provider, RAMPART_HASH_ALGORITHM_SHA256, record->public_key,
                                     sizeof(record->public_key), digest, sizeof(digest));
        if (status != RAMPART_OK) {
            return status;
        }
        if (!key_ids_equal(record->key_id, digest)) {
            return RAMPART_ERR_TRUST_STORE;
        }
        for (previous = 0u; previous < index; ++previous) {
            if (key_ids_equal(record->key_id, store->records[previous].key_id)) {
                return RAMPART_ERR_TRUST_STORE;
            }
        }
    }
    return RAMPART_OK;
}

static bool valid_role(uint16_t role) {
    return (role == RAMPART_KEY_ROLE_RELEASE) || (role == RAMPART_KEY_ROLE_SECURITY) ||
           (role == RAMPART_KEY_ROLE_BOOT_MANAGER) || (role == RAMPART_KEY_ROLE_RECOVERY) ||
           (role == RAMPART_KEY_ROLE_FACTORY) || (role == RAMPART_KEY_ROLE_DEVELOPMENT);
}

rampart_status_t rampart_trust_authorize(const struct rampart_trust_store *store,
                                         const struct rampart_crypto_provider *provider,
                                         const struct rampart_trust_request *request,
                                         struct rampart_trust_result *result) {
    const struct rampart_trust_record *matched = NULL;
    rampart_status_t status = RAMPART_OK;
    size_t index = 0u;

    if ((store == NULL) || (provider == NULL) || (request == NULL) || (result == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }
    if ((request->key_id == NULL) || (request->key_id_len != RAMPART_KEY_ID_SIZE) ||
        !valid_role(request->required_role) || !valid_role(request->manifest_role) ||
        ((request->lifecycle != RAMPART_LIFECYCLE_DEVELOPMENT) &&
         (request->lifecycle != RAMPART_LIFECYCLE_PRODUCTION))) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }
    status = rampart_trust_store_validate(store, provider);
    if (status != RAMPART_OK) {
        return status;
    }
    for (index = 0u; index < store->count; ++index) {
        if (key_ids_equal(store->records[index].key_id, request->key_id)) {
            matched = &store->records[index];
            break; /* Validation has already proved every ID unique. */
        }
    }
    if (matched == NULL) {
        return RAMPART_ERR_KEY_UNKNOWN;
    }
    if (matched->status == RAMPART_TRUST_KEY_REVOKED) {
        return RAMPART_ERR_KEY_REVOKED;
    }
    if (matched->status == RAMPART_TRUST_KEY_EXPIRED) {
        return RAMPART_ERR_KEY_EXPIRED;
    }
    if ((request->lifecycle == RAMPART_LIFECYCLE_PRODUCTION) &&
        ((matched->status == RAMPART_TRUST_KEY_DEVELOPMENT_ONLY) ||
         (request->required_role == RAMPART_KEY_ROLE_DEVELOPMENT))) {
        return RAMPART_ERR_KEY_LIFECYCLE;
    }
    if ((request->manifest_role != request->required_role) ||
        ((matched->roles & (UINT32_C(1) << request->required_role)) == 0u)) {
        return RAMPART_ERR_KEY_ROLE;
    }
    result->record = matched;
    return RAMPART_OK;
}
