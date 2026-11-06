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
