#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rampart/host/openssl_crypto.h"
#include "rampart/image.h"
#include "rampart/trust.h"

/* Provisioning is an explicit test decision, not an artifact-intake policy. */
static bool provision_fixture_record(struct rampart_trust_record *record) {
    uint8_t bytes[1024u];
    struct rampart_image_view image = {0};
    FILE *file = fopen(RAMPART_TEST_VECTOR_DIR "/valid.rampart", "rb");
    size_t len = 0u;
    bool complete = false;

    if (file == NULL) {
        return false;
    }
    len = fread(bytes, 1u, sizeof(bytes), file);
    complete = (len != 0u) && (fgetc(file) == EOF) && (ferror(file) == 0);
    if (fclose(file) != 0) {
        complete = false;
    }
    if (!complete || (rampart_image_parse(bytes, len, &image) != RAMPART_OK)) {
        return false;
    }
    if ((image.manifest.key_id_len != sizeof(record->key_id)) ||
        (image.signature.public_key_len != sizeof(record->public_key))) {
        return false;
    }
    /* Copy only public material and the independent Rust-derived identifier. */
    (void)memcpy(record->key_id, image.manifest.key_id, sizeof(record->key_id));
    (void)memcpy(record->public_key, image.signature.public_key, sizeof(record->public_key));
    record->algorithm = RAMPART_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256;
    record->roles = RAMPART_TRUST_ROLE_RELEASE;
    record->status = RAMPART_TRUST_KEY_TRUSTED;
    record->key_epoch = UINT32_MAX;
    return true;
}

int main(void) {
    struct rampart_trust_record record = {0};
    const struct rampart_trust_store store = {.records = &record, .count = 1u};
    struct rampart_crypto_provider provider = rampart_host_openssl_provider(NULL);
    uint8_t digest[RAMPART_SHA256_DIGEST_SIZE];
    const struct rampart_trust_record sentinel = {0};
    struct rampart_trust_result result = {.record = &sentinel};
    const struct rampart_trust_request request = {
        .key_id = record.key_id,
        .key_id_len = sizeof(record.key_id),
        .required_role = RAMPART_KEY_ROLE_RELEASE,
        .manifest_role = RAMPART_KEY_ROLE_RELEASE,
        .lifecycle = RAMPART_LIFECYCLE_PRODUCTION,
    };

    if (!provision_fixture_record(&record)) {
        (void)fprintf(stderr, "could not provision public fixture record\n");
        return 1;
    }
    /* Store validation must need hashing only, never signature verification. */
    provider.verify_ecdsa_p256_sha256 = NULL;
    if ((rampart_crypto_hash(&provider, RAMPART_HASH_ALGORITHM_SHA256, record.public_key,
                             sizeof(record.public_key), digest, sizeof(digest)) != RAMPART_OK) ||
        (memcmp(record.key_id, digest, sizeof(record.key_id)) != 0) ||
        (rampart_trust_store_validate(&store, &provider) != RAMPART_OK)) {
        (void)fprintf(stderr, "Rust-derived fixture ID did not validate\n");
        return 1;
    }
    if ((rampart_trust_authorize(&store, &provider, &request, &result) != RAMPART_OK) ||
        (result.record != &record) || (result.record->key_epoch != UINT32_MAX)) {
        (void)fprintf(stderr, "provisioned fixture authority did not pass\n");
        return 1;
    }
    result.record = &sentinel;
    record.key_id[0] ^= 1u;
    if (rampart_trust_store_validate(&store, &provider) != RAMPART_ERR_TRUST_STORE) {
        (void)fprintf(stderr, "inconsistent fixture ID did not reject\n");
        return 1;
    }
    if ((rampart_trust_authorize(&store, &provider, &request, &result) !=
         RAMPART_ERR_TRUST_STORE) ||
        (result.record != &sentinel)) {
        (void)fprintf(stderr, "failed fixture authorization changed output\n");
        return 1;
    }
    return 0;
}
