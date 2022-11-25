#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "rampart/manifest.h"
#include "rampart/stage0.h"
#include "rampart/status.h"
#include "rampart/target.h"

static int failures = 0;

#define EXPECT_TRUE(expression)                                                                    \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            (void)fprintf(stderr, "%s:%d: expected true: %s\n", __FILE__, __LINE__, #expression);  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

#define EXPECT_STATUS(expected, expression)                                                        \
    do {                                                                                           \
        rampart_status_t actual_status = (expression);                                             \
        if (actual_status != (expected)) {                                                         \
            (void)fprintf(stderr, "%s:%d: expected %s, got %s\n", __FILE__, __LINE__,              \
                          rampart_status_string(expected), rampart_status_string(actual_status));  \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

static struct rampart_target_id test_device_target(void) {
    const struct rampart_target_id target = {
        .vendor_id = 0x52414D50u,
        .product_id = 0x00000001u,
        .hardware_family = 0x00000585u,
        .component_id = 0x00000010u,
    };

    return target;
}

static void test_target_binding_rejects_cross_product_artifact(void) {
    const struct rampart_target_id device = test_device_target();
    struct rampart_target_id artifact = test_device_target();

    EXPECT_TRUE(rampart_target_matches(&artifact, &device));

    artifact.product_id = 0x00000002u;
    EXPECT_STATUS(RAMPART_ERR_TARGET_MISMATCH, rampart_target_validate_binding(&artifact, &device));
}

static void test_manifest_basic_validation_enforces_epoch_and_digest_shape(void) {
    const struct rampart_target_id device = test_device_target();
    const uint8_t digest[RAMPART_SHA256_DIGEST_SIZE] = {0u};
    struct rampart_manifest_view manifest = {
        .format_version = RAMPART_MANIFEST_FORMAT_VERSION_1,
        .target = device,
        .security_epoch = 12u,
        .payload_size = 4096u,
        .payload_digest = digest,
        .payload_digest_len = sizeof(digest),
    };

    EXPECT_STATUS(RAMPART_OK, rampart_manifest_validate_basic(&manifest, &device, 12u));

    manifest.security_epoch = 11u;
    EXPECT_STATUS(RAMPART_ERR_SECURITY_EPOCH,
                  rampart_manifest_validate_basic(&manifest, &device, 12u));

    manifest.security_epoch = 12u;
    manifest.payload_digest_len = RAMPART_SHA256_DIGEST_SIZE - 1u;
    EXPECT_STATUS(RAMPART_ERR_MANIFEST_FORMAT,
                  rampart_manifest_validate_basic(&manifest, &device, 12u));
}

static void test_stage0_prefers_eligible_trial_stage1_then_fallback(void) {
    struct rampart_stage0_stage1_candidate candidates[2] = {
        {
            .slot_id = 0u,
            .state = RAMPART_STAGE1_SLOT_CONFIRMED,
            .authenticated = true,
            .security_epoch = 7u,
            .image_base = 0x08010000u,
            .image_size = 32768u,
            .entry_point = 0x08010101u,
            .trial_attempt = 0u,
            .max_trial_attempts = 0u,
        },
        {
            .slot_id = 1u,
            .state = RAMPART_STAGE1_SLOT_TRIAL,
            .authenticated = true,
            .security_epoch = 8u,
            .image_base = 0x08020000u,
            .image_size = 32768u,
            .entry_point = 0x08020101u,
            .trial_attempt = 0u,
            .max_trial_attempts = 3u,
        },
    };
    struct rampart_stage0_decision decision = {0u};

    EXPECT_STATUS(RAMPART_OK, rampart_stage0_select_stage1(candidates, 2u, 7u, &decision));
    EXPECT_TRUE(decision.selected_slot_id == 1u);
    EXPECT_TRUE(decision.reason == RAMPART_STAGE0_DECISION_TRIAL_STAGE1);

    candidates[1].trial_attempt = 3u;
    EXPECT_STATUS(RAMPART_OK, rampart_stage0_select_stage1(candidates, 2u, 7u, &decision));
    EXPECT_TRUE(decision.selected_slot_id == 0u);
    EXPECT_TRUE(decision.reason == RAMPART_STAGE0_DECISION_CONFIRMED_STAGE1);

    candidates[0].authenticated = false;
    EXPECT_STATUS(RAMPART_ERR_NO_BOOTABLE_IMAGE,
                  rampart_stage0_select_stage1(candidates, 2u, 7u, &decision));
}

int main(void) {
    test_target_binding_rejects_cross_product_artifact();
    test_manifest_basic_validation_enforces_epoch_and_digest_shape();
    test_stage0_prefers_eligible_trial_stage1_then_fallback();

    if (failures != 0) {
        (void)fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
