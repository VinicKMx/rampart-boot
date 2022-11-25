#ifndef RAMPART_STAGE0_H
#define RAMPART_STAGE0_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rampart/status.h"

#ifdef __cplusplus
extern "C" {
#endif

enum rampart_stage1_slot_state {
    RAMPART_STAGE1_SLOT_EMPTY = 0,
    RAMPART_STAGE1_SLOT_CONFIRMED,
    RAMPART_STAGE1_SLOT_TRIAL,
    RAMPART_STAGE1_SLOT_REJECTED,
    RAMPART_STAGE1_SLOT_INVALID
};

enum rampart_stage0_decision_reason {
    RAMPART_STAGE0_DECISION_TRIAL_STAGE1 = 0,
    RAMPART_STAGE0_DECISION_CONFIRMED_STAGE1
};

struct rampart_stage0_stage1_candidate {
    uint32_t slot_id;
    enum rampart_stage1_slot_state state;
    bool authenticated;
    uint32_t security_epoch;
    uintptr_t image_base;
    size_t image_size;
    uintptr_t entry_point;
    uint32_t trial_attempt;
    uint32_t max_trial_attempts;
};

struct rampart_stage0_decision {
    uint32_t selected_slot_id;
    uintptr_t entry_point;
    enum rampart_stage0_decision_reason reason;
};

rampart_status_t
rampart_stage0_select_stage1(const struct rampart_stage0_stage1_candidate *candidates,
                             size_t candidate_count, uint32_t minimum_security_epoch,
                             struct rampart_stage0_decision *decision);

#ifdef __cplusplus
}
#endif

#endif
