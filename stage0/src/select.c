#include "rampart/stage0.h"

static bool
candidate_has_executable_shape(const struct rampart_stage0_stage1_candidate *candidate) {
    return (candidate->authenticated && (candidate->image_base != 0u) &&
            (candidate->image_size != 0u) && (candidate->entry_point != 0u));
}

static bool candidate_is_eligible_trial(const struct rampart_stage0_stage1_candidate *candidate,
                                        uint32_t minimum_security_epoch) {
    return candidate_has_executable_shape(candidate) &&
           (candidate->state == RAMPART_STAGE1_SLOT_TRIAL) &&
           (candidate->security_epoch >= minimum_security_epoch) &&
           (candidate->trial_attempt < candidate->max_trial_attempts);
}

static bool candidate_is_eligible_confirmed(const struct rampart_stage0_stage1_candidate *candidate,
                                            uint32_t minimum_security_epoch) {
    return candidate_has_executable_shape(candidate) &&
           (candidate->state == RAMPART_STAGE1_SLOT_CONFIRMED) &&
           (candidate->security_epoch >= minimum_security_epoch);
}

static bool candidate_is_preferred(const struct rampart_stage0_stage1_candidate *candidate,
                                   const struct rampart_stage0_stage1_candidate *current_best) {
    if (current_best == NULL) {
        return true;
    }

    if (candidate->security_epoch > current_best->security_epoch) {
        return true;
    }

    if (candidate->security_epoch < current_best->security_epoch) {
        return false;
    }

    return candidate->slot_id < current_best->slot_id;
}

static const struct rampart_stage0_stage1_candidate *
select_trial(const struct rampart_stage0_stage1_candidate *candidates, size_t candidate_count,
             uint32_t minimum_security_epoch) {
    const struct rampart_stage0_stage1_candidate *best = NULL;

    for (size_t index = 0u; index < candidate_count; ++index) {
        const struct rampart_stage0_stage1_candidate *candidate = &candidates[index];

        if (candidate_is_eligible_trial(candidate, minimum_security_epoch) &&
            candidate_is_preferred(candidate, best)) {
            best = candidate;
        }
    }

    return best;
}

static const struct rampart_stage0_stage1_candidate *
select_confirmed(const struct rampart_stage0_stage1_candidate *candidates, size_t candidate_count,
                 uint32_t minimum_security_epoch) {
    const struct rampart_stage0_stage1_candidate *best = NULL;

    for (size_t index = 0u; index < candidate_count; ++index) {
        const struct rampart_stage0_stage1_candidate *candidate = &candidates[index];

        if (candidate_is_eligible_confirmed(candidate, minimum_security_epoch) &&
            candidate_is_preferred(candidate, best)) {
            best = candidate;
        }
    }

    return best;
}

rampart_status_t
rampart_stage0_select_stage1(const struct rampart_stage0_stage1_candidate *candidates,
                             size_t candidate_count, uint32_t minimum_security_epoch,
                             struct rampart_stage0_decision *decision) {
    const struct rampart_stage0_stage1_candidate *selected = NULL;

    if ((candidates == NULL) || (decision == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (candidate_count == 0u) {
        return RAMPART_ERR_NO_BOOTABLE_IMAGE;
    }

    selected = select_trial(candidates, candidate_count, minimum_security_epoch);
    if (selected != NULL) {
        decision->selected_slot_id = selected->slot_id;
        decision->entry_point = selected->entry_point;
        decision->reason = RAMPART_STAGE0_DECISION_TRIAL_STAGE1;
        return RAMPART_OK;
    }

    selected = select_confirmed(candidates, candidate_count, minimum_security_epoch);
    if (selected != NULL) {
        decision->selected_slot_id = selected->slot_id;
        decision->entry_point = selected->entry_point;
        decision->reason = RAMPART_STAGE0_DECISION_CONFIRMED_STAGE1;
        return RAMPART_OK;
    }

    return RAMPART_ERR_NO_BOOTABLE_IMAGE;
}
