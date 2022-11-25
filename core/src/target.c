#include "rampart/target.h"

#include <stddef.h>

bool rampart_target_matches(const struct rampart_target_id *artifact_target,
                            const struct rampart_target_id *device_target) {
    if ((artifact_target == NULL) || (device_target == NULL)) {
        return false;
    }

    return (artifact_target->vendor_id == device_target->vendor_id) &&
           (artifact_target->product_id == device_target->product_id) &&
           (artifact_target->hardware_family == device_target->hardware_family) &&
           (artifact_target->component_id == device_target->component_id);
}

rampart_status_t rampart_target_validate_binding(const struct rampart_target_id *artifact_target,
                                                 const struct rampart_target_id *device_target) {
    if ((artifact_target == NULL) || (device_target == NULL)) {
        return RAMPART_ERR_INVALID_ARGUMENT;
    }

    if (!rampart_target_matches(artifact_target, device_target)) {
        return RAMPART_ERR_TARGET_MISMATCH;
    }

    return RAMPART_OK;
}
