#ifndef RAMPART_TARGET_H
#define RAMPART_TARGET_H

#include <stdbool.h>
#include <stdint.h>

#include "rampart/status.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rampart_target_id {
    uint32_t vendor_id;
    uint32_t product_id;
    uint32_t hardware_family;
    uint32_t component_id;
};

bool rampart_target_matches(const struct rampart_target_id *artifact_target,
                            const struct rampart_target_id *device_target);

rampart_status_t rampart_target_validate_binding(const struct rampart_target_id *artifact_target,
                                                 const struct rampart_target_id *device_target);

#ifdef __cplusplus
}
#endif

#endif
