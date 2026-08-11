#include "rampart/stage1.h"

void rampart_platform_reset_entry(void);

void rampart_platform_reset_entry(void) {
    (void)rampart_stage1_main();

    for (;;) {
    }
}
