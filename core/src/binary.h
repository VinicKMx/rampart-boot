#ifndef RAMPART_BINARY_H
#define RAMPART_BINARY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rampart/status.h"

bool rampart_binary_bytes_equal(const uint8_t *left, const uint8_t *right, size_t len);

bool rampart_binary_bytes_match(const uint8_t *left, const char *right, size_t len);

bool rampart_binary_all_zeroes(const uint8_t *bytes, size_t len);

bool rampart_binary_range_available(size_t offset, size_t len, size_t total_len, size_t *end);

rampart_status_t rampart_binary_checked_add_size(size_t left, size_t right, size_t *out);

rampart_status_t rampart_binary_read_u16_le(const uint8_t *bytes, size_t len, size_t offset,
                                            uint16_t *out);

rampart_status_t rampart_binary_read_u32_le(const uint8_t *bytes, size_t len, size_t offset,
                                            uint32_t *out);

#endif
