#include "rampart/status.h"

const char *rampart_status_string(rampart_status_t status) {
    switch (status) {
    case RAMPART_OK:
        return "ok";
    case RAMPART_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case RAMPART_ERR_BOUNDS:
        return "bounds error";
    case RAMPART_ERR_OVERFLOW:
        return "integer overflow";
    case RAMPART_ERR_IMAGE_FORMAT:
        return "image format error";
    case RAMPART_ERR_MANIFEST_FORMAT:
        return "manifest format error";
    case RAMPART_ERR_SIGNATURE:
        return "signature error";
    case RAMPART_ERR_KEY_REVOKED:
        return "key revoked";
    case RAMPART_ERR_SECURITY_EPOCH:
        return "security epoch rejected";
    case RAMPART_ERR_TARGET_MISMATCH:
        return "target mismatch";
    case RAMPART_ERR_SLOT_INVALID:
        return "invalid slot";
    case RAMPART_ERR_TRANSACTION_CORRUPT:
        return "transaction metadata corrupt";
    case RAMPART_ERR_HEALTH_FAILED:
        return "health contract failed";
    case RAMPART_ERR_NO_BOOTABLE_IMAGE:
        return "no bootable image";
    case RAMPART_ERR_INTERNAL:
        return "internal error";
    case RAMPART_ERR_UNSUPPORTED_ALGORITHM:
        return "unsupported algorithm";
    case RAMPART_ERR_CRYPTO_PROVIDER:
        return "crypto provider failure";
    default:
        return "unknown error";
    }
}
