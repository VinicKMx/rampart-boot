# STM32U585 Memory Map

This is the initial minimal build map used by the foundation checkpoint. It is not the final
production layout.

## Minimal build linker map

```text
FLASH  0x08000000  64 KiB
RAM    0x20000000  32 KiB
```

The minimal linker script exists only to prove that Stage 0 and Stage 1 freestanding images compile
for Cortex-M33. The final STM32U585 layout must reserve separate regions for:

- protected Stage 0;
- Stage 1A;
- Stage 1B;
- Application A;
- Application B;
- Recovery Capsule;
- Boot Journal;
- Transaction Metadata;
- Trust Metadata;
- Crash Evidence.

## Production constraints

The final map must document protection boundaries, erase granularity, write granularity, TrustZone
attribution, monotonic storage, and any irreversible provisioning assumptions.

