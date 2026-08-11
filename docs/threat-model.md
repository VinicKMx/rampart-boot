# Threat Model

This document records the initial Rampart Boot threat model. It is intentionally conservative and
will be updated as implementation details become concrete.

## Attacker capabilities

Assume an attacker can:

- control the firmware download server;
- control the OTA channel;
- replace firmware artifacts;
- modify bytes in transit or storage;
- send arbitrary images;
- send malformed manifests;
- replay old but still signed images;
- truncate downloads;
- repeat fragments;
- cause resets;
- cause power loss during any relevant write;
- corrupt unprotected flash;
- manipulate unauthenticated metadata;
- attempt integer overflows and underflows;
- manipulate offsets and sizes;
- attack parsers with malformed input;
- attempt cross-device firmware installation;
- attempt firmware for another hardware revision;
- present unknown key IDs;
- use a key that has been revoked;
- induce failures during security decisions.

## Security goals

Rampart should ensure:

- unauthenticated application firmware is not executed;
- unauthenticated Stage 1 firmware is not executed;
- artifacts intended for another vendor, product, hardware family, or component are rejected;
- old firmware below the trusted security epoch is rejected;
- corrupted metadata leads to conservative behavior;
- parser failures are fail-closed;
- trial firmware cannot irreversibly destroy confirmed fallback before commit;
- recovery continues to require authenticated artifacts.

## Out of scope

Rampart does not currently promise complete resistance to:

- decapsulation;
- FIB editing;
- laser fault injection;
- high-end EM glitching;
- laboratory power analysis;
- advanced invasive probing;
- physical chip replacement.

Fault-injection hardening is part of the roadmap, but physical attack resistance must not be claimed
without target-specific evidence.

## Transport security

TLS authenticates transport. Rampart authenticates firmware. Firmware artifacts remain signed even
when downloaded over HTTPS.

