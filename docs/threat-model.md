# Threat Model

This document defines the security boundary for Rampart Boot. It is intentionally conservative:
when Rampart cannot prove that a boot or update decision is authorized, compatible, and recoverable,
the decision must fail closed.

## Security Scope

Rampart protects the firmware lifecycle from artifact intake to final boot acceptance. Its scope
includes:

- artifact structure validation;
- firmware authentication;
- target binding;
- security epoch enforcement;
- boot and recovery selection;
- persistent slot and transaction metadata;
- trial boot state;
- health evidence used for commit decisions;
- forensic boot journal records;
- trust-store authorization and revocation policy.

Rampart is transport-agnostic. The downloader may use HTTPS, BLE, USB, UART, CAN, Ethernet, LoRa,
or removable media, but transport authenticity is not a substitute for signed firmware artifacts.

## Protected Assets

The primary assets are:

- Stage 0 executable root of trust;
- authenticated Stage 1 boot manager images;
- authenticated application and recovery artifacts;
- trusted public keys and their roles;
- key revocation state;
- trusted security epoch state;
- persistent slot lifecycle state;
- transaction commit records;
- health contract evidence;
- crash evidence;
- boot journal records;
- platform protection configuration.

Private firmware-signing keys are outside the device and must never be stored in Rampart firmware.

## Trust Boundaries

Rampart treats these inputs as untrusted until validated:

- downloaded artifact bytes;
- manifests and bundles;
- staged flash contents;
- update offsets, sizes, and chunk metadata;
- non-protected persistent metadata;
- host-provided device commands;
- application-reported health events;
- reset reason data that is not protected by the platform;
- physical-presence signals until sampled through the platform abstraction layer.

Rampart treats these as trusted only when the platform provides the required protection:

- Stage 0 storage after write protection is enabled;
- immutable or protected device identity;
- monotonic counters or equivalent anti-rollback storage;
- secure-world metadata on TrustZone-capable platforms;
- platform crypto backends and their verified results.

## Attacker Capabilities

Assume an attacker can:

- control the firmware download server;
- control the OTA channel;
- replace firmware artifacts;
- modify bytes in transit or storage;
- send arbitrary images;
- send malformed manifests and bundles;
- replay old but still signed images;
- truncate downloads;
- repeat fragments;
- reorder fragments;
- cause resets;
- cause power loss during any relevant write;
- corrupt unprotected flash;
- manipulate unauthenticated metadata;
- attempt integer overflows and underflows;
- manipulate offsets and sizes;
- attack parsers with malformed input;
- attempt cross-device firmware installation;
- attempt firmware for another hardware revision;
- attempt component substitution inside a bundle;
- present unknown key IDs;
- use keys with insufficient roles;
- use keys that have been revoked or expired;
- present development artifacts to production-locked devices;
- attempt to advance or reduce the trusted security epoch incorrectly;
- attempt to fill or corrupt the journal;
- attempt to forge health evidence from non-secure application code;
- induce resets between validation and jump;
- induce failures during security decisions.

## Security Goals

Rampart must ensure:

- unauthenticated application firmware is not executed;
- unauthenticated Stage 1 firmware is not executed;
- artifacts intended for another vendor, product, hardware family, or component are rejected;
- partially written images are never bootable;
- old firmware below the trusted security epoch is rejected;
- revoked keys never authorize a new boot;
- keys cannot authorize operations outside their roles;
- corrupted metadata leads to conservative behavior;
- parser failures are fail-closed;
- trial firmware cannot irreversibly destroy confirmed fallback before commit;
- irreversible epoch advancement cannot occur before the system is ready to abandon older firmware;
- recovery continues to require authenticated artifacts;
- after power loss, the device can reconstruct state from valid persistent records;
- significant boot decisions leave forensic evidence.

## Non-Goals

Rampart does not attempt to be:

- a network OTA protocol;
- a TLS replacement;
- an RTOS;
- a secure element;
- a hardware security module;
- a custom cryptographic primitive implementation;
- a complete physical tamper-resistance solution.

## Out of Scope

Rampart does not currently promise complete resistance to:

- decapsulation;
- FIB editing;
- laser fault injection;
- high-end EM glitching;
- laboratory power analysis;
- advanced invasive probing;
- physical chip replacement.

Fault-injection hardening is part of the security strategy, but physical attack resistance must not
be claimed without target-specific evidence.

## Attack Surface

Security-sensitive attack surfaces include:

- image and bundle parsers;
- manifest signed-region calculation;
- payload digest calculation;
- signature verification result handling;
- target compatibility checks;
- security epoch comparison;
- trust-store lookup and mutation;
- slot metadata recovery;
- transaction commit records;
- journal append and recovery;
- health report handling;
- recovery authorization;
- Stage 1 selection by Stage 0;
- final jump validation.

Each surface must have explicit bounds checks, error handling, and fail-closed behavior.

## Required Responses

| Threat | Required Rampart response | Related invariants |
| --- | --- | --- |
| Unsigned or incorrectly signed application | Reject and select authenticated fallback or recovery | INV-001, INV-010 |
| Unsigned or incorrectly signed Stage 1 | Stage 0 rejects and selects another authenticated Stage 1 or recovery | INV-002, INV-010 |
| Artifact for another target | Reject before installation or boot eligibility | INV-003, INV-011 |
| Partially staged image | Keep non-bootable until final authentication succeeds | INV-004, INV-012, INV-013 |
| Old signed firmware below trusted epoch | Reject as a security downgrade | INV-007, INV-010 |
| Power loss during persistent update | Reconstruct one authoritative state after reboot | INV-014, INV-015, INV-016 |
| Trial image fails health contract | Reject candidate, preserve fallback, record evidence | INV-005, INV-006, INV-016 |
| Revoked key presented | Reject authorization | INV-017 |
| Key lacks required role | Reject authorization | INV-018 |
| Corrupted metadata | Ignore invalid record and choose conservative path | INV-009, INV-015 |
| Journal corruption | Recover valid prefix or compacted state without trusting corrupted data | INV-014, INV-015 |
| Recovery override without policy | Reject unless authenticated and authorized by recovery policy | INV-010, INV-018 |

## Power-Loss Model

Power loss may occur:

- before or after any flash erase;
- before or after any flash program operation;
- between journal records;
- during staging;
- during verification;
- during trial transition;
- during confirmation;
- during rollback;
- during Stage 1 update;
- during trust-store update;
- during security epoch advancement.

The persistent representation must allow reboot-time reconstruction from valid records only. Power
loss must not create a confirmed image, erase the only authenticated boot path, or create two
authoritative transaction commits.

## Transport Security

TLS authenticates transport. Rampart authenticates firmware. Firmware artifacts remain signed even
when downloaded over HTTPS.
