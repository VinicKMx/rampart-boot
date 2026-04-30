# Security Policy

## Supported security scope

Rampart Boot is intended to provide a secure firmware lifecycle for embedded systems:

- firmware authentication;
- target binding;
- key roles and revocation;
- security epoch enforcement;
- power-fail-safe update state;
- trial boot and health evidence;
- forensic boot journal records;
- authenticated recovery paths.

## Unsupported claims

Rampart does not currently claim resistance against invasive physical attacks such as FIB editing,
laser fault injection, advanced EM glitching, laboratory power analysis, decapsulation, or physical
chip replacement.

Rampart also does not implement cryptographic primitives. SHA, ECDSA, Ed25519, RSA, AES, random
generation, and equivalent primitives must come from platform or library backends selected for the
target.

## Responsible disclosure

Report suspected vulnerabilities privately to the project maintainers. Include:

- affected commit or release;
- target platform, if hardware-specific;
- reproduction steps;
- expected and observed behavior;
- whether the issue can affect authentication, rollback, recovery, journal integrity, or key
  lifecycle state.

Do not publish exploit details before maintainers have had a reasonable opportunity to investigate
and prepare a fix.

## Production hardening

Production provisioning must be explicit. Development builds must not automatically burn fuses,
permanently disable debug, lock OTP, enable irreversible read protection, or perform equivalent
one-way operations.

## Known limitations

At the current checkpoint, the Rust host CLI can sign, inspect, and verify canonical v1 artifacts.
Its verifier checks the payload digest, embedded-key signature, target binding, and minimum security
epoch policy inputs. The independent C parser structurally validates canonical v1 artifacts and is
covered by deterministic invalid, truncation, and boundary tests plus bounded ASan/UBSan fuzzing on
the host.

These host results do not authorize an image for device boot. Device trust-store integration, key
roles and revocation enforcement, cryptographic backend integration in the trusted boot path, and
Stage 0/Stage 1 enforcement of authenticated boot eligibility are not implemented. The STM32U585
firmware is target-built only and has not been validated on hardware or through HIL.

Flash transactions, health contracts, journaling, recovery, anti-rollback storage, and TrustZone
hardening are also not yet implemented.
