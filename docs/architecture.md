# Architecture

Rampart Boot is a portable, transactional, and observable secure firmware lifecycle framework for
embedded systems.

The project scope is larger than a bootloader. Rampart covers firmware build artifacts, manifests,
signing, staging, verification, trial boot, health evidence, commit, rollback, recovery, and
forensic explanation.

## Stages

Stage 0 is the executable root of trust owned by Rampart. It must remain small:

- minimal CPU setup;
- Stage 1 metadata reads;
- boundary validation;
- Stage 1 authentication;
- Stage 1A/Stage 1B selection;
- minimal recovery entry when no Stage 1 can be selected.

Stage 0 must not contain OTA transports, filesystems, JSON, generic CBOR processing, application
health evaluation, large crypto frameworks, dynamic allocation, or multi-component installation
logic.

Stage 1 is the Rampart Boot Manager. It owns:

- application image validation;
- manifest policy;
- slot lifecycle;
- trial boot;
- health contracts;
- rollback;
- security epoch decisions;
- boot journal;
- recovery selection;
- multi-component transaction coordination;
- trust-store management.

Stage 1 is itself managed as an A/B component so the boot manager can be updated without replacing
Stage 0.

## Conceptual memory layout

```text
Stage 0
Stage 1A
Stage 1B
Application A
Application B
Recovery Capsule
Boot Journal
Transaction Metadata
Trust Metadata
Crash Evidence
```

Concrete platform layouts are documented under `docs/platforms/`.

## Core boundary

The portable core must not know STM32, ESP32, USB, BLE, HTTPS, filesystems, or a network stack.
Platform adapters provide flash, crypto, monotonic counters, reset reason, watchdog, random,
protection, device identity, physical presence, and jump services.

The portable core owns validation order, trust policy, and authorization. A crypto provider owns
only the requested cryptographic operation: it cannot authorize a key, approve target or epoch
policy, select an image, or publish boot eligibility. Provider inputs remain caller-owned and
immutable for the complete call, and a provider must not retain their addresses after returning.

A host crypto provider is compatibility and test evidence only. It does not select the backend for
an embedded target and does not establish target hardware, HIL, or production security evidence.

## Commit philosophy

An update is a transaction. Power loss can happen before or after any persistent operation. Rampart
must preserve either an authenticated bootable chain or an authenticated recovery path when one
existed before the operation.

