# Rampart Bundle Format

This document defines the initial bundle format direction for Rampart Boot.

Bundle installation is not implemented in checkpoint 3. This file exists to reserve the user-facing
contract and to keep single-image artifacts from growing into a hidden multi-component format.

## Scope

A Rampart bundle represents an authenticated transaction over one or more components.

Examples:

- main application firmware;
- boot manager firmware;
- recovery capsule;
- configuration data;
- coprocessor firmware;
- calibration data;
- FPGA bitstream;
- assets.

## Relationship to Image Artifacts

The `.rampart` image format is a single-component artifact.

A future bundle is a container that references or embeds component artifacts and declares:

- component identities;
- dependency order;
- rollback requirements;
- per-component capabilities;
- transaction policy;
- bundle-level health contract;
- signature policy;
- target binding;
- security epoch requirements.

The bundle coordinator must not reinterpret an image payload or bypass image verification. Every
embedded firmware image remains subject to its own manifest, digest, signature, target binding, and
security epoch checks.

## Required Bundle Semantics

A bundle verifier must be able to answer before installation:

- which components will change;
- which components are mandatory;
- which components can be staged;
- which components support rollback;
- which components can resume interrupted staging;
- which persistent schema migrations are required;
- whether rollback remains compatible after migration;
- which key roles authorize the transaction;
- whether the target device is compatible;
- whether the requested security epoch is acceptable.

## Capability Model

Component backends declare capabilities. Initial capability names are:

| Capability | Meaning |
| --- | --- |
| `STAGING` | Component can receive staged bytes before commit. |
| `VERIFY` | Component can verify staged bytes before execution or activation. |
| `TRIAL` | Component supports a trial state before permanent commit. |
| `ROLLBACK` | Component can restore its previous confirmed state. |
| `RESUME` | Component can resume interrupted staging. |
| `ATOMIC_COMMIT` | Component can make its commit step atomic at its own boundary. |

If bundle policy requires rollback for all components and one component lacks `ROLLBACK`, the
bundle must be rejected during preflight.

## Transaction States

The bundle state machine reserves these states:

```text
PREPARED
STAGING
STAGED
VERIFYING
READY
TRIAL
COMMITTING
CONFIRMED
ROLLING_BACK
ROLLED_BACK
FAILED
```

Every persistent transition must be power-fail-safe.

## Non-Goals for Checkpoint 3

Checkpoint 3 does not implement:

- bundle creation;
- bundle signing;
- bundle verification;
- multi-component transaction coordination;
- configuration migration;
- resumable staging;
- bundle health contracts.

The CLI command tree reserves `rampart bundle`, but those commands remain planned until the
multi-component checkpoints.

## Compatibility Rule

Bundle format work must not weaken single-image verification. If a future bundle embeds a Rampart
image, the image bytes must remain independently inspectable and verifiable by `rampart image`.
