# Rampart Boot

Rampart Boot is a transactional and observable secure firmware lifecycle framework for embedded
systems.

**Signed firmware. Safe updates. Reliable recovery.**

Rampart is not just a bootloader. It covers the lifecycle between a firmware artifact being
produced and a device deciding that the image is authenticated, intended for this target,
operationally healthy, and safe to commit.

## Current status

This repository is at the foundation stage. The permanent build structure, C core contracts, Stage 0
and Stage 1 skeletons, Rust CLI workspace, host tests, sanitizers, CI, and the first security
documents are present. Image signing, bundle installation, flash transactions, health contracts,
journaling, and hardware ports are still upcoming checkpoints.

## Security model summary

Rampart is built around five properties:

- Trust: only authorized software is eligible to run.
- Transactionality: updates must survive power loss at any persistent operation boundary.
- Evidence-based acceptance: trial firmware is committed only after satisfying a declared health
  contract.
- Forensics: significant boot decisions leave durable evidence.
- Recoverability: failures should lead to fallback, rollback, or authenticated recovery.

See [docs/threat-model.md](docs/threat-model.md), [docs/invariants.md](docs/invariants.md), and
[docs/security-model.md](docs/security-model.md).

## Architecture

```text
Immutable / protected Stage 0
        |
        v
Stage 1A / Stage 1B Rampart Boot Manager
        |
        v
Application A / Application B / Recovery Capsule
```

Stage 0 stays small and authenticates Stage 1. Stage 1 owns application lifecycle, slot policy,
trial boot, health evidence, rollback, journal, recovery, trust metadata, and multi-component
coordination.

## Build

Host build:

```bash
cmake --preset host-debug
cmake --build --preset host-debug
ctest --preset host-debug
```

Host sanitizers:

```bash
cmake --preset host-sanitize
cmake --build --preset host-sanitize
ctest --preset host-sanitize
```

STM32U585 minimal firmware build:

```bash
cmake --preset stm32u585
cmake --build --preset stm32u585
```

Rust host CLI:

```bash
cargo test --workspace
cargo run -p rampart -- self-check
```

## Tooling

The final CLI is `rampart`. The command tree is already reserved:

```text
rampart image
rampart bundle
rampart key
rampart trust
rampart manifest
rampart simulate
rampart device
rampart journal
rampart recovery
```

Only `rampart self-check` is implemented at this checkpoint.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Invariants](docs/invariants.md)
- [Security model](docs/security-model.md)
- [STM32U585 memory map](docs/platforms/stm32u585-memory-map.md)

## Security disclaimer

Rampart does not implement cryptographic primitives. It defines protocol, policy, state, and
authorization rules over vetted cryptographic backends. This repository does not currently make
production security claims. See [SECURITY.md](SECURITY.md).
