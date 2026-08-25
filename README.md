# Rampart Boot

Rampart Boot is a transactional and observable secure firmware lifecycle framework for embedded
systems.

**Signed firmware. Safe updates. Reliable recovery.**

Rampart is not just a bootloader. It covers the lifecycle between a firmware artifact being
produced and a device deciding that the image is authenticated, intended for this target,
operationally healthy, and safe to commit.

## Current status

This repository has the permanent build foundation, first security specifications, Stage 0 and
Stage 1 skeletons, C core contracts, and the initial `.rampart` single-image format. The Rust CLI
can generate P-256 signing keys, sign image artifacts, inspect them, and verify payload digest,
signature, target binding, and security epoch policy inputs. Bundle installation, flash
transactions, health contracts, journaling, and hardware ports are still upcoming checkpoints.

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

Host C builds require OpenSSL 3 development headers and libraries (`libssl-dev` on Ubuntu).

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

The C suites parse the committed Rust-generated v1 artifact and cover invalid fields,
non-canonical layouts, every truncated prefix, boundary lengths, and unchanged output views on
rejection.

Bounded parser fuzz smoke tests with Clang, libFuzzer, ASan, and UBSan:

```bash
cmake --preset host-fuzz
cmake --build --preset host-fuzz
ctest --preset host-fuzz
```

The smoke preset replays tracked canonical and truncated seeds and runs each production parser
harness for 100,000 inputs. Tracked seeds remain read-only. Generated corpus entries and crash
artifacts stay under `build/host-fuzz/`. A reproducible finding is minimized and retained only when
it protects a specific parser regression.

These bounded runs provide sampled host memory-safety evidence, not proof over every input. The
fuzz preset disables leak detection with `ASAN_OPTIONS=detect_leaks=0`.

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

Verify the committed canonical artifact consumed by the C parser tests:

```bash
cargo run --quiet -p rampart -- image verify tests/vectors/image-v1/valid.rampart
```

This host command verifies the payload digest, embedded-key signature, target binding, and security
epoch policy inputs. It does not authorize the key through a device trust store or make the image
eligible to boot.

Create and verify a single-image artifact:

```bash
cargo run -p rampart -- key generate --role RELEASE --output release.pem
cargo run -p rampart -- image sign firmware.bin \
  --manifest tests/vectors/image-v1/manifest.toml \
  --key release.pem \
  --output firmware.rampart
cargo run -p rampart -- image verify firmware.rampart \
  --vendor-id 0x52414d50 \
  --product-id 1 \
  --hardware-family 0x00000585 \
  --component-id 16 \
  --minimum-security-epoch 12
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

`rampart self-check`, `rampart key generate`, `rampart key inspect`, `rampart key public`,
`rampart image sign`, `rampart image inspect`, and `rampart image verify` are implemented.
Remaining command groups are reserved for later checkpoints.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Invariants](docs/invariants.md)
- [Security model](docs/security-model.md)
- [Image format](docs/image-format.md)
- [Bundle format](docs/bundle-format.md)
- [STM32U585 memory map](docs/platforms/stm32u585-memory-map.md)

## Security disclaimer

Rampart does not implement cryptographic primitives. It defines protocol, policy, state, and
authorization rules over vetted cryptographic backends. This repository does not currently make
production security claims. See [SECURITY.md](SECURITY.md).

## Buy me a coffee

If this project helped you, you can send a few sats over Lightning:

`maquinalab@walletofsatoshi.com`

<img src="assets/lightning-donation-qr.svg" alt="Lightning donation QR code" width="180">

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.
