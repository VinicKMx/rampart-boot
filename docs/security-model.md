# Security Model

Rampart implements protocol, policy, state, and authorization. Rampart does not implement
cryptographic primitives.

## Cryptography

Reference algorithms for STM32 are SHA-256 and ECDSA P-256. Algorithms must be explicit in artifact
formats and must not be inferred from context.

Cryptographic backends provide:

- hashing;
- signature verification;
- random generation when needed;
- platform-specific protected key or monotonic services where available.

## Trust store

The trust store supports multiple public keys. A key record contains:

- key ID;
- algorithm;
- role;
- epoch;
- status;
- public material.

Initial statuses:

- trusted;
- revoked;
- expired;
- development-only.

Initial roles:

- release;
- security;
- boot manager;
- recovery;
- factory;
- development.

## Policy

Example policy requirements:

- normal application update: release role;
- security epoch increase: release and security roles;
- Stage 1 update: boot manager and security roles;
- recovery override: recovery role and physical presence;
- factory provisioning: factory role.

Policy data used for authorization must be authenticated.

## Target binding

A firmware artifact signed by a valid release key is still rejected if it is not intended for the
device target. The manifest authenticates vendor, product, hardware family, and component identity.

## Development vs production

Development devices may accept development keys. Production-locked devices must not. The device
lifecycle state must be observable and must never be hidden by tooling.

## Anti-rollback

Security epoch is separate from semantic version. The epoch represents the minimum accepted security
generation. Rollback within the same epoch can be valid when policy allows it. Booting below the
trusted epoch is rejected.

## Fail closed

When Rampart cannot prove that an operation is authorized and safe, it rejects, falls back, or enters
authenticated recovery. It must not best-effort execute.

