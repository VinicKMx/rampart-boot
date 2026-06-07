# Security Model

Rampart implements protocol, policy, state, and authorization. Rampart does not implement
cryptographic primitives. All cryptographic algorithms are provided by platform or host backends
with explicit interfaces.

## Trust Chain

The reference trust chain is:

```text
protected Stage 0
      |
      v
authenticated Stage 1A or Stage 1B
      |
      v
authenticated application slot or authenticated recovery capsule
```

Stage 0 is the smallest executable trust anchor. It authenticates Stage 1 candidates and transfers
execution only to a selected Stage 1 image that passes boundary, policy, and entry-point checks.

Stage 1 is the Rampart Boot Manager. It authenticates application and recovery artifacts, evaluates
slot lifecycle state, enforces the security epoch, records boot decisions, and gates permanent
acceptance on health evidence.

## Cryptography

Reference algorithms for STM32 are SHA-256 and ECDSA P-256. Algorithms must be explicit in artifact
formats and must not be inferred from context.

The portable verification boundary supports algorithm-explicit operations. For image format v1:

- SHA-256 hashes exactly the caller-supplied byte sequence;
- ECDSA-P256-SHA256 receives the original message bytes, hashes them exactly once with SHA-256, and
  verifies the resulting digest with P-256;
- the message for an image signature is exactly the parser-validated signed region;
- signatures are fixed-width raw `r || s` values, not ASN.1 DER supplied by the artifact;
- public keys are uncompressed SEC1 P-256 points.

A prehashed signature interface, if one is introduced in a later format or provider, must use a
different algorithm-explicit contract. Callers must not prehash input passed to the v1
ECDSA-P256-SHA256 message operation.

### Provider Boundary

The portable core supplies a caller-owned provider and context. Provider inputs are bounded,
immutable byte spans whose lifetime covers the call. Providers must not retain input or output
pointers after returning. The portable core uses no dynamic allocation and does not expose a global
mutable provider.

Provider success is exactly `RAMPART_OK`. Every other result is conservative:

- an invalid signature rejects authentication;
- a malformed key or signature rejects authentication;
- an unsupported algorithm rejects before use;
- a missing operation or provider failure rejects authentication;
- hash output is published only after the provider reports success.

Invalid cryptographic evidence and an internal provider failure may have different diagnostic
statuses, but neither can make an image eligible. Callers must not convert provider results to a
best-effort boolean or continue after an error.

Host adapters may use allocation required by their vetted library, but that allocation remains
inside the host adapter and must be released on every path. This does not permit dynamic allocation
in the portable core, Stage 0, Stage 1, or an embedded trusted boot path.

Broader platform crypto services may also provide:

- random generation when needed;
- platform-specific protected key or monotonic services where available.

Rampart must never implement SHA, ECDSA, Ed25519, RSA, AES, or TRNG logic from scratch.

### Verification Is Not Authorization

A provider proves only whether cryptographic math succeeds for the supplied bytes and public key.
It does not decide:

- whether the public key is trusted;
- whether the key is revoked, expired, or development-only;
- whether the key has the required role;
- whether the device lifecycle permits the key;
- whether target binding or security epoch policy passes;
- whether an image is boot-eligible or selected.

Image format v1 embeds a public key so host tooling can perform self-contained verification. That
key is untrusted artifact input on a device. Device authorization must resolve trusted public
material from the trust store, reject ambiguous key IDs, require agreement with the embedded key,
and verify using the trusted material. A key ID is an identifier, not proof of key ownership or
authorization.

## Authenticated Decision Fields

Every field used for a security decision must be inside an authenticated region or protected by a
platform mechanism. At minimum, artifact authentication covers:

- format version;
- vendor ID;
- product ID;
- hardware family;
- component ID;
- semantic version;
- security epoch;
- payload size;
- payload digest;
- digest algorithm;
- signature algorithm;
- key IDs;
- signature policy;
- component requirements;
- dependencies;
- trial policy;
- health contract;
- rollback policy.

Unauthenticated transport metadata, filenames, URLs, headers, progress records, or host-side command
arguments must not authorize execution.

## Trust Store

The trust store supports multiple public keys. A key record contains:

- key ID;
- algorithm;
- role set;
- key epoch;
- status;
- public material.

Initial statuses:

| Status | Meaning |
| --- | --- |
| trusted | May authorize operations allowed by its role set and policy. |
| revoked | Must not authorize any new boot or update. |
| expired | Must not authorize new operations after the policy-defined validity window. |
| development-only | May be accepted only on development lifecycle devices. |

Initial roles:

| Role | Capability |
| --- | --- |
| release | Authorizes normal application artifacts. |
| security | Co-authorizes security-sensitive changes such as epoch increases. |
| boot manager | Authorizes Stage 1 artifacts. |
| recovery | Authorizes recovery artifacts and recovery overrides. |
| factory | Authorizes provisioning operations. |
| development | Authorizes development artifacts on development devices only. |

## Policy Matrix

Policy data used for authorization must be authenticated.

| Operation | Required authorization |
| --- | --- |
| Normal application update | release role |
| Application update with security epoch increase | release role and security role |
| Stage 1 update | boot manager role and security role |
| Recovery capsule update | recovery role |
| Recovery override | recovery role and physical presence when policy requires it |
| Trust-store rotation | security role or root-authorized trust manifest |
| Key revocation | security role or root-authorized trust manifest |
| Factory provisioning | factory role |
| Development artifact boot | development role and development lifecycle state |

No tooling command may silently weaken these requirements. Critical policy changes must be explicit
in the artifact or trust manifest being authenticated.

## Target Binding

A firmware artifact signed by a valid release key is still rejected if it is not intended for the
device target. The manifest authenticates:

- vendor ID;
- product ID;
- hardware family;
- hardware revision compatibility;
- component ID.

Target binding is enforced before an image becomes boot eligible. This prevents one product from
booting another product's firmware even when the same signing authority is used.

## Development vs Production

Development devices may accept development keys. Production-locked devices must not. The device
lifecycle state must be observable and must never be hidden by tooling.

Expected lifecycle behavior:

| Device lifecycle | Development keys | Production release keys |
| --- | --- | --- |
| development | allowed by policy | allowed by policy |
| production | rejected | allowed by policy |

Production provisioning operations that disable debug, lock readout, program fuses, or make
irreversible protection changes must require an explicit production process. Rampart must not apply
irreversible production hardening automatically during ordinary development workflows.

## Anti-Rollback

Security epoch is separate from semantic version. The epoch represents the minimum accepted security
generation. Rollback within the same epoch can be valid when policy allows it. Booting below the
trusted epoch is rejected.

Example:

```text
allowed when policy permits:
  version 2.8.3, epoch 12
  version 2.8.2, epoch 12

rejected after epoch 12 is trusted:
  version 3.0.0, epoch 11
```

The trusted security epoch must live in monotonic or protected storage when the platform provides
it. If the platform cannot provide monotonic storage, the limitation must be documented for that
port and the security claim must be reduced accordingly.

## Commit Ordering

Security-sensitive commits must be ordered to preserve rollback and recovery.

The safe ordering rule is:

1. Validate the complete artifact and manifest.
2. Verify target binding and required key roles.
3. Verify that the current fallback or recovery path remains authenticated.
4. Stage the candidate without making it authoritative.
5. Boot the candidate as trial.
6. Collect required health evidence.
7. Write the confirmed-state record atomically.
8. Advance irreversible security epoch state only after the system is prepared to abandon older
   firmware.
9. Record the final decision in the journal when possible.

Rampart must not advance an irreversible security epoch and only then discover that the candidate
cannot become the confirmed boot path.

## Metadata Trust

Persistent metadata is classified by how it is protected:

| Metadata | Required protection |
| --- | --- |
| Artifact manifest | cryptographic authentication |
| Payload digest | cryptographic authentication through manifest |
| Slot state | recoverable persistent records with conservative corruption handling |
| Journal records | CRC for accidental corruption; optional authentication on capable platforms |
| Trust store | authenticated trust manifest or protected provisioning path |
| Security epoch | monotonic or protected storage when available |
| Health state | protected from direct application mutation; secure-world storage on TrustZone targets where possible |
| Crash evidence | bounded records; integrity-protected when used for security decisions |

CRC must never be treated as adversarial integrity. It is for accidental corruption detection only.

## Health Evidence

A candidate is not permanently accepted merely because application code calls a confirmation
function. The selected image must satisfy its authenticated health contract.

Health evidence must be bound to:

- the selected component;
- the selected slot;
- the trial attempt;
- the authenticated health contract;
- the current boot ID or equivalent monotonic context when available.

On TrustZone-capable STM32U5 targets, sensitive trial state should be held in the Secure World. The
Non-Secure application reports milestones through a controlled API rather than writing boot-manager
metadata directly.

## Recovery Authorization

Recovery is an authenticated path, not a bypass. Recovery mode may accept new artifacts, but those
artifacts must still satisfy signature, target, epoch, and role policy.

Extraordinary recovery operations may require:

- a recovery role;
- physical presence;
- a target-specific service policy.

Physical presence may come from a button, jumper, service pin, factory strap, or equivalent
platform signal. The platform adapter must document how the signal is sampled and how false
authorization is avoided.

## Fail Closed

When Rampart cannot prove that an operation is authorized and safe, it rejects, falls back, or enters
authenticated recovery. It must not best-effort execute.

Required fail-closed examples:

- parser error: reject artifact;
- unknown key: reject authorization;
- revoked key: reject authorization;
- target mismatch: reject artifact;
- epoch downgrade: reject artifact;
- corrupt slot metadata: ignore corrupted state;
- failed health contract: reject trial candidate;
- no valid application: select authenticated recovery when available;
- no valid Stage 1: Stage 0 enters minimal recovery when available.

## Security Evidence

Rampart should preserve enough evidence to answer:

- what was selected;
- why it was selected;
- why alternatives were rejected;
- which key authorized the selected artifact;
- which target binding was evaluated;
- which security epoch was enforced;
- which health milestones were observed;
- why commit or rollback happened;
- which recovery path remains available.
