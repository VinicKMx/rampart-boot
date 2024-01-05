# Invariants

These invariants are more important than any feature. Implementation work must preserve them. If an
invariant appears to conflict with a new feature, the feature design is wrong until the security
case is made explicit.

The words "must", "must not", and "never" are normative in this document.

## Core Invariants

### INV-001

No application firmware is executed without valid cryptographic authentication.

### INV-002

No Stage 1 image is executed without authentication by Stage 0.

### INV-003

An image intended for another product, hardware, or component is rejected.

### INV-004

A partially written image is never bootable.

### INV-005

A confirmed valid image must not be destroyed before a safe recovery path exists.

### INV-006

Trial firmware never irreversibly eliminates the confirmed fallback before commit.

### INV-007

The trusted security epoch never decreases.

### INV-008

The security epoch must not advance irreversibly before the system is prepared to abandon older
firmware.

### INV-009

Corrupted metadata produces conservative behavior.

### INV-010

Validation failure is fail-closed.

### INV-011

Every field used for a security decision must be authenticated.

### INV-012

Parsers never read outside supplied bounds.

### INV-013

Offset overflow or underflow results in an error.

### INV-014

Failure during journal commit must not produce two conflicting states that are both considered
valid.

### INV-015

After any reset, state can be reconstructed only from valid persistent data.

### INV-016

If at least one authenticated bootable chain existed before an operation, after any power loss there
must be either an authenticated bootable chain or an authenticated recovery path.

### INV-017

A revoked key never authorizes a new boot.

### INV-018

A key without the appropriate role cannot authorize an operation outside its capability.

## Decision Traceability

Every security decision must map to one or more invariants. This table is the baseline traceability
matrix for implementation and review.

| Decision | Required checks | Related invariants |
| --- | --- | --- |
| Stage 0 selects Stage 1 | Stage 1 bounds, metadata shape, target binding when available, signature, key role, epoch, entry point | INV-002, INV-003, INV-007, INV-010, INV-011, INV-017, INV-018 |
| Stage 1 selects an application slot | manifest validity, payload digest, signature, target binding, epoch, slot state, fallback availability | INV-001, INV-003, INV-004, INV-005, INV-007, INV-010, INV-011 |
| Parser accepts an artifact | supplied buffer bounds, canonical sizes, offsets, version, signed region, authenticated decision fields | INV-011, INV-012, INV-013 |
| Image becomes boot eligible | complete write, final authentication, target compatibility, required roles, non-revoked key | INV-001, INV-003, INV-004, INV-010, INV-017, INV-018 |
| Trial starts | fallback still available, candidate authenticated, attempt limit state valid, journal append attempted | INV-005, INV-006, INV-014, INV-016 |
| Health evidence is accepted | event belongs to selected candidate, milestone is required or allowed, state is protected from direct application mutation | INV-006, INV-009, INV-011, INV-015 |
| Candidate is confirmed | health contract satisfied, fallback or recovery guarantees preserved, commit record written atomically | INV-005, INV-006, INV-014, INV-015, INV-016 |
| Candidate is rejected | failure reason recorded when possible, fallback selected only after authentication, rejected image not boot eligible | INV-001, INV-004, INV-010, INV-014 |
| Security epoch advances | new image is authenticated and ready to become authoritative, older firmware abandonment is safe, monotonic write succeeds | INV-007, INV-008, INV-014, INV-016 |
| Trust store changes | trust manifest authenticated, required roles present, revocation state applied before affected keys authorize new boots | INV-010, INV-011, INV-017, INV-018 |
| Recovery is selected | recovery artifact authenticated, recovery policy satisfied, physical presence checked when required | INV-010, INV-011, INV-016, INV-018 |
| Boot journal is recovered | only valid CRC/authenticated records are trusted, ambiguous tails are ignored, one authoritative state is reconstructed | INV-009, INV-014, INV-015 |
| Jump target is executed | vector table bounds, stack pointer range, reset vector range, alignment, execution region, no writable window after validation | INV-001, INV-002, INV-010 |

## Fail-Closed Outcomes

When a check fails, Rampart must choose a conservative outcome.

| Failed condition | Conservative outcome |
| --- | --- |
| Manifest parse failure | reject artifact |
| Signature verification failure | reject artifact or slot |
| Unknown key ID | reject authorization |
| Revoked or expired key | reject authorization |
| Missing required role | reject authorization |
| Target mismatch | reject artifact |
| Security epoch too low | reject artifact |
| Slot metadata corruption | ignore corrupted state and reconstruct from valid records |
| Journal tail corruption | recover valid prefix or enter authenticated recovery |
| Trial state corruption | reject candidate unless valid persistent evidence proves it is confirmed |
| No authenticated application slot | select authenticated recovery when available |
| No authenticated Stage 1 | Stage 0 enters minimal recovery path when available |
| Arithmetic overflow or underflow | return structured error |
| Bounds violation | return structured error |

## Persistent State Requirements

Persistent state that influences boot must be:

- versioned;
- bounded by explicit size limits;
- recoverable after reset;
- protected against ambiguous double-commit;
- authenticated or derived from authenticated records when used for security decisions;
- CRC-protected at minimum when used for accidental corruption detection.

CRC is not a security mechanism. It detects accidental corruption only. Adversarial integrity must
come from cryptographic authentication, protected storage, or platform security services.

## Implementation Review Rule

Any new boot, update, recovery, trust-store, journal, or health transition must answer:

- Which invariant permits this transition?
- Which invariant rejects the unsafe version of this transition?
- Which persistent record reconstructs the state after reset?
- What happens if power loss occurs before, during, or after the transition?
- What evidence explains the decision later?
