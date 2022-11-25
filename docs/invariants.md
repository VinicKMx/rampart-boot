# Invariants

These invariants are more important than any feature. Implementation work must preserve them or
explicitly update this document through review.

## INV-001

No application firmware is executed without valid cryptographic authentication.

## INV-002

No Stage 1 image is executed without authentication by Stage 0.

## INV-003

An image intended for another product, hardware, or component is rejected.

## INV-004

A partially written image is never bootable.

## INV-005

A confirmed valid image must not be destroyed before a safe recovery path exists.

## INV-006

Trial firmware never irreversibly eliminates the confirmed fallback before commit.

## INV-007

The trusted security epoch never decreases.

## INV-008

The security epoch must not advance irreversibly before the system is prepared to abandon older
firmware.

## INV-009

Corrupted metadata produces conservative behavior.

## INV-010

Validation failure is fail-closed.

## INV-011

Every field used for a security decision must be authenticated.

## INV-012

Parsers never read outside supplied bounds.

## INV-013

Offset overflow or underflow results in an error.

## INV-014

Failure during journal commit must not produce two conflicting states that are both considered
valid.

## INV-015

After any reset, state can be reconstructed only from valid persistent data.

## INV-016

If at least one authenticated bootable chain existed before an operation, after any power loss there
must be either an authenticated bootable chain or an authenticated recovery path.

## INV-017

A revoked key never authorizes a new boot.

## INV-018

A key without the appropriate role cannot authorize an operation outside its capability.

