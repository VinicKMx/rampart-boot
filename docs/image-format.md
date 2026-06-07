# Rampart Image Format

This document defines the initial canonical `.rampart` single-image artifact format.

The format is intentionally small and deterministic. It is not a serialized C struct. Every field
has an explicit width, byte order, offset, and validation rule.

## Scope

Image format v1 covers one firmware payload and one signature record.

It provides:

- payload digest binding;
- target binding fields;
- hardware compatibility bounds;
- semantic version core fields;
- security epoch;
- signature policy metadata;
- trial policy metadata;
- a signed manifest plus payload region.

Trust-store authorization, key revocation, multi-signature threshold policy, and bundle
coordination are implemented by later checkpoints. A mathematically valid signature is not the same
thing as an authorized boot decision.

## Encoding Rules

- All integers are unsigned little-endian.
- All offsets are from the beginning of the file.
- All sizes are byte counts.
- Reserved fields must be zero.
- Sections are stored in canonical order: image header, manifest, payload, signature section.
- Parsers must reject non-canonical section order, overlapping ranges, integer overflow, truncated
  sections, and non-zero reserved bytes.
- UTF-8 strings are stored without NUL termination.
- Manifest padding bytes are zero and are included in the signed region.

## Image Header

The image header is 64 bytes.

| Offset | Size | Field | Value |
| --- | ---: | --- | --- |
| 0 | 8 | magic | `RMPIMG01` |
| 8 | 2 | image format version | `1` |
| 10 | 2 | artifact kind | `1` for firmware image |
| 12 | 2 | header size | `64` |
| 14 | 2 | flags | `0` |
| 16 | 4 | manifest offset | `64` |
| 20 | 4 | manifest size | canonical manifest size |
| 24 | 4 | payload offset | `manifest_offset + manifest_size` |
| 28 | 4 | payload size | payload byte count |
| 32 | 4 | signature offset | `payload_offset + payload_size` |
| 36 | 4 | signature size | signature section byte count |
| 40 | 4 | signed region offset | `manifest_offset` |
| 44 | 4 | signed region size | `manifest_size + payload_size` |
| 48 | 16 | reserved | zero |

The signed region is exactly:

```text
manifest bytes || payload bytes
```

The image header is validated for canonical layout but is not part of the signed region. Security
decisions must come from authenticated manifest fields and verified payload bytes.

The payload digest is SHA-256 over exactly the payload bytes. ECDSA-P256-SHA256 signs the SHA-256
digest of exactly the signed-region bytes above. A message-oriented verifier receives those
original signed-region bytes and applies SHA-256 exactly once; callers must not prehash them before
using that operation.

## Manifest Section

The manifest begins with a fixed 128-byte header followed by `artifact_id` bytes and zero padding to
a 4-byte boundary.

| Offset | Size | Field | Value |
| --- | ---: | --- | --- |
| 0 | 8 | magic | `RPMFST01` |
| 8 | 2 | manifest format version | `1` |
| 10 | 2 | manifest header size | `128` |
| 12 | 4 | manifest size | fixed header + artifact ID + padding |
| 16 | 4 | vendor ID | authenticated target binding |
| 20 | 4 | product ID | authenticated target binding |
| 24 | 4 | hardware family | authenticated target binding |
| 28 | 4 | hardware revision minimum | inclusive |
| 32 | 4 | hardware revision maximum | inclusive |
| 36 | 4 | component ID | authenticated target binding |
| 40 | 4 | security epoch | minimum security generation represented by this image |
| 44 | 2 | semantic version major | SemVer core |
| 46 | 2 | semantic version minor | SemVer core |
| 48 | 2 | semantic version patch | SemVer core |
| 50 | 2 | digest algorithm | `1` for SHA-256 |
| 52 | 4 | payload size | must match image header |
| 56 | 32 | payload digest | SHA-256 over the payload bytes |
| 88 | 2 | signature algorithm | `1` for ECDSA P-256 over SHA-256 |
| 90 | 2 | required key role | role required by policy |
| 92 | 2 | signature threshold | v1 requires `1` |
| 94 | 2 | signature count | v1 requires `1` |
| 96 | 8 | key ID | signer key ID expected by the signature section |
| 104 | 2 | trial max attempts | `0` means no trial policy encoded yet |
| 106 | 2 | rollback policy | `0` none, `1` fallback |
| 108 | 4 | trial probation period ms | probation window hint |
| 112 | 2 | artifact ID length | 1..128 |
| 114 | 2 | requirement count | v1 requires `0` |
| 116 | 2 | dependency count | v1 requires `0` |
| 118 | 2 | health required count | v1 requires `0` |
| 120 | 8 | reserved | zero |

Role values:

| Value | Role |
| ---: | --- |
| 1 | `RELEASE` |
| 2 | `SECURITY` |
| 3 | `BOOT_MANAGER` |
| 4 | `RECOVERY` |
| 5 | `FACTORY` |
| 6 | `DEVELOPMENT` |

The manifest section is authenticated because it is inside the signed region.

## Signature Section

The v1 signature section is 192 bytes: a 32-byte header and one 160-byte record.

| Offset | Size | Field | Value |
| --- | ---: | --- | --- |
| 0 | 8 | magic | `RPSIGN01` |
| 8 | 2 | signature section version | `1` |
| 10 | 2 | signature header size | `32` |
| 12 | 4 | signature section size | `192` |
| 16 | 4 | signed region offset | must match image header |
| 20 | 4 | signed region size | must match image header |
| 24 | 2 | signature count | `1` |
| 26 | 2 | signature algorithm | `1` |
| 28 | 2 | signature record size | `160` |
| 30 | 2 | reserved | zero |

Record layout:

| Offset | Size | Field | Value |
| --- | ---: | --- | --- |
| 0 | 8 | key ID | must match manifest key ID |
| 8 | 2 | signature algorithm | `1` |
| 10 | 2 | public key algorithm | `1` for P-256 |
| 12 | 2 | signature size | `64` |
| 14 | 2 | public key size | `65` |
| 16 | 64 | signature | raw `r || s` ECDSA P-256 signature |
| 80 | 65 | public key | uncompressed SEC1 P-256 public key |
| 145 | 15 | padding | zero |

The raw signature is:

```text
r[32] || s[32]
```

Each scalar is an unsigned 32-byte big-endian P-256 value. Artifact signatures are not ASN.1 DER.
Both scalars must be valid for P-256; malformed, zero, or out-of-range values are rejected.

The public key is:

```text
0x04 || x[32] || y[32]
```

The coordinates are unsigned big-endian P-256 values and must encode a valid curve point. The key
ID is the first eight bytes of SHA-256 over this complete 65-byte SEC1 encoding. A key ID collision
or disagreement with trusted public material must never be resolved by accepting the embedded key.

The public key is embedded so host tooling can verify test artifacts without a device trust store.
It is untrusted artifact input on a device and does not establish signer authority. Boot
authorization must resolve the key ID through the device trust store, reject unknown or ambiguous
records, require the embedded key to agree with trusted public material, and perform signature
verification using the trusted material.

## Manifest TOML Used by Host Tooling

The `rampart image sign` command accepts a TOML manifest document and emits the canonical binary
manifest described above.

Example:

```toml
artifact_id = "industrial-controller-main-2.4.0"
vendor_id = 1380011344
product_id = 1
hardware_family = 1413
hardware_revision_min = 1
hardware_revision_max = 3
component_id = 16
version = "2.4.0"
security_epoch = 12
signature_role = "RELEASE"
rollback_policy = "fallback"

[trial]
max_attempts = 3
probation_period_ms = 30000
```

`key_id` may be supplied as a 16-character hexadecimal string. When omitted, the host tool derives
it from SHA-256 over the uncompressed SEC1 public key and uses the first eight bytes.

## Verification Requirements

A verifier must reject the image if any of these checks fail:

- image header magic, version, kind, size, or reserved fields;
- non-canonical section offsets or sizes;
- any range overflow or range extending past the file;
- manifest magic, version, digest algorithm, signature algorithm, or reserved fields;
- hardware revision range where minimum is greater than maximum;
- missing or oversized artifact ID;
- non-zero requirement, dependency, or health counts in image format v1;
- payload size mismatch between header and manifest;
- payload digest mismatch;
- signature section mismatch with the signed region;
- signature key ID mismatch with manifest policy;
- embedded public key does not derive the same key ID;
- ECDSA verification fails;
- optional device target policy rejects vendor, product, hardware family, or component;
- optional minimum security epoch policy rejects the image.

## Compatibility

The v1 parser must fail closed on unknown format versions. Future versions can add new sections or
extension tables, but v1 fields used for security decisions must remain unambiguous and
authenticated.
