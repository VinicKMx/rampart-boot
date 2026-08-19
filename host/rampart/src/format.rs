use std::fs;
use std::ops::Range;
use std::path::Path;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::keys::{KEY_ID_SIZE, derive_key_id, key_id_hex, parse_key_id_hex, read_signing_key};

const IMAGE_MAGIC: &[u8; 8] = b"RMPIMG01";
const MANIFEST_MAGIC: &[u8; 8] = b"RPMFST01";
const SIGNATURE_MAGIC: &[u8; 8] = b"RPSIGN01";

const IMAGE_FORMAT_VERSION: u16 = 1;
const IMAGE_KIND_FIRMWARE: u16 = 1;
const IMAGE_HEADER_SIZE: usize = 64;

const MANIFEST_FORMAT_VERSION: u16 = 1;
const MANIFEST_HEADER_SIZE: usize = 128;
const MANIFEST_ARTIFACT_ID_MAX: usize = 128;

const SIGNATURE_FORMAT_VERSION: u16 = 1;
const SIGNATURE_HEADER_SIZE: usize = 32;
const SIGNATURE_RECORD_SIZE: usize = 160;

const HASH_ALGORITHM_SHA256: u16 = 1;
const SIGNATURE_ALGORITHM_ECDSA_P256_SHA256: u16 = 1;
const PUBLIC_KEY_ALGORITHM_P256: u16 = 1;

const ROLE_RELEASE: u16 = 1;
const ROLE_SECURITY: u16 = 2;
const ROLE_BOOT_MANAGER: u16 = 3;
const ROLE_RECOVERY: u16 = 4;
const ROLE_FACTORY: u16 = 5;
const ROLE_DEVELOPMENT: u16 = 6;

const ROLLBACK_POLICY_NONE: u16 = 0;
const ROLLBACK_POLICY_FALLBACK: u16 = 1;

const SIGNATURE_SIZE: usize = 64;
const PUBLIC_KEY_SIZE: usize = 65;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDocument {
    pub artifact_id: String,
    pub vendor_id: u32,
    pub product_id: u32,
    pub hardware_family: u32,
    pub hardware_revision_min: u32,
    pub hardware_revision_max: u32,
    pub component_id: u32,
    pub version: String,
    pub security_epoch: u32,
    pub signature_role: Option<String>,
    pub rollback_policy: Option<String>,
    pub key_id: Option<String>,
    pub trial: Option<TrialDocument>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialDocument {
    pub max_attempts: u16,
    pub probation_period_ms: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DeviceTarget {
    pub vendor_id: u32,
    pub product_id: u32,
    pub hardware_family: u32,
    pub component_id: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RampartManifest {
    pub artifact_id: String,
    pub vendor_id: u32,
    pub product_id: u32,
    pub hardware_family: u32,
    pub hardware_revision_min: u32,
    pub hardware_revision_max: u32,
    pub component_id: u32,
    pub security_epoch: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
    pub payload_size: u32,
    pub payload_digest: [u8; 32],
    pub signature_role: u16,
    pub signature_threshold: u16,
    pub signature_count: u16,
    pub key_id: [u8; KEY_ID_SIZE],
    pub trial_max_attempts: u16,
    pub trial_probation_ms: u32,
    pub rollback_policy: u16,
    pub requirement_count: u16,
    pub dependency_count: u16,
    pub health_required_count: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignatureRecord {
    pub key_id: [u8; KEY_ID_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedImage {
    pub manifest: RampartManifest,
    pub manifest_range: Range<usize>,
    pub payload_range: Range<usize>,
    pub signature_range: Range<usize>,
    pub signed_region_range: Range<usize>,
    pub signature: SignatureRecord,
}

#[derive(Debug, Clone)]
pub struct VerificationOptions {
    pub device_target: Option<DeviceTarget>,
    pub minimum_security_epoch: u32,
}

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub image: ParsedImage,
    pub payload_digest_valid: bool,
    pub signature_valid: bool,
    pub target_valid: bool,
    pub security_epoch_valid: bool,
}

impl VerificationReport {
    pub fn is_valid(&self) -> bool {
        self.payload_digest_valid
            && self.signature_valid
            && self.target_valid
            && self.security_epoch_valid
    }
}

impl ManifestDocument {
    fn into_manifest(
        self,
        payload_size: u32,
        payload_digest: [u8; 32],
        key_id: [u8; KEY_ID_SIZE],
    ) -> Result<RampartManifest, String> {
        if self.artifact_id.is_empty() {
            return Err("artifact_id must not be empty".to_string());
        }

        if self.artifact_id.len() > MANIFEST_ARTIFACT_ID_MAX {
            return Err(format!(
                "artifact_id must be at most {MANIFEST_ARTIFACT_ID_MAX} bytes"
            ));
        }

        if self.artifact_id.as_bytes().contains(&0u8) {
            return Err("artifact_id must not contain NUL bytes".to_string());
        }

        if self.hardware_revision_min > self.hardware_revision_max {
            return Err("hardware_revision_min must be <= hardware_revision_max".to_string());
        }

        let (version_major, version_minor, version_patch) = parse_semver_core(&self.version)?;
        let signature_role = parse_role(self.signature_role.as_deref().unwrap_or("RELEASE"))?;
        let rollback_policy =
            parse_rollback_policy(self.rollback_policy.as_deref().unwrap_or("fallback"))?;
        let trial = self.trial.unwrap_or(TrialDocument {
            max_attempts: 0,
            probation_period_ms: 0,
        });

        Ok(RampartManifest {
            artifact_id: self.artifact_id,
            vendor_id: self.vendor_id,
            product_id: self.product_id,
            hardware_family: self.hardware_family,
            hardware_revision_min: self.hardware_revision_min,
            hardware_revision_max: self.hardware_revision_max,
            component_id: self.component_id,
            security_epoch: self.security_epoch,
            version_major,
            version_minor,
            version_patch,
            payload_size,
            payload_digest,
            signature_role,
            signature_threshold: 1,
            signature_count: 1,
            key_id,
            trial_max_attempts: trial.max_attempts,
            trial_probation_ms: trial.probation_period_ms,
            rollback_policy,
            requirement_count: 0,
            dependency_count: 0,
            health_required_count: 0,
        })
    }
}

impl RampartManifest {
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}",
            self.version_major, self.version_minor, self.version_patch
        )
    }

    pub fn signature_role_name(&self) -> &'static str {
        role_name(self.signature_role)
    }

    pub fn rollback_policy_name(&self) -> &'static str {
        rollback_policy_name(self.rollback_policy)
    }
}

pub fn sign_image(
    payload_path: &Path,
    manifest_path: &Path,
    key_path: &Path,
    output_path: &Path,
    key_id_override: Option<&str>,
) -> Result<ParsedImage, String> {
    if output_path.exists() {
        return Err(format!(
            "refusing to overwrite existing artifact {}",
            output_path.display()
        ));
    }

    let payload = fs::read(payload_path)
        .map_err(|error| format!("failed to read payload {}: {error}", payload_path.display()))?;
    let payload_size = u32::try_from(payload.len())
        .map_err(|_| "payload size exceeds Rampart image v1 limit".to_string())?;
    if payload.is_empty() {
        return Err("payload must not be empty".to_string());
    }

    let signing_key = read_signing_key(key_path)?;
    let verifying_key = signing_key.verifying_key();
    let derived_key_id = derive_key_id(verifying_key);
    let key_id = match key_id_override {
        Some(value) => parse_key_id_hex(value)?,
        None => derived_key_id,
    };

    let manifest_document = read_manifest_document(manifest_path)?;
    if let Some(manifest_key_id) = manifest_document.key_id.as_deref() {
        let declared = parse_key_id_hex(manifest_key_id)?;
        if declared != key_id {
            return Err("manifest key_id does not match signing key ID".to_string());
        }
    }

    let payload_digest = digest_payload(&payload);
    let manifest = manifest_document.into_manifest(payload_size, payload_digest, key_id)?;
    let manifest_bytes = encode_manifest(&manifest)?;

    let mut signed_region = Vec::with_capacity(manifest_bytes.len() + payload.len());
    signed_region.extend_from_slice(&manifest_bytes);
    signed_region.extend_from_slice(&payload);

    let signature_record = sign_region(&signing_key, verifying_key, key_id, &signed_region)?;
    let signature_bytes = encode_signature_section(&signature_record, &signed_region)?;
    let image_bytes = encode_image(&manifest_bytes, &payload, &signature_bytes)?;

    fs::write(output_path, &image_bytes).map_err(|error| {
        format!(
            "failed to write artifact {}: {error}",
            output_path.display()
        )
    })?;

    parse_image(&image_bytes)
}

pub fn inspect_image(bytes: &[u8]) -> Result<String, String> {
    let image = parse_image(bytes)?;
    let digest = digest_payload(&bytes[image.payload_range.clone()]);
    let digest_valid = digest == image.manifest.payload_digest;

    Ok(format_image_report(&image, Some(digest_valid), None))
}

pub fn verify_image(
    bytes: &[u8],
    options: &VerificationOptions,
) -> Result<VerificationReport, String> {
    let image = parse_image(bytes)?;
    let payload_digest_valid =
        digest_payload(&bytes[image.payload_range.clone()]) == image.manifest.payload_digest;
    let signature_valid = verify_signature(bytes, &image)?;
    let target_valid = match options.device_target {
        Some(target) => target_matches(&image.manifest, target),
        None => true,
    };
    let security_epoch_valid = image.manifest.security_epoch >= options.minimum_security_epoch;

    Ok(VerificationReport {
        image,
        payload_digest_valid,
        signature_valid,
        target_valid,
        security_epoch_valid,
    })
}

pub fn format_verification_report(report: &VerificationReport) -> String {
    format_image_report(
        &report.image,
        Some(report.payload_digest_valid),
        Some(report.signature_valid),
    ) + &format!(
        "\nPolicy Checks\n  target binding      {}\n  security epoch      {}\n\nResult\n  {}\n",
        status_word(report.target_valid),
        status_word(report.security_epoch_valid),
        if report.is_valid() {
            "valid"
        } else {
            "rejected"
        }
    )
}

pub fn parse_image(bytes: &[u8]) -> Result<ParsedImage, String> {
    if bytes.len() < IMAGE_HEADER_SIZE {
        return Err("image is shorter than the Rampart header".to_string());
    }

    require_magic(&bytes[0..8], IMAGE_MAGIC, "image")?;
    require_u16(bytes, 8, IMAGE_FORMAT_VERSION, "image format version")?;
    require_u16(bytes, 10, IMAGE_KIND_FIRMWARE, "image artifact kind")?;
    require_u16(
        bytes,
        12,
        u16::try_from(IMAGE_HEADER_SIZE).expect("header fits u16"),
        "image header size",
    )?;
    require_u16(bytes, 14, 0, "image flags")?;

    let manifest_offset = read_u32(bytes, 16)? as usize;
    let manifest_size = read_u32(bytes, 20)? as usize;
    let payload_offset = read_u32(bytes, 24)? as usize;
    let payload_size = read_u32(bytes, 28)? as usize;
    let signature_offset = read_u32(bytes, 32)? as usize;
    let signature_size = read_u32(bytes, 36)? as usize;
    let signed_region_offset = read_u32(bytes, 40)? as usize;
    let signed_region_size = read_u32(bytes, 44)? as usize;

    require_zeroes(&bytes[48..64], "image reserved bytes")?;

    if manifest_offset != IMAGE_HEADER_SIZE {
        return Err("manifest must immediately follow the image header".to_string());
    }

    let expected_payload_offset = checked_add(manifest_offset, manifest_size)?;
    if payload_offset != expected_payload_offset {
        return Err("payload must immediately follow the manifest".to_string());
    }

    let expected_signature_offset = checked_add(payload_offset, payload_size)?;
    if signature_offset != expected_signature_offset {
        return Err("signature section must immediately follow the payload".to_string());
    }

    let expected_file_len = checked_add(signature_offset, signature_size)?;
    if expected_file_len != bytes.len() {
        return Err("image length does not match section table".to_string());
    }

    if signed_region_offset != manifest_offset {
        return Err("signed region must start at the manifest".to_string());
    }

    if signed_region_size != checked_add(manifest_size, payload_size)? {
        return Err("signed region must cover manifest and payload".to_string());
    }

    let manifest_range = checked_range(manifest_offset, manifest_size, bytes.len())?;
    let payload_range = checked_range(payload_offset, payload_size, bytes.len())?;
    let signature_range = checked_range(signature_offset, signature_size, bytes.len())?;
    let signed_region_range = checked_range(signed_region_offset, signed_region_size, bytes.len())?;

    let manifest = parse_manifest(&bytes[manifest_range.clone()])?;
    if usize::try_from(manifest.payload_size).expect("u32 fits usize") != payload_size {
        return Err("manifest payload size does not match image header".to_string());
    }

    let signature = parse_signature_section(
        &bytes[signature_range.clone()],
        signed_region_offset,
        signed_region_size,
        &manifest,
    )?;

    Ok(ParsedImage {
        manifest,
        manifest_range,
        payload_range,
        signature_range,
        signed_region_range,
        signature,
    })
}

fn read_manifest_document(path: &Path) -> Result<ManifestDocument, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read manifest {}: {error}", path.display()))?;

    toml::from_str(&text)
        .map_err(|error| format!("failed to parse manifest {}: {error}", path.display()))
}

fn encode_manifest(manifest: &RampartManifest) -> Result<Vec<u8>, String> {
    let artifact_id = manifest.artifact_id.as_bytes();
    if artifact_id.len() > MANIFEST_ARTIFACT_ID_MAX {
        return Err(format!(
            "artifact_id must be at most {MANIFEST_ARTIFACT_ID_MAX} bytes"
        ));
    }

    let mut out = vec![0u8; MANIFEST_HEADER_SIZE];
    out[0..8].copy_from_slice(MANIFEST_MAGIC);
    write_u16(&mut out, 8, MANIFEST_FORMAT_VERSION);
    write_u16(
        &mut out,
        10,
        u16::try_from(MANIFEST_HEADER_SIZE).expect("manifest header fits u16"),
    );
    write_u32(&mut out, 16, manifest.vendor_id);
    write_u32(&mut out, 20, manifest.product_id);
    write_u32(&mut out, 24, manifest.hardware_family);
    write_u32(&mut out, 28, manifest.hardware_revision_min);
    write_u32(&mut out, 32, manifest.hardware_revision_max);
    write_u32(&mut out, 36, manifest.component_id);
    write_u32(&mut out, 40, manifest.security_epoch);
    write_u16(&mut out, 44, manifest.version_major);
    write_u16(&mut out, 46, manifest.version_minor);
    write_u16(&mut out, 48, manifest.version_patch);
    write_u16(&mut out, 50, HASH_ALGORITHM_SHA256);
    write_u32(&mut out, 52, manifest.payload_size);
    out[56..88].copy_from_slice(&manifest.payload_digest);
    write_u16(&mut out, 88, SIGNATURE_ALGORITHM_ECDSA_P256_SHA256);
    write_u16(&mut out, 90, manifest.signature_role);
    write_u16(&mut out, 92, manifest.signature_threshold);
    write_u16(&mut out, 94, manifest.signature_count);
    out[96..104].copy_from_slice(&manifest.key_id);
    write_u16(&mut out, 104, manifest.trial_max_attempts);
    write_u16(&mut out, 106, manifest.rollback_policy);
    write_u32(&mut out, 108, manifest.trial_probation_ms);
    write_u16(
        &mut out,
        112,
        u16::try_from(artifact_id.len()).expect("artifact ID length fits u16"),
    );
    write_u16(&mut out, 114, manifest.requirement_count);
    write_u16(&mut out, 116, manifest.dependency_count);
    write_u16(&mut out, 118, manifest.health_required_count);

    out.extend_from_slice(artifact_id);
    while out.len() % 4 != 0 {
        out.push(0u8);
    }

    let manifest_size = u32::try_from(out.len())
        .map_err(|_| "manifest size exceeds Rampart image v1 limit".to_string())?;
    write_u32(&mut out, 12, manifest_size);

    Ok(out)
}

fn parse_manifest(bytes: &[u8]) -> Result<RampartManifest, String> {
    if bytes.len() < MANIFEST_HEADER_SIZE {
        return Err("manifest is shorter than the fixed header".to_string());
    }

    require_magic(&bytes[0..8], MANIFEST_MAGIC, "manifest")?;
    require_u16(bytes, 8, MANIFEST_FORMAT_VERSION, "manifest format version")?;
    require_u16(
        bytes,
        10,
        u16::try_from(MANIFEST_HEADER_SIZE).expect("manifest header fits u16"),
        "manifest header size",
    )?;

    let manifest_size = read_u32(bytes, 12)? as usize;
    if manifest_size != bytes.len() {
        return Err("manifest size does not match section size".to_string());
    }

    require_u16(bytes, 50, HASH_ALGORITHM_SHA256, "digest algorithm")?;
    require_u16(
        bytes,
        88,
        SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
        "signature algorithm",
    )?;

    let artifact_id_len = read_u16(bytes, 112)? as usize;
    if artifact_id_len == 0 || artifact_id_len > MANIFEST_ARTIFACT_ID_MAX {
        return Err("artifact_id length is invalid".to_string());
    }

    let artifact_id_end = checked_add(MANIFEST_HEADER_SIZE, artifact_id_len)?;
    if artifact_id_end > bytes.len() {
        return Err("artifact_id extends beyond manifest bounds".to_string());
    }

    require_zeroes(&bytes[120..MANIFEST_HEADER_SIZE], "manifest reserved bytes")?;
    require_zeroes(&bytes[artifact_id_end..], "manifest trailing padding")?;

    let artifact_id = std::str::from_utf8(&bytes[MANIFEST_HEADER_SIZE..artifact_id_end])
        .map_err(|_| "artifact_id must be UTF-8".to_string())?
        .to_string();

    let mut payload_digest = [0u8; 32];
    payload_digest.copy_from_slice(&bytes[56..88]);
    let mut key_id = [0u8; KEY_ID_SIZE];
    key_id.copy_from_slice(&bytes[96..104]);

    let hardware_revision_min = read_u32(bytes, 28)?;
    let hardware_revision_max = read_u32(bytes, 32)?;
    if hardware_revision_min > hardware_revision_max {
        return Err("hardware revision range is invalid".to_string());
    }

    let signature_role = read_u16(bytes, 90)?;
    if !is_known_role(signature_role) {
        return Err("signature role is unknown".to_string());
    }

    let rollback_policy = read_u16(bytes, 106)?;
    if !is_known_rollback_policy(rollback_policy) {
        return Err("rollback policy is unknown".to_string());
    }

    let signature_threshold = read_u16(bytes, 92)?;
    let signature_count = read_u16(bytes, 94)?;
    if signature_threshold != 1 || signature_count != 1 {
        return Err("image v1 requires exactly one signature".to_string());
    }

    let requirement_count = read_u16(bytes, 114)?;
    let dependency_count = read_u16(bytes, 116)?;
    let health_required_count = read_u16(bytes, 118)?;
    if requirement_count != 0 || dependency_count != 0 || health_required_count != 0 {
        return Err("image v1 does not support manifest extension counts yet".to_string());
    }

    Ok(RampartManifest {
        artifact_id,
        vendor_id: read_u32(bytes, 16)?,
        product_id: read_u32(bytes, 20)?,
        hardware_family: read_u32(bytes, 24)?,
        hardware_revision_min,
        hardware_revision_max,
        component_id: read_u32(bytes, 36)?,
        security_epoch: read_u32(bytes, 40)?,
        version_major: read_u16(bytes, 44)?,
        version_minor: read_u16(bytes, 46)?,
        version_patch: read_u16(bytes, 48)?,
        payload_size: read_u32(bytes, 52)?,
        payload_digest,
        signature_role,
        signature_threshold,
        signature_count,
        key_id,
        trial_max_attempts: read_u16(bytes, 104)?,
        trial_probation_ms: read_u32(bytes, 108)?,
        rollback_policy,
        requirement_count,
        dependency_count,
        health_required_count,
    })
}

fn sign_region(
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    key_id: [u8; KEY_ID_SIZE],
    signed_region: &[u8],
) -> Result<SignatureRecord, String> {
    let signature: Signature = signing_key.sign(signed_region);
    let signature_bytes = signature.to_bytes();
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key_point.as_bytes();

    if public_key_bytes.len() != PUBLIC_KEY_SIZE {
        return Err("P-256 public key must use uncompressed SEC1 encoding".to_string());
    }

    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    public_key.copy_from_slice(public_key_bytes);

    let mut encoded_signature = [0u8; SIGNATURE_SIZE];
    encoded_signature.copy_from_slice(&signature_bytes);

    Ok(SignatureRecord {
        key_id,
        signature: encoded_signature,
        public_key,
    })
}

fn encode_signature_section(
    record: &SignatureRecord,
    signed_region: &[u8],
) -> Result<Vec<u8>, String> {
    let signed_region_size = u32::try_from(signed_region.len())
        .map_err(|_| "signed region exceeds Rampart image v1 limit".to_string())?;
    let section_size = SIGNATURE_HEADER_SIZE + SIGNATURE_RECORD_SIZE;
    let mut out = vec![0u8; section_size];

    out[0..8].copy_from_slice(SIGNATURE_MAGIC);
    write_u16(&mut out, 8, SIGNATURE_FORMAT_VERSION);
    write_u16(
        &mut out,
        10,
        u16::try_from(SIGNATURE_HEADER_SIZE).expect("signature header fits u16"),
    );
    write_u32(
        &mut out,
        12,
        u32::try_from(section_size).expect("signature section fits u32"),
    );
    write_u32(
        &mut out,
        16,
        u32::try_from(IMAGE_HEADER_SIZE).expect("image header fits u32"),
    );
    write_u32(&mut out, 20, signed_region_size);
    write_u16(&mut out, 24, 1);
    write_u16(&mut out, 26, SIGNATURE_ALGORITHM_ECDSA_P256_SHA256);
    write_u16(
        &mut out,
        28,
        u16::try_from(SIGNATURE_RECORD_SIZE).expect("signature record fits u16"),
    );

    let record_offset = SIGNATURE_HEADER_SIZE;
    out[record_offset..record_offset + KEY_ID_SIZE].copy_from_slice(&record.key_id);
    write_u16(
        &mut out,
        record_offset + 8,
        SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
    );
    write_u16(&mut out, record_offset + 10, PUBLIC_KEY_ALGORITHM_P256);
    write_u16(
        &mut out,
        record_offset + 12,
        u16::try_from(SIGNATURE_SIZE).expect("signature size fits u16"),
    );
    write_u16(
        &mut out,
        record_offset + 14,
        u16::try_from(PUBLIC_KEY_SIZE).expect("public key size fits u16"),
    );
    out[record_offset + 16..record_offset + 16 + SIGNATURE_SIZE].copy_from_slice(&record.signature);
    out[record_offset + 80..record_offset + 80 + PUBLIC_KEY_SIZE]
        .copy_from_slice(&record.public_key);

    Ok(out)
}

fn parse_signature_section(
    bytes: &[u8],
    signed_region_offset: usize,
    signed_region_size: usize,
    manifest: &RampartManifest,
) -> Result<SignatureRecord, String> {
    let expected_size = SIGNATURE_HEADER_SIZE + SIGNATURE_RECORD_SIZE;
    if bytes.len() != expected_size {
        return Err("signature section size is invalid".to_string());
    }

    require_magic(&bytes[0..8], SIGNATURE_MAGIC, "signature section")?;
    require_u16(
        bytes,
        8,
        SIGNATURE_FORMAT_VERSION,
        "signature section format version",
    )?;
    require_u16(
        bytes,
        10,
        u16::try_from(SIGNATURE_HEADER_SIZE).expect("signature header fits u16"),
        "signature section header size",
    )?;
    require_u32(
        bytes,
        12,
        u32::try_from(expected_size).expect("signature section fits u32"),
        "signature section size",
    )?;
    require_u32(
        bytes,
        16,
        u32::try_from(signed_region_offset).map_err(|_| "signed region offset exceeds u32")?,
        "signature signed region offset",
    )?;
    require_u32(
        bytes,
        20,
        u32::try_from(signed_region_size).map_err(|_| "signed region size exceeds u32")?,
        "signature signed region size",
    )?;
    require_u16(bytes, 24, 1, "signature count")?;
    require_u16(
        bytes,
        26,
        SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
        "signature section algorithm",
    )?;
    require_u16(
        bytes,
        28,
        u16::try_from(SIGNATURE_RECORD_SIZE).expect("signature record fits u16"),
        "signature record size",
    )?;
    require_u16(bytes, 30, 0, "signature reserved field")?;

    let record_offset = SIGNATURE_HEADER_SIZE;
    let mut key_id = [0u8; KEY_ID_SIZE];
    key_id.copy_from_slice(&bytes[record_offset..record_offset + KEY_ID_SIZE]);
    if key_id != manifest.key_id {
        return Err("signature key ID does not match manifest policy".to_string());
    }

    require_u16(
        bytes,
        record_offset + 8,
        SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
        "signature record algorithm",
    )?;
    require_u16(
        bytes,
        record_offset + 10,
        PUBLIC_KEY_ALGORITHM_P256,
        "signature record public key algorithm",
    )?;
    require_u16(
        bytes,
        record_offset + 12,
        u16::try_from(SIGNATURE_SIZE).expect("signature size fits u16"),
        "signature size",
    )?;
    require_u16(
        bytes,
        record_offset + 14,
        u16::try_from(PUBLIC_KEY_SIZE).expect("public key size fits u16"),
        "public key size",
    )?;

    let mut signature = [0u8; SIGNATURE_SIZE];
    signature.copy_from_slice(&bytes[record_offset + 16..record_offset + 16 + SIGNATURE_SIZE]);
    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    public_key.copy_from_slice(&bytes[record_offset + 80..record_offset + 80 + PUBLIC_KEY_SIZE]);
    require_zeroes(
        &bytes[record_offset + 145..record_offset + SIGNATURE_RECORD_SIZE],
        "signature record padding",
    )?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| "signature record public key is not valid P-256 SEC1".to_string())?;
    let derived_key_id = derive_key_id(&verifying_key);
    if derived_key_id != key_id {
        return Err("signature key ID does not match embedded public key".to_string());
    }

    Ok(SignatureRecord {
        key_id,
        signature,
        public_key,
    })
}

fn verify_signature(bytes: &[u8], image: &ParsedImage) -> Result<bool, String> {
    let signed_region = &bytes[image.signed_region_range.clone()];
    let verifying_key = VerifyingKey::from_sec1_bytes(&image.signature.public_key)
        .map_err(|_| "signature public key is not valid P-256 SEC1".to_string())?;
    let signature = Signature::from_slice(&image.signature.signature)
        .map_err(|_| "signature bytes are not a valid P-256 ECDSA signature".to_string())?;

    Ok(verifying_key.verify(signed_region, &signature).is_ok())
}

fn encode_image(manifest: &[u8], payload: &[u8], signature: &[u8]) -> Result<Vec<u8>, String> {
    let manifest_offset = IMAGE_HEADER_SIZE;
    let payload_offset = checked_add(manifest_offset, manifest.len())?;
    let signature_offset = checked_add(payload_offset, payload.len())?;
    let file_len = checked_add(signature_offset, signature.len())?;
    let signed_region_size = checked_add(manifest.len(), payload.len())?;

    let mut out = vec![0u8; file_len];
    out[0..8].copy_from_slice(IMAGE_MAGIC);
    write_u16(&mut out, 8, IMAGE_FORMAT_VERSION);
    write_u16(&mut out, 10, IMAGE_KIND_FIRMWARE);
    write_u16(
        &mut out,
        12,
        u16::try_from(IMAGE_HEADER_SIZE).expect("image header fits u16"),
    );
    write_u32(
        &mut out,
        16,
        checked_u32(manifest_offset, "manifest offset")?,
    );
    write_u32(&mut out, 20, checked_u32(manifest.len(), "manifest size")?);
    write_u32(&mut out, 24, checked_u32(payload_offset, "payload offset")?);
    write_u32(&mut out, 28, checked_u32(payload.len(), "payload size")?);
    write_u32(
        &mut out,
        32,
        checked_u32(signature_offset, "signature offset")?,
    );
    write_u32(
        &mut out,
        36,
        checked_u32(signature.len(), "signature size")?,
    );
    write_u32(
        &mut out,
        40,
        checked_u32(manifest_offset, "signed region offset")?,
    );
    write_u32(
        &mut out,
        44,
        checked_u32(signed_region_size, "signed region size")?,
    );

    out[manifest_offset..payload_offset].copy_from_slice(manifest);
    out[payload_offset..signature_offset].copy_from_slice(payload);
    out[signature_offset..file_len].copy_from_slice(signature);

    Ok(out)
}

fn digest_payload(payload: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn target_matches(manifest: &RampartManifest, target: DeviceTarget) -> bool {
    manifest.vendor_id == target.vendor_id
        && manifest.product_id == target.product_id
        && manifest.hardware_family == target.hardware_family
        && manifest.component_id == target.component_id
}

fn format_image_report(
    image: &ParsedImage,
    payload_digest_valid: Option<bool>,
    signature_valid: Option<bool>,
) -> String {
    let manifest = &image.manifest;
    let payload_digest = hex_lower(&manifest.payload_digest);

    format!(
        "Rampart Image\n\nArtifact\n  {}\n\nTarget\n  vendor_id        0x{:08x}\n  product_id       0x{:08x}\n  hardware_family  0x{:08x}\n  hardware_rev     {}..{}\n  component_id     0x{:08x}\n\nVersion\n  {}\n\nSecurity Epoch\n  {}\n\nPayload\n  {} bytes\n  SHA-256\n  {}\n  digest {}\n\nAuthorization\n  role              {}\n  key_id            0x{}\n  signature         ECDSA_P256_SHA256\n  signature {}\n\nTrial Policy\n  attempts          {}\n  probation_ms      {}\n\nRollback\n  {}\n",
        manifest.artifact_id,
        manifest.vendor_id,
        manifest.product_id,
        manifest.hardware_family,
        manifest.hardware_revision_min,
        manifest.hardware_revision_max,
        manifest.component_id,
        manifest.version_string(),
        manifest.security_epoch,
        manifest.payload_size,
        payload_digest,
        optional_status(payload_digest_valid),
        manifest.signature_role_name(),
        key_id_hex(&manifest.key_id),
        optional_status(signature_valid),
        manifest.trial_max_attempts,
        manifest.trial_probation_ms,
        manifest.rollback_policy_name()
    )
}

fn parse_semver_core(version: &str) -> Result<(u16, u16, u16), String> {
    let mut parts = version.split('.');
    let major = parse_semver_part(parts.next(), "major")?;
    let minor = parse_semver_part(parts.next(), "minor")?;
    let patch = parse_semver_part(parts.next(), "patch")?;

    if parts.next().is_some() {
        return Err("version must use major.minor.patch form".to_string());
    }

    Ok((major, minor, patch))
}

fn parse_semver_part(part: Option<&str>, label: &str) -> Result<u16, String> {
    let value = part.ok_or_else(|| format!("version is missing {label} component"))?;
    if value.is_empty() {
        return Err(format!("version {label} component is empty"));
    }

    value
        .parse::<u16>()
        .map_err(|_| format!("version {label} component must fit in u16"))
}

fn parse_role(role: &str) -> Result<u16, String> {
    match role {
        "RELEASE" => Ok(ROLE_RELEASE),
        "SECURITY" => Ok(ROLE_SECURITY),
        "BOOT_MANAGER" => Ok(ROLE_BOOT_MANAGER),
        "RECOVERY" => Ok(ROLE_RECOVERY),
        "FACTORY" => Ok(ROLE_FACTORY),
        "DEVELOPMENT" => Ok(ROLE_DEVELOPMENT),
        _ => Err(format!("unknown signature role {role}")),
    }
}

fn role_name(role: u16) -> &'static str {
    match role {
        ROLE_RELEASE => "RELEASE",
        ROLE_SECURITY => "SECURITY",
        ROLE_BOOT_MANAGER => "BOOT_MANAGER",
        ROLE_RECOVERY => "RECOVERY",
        ROLE_FACTORY => "FACTORY",
        ROLE_DEVELOPMENT => "DEVELOPMENT",
        _ => "UNKNOWN",
    }
}

fn is_known_role(role: u16) -> bool {
    matches!(
        role,
        ROLE_RELEASE
            | ROLE_SECURITY
            | ROLE_BOOT_MANAGER
            | ROLE_RECOVERY
            | ROLE_FACTORY
            | ROLE_DEVELOPMENT
    )
}

fn parse_rollback_policy(policy: &str) -> Result<u16, String> {
    match policy {
        "none" => Ok(ROLLBACK_POLICY_NONE),
        "fallback" => Ok(ROLLBACK_POLICY_FALLBACK),
        _ => Err(format!("unknown rollback policy {policy}")),
    }
}

fn rollback_policy_name(policy: u16) -> &'static str {
    match policy {
        ROLLBACK_POLICY_NONE => "none",
        ROLLBACK_POLICY_FALLBACK => "fallback",
        _ => "unknown",
    }
}

fn is_known_rollback_policy(policy: u16) -> bool {
    matches!(policy, ROLLBACK_POLICY_NONE | ROLLBACK_POLICY_FALLBACK)
}

fn status_word(valid: bool) -> &'static str {
    if valid { "valid" } else { "rejected" }
}

fn optional_status(valid: Option<bool>) -> &'static str {
    match valid {
        Some(true) => "valid",
        Some(false) => "rejected",
        None => "not checked",
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, String> {
    left.checked_add(right)
        .ok_or_else(|| "section offset overflow".to_string())
}

fn checked_range(offset: usize, len: usize, total_len: usize) -> Result<Range<usize>, String> {
    let end = checked_add(offset, len)?;
    if end > total_len {
        return Err("section range extends beyond image bounds".to_string());
    }

    Ok(offset..end)
}

fn checked_u32(value: usize, field: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{field} exceeds u32"))
}

fn require_magic(actual: &[u8], expected: &[u8; 8], label: &str) -> Result<(), String> {
    if actual != expected {
        return Err(format!("{label} magic is invalid"));
    }

    Ok(())
}

fn require_zeroes(bytes: &[u8], label: &str) -> Result<(), String> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(format!("{label} must be zero"));
    }

    Ok(())
}

fn require_u16(bytes: &[u8], offset: usize, expected: u16, label: &str) -> Result<(), String> {
    let actual = read_u16(bytes, offset)?;
    if actual != expected {
        return Err(format!("{label} is unsupported"));
    }

    Ok(())
}

fn require_u32(bytes: &[u8], offset: usize, expected: u32, label: &str) -> Result<(), String> {
    let actual = read_u32(bytes, offset)?;
    if actual != expected {
        return Err(format!("{label} is unsupported"));
    }

    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = checked_add(offset, 2)?;
    if end > bytes.len() {
        return Err("u16 read exceeds bounds".to_string());
    }

    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = checked_add(offset, 4)?;
    if end > bytes.len() {
        return Err("u32 read exceeds bounds".to_string());
    }

    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }

    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use tempfile::tempdir;

    use super::{
        DeviceTarget, IMAGE_HEADER_SIZE, VerificationOptions, parse_image, sign_image, verify_image,
    };

    const TEST_PRIVATE_KEY_DER: [u8; 138] = [
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30,
        0x6B, 0x02, 0x01, 0x01, 0x04, 0x20, 0x7D, 0x7D, 0xC5, 0xF7, 0x1D, 0x32, 0x1B, 0xD8, 0x90,
        0x1B, 0x45, 0xAC, 0x1E, 0x18, 0x7C, 0xC7, 0xA6, 0x94, 0xE7, 0x7A, 0x14, 0x1D, 0xC4, 0x2D,
        0x9F, 0x44, 0xA7, 0xC7, 0xBC, 0x4E, 0x4D, 0x58, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x78,
        0x28, 0xCE, 0x99, 0x99, 0xD2, 0x5D, 0xED, 0x51, 0x4A, 0x69, 0xF8, 0x42, 0x72, 0x26, 0x91,
        0x4E, 0x36, 0x8F, 0x71, 0x02, 0x2D, 0x70, 0x1B, 0xD0, 0x21, 0x57, 0xD2, 0x91, 0x70, 0xF3,
        0xB2, 0xB4, 0x58, 0x18, 0x1B, 0x14, 0x26, 0x0C, 0x8C, 0xC8, 0x15, 0x39, 0xA4, 0x69, 0x2F,
        0xAB, 0x93, 0x58, 0x66, 0xDD, 0x5B, 0xED, 0xF2, 0xE8, 0xFB, 0x93, 0x88, 0xEA, 0x46, 0xCF,
        0xB9, 0xE2, 0x4F,
    ];

    #[test]
    fn signs_and_verifies_image_artifact() {
        let dir = tempdir().expect("tempdir");
        let payload_path = dir.path().join("payload.bin");
        let manifest_path = dir.path().join("manifest.toml");
        let key_path = dir.path().join("release-test-key.pem");
        let output_path = dir.path().join("firmware.rampart");

        fs::write(&payload_path, b"rampart test firmware\n").expect("payload");
        fs::write(
            &manifest_path,
            r#"
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
"#,
        )
        .expect("manifest");

        let signing_key = SigningKey::from_slice(&TEST_PRIVATE_KEY_DER[36..68]).expect("key");
        let pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode key");
        fs::write(&key_path, pem.as_bytes()).expect("key file");

        let parsed =
            sign_image(&payload_path, &manifest_path, &key_path, &output_path, None).expect("sign");
        assert_eq!(parsed.manifest.version_string(), "2.4.0");
        assert_eq!(parsed.manifest.security_epoch, 12);

        let bytes = fs::read(&output_path).expect("image");
        let parsed_again = parse_image(&bytes).expect("parse");
        assert_eq!(
            parsed_again.manifest.artifact_id,
            parsed.manifest.artifact_id
        );
        assert_eq!(parsed_again.manifest_range.start, IMAGE_HEADER_SIZE);

        let report = verify_image(
            &bytes,
            &VerificationOptions {
                device_target: Some(DeviceTarget {
                    vendor_id: 1380011344,
                    product_id: 1,
                    hardware_family: 1413,
                    component_id: 16,
                }),
                minimum_security_epoch: 12,
            },
        )
        .expect("verify");
        assert!(report.is_valid());
    }

    #[test]
    fn rejects_tampered_payload() {
        let dir = tempdir().expect("tempdir");
        let payload_path = dir.path().join("payload.bin");
        let manifest_path = dir.path().join("manifest.toml");
        let key_path = dir.path().join("release-test-key.pem");
        let output_path = dir.path().join("firmware.rampart");

        fs::write(&payload_path, b"rampart test firmware\n").expect("payload");
        fs::write(
            &manifest_path,
            r#"
artifact_id = "industrial-controller-main-2.4.0"
vendor_id = 1380011344
product_id = 1
hardware_family = 1413
hardware_revision_min = 1
hardware_revision_max = 3
component_id = 16
version = "2.4.0"
security_epoch = 12
"#,
        )
        .expect("manifest");

        let signing_key = SigningKey::from_slice(&TEST_PRIVATE_KEY_DER[36..68]).expect("key");
        let pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode key");
        fs::write(&key_path, pem.as_bytes()).expect("key file");

        sign_image(&payload_path, &manifest_path, &key_path, &output_path, None).expect("sign");
        let mut bytes = fs::read(&output_path).expect("image");
        let image = parse_image(&bytes).expect("parse");
        bytes[image.payload_range.start] ^= 0x01;

        let report = verify_image(
            &bytes,
            &VerificationOptions {
                device_target: None,
                minimum_security_epoch: 0,
            },
        )
        .expect("verify tampered");
        assert!(!report.payload_digest_valid);
        assert!(!report.signature_valid);
        assert!(!report.is_valid());
    }
}
