use std::fs;
use std::path::Path;

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub const KEY_ID_SIZE: usize = 8;

pub fn derive_key_id(public_key: &VerifyingKey) -> [u8; KEY_ID_SIZE] {
    let public_key_bytes = public_key.to_encoded_point(false);
    let digest = Sha256::digest(public_key_bytes.as_bytes());
    let mut key_id = [0u8; KEY_ID_SIZE];
    key_id.copy_from_slice(&digest[..KEY_ID_SIZE]);
    key_id
}

pub fn key_id_hex(key_id: &[u8; KEY_ID_SIZE]) -> String {
    let mut encoded = String::with_capacity(KEY_ID_SIZE * 2);

    for byte in key_id {
        encoded.push_str(&format!("{byte:02x}"));
    }

    encoded
}

pub fn parse_key_id_hex(encoded: &str) -> Result<[u8; KEY_ID_SIZE], String> {
    let value = encoded
        .strip_prefix("0x")
        .or_else(|| encoded.strip_prefix("0X"))
        .unwrap_or(encoded);

    if value.len() != KEY_ID_SIZE * 2 {
        return Err(format!(
            "key ID must contain {} hexadecimal characters",
            KEY_ID_SIZE * 2
        ));
    }

    let mut key_id = [0u8; KEY_ID_SIZE];
    for (index, byte) in key_id.iter_mut().enumerate() {
        let start = index * 2;
        let end = start + 2;
        *byte = u8::from_str_radix(&value[start..end], 16)
            .map_err(|_| "key ID contains non-hexadecimal characters".to_string())?;
    }

    Ok(key_id)
}

pub fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let pem = fs::read_to_string(path)
        .map_err(|error| format!("failed to read key {}: {error}", path.display()))?;

    SigningKey::from_pkcs8_pem(&pem).map_err(|error| {
        format!(
            "failed to decode P-256 PKCS#8 key {}: {error}",
            path.display()
        )
    })
}

pub fn generate_private_key(path: &Path) -> Result<String, String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing key {}",
            path.display()
        ));
    }

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let key_id = derive_key_id(verifying_key);
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| format!("failed to encode PKCS#8 key: {error}"))?;

    fs::write(path, pem.as_bytes())
        .map_err(|error| format!("failed to write key {}: {error}", path.display()))?;

    Ok(key_id_hex(&key_id))
}

pub fn inspect_private_key(path: &Path) -> Result<String, String> {
    let signing_key = read_signing_key(path)?;
    let verifying_key = signing_key.verifying_key();
    let key_id = derive_key_id(verifying_key);

    Ok(format!(
        "Rampart Key\n\nAlgorithm\n  ECDSA_P256_SHA256\n\nKey ID\n  0x{}\n",
        key_id_hex(&key_id)
    ))
}

pub fn export_public_key(private_key_path: &Path, output_path: &Path) -> Result<String, String> {
    if output_path.exists() {
        return Err(format!(
            "refusing to overwrite existing public key {}",
            output_path.display()
        ));
    }

    let signing_key = read_signing_key(private_key_path)?;
    let verifying_key = signing_key.verifying_key();
    let key_id = derive_key_id(verifying_key);
    let pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| format!("failed to encode public key: {error}"))?;

    fs::write(output_path, pem.as_bytes()).map_err(|error| {
        format!(
            "failed to write public key {}: {error}",
            output_path.display()
        )
    })?;

    Ok(key_id_hex(&key_id))
}

#[cfg(test)]
mod tests {
    use super::{KEY_ID_SIZE, parse_key_id_hex};

    #[test]
    fn parses_prefixed_key_id() {
        let parsed = parse_key_id_hex("0x0011223344556677").expect("parse key id");
        assert_eq!(parsed, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    #[test]
    fn rejects_wrong_key_id_length() {
        let error = parse_key_id_hex("0011").expect_err("short key id rejected");
        assert!(error.contains(&(KEY_ID_SIZE * 2).to_string()));
    }
}
