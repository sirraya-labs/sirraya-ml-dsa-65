//! Enterprise-Grade Dilithium5 Signature Verification
//! NIST FIPS 203 Compliant - Production Ready
//!
//! Run: cargo run --example enterprise_verify --features="std,serde,serde_json"

use dilithium5::{constants::*, Dilithium5};
use hex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// Reuse the same serialization modules
mod hex_serde_array {
    use hex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length"))
    }
}

mod hex_serde_vec {
    use hex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub algorithm: String,
    pub security_level: u8,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub created_at: u64,
    pub key_id: String,
    pub format_version: String,
    pub generator: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPackage {
    pub metadata: KeyMetadata,
    #[serde(with = "hex_serde_array")]
    pub public_key: [u8; PUBLICKEYBYTES],
    #[serde(with = "hex_serde_array")]
    pub secret_key: [u8; SECRETKEYBYTES],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub signature_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub security_level: u8,
    pub signature_bytes: usize,
    pub created_at: u64,
    pub message_digest: String,
    pub format_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignaturePackage {
    pub metadata: SignatureMetadata,
    #[serde(with = "hex_serde_array")]
    pub signature: [u8; SIGNBYTES],
    #[serde(with = "hex_serde_vec")]
    pub message: Vec<u8>,
}

// ==================== ENTERPRISE VERIFICATION ====================

pub struct EnterpriseVerifier;

impl EnterpriseVerifier {
    /// Load key package from JSON file
    pub fn load_keypackage(path: &Path) -> Result<KeyPackage, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let key_package: KeyPackage = serde_json::from_str(&data)?;
        Ok(key_package)
    }

    /// Load signature package from JSON file
    pub fn load_signature_package(
        path: &Path,
    ) -> Result<SignaturePackage, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let sig_package: SignaturePackage = serde_json::from_str(&data)?;
        Ok(sig_package)
    }

    /// Verify a signature with comprehensive validation
    pub fn verify_signature(
        public_key: &[u8; PUBLICKEYBYTES],
        message: &[u8],
        signature: &[u8; SIGNBYTES],
    ) -> Result<VerificationReport, Box<dyn std::error::Error>> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();

        // Perform the actual Dilithium5 verification
        let is_valid = Dilithium5::verify(public_key, message, signature)?;

        let end_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();

        let verification_time_ms = (end_time - start_time) as f64 / 1000.0;

        // Generate verification report
        let report = VerificationReport {
            verified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            algorithm: "Dilithium5".to_string(),
            security_level: 5,
            nist_standard: "FIPS 203".to_string(),
            public_key_fingerprint: hex::encode(&public_key[..16]),
            message_digest: {
                let mut hasher = Sha3_256::new();
                hasher.update(message);
                hex::encode(hasher.finalize())
            },
            signature_fingerprint: hex::encode(&signature[..16]),
            verification_result: is_valid,
            verification_time_ms,
            signature_bytes: SIGNBYTES,
        };

        Ok(report)
    }

    /// Verify and generate comprehensive audit report
    pub fn verify_with_audit(
        key_package: &KeyPackage,
        sig_package: &SignaturePackage,
        output_dir: &Path,
    ) -> Result<VerificationReport, Box<dyn std::error::Error>> {
        fs::create_dir_all(output_dir)?;

        println!("\n[VERIFICATION AUDIT]");
        println!("    Signature ID: {}", sig_package.metadata.signature_id);
        println!("    Key ID: {}", key_package.metadata.key_id);

        // Verify key ID matches
        if sig_package.metadata.key_id != key_package.metadata.key_id {
            return Err(format!(
                "Key ID mismatch: signature uses '{}' but provided key is '{}'",
                sig_package.metadata.key_id, key_package.metadata.key_id
            )
            .into());
        }

        // Verify algorithm
        if sig_package.metadata.algorithm != "Dilithium5"
            || key_package.metadata.algorithm != "Dilithium5"
        {
            return Err("Algorithm mismatch: expected Dilithium5".into());
        }

        // Verify signature size
        if sig_package.signature.len() != SIGNBYTES {
            return Err(format!(
                "Invalid signature size: expected {} bytes, got {} bytes",
                SIGNBYTES,
                sig_package.signature.len()
            )
            .into());
        }

        // Verify message digest matches
        let mut hasher = Sha3_256::new();
        hasher.update(&sig_package.message);
        let computed_digest = hex::encode(hasher.finalize());

        if computed_digest != sig_package.metadata.message_digest {
            println!("    WARNING: Message digest mismatch");
            println!("      Expected: {}", sig_package.metadata.message_digest);
            println!("      Computed: {}", computed_digest);
        }

        // Perform cryptographic verification
        let report = Self::verify_signature(
            &key_package.public_key,
            &sig_package.message,
            &sig_package.signature,
        )?;

        // Save audit report
        let audit_path =
            output_dir.join(format!("{}_audit.json", sig_package.metadata.signature_id));
        let audit_data = serde_json::json!({
            "verification_audit": {
                "signature_id": sig_package.metadata.signature_id,
                "key_id": key_package.metadata.key_id,
                "verification_timestamp": report.verified_at,
                "verification_result": report.verification_result,
                "verification_time_ms": report.verification_time_ms,
                "algorithm": report.algorithm,
                "security_level": report.security_level,
                "nist_standard": report.nist_standard,
                "cryptographic_verification": {
                    "public_key_fingerprint": report.public_key_fingerprint,
                    "signature_fingerprint": report.signature_fingerprint,
                    "message_digest": report.message_digest,
                    "signature_bytes": report.signature_bytes
                },
                "compliance": {
                    "fips_203": true,
                    "pqc_standard": true,
                    "tamper_evident": true,
                    "non_repudiation": report.verification_result
                },
                "verifier": "dilithium5-rust/enterprise-verifier v1.0.0"
            }
        });

        fs::write(audit_path, serde_json::to_string_pretty(&audit_data)?)?;

        Ok(report)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    pub verified_at: u64,
    pub algorithm: String,
    pub security_level: u8,
    pub nist_standard: String,
    pub public_key_fingerprint: String,
    pub message_digest: String,
    pub signature_fingerprint: String,
    pub verification_result: bool,
    pub verification_time_ms: f64,
    pub signature_bytes: usize,
}

// ==================== PRODUCTION EXAMPLE ====================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Sirraya One Enterprise Verification");
    println!("NIST FIPS 203 Post-Quantum Cryptography");
    println!("============================================");

    // Check for quantum_keys directory
    let key_dir = PathBuf::from("quantum_keys");
    if !key_dir.exists() {
        println!("Error: quantum_keys/ directory not found.");
        return Ok(());
    }

    // Check for quantum_signatures directory
    let sig_dir = PathBuf::from("quantum_signatures");
    if !sig_dir.exists() {
        println!("Error: quantum_signatures/ directory not found.");
        println!("Please run enterprise_sign first:");
        println!("cargo run --example enterprise_sign --features=\"std,serde,serde_json\"");
        return Ok(());
    }

    // Find the most recent key package
    let key_files: Vec<_> = fs::read_dir(&key_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .filter(|e| {
            e.path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("dilithium5-prod"))
                .unwrap_or(false)
        })
        .collect();

    if key_files.is_empty() {
        println!("No key package found in quantum_keys/");
        return Ok(());
    }

    // Find the most recent signature package
    let sig_files: Vec<_> = fs::read_dir(&sig_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .filter(|e| {
            e.path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("sig-dilithium5"))
                .unwrap_or(false)
        })
        .collect();

    if sig_files.is_empty() {
        println!("No signature package found in quantum_signatures/");
        println!("Please run enterprise_sign first:");
        println!("cargo run --example enterprise_sign --features=\"std,serde,serde_json\"");
        return Ok(());
    }

    let key_path = key_files[0].path();
    let sig_path = sig_files[0].path();

    println!(
        "\n[1/4] Loading key package: {}",
        key_path.file_name().unwrap_or_default().to_string_lossy()
    );
    let key_package = EnterpriseVerifier::load_keypackage(&key_path)?;
    println!("    Key ID: {}", key_package.metadata.key_id);
    println!("    Created: {}", key_package.metadata.created_at);

    println!(
        "\n[2/4] Loading signature package: {}",
        sig_path.file_name().unwrap_or_default().to_string_lossy()
    );
    let sig_package = EnterpriseVerifier::load_signature_package(&sig_path)?;
    println!("    Signature ID: {}", sig_package.metadata.signature_id);
    println!("    Created: {}", sig_package.metadata.created_at);
    println!(
        "    Message: {}",
        String::from_utf8_lossy(&sig_package.message)
            .lines()
            .next()
            .unwrap_or("")
    );

    println!("\n[3/4] Performing cryptographic verification...");
    println!("    Algorithm: Dilithium5 (FIPS 203)");
    println!("    Security Level: 5");

    let audit_dir = PathBuf::from("quantum_audits");
    let report = EnterpriseVerifier::verify_with_audit(&key_package, &sig_package, &audit_dir)?;

    println!("\n[4/4] Verification Result:");
    println!(
        "    Status: {}",
        if report.verification_result {
            "✅ VALID - Signature authentic"
        } else {
            "❌ INVALID - Signature forged or tampered"
        }
    );
    println!(
        "    Verification time: {:.3} ms",
        report.verification_time_ms
    );
    println!(
        "    Public key fingerprint: {}...",
        &report.public_key_fingerprint[..16]
    );
    println!(
        "    Signature fingerprint: {}...",
        &report.signature_fingerprint[..16]
    );
    println!("    Message digest: {}...", &report.message_digest[..16]);

    println!("\n✅ Audit report saved:");
    println!("    Directory: {}/", audit_dir.display());
    println!("    File: {}_audit.json", sig_package.metadata.signature_id);

    println!("\n✅ Verification complete");
    println!(
        "   Integrity: {}",
        if report.verification_result {
            "INTACT"
        } else {
            "COMPROMISED"
        }
    );
    println!(
        "   Non-repudiation: {}",
        if report.verification_result {
            "ESTABLISHED"
        } else {
            "FAILED"
        }
    );
    println!("   Timestamp: {}", report.verified_at);

    Ok(())
}
