//! Enterprise-Grade Dilithium5 Signing Operations
//! NIST FIPS 203 Compliant - Production Ready
//!
//! Run: cargo run --example enterprise_sign --features="std,serde,serde_json"

use dilithium5::{Dilithium5, constants::*};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use hex;

// Reuse the same KeyPackage struct from enterprise_keygen
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

// For fixed-size arrays
mod hex_serde_array {
    use serde::{Deserialize, Serializer, Deserializer};
    use hex;

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
        bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid length"))
    }
}

// For Vec<u8> (variable length)
mod hex_serde_vec {
    use serde::{Deserialize, Serializer, Deserializer};
    use hex;

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

// ==================== ENTERPRISE SIGNING ====================

pub struct EnterpriseSigner;

impl EnterpriseSigner {
    /// Load a key package from JSON file
    pub fn load_keypackage(path: &Path) -> Result<KeyPackage, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let key_package: KeyPackage = serde_json::from_str(&data)?;
        Ok(key_package)
    }
    
    /// Sign a message with enterprise-grade audit trail
    pub fn sign_message(
        key_package: &KeyPackage,
        message: &[u8],
        output_dir: &Path,
    ) -> Result<SignaturePackage, Box<dyn std::error::Error>> {
        // Create output directory
        fs::create_dir_all(output_dir)?;
        
        // Generate actual Dilithium5 signature
        let signature = Dilithium5::sign(&key_package.secret_key, message)?;
        
        // Generate signature ID
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let signature_id = format!("sig-{}-{}", key_package.metadata.key_id, timestamp);
        
        // Simple hash for message digest (using sha3 since it's already a dependency)
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();
        
        // Create signature package with metadata
        let signature_package = SignaturePackage {
            metadata: SignatureMetadata {
                signature_id: signature_id.clone(),
                key_id: key_package.metadata.key_id.clone(),
                algorithm: "Dilithium5".to_string(),
                security_level: 5,
                signature_bytes: SIGNBYTES,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                message_digest: hex::encode(message_hash),
                format_version: "1.0.0".to_string(),
            },
            signature,
            message: message.to_vec(),
        };
        
        // Save signature in multiple formats
        Self::save_signature_binary(&signature_package, output_dir)?;
        Self::save_signature_json(&signature_package, output_dir)?;
        Self::save_message_file(&signature_package, output_dir)?;
        Self::save_verification_instructions(&signature_package, key_package, output_dir)?;
        
        Ok(signature_package)
    }
    
    /// Save raw signature binary
    fn save_signature_binary(
        sig_package: &SignaturePackage,
        output_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sig_path = output_dir.join(format!("{}.sig.raw", sig_package.metadata.signature_id));
        fs::write(&sig_path, &sig_package.signature)?;
        
        let sig_hex_path = output_dir.join(format!("{}.sig.hex", sig_package.metadata.signature_id));
        fs::write(&sig_hex_path, hex::encode(&sig_package.signature))?;
        
        Ok(())
    }
    
    /// Save original message
    fn save_message_file(
        sig_package: &SignaturePackage,
        output_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let msg_path = output_dir.join(format!("{}.msg.txt", sig_package.metadata.signature_id));
        fs::write(&msg_path, &sig_package.message)?;
        
        let msg_hex_path = output_dir.join(format!("{}.msg.hex", sig_package.metadata.signature_id));
        fs::write(&msg_hex_path, hex::encode(&sig_package.message))?;
        
        Ok(())
    }
    
    /// Save signature JSON with metadata
    fn save_signature_json(
        sig_package: &SignaturePackage,
        output_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json_path = output_dir.join(format!("{}.json", sig_package.metadata.signature_id));
        let json_data = serde_json::to_string_pretty(sig_package)?;
        fs::write(json_path, json_data)?;
        Ok(())
    }
    
    /// Save verification instructions
    fn save_verification_instructions(
        sig_package: &SignaturePackage,
        key_package: &KeyPackage,
        output_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let instructions = serde_json::json!({
            "verification_instructions": {
                "signature_id": sig_package.metadata.signature_id,
                "key_id": key_package.metadata.key_id,
                "algorithm": "Dilithium5",
                "nist_standard": "FIPS 203",
                "security_level": 5,
                "steps": [
                    {
                        "step": 1,
                        "action": "Load public key",
                        "file": format!("{}.pk.raw", key_package.metadata.key_id),
                        "format": "Raw binary",
                        "location": format!("quantum_keys/{}.pk.raw", key_package.metadata.key_id)
                    },
                    {
                        "step": 2,
                        "action": "Load signature",
                        "file": format!("{}.sig.raw", sig_package.metadata.signature_id),
                        "format": "Raw binary",
                        "location": format!("quantum_signatures/{}.sig.raw", sig_package.metadata.signature_id)
                    },
                    {
                        "step": 3,
                        "action": "Load original message",
                        "file": format!("{}.msg.txt", sig_package.metadata.signature_id),
                        "format": "UTF-8 text",
                        "location": format!("quantum_signatures/{}.msg.txt", sig_package.metadata.signature_id)
                    },
                    {
                        "step": 4,
                        "action": "Verify using Dilithium5",
                        "command": "cargo run --example enterprise_verify --features=\"std,serde,serde_json\"",
                        "verification_function": "Dilithium5::verify()"
                    }
                ],
                "generated_at": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                "verification_tool": "dilithium5-rust/enterprise"
            }
        });
        
        let inst_path = output_dir.join(format!("{}_verify.json", sig_package.metadata.signature_id));
        fs::write(inst_path, serde_json::to_string_pretty(&instructions)?)?;
        
        Ok(())
    }
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

// ==================== PRODUCTION EXAMPLE ====================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Sirraya One Enterprise Signing");
    println!("NIST FIPS 203 Post-Quantum Cryptography");
    println!("==========================================");
    
    // Load the key package from previous step
    let key_dir = PathBuf::from("quantum_keys");
    if !key_dir.exists() {
        println!("Error: quantum_keys/ directory not found.");
        println!("Please run enterprise_keygen first:");
        println!("cargo run --example enterprise_keygen --features=\"std,serde,serde_json\"");
        return Ok(());
    }
    
    let key_files: Vec<_> = fs::read_dir(&key_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "json").unwrap_or(false))
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
        println!("Please run enterprise_keygen first:");
        println!("cargo run --example enterprise_keygen --features=\"std,serde,serde_json\"");
        return Ok(());
    }
    
    // Use the most recent key
    let key_path = key_files[0].path();
    println!("\n[1/4] Loading key package: {}", key_path.file_name().unwrap_or_default().to_string_lossy());
    let key_package = EnterpriseSigner::load_keypackage(&key_path)?;
    println!("    Key ID: {}", key_package.metadata.key_id);
    println!("    Algorithm: {}", key_package.metadata.algorithm);
    println!("    Created: {}", key_package.metadata.created_at);
    
    // Get message from user
    println!("\n[2/4] Enter message to sign (press Enter twice to finish):");
    
    let mut message = String::new();
    let stdin = std::io::stdin();
    let mut lines = 0;
    
    for line in stdin.lines() {
        let line = line?;
        if line.is_empty() {
            lines += 1;
            if lines >= 2 {
                break;
            }
        } else {
            lines = 0;
            message.push_str(&line);
            message.push('\n');
        }
    }
    
    if message.is_empty() {
        message = "Default test message for Dilithium5 enterprise signing".to_string();
        println!("    Using default message");
    }
    
    // Create signing output directory
    let sig_dir = PathBuf::from("quantum_signatures");
    
    println!("\n[3/4] Generating Dilithium5 signature...");
    println!("    Message length: {} bytes", message.len());
    println!("    Signature size: {} bytes", SIGNBYTES);
    
    let sig_package = EnterpriseSigner::sign_message(
        &key_package,
        message.as_bytes(),
        &sig_dir,
    )?;
    
    println!("\n[4/4] Signature generation successful");
    println!("    Signature ID: {}", sig_package.metadata.signature_id);
    println!("    Created: {}", sig_package.metadata.created_at);
    println!("    Signature fingerprint: {}...", 
        hex::encode(&sig_package.signature[..16]));
    println!("    Message digest (SHA3-256): {}", sig_package.metadata.message_digest);
    
    println!("\n✅ Enterprise signature files written:");
    println!("    Directory: {}/", sig_dir.display());
    println!("    Files:");
    println!("      • {}.json         - Complete signature package with metadata", 
        sig_package.metadata.signature_id);
    println!("      • {}.sig.raw      - Raw signature (binary)", 
        sig_package.metadata.signature_id);
    println!("      • {}.sig.hex      - Raw signature (hex)", 
        sig_package.metadata.signature_id);
    println!("      • {}.msg.txt      - Original message (text)", 
        sig_package.metadata.signature_id);
    println!("      • {}.msg.hex      - Original message (hex)", 
        sig_package.metadata.signature_id);
    println!("      • {}_verify.json  - Verification instructions", 
        sig_package.metadata.signature_id);
    
    println!("\n✅ Signing complete");
    println!("   To verify this signature, run:");
    println!("   cargo run --example enterprise_verify --features=\"std,serde,serde_json\"");
    
    Ok(())
}