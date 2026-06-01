// src/vc_verifier.rs
//! Verifiable Credential verification using ML-DSA-65
//! Supports the mldsa65-rdfc-2024 cryptosuite

use serde_json::{json, Value};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use std::collections::BTreeMap;

use crate::constants::{PUBLICKEYBYTES, SIGNBYTES};
use crate::ml_dsa_65::MlDsa65;

const MLDSA65_MULTICODEC: u16 = 0x1305; // ML-DSA-65 multicodec identifier

/// Extract public key from did:key with ML-DSA-65 multicodec
pub fn extract_public_key_from_did_key(did_key: &str) -> Result<[u8; PUBLICKEYBYTES], Box<dyn std::error::Error>> {
    // did:key:z<base58btc-multibase>
    let encoded = did_key.strip_prefix("did:key:z")
        .ok_or("Invalid did:key format")?;
    
    // Decode base58btc (multibase 'z' prefix)
    let multicodec_bytes = bs58::decode(encoded).into_vec()?;
    
    // Parse multicodec prefix
    if multicodec_bytes.len() < 2 {
        return Err("Invalid multicodec length".into());
    }
    
    let codec = u16::from_be_bytes([multicodec_bytes[0], multicodec_bytes[1]]);
    if codec != MLDSA65_MULTICODEC {
        return Err(format!("Expected ML-DSA-65 multicodec (0x{:04x}), got 0x{:04x}", 
                          MLDSA65_MULTICODEC, codec).into());
    }
    
    // Extract raw public key bytes
    let pk_bytes = &multicodec_bytes[2..];
    if pk_bytes.len() != PUBLICKEYBYTES {
        return Err(format!("Invalid public key length: expected {}, got {}", 
                          PUBLICKEYBYTES, pk_bytes.len()).into());
    }
    
    let mut pk = [0u8; PUBLICKEYBYTES];
    pk.copy_from_slice(pk_bytes);
    Ok(pk)
}

/// Simple JCS (JSON Canonicalization Scheme) implementation
pub fn canonicalize_json_jcs(value: &Value) -> Result<String, Box<dyn std::error::Error>> {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map.iter().collect();
            let mut result = String::from("{");
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    result.push(',');
                }
                result.push('"');
                result.push_str(k);
                result.push_str("\":");
                result.push_str(&canonicalize_json_jcs(v)?);
            }
            result.push('}');
            Ok(result)
        }
        Value::Array(arr) => {
            let mut result = String::from("[");
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    result.push(',');
                }
                result.push_str(&canonicalize_json_jcs(v)?);
            }
            result.push(']');
            Ok(result)
        }
        Value::String(s) => Ok(json!(s).to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok("null".to_string()),
    }
}

/// Canonicalize VC by removing proof and applying JCS
pub fn canonicalize_vc(vc: &Value) -> Result<String, Box<dyn std::error::Error>> {
    // Remove proof from document
    let mut vc_without_proof = vc.clone();
    if let Some(obj) = vc_without_proof.as_object_mut() {
        obj.remove("proof");
    }
    
    canonicalize_json_jcs(&vc_without_proof)
}

/// Construct verification message according to mldsa65-rdfc-2024
pub fn construct_verification_message(
    canonical_doc: &str,
    proof_config: &Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let proof_config_canonical = canonicalize_json_jcs(proof_config)?;
    
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, proof_config_canonical.as_bytes());
    
    let mut msg = vec![0u8; 64]; // 512 bits
    hasher.finalize_xof().read(&mut msg);
    
    Ok(msg)
}

/// Verify a Verifiable Credential with ML-DSA-65 proof
pub fn verify_vc(vc_json: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // Parse the VC
    let vc: Value = serde_json::from_str(vc_json)?;
    
    // Extract proof
    let proof = vc.get("proof")
        .ok_or("No proof found in credential")?;
    
    // Verify cryptosuite
    let cryptosuite = proof.get("cryptosuite")
        .and_then(|v| v.as_str())
        .ok_or("Missing cryptosuite")?;
    
    if cryptosuite != "mldsa65-rdfc-2024" {
        return Err(format!("Unsupported cryptosuite: {}", cryptosuite).into());
    }
    
    // Extract verification method (DID key)
    let vm = proof.get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or("Missing verificationMethod")?;
    
    // Extract the public key
    let pk = extract_public_key_from_did_key(vm)?;
    
    // Extract signature
    let proof_value = proof.get("proofValue")
        .and_then(|v| v.as_str())
        .ok_or("Missing proofValue")?;
    
    let signature = URL_SAFE_NO_PAD.decode(proof_value)?;
    if signature.len() != SIGNBYTES {
        return Err(format!("Invalid signature length: expected {}, got {}", 
                          SIGNBYTES, signature.len()).into());
    }
    
    // Canonicalize the unsigned VC
    let canonical_doc = canonicalize_vc(&vc)?;
    
    // Create proof configuration (without proofValue)
    let proof_config = {
        let mut config = proof.clone();
        if let Some(obj) = config.as_object_mut() {
            obj.remove("proofValue");
        }
        config
    };
    
    // Construct verification message
    let verification_msg = construct_verification_message(&canonical_doc, &proof_config)?;
    
    // Verify with ML-DSA-65
    let mut sig_array = [0u8; SIGNBYTES];
    sig_array.copy_from_slice(&signature);
    
    // Use ML-DSA-65 verify function
    let is_valid = MlDsa65::verify(&pk, &verification_msg, &sig_array)?;
    
    Ok(is_valid)
}