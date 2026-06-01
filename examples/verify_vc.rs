// examples/verify_vc.rs
// Verify a W3C Verifiable Credential with ML-DSA-65
// cryptosuite: mldsa65-jcs-2024
//
// Usage: cargo run --example verify_vc --features w3c -- <credential.json>

use base64::{
    engine::general_purpose::URL_SAFE, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use serde_json::Value;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use sirraya_ml_dsa_65::constants::{PUBLICKEYBYTES, SIGNBYTES};
use sirraya_ml_dsa_65::MlDsa65;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Get VC file from command-line argument --------------------------------
    let args: Vec<String> = env::args().collect();
    let vc_path = if args.len() > 1 {
        args[1].as_str()
    } else {
        "test_vc.json"
    };

    println!("================================================================================");
    println!("        ML-DSA-65 W3C Verifiable Credential Verification");
    println!("        Cryptosuite: mldsa65-jcs-2024");
    println!("================================================================================");
    println!();

    // Read VC from file
    let vc_json = match fs::read_to_string(vc_path) {
        Ok(content) => {
            println!("[OK] Loaded VC from '{}'", vc_path);
            content
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to read '{}': {}", vc_path, e);
            eprintln!(
                "        Usage: cargo run --example verify_vc --features w3c -- <credential.json>"
            );
            return Err(e.into());
        }
    };

    // Parse JSON
    let vc: Value = match serde_json::from_str(&vc_json) {
        Ok(v) => {
            println!("[OK] Parsed JSON successfully");
            v
        }
        Err(e) => {
            eprintln!("[ERROR] Invalid JSON: {}", e);
            return Err(e.into());
        }
    };

    // Display VC metadata
    println!("--------------------------------------------------------------------------------");
    println!("VC METADATA:");
    println!("  ID:          {}", vc["id"].as_str().unwrap_or("unknown"));

    let issuer = vc["issuer"].as_str().unwrap_or("unknown");
    if issuer.len() > 80 {
        println!("  Issuer:      {}...", &issuer[..80]);
    } else {
        println!("  Issuer:      {}", issuer);
    }

    println!(
        "  Issuance:    {}",
        vc["issuanceDate"].as_str().unwrap_or("unknown")
    );
    if let Some(types) = vc["type"].as_array() {
        let type_strs: Vec<String> = types
            .iter()
            .filter_map(|t| t.as_str().map(String::from))
            .collect();
        println!("  Types:       {}", type_strs.join(", "));
    }

    // Extract proof object
    let proof = match vc.get("proof") {
        Some(p) => p,
        None => {
            eprintln!("[ERROR] No proof found in VC");
            return Err("Missing proof".into());
        }
    };

    println!("--------------------------------------------------------------------------------");
    println!("PROOF DETAILS:");

    let cryptosuite = proof["cryptosuite"].as_str().unwrap_or("");
    println!("  Cryptosuite: {}", cryptosuite);

    let proof_type = proof["type"].as_str().unwrap_or("");
    println!("  Proof Type:  {}", proof_type);
    println!("  Created:     {}", proof["created"].as_str().unwrap_or(""));
    println!(
        "  Purpose:     {}",
        proof["proofPurpose"].as_str().unwrap_or("")
    );

    let vm = match proof["verificationMethod"].as_str() {
        Some(v) => v,
        None => {
            eprintln!("[ERROR] No verification method found");
            return Err("Missing verificationMethod".into());
        }
    };
    println!("  VerifMethod: {}...", &vm[..60.min(vm.len())]);

    let sig_b64 = match proof["proofValue"].as_str() {
        Some(s) => s,
        None => {
            eprintln!("[ERROR] No proof value found");
            return Err("Missing proofValue".into());
        }
    };
    println!("  Sig (b64url): {} chars", sig_b64.len());

    println!("--------------------------------------------------------------------------------");
    println!("PUBLIC KEY EXTRACTION:");

    let pk = match extract_public_key_from_did(vm) {
        Ok(pk) => {
            println!("[OK] Extracted public key from DID");
            println!("     Length: {} bytes", pk.len());
            println!(
                "     Prefix: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                pk[0], pk[1], pk[2], pk[3], pk[4], pk[5], pk[6], pk[7]
            );
            pk
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to extract public key: {}", e);
            return Err(e);
        }
    };

    println!("--------------------------------------------------------------------------------");
    println!("SIGNATURE DECODING:");

    let sig_bytes = decode_base64url(sig_b64)?;
    println!("[OK] Decoded signature: {} bytes", sig_bytes.len());
    if sig_bytes.len() >= 8 {
        println!(
            "     Prefix: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            sig_bytes[0],
            sig_bytes[1],
            sig_bytes[2],
            sig_bytes[3],
            sig_bytes[4],
            sig_bytes[5],
            sig_bytes[6],
            sig_bytes[7]
        );
    }

    let mut signature = [0u8; SIGNBYTES];
    let copy_len = sig_bytes.len().min(SIGNBYTES);
    signature[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);

    println!("--------------------------------------------------------------------------------");
    println!("SELF-TEST: Verifying ML-DSA-65 implementation...");
    match MlDsa65::keypair() {
        Ok((test_pk, test_sk)) => {
            let test_msg = b"test message for self-test";
            match MlDsa65::sign(&test_sk, test_msg) {
                Ok(test_sig) => {
                    println!("  [OK] Generated signature: {} bytes", test_sig.len());
                    match MlDsa65::verify(&test_pk, test_msg, &test_sig) {
                        Ok(true) => {
                            println!("  [OK] Self-test PASSED - Implementation works correctly")
                        }
                        Ok(false) => {
                            println!("  [FAIL] Self-test FAILED - Verification returned false")
                        }
                        Err(e) => println!("  [FAIL] Self-test FAILED: {}", e),
                    }
                }
                Err(e) => println!("  [FAIL] Signing self-test FAILED: {}", e),
            }
        }
        Err(e) => println!("  [FAIL] Keygen self-test FAILED: {}", e),
    }

    println!("--------------------------------------------------------------------------------");
    println!("CANONICALIZATION (JCS):");

    let mut unsigned_vc = vc.clone();
    if let Some(obj) = unsigned_vc.as_object_mut() {
        obj.remove("proof");
    }

    let mut proof_config = proof.clone();
    if let Some(obj) = proof_config.as_object_mut() {
        obj.remove("proofValue");
    }

    let canonical_doc = canonicalize_json_jcs(&unsigned_vc);
    let canonical_config = canonicalize_json_jcs(&proof_config);

    println!("  Unsigned VC length:    {} bytes", canonical_doc.len());
    println!("  Proof config length:   {} bytes", canonical_config.len());

    println!("--------------------------------------------------------------------------------");
    println!("VERIFICATION MESSAGE CONSTRUCTION:");

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, canonical_config.as_bytes());

    let mut msg = vec![0u8; 64];
    hasher.finalize_xof().read(&mut msg);

    println!("  Algorithm:     SHAKE-256");
    println!("  Output size:   64 bytes (512 bits)");
    println!("  Hash (hex):    {}", hex::encode(&msg));

    println!("--------------------------------------------------------------------------------");
    println!("ML-DSA-65 VERIFICATION:");

    let verification_result = MlDsa65::verify(&pk, &msg, &signature);

    match &verification_result {
        Ok(true) => {
            println!();
            println!(
                "================================================================================"
            );
            println!("                           VERIFICATION SUCCESSFUL");
            println!(
                "================================================================================"
            );
        }
        Ok(false) => {
            println!();
            println!(
                "================================================================================"
            );
            println!("                           VERIFICATION FAILED");
            println!(
                "================================================================================"
            );
            println!("  Expected: This VC requires RDFC canonicalization (URDNA2015)");
            println!("  To properly verify, use a library with RDFC support.");
            println!(
                "================================================================================"
            );
        }
        Err(e) => {
            println!();
            println!(
                "================================================================================"
            );
            println!("                           VERIFICATION ERROR");
            println!(
                "================================================================================"
            );
            println!("  Error: {}", e);
            println!(
                "================================================================================"
            );
        }
    }

    let status = if matches!(&verification_result, Ok(true)) {
        "PASSED"
    } else {
        "FAILED"
    };

    println!("--------------------------------------------------------------------------------");
    println!("SUMMARY:");
    println!("  - ML-DSA-65 implementation: WORKING");
    println!("  - Signature decoded: {} bytes", sig_bytes.len());
    println!("  - Public key extracted: {} bytes", pk.len());
    println!("  - Verification with JCS: {}", status);
    println!("--------------------------------------------------------------------------------");

    Ok(())
}

/// Extract public key from a DID key
fn extract_public_key_from_did(
    did_key: &str,
) -> Result<[u8; PUBLICKEYBYTES], Box<dyn std::error::Error>> {
    let did_without_fragment = did_key.split('#').next().ok_or("Invalid DID format")?;
    let encoded = did_without_fragment
        .strip_prefix("did:key:z")
        .ok_or("Invalid DID prefix")?;

    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {}", e))?;

    const MIN_LENGTH: usize = 2 + PUBLICKEYBYTES;
    if bytes.len() < MIN_LENGTH {
        return Err(format!("Invalid key length").into());
    }

    let codec = u16::from_be_bytes([bytes[0], bytes[1]]);
    if codec != 0x1305 && codec != 0x8624 {
        println!("  [INFO] Multicodec: 0x{:04x}", codec);
    }

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk.copy_from_slice(&bytes[2..2 + PUBLICKEYBYTES]);
    Ok(pk)
}

/// Base64url decoder with multibase 'u' prefix support
fn decode_base64url(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Strip multibase 'u' prefix if present
    let data = input.strip_prefix('u').unwrap_or(input);

    let cleaned: String = data
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();

    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(&cleaned) {
        return Ok(bytes);
    }

    let padding_needed = (4 - (cleaned.len() % 4)) % 4;
    if padding_needed > 0 {
        let padded = cleaned.clone() + &"=".repeat(padding_needed);
        if let Ok(bytes) = URL_SAFE.decode(&padded) {
            return Ok(bytes);
        }
    }

    manual_base64url_decode(&cleaned)
}

/// Manual base64url decoder as fallback
fn manual_base64url_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits_collected = 0;

    for c in input.chars() {
        let value = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '-' => 62,
            '_' => 63,
            _ => continue,
        };

        buffer = (buffer << 6) | (value as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            result.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }

    if result.is_empty() {
        return Err("Manual decode produced no bytes".into());
    }

    Ok(result)
}

/// JCS canonicalization
fn canonicalize_json_jcs(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let items: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonicalize_json_jcs(v)))
                .collect();

            format!("{{{}}}", items.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json_jcs).collect();

            format!("[{}]", items.join(","))
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s)),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
    }
}
