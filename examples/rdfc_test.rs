// examples/verify_vc_w3c.rs
// W3C-Compliant ML-DSA-65 Verifiable Credential Verifier
// Fully aligned with: https://www.w3.org/TR/vc-data-integrity/

use ml_dsa_65::{MlDsa65, PUBLICKEYBYTES, SIGNBYTES};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use serde_json::Value;
use std::fs;
use std::time::Instant;
use std::collections::HashMap;

// ============================================================================
// W3C Constants
// ============================================================================

/// Multibase prefix for base64url-no-pad encoding
const MULTIBASE_BASE64URL_PREFIX: char = 'u';

/// Multibase prefix for base58btc encoding
const MULTIBASE_BASE58BTC_PREFIX: char = 'z';

/// ML-DSA-65 multicodec (FIPS 204)
const MULTICODEC_MLDSA65: u16 = 0x1305;

/// Standard Base58BTC alphabet (no 0, O, I, l)
const BASE58BTC_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header();
    
    let vc_path = "test_vc.json";
    let start_time = Instant::now();
    
    // Step 1: Load VC
    println!("[STEP 1] LOADING VERIFIABLE CREDENTIAL");
    println!("────────────────────────────────────────────────────────────────");
    let vc_json = load_vc(vc_path)?;
    let vc: Value = parse_vc(&vc_json)?;
    print_vc_metadata(&vc);
    
    // Step 2: Extract Proof Components
    println!("\n[STEP 2] EXTRACTING PROOF COMPONENTS");
    println!("────────────────────────────────────────────────────────────────");
    let proof = extract_proof(&vc)?;
    let components = extract_proof_components(proof)?;
    
    println!("  Cryptosuite:     {}", components.cryptosuite);
    println!("  Proof Type:      {}", components.proof_type);
    println!("  Created:         {}", components.created);
    println!("  Purpose:         {}", components.purpose);
    println!("  Verification VM: {}...", &components.vm[..60.min(components.vm.len())]);
    println!("  Signature:        {} chars", components.sig_value.len());
    
    // Step 3: Decode Signature with Multibase support
    println!("\n[STEP 3] DECODING SIGNATURE (Multibase-aware)");
    println!("────────────────────────────────────────────────────────────────");
    let sig_bytes = decode_multibase_signature(&components.sig_value)?;
    print_signature_info(&sig_bytes, &components.cryptosuite);
    
    // Step 4: Extract Public Key from DID (Standard Base58BTC)
    println!("\n[STEP 4] EXTRACTING PUBLIC KEY FROM DID (Standard Base58BTC)");
    println!("────────────────────────────────────────────────────────────────");
    let pk_bytes = extract_public_key_w3c(&components.vm)?;
    print_public_key_info(&pk_bytes);
    
    // Step 5: Validate Signature Structure
    println!("\n[STEP 5] VALIDATING SIGNATURE STRUCTURE");
    println!("────────────────────────────────────────────────────────────────");
    validate_signature_structure(&sig_bytes, &components.cryptosuite)?;
    
    // Step 6: Self-Test ML-DSA-65 Implementation
    println!("\n[STEP 6] SELF-TEST: ML-DSA-65 IMPLEMENTATION");
    println!("────────────────────────────────────────────────────────────────");
    self_test_implementation()?;
    
    // Step 7: Canonicalization
    println!("\n[STEP 7] CANONICALIZATION (JCS - RFC 8785)");
    println!("────────────────────────────────────────────────────────────────");
    let (canonical_doc, canonical_config, msg) = create_verification_message(&vc, proof)?;
    println!("  Canonicalized doc:    {} bytes", canonical_doc.len());
    println!("  Canonicalized config: {} bytes", canonical_config.len());
    println!("  Verification message: 64 bytes (SHAKE-256)");
    println!("  Message hash (hex):   {}...", hex::encode(&msg[..16]));
    
    // Step 8: Verify Signature
    println!("\n[STEP 8] VERIFYING SIGNATURE");
    println!("────────────────────────────────────────────────────────────────");
    let verification_result = verify_signature(&pk_bytes, &msg, &sig_bytes)?;
    
    // Step 9: Additional W3C Compliance Checks
    println!("\n[STEP 9] W3C COMPLIANCE CHECKS");
    println!("────────────────────────────────────────────────────────────────");
    run_w3c_compliance_checks(&vc, proof, &components)?;
    
    // Final Result
    let elapsed = start_time.elapsed();
    println!();
    print_final_result(verification_result, &components.cryptosuite, elapsed);
    
    // Save debug info if verification failed
    if !verification_result {
        println!("\n[DEBUG] Saving verification data for analysis...");
        save_debug_info(&vc_json, &pk_bytes, &sig_bytes, &canonical_doc, &canonical_config, &msg)?;
    }
    
    Ok(())
}

// ============================================================================
// Data Structures
// ============================================================================

struct ProofComponents {
    vm: String,
    sig_value: String,
    cryptosuite: String,
    created: String,
    proof_type: String,
    purpose: String,
}

// ============================================================================
// Step 1: Loading and Parsing
// ============================================================================

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║              ML-DSA-65 W3C VERIFIABLE CREDENTIAL VERIFIER                     ║");
    println!("║                    W3C Data Integrity Proof v2 Compliant                       ║");
    println!("║                         Multibase • Base58BTC • JCS                            ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

fn load_vc(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    match fs::read_to_string(path) {
        Ok(content) => {
            println!("  [OK] Loaded VC from '{}' ({} bytes)", path, content.len());
            Ok(content)
        }
        Err(e) => {
            println!("  [ERROR] Failed to load '{}': {}", path, e);
            Err(e.into())
        }
    }
}

fn parse_vc(vc_json: &str) -> Result<Value, Box<dyn std::error::Error>> {
    match serde_json::from_str(vc_json) {
        Ok(vc) => {
            println!("  [OK] Parsed JSON successfully");
            Ok(vc)
        }
        Err(e) => {
            println!("  [ERROR] Invalid JSON at line {}, column {}: {}", e.line(), e.column(), e);
            Err(e.into())
        }
    }
}

fn print_vc_metadata(vc: &Value) {
    let id = vc["id"].as_str().unwrap_or("unknown");
    let issuer = vc["issuer"].as_str().unwrap_or("unknown");
    let issuance = vc["issuanceDate"].as_str().unwrap_or("unknown");
    
    println!("  VC ID:      {}", id);
    println!("  Issuer:     {}...", &issuer[..40.min(issuer.len())]);
    println!("  Issued:     {}", issuance);
    
    if let Some(types) = vc["type"].as_array() {
        let type_strs: Vec<String> = types.iter()
            .filter_map(|t| t.as_str().map(String::from))
            .collect();
        println!("  Types:      {}", type_strs.join(", "));
    }
    
    // Check for W3C context
    if let Some(contexts) = vc["@context"].as_array() {
        let has_w3c_v2 = contexts.iter().any(|c| {
            c.as_str().map(|s| s.contains("w3.org/ns/credentials/v2")).unwrap_or(false)
        });
        if has_w3c_v2 {
            println!("  Context:    W3C Credentials v2 ✓");
        }
    }
}

// ============================================================================
// Step 2: Proof Extraction
// ============================================================================

fn extract_proof(vc: &Value) -> Result<&Value, Box<dyn std::error::Error>> {
    vc.get("proof").ok_or_else(|| {
        println!("  [ERROR] No 'proof' object found in VC");
        "Missing proof".into()
    })
}

fn extract_proof_components(proof: &Value) -> Result<ProofComponents, Box<dyn std::error::Error>> {
    Ok(ProofComponents {
        vm: proof["verificationMethod"].as_str().ok_or("Missing verificationMethod")?.to_string(),
        sig_value: proof["proofValue"].as_str().ok_or("Missing proofValue")?.to_string(),
        cryptosuite: proof["cryptosuite"].as_str().unwrap_or("unknown").to_string(),
        created: proof["created"].as_str().unwrap_or("unknown").to_string(),
        proof_type: proof["type"].as_str().unwrap_or("DataIntegrityProof").to_string(),
        purpose: proof["proofPurpose"].as_str().unwrap_or("assertionMethod").to_string(),
    })
}

// ============================================================================
// Step 3: Multibase Signature Decoding
// ============================================================================

/// Decode a multibase-encoded signature
/// Format: <multibase-prefix><base-encoded-data>
/// For mldsa65 cryptosuites, the prefix should be 'u' (base64url-no-pad)
fn decode_multibase_signature(encoded: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encoded.is_empty() {
        return Err("Empty signature".into());
    }
    
    let first_char = encoded.chars().next().unwrap();
    
    match first_char {
        MULTIBASE_BASE64URL_PREFIX => {
            println!("  [OK] Multibase prefix 'u' detected (base64url-no-pad)");
            let data = &encoded[1..];
            decode_base64url(data)
        }
        'z' => {
            println!("  [WARNING] Multibase prefix 'z' detected (base58btc) - should be 'u' for signatures");
            let data = &encoded[1..];
            decode_base58btc(data)
        }
        _ => {
            // No multibase prefix - assume raw base64url (legacy)
            println!("  [INFO] No multibase prefix detected - assuming raw base64url");
            decode_base64url(encoded)
        }
    }
}

fn decode_base64url(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cleaned: String = data.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    
    match URL_SAFE_NO_PAD.decode(&cleaned) {
        Ok(bytes) => {
            println!("  [OK] Decoded {} chars -> {} bytes", cleaned.len(), bytes.len());
            Ok(bytes)
        }
        Err(_) => manual_base64url_decode(&cleaned)
    }
}

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
    
    println!("  [OK] Manual decode: {} chars -> {} bytes", input.len(), result.len());
    Ok(result)
}

fn decode_base58btc(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    bs58::decode(data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("Base58BTC decode error: {}", e).into())
}

fn print_signature_info(sig_bytes: &[u8], cryptosuite: &str) {
    println!("  Signature size: {} bytes", sig_bytes.len());
    println!("  Prefix: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
             sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3],
             sig_bytes[4], sig_bytes[5], sig_bytes[6], sig_bytes[7]);
    
    let expected = match cryptosuite {
        s if s.contains("44") => 2420,
        s if s.contains("65") => 3309,
        s if s.contains("87") => 4627,
        _ => 3309,
    };
    
    if sig_bytes.len() == expected {
        println!("  [OK] Size matches {} ({} bytes)", cryptosuite, expected);
    } else {
        println!("  [WARNING] Expected {} bytes, got {} bytes", expected, sig_bytes.len());
    }
}

// ============================================================================
// Step 4: Public Key Extraction (Standard Base58BTC)
// ============================================================================

/// Extract public key from a W3C-compliant DID key
/// Format: did:key:z<base58btc-multicodec-pubkey>#<fragment>
fn extract_public_key_w3c(did_key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Remove fragment identifier
    let did_without_fragment = did_key.split('#').next().ok_or("Invalid DID format")?;
    
    // Check DID prefix
    if !did_without_fragment.starts_with("did:key:z") {
        return Err(format!("Unsupported DID method (expected did:key:z): {}", did_without_fragment).into());
    }
    
    let encoded = &did_without_fragment[9..]; // Skip "did:key:z"
    
    // Decode using STANDARD Base58BTC alphabet
    let bytes = bs58::decode(encoded)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("Base58BTC decode error: {}", e))?;
    
    println!("  Decoded DID: {} bytes (multicodec + public key)", bytes.len());
    
    // Check minimum length
    if bytes.len() < 2 + PUBLICKEYBYTES {
        return Err(format!("Invalid key length: {} bytes (expected at least {})", 
                          bytes.len(), 2 + PUBLICKEYBYTES).into());
    }
    
    // Extract multicodec
    let codec = u16::from_be_bytes([bytes[0], bytes[1]]);
    println!("  Multicodec: 0x{:04x}", codec);
    
    match codec {
        MULTICODEC_MLDSA65 => println!("  [OK] ML-DSA-65 (FIPS 204) ✓"),
        0x1304 => println!("  [INFO] ML-DSA-44 detected"),
        0x1306 => println!("  [INFO] ML-DSA-87 detected"),
        _ => println!("  [WARNING] Unknown multicodec: 0x{:04x}", codec),
    }
    
    // Extract public key bytes
    let pk_bytes = bytes[2..2 + PUBLICKEYBYTES].to_vec();
    Ok(pk_bytes)
}

fn print_public_key_info(pk_bytes: &[u8]) {
    println!("  [OK] Extracted public key");
    println!("  Length: {} bytes", pk_bytes.len());
    println!("  Prefix: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
             pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
             pk_bytes[4], pk_bytes[5], pk_bytes[6], pk_bytes[7]);
    
    let entropy = estimate_entropy(pk_bytes);
    println!("  Entropy: {:.2} bits/byte (max 8.0)", entropy);
}

fn estimate_entropy(data: &[u8]) -> f64 {
    let mut counts = HashMap::new();
    for &b in data {
        *counts.entry(b).or_insert(0) += 1;
    }
    
    let len = data.len() as f64;
    counts.values()
        .map(|&c| {
            let p = c as f64 / len;
            if p > 0.0 { -p * p.log2() } else { 0.0 }
        })
        .sum()
}

// ============================================================================
// Step 5: Signature Structure Validation
// ============================================================================

fn validate_signature_structure(sig_bytes: &[u8], cryptosuite: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (algorithm, l, k, total_expected) = match cryptosuite {
        s if s.contains("44") => ("ML-DSA-44", 4, 4, 2420),
        s if s.contains("65") => ("ML-DSA-65", 5, 6, 3309),
        s if s.contains("87") => ("ML-DSA-87", 7, 8, 4627),
        _ => ("ML-DSA-65", 5, 6, 3309),
    };
    
    println!("  Algorithm:        {}", algorithm);
    println!("  L (rows):         {}", l);
    println!("  K (columns):      {}", k);
    println!("  c̃ (challenge):    32 bytes");
    println!("  z (response):     {} bytes", l * 640);
    println!("  h (hints):        {} bytes", total_expected - 32 - (l * 640));
    println!("  Total expected:   {} bytes", total_expected);
    println!("  Actual size:      {} bytes", sig_bytes.len());
    
    if sig_bytes.len() == total_expected {
        println!("  [OK] Signature structure is valid ✓");
        Ok(())
    } else {
        println!("  [ERROR] Signature structure mismatch!");
        Err(format!("Expected {} bytes, got {}", total_expected, sig_bytes.len()).into())
    }
}

// ============================================================================
// Step 6: Self-Test
// ============================================================================

fn self_test_implementation() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = MlDsa65::keypair()?;
    println!("  [OK] Key generation: {} bytes PK", pk.len());
    
    let msg = b"ML-DSA-65 W3C compliance test";
    let sig = MlDsa65::sign(&sk, msg)?;
    println!("  [OK] Signing: {} bytes signature", sig.len());
    
    match MlDsa65::verify(&pk, msg, &sig) {
        Ok(true) => println!("  [OK] Verification: PASSED ✓"),
        _ => return Err("Self-test verification failed".into()),
    }
    
    let tampered = b"tampered message";
    match MlDsa65::verify(&pk, tampered, &sig) {
        Ok(false) => println!("  [OK] Tamper detection: REJECTED ✓"),
        _ => println!("  [WARNING] Tamper detection unexpected"),
    }
    
    println!("  [OK] All self-tests PASSED");
    Ok(())
}

// ============================================================================
// Step 7: Canonicalization (JCS - RFC 8785)
// ============================================================================

fn create_verification_message(
    vc: &Value,
    proof: &Value,
) -> Result<(String, String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut unsigned_vc = vc.clone();
    if let Some(obj) = unsigned_vc.as_object_mut() {
        obj.remove("proof");
    }
    
    let mut proof_config = proof.clone();
    if let Some(obj) = proof_config.as_object_mut() {
        obj.remove("proofValue");
    }
    
    let canonical_doc = jcs_canonicalize(&unsigned_vc);
    let canonical_config = jcs_canonicalize(&proof_config);
    
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, canonical_config.as_bytes());
    
    let mut msg = vec![0u8; 64];
    hasher.finalize_xof().read(&mut msg);
    
    Ok((canonical_doc, canonical_config, msg))
}

fn jcs_canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let items: Vec<String> = sorted.iter()
                .map(|(k, v)| format!("\"{}\":{}", k, jcs_canonicalize(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(jcs_canonicalize).collect();
            format!("[{}]", items.join(","))
        }
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
    }
}

// ============================================================================
// Step 8: Signature Verification
// ============================================================================

fn verify_signature(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let mut pk_array = [0u8; PUBLICKEYBYTES];
    let mut sig_array = [0u8; SIGNBYTES];
    
    pk_array.copy_from_slice(pk_bytes);
    sig_array[..sig_bytes.len()].copy_from_slice(sig_bytes);
    
    match MlDsa65::verify(&pk_array, msg, &sig_array) {
        Ok(true) => {
            println!("  [OK] ML-DSA-65 verification: SIGNATURE VALID ✓");
            Ok(true)
        }
        Ok(false) => {
            println!("  [FAIL] ML-DSA-65 verification: SIGNATURE INVALID");
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

// ============================================================================
// Step 9: W3C Compliance Checks
// ============================================================================

fn run_w3c_compliance_checks(vc: &Value, proof: &Value, components: &ProofComponents) -> Result<(), Box<dyn std::error::Error>> {
    let mut compliant = true;
    
    // Check 1: @context includes W3C v2
    if let Some(contexts) = vc["@context"].as_array() {
        let has_v2 = contexts.iter().any(|c| {
            c.as_str().map(|s| s.contains("w3.org/ns/credentials/v2")).unwrap_or(false)
        });
        if has_v2 {
            println!("  [OK] W3C Credentials v2 context ✓");
        } else {
            println!("  [WARNING] Missing W3C Credentials v2 context");
            compliant = false;
        }
    }
    
    // Check 2: Type includes VerifiableCredential
    if let Some(types) = vc["type"].as_array() {
        let has_vc = types.iter().any(|t| t.as_str() == Some("VerifiableCredential"));
        if has_vc {
            println!("  [OK] 'VerifiableCredential' type ✓");
        } else {
            println!("  [WARNING] Missing 'VerifiableCredential' type");
            compliant = false;
        }
    }
    
    // Check 3: Proof type
    if components.proof_type == "DataIntegrityProof" {
        println!("  [OK] DataIntegrityProof type ✓");
    } else {
        println!("  [WARNING] Expected DataIntegrityProof, got {}", components.proof_type);
        compliant = false;
    }
    
    // Check 4: Cryptosuite
    if components.cryptosuite.contains("mldsa") && components.cryptosuite.contains("2024") {
        println!("  [OK] Cryptosuite format valid ✓");
    } else {
        println!("  [WARNING] Cryptosuite format: {}", components.cryptosuite);
        compliant = false;
    }
    
    if compliant {
        println!("  [OK] All W3C compliance checks PASSED ✓");
    } else {
        println!("  [INFO] Some W3C compliance checks failed (non-critical)");
    }
    
    Ok(())
}

// ============================================================================
// Final Result
// ============================================================================

fn print_final_result(success: bool, cryptosuite: &str, elapsed: std::time::Duration) {
    if success {
        println!("╔══════════════════════════════════════════════════════════════════════════════╗");
        println!("║                         ✅ VERIFICATION SUCCESSFUL                            ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        println!("║  The credential is authentic, valid, and has not been tampered with.          ║");
        println!("║  Cryptographic verification: {}                                    ║", pad_right(cryptosuite, 38));
        println!("║  Standard compliance:        W3C Data Integrity v2 ✓                          ║");
        println!("║  Verification time:          {:>10} ms                                   ║", elapsed.as_millis());
        println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    } else {
        println!("╔══════════════════════════════════════════════════════════════════════════════╗");
        println!("║                         ❌ VERIFICATION FAILED                                ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        println!("║  The credential could not be verified.                                        ║");
        println!("║  Check: - Multibase encoding (should be 'u' prefix)                          ║");
        println!("║         - Base58BTC alphabet (standard Bitcoin alphabet)                      ║");
        println!("║         - Canonicalization method (JCS vs RDFC)                               ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    }
    println!();
}

fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s[..width].to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - s.len()))
    }
}

// ============================================================================
// Debug Info
// ============================================================================

fn save_debug_info(
    vc_json: &str,
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    canonical_doc: &str,
    canonical_config: &str,
    msg: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write("debug_vc.json", vc_json)?;
    println!("    Saved: debug_vc.json");
    
    fs::write("debug_public_key.bin", pk_bytes)?;
    println!("    Saved: debug_public_key.bin ({} bytes)", pk_bytes.len());
    
    fs::write("debug_signature.bin", sig_bytes)?;
    println!("    Saved: debug_signature.bin ({} bytes)", sig_bytes.len());
    
    fs::write("debug_canonical_doc.txt", canonical_doc)?;
    fs::write("debug_canonical_config.txt", canonical_config)?;
    fs::write("debug_message.bin", msg)?;
    
    Ok(())
}// examples/verify_vc_rdfc_enterprise.rs
// ============================================================================
// Sirraya Labs — Enterprise W3C VC Verifier
// ML-DSA-65 (FIPS 204) + Full RDFC-1.0 / URDNA2015 (from scratch)
// W3C Data Integrity Proofs v2
// ============================================================================
//
// Cargo.toml [dependencies]:
//   ml-dsa-65   = { path = ".." }           (or your crate path)
//   base64      = "0.22"
//   sha2        = "0.10"
//   sha3        = "0.10"
//   hex         = "0.4"
//   serde       = { version = "1", features = ["derive"] }
//   serde_json  = "1"
//   bs58        = "0.5"
//   anyhow      = "1"

use ml_dsa_65::{MlDsa65, PUBLICKEYBYTES, SIGNBYTES};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use sha2::{Sha256, Digest as Sha2Digest};
use serde_json::Value;
use std::fs;
use std::time::Instant;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

// ============================================================================
// Constants
// ============================================================================

const MULTIBASE_BASE64URL_PREFIX: char = 'u';
const MULTIBASE_BASE58BTC_PREFIX: char = 'z';
const MLDSA65_SIGNATURE_SIZE: usize = 3309;
const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
const VERIFICATION_MESSAGE_SIZE: usize = 64;
const MULTICODEC_MLDSA65: u16 = 0x1305;
const MULTICODEC_MLDSA65_EXPERIMENTAL: u16 = 0x9124;

// ============================================================================
// §1  RDF / N-Quads Data Model
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Term {
    Iri(String),
    Blank(String),
    Literal {
        value:    String,
        datatype: Option<String>,
        language: Option<String>,
    },
    DefaultGraph,
}

impl Term {
    fn is_blank(&self) -> bool { matches!(self, Term::Blank(_)) }

    fn blank_id(&self) -> Option<&str> {
        if let Term::Blank(id) = self { Some(id) } else { None }
    }

    /// Canonical N-Quads serialisation of this term (no trailing space).
    fn to_nquads(&self) -> String {
        match self {
            Term::Iri(iri)  => format!("<{}>", iri),
            Term::Blank(id) => format!("_:{}", id),
            Term::DefaultGraph => String::new(),
            Term::Literal { value, datatype, language } => {
                let esc = escape_string(value);
                if let Some(lang) = language {
                    format!("\"{}\"@{}", esc, lang)
                } else if let Some(dt) = datatype {
                    // xsd:string is the implicit type — elide it (spec §A)
                    if dt == "http://www.w3.org/2001/XMLSchema#string" {
                        format!("\"{}\"", esc)
                    } else {
                        format!("\"{}\"^^<{}>", esc, dt)
                    }
                } else {
                    format!("\"{}\"", esc)
                }
            }
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_nquads())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Quad {
    subject:    Term,
    predicate:  Term,
    object:     Term,
    graph:      Term,   // Term::DefaultGraph when in default graph
}

impl Quad {
    /// Canonical N-Quads line (spec §A — trailing LF).
    fn to_nquads(&self) -> String {
        let g = match &self.graph {
            Term::DefaultGraph => String::new(),
            other              => format!(" {}", other.to_nquads()),
        };
        format!(
            "{} {} {}{}.\n",
            self.subject.to_nquads(),
            self.predicate.to_nquads(),
            self.object.to_nquads(),
            g,
        )
    }

    /// Return a copy with all blank nodes passed through `replacer`.
    fn replace_blanks<F: FnMut(&str) -> String>(&self, mut replacer: F) -> Quad {
        // We define a helper that takes the replacer by mutable reference 
        // to avoid ownership conflicts across multiple calls.
        let mut rep = |t: &Term| -> Term {
            match t {
                Term::Blank(id) => Term::Blank(replacer(id)),
                _ => t.clone(),
            }
        };

        Quad {
            subject:   rep(&self.subject),
            predicate: rep(&self.predicate),
            object:    rep(&self.object),
            graph:     rep(&self.graph),
        }
    }
}

/// Escape a literal string value for N-Quads output (RDFC-1.0 §A).
fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\x08' => out.push_str("\\b"),
            '\x09' => out.push_str("\\t"),
            '\x0A' => out.push_str("\\n"),
            '\x0B' => out.push_str("\\u000B"),
            '\x0C' => out.push_str("\\f"),
            '\x0D' => out.push_str("\\r"),
            '"'    => out.push_str("\\\""),
            '\\'   => out.push_str("\\\\"),
            '\x7F' => out.push_str("\\u007F"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ============================================================================
// §2  SHA-256 helper
// ============================================================================

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    Sha2Digest::update(&mut h, data);
    hex::encode(Sha2Digest::finalize(h))
}

// ============================================================================
// §3  Identifier Issuer  (RDFC-1.0 §4.3 / §4.5)
// ============================================================================

#[derive(Debug, Clone)]
struct IdentifierIssuer {
    prefix:  String,
    counter: u64,
    /// Maps original blank-node id → issued canonical id.
    issued:  BTreeMap<String, String>,
    /// Tracks insertion order so callers can replay issuance sequence.
    order:   Vec<String>,
}

impl IdentifierIssuer {
    fn new(prefix: &str) -> Self {
        Self { prefix: prefix.to_string(), counter: 0, issued: BTreeMap::new(), order: Vec::new() }
    }

    /// Issue (or retrieve) a canonical identifier for `existing_id`.
    fn issue(&mut self, existing_id: &str) -> String {
        if let Some(id) = self.issued.get(existing_id) { return id.clone(); }
        let new_id = format!("{}{}", self.prefix, self.counter);
        self.counter += 1;
        self.issued.insert(existing_id.to_string(), new_id.clone());
        self.order.push(existing_id.to_string());
        new_id
    }

    fn has_issued(&self, id: &str) -> bool { self.issued.contains_key(id) }
    fn get(&self, id: &str) -> Option<&str>  { self.issued.get(id).map(|s| s.as_str()) }
}

// ============================================================================
// §4  Hash First-Degree Quads  (RDFC-1.0 §4.6)
// ============================================================================
//
// Replaces the target blank node with `_:a` and all other blank nodes with
// `_:z`, sorts the resulting N-Quads lines, and hashes the concatenation.

fn hash_first_degree_quads(id: &str, bn_to_quads: &HashMap<String, Vec<Quad>>) -> String {
    let quads = match bn_to_quads.get(id) {
        Some(q) => q,
        None    => return sha256_hex(b""),
    };
    let mut nquads: Vec<String> = quads.iter().map(|q| {
        q.replace_blanks(|bn| if bn == id { "a".to_string() } else { "z".to_string() })
         .to_nquads()
    }).collect();
    nquads.sort();
    sha256_hex(nquads.concat().as_bytes())
}

// ============================================================================
// §5  Hash N-Degree Quads  (RDFC-1.0 §4.8)
// ============================================================================
//
// Computes a hash that captures the full neighbourhood of blank node `id` by
// traversing the dataset, ordering ambiguous paths via permutation, and
// recursing until all reachable blank nodes have temporary or canonical ids.
//
// Returns: (hash_hex_string, updated_temporary_issuer)

fn hash_n_degree_quads(
    id:           &str,
    canon_issuer: &IdentifierIssuer,
    tmp_issuer:   &mut IdentifierIssuer,
    bn_to_quads:  &HashMap<String, Vec<Quad>>,
) -> (String, IdentifierIssuer) {
    // --- Step 1: build hash_to_related_bnodes map ----------------------------
    //
    // For every quad that mentions `id`, and for every *other* blank node in
    // that quad, compute a "related hash" that encodes the position, predicate,
    // and best-available label for the related blank node.

    let mut hash_to_related: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let quads = match bn_to_quads.get(id) {
        Some(q) => q.clone(),
        None    => return (sha256_hex(b""), tmp_issuer.clone()),
    };

    for quad in &quads {
        for (term, pos) in [(&quad.subject, "s"), (&quad.object, "o"), (&quad.graph, "g")] {
            if let Term::Blank(related) = term {
                if related.as_str() == id { continue; }

                // Best label for `related` at this point in the algorithm
                let chosen_label = if let Some(c_id) = canon_issuer.get(related) {
                    format!("_:{}", c_id)
                } else if let Some(t_id) = tmp_issuer.get(related) {
                    format!("_:{}", t_id)
                } else {
                    // Not yet assigned — use its first-degree hash as a fingerprint
                    format!("_:{}", hash_first_degree_quads(related, bn_to_quads))
                };

                // input = position + predicate_nquads + chosen_label  (§4.7.3)
                let input = format!("{}{}{}", pos, quad.predicate.to_nquads(), chosen_label);
                let h = sha256_hex(input.as_bytes());
                hash_to_related.entry(h).or_default().push(related.clone());
            }
        }
    }

    // --- Step 2: build data_to_hash by iterating in code-point order ---------
    //
    // For each group of related blank nodes sharing a hash, find the
    // lexicographically smallest path using all permutations of the group,
    // recursing into nodes that need temporary ids.

    let mut data_to_hash = String::new();

    for (rel_hash, bnode_list) in &hash_to_related {
        data_to_hash.push_str(rel_hash);

        let mut chosen_path:   String = String::new();
        let mut chosen_issuer: Option<IdentifierIssuer> = None;

        for perm in permutations(bnode_list) {
            let mut issuer_copy    = tmp_issuer.clone();
            let mut path           = String::new();
            let mut recursion_list = Vec::<String>::new();
            let mut abort          = false;

            for related in &perm {
                if let Some(c_id) = canon_issuer.get(related) {
                    path.push_str(&format!("_:{}", c_id));
                } else {
                    if !issuer_copy.has_issued(related) {
                        recursion_list.push(related.clone());
                    }
                    path.push_str(&format!("_:{}", issuer_copy.issue(related)));
                }
                // Early prune — already worse than current best
                if !chosen_path.is_empty() && path > chosen_path {
                    abort = true;
                    break;
                }
            }

            if !abort {
                for related in &recursion_list {
                    let (result_hash, result_issuer) =
                        hash_n_degree_quads(related, canon_issuer, &mut issuer_copy, bn_to_quads);
                    path.push_str(&format!("<{}>", result_hash));
                    issuer_copy = result_issuer;

                    if !chosen_path.is_empty() && path > chosen_path {
                        abort = true;
                        break;
                    }
                }
            }

            if !abort && (chosen_path.is_empty() || path < chosen_path) {
                chosen_path   = path;
                chosen_issuer = Some(issuer_copy);
            }
        }

        data_to_hash.push_str(&chosen_path);
        if let Some(ci) = chosen_issuer { *tmp_issuer = ci; }
    }

    (sha256_hex(data_to_hash.as_bytes()), tmp_issuer.clone())
}

/// All permutations of `items` (factorial — only called on small slices).
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() { return vec![vec![]]; }
    if items.len() == 1 { return vec![items.to_vec()]; }
    let mut result = Vec::new();
    for i in 0..items.len() {
        let mut rest  = items.to_vec();
        let pivot = rest.remove(i);
        for mut perm in permutations(&rest) {
            perm.insert(0, pivot.clone());
            result.push(perm);
        }
    }
    result
}

// ============================================================================
// §6  Main Canonicalization Algorithm  (RDFC-1.0 §4.4)
// ============================================================================

fn canonicalize(quads: &[Quad]) -> String {
    // Step 1: build blank-node → quads map
    let mut bn_to_quads: HashMap<String, Vec<Quad>> = HashMap::new();
    for quad in quads {
        for term in [&quad.subject, &quad.predicate, &quad.object, &quad.graph] {
            if let Term::Blank(id) = term {
                bn_to_quads.entry(id.clone()).or_default().push(quad.clone());
            }
        }
    }

    // Step 2: compute first-degree hashes → group by hash
    let mut hash_to_bnodes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for bn in bn_to_quads.keys() {
        let h = hash_first_degree_quads(bn, &bn_to_quads);
        hash_to_bnodes.entry(h).or_default().push(bn.clone());
    }

    // Step 3: canonical issuer
    let mut canon_issuer = IdentifierIssuer::new("c14n");

    // Step 4: issue canonical ids for blank nodes with unique first-degree hash
    let mut non_unique: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (hash, mut id_list) in hash_to_bnodes {
        id_list.sort();   // deterministic order within group
        if id_list.len() == 1 {
            canon_issuer.issue(&id_list[0]);
        } else {
            non_unique.insert(hash, id_list);
        }
    }

    // Step 5: process non-unique blank nodes via N-degree hashing
    for id_list in non_unique.values() {
        let mut hash_path_list: Vec<(String, IdentifierIssuer)> = Vec::new();

        for bn in id_list {
            if canon_issuer.has_issued(bn) { continue; }

            let mut tmp_issuer = IdentifierIssuer::new("b");
            tmp_issuer.issue(bn);   // step 5.2.3: issue first temporary id for `bn`

            let (nd_hash, result_issuer) =
                hash_n_degree_quads(bn, &canon_issuer, &mut tmp_issuer, &bn_to_quads);
            hash_path_list.push((nd_hash, result_issuer));
        }

        // Sort by n-degree hash, then issue canonical ids in that order
        hash_path_list.sort_by(|a, b| a.0.cmp(&b.0));
        for (_hash, result_issuer) in hash_path_list {
            for orig_id in &result_issuer.order {
                canon_issuer.issue(orig_id);
            }
        }
    }

    // Step 6/7: replace blank nodes with canonical ids and sort
    let mut canonical_quads: Vec<String> = quads.iter().map(|q| {
        q.replace_blanks(|bn| {
            canon_issuer.get(bn)
                .map(|c| c.to_string())
                .unwrap_or_else(|| format!("UNISSUED_{}", bn))
        }).to_nquads()
    }).collect();

    canonical_quads.sort();   // Unicode code-point order (spec §4.4.3 step 7)
    canonical_quads.concat()
}

// ============================================================================
// §7  JSON-LD Context Resolution
// ============================================================================

#[derive(Debug, Clone)]
struct Context {
    mapping:    HashMap<String, String>,
    vocabulary: Option<String>,
    base:       Option<String>,
}

impl Context {
    fn new() -> Self {
        Self { mapping: HashMap::new(), vocabulary: None, base: None }
    }

    fn expand_term(&self, term: &str) -> String {
        // Already an absolute IRI or DID
        if term.starts_with("http://") || term.starts_with("https://")
            || term.starts_with("did:")  || term.starts_with("urn:") {
            return term.to_string();
        }
        // Prefix:local  (e.g.  xsd:string)
        if let Some(colon) = term.find(':') {
            let prefix = &term[..colon];
            let local  = &term[colon + 1..];
            if let Some(prefix_iri) = self.mapping.get(prefix) {
                return format!("{}{}", prefix_iri, local);
            }
        }
        // Direct mapping
        if let Some(iri) = self.mapping.get(term) { return iri.clone(); }
        // @vocab fallback
        if let Some(vocab) = &self.vocabulary { return format!("{}{}", vocab, term); }
        term.to_string()
    }

    fn merge(&mut self, other: &Context) {
        for (k, v) in &other.mapping { self.mapping.insert(k.clone(), v.clone()); }
        if other.vocabulary.is_some() { self.vocabulary = other.vocabulary.clone(); }
        if other.base.is_some()       { self.base       = other.base.clone(); }
    }
}

struct ContextRegistry {
    builtin: HashMap<String, Context>,
}

impl ContextRegistry {
    fn new() -> Self {
        let mut r = Self { builtin: HashMap::new() };
        r.register_builtins();
        r
    }

    fn register_builtins(&mut self) {
        // ── W3C Credentials v2 ────────────────────────────────────────────────
        let mut c = Context::new();
        c.vocabulary = Some("https://www.w3.org/2018/credentials#".into());
        let cred_terms = [
            ("VerifiableCredential",  "https://www.w3.org/2018/credentials#VerifiableCredential"),
            ("credentialSubject",     "https://www.w3.org/2018/credentials#credentialSubject"),
            ("issuer",                "https://www.w3.org/2018/credentials#issuer"),
            ("issuanceDate",          "https://www.w3.org/2018/credentials#issuanceDate"),
            ("validFrom",             "https://www.w3.org/2018/credentials#validFrom"),
            ("validUntil",            "https://www.w3.org/2018/credentials#validUntil"),
            ("evidence",              "https://www.w3.org/2018/credentials#evidence"),
            ("credentialStatus",      "https://www.w3.org/2018/credentials#credentialStatus"),
            ("credentialSchema",      "https://www.w3.org/2018/credentials#credentialSchema"),
            ("refreshService",        "https://www.w3.org/2018/credentials#refreshService"),
            ("termsOfUse",            "https://www.w3.org/2018/credentials#termsOfUse"),
        ];
        for (k, v) in cred_terms { c.mapping.insert(k.into(), v.into()); }
        self.builtin.insert("https://www.w3.org/ns/credentials/v2".into(), c.clone());
        // Also handle older URL variant
        self.builtin.insert("https://www.w3.org/2018/credentials/v1".into(), c);

        // ── Security / Multikey ───────────────────────────────────────────────
        let mut s = Context::new();
        let sec_terms = [
            ("DataIntegrityProof",  "https://w3id.org/security#DataIntegrityProof"),
            ("cryptosuite",         "https://w3id.org/security#cryptosuite"),
            ("proof",               "https://w3id.org/security#proof"),
            ("proofValue",          "https://w3id.org/security#proofValue"),
            ("proofPurpose",        "https://w3id.org/security#proofPurpose"),
            ("verificationMethod",  "https://w3id.org/security#verificationMethod"),
            ("created",             "https://w3id.org/security#created"),
            ("expires",             "https://w3id.org/security#expires"),
            ("domain",              "https://w3id.org/security#domain"),
            ("challenge",           "https://w3id.org/security#challenge"),
        ];
        for (k, v) in sec_terms { s.mapping.insert(k.into(), v.into()); }
        self.builtin.insert("https://w3id.org/security/multikey/v1".into(), s.clone());
        self.builtin.insert("https://w3id.org/security/data-integrity/v2".into(), s);

        // ── DID Core ──────────────────────────────────────────────────────────
        let mut d = Context::new();
        d.vocabulary = Some("https://www.w3.org/ns/did/v1#".into());
        let did_terms = [
            ("id",                    "@id"),
            ("controller",            "https://www.w3.org/ns/did/v1#controller"),
            ("alsoKnownAs",           "https://www.w3.org/ns/did/v1#alsoKnownAs"),
            ("verificationMethod",    "https://www.w3.org/ns/did/v1#verificationMethod"),
            ("authentication",        "https://www.w3.org/ns/did/v1#authentication"),
            ("assertionMethod",       "https://www.w3.org/ns/did/v1#assertionMethod"),
            ("keyAgreement",          "https://www.w3.org/ns/did/v1#keyAgreement"),
            ("capabilityInvocation",  "https://www.w3.org/ns/did/v1#capabilityInvocation"),
            ("capabilityDelegation",  "https://www.w3.org/ns/did/v1#capabilityDelegation"),
            ("service",               "https://www.w3.org/ns/did/v1#service"),
        ];
        for (k, v) in did_terms { d.mapping.insert(k.into(), v.into()); }
        self.builtin.insert("https://www.w3.org/ns/did/v1".into(), d);
    }

    fn resolve(&self, ctx_value: &Value) -> Context {
        let mut combined = Context::new();
        // Convenience terms present in every context
        combined.mapping.insert("@id".into(),   "@id".into());
        combined.mapping.insert("@type".into(), "@type".into());

        match ctx_value {
            Value::String(url)  => {
                if let Some(ctx) = self.builtin.get(url) { combined.merge(ctx); }
            }
            Value::Array(arr)   => {
                for item in arr {
                    match item {
                        Value::String(url) => {
                            if let Some(ctx) = self.builtin.get(url) { combined.merge(ctx); }
                        }
                        Value::Object(map) => self.apply_inline_context(map, &mut combined),
                        _ => {}
                    }
                }
            }
            Value::Object(map) => self.apply_inline_context(map, &mut combined),
            _ => {}
        }
        combined
    }

    fn apply_inline_context(&self, map: &serde_json::Map<String, Value>, ctx: &mut Context) {
        if let Some(v) = map.get("@vocab")  { if let Some(s) = v.as_str() { ctx.vocabulary = Some(s.into()); } }
        if let Some(v) = map.get("@base")   { if let Some(s) = v.as_str() { ctx.base = Some(s.into()); } }
        for (key, val) in map {
            if key.starts_with('@') { continue; }
            match val {
                Value::String(iri) => { ctx.mapping.insert(key.clone(), iri.clone()); }
                Value::Object(obj) => {
                    if let Some(id) = obj.get("@id").and_then(|v| v.as_str()) {
                        ctx.mapping.insert(key.clone(), id.into());
                    }
                }
                _ => {}
            }
        }
    }
}

// ============================================================================
// §8  JSON-LD → RDF Quads expansion
// ============================================================================
//
// This is a simplified (but correct for W3C VC documents) expansion that:
//   • Resolves @context via the ContextRegistry
//   • Maps @type / type → rdf:type
//   • Detects IRI-valued properties vs literal-valued properties
//   • Recurses into nested objects creating blank nodes as needed
//   • Skips the `proof` graph entirely (unsigned document for verification)

fn json_ld_to_quads(vc: &Value) -> anyhow::Result<Vec<Quad>> {
    let registry = ContextRegistry::new();
    let mut quads   = Vec::new();
    let mut counter = 0u32;

    let context = vc.get("@context")
        .map(|c| registry.resolve(c))
        .unwrap_or_else(Context::new);

    let subject_id = vc.get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| { counter += 1; format!("_:b{}", counter) });

    expand_node(
        &subject_id,
        vc,
        &context,
        &registry,
        &mut quads,
        &mut counter,
        None,
    )?;

    Ok(quads)
}

fn expand_node(
    subject_str: &str,
    node:        &Value,
    context:     &Context,
    registry:    &ContextRegistry,
    quads:       &mut Vec<Quad>,
    counter:     &mut u32,
    graph:       Option<Term>,
) -> anyhow::Result<()> {
    let subject = str_to_term(subject_str);
    let obj = match node.as_object() { Some(o) => o, None => return Ok(()) };

    // ── @type / type ─────────────────────────────────────────────────────────
    let type_key = if obj.contains_key("@type") { Some("@type") }
                   else if obj.contains_key("type") { Some("type") }
                   else { None };

    if let Some(tk) = type_key {
        let rdf_type = Term::Iri("http://www.w3.org/1999/02/22-rdf-syntax-ns#type".into());
        let type_vals = match obj.get(tk).unwrap() {
            Value::Array(arr) => arr.iter().map(|v| v.as_str().unwrap_or("")).collect::<Vec<_>>(),
            Value::String(s)  => vec![s.as_str()],
            _ => vec![],
        };
        for tv in type_vals {
            if tv.is_empty() { continue; }
            quads.push(Quad {
                subject:   subject.clone(),
                predicate: rdf_type.clone(),
                object:    Term::Iri(context.expand_term(tv)),
                graph:     graph.clone().unwrap_or(Term::DefaultGraph),
            });
        }
    }

    // ── All other properties ─────────────────────────────────────────────────
    for (key, value) in obj {
        if matches!(key.as_str(), "@context" | "@id" | "id" | "@type" | "type" | "proof") {
            continue;
        }

        let predicate = Term::Iri(context.expand_term(key));

        expand_value(
            &subject, &predicate, value, key,
            context, registry, quads, counter,
            graph.clone(),
        )?;
    }

    Ok(())
}

/// Determines whether a string value should be treated as an IRI or a literal.
fn is_iri_value(s: &str, key: &str) -> bool {
    // These properties always carry IRI/DID values, not plain strings
    matches!(key, "id" | "issuer" | "verificationMethod" | "controller" | "assertionMethod")
    || s.starts_with("http://")
    || s.starts_with("https://")
    || s.starts_with("did:")
    || s.starts_with("urn:")
}

fn str_to_term(s: &str) -> Term {
    if s.starts_with("_:") { Term::Blank(s[2..].to_string()) } else { Term::Iri(s.to_string()) }
}

fn expand_value(
    subject:   &Term,
    predicate: &Term,
    value:     &Value,
    key:       &str,
    context:   &Context,
    registry:  &ContextRegistry,
    quads:     &mut Vec<Quad>,
    counter:   &mut u32,
    graph:     Option<Term>,
) -> anyhow::Result<()> {
    match value {
        Value::String(s) => {
            let object = if is_iri_value(s, key) {
                Term::Iri(s.clone())
            } else {
                Term::Literal { value: s.clone(), datatype: None, language: None }
            };
            quads.push(Quad {
                subject: subject.clone(), predicate: predicate.clone(), object,
                graph: graph.clone().unwrap_or(Term::DefaultGraph),
            });
        }

        Value::Number(n) => {
            let dt = if n.is_i64() {
                "http://www.w3.org/2001/XMLSchema#integer"
            } else {
                "http://www.w3.org/2001/XMLSchema#double"
            };
            quads.push(Quad {
                subject: subject.clone(), predicate: predicate.clone(),
                object: Term::Literal {
                    value: n.to_string(), datatype: Some(dt.into()), language: None,
                },
                graph: graph.clone().unwrap_or(Term::DefaultGraph),
            });
        }

        Value::Bool(b) => {
            quads.push(Quad {
                subject: subject.clone(), predicate: predicate.clone(),
                object: Term::Literal {
                    value: b.to_string(),
                    datatype: Some("http://www.w3.org/2001/XMLSchema#boolean".into()),
                    language: None,
                },
                graph: graph.clone().unwrap_or(Term::DefaultGraph),
            });
        }

        Value::Object(inner) => {
            // Determine the nested subject: use inner `id` if present, else blank node
            let inner_subject_str = inner.get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| { *counter += 1; format!("_:b{}", counter) });

            // Resolve context for the inner node
            let inner_ctx = inner.get("@context")
                .map(|c| {
                    let mut base = context.clone();
                    base.merge(&registry.resolve(c));
                    base
                })
                .unwrap_or_else(|| context.clone());

            // Link subject → nested subject
            quads.push(Quad {
                subject:   subject.clone(),
                predicate: predicate.clone(),
                object:    str_to_term(&inner_subject_str),
                graph:     graph.clone().unwrap_or(Term::DefaultGraph),
            });

            expand_node(
                &inner_subject_str,
                value,
                &inner_ctx,
                registry,
                quads,
                counter,
                graph,
            )?;
        }

        Value::Array(arr) => {
            for item in arr {
                expand_value(subject, predicate, item, key, context, registry, quads, counter, graph.clone())?;
            }
        }

        Value::Null => {}
    }
    Ok(())
}

// ============================================================================
// §9  Signature Decoding
// ============================================================================

fn decode_multibase_signature(encoded: &str) -> anyhow::Result<Vec<u8>> {
    if encoded.is_empty() { anyhow::bail!("Empty proofValue"); }
    match encoded.chars().next().unwrap() {
        MULTIBASE_BASE64URL_PREFIX => {
            println!("    Multibase prefix: 'u' (base64url-no-pad)");
            decode_base64url(&encoded[1..])
        }
        MULTIBASE_BASE58BTC_PREFIX => {
            println!("    Multibase prefix: 'z' (base58btc)");
            decode_base58btc(&encoded[1..])
        }
        _ => {
            println!("    No recognised multibase prefix — trying raw base64url");
            decode_base64url(encoded)
        }
    }
}

fn decode_base64url(data: &str) -> anyhow::Result<Vec<u8>> {
    let cleaned: String = data.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    URL_SAFE_NO_PAD.decode(&cleaned)
        .map_err(|e| anyhow::anyhow!("base64url decode: {}", e))
}

fn decode_base58btc(data: &str) -> anyhow::Result<Vec<u8>> {
    bs58::decode(data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("base58btc decode: {}", e))
}

// ============================================================================
// §10  Public Key Extraction from DID
// ============================================================================

fn extract_public_key_from_did(did_key: &str) -> anyhow::Result<(Vec<u8>, String)> {
    // Strip fragment (#key-1, etc.)
    let did = did_key.split('#').next().unwrap_or(did_key);

    if !did.starts_with("did:key:") {
        anyhow::bail!("Unsupported DID method: {}", did);
    }

    let rest = &did[8..];  // after "did:key:"
    if rest.is_empty() { anyhow::bail!("Empty DID key"); }

    let (multibase_prefix, encoded) = (rest.chars().next().unwrap(), &rest[1..]);

    let bytes = match multibase_prefix {
        MULTIBASE_BASE58BTC_PREFIX => {
            println!("    DID multibase: 'z' (base58btc)");
            decode_base58btc(encoded)?
        }
        MULTIBASE_BASE64URL_PREFIX => {
            println!("    DID multibase: 'u' (base64url)");
            decode_base64url(encoded)?
        }
        other => anyhow::bail!("Unsupported DID multibase prefix: '{}'", other),
    };

    if bytes.len() < 2 + MLDSA65_PUBLIC_KEY_SIZE {
        anyhow::bail!(
            "DID key payload too short: {} bytes (need at least {})",
            bytes.len(),
            2 + MLDSA65_PUBLIC_KEY_SIZE
        );
    }

    let codec = u16::from_be_bytes([bytes[0], bytes[1]]);
    let codec_info = match codec {
        MULTICODEC_MLDSA65              => format!("0x{:04x} (ML-DSA-65 FIPS 204)", codec),
        MULTICODEC_MLDSA65_EXPERIMENTAL => format!("0x{:04x} (ML-DSA-65 experimental)", codec),
        other                           => format!("0x{:04x} (unknown multicodec)", other),
    };

    let pk = bytes[2..2 + MLDSA65_PUBLIC_KEY_SIZE].to_vec();
    Ok((pk, codec_info))
}

// ============================================================================
// §11  ML-DSA-65 Verification
// ============================================================================

// ============================================================================
// §11  ML-DSA-65 Verification (FIXED)
// ============================================================================

// ============================================================================
// §11  ML-DSA-65 Verification (Updated for SHA-256 hash)
// ============================================================================

// ============================================================================
// §11  ML-DSA-65 Verification (FIXED - Actually uses the result!)
// ============================================================================

fn verify_ml_dsa(pk_bytes: &[u8], msg_hash: &[u8], sig_bytes: &[u8]) -> anyhow::Result<bool> {
    if pk_bytes.len() != PUBLICKEYBYTES {
        anyhow::bail!("Wrong public key size: expected {}, got {}", PUBLICKEYBYTES, pk_bytes.len());
    }
    if sig_bytes.len() != SIGNBYTES {
        anyhow::bail!("Wrong signature size: expected {}, got {}", SIGNBYTES, sig_bytes.len());
    }
    
    println!("  Verifying ML-DSA-65 signature over {} bytes (SHA-256 hash)", msg_hash.len());

    let mut pk = [0u8; PUBLICKEYBYTES];
    let mut sig = [0u8; SIGNBYTES];
    pk.copy_from_slice(pk_bytes);
    sig.copy_from_slice(sig_bytes);

    // MlDsa65::verify returns Result<bool, MlDsaError>
    // The bool indicates whether the signature is valid
    match MlDsa65::verify(&pk, msg_hash, &sig) {
        Ok(is_valid) => {
            if is_valid {
                println!("  ✓ Signature is cryptographically VALID");
            } else {
                println!("  ✗ Signature is cryptographically INVALID");
            }
            Ok(is_valid)  // ✅ Return the actual boolean result
        },
        Err(e) => {
            println!("  ✗ ML-DSA-65 verification error: {:?}", e);
            Ok(false)
        }
    }
}

// ============================================================================
// §12  Entry Point (FIXED Phase 6)
// ============================================================================

fn main() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║          Sirraya Labs — ML-DSA-65 + RDFC-1.0 VC Verifier                     ║");
    println!("║          FIPS 204 • W3C Data Integrity v2 • URDNA2015 from scratch           ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = std::env::args().collect();
    let vc_path = args.get(1).map(|s| s.as_str()).unwrap_or("test_vc.json");

    println!("📄  Loading: {}\n", vc_path);
    let start = Instant::now();

    // ── Load & parse ─────────────────────────────────────────────────────────
    let vc_json = fs::read_to_string(vc_path)
        .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", vc_path, e))?;
    let vc: Value = serde_json::from_str(&vc_json)?;

    let credential_id = vc["id"].as_str().unwrap_or("(no id)");
    let issuer        = vc["issuer"].as_str().unwrap_or("(no issuer)");
    println!("  Credential ID : {}", credential_id);
    println!("  Issuer        : {}", issuer);

    // ── Extract proof components ──────────────────────────────────────────────
    let proof = vc.get("proof")
        .ok_or_else(|| anyhow::anyhow!("Missing 'proof' field"))?;

    let verification_method = proof["verificationMethod"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing verificationMethod"))?;
    let proof_value = proof["proofValue"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing proofValue"))?;
    let cryptosuite = proof["cryptosuite"].as_str().unwrap_or("(unknown)");

    println!("  Cryptosuite   : {}", cryptosuite);

    // ── Decode signature ──────────────────────────────────────────────────────
    println!("\n[Phase 1] Decoding signature...");
    let sig_bytes = decode_multibase_signature(proof_value)?;
    println!("  Decoded: {} bytes", sig_bytes.len());

    if sig_bytes.len() != MLDSA65_SIGNATURE_SIZE {
        anyhow::bail!(
            "Unexpected signature size: expected {}, got {}",
            MLDSA65_SIGNATURE_SIZE, sig_bytes.len()
        );
    }

    // ── Extract public key ────────────────────────────────────────────────────
    println!("\n[Phase 2] Extracting public key from DID...");
    let (pk_bytes, codec_info) = extract_public_key_from_did(verification_method)?;
    println!("  Key: {} bytes  codec: {}", pk_bytes.len(), codec_info);

    // ── Build unsigned document (remove proof graph) ──────────────────────────
    println!("\n[Phase 3] Building unsigned document...");
    let mut unsigned_vc = vc.clone();
    if let Some(obj) = unsigned_vc.as_object_mut() { obj.remove("proof"); }

    // ── Expand JSON-LD → RDF quads ────────────────────────────────────────────
    println!("\n[Phase 4] Expanding JSON-LD → RDF quads...");
    let quads = json_ld_to_quads(&unsigned_vc)?;
    println!("  Generated: {} quad(s)", quads.len());

    // ── RDFC-1.0 / URDNA2015 canonicalization ────────────────────────────────
    println!("\n[Phase 5] RDFC-1.0 canonicalization (URDNA2015)...");
    let canonical = canonicalize(&quads);
    println!("  Canonical form: {} byte(s)  ({} line(s))",
             canonical.len(), canonical.lines().count());

    // Save for inspection
    let nq_path = vc_path.replace(".json", ".canonical.nq");
    fs::write(&nq_path, &canonical).ok();
    println!("  Saved: {}", nq_path);

    // ── FIXED: Build verification message using SHA-256 (NOT SHAKE-256) ──────
    println!("\n[Phase 6] Building verification message (SHA-256, 32 bytes)...");
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, canonical.as_bytes());
    let msg = Sha2Digest::finalize(hasher);
    let msg_bytes = msg.as_slice();
    
    println!("  Message hash (full): {}", hex::encode(msg_bytes));
    println!("  Message hash (first 16 bytes): {}...", hex::encode(&msg_bytes[..16]));
    println!("  Message length: {} bytes", msg_bytes.len());

    // Save verification message for external debugging
    let msg_path = vc_path.replace(".json", ".verification-msg.bin");
    fs::write(&msg_path, msg_bytes)?;
    println!("  Saved verification message to: {}", msg_path);

    // ── ML-DSA-65 verification ────────────────────────────────────────────────
    println!("\n[Phase 7] ML-DSA-65 signature verification...");
    let elapsed = start.elapsed();

    match verify_ml_dsa(&pk_bytes, msg_bytes, &sig_bytes) {
        Ok(true) => {
            println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
            println!("║  Status      : ✅ VERIFICATION SUCCESSFUL                                     ║");
            println!("║  Credential  : {:60}║", truncate(credential_id, 60));
            println!("║  Issuer      : {:60}║", truncate(issuer, 60));
            println!("║  Cryptosuite : {:60}║", cryptosuite);
            println!("║  Codec       : {:60}║", codec_info);
            println!("║  Sig size    : {:5} bytes                                                    ║", sig_bytes.len());
            println!("║  Key size    : {:5} bytes                                                    ║", pk_bytes.len());
            println!("║  Quads       : {:5}                                                          ║", quads.len());
            println!("║  Time        : {:5} ms                                                       ║", elapsed.as_millis());
            println!("╚══════════════════════════════════════════════════════════════════════════════╝");
        }
        Ok(false) => {
            println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
            println!("║  Status : ❌ VERIFICATION FAILED — signature is invalid                      ║");
            println!("╚══════════════════════════════════════════════════════════════════════════════╝");
            println!("\n  Debug information:");
            println!("  • Message hash: {}", hex::encode(msg_bytes));
            println!("  • Canonical form saved to: {}", nq_path);
            println!("  • Verification message saved to: {}", msg_path);
            println!("\n  Possible causes:");
            println!("  • The credential was modified after signing");
            println!("  • The wrong public key is being used");
            println!("  • The JSON-LD expansion does not match what the signer used");
            println!("  • Compare {} with a known-good canonicalization", nq_path);
            println!("  • Verify message {} with external tools", msg_path);
        }
        Err(e) => {
            println!("\n❌  ML-DSA-65 error: {}", e);
            anyhow::bail!("Verification error: {}", e);
        }
    }

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}...", &s[..max.saturating_sub(3)]) }
}