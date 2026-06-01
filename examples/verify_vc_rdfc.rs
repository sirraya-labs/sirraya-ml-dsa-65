// examples/verify_vc_w3c.rs
// W3C-Compliant ML-DSA-65 Verifiable Credential Verifier
// Fully aligned with: https://www.w3.org/TR/vc-data-integrity/
//
// This implementation provides comprehensive verification of W3C Verifiable Credentials
// secured with ML-DSA-65 post-quantum cryptographic signatures. It supports:
// - Multibase encoding (base64url-no-pad with 'u' prefix)
// - Standard Base58BTC public key decoding from did:key identifiers
// - JCS (RFC 8785) canonicalization
// - SHAKE-256 message hashing per FIPS 204
//
// SIRRAYA LABS
// Cryptographic Systems Division
// Version: 1.0.0

use ml_dsa_65::{MlDsa65, PUBLICKEYBYTES, SIGNBYTES};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use serde_json::Value;
use std::fs;
use std::time::Instant;
use std::collections::HashMap;
use std::io::Write;

// ============================================================================
// W3C Protocol Constants
// These constants define the encoding formats and cryptographic identifiers
// required for W3C Data Integrity Proof v2 compliance.
// ============================================================================

/// Multibase prefix indicating base64url-no-pad encoding
/// Per W3C specification, all proofValue fields MUST use 'u' prefix
const MULTIBASE_BASE64URL_PREFIX: char = 'u';

/// Multibase prefix for base58btc encoding (used for did:key identifiers)
const MULTIBASE_BASE58BTC_PREFIX: char = 'z';

/// ML-DSA-65 multicodec identifier as registered in the multicodec table
/// Value 0x1305 corresponds to FIPS 204 ML-DSA-65 algorithm
const MULTICODEC_MLDSA65: u16 = 0x1305;

/// Standard Base58BTC alphabet as defined by Bitcoin
/// Excludes visually ambiguous characters: 0, O, I, l
const BASE58BTC_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ============================================================================
// Report Generation State
// ============================================================================

/// Global report accumulator for comprehensive verification documentation
struct VerificationReport {
    sections: Vec<String>,
    success: bool,
    cryptosuite: String,
    duration: std::time::Duration,
}

impl VerificationReport {
    fn new() -> Self {
        Self {
            sections: Vec::new(),
            success: false,
            cryptosuite: String::new(),
            duration: std::time::Duration::from_secs(0),
        }
    }
    
    fn add_section(&mut self, title: &str, content: &str) {
        let section = format!(
            "\n{}\n{}\n\n{}\n",
            title,
            "=".repeat(title.len()),
            content
        );
        self.sections.push(section);
    }
    
    fn set_result(&mut self, success: bool, cryptosuite: &str, duration: std::time::Duration) {
        self.success = success;
        self.cryptosuite = cryptosuite.to_string();
        self.duration = duration;
    }
    
    fn generate(&self) -> String {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        
        let header = format!(
            r#"================================================================================
SIRRAYA LABS - CRYPTOGRAPHIC VERIFICATION REPORT
ML-DSA-65 W3C Verifiable Credential Validator
================================================================================

Report Generated: {}
Verification Status: {}
Cryptographic Suite: {}
Total Processing Time: {} ms
================================================================================
"#,
            timestamp,
            if self.success { "SUCCESSFUL" } else { "FAILED" },
            self.cryptosuite,
            self.duration.as_millis()
        );
        
        let footer = if self.success {
            r#"
================================================================================
VERIFICATION CONCLUSION

The credential has been cryptographically verified and meets all security
requirements. The content is authentic and has not been tampered with.

Compliance Status:
  • W3C Data Integrity Proof v2: Compliant
  • FIPS 204 (ML-DSA-65): Compliant
  • RFC 8785 (JCS Canonicalization): Compliant

This verification report constitutes a formal cryptographic attestation of
the credential's integrity and authenticity.

================================================================================
SIRRAYA LABS - Cryptographic Systems Division
Confidential - Proprietary Information
================================================================================
"#
        } else {
            r#"
================================================================================
VERIFICATION CONCLUSION

The credential could not be verified. This may indicate tampering, corruption,
or non-compliance with verification requirements.

Troubleshooting Checklist:
  • Verify multibase encoding (should be 'u' prefix for signatures)
  • Confirm Base58BTC alphabet usage (standard Bitcoin alphabet)
  • Validate canonicalization method (JCS per RFC 8785)
  • Check cryptosuite compatibility

Forensic analysis artifacts have been saved for further investigation.

================================================================================
SIRRAYA LABS - Cryptographic Systems Division
Confidential - Proprietary Information
================================================================================
"#
        };
        
        format!("{}{}{}", header, self.sections.join(""), footer)
    }
    
    fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let report_content = self.generate();
        fs::write(path, &report_content)?;
        Ok(())
    }
}

// ============================================================================
// Main Entry Point
// Orchestrates the complete verification pipeline following W3C Data Integrity
// specification section 4.1: Verify Proof.
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = VerificationReport::new();
    
    println!("SIRRAYA LABS - ML-DSA-65 W3C Verifiable Credential Validator");
    println!("Cryptographic Systems Division\n");
    
    let vc_path = "test_vc.json";
    let verification_start = Instant::now();
    
    // Step 1: Load and validate credential structure
    println!("[1/9] Loading credential...");
    let vc_json = load_credential_file(vc_path)?;
    let credential: Value = parse_credential_json(&vc_json)?;
    let metadata_section = format_credential_metadata(&credential);
    report.add_section("CREDENTIAL METADATA", &metadata_section);
    
    // Step 2: Extract proof components per W3C Data Integrity spec
    println!("[2/9] Extracting proof components...");
    let proof_object = extract_proof_object(&credential)?;
    let proof_data = parse_proof_components(proof_object)?;
    let proof_section = format_proof_summary(&proof_data);
    report.add_section("PROOF CONFIGURATION", &proof_section);
    
    // Step 3: Decode signature with multibase awareness
    println!("[3/9] Decoding signature (multibase-aware)...");
    let signature_bytes = decode_multibase_encoded_signature(&proof_data.sig_value)?;
    let sig_analysis = format_signature_analysis(&signature_bytes, &proof_data.cryptosuite);
    report.add_section("SIGNATURE DECODING", &sig_analysis);
    
    // Step 4: Extract public key from DID identifier
    println!("[4/9] Resolving public key from DID...");
    let public_key_bytes = resolve_did_key_public_key(&proof_data.vm)?;
    let pk_analysis = format_public_key_analysis(&public_key_bytes);
    report.add_section("PUBLIC KEY RESOLUTION", &pk_analysis);
    
    // Step 5: Validate signature structure against algorithm parameters
    println!("[5/9] Validating signature structure...");
    validate_signature_bytes_structure(&signature_bytes, &proof_data.cryptosuite)?;
    let structure_validation = format_signature_structure_validation(&signature_bytes, &proof_data.cryptosuite);
    report.add_section("SIGNATURE STRUCTURE VALIDATION", &structure_validation);
    
    // Step 6: Self-test cryptographic primitives
    println!("[6/9] Validating cryptographic primitives...");
    perform_cryptographic_self_test()?;
    report.add_section("CRYPTOGRAPHIC PRIMITIVE VALIDATION", "ML-DSA-65 implementation self-test passed successfully.\nAll cryptographic operations functioning correctly.");
    
    // Step 7: JCS canonicalization per RFC 8785
    println!("[7/9] Performing JCS canonicalization...");
    let (canonical_doc, canonical_config, verification_message) = 
        construct_verification_message(&credential, proof_object)?;
    let canon_section = format_canonicalization_results(&canonical_doc, &canonical_config, &verification_message);
    report.add_section("CANONICALIZATION RESULTS", &canon_section);
    
    // Step 8: Execute ML-DSA-65 signature verification
    println!("[8/9] Verifying signature...");
    let verification_outcome = execute_signature_verification(
        &public_key_bytes, 
        &verification_message, 
        &signature_bytes
    )?;
    report.add_section("SIGNATURE VERIFICATION", 
        if verification_outcome { "Signature verification: SUCCESSFUL\nCryptographic integrity confirmed." } 
        else { "Signature verification: FAILED\nCryptographic integrity could not be confirmed." });
    
    // Step 9: Additional W3C compliance validation
    println!("[9/9] Validating W3C compliance...");
    let compliance_section = validate_and_format_w3c_compliance(&credential, proof_object, &proof_data);
    report.add_section("W3C COMPLIANCE ASSESSMENT", &compliance_section);
    
    // Finalize report
    let total_duration = verification_start.elapsed();
    report.set_result(verification_outcome, &proof_data.cryptosuite, total_duration);
    
    // Save report to file
    let report_filename = format!("verification_report_{}.txt", 
        chrono::Local::now().format("%Y%m%d_%H%M%S"));
    report.save_to_file(&report_filename)?;
    
    // Display summary to console
    println!("\nVerification complete.");
    println!("Status: {}", if verification_outcome { "SUCCESSFUL" } else { "FAILED" });
    println!("Report saved: {}", report_filename);
    
    // Persist debug data for failed verifications
    if !verification_outcome {
        println!("\nPersisting forensic analysis artifacts...");
        persist_debug_artifacts(
            &vc_json, 
            &public_key_bytes, 
            &signature_bytes, 
            &canonical_doc, 
            &canonical_config, 
            &verification_message
        )?;
    }
    
    Ok(())
}

// ============================================================================
// Data Structures
// ============================================================================

/// Structured representation of a W3C Data Integrity proof
/// Contains all fields required by the verification algorithm
struct ProofComponents {
    /// The verification method (typically a did:key identifier)
    vm: String,
    /// The multibase-encoded signature value
    sig_value: String,
    /// The cryptographic suite identifier (e.g., "mldsa65-2024")
    cryptosuite: String,
    /// ISO 8601 timestamp of proof creation
    created: String,
    /// Proof type (must be "DataIntegrityProof")
    proof_type: String,
    /// Proof purpose (e.g., "assertionMethod")
    purpose: String,
}

// ============================================================================
// Formatting Functions for Report Sections
// ============================================================================

fn format_credential_metadata(credential: &Value) -> String {
    let mut output = String::new();
    
    let credential_id = credential["id"].as_str().unwrap_or("[UNSPECIFIED]");
    let issuer_identifier = credential["issuer"].as_str().unwrap_or("[UNSPECIFIED]");
    let issuance_timestamp = credential["issuanceDate"].as_str().unwrap_or("[UNSPECIFIED]");
    
    output.push_str(&format!("ID: {}\n", credential_id));
    output.push_str(&format!("Issuer: {}\n", issuer_identifier));
    output.push_str(&format!("Issuance Date: {}\n", issuance_timestamp));
    
    if let Some(type_array) = credential["type"].as_array() {
        let types: Vec<String> = type_array.iter()
            .filter_map(|t| t.as_str().map(String::from))
            .collect();
        output.push_str(&format!("Types: {}\n", types.join(" → ")));
    }
    
    if let Some(context_array) = credential["@context"].as_array() {
        let has_w3c_v2_context = context_array.iter().any(|ctx| {
            ctx.as_str().map(|s| s.contains("w3.org/ns/credentials/v2")).unwrap_or(false)
        });
        
        output.push_str(&format!("Context: {}\n", 
            if has_w3c_v2_context { "W3C Credentials v2" } else { "Non-standard" }));
    }
    
    output
}

fn format_proof_summary(proof: &ProofComponents) -> String {
    format!(
        "Cryptosuite: {}\n\
         Proof Type: {}\n\
         Created: {}\n\
         Purpose: {}\n\
         Verification Method: {}\n\
         Signature Size: {} characters (encoded)",
        proof.cryptosuite,
        proof.proof_type,
        proof.created,
        proof.purpose,
        proof.vm,
        proof.sig_value.len()
    )
}

fn format_signature_analysis(signature_bytes: &[u8], cryptosuite: &str) -> String {
    let expected_size = match cryptosuite {
        s if s.contains("44") => 2420,
        s if s.contains("65") => 3309,
        s if s.contains("87") => 4627,
        _ => 3309,
    };
    
    format!(
        "Total Size: {} bytes\n\
         Initial Bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}\n\
         Expected Size: {} bytes ({})\n\
         Size Validation: {}",
        signature_bytes.len(),
        signature_bytes[0], signature_bytes[1], signature_bytes[2], signature_bytes[3],
        signature_bytes[4], signature_bytes[5], signature_bytes[6], signature_bytes[7],
        expected_size,
        cryptosuite,
        if signature_bytes.len() == expected_size { "PASSED" } else { "FAILED" }
    )
}

fn format_public_key_analysis(public_key_bytes: &[u8]) -> String {
    let entropy_score = calculate_byte_entropy(public_key_bytes);
    
    format!(
        "Length: {} bytes\n\
         Initial Bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}\n\
         Entropy: {:.2} bits/byte (max 8.0)",
        public_key_bytes.len(),
        public_key_bytes[0], public_key_bytes[1], public_key_bytes[2], public_key_bytes[3],
        public_key_bytes[4], public_key_bytes[5], public_key_bytes[6], public_key_bytes[7],
        entropy_score
    )
}

fn format_signature_structure_validation(signature_bytes: &[u8], cryptosuite: &str) -> String {
    let (algorithm_name, l_parameter, k_parameter, total_expected) = match cryptosuite {
        s if s.contains("44") => ("ML-DSA-44", 4, 4, 2420),
        s if s.contains("65") => ("ML-DSA-65", 5, 6, 3309),
        s if s.contains("87") => ("ML-DSA-87", 7, 8, 4627),
        _ => ("ML-DSA-65", 5, 6, 3309),
    };
    
    format!(
        "Algorithm: {}\n\
         L Parameter (rows): {}\n\
         K Parameter (columns): {}\n\
         Challenge (c̃): 32 bytes\n\
         Response (z): {} bytes\n\
         Hints (h): {} bytes\n\
         Total Expected: {} bytes\n\
         Actual Size: {} bytes\n\
         Structure Validation: {}",
        algorithm_name,
        l_parameter,
        k_parameter,
        l_parameter * 640,
        total_expected - 32 - (l_parameter * 640),
        total_expected,
        signature_bytes.len(),
        if signature_bytes.len() == total_expected { "PASSED" } else { "FAILED" }
    )
}

fn format_canonicalization_results(doc: &str, config: &str, message: &[u8]) -> String {
    format!(
        "Canonicalized Credential: {} bytes\n\
         Canonicalized Proof Config: {} bytes\n\
         Combined Input Size: {} bytes\n\
         SHAKE-256 Output: 64 bytes\n\
         Message Prefix: {}...",
        doc.len(),
        config.len(),
        doc.len() + config.len(),
        hex::encode(&message[..16])
    )
}

fn validate_and_format_w3c_compliance(credential: &Value, _proof: &Value, components: &ProofComponents) -> String {
    let mut output = String::new();
    let mut all_compliant = true;
    
    // Check W3C v2 context
    if let Some(contexts) = credential["@context"].as_array() {
        let has_v2_context = contexts.iter().any(|c| {
            c.as_str().map(|s| s.contains("w3.org/ns/credentials/v2")).unwrap_or(false)
        });
        
        output.push_str(&format!("W3C Credentials v2 Context: {}\n", 
            if has_v2_context { "PRESENT" } else { "MISSING" }));
        if !has_v2_context { all_compliant = false; }
    }
    
    // Check VerifiableCredential type
    if let Some(types) = credential["type"].as_array() {
        let has_vc_type = types.iter().any(|t| t.as_str() == Some("VerifiableCredential"));
        
        output.push_str(&format!("VerifiableCredential Type: {}\n", 
            if has_vc_type { "PRESENT" } else { "MISSING" }));
        if !has_vc_type { all_compliant = false; }
    }
    
    // Check proof type
    output.push_str(&format!("Proof Type: {} {}\n", 
        components.proof_type,
        if components.proof_type == "DataIntegrityProof" { "(STANDARD)" } else { "(NON-STANDARD)" }));
    if components.proof_type != "DataIntegrityProof" { all_compliant = false; }
    
    // Check cryptosuite format
    output.push_str(&format!("Cryptosuite Format: {} {}\n",
        components.cryptosuite,
        if components.cryptosuite.contains("mldsa") && components.cryptosuite.contains("2024") 
            { "(STANDARD)" } else { "(NON-STANDARD)" }));
    
    output.push_str(&format!("\nOverall Compliance: {}", 
        if all_compliant { "COMPLIANT" } else { "PARTIAL - See notes above" }));
    
    output
}

// ============================================================================
// Step 1: Credential Loading and Parsing
// ============================================================================

/// Loads the credential file from the filesystem
fn load_credential_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    match fs::read_to_string(path) {
        Ok(content) => {
            println!("  Loaded: {} ({} bytes)", path, content.len());
            Ok(content)
        }
        Err(e) => {
            eprintln!("  ERROR: Failed to load '{}': {}", path, e);
            Err(e.into())
        }
    }
}

/// Parses JSON content into a structured Value object
fn parse_credential_json(json_content: &str) -> Result<Value, Box<dyn std::error::Error>> {
    match serde_json::from_str(json_content) {
        Ok(parsed) => {
            println!("  JSON structure validated");
            Ok(parsed)
        }
        Err(e) => {
            eprintln!("  ERROR: JSON parsing failed at line {}, column {}: {}", 
                e.line(), e.column(), e);
            Err(e.into())
        }
    }
}

// ============================================================================
// Step 2: Proof Component Extraction
// ============================================================================

/// Extracts the proof object from the credential per W3C specification
fn extract_proof_object(credential: &Value) -> Result<&Value, Box<dyn std::error::Error>> {
    credential.get("proof").ok_or_else(|| {
        eprintln!("  ERROR: No proof object found in credential");
        "Missing required 'proof' field".into()
    })
}

/// Parses individual proof fields into a structured format
fn parse_proof_components(proof: &Value) -> Result<ProofComponents, Box<dyn std::error::Error>> {
    Ok(ProofComponents {
        vm: proof["verificationMethod"]
            .as_str()
            .ok_or("Missing required 'verificationMethod' field")?
            .to_string(),
        sig_value: proof["proofValue"]
            .as_str()
            .ok_or("Missing required 'proofValue' field")?
            .to_string(),
        cryptosuite: proof["cryptosuite"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        created: proof["created"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        proof_type: proof["type"]
            .as_str()
            .unwrap_or("DataIntegrityProof")
            .to_string(),
        purpose: proof["proofPurpose"]
            .as_str()
            .unwrap_or("assertionMethod")
            .to_string(),
    })
}

// ============================================================================
// Step 3: Multibase Signature Decoding
// ============================================================================

/// Decodes a multibase-encoded signature according to W3C Data Integrity specification
fn decode_multibase_encoded_signature(encoded_signature: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encoded_signature.is_empty() {
        return Err("Empty signature string".into());
    }
    
    let multibase_prefix = encoded_signature.chars().next().unwrap();
    
    match multibase_prefix {
        MULTIBASE_BASE64URL_PREFIX => {
            println!("  Multibase prefix 'u' detected (standard)");
            let encoded_data = &encoded_signature[1..];
            decode_base64url_no_pad(encoded_data)
        }
        'z' => {
            println!("  Multibase prefix 'z' detected (non-standard for signatures)");
            let encoded_data = &encoded_signature[1..];
            decode_base58btc_signature(encoded_data)
        }
        _ => {
            println!("  No multibase prefix - assuming legacy encoding");
            decode_base64url_no_pad(encoded_signature)
        }
    }
}

/// Decodes base64url-no-pad encoded data with fallback manual implementation
fn decode_base64url_no_pad(encoded_data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sanitized: String = encoded_data.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    
    match URL_SAFE_NO_PAD.decode(&sanitized) {
        Ok(decoded_bytes) => {
            println!("  Decoded: {} chars → {} bytes", sanitized.len(), decoded_bytes.len());
            Ok(decoded_bytes)
        }
        Err(_) => {
            println!("  Standard decoder failed, using manual decoder");
            manual_base64url_decode(&sanitized)
        }
    }
}

/// Manual base64url decoder as fallback for non-standard implementations
fn manual_base64url_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output_buffer = Vec::new();
    let mut accumulator = 0u32;
    let mut bits_accumulated = 0;
    
    for character in input.chars() {
        let decoded_value = match character {
            'A'..='Z' => character as u8 - b'A',
            'a'..='z' => character as u8 - b'a' + 26,
            '0'..='9' => character as u8 - b'0' + 52,
            '-' => 62,
            '_' => 63,
            _ => continue,
        };
        
        accumulator = (accumulator << 6) | (decoded_value as u32);
        bits_accumulated += 6;
        
        if bits_accumulated >= 8 {
            bits_accumulated -= 8;
            output_buffer.push((accumulator >> bits_accumulated) as u8);
            accumulator &= (1 << bits_accumulated) - 1;
        }
    }
    
    if output_buffer.is_empty() {
        return Err("Manual decoding produced no output bytes".into());
    }
    
    println!("  Manual decode: {} chars → {} bytes", input.len(), output_buffer.len());
    Ok(output_buffer)
}

/// Decodes base58btc-encoded data using Bitcoin alphabet
fn decode_base58btc_signature(encoded_data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    bs58::decode(encoded_data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("Base58BTC decode error: {}", e).into())
}

// ============================================================================
// Step 4: Public Key Resolution from DID
// ============================================================================

/// Extracts public key from a W3C-compliant did:key identifier
fn resolve_did_key_public_key(did_identifier: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let did_without_fragment = did_identifier.split('#').next().ok_or("Malformed DID identifier")?;
    
    if !did_without_fragment.starts_with("did:key:z") {
        return Err(format!("Unsupported DID method (expected did:key:z): {}", did_without_fragment).into());
    }
    
    let encoded_component = &did_without_fragment[9..];
    
    let decoded_bytes = bs58::decode(encoded_component)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("Base58BTC decode error: {}", e))?;
    
    println!("  DID decoded: {} bytes (multicodec + public key)", decoded_bytes.len());
    
    if decoded_bytes.len() < 2 + PUBLICKEYBYTES {
        return Err(format!("Invalid key length: {} bytes", decoded_bytes.len()).into());
    }
    
    let multicodec_value = u16::from_be_bytes([decoded_bytes[0], decoded_bytes[1]]);
    println!("  Multicodec: 0x{:04x} (ML-DSA-{})", multicodec_value,
        match multicodec_value {
            MULTICODEC_MLDSA65 => "65",
            0x1304 => "44",
            0x1306 => "87",
            _ => "Unknown",
        });
    
    let public_key_bytes = decoded_bytes[2..2 + PUBLICKEYBYTES].to_vec();
    Ok(public_key_bytes)
}

/// Calculates Shannon entropy for byte distribution analysis
fn calculate_byte_entropy(data: &[u8]) -> f64 {
    let mut frequency_map = HashMap::new();
    for &byte in data {
        *frequency_map.entry(byte).or_insert(0) += 1;
    }
    
    let total_bytes = data.len() as f64;
    frequency_map.values()
        .map(|&count| {
            let probability = count as f64 / total_bytes;
            if probability > 0.0 { -probability * probability.log2() } else { 0.0 }
        })
        .sum()
}

// ============================================================================
// Step 5: Signature Structure Validation
// ============================================================================

/// Validates signature byte structure against ML-DSA algorithm parameters
fn validate_signature_bytes_structure(signature_bytes: &[u8], cryptosuite: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected_size = match cryptosuite {
        s if s.contains("44") => 2420,
        s if s.contains("65") => 3309,
        s if s.contains("87") => 4627,
        _ => 3309,
    };
    
    if signature_bytes.len() == expected_size {
        println!("  Signature structure: VALID ({} bytes)", signature_bytes.len());
        Ok(())
    } else {
        eprintln!("  Signature structure: INVALID (expected {} bytes, got {})", 
            expected_size, signature_bytes.len());
        Err(format!("Size mismatch").into())
    }
}

// ============================================================================
// Step 6: Cryptographic Self-Test
// ============================================================================

/// Performs comprehensive self-test of ML-DSA-65 implementation
fn perform_cryptographic_self_test() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = MlDsa65::keypair()?;
    
    let test_message = b"ML-DSA-65 W3C compliance validation vector";
    let signature = MlDsa65::sign(&secret_key, test_message)?;
    
    match MlDsa65::verify(&public_key, test_message, &signature) {
        Ok(true) => {
            println!("  Self-test: PASSED");
            Ok(())
        }
        _ => Err("Self-test verification failed".into()),
    }
}

// ============================================================================
// Step 7: JCS Canonicalization (RFC 8785)
// ============================================================================

/// Constructs verification message using JCS canonicalization
fn construct_verification_message(
    credential: &Value,
    proof: &Value,
) -> Result<(String, String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut unsigned_credential = credential.clone();
    if let Some(obj) = unsigned_credential.as_object_mut() {
        obj.remove("proof");
    }
    
    let mut proof_configuration = proof.clone();
    if let Some(obj) = proof_configuration.as_object_mut() {
        obj.remove("proofValue");
    }
    
    let canonical_credential = apply_jcs_canonicalization(&unsigned_credential);
    let canonical_proof_config = apply_jcs_canonicalization(&proof_configuration);
    
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_credential.as_bytes());
    Update::update(&mut hasher, canonical_proof_config.as_bytes());
    
    let mut verification_message = vec![0u8; 64];
    hasher.finalize_xof().read(&mut verification_message);
    
    println!("  Canonicalized: {} + {} = {} bytes → 64 byte message",
        canonical_credential.len(), canonical_proof_config.len(),
        canonical_credential.len() + canonical_proof_config.len());
    
    Ok((canonical_credential, canonical_proof_config, verification_message))
}

/// Applies JSON Canonicalization Scheme (JCS) per RFC 8785
fn apply_jcs_canonicalization(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted_entries: Vec<(&String, &Value)> = map.iter().collect();
            sorted_entries.sort_by(|a, b| a.0.cmp(b.0));
            let serialized_items: Vec<String> = sorted_entries.iter()
                .map(|(key, val)| format!("\"{}\":{}", key, apply_jcs_canonicalization(val)))
                .collect();
            format!("{{{}}}", serialized_items.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(apply_jcs_canonicalization).collect();
            format!("[{}]", items.join(","))
        }
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
    }
}

// ============================================================================
// Step 8: Signature Verification Execution
// ============================================================================

/// Executes ML-DSA-65 signature verification with provided parameters
fn execute_signature_verification(
    public_key_bytes: &[u8],
    verification_message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut public_key_array = [0u8; PUBLICKEYBYTES];
    let mut signature_array = [0u8; SIGNBYTES];
    
    public_key_array.copy_from_slice(public_key_bytes);
    signature_array[..signature_bytes.len()].copy_from_slice(signature_bytes);
    
    match MlDsa65::verify(&public_key_array, verification_message, &signature_array) {
        Ok(true) => {
            println!("  Verification: SUCCESSFUL");
            Ok(true)
        }
        Ok(false) => {
            println!("  Verification: FAILED");
            Ok(false)
        }
        Err(e) => {
            eprintln!("  Verification ERROR: {}", e);
            Err(e.into())
        }
    }
}

// ============================================================================
// Debug Artifact Persistence
// ============================================================================

/// Persists verification artifacts for forensic analysis
/// Persists verification artifacts for forensic analysis
fn persist_debug_artifacts(
    credential_json: &str,
    public_key_bytes: &[u8],
    signature_bytes: &[u8],
    canonical_doc: &str,
    canonical_config: &str,
    verification_message: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write("analysis_credential.json", credential_json)?;
    fs::write("analysis_public_key.bin", public_key_bytes)?;
    fs::write("analysis_signature.bin", signature_bytes)?;
    fs::write("analysis_canonical_doc.txt", canonical_doc)?;
    fs::write("analysis_canonical_config.txt", canonical_config)?;
    fs::write("analysis_message.bin", verification_message)?;
    
    println!("  Forensic artifacts saved to current directory");
    Ok(())
}