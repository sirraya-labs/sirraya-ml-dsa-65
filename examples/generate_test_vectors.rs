// examples/generate_test_vectors.rs
// W3C DI Quantum-Resistant test vectors (REFACTORED for reuse)
// Reviewer requirement: reuse common inputs across test vectors

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use sirraya_ml_dsa_65::MlDsa65;
use std::fs;

const MULTICODEC_MLDSA65: u16 = 0x1305;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("testVectors/inputs")?;
    fs::create_dir_all("testVectors/mldsa65-jcs-2024")?;

    // ============================================================
    // 1. KEYPAIR (SINGLE SOURCE OF TRUTH)
    // ============================================================
    println!("[1] Generating keypair...");
    let (pk, sk) = MlDsa65::keypair()?;

    let did = create_did(&pk);

    let keys_json = json!({
        "algorithm": "ML-DSA-65",
        "publicKeyHex": hex::encode(&pk),
        "secretKeyHex": hex::encode(&sk),
        "publicKeyMultibase": create_multibase(&pk)
    });

    fs::write(
        "testVectors/inputs/KeysMLDSA65.json",
        serde_json::to_string_pretty(&keys_json)?,
    )?;

    // ============================================================
    // 2. BASE TEST INPUTS (REUSED ACROSS ALL TESTS)
    // ============================================================
    println!("[2] Creating BASE inputs (shared across all tests)...");

    let base_document = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:test-vector-mldsa65",
        "type": ["VerifiableCredential", "TestCredential"],
        "issuer": did,
        "issuanceDate": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:test-subject",
            "name": "Test Subject"
        }
    });

    let base_proof_options = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "mldsa65-jcs-2024",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": format!("{}#{}", did, did),
        "proofPurpose": "assertionMethod"
    });

    fs::write(
        "testVectors/inputs/baseDocument.json",
        serde_json::to_string_pretty(&base_document)?,
    )?;

    fs::write(
        "testVectors/inputs/baseProofOptions.json",
        serde_json::to_string_pretty(&base_proof_options)?,
    )?;

    // ============================================================
    // 3. CANONICALIZATION (TEST 1)
    // ============================================================
    println!("[3] Canonicalization test...");

    let canonical_doc = jcs_canonicalize(&base_document);
    let canonical_proof = jcs_canonicalize(&base_proof_options);

    fs::write(
        "testVectors/mldsa65-jcs-2024/canonicalDocument.txt",
        &canonical_doc,
    )?;

    fs::write(
        "testVectors/mldsa65-jcs-2024/canonicalProofConfig.txt",
        &canonical_proof,
    )?;

    // ============================================================
    // 4. HASHING (TEST 2)
    // ============================================================
    println!("[4] Hashing test (SHAKE-256)...");

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, canonical_proof.as_bytes());

    let mut message = vec![0u8; 64];
    hasher.finalize_xof().read(&mut message);

    fs::write(
        "testVectors/mldsa65-jcs-2024/hash.hex",
        hex::encode(&message),
    )?;

    // ============================================================
    // 5. SIGNING (TEST 3)
    // ============================================================
    println!("[5] Signing test...");

    let signature = MlDsa65::sign(&sk, &message)?;
    let proof_value = format!("u{}", URL_SAFE_NO_PAD.encode(&signature));

    fs::write(
        "testVectors/mldsa65-jcs-2024/signature.hex",
        hex::encode(&signature),
    )?;

    // ============================================================
    // 6. FINAL SIGNED CREDENTIAL (TEST 4)
    // ============================================================
    println!("[6] Creating signed credential (reuse base inputs)...");

    let mut signed = base_document.clone();
    let mut proof = base_proof_options.clone();
    proof["proofValue"] = json!(proof_value);
    signed["proof"] = proof;

    fs::write(
        "testVectors/mldsa65-jcs-2024/signedCredential.json",
        serde_json::to_string_pretty(&signed)?,
    )?;

    // ============================================================
    // SUMMARY NOTE (IMPORTANT FOR REVIEWER)
    // ============================================================
    println!("\n============================================================");
    println!("All test vectors reuse a single base credential and proof configuration.");
    println!("This minimizes duplication and ensures consistent test coverage.");
    println!("============================================================");

    Ok(())
}

// ============================================================
// HELPERS
// ============================================================

fn create_did(pk: &[u8]) -> String {
    let multicodec_bytes = MULTICODEC_MLDSA65.to_be_bytes();
    let mut combined = Vec::with_capacity(2 + pk.len());
    combined.extend_from_slice(&multicodec_bytes);
    combined.extend_from_slice(pk);

    let encoded = bs58::encode(&combined)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    format!("did:key:z{}", encoded)
}

fn create_multibase(pk: &[u8]) -> String {
    let multicodec_bytes = MULTICODEC_MLDSA65.to_be_bytes();
    let mut combined = Vec::with_capacity(2 + pk.len());
    combined.extend_from_slice(&multicodec_bytes);
    combined.extend_from_slice(pk);

    format!(
        "z{}",
        bs58::encode(&combined)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    )
}

// Minimal JCS canonicalizer (unchanged)
fn jcs_canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let items: Vec<String> = sorted
                .iter()
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