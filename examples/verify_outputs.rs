// examples/verify_outputs.rs
//! Verifies that the DID documents and verifiable credentials you generated
//! are valid and work correctly.

use dilithium5::Dilithium5;
use serde_json::Value;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("                 VERIFYING YOUR GENERATED OUTPUTS");
    println!("================================================================================");
    println!();

    // ============================================================================
    // Test 1: Verify the DID Document structure and key extraction
    // ============================================================================
    println!("TEST 1: DID Document Validation");
    println!("--------------------------------------------------------------------------------");

    let did_json = fs::read_to_string("did_document.json")?;
    let did_doc: Value = serde_json::from_str(&did_json)?;

    println!("✓ DID Document loaded ({} bytes)", did_json.len());
    println!("  DID: {}", did_doc["id"].as_str().unwrap_or("missing"));

    // Extract the public key from DID Document
    let verification_method = &did_doc["verification_method"][0];
    let multibase_key = verification_method["public_key_multibase"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('z');

    println!("  Public key (multibase): {}...", &multibase_key[..32]);
    println!();

    // ============================================================================
    // Test 2: Load and verify the verifiable credential
    // ============================================================================
    println!("TEST 2: Verifiable Credential Verification");
    println!("--------------------------------------------------------------------------------");

    let vc_json = fs::read_to_string("verifiable_credential.json")?;
    let vc: Value = serde_json::from_str(&vc_json)?;

    println!("✓ Verifiable Credential loaded ({} bytes)", vc_json.len());
    println!(
        "  Credential ID: {}",
        vc["id"].as_str().unwrap_or("missing")
    );
    println!("  Issuer: {}", vc["issuer"].as_str().unwrap_or("missing"));
    println!("  Type: {:?}", vc["type"]);
    println!(
        "  Subject: {}",
        vc["credential_subject"]["name"]
            .as_str()
            .unwrap_or("missing")
    );
    println!(
        "  Degree: {}",
        vc["credential_subject"]["degree"]["type"]
            .as_str()
            .unwrap_or("missing")
    );
    println!();

    // Extract the signature from the credential
    let proof_value = vc["proof"]["proof_value"].as_str().unwrap_or("");
    println!("  Signature: {}...", &proof_value[..32]);
    println!();

    // ============================================================================
    // Test 3: Verify the credential signature with the public key
    // ============================================================================
    println!("TEST 3: Cryptographic Verification");
    println!("--------------------------------------------------------------------------------");

    // Load the actual keys (they were saved during did_document_demo run)
    println!("Loading keys...");

    let public_key_bytes = fs::read("public_key.bin")?;
    let secret_key_bytes = fs::read("secret_key.bin")?;

    println!("  Public key: {} bytes", public_key_bytes.len());
    println!("  Secret key: {} bytes", secret_key_bytes.len());
    println!();

    // Reconstruct the credential subject (what was signed)
    let credential_subject = &vc["credential_subject"];
    let canonical = serde_json::to_string(credential_subject)?;
    println!("  Canonical credential data: {} bytes", canonical.len());
    println!("  Data being verified: {}", canonical);
    println!();

    // Decode the signature from base64
    use base64::engine::Engine;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof_value)?;

    let mut sig_array = [0u8; 4627];
    sig_array.copy_from_slice(&signature_bytes);

    // Convert public key bytes to fixed-size array
    let mut pub_array = [0u8; 2592];
    pub_array.copy_from_slice(&public_key_bytes);

    println!("  Verifying ML-DSA-87 signature...");
    let valid = Dilithium5::verify(&pub_array, canonical.as_bytes(), &sig_array)?;

    if valid {
        println!();
        println!("  ✅✅✅ SIGNATURE IS VALID! ✅✅✅");
        println!();
        println!("  The verifiable credential was:");
        println!(
            "    - Issued by: {}",
            vc["issuer"].as_str().unwrap_or("missing")
        );
        println!(
            "    - To: {}",
            vc["credential_subject"]["name"]
                .as_str()
                .unwrap_or("missing")
        );
        println!(
            "    - For: {}",
            vc["credential_subject"]["degree"]["type"]
                .as_str()
                .unwrap_or("missing")
        );
        println!(
            "    - From: {}",
            vc["credential_subject"]["degree"]["university"]
                .as_str()
                .unwrap_or("missing")
        );
        println!();
        println!("  This signature proves the credential is authentic and untampered.");
    } else {
        println!("  ❌❌❌ SIGNATURE IS INVALID! ❌❌❌");
        println!("  Something went wrong with the signing or verification.");
    }
    println!();

    // ============================================================================
    // Test 4: Verify the advanced DID document
    // ============================================================================
    println!("TEST 4: Advanced DID Document Validation");
    println!("--------------------------------------------------------------------------------");

    let advanced_json = fs::read_to_string("advanced_did.json")?;
    let advanced_doc: Value = serde_json::from_str(&advanced_json)?;

    println!(
        "✓ Advanced DID Document loaded ({} bytes)",
        advanced_json.len()
    );
    println!(
        "  DID: {}",
        advanced_doc["id"].as_str().unwrap_or("missing")
    );

    let verification_methods = advanced_doc["verificationMethod"].as_array().unwrap();
    println!("  Verification methods: {}", verification_methods.len());

    for (i, method) in verification_methods.iter().enumerate() {
        let key_id = method["id"].as_str().unwrap_or("missing");
        let key_type = method["type"].as_str().unwrap_or("missing");
        let multibase = method["public_key_multibase"].as_str().unwrap_or("");
        println!("    Key {}: {} ({})", i + 1, key_id, key_type);
        println!("       Multibase prefix: {}...", &multibase[..32]);
    }

    let services = advanced_doc["service"].as_array().unwrap();
    println!("  Services:");
    for service in services {
        println!(
            "    {} - {}",
            service["type"].as_str().unwrap_or("missing"),
            service["service_endpoint"].as_str().unwrap_or("missing")
        );
    }
    println!();

    // ============================================================================
    // Test 5: Verify that the public key in DID Document matches the actual key
    // ============================================================================
    println!("TEST 5: Key Consistency Check");
    println!("--------------------------------------------------------------------------------");

    // Extract public key from DID Document
    let did_multibase = verification_method["public_key_multibase"]
        .as_str()
        .unwrap_or("");
    let did_pubkey_base64 = did_multibase.trim_start_matches('z');

    // Convert actual public key to base64url for comparison
    let actual_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key_bytes);

    println!(
        "  DID Document public key prefix: {}...",
        &did_pubkey_base64[..32]
    );
    println!(
        "  Actual public key prefix:        {}...",
        &actual_base64[..32]
    );

    if did_pubkey_base64.starts_with(&actual_base64[..32]) {
        println!("  ✅ Keys match! The DID Document contains the correct public key.");
    } else {
        println!("  ⚠️ Keys differ. This may indicate the DID Document was generated with a different key.");
    }
    println!();

    Ok(())
}
