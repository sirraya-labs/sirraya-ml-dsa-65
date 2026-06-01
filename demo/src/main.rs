use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde_json::{json, Value};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use sirraya_ml_dsa_65::{MlDsa65, PUBLICKEYBYTES, SECRETKEYBYTES};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("  sirraya-ml-dsa-65 — Full VC Issuance & Verification Demo");
    println!("============================================================\n");

    // ── Generate keypair ─────────────────────────────────────────
    println!("[1] Generating ML-DSA-65 keypair...");
    let (pk, sk) = MlDsa65::keypair()?;
    let did = create_did(&pk);
    println!("    DID: {}...", &did[..60]);

    // ── Build credential ─────────────────────────────────────────
    println!("\n[2] Constructing Verifiable Credential...");
    let credential = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": "urn:uuid:demo-vc",
        "type": ["VerifiableCredential", "TestCredential"],
        "issuer": did,
        "issuanceDate": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:subject",
            "name": "Demo Subject"
        }
    });

    // ── Sign ─────────────────────────────────────────────────────
    println!("\n[3] Signing with ML-DSA-65...");
    let signed_vc = sign_credential(credential, &sk, &did)?;
    fs::write("demo_vc.json", serde_json::to_string_pretty(&signed_vc)?)?;
    println!("    Saved: demo_vc.json");

    // ── Verify ───────────────────────────────────────────────────
    println!("\n[4] Verifying credential...");
    let vc_json = fs::read_to_string("demo_vc.json")?;
    let valid = verify_credential(&vc_json, &pk)?;

    if valid {
        println!("    Status: VALID");
        println!("\n============================================================");
        println!("  Demo complete. Credential issued and verified.");
        println!("  File: demo_vc.json");
        println!("============================================================");
    } else {
        println!("    Status: INVALID — verification failed");
    }

    Ok(())
}

fn create_did(pk: &[u8]) -> String {
    let codec = 0x1305u16.to_be_bytes();
    let mut combined = Vec::with_capacity(2 + pk.len());
    combined.extend_from_slice(&codec);
    combined.extend_from_slice(pk);
    let encoded = bs58::encode(combined)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();
    format!("did:key:z{}", encoded)
}

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

fn sign_credential(
    mut credential: Value,
    sk: &[u8; SECRETKEYBYTES],
    did: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let created = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "mldsa65-jcs-2024",
        "created": created,
        "verificationMethod": format!("{}#{}", did, did),
        "proofPurpose": "assertionMethod"
    });

    let unsigned = credential.clone();
    let canonical_doc = jcs_canonicalize(&unsigned);
    let canonical_config = jcs_canonicalize(&proof_config);

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, canonical_config.as_bytes());
    let mut msg = vec![0u8; 64];
    hasher.finalize_xof().read(&mut msg);

    let sig = MlDsa65::sign(sk, &msg)?;
    let encoded = format!("u{}", URL_SAFE_NO_PAD.encode(&sig));

    let mut proof = proof_config;
    proof["proofValue"] = json!(encoded);
    credential["proof"] = proof;

    Ok(credential)
}

fn verify_credential(vc_json: &str, pk: &[u8; PUBLICKEYBYTES]) -> Result<bool, Box<dyn std::error::Error>> {
    let vc: Value = serde_json::from_str(vc_json)?;
    let proof = vc.get("proof").ok_or("No proof")?;

    // Decode signature
    let sig_str = proof["proofValue"].as_str().ok_or("No proofValue")?;
    let sig_b64 = sig_str.strip_prefix('u').unwrap_or(sig_str);
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let mut sig = [0u8; 3309];
    sig.copy_from_slice(&sig_bytes);

    // Canonicalize
    let mut unsigned = vc.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    let mut config = proof.clone();
    config.as_object_mut().unwrap().remove("proofValue");

    let canonical_doc = jcs_canonicalize(&unsigned);
    let canonical_config = jcs_canonicalize(&config);

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, canonical_config.as_bytes());
    let mut msg = vec![0u8; 64];
    hasher.finalize_xof().read(&mut msg);

    MlDsa65::verify(pk, &msg, &sig).map_err(|e| e.into())
}