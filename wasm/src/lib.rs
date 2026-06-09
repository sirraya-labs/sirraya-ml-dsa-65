use wasm_bindgen::prelude::*;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use sirraya_ml_dsa_65::{MlDsa65, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};

#[wasm_bindgen]
pub fn generate_keypair() -> String {
    let (pk, sk) = MlDsa65::keypair().unwrap();
    serde_json::json!({
        "public_key": hex::encode(&pk),
        "secret_key": hex::encode(&sk)
    })
    .to_string()
}

#[wasm_bindgen]
pub fn sign(secret_key_hex: &str, message: &str) -> String {
    let sk_bytes = hex::decode(secret_key_hex).unwrap();
    let mut sk = [0u8; SECRETKEYBYTES];
    sk.copy_from_slice(&sk_bytes);
    let sig = MlDsa65::sign(&sk, message.as_bytes()).unwrap();
    hex::encode(&sig)
}

#[wasm_bindgen]
pub fn verify(public_key_hex: &str, message: &str, signature_hex: &str) -> bool {
    let pk_bytes = hex::decode(public_key_hex).unwrap();
    let sig_bytes = hex::decode(signature_hex).unwrap();
    let mut pk = [0u8; PUBLICKEYBYTES];
    let mut sig = [0u8; SIGNBYTES];
    pk.copy_from_slice(&pk_bytes);
    sig.copy_from_slice(&sig_bytes);
    MlDsa65::verify(&pk, message.as_bytes(), &sig).unwrap_or(false)
}

#[wasm_bindgen]
pub fn verify_vc_proof(
    public_key_hex: &str,
    canonical_vc: &str,
    canonical_proof: &str,
    signature_hex: &str,
) -> bool {
    let pk_bytes = hex::decode(public_key_hex).unwrap();
    let sig_bytes = hex::decode(signature_hex).unwrap();
    let mut pk = [0u8; PUBLICKEYBYTES];
    let mut sig = [0u8; SIGNBYTES];
    pk.copy_from_slice(&pk_bytes);
    sig.copy_from_slice(&sig_bytes);

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_vc.as_bytes());
    Update::update(&mut hasher, canonical_proof.as_bytes());
    let mut msg = vec![0u8; 64];
    hasher.finalize_xof().read(&mut msg);

    MlDsa65::verify(&pk, &msg, &sig).unwrap_or(false)
}

#[wasm_bindgen]
pub fn extract_pk_from_did(did: &str) -> String {
    let did = did.split('#').next().unwrap_or(did);
    let encoded = did.strip_prefix("did:key:z").unwrap_or("");
    match bs58::decode(encoded).into_vec() {
        Ok(bytes) if bytes.len() > 2 => hex::encode(&bytes[2..]),
        _ => String::new(),
    }
}

#[wasm_bindgen]
pub fn sign_vc_proof(secret_key_hex: &str, canonical_vc: &str, canonical_proof: &str) -> String {
    let sk_bytes = hex::decode(secret_key_hex).unwrap();
    let mut sk = [0u8; SECRETKEYBYTES];
    sk.copy_from_slice(&sk_bytes);

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_vc.as_bytes());
    Update::update(&mut hasher, canonical_proof.as_bytes());
    let mut msg = vec![0u8; 64];
    hasher.finalize_xof().read(&mut msg);

    let sig = MlDsa65::sign(&sk, &msg).unwrap();
    hex::encode(&sig)
}

#[wasm_bindgen]
pub fn jcs_canonicalize_unsigned_vc(vc_json: &str) -> String {
    let mut vc: serde_json::Value = serde_json::from_str(vc_json).unwrap();
    if let Some(obj) = vc.as_object_mut() {
        obj.remove("proof");
    }
    canonicalize_json_jcs(&vc)
}

#[wasm_bindgen]
pub fn jcs_canonicalize_proof_config(vc_json: &str) -> String {
    let vc: serde_json::Value = serde_json::from_str(vc_json).unwrap();
    let proof = vc.get("proof").unwrap();
    let mut config = proof.clone();
    if let Some(obj) = config.as_object_mut() {
        obj.remove("proofValue");
    }
    canonicalize_json_jcs(&config)
}

fn canonicalize_json_jcs(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let items: Vec<String> = sorted.iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonicalize_json_jcs(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json_jcs).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

#[wasm_bindgen]
pub fn create_did(public_key_hex: &str) -> String {
    let pk_bytes = hex::decode(public_key_hex).unwrap_or_default();
    let multicodec = 0x1305u16.to_be_bytes();
    let mut combined = Vec::with_capacity(2 + pk_bytes.len());
    combined.extend_from_slice(&multicodec);
    combined.extend_from_slice(&pk_bytes);
    let encoded = bs58::encode(&combined)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();
    format!("did:key:z{}", encoded)
}