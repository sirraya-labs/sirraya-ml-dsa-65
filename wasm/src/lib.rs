use wasm_bindgen::prelude::*;
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