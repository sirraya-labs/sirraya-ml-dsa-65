// src/main.rs
use sirraya_ml_dsa_65::MlDsa65;

fn main() {
    println!("ML-DSA-65 Post-Quantum Cryptographic System");
    println!("FIPS 204 · NIST Level 2\n");

    match MlDsa65::keypair() {
        Ok((_pk, _sk)) => {
            println!("Key generation: OK");
            println!("Signature Size: {} bytes", sirraya_ml_dsa_65::SIGNBYTES);
            println!(
                "Public Key Size: {} bytes",
                sirraya_ml_dsa_65::PUBLICKEYBYTES
            );
        }
        Err(e) => println!("Error: {}", e),
    }
}
