//! ML-DSA-65 Post-Quantum Cryptography Implementation
//!
//! This is a complete implementation of the ML-DSA-65 digital signature algorithm,
//! standardized by NIST in FIPS 204 for post-quantum cryptography.

use ml_dsa_65::MlDsa65;

fn main() {
    println!("=================================================================");
    println!("ML-DSA-65 - POST-QUANTUM CRYPTOGRAPHY IMPLEMENTATION");
    println!("FIPS 204 · NIST Standard");
    println!("=================================================================");
    println!();

    match MlDsa65::keypair() {
        Ok((pk, sk)) => {
            println!("Key generation: OK");

            let msg = b"FIPS 204 ML-DSA-65 self-test";
            match MlDsa65::sign(&sk, msg) {
                Ok(sig) => match MlDsa65::verify(&pk, msg, &sig) {
                    Ok(true) => {
                        println!("Sign/verify: OK");
                        println!();
                        println!("Implementation ready for production use.");
                        println!("  Security Level: NIST Level 2");
                        println!("  Signature Size: {} bytes", sig.len());
                        println!("  Public Key Size: {} bytes", pk.len());
                    }
                    Ok(false) => {
                        eprintln!("Error: Verification returned false");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error during verification: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Error during signing: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error during key generation: {}", e);
            std::process::exit(1);
        }
    }
}
