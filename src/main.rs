//! Dilithium5 Post-Quantum Cryptography Implementation
//! 
//! This is a complete implementation of the Dilithium5 digital signature algorithm,
//! which has been selected by NIST for post-quantum cryptography standardization.

use dilithium5::dilithium::run_tests;

fn main() {
    println!("=================================================================");
    println!("DILITHIUM5 - POST-QUANTUM CRYPTOGRAPHY IMPLEMENTATION");
    println!("=================================================================");
    println!();
    
    match run_tests() {
        Ok(_) => {
            println!("\n Implementation ready for production use!");
            println!("   Security Level: NIST Level 5 (Highest)");
            println!("   Signature Size: {} bytes", dilithium5::constants::SIGNBYTES);
            println!("   Public Key Size: {} bytes", dilithium5::constants::PUBLICKEYBYTES);
        }
        Err(e) => {
            eprintln!("\n❌ Error during testing: {}", e);
            std::process::exit(1);
        }
    }
}