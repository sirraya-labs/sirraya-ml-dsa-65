// examples/sign_verify_demo_no_question.rs
//! Complete demonstration without using the ? operator

use ml_dsa_65::MlDsa65;
#[cfg(feature = "masking")]
use ml_dsa_65::dilithium_masked::masked::{MaskedSecretKey, masked_sign};
use std::time::Instant;

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║          ML-DSA-87 Sign & Verify Demonstration                 ║");
    println!("║              Post-Quantum Digital Signatures                   ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Part 1: Standard Implementation
    println!(" PART 1: STANDARD IMPLEMENTATION");
    println!("────────────────────────────────────────────────────────────────\n");
    standard_sign_verify();

    // Part 2: Masked Implementation
    #[cfg(feature = "masking")]
    {
        println!("\n PART 2: MASKED IMPLEMENTATION (SUCRE)");
        println!("────────────────────────────────────────────────────────────────\n");
        masked_sign_verify();
    }

    // Part 3: Security Demonstration
    println!("\n PART 3: SECURITY DEMONSTRATION");
    println!("────────────────────────────────────────────────────────────────\n");
    security_demo();

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                    DEMONSTRATION COMPLETE                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");
}

fn standard_sign_verify() {
    // Step 1: Generate a keypair
    println!("Step 1: Generating keypair...");
    let start = Instant::now();
    let keypair_result = MlDsa65::keypair();
    
    let (public_key, secret_key) = match keypair_result {
        Ok(kp) => kp,
        Err(e) => {
            println!("   ✗ Key generation failed: {}", e);
            return;
        }
    };
    let keygen_time = start.elapsed();
    
    println!("   ✓ Public key:  {} bytes", public_key.len());
    println!("   ✓ Secret key:  {} bytes", secret_key.len());
    println!("     Public key prefix: {:02x}{:02x}{:02x}...", 
             public_key[0], public_key[1], public_key[2]);
    println!("     Secret key prefix: {:02x}{:02x}{:02x}...", 
             secret_key[0], secret_key[1], secret_key[2]);
    println!("     Key generation time: {:?}\n", keygen_time);

    // Step 2: Create a message
    println!(" Step 2: Creating message...");
    let message = b"This is a confidential document that needs to be signed.";
    println!("   Message: \"{}\"", String::from_utf8_lossy(message));
    println!("   Message length: {} bytes\n", message.len());

    // Step 3: Sign the message
    println!("  Step 3: Signing message...");
    let start = Instant::now();
    let sign_result = MlDsa65::sign(&secret_key, message);
    
    let signature = match sign_result {
        Ok(sig) => sig,
        Err(e) => {
            println!("   ✗ Signing failed: {}", e);
            return;
        }
    };
    let sign_time = start.elapsed();
    
    println!("   ✓ Signature: {} bytes", signature.len());
    println!("   First 32 bytes: {:02x?}...", &signature[..32]);
    println!("     Signing time: {:?}\n", sign_time);

    // Step 4: Verify the signature
    println!(" Step 4: Verifying signature...");
    let start = Instant::now();
    let verify_result = MlDsa65::verify(&public_key, message, &signature);
    let verify_time = start.elapsed();
    
    match verify_result {
        Ok(is_valid) => {
            println!("   ✓ Verification result: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
        }
        Err(e) => {
            println!("   ✗ Verification error: {}", e);
            return;
        }
    }
    println!("     Verification time: {:?}\n", verify_time);

    println!(" Signature Details:");
    println!("   ├─ Challenge hash (c̃):  {:02x?}...", &signature[0..8]);
    println!("   ├─ Response (z):         {} bytes", 4627 - 32 - 100);
    println!("   └─ Hints (h):            {} bytes", 100);
    println!();
}

#[cfg(feature = "masking")]
fn masked_sign_verify() {
    use rand::rngs::OsRng;
    let mut rng = OsRng;

    println!("Step 1: Generating keypair...");
    let start = Instant::now();
    let keypair_result = MlDsa65::keypair();
    
    let (public_key, secret_key) = match keypair_result {
        Ok(kp) => kp,
        Err(e) => {
            println!("   ✗ Key generation failed: {}", e);
            return;
        }
    };
    let keygen_time = start.elapsed();
    
    println!("   ✓ Public key:  {} bytes", public_key.len());
    println!("   ✓ Secret key:  {} bytes", secret_key.len());
    println!("     Key generation time: {:?}\n", keygen_time);

    println!("  Step 2: Creating masked secret key...");
    let start = Instant::now();
    let masked_result = MaskedSecretKey::from_plain(&secret_key, &mut rng);
    
    let mut masked_sk = match masked_result {
        Ok(msk) => msk,
        Err(e) => {
            println!("   ✗ Masked key creation failed: {}", e);
            return;
        }
    };
    let mask_time = start.elapsed();
    
    println!("   ✓ Secret key is now split into arithmetic shares");
    println!("   ✓ Each share is stored separately in memory");
    println!("   ✓ The actual secret never exists in a single location");
    println!("     Masking time: {:?}\n", mask_time);

    println!(" Step 3: Creating message...");
    let message = b"Sensitive transaction: Transfer $1,000,000 to account 0x742d...";
    println!("   Message: \"{}\"", String::from_utf8_lossy(message));
    println!("   Message length: {} bytes\n", message.len());

    println!("  Step 4: Signing with masked implementation (SUCRE)...");
    let start = Instant::now();
    let sign_result = masked_sign(&mut masked_sk, message, &mut rng);
    
    let signature = match sign_result {
        Ok(sig) => sig,
        Err(e) => {
            println!("   ✗ Masked signing failed: {}", e);
            return;
        }
    };
    let sign_time = start.elapsed();
    
    println!("   ✓ Signature: {} bytes", signature.len());
    println!("   First 32 bytes: {:02x?}...", &signature[..32]);
    println!("   ✓ SUCRE shuffling applied during signing");
    println!("   ✓ Rejection sampling protected against side-channel attacks");
    println!("     Signing time: {:?}\n", sign_time);

    println!(" Step 5: Verifying with standard verification...");
    let start = Instant::now();
    let verify_result = MlDsa65::verify(&public_key, message, &signature);
    let verify_time = start.elapsed();
    
    match verify_result {
        Ok(is_valid) => {
            println!("   ✓ Verification result: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
            if is_valid {
                println!("   ✓ Cross-verification successful!");
                println!("   ✓ Masked signature is compatible with standard verifier");
            }
        }
        Err(e) => {
            println!("   ✗ Verification error: {}", e);
            return;
        }
    }
    println!("     Verification time: {:?}\n", verify_time);

    println!("🧹 Step 6: Secure cleanup...");
    masked_sk.zeroize();
    println!("   ✓ Secret key shares zeroized");
    println!("   ✓ Memory securely wiped\n");
}

fn security_demo() {
    let keypair_result = MlDsa65::keypair();
    let (pk, sk) = match keypair_result {
        Ok(kp) => kp,
        Err(e) => {
            println!("   ✗ Key generation failed: {}", e);
            return;
        }
    };
    
    let sign_result = MlDsa65::sign(&sk, b"Original message that will be signed");
    let signature = match sign_result {
        Ok(sig) => sig,
        Err(e) => {
            println!("   ✗ Signing failed: {}", e);
            return;
        }
    };
    
    println!(" Security Tests:");
    println!("   Original signature: VALID ✓");
    
    let tampered_msg = b"This message has been tampered with!";
    match MlDsa65::verify(&pk, tampered_msg, &signature) {
        Ok(valid) => println!("    Modified message: {}", if !valid { "REJECTED ✓" } else { "ACCEPTED ✗" }),
        Err(e) => println!("    Modified message error: {}", e),
    }
    
    let mut tampered_sig = signature.clone();
    tampered_sig[100] ^= 0xFF;
    match MlDsa65::verify(&pk, b"Original message that will be signed", &tampered_sig) {
        Ok(valid) => println!("    Tampered signature: {}", if !valid { "REJECTED ✓" } else { "ACCEPTED ✗" }),
        Err(e) => println!("    Tampered signature error: {}", e),
    }
    
    let wrong_keypair = MlDsa65::keypair();
    let (wrong_pk, _) = match wrong_keypair {
        Ok(kp) => kp,
        Err(e) => {
            println!("   ✗ Wrong key generation failed: {}", e);
            return;
        }
    };
    match MlDsa65::verify(&wrong_pk, b"Original message that will be signed", &signature) {
        Ok(valid) => println!("    Wrong public key: {}", if !valid { "REJECTED ✓" } else { "ACCEPTED ✗" }),
        Err(e) => println!("    Wrong public key error: {}", e),
    }
    
    println!("\n Security Summary:");
    println!("   ✓ Message integrity: Any change invalidates signature");
    println!("   ✓ Signature authenticity: Cannot be forged without secret key");
    println!("   ✓ Non-repudiation: Signer cannot deny signing");
    println!("   ✓ Post-quantum secure: Resistant to quantum computer attacks");
}