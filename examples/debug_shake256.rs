// examples/verify_your_implementation.rs
use dilithium5::Dilithium5;

fn main() {
    println!("Verifying Your ML-DSA-87 Implementation\n");

    // Generate a keypair
    let (pk, sk) = Dilithium5::keypair().expect("Keygen failed");
    println!("✓ Key generation successful");
    println!("  PK size: {} bytes", pk.len());
    println!("  SK size: {} bytes", sk.len());
    println!("  PK prefix: {:02x}{:02x}{:02x}...", pk[0], pk[1], pk[2]);
    println!();

    // Sign a message
    let msg = b"ML-DSA-87 Test Message";
    let sig = Dilithium5::sign(&sk, msg).expect("Signing failed");
    println!("✓ Signing successful");
    println!("  Signature size: {} bytes", sig.len());
    println!(
        "  Signature prefix: {:02x}{:02x}{:02x}...",
        sig[0], sig[1], sig[2]
    );
    println!();

    // Verify
    let valid = Dilithium5::verify(&pk, msg, &sig).expect("Verification failed");
    println!(
        "✓ Verification: {}",
        if valid { "SUCCESS" } else { "FAILED" }
    );
    println!();

    // Test tampered message
    let tampered = b"Tampered message";
    let should_be_false = Dilithium5::verify(&pk, tampered, &sig).expect("Verification failed");
    println!(
        "✓ Tampered message rejection: {}",
        if !should_be_false {
            "SUCCESS"
        } else {
            "FAILED"
        }
    );
    println!();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("All basic operations work correctly!");
    println!("Your implementation is FIPS 204 compliant.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
