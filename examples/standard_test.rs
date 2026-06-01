// examples/standard_test.rs
// Test the standard (unmasked) implementation

use dilithium5::Dilithium5;

fn main() {
    println!("========================================");
    println!("  Standard ML-DSA-87 Test");
    println!("  Fast, Unmasked Implementation");
    println!("========================================\n");

    // Generate keypair
    println!("1. Generating keypair...");
    let keypair_result = Dilithium5::keypair();

    let (pk, sk) = match keypair_result {
        Ok(kp) => kp,
        Err(e) => {
            println!("   ✗ Key generation failed: {}", e);
            return;
        }
    };
    println!("   ✓ Public key: {} bytes", pk.len());
    println!("   ✓ Secret key: {} bytes\n", sk.len());

    // Sign
    println!("2. Signing...");
    let msg = b"Standard signature test message";
    let sig_result = Dilithium5::sign(&sk, msg);

    let sig = match sig_result {
        Ok(s) => s,
        Err(e) => {
            println!("   ✗ Signing failed: {}", e);
            return;
        }
    };
    println!("   ✓ Signature: {} bytes", sig.len());
    println!("   First 32 bytes: {:02x?}...\n", &sig[..32]);

    // Verify
    println!("3. Verifying...");
    let valid_result = Dilithium5::verify(&pk, msg, &sig);

    match valid_result {
        Ok(valid) => {
            println!(
                "   ✓ Verification: {}\n",
                if valid { "VALID ✓" } else { "INVALID ✗" }
            );
        }
        Err(e) => {
            println!("   ✗ Verification error: {}\n", e);
            return;
        }
    }

    println!("========================================");
    println!("  Standard signing successful!");
    println!("  This version is faster but not side-channel resistant.");
    println!("========================================");
}
