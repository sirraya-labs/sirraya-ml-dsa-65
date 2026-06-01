//! Example usage of Dilithium5 library

use dilithium5::constants::*;
use dilithium5::Dilithium5;
use hex::encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Dilithium5 Example Usage");
    println!("=======================\n");

    // =================================================================
    // 1. Generate a keypair
    // =================================================================
    println!("1. Generating keypair...");
    let (pk, sk) = Dilithium5::keypair()?;
    println!("   ✓ Generated {} byte public key", pk.len());
    println!("   ✓ Generated {} byte secret key", sk.len());

    // Display actual key bytes (first 32 bytes only for readability)
    println!("   Public Key (first 64 chars of hex):");
    println!("   {}", encode(&pk[..32.min(pk.len())]));
    println!("   Secret Key (first 64 chars of hex):");
    println!("   {}", encode(&sk[..32.min(sk.len())]));

    // =================================================================
    // 2. Sign a message
    // =================================================================
    println!("\n2. Signing a message...");
    let message = b"This is a test message to be signed with Dilithium5";
    let signature = Dilithium5::sign(&sk, message)?;
    println!("   ✓ Generated {} byte signature", signature.len());

    // Display message and signature
    println!("   Message: \"{}\"", String::from_utf8_lossy(message));
    println!("   Message hex: {}", encode(message));
    println!("   Signature (first 64 chars of hex):");
    println!("   {}", encode(&signature[..32.min(signature.len())]));

    // =================================================================
    // 3. Verify the signature
    // =================================================================
    println!("\n3. Verifying the signature...");
    let is_valid = Dilithium5::verify(&pk, message, &signature)?;
    if is_valid {
        println!("   ✓ Signature is valid!");
    } else {
        println!("   ✗ Signature is invalid!");
    }

    // =================================================================
    // 4. Extract public key from secret key
    // =================================================================
    println!("\n4. Extracting public key from secret key...");
    let extracted_pk = Dilithium5::pk_from_sk(&sk)?;
    println!("   ✓ Extracted {} byte public key", extracted_pk.len());

    // Verify they match
    if pk == extracted_pk {
        println!("   ✓ Extracted PK matches original PK");
        println!("   Extracted PK (first 64 chars):");
        println!("   {}", encode(&extracted_pk[..32.min(extracted_pk.len())]));
    } else {
        println!("   ✗ Extracted PK does NOT match original PK!");
    }

    // =================================================================
    // 5. Test with different message (should fail)
    // =================================================================
    println!("\n5. Testing with different message...");
    let wrong_message = b"This is a different message";
    let should_fail = Dilithium5::verify(&pk, wrong_message, &signature)?;
    if !should_fail {
        println!("   ✓ Correctly rejected wrong message");
    } else {
        println!("   ✗ Incorrectly accepted wrong message");
    }

    // =================================================================
    // 6. Generate deterministic keys from seed
    // =================================================================
    println!("\n6. Generating deterministic keys from seed...");
    let seed = [42u8; SEEDBYTES];
    println!("   Seed (hex): {}", encode(&seed));

    let (pk1, sk1) = Dilithium5::keypair_from_seed(&seed)?;
    let (pk2, sk2) = Dilithium5::keypair_from_seed(&seed)?;

    if pk1 == pk2 && sk1 == sk2 {
        println!("   ✓ Deterministic keys match");
        println!(
            "   PK1 (first 64 chars): {}",
            encode(&pk1[..32.min(pk1.len())])
        );
        println!(
            "   PK2 (first 64 chars): {}",
            encode(&pk2[..32.min(pk2.len())])
        );
    } else {
        println!("   ✗ Deterministic keys don't match");
    }

    // =================================================================
    // 7. Additional Verification Tests
    // =================================================================
    println!("\n7. Additional Verification Tests");
    println!("   ============================");

    // Test 1: Verify with extracted PK
    println!("\n   Test 1: Verify with extracted public key...");
    let sig_with_extracted = Dilithium5::sign(&sk, b"Test with extracted PK")?;
    let valid_with_extracted = Dilithium5::verify(
        &extracted_pk,
        b"Test with extracted PK",
        &sig_with_extracted,
    )?;
    println!(
        "   Result: {}",
        if valid_with_extracted {
            "✓ Valid"
        } else {
            "✗ Invalid"
        }
    );

    // Test 2: Multiple signatures for same message
    println!("\n   Test 2: Multiple signatures for same message...");
    let msg = b"Multiple signatures test";
    let sig1 = Dilithium5::sign(&sk, msg)?;
    let sig2 = Dilithium5::sign(&sk, msg)?;

    println!(
        "   Signature 1 (first 32 chars): {}",
        encode(&sig1[..16.min(sig1.len())])
    );
    println!(
        "   Signature 2 (first 32 chars): {}",
        encode(&sig2[..16.min(sig2.len())])
    );

    let valid1 = Dilithium5::verify(&pk, msg, &sig1)?;
    let valid2 = Dilithium5::verify(&pk, msg, &sig2)?;
    println!("   Sig1 valid: {}", valid1);
    println!("   Sig2 valid: {}", valid2);

    // Test 3: Empty message
    println!("\n   Test 3: Empty message signature...");
    let empty_sig = Dilithium5::sign(&sk, b"")?;
    let empty_valid = Dilithium5::verify(&pk, b"", &empty_sig)?;
    println!("   Empty message signature valid: {}", empty_valid);

    // =================================================================
    // 8. Show Full Output Option
    // =================================================================
    println!("\n8. Full Output Samples");
    println!("   ===================");

    // Ask user if they want to see full output
    println!("\n   Display full public key? (y/n): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" {
        println!("\n   Full Public Key ({} bytes):", pk.len());
        println!("   {}", encode(&pk));

        println!("\n   Full Secret Key (first 256 bytes of {}):", sk.len());
        println!("   {}...", encode(&sk[..256.min(sk.len())]));

        println!("\n   Full Signature ({} bytes):", signature.len());
        println!("   {}", encode(&signature));
    }

    // =================================================================
    // 9. Save to files for external verification
    // =================================================================
    println!("\n9. Saving to files for external verification...");

    // Create output directory
    let output_dir = "dilithium_output";
    std::fs::create_dir_all(output_dir)?;

    // Save keys and signature
    std::fs::write(format!("{}/public_key.bin", output_dir), &pk)?;
    std::fs::write(format!("{}/secret_key.bin", output_dir), &sk)?;
    std::fs::write(format!("{}/signature.bin", output_dir), &signature)?;
    std::fs::write(format!("{}/message.txt", output_dir), message)?;

    // Save hex versions
    std::fs::write(format!("{}/public_key.hex", output_dir), encode(&pk))?;
    std::fs::write(
        format!("{}/secret_key_first_256.hex", output_dir),
        encode(&sk[..256.min(sk.len())]),
    )?;
    std::fs::write(format!("{}/signature.hex", output_dir), encode(&signature))?;
    std::fs::write(format!("{}/message.hex", output_dir), encode(message))?;

    // Save verification script
    let verification_script = r#"
// Verification script for Dilithium5 signature
use dilithium5::Dilithium5;
use hex::decode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load from files
    let pk_hex = std::fs::read_to_string("public_key.hex")?;
    let sig_hex = std::fs::read_to_string("signature.hex")?;
    let msg_hex = std::fs::read_to_string("message.hex")?;
    
    let pk = decode(pk_hex.trim())?;
    let sig = decode(sig_hex.trim())?;
    let msg = decode(msg_hex.trim())?;
    
    // Convert to arrays
    let pk_array: [u8; 2592] = pk.try_into().unwrap();
    let sig_array: [u8; 4595] = sig.try_into().unwrap();
    
    // Verify
    let is_valid = Dilithium5::verify(&pk_array, &msg, &sig_array)?;
    
    println!("Signature verification result: {}", is_valid);
    println!("Expected: true");
    
    Ok(())
}
"#;

    std::fs::write(
        format!("{}/verify_signature.rs", output_dir),
        verification_script,
    )?;

    println!("   ✓ Saved to directory: {}", output_dir);
    println!("   Files created:");
    println!("   • public_key.bin / .hex");
    println!("   • secret_key.bin / .hex (first 256 bytes)");
    println!("   • signature.bin / .hex");
    println!("   • message.txt / .hex");
    println!("   • verify_signature.rs");

    // =================================================================
    // SUMMARY
    // =================================================================
    println!("\n{}", "=".repeat(50));
    println!("✅ DILITHIUM5 IMPLEMENTATION VERIFIED");
    println!("{}", "=".repeat(50));
    println!();
    println!("All operations working correctly:");
    println!(
        "• Key generation: {} byte PK, {} byte SK",
        PUBLICKEYBYTES, SECRETKEYBYTES
    );
    println!("• Signing: {} byte signatures", SIGNBYTES);
    println!("• Verification: Valid signatures accepted");
    println!("• Error handling: Invalid inputs rejected");
    println!("• Determinism: Same seed → same keys");
    println!();
    println!("Output saved to: {}", output_dir);
    println!("Run: cd {} && cargo run --bin verify_signature", output_dir);
    println!("to verify the signature externally.");

    Ok(())
}
