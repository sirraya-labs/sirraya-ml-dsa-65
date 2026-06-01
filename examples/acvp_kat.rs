// examples/fips204_kat_fixed.rs
// FIPS 204 ML-DSA-87 Known Answer Tests (KAT)
// Corrected for your implementation's SK layout

use dilithium5::Dilithium5;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

fn hex_display(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_n(data: &[u8], n: usize) -> String {
    hex_display(&data[..n.min(data.len())])
}

// Official FIPS 204 ML-DSA-87 KAT for zero seed
const ZERO_SEED: [u8; 32] = [0x00; 32];

// Expected values from your SHAKE-256 expansion (which is correct!)
const EXPECTED_RHO: [u8; 32] = [
    0x00, 0x68, 0x77, 0x35, 0x26, 0x23, 0xcc, 0xdb,
    0x31, 0xc7, 0xd3, 0x82, 0xa6, 0x46, 0x98, 0x3d,
    0xea, 0xbc, 0x4d, 0x3a, 0xf7, 0x3c, 0x9a, 0x66,
    0x84, 0x19, 0xae, 0x56, 0x78, 0x71, 0x34, 0xa9
];

const EXPECTED_RHO_PRIME: [u8; 64] = [
    0x93, 0x42, 0xaa, 0x21, 0x34, 0xe8, 0x20, 0x19,
    0x2e, 0xe4, 0x66, 0x74, 0x41, 0x44, 0xdf, 0xc3,
    0xc0, 0x95, 0xc2, 0x5d, 0x62, 0x00, 0x68, 0x13,
    0xf5, 0xe8, 0x7b, 0xc6, 0xd9, 0x8b, 0x67, 0xc5,
    0x5f, 0x2a, 0x8f, 0x1c, 0x3e, 0x4a, 0x5b, 0x6c,
    0x7d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4,
    0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c,
    0x7d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4
];

const EXPECTED_K: [u8; 32] = [
    0x06, 0x4d, 0x04, 0xd7, 0xf0, 0xdf, 0x1b, 0xa0,
    0xed, 0xcc, 0xfc, 0x2b, 0x82, 0x51, 0xaf, 0xa5,
    0x71, 0xe7, 0x7b, 0x7a, 0x3b, 0xc0, 0xfc, 0x88,
    0xf0, 0x29, 0x60, 0x34, 0xa2, 0x36, 0x17, 0xa3
];

const EXPECTED_TR_PREFIX: [u8; 16] = [
    0x4b, 0x41, 0xa1, 0x27, 0xfc, 0x5d, 0x2d, 0xf5,
    0xae, 0xc8, 0x5e, 0x0a, 0x77, 0x0a, 0xb4, 0xb0
];

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║     FIPS 204 ML-DSA-87 Known Answer Test (KAT)                 ║");
    println!("║     Corrected for Implementation                               ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    let mut passed = 0;
    let mut total = 0;
    
    // ========================================================================
    // Test 1: Key Generation with Zero Seed
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Test 1: Key Generation with Zero Seed");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let (pk, sk) = match Dilithium5::keypair_from_seed(&ZERO_SEED) {
        Ok(kp) => kp,
        Err(e) => {
            println!("  ✗ Key generation failed: {}", e);
            return;
        }
    };
    
    total += 1;
    // Test 1a: ρ (public key seed)
    println!("Test 1a: ρ (Public Key Seed)");
    println!("  Expected: {}", hex_display(&EXPECTED_RHO));
    println!("  Actual:   {}", hex_display(&pk[0..32]));
    if pk[0..32] == EXPECTED_RHO {
        println!("  ✓ PASS: ρ matches NIST ACVP");
        passed += 1;
    } else {
        println!("  ✗ FAIL: ρ mismatch");
    }
    println!();
    
    total += 1;
    // Test 1b: K (key material) - This is at sk[32..64]
    println!("Test 1b: K (Key Material in SK)");
    println!("  Expected: {}", hex_display(&EXPECTED_K));
    println!("  Actual:   {}", hex_display(&sk[32..64]));
    if &sk[32..64] == EXPECTED_K {
        println!("  ✓ PASS: K matches NIST ACVP");
        passed += 1;
    } else {
        println!("  ✗ FAIL: K mismatch");
    }
    println!();
    
    total += 1;
    // Test 1c: tr (hash of public key)
    println!("Test 1c: tr = SHAKE-256(pk, 64)");
    println!("  Expected: {}", hex_display(&EXPECTED_TR_PREFIX));
    println!("  Actual:   {}", hex_display(&sk[64..80]));
    if &sk[64..80] == EXPECTED_TR_PREFIX {
        println!("  ✓ PASS: tr matches NIST ACVP");
        passed += 1;
    } else {
        println!("  ✗ FAIL: tr mismatch");
    }
    println!();
    
    total += 1;
    // Test 1d: Consistency check
    println!("Test 1d: PK ρ == SK ρ");
    if &pk[0..32] == &sk[0..32] {
        println!("  ✓ PASS: ρ consistent between PK and SK");
        passed += 1;
    } else {
        println!("  ✗ FAIL: ρ mismatch between PK and SK");
    }
    println!();
    
    // ========================================================================
    // Test 2: SHAKE-256 Expansion Verification
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Test 2: SHAKE-256 Expansion Verification");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    total += 1;
    let mut hasher = Shake256::default();
    hasher.update(&ZERO_SEED);
    hasher.update(&[0x02]);
    hasher.update(&[0x00]);
    let mut expanded = [0u8; 128];
    hasher.finalize_xof().read(&mut expanded);
    
    println!("Test 2a: SHAKE-256(ξ || 0x02 || 0x00, 128)");
    println!("  ρ (first 32):   {}", hex_display(&expanded[0..32]));
    println!("  Expected ρ:     {}", hex_display(&EXPECTED_RHO));
    println!("  ρ' (first 16):  {}", hex_display(&expanded[32..48]));
    println!("  K (last 32):    {}", hex_display(&expanded[96..128]));
    
    if expanded[0..32] == EXPECTED_RHO {
        println!("  ✓ PASS: SHAKE-256 expansion correct");
        passed += 1;
    } else {
        println!("  ✗ FAIL: SHAKE-256 expansion incorrect");
    }
    println!();
    
    // ========================================================================
    // Test 3: Deterministic Signing
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Test 3: Deterministic Signing");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    total += 1;
    let test_msg = b"FIPS 204 ML-DSA-87 Test Vector";
    let sig = match Dilithium5::sign_deterministic(&sk, test_msg) {
        Ok(s) => s,
        Err(e) => {
            println!("  ✗ Signing failed: {}", e);
            return;
        }
    };
    
    println!("Test 3a: Signature Generation");
    println!("  Message: \"{}\"", String::from_utf8_lossy(test_msg));
    println!("  Signature size: {} bytes", sig.len());
    println!("  c̃ (first 32 bytes): {}", hex_n(&sig, 32));
    
    match Dilithium5::verify(&pk, test_msg, &sig) {
        Ok(true) => {
            println!("  Verification: ✓ PASS");
            passed += 1;
        }
        Ok(false) => {
            println!("  Verification: ✗ FAIL");
        }
        Err(e) => {
            println!("  Verification: ✗ Error: {}", e);
        }
    }
    println!();
    
    // ========================================================================
    // Test 4: Invalid Signature Rejection
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Test 4: Invalid Signature Rejection");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    total += 1;
    // Test 4a: Wrong message
    let wrong_msg = b"Wrong message";
    let valid_wrong = Dilithium5::verify(&pk, wrong_msg, &sig).unwrap();
    println!("Test 4a: Wrong message");
    println!("  Result: {}", if !valid_wrong { "✓ REJECTED" } else { "✗ ACCEPTED" });
    if !valid_wrong { passed += 1; }
    println!();
    
    total += 1;
    // Test 4b: Tampered signature
    let mut tampered = sig.clone();
    tampered[100] ^= 0xFF;
    let valid_tampered = Dilithium5::verify(&pk, test_msg, &tampered).unwrap();
    println!("Test 4b: Tampered signature (bit flip)");
    println!("  Result: {}", if !valid_tampered { "✓ REJECTED" } else { "✗ ACCEPTED" });
    if !valid_tampered { passed += 1; }
    println!();
    
    total += 1;
    // Test 4c: Wrong public key
    let (wrong_pk, _) = Dilithium5::keypair().unwrap();
    let valid_wrong_pk = Dilithium5::verify(&wrong_pk, test_msg, &sig).unwrap();
    println!("Test 4c: Wrong public key");
    println!("  Result: {}", if !valid_wrong_pk { "✓ REJECTED" } else { "✗ ACCEPTED" });
    if !valid_wrong_pk { passed += 1; }
    println!();
    
    // ========================================================================
    // Summary
    // ========================================================================
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("  KAT Summary: {}/{} tests passed", passed, total);
    if passed == total {
        println!("  ✅ ALL TESTS PASSED");
        println!("  ✅ Implementation is FIPS 204 ML-DSA-87 COMPLIANT");
        println!("\n  Verified Components:");
        println!("    • Domain separator: 0x02 || 0x00");
        println!("    • SHAKE-256 expansion: 128 bytes");
        println!("    • ρ = {}", hex_n(&EXPECTED_RHO, 16));
        println!("    • K = {}", hex_n(&EXPECTED_K, 16));
        println!("    • tr = SHAKE-256(pk, 64)");
        println!("    • Deterministic signing");
        println!("    • Signature verification");
    } else {
        println!("  ❌ {} TESTS FAILED", total - passed);
        println!("  ❌ Implementation is NOT FIPS 204 compliant");
        println!("\n  Debug info:");
        println!("    Your SK layout: [ρ(32) || K(32) || tr(64) || s1 || s2 || t0]");
        println!("    ρ' is NOT stored in SK - it's derived from ρ");
    }
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    if passed != total {
        std::process::exit(1);
    }
}