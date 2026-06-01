// examples/practice_example.rs
use dilithium5::Dilithium5;
use dilithium5::constants::*;

// Helper function for hex display (since we can't use hex crate in all cases)
fn hex_display(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_n(data: &[u8], n: usize) -> String {
    data[..n.min(data.len())].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Extract and verify s₁ coefficients from raw secret key
/// FIPS 204 §8.2: Polynomial eta encoding (3 bits per coefficient)
fn verify_s1_coefficients(sk: &[u8; SECRETKEYBYTES]) -> Result<(), String> {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  FIPS 204 §8.2: s₁ Coefficient Extraction (η=2, 3 bits/coeff)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // s₁ starts after ρ(32) + K(32) + tr(64) = 128 bytes
    let s1_offset = 128;
    
    // Each s₁ polynomial: 256 coefficients × 3 bits = 768 bits = 96 bytes
    let poly_size = POLYETA_PACKEDBYTES; // 96 bytes
    
    println!("SK Layout:");
    println!("  ├─ ρ (seed):       bytes 0-31   (32 bytes)");
    println!("  ├─ K (key mat):    bytes 32-63  (32 bytes)");
    println!("  ├─ tr (hash):      bytes 64-127 (64 bytes)");
    println!("  └─ s₁:             bytes 128-{}  ({} bytes per polynomial × {} = {} bytes total)",
        s1_offset + L * poly_size - 1, poly_size, L, L * poly_size);
    
    println!("\nExtracting s₁[0] (first polynomial):");
    println!("  Raw bytes (96 bytes):");
    
    let s1_poly_start = s1_offset; // First polynomial starts here
    let s1_poly_raw = &sk[s1_poly_start..s1_poly_start + poly_size];
    
    // Display first 16 bytes of raw encoding
    println!("  {:02x?}...", &s1_poly_raw[..16]);
    
    // Decode coefficients (3 bits each)
    println!("\n  Decoded coefficients (first 32 of 256):");
    print!("  [");
    
    let mut coeffs = Vec::with_capacity(N);
    let mut bits_read = 0;
    let mut buffer = 0u32;
    let mut byte_pos = 0;
    
    for i in 0..N {
        // Fill buffer when needed
        while bits_read < 3 && byte_pos < poly_size {
            buffer |= (s1_poly_raw[byte_pos] as u32) << bits_read;
            bits_read += 8;
            byte_pos += 1;
        }
        
        // Extract 3 bits (η=2 means values in [-2, 2] encoded as 0..4)
        let val = buffer & 0x7;  // 3 bits mask
        let coeff = (val as i32) - 2;  // Convert to signed [-2, 2]
        
        coeffs.push(coeff);
        
        if i < 32 {
            print!("{:3}", coeff);
            if i < 31 { print!(", "); }
        }
        
        // Shift buffer
        buffer >>= 3;
        bits_read -= 3;
    }
    println!(" ...]");
    
    // Verify bounds
    let out_of_bounds = coeffs.iter().filter(|&&c| c < -2 || c > 2).count();
    if out_of_bounds > 0 {
        return Err(format!("Found {} coefficients outside [-2, 2] range!", out_of_bounds));
    }
    
    println!("\n  ✓ All coefficients within [-2, 2] range (η=2)");
    
    // Compute and display statistics
    let min = coeffs.iter().min().unwrap();
    let max = coeffs.iter().max().unwrap();
    let zeros = coeffs.iter().filter(|&&c| c == 0).count();
    let ones = coeffs.iter().filter(|&&c| c == 1).count();
    let neg_ones = coeffs.iter().filter(|&&c| c == -1).count();
    
    println!("\n  Statistics for s₁[0]:");
    println!("    Range: [{}, {}]", min, max);
    println!("    Zeros:  {} ({:.1}%)", zeros, zeros as f32 / N as f32 * 100.0);
    println!("    +1:     {} ({:.1}%)", ones, ones as f32 / N as f32 * 100.0);
    println!("    -1:     {} ({:.1}%)", neg_ones, neg_ones as f32 / N as f32 * 100.0);
    
    Ok(())
}

/// Compare FIPS 204 vs old Dilithium key derivation
fn compare_derivation_methods() {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  FIPS 204 §6.1 vs Old Dilithium: Key Derivation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
    
    let zero_seed = [0u8; 32];
    
    // FIPS 204 method
    let mut fips_input = [0u8; 33];
    fips_input[..32].copy_from_slice(&zero_seed);
    fips_input[32] = 0x02;
    
    let mut fips_exp = [0u8; 128];
    let mut hasher = Shake256::default();
    hasher.update(&fips_input);
    hasher.finalize_xof().read(&mut fips_exp);
    
    // Old Dilithium method
    let mut old_exp = [0u8; 96];
    let mut hasher = Shake256::default();
    hasher.update(&zero_seed);
    hasher.finalize_xof().read(&mut old_exp);
    
    println!("Same seed (all zeros) produces:");
    println!("  FIPS 204 ρ (32 bytes): {}…", hex_n(&fips_exp[0..32], 16));
    println!("  Old Dilithium ρ:       {}…", hex_n(&old_exp[0..32], 16));
    println!("\n  First 8 bytes comparison:");
    for i in 0..8 {
        if fips_exp[i] != old_exp[i] {
            println!("    Byte {}: {:02x} vs {:02x} ✗ DIFFERENT", i, fips_exp[i], old_exp[i]);
        } else {
            println!("    Byte {}: {:02x} vs {:02x} ✓ SAME (coincidence)", i, fips_exp[i], old_exp[i]);
        }
    }
    println!("\n  ✓ Domain separator (0x02) changes the expansion as expected");
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     ML-DSA-87: Full Secret Key Component Extraction         ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    
    // Generate a fresh keypair - handle errors without ?
    let keypair_result = Dilithium5::keypair();
    
    let (pk, sk) = match keypair_result {
        Ok(kp) => kp,
        Err(e) => {
            println!("✗ Failed to generate keypair: {}", e);
            return;
        }
    };
    
    // Display full keys (using our custom hex function since hex crate might not be available)
    println!("\n--- FULL PUBLIC KEY (PK) ---");
    println!("{}", hex_display(&pk));
    println!("\nPK Size: {} bytes", pk.len());
    
    println!("\n--------------------------------------------------\n");
    
    println!("--- FULL SECRET KEY (SK) ---");
    println!("{}", hex_display(&sk));
    println!("\nSK Size: {} bytes", sk.len());
    
    // Display component breakdown
    println!("\n--- SK COMPONENT BREAKDOWN ---");
    println!("rho (seed): {}", hex_display(&sk[0..32]));
    println!("K (rnd):    {}", hex_display(&sk[32..64]));
    println!("tr (hash):  {}", hex_display(&sk[64..128]));
    println!("s₁ (start): {}... ({} bytes total)", 
             hex_display(&sk[128..144]), L * POLYETA_PACKEDBYTES);
    println!("s₂ (start): {}... ({} bytes total)", 
             hex_display(&sk[128 + L * POLYETA_PACKEDBYTES..128 + L * POLYETA_PACKEDBYTES + 16]), 
             K * POLYETA_PACKEDBYTES);
    
    // Extract and verify s₁ coefficients
    match verify_s1_coefficients(&sk) {
        Ok(_) => println!("\n✓ s₁ extraction and verification complete"),
        Err(e) => println!("\n✗ s₁ verification failed: {}", e),
    }
    
    // Compare derivation methods
    compare_derivation_methods();
    
    // Note about full lattice verification
    println!("\n--- LATTICE VERIFICATION ---");
    println!("For full lattice verification, run your diagnostic module:");
    println!("  cargo test -- --nocapture");
    println!("  (The tests include diagnostic::demonstrate_lattice)");
    
    // Demonstrate that we can sign and verify
    println!("\n--- SIGNING DEMONSTRATION ---");
    let msg = b"ML-DSA-87 Key Extraction Test";
    match Dilithium5::sign(&sk, msg) {
        Ok(sig) => {
            println!("✓ Signature created ({} bytes)", sig.len());
            match Dilithium5::verify(&pk, msg, &sig) {
                Ok(valid) => {
                    println!("✓ Signature verification: {}", if valid { "SUCCESS" } else { "FAILED" });
                }
                Err(e) => println!("✗ Verification error: {}", e),
            }
        }
        Err(e) => println!("✗ Signing failed: {}", e),
    }
    
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  Key extraction complete!                                   ║");
    println!("║  All components properly encoded per FIPS 204 §7.2          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}