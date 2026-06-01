// src/lib.rs
//! ML-DSA-65 Post-Quantum Cryptography Implementation (FIPS 204)
//!
//!
//! This crate provides two versions:
//! - Standard implementation (in `ml_dsa_65` module) - Fast, unmasked ML-DSA-65
//! - Masked implementation (in `dilithium_masked` module) - Side-channel resistant
//!   (kept for legacy compatibility)

pub mod constants;
pub mod dilithium_masked;
pub mod ml_dsa_65;
pub mod polynomial;

// Re-export ML-DSA-65 as the default
pub use ml_dsa_65::MlDsa65;

// Re-export constants for public use
pub use constants::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};

// RDFC module - pure Rust RDFC-1.0 canonicalization
#[cfg(feature = "w3c")]
pub mod rdfc;

#[cfg(feature = "w3c")]
pub use rdfc::{
    // Public API - what users should actually use
    canonicalize,
    parse_nquads,
    IdentifierIssuer,
    // Remove these private functions:
    // hash_first_degree_quads,
    // hash_n_degree_quads,
    Quad,
    Term,
};

// VC Verifier module - JCS-based verification
#[cfg(feature = "w3c")]
pub mod vc_verifier;

#[cfg(feature = "w3c")]
pub use vc_verifier::verify_vc;

// For backward compatibility with existing code that expects Dilithium5
pub use dilithium_masked::Dilithium5 as Dilithium5Masked;

#[deprecated(since = "1.0.0", note = "Use MlDsa65 instead")]
pub use ml_dsa_65::MlDsa65 as Dilithium5;
