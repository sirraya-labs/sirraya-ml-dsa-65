# sirraya-ml-dsa-65 -- Post-Quantum Digital Signatures (FIPS 204)

[![Build](https://github.com/sirraya-labs/sirraya-ml-dsa-65/actions/workflows/ci.yml/badge.svg)](https://github.com/sirraya-labs/sirraya-ml-dsa-65/actions)
[![Crates.io](https://img.shields.io/crates/v/sirraya-ml-dsa-65.svg)](https://crates.io/crates/sirraya-ml-dsa-65)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pure Rust implementation of the NIST FIPS 204 Module-Lattice-Based Digital
Signature Algorithm with W3C Verifiable Credential and Decentralized Identifier
support.

---

## Standards

| Standard | Implementation |
|----------|---------------|
| NIST FIPS 204 | ML-DSA-65 key generation, signing, verification |
| W3C DID Core 1.0 | did:key method with multicodec |
| W3C VC Data Model 2.0 | Full credential structure and proof chain |
| W3C Data Integrity 1.0 | DataIntegrityProof with multibase encoding |
| RFC 8785 | JSON Canonicalization Scheme |
| IANA Multicodec | 0x1305 (ML-DSA-65 public key, provisional) |

---

## Installation


[dependencies]
sirraya-ml-dsa-65 = { version = "0.1", features = ["w3c"] }
Quick Start
Generate a signed credential
bash
cargo run --example mldsa-65-vc-generate --features w3c
Produces degree_bs_computer_science.json -- a W3C Verifiable Credential
secured with an ML-DSA-65 Data Integrity proof.

Verify a credential
bash
cargo run --example verify_vc --features w3c -- degree_bs_computer_science.json
Library Usage
Key generation, signing, verification
rust
use sirraya_ml_dsa_65::MlDsa65;

let (pk, sk) = MlDsa65::keypair()?;
let sig = MlDsa65::sign(&sk, b"message")?;
let valid = MlDsa65::verify(&pk, b"message", &sig)?;
assert!(valid);
Working with DIDs
rust
use sirraya_ml_dsa_65::vc_verifier::extract_public_key_from_did_key;

let pk = extract_public_key_from_did_key(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
)?;
Verifying a credential programmatically
rust
use sirraya_ml_dsa_65::vc_verifier::verify_vc;

let vc_json = std::fs::read_to_string("credential.json")?;
match verify_vc(&vc_json) {
    Ok(true)  => println!("Valid"),
    Ok(false) => println!("Invalid signature"),
    Err(e)    => eprintln!("Error: {}", e),
}
Key Sizes
Parameter	Bytes
Public key	1,952
Secret key	4,032
Signature	3,309
Features
Feature	Description
default	Standard library support
w3c	Verifiable Credentials, DIDs, JCS canonicalization
masking	Side-channel resistant masked signing
Cryptosuites
Identifier	Canonicalization	Status
mldsa65-jcs-2024	JCS (RFC 8785)	Stable
mldsa65-rdfc-2024	RDFC-1.0	Experimental
Repository Structure
text
src/
  ml_dsa_65.rs         Core FIPS 204 implementation
  polynomial.rs        Polynomial arithmetic and NTT
  constants.rs         Algorithm parameters
  dilithium_masked.rs  Side-channel resistant variant
  vc_verifier.rs       Credential verification library
  rdfc.rs              RDFC-1.0 canonicalization
examples/
  mldsa-65-vc-generate.rs  Credential issuance demo
  verify_vc.rs             Credential verification demo
  did_document_demo.rs     DID document creation
Build from Source
bash
git clone https://github.com/sirraya-labs/sirraya-ml-dsa-65.git
cd sirraya-ml-dsa-65
cargo build --release --features w3c
cargo test --features w3c
License
MIT License. See LICENSE.

References
NIST FIPS 204 -- ML-DSA Standard

W3C DID Core -- Decentralized Identifiers

W3C VC Data Model -- Verifiable Credentials

W3C Data Integrity -- Proof Specification

RFC 8785 -- JSON Canonicalization Scheme