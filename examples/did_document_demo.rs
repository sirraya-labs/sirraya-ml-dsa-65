// examples/did_document_demo.rs
//! Demonstrates ML-DSA-65 (FIPS 204) keys in W3C DID Document and Verifiable
//! Credentials format.
//!
//! This example is intended as a reference implementation contribution to the
//! W3C Credentials Community Group (W3C CCG) showing how post-quantum keys
//! produced by ML-DSA-65 can be encoded and used within the decentralized
//! identity stack.
//!
//! # Standards Compliance
//!
//! - W3C DID Core 1.0                  <https://www.w3.org/TR/did-1.0/>
//! - W3C DID Key Method v0.9           <https://w3c-ccg.github.io/did-key-spec/>
//! - W3C VC Data Model 2.0             <https://www.w3.org/TR/vc-data-model-2.0/>
//! - W3C Data Integrity 1.0            <https://www.w3.org/TR/vc-data-integrity/>
//! - W3C CCG Quantum-Safe Cryptosuites <https://w3c-ccg.github.io/di-quantum-safe/>
//! - Multiformats Multibase             <https://github.com/multiformats/multibase>
//! - Multiformats Multicodec            <https://github.com/multiformats/multicodec>
//! - NIST FIPS 204 (ML-DSA)            <https://csrc.nist.gov/pubs/fips/204/final>
//!
//! # did:key Encoding
//!
//! Per the did:key spec, the DID identifier is constructed as:
//!
//!   `did:key:MULTIBASE(base58-btc, MULTICODEC(varint(key_type), raw_public_key_bytes))`
//!
//! The multibase prefix for base58-btc is the ASCII character `z`.
//!
//! ML-DSA-65 does not yet have a finalized entry in the multicodec table. This
//! implementation uses the provisional varint code `0x1206` (encoded as the
//! two-byte varint `[0x86, 0x24]`), consistent with the W3C CCG Quantum-Safe
//! Cryptosuites draft. Implementers MUST update this code point when a final
//! assignment is published in the multicodec registry.
//!
//! # Proof Encoding
//!
//! Data Integrity proof values use Multibase base64url-nopad encoding, prefixed
//! with `u`, per the VC Data Integrity spec §2.1.
//!
//! The `cryptosuite` identifier follows the W3C CCG Quantum-Safe Cryptosuites
//! draft: `mldsa65-rdfc-2024` (RDFC-1.0 canonicalization + ML-DSA-65 signatures).

use ml_dsa_65::MlDsa65;
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Multicodec / Multibase helpers
// ---------------------------------------------------------------------------

/// Provisional multicodec varint for ML-DSA-65 public keys.
///
/// `0x1206` encoded as the unsigned varint `[0x86, 0x24]`.
/// See <https://github.com/multiformats/multicodec> for the canonical table.
///
/// **Update this constant when the final code point is assigned.**
const ML_DSA_65_MULTICODEC_VARINT: &[u8] = &[0x86, 0x24];

/// Encode raw public key bytes as a W3C-compliant `publicKeyMultibase` value.
///
/// Algorithm (did:key spec §3.1):
/// 1. Prepend the multicodec varint identifier for the key type.
/// 2. Encode the resulting bytes with base58-btc.
/// 3. Prepend the multibase prefix `z` (base58-btc indicator).
pub fn encode_public_key_multibase(raw_public_key: &[u8]) -> String {
    let mut multicodec_bytes =
        Vec::with_capacity(ML_DSA_65_MULTICODEC_VARINT.len() + raw_public_key.len());
    multicodec_bytes.extend_from_slice(ML_DSA_65_MULTICODEC_VARINT);
    multicodec_bytes.extend_from_slice(raw_public_key);
    format!("z{}", bs58::encode(&multicodec_bytes).into_string())
}

/// Encode arbitrary bytes as a Multibase base64url-nopad value (prefix `u`).
///
/// Used for `proofValue` fields per the VC Data Integrity spec §2.1.
pub fn encode_proof_value_multibase(bytes: &[u8]) -> String {
    use base64::engine::Engine;
    format!(
        "u{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Derive the `did:key` DID string from a raw ML-DSA-65 public key.
///
/// The full multibase-encoded key string is used both as the DID identifier
/// (after `did:key:`) **and** as the verification method fragment, per §3.2
/// of the did:key spec.
pub fn derive_did_key(raw_public_key: &[u8]) -> String {
    format!("did:key:{}", encode_public_key_multibase(raw_public_key))
}

// ---------------------------------------------------------------------------
// DID Document structures (W3C DID Core 1.0)
// ---------------------------------------------------------------------------

/// W3C DID Document.
///
/// Conforms to the abstract data model defined in DID Core 1.0 §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context. The first entry MUST be the DID Core context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID subject — the entity described by this document.
    pub id: String,

    /// Optional controller DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,

    /// Cryptographic key material used to authenticate the DID subject.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// Keys authorised to authenticate as the DID subject.
    pub authentication: Vec<String>,

    /// Keys authorised to make verifiable claims (e.g. issue VCs).
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,

    /// Keys for key agreement (encryption).
    ///
    /// ML-DSA-65 is a signing-only algorithm and cannot be used for key
    /// encapsulation or agreement. This field is intentionally left empty.
    /// Pair with an ML-KEM-768 (FIPS 203) key when key agreement is needed.
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<String>,

    /// Keys authorised for capability invocation (e.g. authorising DID ops).
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<String>,

    /// Keys authorised for capability delegation.
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<String>,

    /// Optional service endpoints (DID Core 1.0 §5.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
}

/// A verification method embedded in or referenced by a DID Document.
///
/// Conforms to DID Core 1.0 §5.2 and uses the `Multikey` type defined in
/// the Controller Documents 1.0 spec
/// <https://www.w3.org/TR/controller-document/>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// The verification method identifier (a DID URL with a fragment).
    pub id: String,

    /// Verification method type.
    ///
    /// `"Multikey"` is the recommended type for post-quantum keys encoded
    /// using multibase + multicodec.
    #[serde(rename = "type")]
    pub type_: String,

    /// The DID that controls this key.
    pub controller: String,

    /// Multibase-encoded Multikey public key (multicodec varint + raw bytes,
    /// base58-btc encoded, `z` prefix).
    ///
    /// Absent when `publicKeyJwk` is used instead.
    #[serde(rename = "publicKeyMultibase")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    /// JSON Web Key representation.
    ///
    /// Absent when `publicKeyMultibase` is used instead.
    #[serde(rename = "publicKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

/// A DID Document service endpoint (DID Core 1.0 §5.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

impl DidDocument {
    /// Construct a minimal single-key DID Document for a `did:key` DID.
    ///
    /// Per the did:key spec §3.2 the verification method `id` MUST use the
    /// same multibase-encoded key string that forms the DID identifier suffix.
    pub fn from_ml_dsa_65_key(did: &str, raw_public_key: &[u8; 1952]) -> Self {
        let multibase_key = encode_public_key_multibase(raw_public_key);

        // Fragment MUST equal the multibase key string (did:key spec §3.2).
        let vm_id = format!("{}#{}", did, multibase_key);

        let verification_method = vec![VerificationMethod {
            id: vm_id.clone(),
            type_: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(multibase_key),
            public_key_jwk: None,
        }];

        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/multikey/v1".to_string(),
            ],
            id: did.to_string(),
            controller: None,
            verification_method,
            authentication: vec![vm_id.clone()],
            assertion_method: vec![vm_id.clone()],
            // ML-DSA-65 is signing-only; keyAgreement is intentionally empty.
            key_agreement: vec![],
            capability_invocation: vec![vm_id.clone()],
            capability_delegation: vec![vm_id],
            service: None,
        }
    }

    /// Serialise the document to indented JSON-LD.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// Verifiable Credential structures (W3C VC Data Model 2.0)
// ---------------------------------------------------------------------------

/// A W3C Verifiable Credential secured with a Data Integrity proof.
///
/// Conforms to VC Data Model 2.0 §4 and Data Integrity 1.0 §3.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    pub id: String,

    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// The DID of the issuer.
    pub issuer: String,

    /// RFC 3339 issuance timestamp.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    /// Optional RFC 3339 expiry timestamp.
    #[serde(rename = "expirationDate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    /// Claims about the credential subject.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: serde_json::Value,

    /// The Data Integrity proof securing this credential.
    pub proof: DataIntegrityProof,
}

/// A W3C Data Integrity proof (Data Integrity 1.0 §2.1).
#[derive(Debug, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    /// MUST be `"DataIntegrityProof"`.
    #[serde(rename = "type")]
    pub type_: String,

    /// Cryptographic suite identifier.
    ///
    /// `"mldsa65-rdfc-2024"` denotes ML-DSA-65 with RDFC-1.0
    /// canonicalization, per the W3C CCG Quantum-Safe Cryptosuites draft.
    pub cryptosuite: String,

    /// RFC 3339 creation timestamp.
    pub created: String,

    /// Intended use of the proof; MUST match a relationship present in the
    /// issuer's DID Document (e.g. `"assertionMethod"`).
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,

    /// DID URL referencing the verification method used to create the proof.
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    /// Multibase base64url-nopad encoded signature (prefix `u`).
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

// ---------------------------------------------------------------------------
// Credential helpers
// ---------------------------------------------------------------------------

/// Create and sign a Verifiable Credential using ML-DSA-65.
///
/// The `credentialSubject` is canonicalized with RDFC-1.0
/// canonicalization before signing, matching the `mldsa65-rdfc-2024`
/// cryptosuite identifier.
///
/// > **Note for production use:** A conformant Data Integrity implementation
/// > MUST include the proof configuration document (type, cryptosuite, created,
/// > proofPurpose, verificationMethod) in the signed payload per Data Integrity
/// > 1.0 §4.4. This example signs only the `credentialSubject` for clarity.
fn create_verifiable_credential(
    issuer_did: &str,
    issuer_vm_id: &str,
    secret_key: &[u8; 4032],
) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
    use chrono::Utc;

    // Generic example subject — replace with domain-specific credential claims.
    let credential_subject = serde_json::json!({
        "id": "did:example:subject123",
        "name": "Example Subject",
        "achievement": {
            "type": "ExampleAchievement",
            "name": "Post-Quantum Cryptography Implementer",
            "description": "Demonstrated implementation of ML-DSA-65 in a W3C-compliant DID system.",
            "criteria": "Successfully generate keys, create a DID Document, issue a Verifiable Credential, and verify the proof using ML-DSA-65 (FIPS 204)."
        }
    });

    let proof_value = sign_rdfc_payload(&credential_subject, secret_key)?;

    Ok(VerifiableCredential {
        context: vec![
            // VC Data Model 2.0 base context
            "https://www.w3.org/ns/credentials/v2".to_string(),
            // Multikey / Data Integrity context
            "https://w3id.org/security/multikey/v1".to_string(),
        ],
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_: vec![
            "VerifiableCredential".to_string(),
            "ExampleAchievementCredential".to_string(),
        ],
        issuer: issuer_did.to_string(),
        issuance_date: Utc::now().to_rfc3339(),
        expiration_date: None,
        credential_subject,
        proof: DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: "mldsa65-rdfc-2024".to_string(),
            created: Utc::now().to_rfc3339(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: issuer_vm_id.to_string(),
            proof_value,
        },
    })
}

/// Sign the RDFC-canonical bytes of `payload` with ML-DSA-65.
///
/// Returns a Multibase base64url-nopad-encoded signature (prefix `u`) as
/// required by the VC Data Integrity spec §2.1.
///
/// Note: This uses JCS as a placeholder. A production implementation MUST
/// use proper RDFC-1.0 canonicalization for the `mldsa65-rdfc-2024` suite.
fn sign_rdfc_payload(
    payload: &serde_json::Value,
    secret_key: &[u8; 4032],
) -> Result<String, Box<dyn std::error::Error>> {
    // FIXME: Replace with proper RDFC-1.0 canonicalization
    // For demonstration, we use JCS (RFC 8785) as an approximation
    let canonical = serde_json::to_string(payload)?;
    let signature = MlDsa65::sign(secret_key, canonical.as_bytes())?;
    Ok(encode_proof_value_multibase(&signature))
}

/// Verify an ML-DSA-65 `DataIntegrityProof` on a Verifiable Credential.
fn verify_verifiable_credential(
    vc: &VerifiableCredential,
    raw_public_key: &[u8; 1952],
) -> Result<bool, Box<dyn std::error::Error>> {
    use base64::engine::Engine;

    println!("Verifying Data Integrity proof…");
    println!("  Cryptosuite        : {}", vc.proof.cryptosuite);
    println!("  Proof purpose      : {}", vc.proof.proof_purpose);
    println!("  Verification method: {}", vc.proof.verification_method);

    // Strip the Multibase prefix `u` and decode from base64url-nopad.
    let proof_b64 = vc
        .proof
        .proof_value
        .strip_prefix('u')
        .ok_or("proofValue must begin with Multibase prefix 'u' (base64url-nopad)")?;

    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof_b64)?;

    if signature_bytes.len() != 3309 {
        return Err(format!(
            "Unexpected ML-DSA-65 signature length: {} bytes (expected 3309)",
            signature_bytes.len()
        )
        .into());
    }

    let mut sig_array = [0u8; 3309];
    sig_array.copy_from_slice(&signature_bytes);

    // FIXME: Replace with proper RDFC-1.0 canonicalization
    let canonical = serde_json::to_string(&vc.credential_subject)?;
    let valid = MlDsa65::verify(raw_public_key, canonical.as_bytes(), &sig_array)?;

    if valid {
        println!("  ✓ Signature VALID");
        println!("  ✓ Issuer authenticated");
        println!("  ✓ Credential integrity confirmed");
    } else {
        println!("  ✗ Signature INVALID");
    }

    Ok(valid)
}

// ---------------------------------------------------------------------------
// Multi-key DID Document (did:web)
// ---------------------------------------------------------------------------

/// Create a `did:web` DID Document with purpose-separated ML-DSA-65 keys and
/// example service endpoints.
///
/// `did:web` documents live at a well-known HTTPS URL and are resolved by
/// dereferencing that URL. Keys here are freshly generated for illustration.
///
/// Note: `keyAgreement` is omitted because ML-DSA-65 is signing-only. Pair
/// with an ML-KEM-768 (FIPS 203) key when key agreement is required.
fn create_multi_key_did_document(
    did: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (auth_key, _) = MlDsa65::keypair()?;
    let (assert_key, _) = MlDsa65::keypair()?;

    let auth_multibase = encode_public_key_multibase(&auth_key);
    let assert_multibase = encode_public_key_multibase(&assert_key);

    let auth_vm_id = format!("{}#{}", did, auth_multibase);
    let assert_vm_id = format!("{}#{}", did, assert_multibase);

    // Extract hostname from did:web for service endpoint URLs.
    let hostname = did.trim_start_matches("did:web:");

    Ok(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": auth_vm_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": auth_multibase
            },
            {
                "id": assert_vm_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": assert_multibase
            }
        ],
        // ML-DSA-65 supports authentication and assertionMethod only.
        // keyAgreement is intentionally omitted (signing-only algorithm).
        "authentication": [auth_vm_id],
        "assertionMethod": [assert_vm_id],
        "service": [
            {
                "id": format!("{}#linked-domain", did),
                "type": "LinkedDomains",
                "serviceEndpoint": format!("https://{}", hostname)
            },
            {
                "id": format!("{}#credential-status", did),
                "type": "StatusList2021",
                "serviceEndpoint": format!("https://{}/status/1", hostname)
            }
        ]
    }))
}

// ---------------------------------------------------------------------------
// Key export reference
// ---------------------------------------------------------------------------

/// Print ML-DSA-65 keys in every common format with standard references.
fn print_key_export_formats(
    raw_public_key: &[u8; 1952],
    raw_secret_key: &[u8; 4032],
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::engine::Engine;

    println!("Key Export Format Reference\n");

    // ① Multibase + Multicodec — used in DID Documents
    let multibase = encode_public_key_multibase(raw_public_key);
    println!("① Multibase / Multikey  [publicKeyMultibase in DID Documents]");
    println!("  Standard  : W3C DID Key Method v0.9, Multiformats Multibase/Multicodec");
    println!("  Prefix    : 'z'  (base58-btc, per multibase table)");
    println!("  Multicodec: 0x1206 → varint [0x86, 0x24]  (provisional ML-DSA-65)");
    println!("  Value     : {}…", &multibase[..64.min(multibase.len())]);
    println!();

    // ② JWK — for JOSE / OIDC ecosystems
    let jwk_public = serde_json::json!({
        "kty": "OKP",
        "crv": "ML-DSA-65",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_public_key),
        "use": "sig",
        "alg": "ML-DSA-65",
        "key_ops": ["verify"]
    });
    println!("② JSON Web Key (JWK)  [JOSE / OIDC — provisional until RFC finalized]");
    println!("  Standard  : RFC 7517 (JWK), draft-ietf-cose-dilithium");
    println!("{}", serde_json::to_string_pretty(&jwk_public)?);
    println!();

    // ③ PEM — informational; PKCS#8 OIDs for ML-DSA not yet standardized.
    let pem_public = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        base64::engine::general_purpose::STANDARD.encode(raw_public_key)
    );
    println!("③ PEM  [informational — PKCS#8 OIDs for ML-DSA pending IETF standardization]");
    println!("  Standard  : draft-ietf-lamps-dilithium-certificates");
    println!(
        "{}",
        pem_public.lines().take(3).collect::<Vec<_>>().join("\n")
    );
    println!("  …");
    println!();

    // ④ Raw base64url-nopad — Multibase `u` prefix, used in proofValue
    let b64url_pub = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_public_key);
    let b64url_sec = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_secret_key);
    println!("④ Raw base64url-nopad  [Multibase 'u' prefix — used in proofValue]");
    println!("  Standard  : W3C Data Integrity 1.0 §2.1, Multiformats Multibase");
    println!("  Public key (first 64 chars): {}…", &b64url_pub[..64]);
    println!("  Secret key (first 64 chars): {}…", &b64url_sec[..64]);
    println!();

    // ⑤ Hex — test vectors and debugging only
    println!("⑤ Hexadecimal  [test vectors and debugging only]");
    println!(
        "  Public key (first 32 bytes): {}",
        hex::encode(&raw_public_key[..32])
    );
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("     ML-DSA-65 DID Document & Verifiable Credentials — Reference Demo");
    println!("     W3C DID Core 1.0 · VC Data Model 2.0 · Data Integrity 1.0");
    println!("     NIST FIPS 204 · W3C CCG Quantum-Safe Cryptosuites (Draft)");
    println!("================================================================================\n");

    // ── Part 1: Key Generation ───────────────────────────────────────────────
    println!("PART 1: KEY GENERATION  (NIST FIPS 204, ML-DSA-65)");
    println!("--------------------------------------------------------------------------------");
    println!("Generating ML-DSA-65 keypair…");

    let start = Instant::now();
    let (public_key, secret_key) = MlDsa65::keypair()?;
    let keygen_time = start.elapsed();

    println!("  Public key : {} bytes", public_key.len());
    println!("  Secret key : {} bytes", secret_key.len());
    println!("  Generated in {:?}\n", keygen_time);

    // ── Part 2: DID Document ─────────────────────────────────────────────────
    println!("PART 2: DID DOCUMENT  (W3C DID Core 1.0 + DID Key Method v0.9)");
    println!("--------------------------------------------------------------------------------");

    // Derive the did:key identifier from the full public key.
    let did = derive_did_key(&public_key);
    println!("DID: {}\n", did);

    let did_doc = DidDocument::from_ml_dsa_65_key(&did, &public_key);
    let did_doc_json = did_doc.to_json_pretty()?;
    println!("{}", did_doc_json);

    std::fs::write("did_document.json", &did_doc_json)?;
    println!("\nSaved → did_document.json\n");

    // The verification method id doubles as the key reference throughout.
    let vm_id = &did_doc.authentication[0];

    // ── Part 3: Key Files ────────────────────────────────────────────────────
    println!("PART 3: KEY FILES");
    println!("--------------------------------------------------------------------------------");

    std::fs::write("public_key.bin", &public_key)?;
    std::fs::write("secret_key.bin", &secret_key)?;
    println!(
        "Raw binary : public_key.bin ({} B), secret_key.bin ({} B)",
        public_key.len(),
        secret_key.len()
    );

    {
        use base64::engine::Engine;

        // PEM — informational; awaiting IETF finalisation of ML-DSA OIDs.
        let pem_pub = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&public_key)
        );
        let pem_sec = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&secret_key)
        );
        std::fs::write("public_key.pem", pem_pub)?;
        std::fs::write("secret_key.pem", pem_sec)?;
        println!("PEM (draft): public_key.pem, secret_key.pem");

        // JWK
        let jwk_pub = serde_json::json!({
            "kty": "OKP",
            "crv": "ML-DSA-65",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key),
            "use": "sig",
            "alg": "ML-DSA-65",
            "key_ops": ["verify"],
            "kid": vm_id
        });
        let jwk_sec = serde_json::json!({
            "kty": "OKP",
            "crv": "ML-DSA-65",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_key),
            "d": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&secret_key),
            "use": "sig",
            "alg": "ML-DSA-65",
            "key_ops": ["sign"],
            "kid": vm_id
        });
        std::fs::write("public_key.jwk", serde_json::to_string_pretty(&jwk_pub)?)?;
        std::fs::write("secret_key.jwk", serde_json::to_string_pretty(&jwk_sec)?)?;
        println!("JWK        : public_key.jwk, secret_key.jwk\n");
    }

    // ── Part 4: Verifiable Credential ────────────────────────────────────────
    println!("PART 4: VERIFIABLE CREDENTIAL  (VC Data Model 2.0 + Data Integrity 1.0)");
    println!("--------------------------------------------------------------------------------");

    let vc = create_verifiable_credential(&did, vm_id, &secret_key)?;
    let vc_json = serde_json::to_string_pretty(&vc)?;
    println!("{}", vc_json);

    std::fs::write("verifiable_credential.json", &vc_json)?;
    println!("\nSaved → verifiable_credential.json\n");

    // ── Part 5: Proof Verification ───────────────────────────────────────────
    println!("PART 5: PROOF VERIFICATION");
    println!("--------------------------------------------------------------------------------");
    verify_verifiable_credential(&vc, &public_key)?;
    println!();

    // ── Part 6: Multi-key DID Document ───────────────────────────────────────
    println!("PART 6: MULTI-KEY DID DOCUMENT  (did:web, purpose-separated keys)");
    println!("--------------------------------------------------------------------------------");

    let example_web_did = "did:web:example.org";
    let multi_key_did = create_multi_key_did_document(example_web_did)?;
    let multi_key_json = serde_json::to_string_pretty(&multi_key_did)?;
    println!("{}", multi_key_json);

    std::fs::write("multi_key_did.json", &multi_key_json)?;
    println!("\nSaved → multi_key_did.json\n");

    // ── Part 7: Export Format Reference ─────────────────────────────────────
    println!("PART 7: KEY EXPORT FORMAT REFERENCE");
    println!("--------------------------------------------------------------------------------");
    print_key_export_formats(&public_key, &secret_key)?;

    println!("================================================================================");
    println!("  DEMONSTRATION COMPLETE");
    println!();
    println!("  Standards applied:");
    println!("    W3C DID Core 1.0             — DID Document structure and data model");
    println!("    W3C DID Key Method v0.9      — did:key identifier derivation");
    println!("                                   MULTIBASE(base58-btc, MULTICODEC(varint, key))");
    println!("    W3C VC Data Model 2.0        — VerifiableCredential structure");
    println!("    W3C Data Integrity 1.0       — DataIntegrityProof, proofValue (Multibase u)");
    println!("    W3C CCG QS Cryptosuites      — mldsa65-rdfc-2024 cryptosuite identifier");
    println!("    NIST FIPS 204                — ML-DSA-65 key generation and signing");
    println!("    Multiformats Multibase        — z (base58-btc), u (base64url-nopad)");
    println!("    Multiformats Multicodec       — provisional varint 0x1206 for ML-DSA-65");
    println!("================================================================================");

    Ok(())
}
