// examples/issue_degree_vc.rs
// Professional Verifiable Credential Issuer - ML-DSA-65
// W3C-Compliant Degree Certificate Generation
//
// SIRRAYA LABS - Cryptographic Systems Division
// Educational Credential Issuance System

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use chrono::Utc;
use ml_dsa_65::{MlDsa65, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use serde_json::{json, Value};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::fs;
use std::time::SystemTime;

// ============================================================================
// Constants
// ============================================================================

const MULTIBASE_BASE64URL_PREFIX: char = 'u';
const MULTICODEC_MLDSA65: u16 = 0x1305;

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SIRRAYA LABS - Educational Credential Issuance System");
    println!("ML-DSA-65 W3C Verifiable Credential Generator\n");

    // Generate issuer keypair
    println!("[1/6] Generating ML-DSA-65 keypair for issuer...");
    let (issuer_public_key, issuer_secret_key) = MlDsa65::keypair()?;
    println!("  ✓ Keypair generated successfully");

    // Create issuer DID
    println!("\n[2/6] Creating issuer DID...");
    let issuer_did = create_did_key(&issuer_public_key);
    println!("  ✓ Issuer DID: {}", truncate_did(&issuer_did));

    // Save issuer keys securely
    println!("\n[3/6] Securing issuer keys...");
    save_issuer_keys(&issuer_public_key, &issuer_secret_key, &issuer_did)?;
    println!("  ✓ Keys saved to issuer_keys/ directory");

    // Create the degree credential
    println!("\n[4/6] Constructing degree credential...");
    let credential = create_degree_credential(&issuer_did);
    println!("  ✓ Credential structure created");

    // Display credential summary
    display_credential_summary(&credential);

    // Sign the credential
    println!("\n[5/6] Applying ML-DSA-65 cryptographic signature...");
    let signed_credential = sign_credential(credential, &issuer_secret_key, &issuer_did)?;
    println!("  ✓ Credential signed successfully");

    // Save the signed credential
    println!("\n[6/6] Exporting signed credential...");
    save_credential(&signed_credential)?;
    println!("  ✓ Credential saved as degree_bs_computer_science.json");

    // Generate verification summary
    let separator = "=".repeat(60);
    println!("\n{}", separator);
    println!("CREDENTIAL ISSUANCE COMPLETE");
    println!("{}", separator);
    println!(
        "Credential ID:   {}",
        signed_credential["id"].as_str().unwrap()
    );
    println!("Holder:          Amir Hameed Mir");
    println!("Degree:          Bachelor of Science in Computer Science");
    println!("Issuer:          University of Kashmir");
    println!("Issuance Date:   2019-07-15T00:00:00Z");
    println!("Cryptosuite:     mldsa65-jcs-2024");
    println!("Verification:    Ready for W3C-compliant verification");
    println!("{}", separator);

    Ok(())
}

// ============================================================================
// DID Creation
// ============================================================================

/// Creates a did:key identifier from an ML-DSA-65 public key
/// Format: did:key:z<base58btc(multicodec || publicKey)>
fn create_did_key(public_key: &[u8]) -> String {
    // Prefix with multicodec for ML-DSA-65
    let multicodec_bytes = MULTICODEC_MLDSA65.to_be_bytes();
    let mut combined = Vec::with_capacity(2 + public_key.len());
    combined.extend_from_slice(&multicodec_bytes);
    combined.extend_from_slice(public_key);

    // Encode with Base58BTC
    let encoded = bs58::encode(combined)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    format!("did:key:z{}", encoded)
}

fn truncate_did(did: &str) -> String {
    if did.len() > 60 {
        format!("{}...{}", &did[..30], &did[did.len() - 30..])
    } else {
        did.to_string()
    }
}

// ============================================================================
// Credential Creation
// ============================================================================

/// Creates a comprehensive BS Computer Science degree credential
fn create_degree_credential(issuer_did: &str) -> Value {
    let issuance_date = "2019-07-15T00:00:00Z";
    let credential_id = format!(
        "urn:uuid:degree-{}-{}",
        "bs-cs-2019",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2",
            {
                "DegreeCredential": "https://schema.org/EducationalOccupationalCredential",
                "alumniOf": "https://schema.org/alumniOf",
                "degreeType": "https://schema.org/educationalCredentialAwarded",
                "major": "https://schema.org/hasCredentialCategory",
                "gpa": "https://schema.org/gpa",
                "honors": "https://schema.org/honorificSuffix",
                "thesis": "https://schema.org/workExample"
            }
        ],
        "id": credential_id,
        "type": ["VerifiableCredential", "DegreeCredential", "UniversityDegreeCredential"],
        "issuer": {
            "id": issuer_did,
            "name": "University of Kashmir",
            "description": "University of Kashmir, Hazratbal, Srinagar, Jammu and Kashmir, India - Established 1948",
            "url": "https://www.kashmiruniversity.net",
            "accreditation": "NAAC Grade A+"
        },
        "issuanceDate": issuance_date,
        "validFrom": issuance_date,
        "expirationDate": null,
        "credentialSubject": {
            "id": "did:example:amir-hameed-mir-2019",
            "type": "Person",
            "name": {
                "fullName": "Amir Hameed Mir",
                "firstName": "Amir",
                "middleName": "Hameed",
                "lastName": "Mir"
            },
            "identifier": [
                {
                    "type": "StudentID",
                    "value": "KU-CS-2015-0892",
                    "issuer": "University of Kashmir"
                },
                {
                    "type": "RollNumber",
                    "value": "15-CS-0892",
                    "issuer": "Department of Computer Science"
                }
            ],
            "contact": {
                "email": "amir.mir@alumni.kashmiruniversity.net",
                "permanentAddress": {
                    "street": "Naseem Bagh, Hazratbal",
                    "locality": "Srinagar",
                    "region": "Jammu and Kashmir",
                    "postalCode": "190006",
                    "country": "India"
                }
            },
            "alumniOf": {
                "id": "https://www.kashmiruniversity.net",
                "name": "University of Kashmir",
                "department": "Department of Computer Science"
            },
            "degreeType": {
                "name": "Bachelor of Science",
                "abbreviation": "BS",
                "qualificationLevel": "Level 6",
                "framework": "National Skills Qualification Framework (NSQF)"
            },
            "major": {
                "name": "Computer Science",
                "specialization": "Software Engineering and Distributed Systems"
            },
            "awardDate": "2019-07-15",
            "graduationYear": 2019,
            "academicStanding": "First Class with Distinction",
            "gpa": {
                "value": 8.74,
                "scale": 10.0,
                "system": "CGPA"
            },
            "percentage": 87.4,
            "honors": [
                "Dean's List - Academic Excellence (2017-2018)",
                "Best Final Year Project Award - Department of Computer Science",
                "Merit Scholarship - J&K State Government (2016-2019)"
            ],
            "thesis": {
                "title": "Blockchain-Based Decentralized Identity Management System for Educational Credentials",
                "supervisor": "Prof. Riyaz Ahmad Shah",
                "abstract": "Designed and implemented a self-sovereign identity framework using distributed ledger technology for secure, verifiable educational credential management.",
                "grade": "A+",
                "recognition": "Published in University Research Journal, Volume 12"
            },
            "coursework": {
                "coreCourses": [
                    "Data Structures and Algorithms",
                    "Database Management Systems",
                    "Operating Systems",
                    "Computer Networks",
                    "Software Engineering",
                    "Theory of Computation",
                    "Compiler Design",
                    "Artificial Intelligence",
                    "Machine Learning Fundamentals",
                    "Distributed Systems",
                    "Cryptography and Network Security"
                ],
                "electives": [
                    "Blockchain Technology",
                    "Cloud Computing",
                    "Mobile Application Development",
                    "Web Technologies"
                ]
            },
            "skills": [
                "Programming Languages: C, C++, Java, Python, JavaScript",
                "Web Technologies: HTML5, CSS3, React, Node.js",
                "Database: MySQL, PostgreSQL, MongoDB",
                "Blockchain: Ethereum, Solidity, Web3.js",
                "Tools: Git, Docker, Jenkins, AWS"
            ],
            "projects": [
                {
                    "name": "Decentralized Identity Platform",
                    "description": "Self-sovereign identity solution for educational institutions",
                    "technologies": ["Blockchain", "React", "Node.js", "IPFS"],
                    "duration": "January 2019 - May 2019"
                }
            ],
            "internships": [
                {
                    "organization": "J&K e-Governance Agency (JaKeGA)",
                    "role": "Software Development Intern",
                    "duration": "June 2018 - August 2018",
                    "project": "Digitization of Land Records System"
                }
            ],
            "languages": [
                {"language": "English", "proficiency": "Professional Working"},
                {"language": "Urdu", "proficiency": "Native"},
                {"language": "Kashmiri", "proficiency": "Native"},
                {"language": "Hindi", "proficiency": "Professional Working"}
            ],
            "certifications": [
                {
                    "name": "Oracle Certified Java Programmer (OCJP)",
                    "issuer": "Oracle Corporation",
                    "year": 2018
                },
                {
                    "name": "AWS Certified Cloud Practitioner",
                    "issuer": "Amazon Web Services",
                    "year": 2019
                }
            ]
        },
        "credentialSchema": {
            "id": "https://kashmiruniversity.net/schemas/degree-credential-v1.json",
            "type": "JsonSchema"
        },
        "evidence": [
            {
                "id": "https://kashmiruniversity.net/transcripts/15-CS-0892",
                "type": ["DocumentVerification", "Transcript"],
                "name": "Official Academic Transcript",
                "description": "Complete academic record for all semesters"
            }
        ],
        "termsOfUse": {
            "type": "IssuerPolicy",
            "id": "https://kashmiruniversity.net/policies/credential-terms",
            "profile": "https://www.w3.org/TR/vc-data-integrity/",
            "prohibition": ["CommercialUse", "Misrepresentation"]
        },
        "credentialStatus": {
            "id": "https://kashmiruniversity.net/credentials/status/15-CS-0892#1",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "15-CS-0892",
            "statusListCredential": "https://kashmiruniversity.net/status/degree-credentials/1"
        }
    })
}

fn display_credential_summary(credential: &Value) {
    let subject = &credential["credentialSubject"];

    println!("\n  Credential Summary:");
    println!("  +-------------------------------------------------------------");
    println!(
        "  | Student:     {} ({})",
        subject["name"]["fullName"].as_str().unwrap_or(""),
        subject["identifier"][0]["value"].as_str().unwrap_or("")
    );
    println!(
        "  | Degree:      {} in {}",
        subject["degreeType"]["name"].as_str().unwrap_or(""),
        subject["major"]["name"].as_str().unwrap_or("")
    );
    println!("  | Institution: University of Kashmir");
    println!(
        "  | Department:  {}",
        subject["alumniOf"]["department"].as_str().unwrap_or("")
    );
    println!(
        "  | Graduation:  {} (Class of {})",
        subject["awardDate"].as_str().unwrap_or(""),
        subject["graduationYear"].as_u64().unwrap_or(0)
    );
    println!(
        "  | CGPA:        {}/{} - {}",
        subject["gpa"]["value"].as_f64().unwrap_or(0.0),
        subject["gpa"]["scale"].as_f64().unwrap_or(0.0),
        subject["academicStanding"].as_str().unwrap_or("")
    );
    println!(
        "  | Honors:      {} award(s)",
        subject["honors"].as_array().unwrap_or(&vec![]).len()
    );
    println!("  +-------------------------------------------------------------");
}

// ============================================================================
// Credential Signing
// ============================================================================

/// Signs the credential using ML-DSA-65 with JCS canonicalization
fn sign_credential(
    mut credential: Value,
    secret_key: &[u8; SECRETKEYBYTES],
    issuer_did: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let now: DateTime<Utc> = Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Create proof configuration
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "mldsa65-jcs-2024",
        "created": created,
        "verificationMethod": format!("{}#{}", issuer_did, issuer_did),
        "proofPurpose": "assertionMethod",
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/undefined-terms/v2"
        ]
    });

    // Create verification message
    let unsigned_credential = credential.clone();

    let canonical_doc = jcs_canonicalize(&unsigned_credential);
    let canonical_config = jcs_canonicalize(&proof_config);

    let mut hasher = Shake256::default();
    Update::update(&mut hasher, canonical_doc.as_bytes());
    Update::update(&mut hasher, canonical_config.as_bytes());

    let mut verification_message = vec![0u8; 64];
    hasher.finalize_xof().read(&mut verification_message);

    // Sign the message
    let signature = MlDsa65::sign(secret_key, &verification_message)?;

    // Encode signature with multibase prefix
    let encoded_signature = format!(
        "{}{}",
        MULTIBASE_BASE64URL_PREFIX,
        URL_SAFE_NO_PAD.encode(&signature)
    );

    // Add proof to credential
    let mut proof = proof_config;
    proof["proofValue"] = json!(encoded_signature);

    credential["proof"] = proof;

    Ok(credential)
}

/// JCS (JSON Canonicalization Scheme) per RFC 8785
fn jcs_canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let items: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, jcs_canonicalize(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(jcs_canonicalize).collect();
            format!("[{}]", items.join(","))
        }
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
    }
}

// ============================================================================
// File Operations
// ============================================================================

fn save_issuer_keys(
    public_key: &[u8; PUBLICKEYBYTES],
    secret_key: &[u8; SECRETKEYBYTES],
    issuer_did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("issuer_keys")?;

    // Save public key
    fs::write("issuer_keys/public_key.bin", public_key)?;

    // Save secret key (encrypted in production)
    fs::write("issuer_keys/secret_key.bin", secret_key)?;

    // Save DID document
    let did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": issuer_did,
        "verificationMethod": [{
            "id": format!("{}#{}", issuer_did, issuer_did),
            "type": "Multikey",
            "controller": issuer_did,
            "publicKeyMultibase": format!("z{}", bs58::encode(public_key)
                .with_alphabet(bs58::Alphabet::BITCOIN)
                .into_string())
        }],
        "assertionMethod": [format!("{}#{}", issuer_did, issuer_did)]
    });

    fs::write(
        "issuer_keys/did.json",
        serde_json::to_string_pretty(&did_document)?,
    )?;

    // Save issuer info
    let issuer_info = json!({
        "did": issuer_did,
        "name": "University of Kashmir",
        "created": Utc::now().to_rfc3339(),
        "key_type": "ML-DSA-65",
        "cryptosuite": "mldsa65-jcs-2024",
        "security_note": "Secret key must be stored in HSM in production"
    });

    fs::write(
        "issuer_keys/issuer_info.json",
        serde_json::to_string_pretty(&issuer_info)?,
    )?;

    Ok(())
}

fn save_credential(credential: &Value) -> Result<(), Box<dyn std::error::Error>> {
    // Save as formatted JSON
    let formatted = serde_json::to_string_pretty(credential)?;
    fs::write("degree_bs_computer_science.json", &formatted)?;

    // Also save a minified version
    let minified = serde_json::to_string(credential)?;
    fs::write("degree_bs_computer_science.min.json", minified)?;

    Ok(())
}
