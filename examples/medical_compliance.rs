//! Sirraya Medical Compliance Engine
//! Enterprise Healthcare Cryptographic Compliance Platform
//! HIPAA · GDPR · HITECH · 21 CFR Part 11

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(elided_lifetimes_in_paths)]

use dilithium5::Dilithium5;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng}
};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicU64, Ordering}};
use regex::Regex;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// CONSTANTS
// ============================================================================

const PUBLICKEYBYTES: usize = dilithium5::constants::PUBLICKEYBYTES;
const SECRETKEYBYTES: usize = dilithium5::constants::SECRETKEYBYTES;
const SIGNBYTES: usize = dilithium5::constants::SIGNBYTES;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEY_ROTATION_DAYS: i64 = 90;

// ============================================================================
// SECTION 1: DILITHIUM5 WRAPPER
// ============================================================================

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    #[zeroize(skip)]
    pub bytes: [u8; SECRETKEYBYTES],
}

impl Serialize for DilithiumSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for DilithiumSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyVisitor;
        
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = DilithiumSecretKey;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "{} bytes", SECRETKEYBYTES)
            }
            
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != SECRETKEYBYTES {
                    return Err(E::custom(format!("expected {} bytes, got {}", SECRETKEYBYTES, v.len())));
                }
                let mut bytes = [0u8; SECRETKEYBYTES];
                bytes.copy_from_slice(v);
                Ok(DilithiumSecretKey { bytes })
            }
        }
        
        deserializer.deserialize_bytes(KeyVisitor)
    }
}

#[derive(Clone)]
pub struct DilithiumPublicKey {
    pub bytes: [u8; PUBLICKEYBYTES],
}

impl Serialize for DilithiumPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for DilithiumPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyVisitor;
        
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = DilithiumPublicKey;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "{} bytes", PUBLICKEYBYTES)
            }
            
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != PUBLICKEYBYTES {
                    return Err(E::custom(format!("expected {} bytes, got {}", PUBLICKEYBYTES, v.len())));
                }
                let mut bytes = [0u8; PUBLICKEYBYTES];
                bytes.copy_from_slice(v);
                Ok(DilithiumPublicKey { bytes })
            }
        }
        
        deserializer.deserialize_bytes(KeyVisitor)
    }
}

#[derive(Clone)]
pub struct DilithiumSignature {
    pub bytes: [u8; SIGNBYTES],
}

impl Serialize for DilithiumSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for DilithiumSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;
        
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = DilithiumSignature;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "{} bytes", SIGNBYTES)
            }
            
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != SIGNBYTES {
                    return Err(E::custom(format!("expected {} bytes, got {}", SIGNBYTES, v.len())));
                }
                let mut bytes = [0u8; SIGNBYTES];
                bytes.copy_from_slice(v);
                Ok(DilithiumSignature { bytes })
            }
        }
        
        deserializer.deserialize_bytes(SigVisitor)
    }
}

// ============================================================================
// SECTION 2: ENCRYPTION KEY MANAGEMENT
// ============================================================================

#[derive(Clone)]
pub struct EncryptionKey {
    pub key_id: String,
    pub aes_key: Vec<u8>,
    pub dilithium_pk: DilithiumPublicKey,
    pub dilithium_sk: DilithiumSecretKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub version: u32,
}

impl Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EncryptionKey", 6)?;
        state.serialize_field("key_id", &self.key_id)?;
        state.serialize_field("aes_key", &base64_serialize(&self.aes_key))?;
        state.serialize_field("dilithium_pk", &self.dilithium_pk)?;
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("expires_at", &self.expires_at)?;
        state.serialize_field("version", &self.version)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct EncryptionKeyData {
            key_id: String,
            aes_key: String,
            dilithium_pk: DilithiumPublicKey,
            created_at: u64,
            expires_at: u64,
            version: u32,
        }

        let data = EncryptionKeyData::deserialize(deserializer)?;
        
        let aes_key = base64_deserialize(&data.aes_key)
            .map_err(serde::de::Error::custom)?;
        
        Ok(EncryptionKey {
            key_id: data.key_id,
            aes_key,
            dilithium_pk: data.dilithium_pk,
            dilithium_sk: DilithiumSecretKey { bytes: [0u8; SECRETKEYBYTES] },
            created_at: data.created_at,
            expires_at: data.expires_at,
            version: data.version,
        })
    }
}

impl ZeroizeOnDrop for EncryptionKey {}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.aes_key.zeroize();
    }
}

// Simple base64 helper functions (not serialization traits)
fn base64_serialize(bytes: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    STANDARD.encode(bytes)
}

fn base64_deserialize(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    STANDARD.decode(s)
}

pub struct KeyManager {
    active_key: Arc<RwLock<EncryptionKey>>,
}

impl KeyManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let initial_key = Self::generate_key()?;
        Ok(Self {
            active_key: Arc::new(RwLock::new(initial_key)),
        })
    }

    fn generate_key() -> Result<EncryptionKey, Box<dyn std::error::Error>> {
        use aes_gcm::aead::rand_core::RngCore;
        
        let mut aes_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut aes_key);
        
        let (pk, sk) = Dilithium5::keypair()?;
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let mut pk_bytes = [0u8; PUBLICKEYBYTES];
        pk_bytes.copy_from_slice(&pk);
        
        let mut sk_bytes = [0u8; SECRETKEYBYTES];
        sk_bytes.copy_from_slice(&sk);
        
        Ok(EncryptionKey {
            key_id: Uuid::new_v4().to_string(),
            aes_key,
            dilithium_pk: DilithiumPublicKey { bytes: pk_bytes },
            dilithium_sk: DilithiumSecretKey { bytes: sk_bytes },
            created_at: now,
            expires_at: now + (KEY_ROTATION_DAYS as u64 * 86400),
            version: 1,
        })
    }

    pub fn get_active_key(&self) -> Result<EncryptionKey, Box<dyn std::error::Error>> {
        let read_guard = self.active_key.read().unwrap();
        Ok(read_guard.clone())
    }
}

// ============================================================================
// SECTION 3: MEDICAL RECORD DATA STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MedicalRecord {
    pub record_id: String,
    pub patient_id: String,
    pub patient_demographics: PatientDemographics,
    pub created_at: u64,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatientDemographics {
    pub full_name: String,
    pub date_of_birth: String,
    pub ssn: Option<String>,
    pub medical_record_number: String,
    pub phone_numbers: Vec<String>,
    pub email_addresses: Vec<String>,
}

// ============================================================================
// SECTION 4: PHI DETECTION
// ============================================================================

pub struct PHIDetector {
    ssn_regex: Regex,
    email_regex: Regex,
    phone_regex: Regex,
}

impl PHIDetector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")?,
            email_regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")?,
            phone_regex: Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")?,
        })
    }

    pub fn analyze_record(&self, record: &MedicalRecord) -> PHIAnalysis {
        let json = serde_json::to_string(record).unwrap_or_default();
        
        let mut findings = Vec::new();
        
        for cap in self.ssn_regex.captures_iter(&json) {
            if let Some(m) = cap.get(0) {
                findings.push(PHIFinding {
                    category: "SSN".into(),
                    value: m.as_str().to_string(),
                });
            }
        }
        
        for cap in self.email_regex.captures_iter(&json) {
            if let Some(m) = cap.get(0) {
                findings.push(PHIFinding {
                    category: "EMAIL".into(),
                    value: m.as_str().to_string(),
                });
            }
        }
        
        for cap in self.phone_regex.captures_iter(&json) {
            if let Some(m) = cap.get(0) {
                findings.push(PHIFinding {
                    category: "PHONE".into(),
                    value: m.as_str().to_string(),
                });
            }
        }
        
        PHIAnalysis {
            record_id: record.record_id.clone(),
            total_findings: findings.len(),
            findings,
        }
    }
}

pub struct PHIAnalysis {
    pub record_id: String,
    pub total_findings: usize,
    pub findings: Vec<PHIFinding>,
}

pub struct PHIFinding {
    pub category: String,
    pub value: String,
}

// ============================================================================
// SECTION 5: ENCRYPTED MEDICAL RECORD
// ============================================================================

mod base64_serde {
    use serde::{Serializer, Deserializer, Deserialize};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMedicalRecord {
    pub record_id: String,
    #[serde(with = "base64_serde")]
    pub encrypted_payload: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    pub key_id: String,
    pub key_version: u32,
    pub signature: DilithiumSignature,
    pub encrypted_at: u64,
}

pub struct EncryptionOrchestrator {
    key_manager: Arc<KeyManager>,
}

impl EncryptionOrchestrator {
    pub fn new(key_manager: Arc<KeyManager>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self { key_manager })
    }

    pub fn encrypt_record(&self, record: &MedicalRecord, _analysis: &PHIAnalysis) -> Result<EncryptedMedicalRecord, Box<dyn std::error::Error>> {
        let key = self.key_manager.get_active_key()?;
        
        let key_array: &[u8; 32] = key.aes_key.as_slice().try_into()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_array));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let record_bytes = serde_json::to_vec(record)?;
        let ciphertext = cipher.encrypt(&nonce, record_bytes.as_ref())
            .map_err(|e| format!("AES encryption failed: {:?}", e))?;
        
        let signature = Dilithium5::sign(&key.dilithium_sk.bytes, &ciphertext)?;
        let mut sig_bytes = [0u8; SIGNBYTES];
        sig_bytes.copy_from_slice(&signature);
        
        Ok(EncryptedMedicalRecord {
            record_id: record.record_id.clone(),
            encrypted_payload: ciphertext,
            nonce: nonce.to_vec(),
            key_id: key.key_id.clone(),
            key_version: key.version,
            signature: DilithiumSignature { bytes: sig_bytes },
            encrypted_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })
    }

    pub fn decrypt_record(&self, encrypted: &EncryptedMedicalRecord) -> Result<MedicalRecord, Box<dyn std::error::Error>> {
        let key = self.key_manager.get_active_key()?;
        
        let valid = Dilithium5::verify(
            &key.dilithium_pk.bytes, 
            &encrypted.encrypted_payload, 
            &encrypted.signature.bytes
        )?;
        
        if !valid {
            return Err("Signature verification failed".into());
        }
        
        let key_array: &[u8; 32] = key.aes_key.as_slice().try_into()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_array));
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        let plaintext = cipher.decrypt(nonce, encrypted.encrypted_payload.as_ref())
            .map_err(|e| format!("AES decryption failed: {:?}", e))?;
        
        let record: MedicalRecord = serde_json::from_slice(&plaintext)?;
        Ok(record)
    }
}

// ============================================================================
// SECTION 6: AUDIT LOGGER
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: u64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub patient_id: Option<String>,
    pub signature: DilithiumSignature,
}

pub struct AuditLogger {
    chain: Arc<RwLock<Vec<AuditEntry>>>,
}

impl AuditLogger {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            chain: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub fn log(&self, entry: AuditEntryBuilder, signing_key: &[u8; SECRETKEYBYTES]) -> Result<AuditEntry, Box<dyn std::error::Error>> {
        let mut chain = self.chain.write().unwrap();
        
        let sequence = chain.len() as u64;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let entry_data = format!("{}{}{}{}{:?}", sequence, timestamp, entry.actor, entry.action, entry.patient_id);
        let signature = Dilithium5::sign(signing_key, entry_data.as_bytes())?;
        let mut sig_bytes = [0u8; SIGNBYTES];
        sig_bytes.copy_from_slice(&signature);
        
        let audit_entry = AuditEntry {
            sequence,
            timestamp,
            actor: entry.actor,
            action: entry.action,
            resource: entry.resource,
            patient_id: entry.patient_id,
            signature: DilithiumSignature { bytes: sig_bytes },
        };
        
        chain.push(audit_entry.clone());
        Ok(audit_entry)
    }
}

pub struct AuditEntryBuilder {
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub patient_id: Option<String>,
}

impl AuditEntryBuilder {
    pub fn new(actor: String, action: String, resource: String) -> Self {
        Self {
            actor,
            action,
            resource,
            patient_id: None,
        }
    }

    pub fn with_patient_id(mut self, patient_id: String) -> Self {
        self.patient_id = Some(patient_id);
        self
    }
}

// ============================================================================
// SECTION 7: BREACH DETECTOR
// ============================================================================

#[derive(Clone)]
pub struct BreachAlert {
    pub alert_id: String,
    pub timestamp: u64,
    pub severity: u8,
    pub rule: String,
    pub patient_ids: Vec<String>,
}

pub struct BreachDetector {
    _alerts: Arc<Mutex<VecDeque<BreachAlert>>>,
}

impl BreachDetector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            _alerts: Arc::new(Mutex::new(VecDeque::new())),
        })
    }
}

// ============================================================================
// SECTION 8: MAIN COMPLIANCE ENGINE
// ============================================================================

pub struct MedicalComplianceEngine {
    key_manager: Arc<KeyManager>,
    phi_detector: Arc<PHIDetector>,
    encryption_orchestrator: Arc<EncryptionOrchestrator>,
    audit_logger: Arc<AuditLogger>,
    _breach_detector: Arc<BreachDetector>,
    records_processed: AtomicU64,
}

impl MedicalComplianceEngine {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("\nSIRRAYA MEDICAL COMPLIANCE ENGINE v{}", VERSION);
        println!("HIPAA · GDPR · HITECH · 21 CFR Part 11");
        println!("{}", "=".repeat(60));
        
        let key_manager = Arc::new(KeyManager::new()?);
        let phi_detector = Arc::new(PHIDetector::new()?);
        let encryption_orchestrator = Arc::new(EncryptionOrchestrator::new(key_manager.clone())?);
        let audit_logger = Arc::new(AuditLogger::new()?);
        let breach_detector = Arc::new(BreachDetector::new()?);
        
        Ok(Self {
            key_manager,
            phi_detector,
            encryption_orchestrator,
            audit_logger,
            _breach_detector: breach_detector,
            records_processed: AtomicU64::new(0),
        })
    }

    pub fn process_record(&self, record: MedicalRecord) -> Result<EncryptedMedicalRecord, Box<dyn std::error::Error>> {
        self.records_processed.fetch_add(1, Ordering::Relaxed);
        
        let analysis = self.phi_detector.analyze_record(&record);
        
        if analysis.total_findings > 0 {
            println!("  PHI detected: {} instances", analysis.total_findings);
        }
        
        let encrypted = self.encryption_orchestrator.encrypt_record(&record, &analysis)?;
        
        let key = self.key_manager.get_active_key()?;
        let audit_entry = AuditEntryBuilder::new(
            record.created_by.clone(),
            "ENCRYPT".into(),
            record.record_id.clone(),
        ).with_patient_id(record.patient_id.clone());
        
        let _ = self.audit_logger.log(audit_entry, &key.dilithium_sk.bytes)?;
        
        Ok(encrypted)
    }

    pub fn get_metrics(&self) -> Value {
        json!({
            "version": VERSION,
            "records_processed": self.records_processed.load(Ordering::Relaxed),
        })
    }
}

// ============================================================================
// SECTION 9: TEST DATA
// ============================================================================

fn create_test_record() -> MedicalRecord {
    MedicalRecord {
        record_id: Uuid::new_v4().to_string(),
        patient_id: "P-12345".into(),
        patient_demographics: PatientDemographics {
            full_name: "John Smith".into(),
            date_of_birth: "1975-03-15".into(),
            ssn: Some("123-45-6789".into()),
            medical_record_number: "MRN-987654".into(),
            phone_numbers: vec!["617-555-0123".into()],
            email_addresses: vec!["john.smith@email.com".into()],
        },
        created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        created_by: "nurse.smith@hospital.org".into(),
    }
}

// ============================================================================
// SECTION 10: MAIN
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=".repeat(60));
    println!("SIRRAYA MEDICAL COMPLIANCE ENGINE");
    println!("Enterprise Healthcare Cryptographic Compliance Platform");
    println!("{}", "=".repeat(60));
    
    let engine = MedicalComplianceEngine::new()?;
    
    let test_record = create_test_record();
    println!("\nProcessing record: {}", test_record.record_id);
    
    let encrypted = engine.process_record(test_record)?;
    println!("  Encrypted: {} bytes", encrypted.encrypted_payload.len());
    println!("  Key version: {}", encrypted.key_version);
    println!("  Signature: {} bytes", encrypted.signature.bytes.len());
    
    let metrics = engine.get_metrics();
    println!("\nSystem Metrics:");
    println!("  Records processed: {}", metrics["records_processed"]);
    
    println!("\n{}", "=".repeat(60));
    println!("Medical Compliance Engine operational");
    println!("{}", "=".repeat(60));
    
    Ok(())
}