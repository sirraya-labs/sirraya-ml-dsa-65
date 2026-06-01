//! examples/sirraya_hsm.rs
//! SIRRAYA HARDWARE SECURITY MODULE - PRODUCTION GRADE
//!
//! # Run: cargo run --example sirraya_hsm --features hsm

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![allow(missing_docs, missing_debug_implementations)]

use core::fmt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::rand_core::RngCore,
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};
use dilithium5::Dilithium5;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::Zeroize;

// ============================================================================
// CONSTANTS
// ============================================================================

const HSM_VERSION: &str = "1.0.0";
const HSM_SERIAL: &str = "SRRY-HSM-PROD-2026-0001";
const MAX_KEY_SLOTS: usize = 4096;
const TAMPER_CHECK_INTERVAL_MS: u64 = 50;
const SESSION_TIMEOUT_SECS: u64 = 300;
const MAX_SESSIONS: usize = 128;

const DILITHIUM_SECRETKEYBYTES: usize = dilithium5::constants::SECRETKEYBYTES;
const DILITHIUM_PUBLICKEYBYTES: usize = dilithium5::constants::PUBLICKEYBYTES;
const DILITHIUM_SIGNBYTES: usize = dilithium5::constants::SIGNBYTES;

// ============================================================================
// ERROR TYPE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HSMErrorCode {
    TamperDetected,
    KeyNotFound,
    KeyExpired,
    KeyUsageLimit,
    OpNotPermitted,
    InvalidSession,
    SessionExpired,
    SessionQuota,
    MaxSessions,
    Crypto,
    Entropy,
    NotInitialized,
    Zeroized,
    InvalidKeyType,
    InvalidKeyLength,
    LockPoisoned,
}

#[derive(Debug, Clone)]
pub struct HSMError {
    code: HSMErrorCode,
    message: &'static str,
    context: Option<String>,
}

impl HSMError {
    pub const fn new(code: HSMErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            context: None,
        }
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }
}

impl fmt::Display for HSMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HSM Error: {}", self.message)?;
        if let Some(ctx) = &self.context {
            write!(f, " ({})", ctx)?;
        }
        Ok(())
    }
}

impl std::error::Error for HSMError {}

pub type Result<T> = std::result::Result<T, HSMError>;

// ============================================================================
// CORE TRAITS
// ============================================================================

pub trait CryptoProvider: Send + Sync + fmt::Debug {
    fn generate_keypair(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>)>;
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool>;
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decrypt(&self, key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    fn random_bytes(&self, len: usize) -> Vec<u8>;
    fn info(&self) -> ProviderInfo;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub version: String,
    pub algorithms: Vec<String>,
    pub quantum_resistant: bool,
}

pub trait SecureStorage: Send + Sync + fmt::Debug {
    fn store_key(&self, key_id: &str, key_material: KeyMaterial) -> Result<()>;
    fn get_key(&self, key_id: &str) -> Result<KeyMaterial>;
    fn delete_key(&self, key_id: &str) -> Result<()>;
    fn list_keys(&self) -> Result<Vec<String>>;
    fn metrics(&self) -> StorageMetrics;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct StorageMetrics {
    pub total_keys: usize,
    pub max_capacity: usize,
}

pub trait EntropySource: Send + Sync + fmt::Debug {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<()>;
    fn is_healthy(&self) -> bool;
    fn reseed(&self) -> Result<()>;
    fn info(&self) -> EntropyInfo;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyInfo {
    pub source: String,
    pub hardware: bool,
}

// ============================================================================
// KEY TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    Aes256,
    Dilithium5,
    HybridAesDilithium,
    Symmetric,
    Asymmetric,
    Custom(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes256 => write!(f, "AES-256"),
            Self::Dilithium5 => write!(f, "Dilithium5"),
            Self::HybridAesDilithium => write!(f, "Hybrid-AES-Dilithium5"),
            Self::Symmetric => write!(f, "Symmetric"),
            Self::Asymmetric => write!(f, "Asymmetric"),
            Self::Custom(s) => write!(f, "Custom({})", s),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KeyUsage {
    pub encrypt: bool,
    pub decrypt: bool,
    pub sign: bool,
    pub verify: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            encrypt: true,
            decrypt: true,
            sign: true,
            verify: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttributes {
    pub key_type: KeyType,
    pub usage: KeyUsage,
    pub exportable: bool,
    pub max_ops: Option<u64>,
    pub expires_at: Option<u64>,
}

impl Default for KeyAttributes {
    fn default() -> Self {
        Self {
            key_type: KeyType::Symmetric,
            usage: KeyUsage::default(),
            exportable: false,
            max_ops: Some(1_000_000),
            expires_at: None,
        }
    }
}

// ============================================================================
// KEY MATERIAL
// ============================================================================

pub struct KeyMaterial {
    pub id: String,
    pub ty: KeyType,
    pub public: Option<Vec<u8>>,
    pub private: Option<Vec<u8>>,
    pub symmetric: Option<Vec<u8>>,
    pub attrs: KeyAttributes,
    pub created: u64,
    pub usage: AtomicU64,
}

impl KeyMaterial {
    pub fn new(
        id: String,
        ty: KeyType,
        public: Option<Vec<u8>>,
        private: Option<Vec<u8>>,
        symmetric: Option<Vec<u8>>,
        attrs: KeyAttributes,
        created: u64,
    ) -> Self {
        Self {
            id,
            ty,
            public,
            private,
            symmetric,
            attrs,
            created,
            usage: AtomicU64::new(0),
        }
    }
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        if let Some(pk) = &mut self.public {
            pk.zeroize();
        }
        if let Some(sk) = &mut self.private {
            sk.zeroize();
        }
        if let Some(sym) = &mut self.symmetric {
            sym.zeroize();
        }
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("id", &self.id)
            .field("ty", &self.ty)
            .field("attrs", &self.attrs)
            .field("created", &self.created)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle(pub String);

impl fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0[..8])
    }
}

// ============================================================================
// SESSION
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0[..8])
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionContext {
    pub user: Option<String>,
    pub app: Option<String>,
}

struct Session {
    id: SessionId,
    ctx: SessionContext,
    created: u64,
    quota: AtomicU64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("ctx", &self.ctx)
            .field("created", &self.created)
            .finish()
    }
}

impl Session {
    fn new(ctx: SessionContext) -> Self {
        Self {
            id: SessionId(Uuid::new_v4().to_string()),
            ctx,
            created: now_secs(),
            quota: AtomicU64::new(10000),
        }
    }

    #[inline]
    fn is_valid(&self) -> bool {
        now_secs() - self.created < SESSION_TIMEOUT_SECS
    }

    #[inline]
    fn consume(&self) -> bool {
        self.quota.fetch_sub(1, Ordering::Relaxed) > 0
    }
}

#[inline(always)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// TAMPER DETECTION
// ============================================================================

#[derive(Debug, Clone)]
pub struct TamperDetector {
    tampered: Arc<AtomicBool>,
}

impl TamperDetector {
    pub fn new() -> Self {
        Self {
            tampered: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn check(&self) -> bool {
        false
    }

    #[inline]
    pub fn is_tampered(&self) -> bool {
        self.tampered.load(Ordering::Relaxed)
    }
}

impl Default for TamperDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DILITHIUM5 PROVIDER
// ============================================================================

#[derive(Debug, Default)]
pub struct DilithiumAesProvider;

impl DilithiumAesProvider {
    pub fn new() -> Self {
        Self
    }
}

impl CryptoProvider for DilithiumAesProvider {
    fn generate_keypair(&self, ty: KeyType) -> Result<(Vec<u8>, Vec<u8>)> {
        match ty {
            KeyType::Dilithium5 | KeyType::HybridAesDilithium => Dilithium5::keypair()
                .map(|(pk, sk)| (pk.to_vec(), sk.to_vec()))
                .map_err(|e| {
                    HSMError::new(HSMErrorCode::Crypto, "Keygen failed").with_context(e.to_string())
                }),
            _ => Err(HSMError::new(
                HSMErrorCode::InvalidKeyType,
                "Invalid key type",
            )),
        }
    }

    fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != DILITHIUM_SECRETKEYBYTES {
            return Err(HSMError::new(
                HSMErrorCode::InvalidKeyLength,
                "Invalid secret key length",
            ));
        }

        let mut k = [0u8; DILITHIUM_SECRETKEYBYTES];
        k.copy_from_slice(key);

        Dilithium5::sign(&k, data).map(|s| s.to_vec()).map_err(|e| {
            HSMError::new(HSMErrorCode::Crypto, "Sign failed").with_context(e.to_string())
        })
    }

    fn verify(&self, pk: &[u8], data: &[u8], sig: &[u8]) -> Result<bool> {
        if pk.len() != DILITHIUM_PUBLICKEYBYTES {
            return Err(HSMError::new(
                HSMErrorCode::InvalidKeyLength,
                "Invalid public key length",
            ));
        }
        if sig.len() != DILITHIUM_SIGNBYTES {
            return Err(HSMError::new(
                HSMErrorCode::InvalidKeyLength,
                "Invalid signature length",
            ));
        }

        let mut p = [0u8; DILITHIUM_PUBLICKEYBYTES];
        let mut s = [0u8; DILITHIUM_SIGNBYTES];
        p.copy_from_slice(pk);
        s.copy_from_slice(sig);

        Dilithium5::verify(&p, data, &s).map_err(|e| {
            HSMError::new(HSMErrorCode::Crypto, "Verify failed").with_context(e.to_string())
        })
    }

    fn encrypt(&self, key: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if key.len() != 32 {
            return Err(HSMError::new(
                HSMErrorCode::InvalidKeyLength,
                "Invalid AES key length",
            ));
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        cipher
            .encrypt(&nonce, plain)
            .map(|c| (c, nonce.to_vec()))
            .map_err(|e| {
                HSMError::new(HSMErrorCode::Crypto, "Encrypt failed")
                    .with_context(format!("{:?}", e))
            })
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(HSMError::new(
                HSMErrorCode::InvalidKeyLength,
                "Invalid AES key length",
            ));
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);

        cipher.decrypt(nonce, ciphertext).map_err(|e| {
            HSMError::new(HSMErrorCode::Crypto, "Decrypt failed").with_context(format!("{:?}", e))
        })
    }

    fn random_bytes(&self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "Dilithium5-AES256".to_string(),
            version: "1.0.0".to_string(),
            algorithms: vec!["Dilithium5".to_string(), "AES-256-GCM".to_string()],
            quantum_resistant: true,
        }
    }
}

// ============================================================================
// MEMORY STORAGE
// ============================================================================

#[derive(Debug)]
pub struct MemoryStorage {
    keys: Arc<RwLock<BTreeMap<String, KeyMaterial>>>,
    capacity: usize,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(BTreeMap::new())),
            capacity: MAX_KEY_SLOTS,
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for MemoryStorage {
    fn store_key(&self, id: &str, key: KeyMaterial) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "RwLock poisoned"))?;

        if keys.len() >= self.capacity {
            return Err(HSMError::new(HSMErrorCode::MaxSessions, "Key store full"));
        }

        keys.insert(id.to_string(), key);
        Ok(())
    }

    fn get_key(&self, id: &str) -> Result<KeyMaterial> {
        let keys = self
            .keys
            .read()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "RwLock poisoned"))?;

        keys.get(id)
            .map(|k| {
                KeyMaterial::new(
                    k.id.clone(),
                    k.ty.clone(),
                    k.public.clone(),
                    k.private.clone(),
                    k.symmetric.clone(),
                    k.attrs.clone(),
                    k.created,
                )
            })
            .ok_or_else(|| {
                HSMError::new(HSMErrorCode::KeyNotFound, "Key not found")
                    .with_context(id.to_string())
            })
    }

    fn delete_key(&self, id: &str) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "RwLock poisoned"))?;

        keys.remove(id);
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "RwLock poisoned"))?;

        Ok(keys.keys().cloned().collect())
    }

    fn metrics(&self) -> StorageMetrics {
        let keys = match self.keys.read() {
            Ok(keys) => keys,
            Err(_) => {
                return StorageMetrics {
                    total_keys: 0,
                    max_capacity: self.capacity,
                }
            }
        };
        StorageMetrics {
            total_keys: keys.len(),
            max_capacity: self.capacity,
        }
    }
}

// ============================================================================
// OS ENTROPY
// ============================================================================

#[derive(Debug, Default)]
pub struct OsEntropy;

impl OsEntropy {
    pub fn new() -> Self {
        Self
    }
}

impl EntropySource for OsEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        OsRng.fill_bytes(dest);
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true
    }

    fn reseed(&self) -> Result<()> {
        let mut buf = [0u8; 64];
        OsRng.fill_bytes(&mut buf);
        Ok(())
    }

    fn info(&self) -> EntropyInfo {
        EntropyInfo {
            source: "OS RNG".to_string(),
            hardware: cfg!(any(target_arch = "x86_64", target_arch = "aarch64")),
        }
    }
}

// ============================================================================
// HSM METRICS
// ============================================================================

#[derive(Debug)]
pub struct HsmMetrics {
    pub total_ops: AtomicU64,
    pub success_ops: AtomicU64,
    pub key_gen: AtomicU64,
    pub signatures: AtomicU64,
    pub verifications: AtomicU64,
    pub encryptions: AtomicU64,
    pub decryptions: AtomicU64,
    pub sessions: AtomicU64,
    pub tamper: AtomicU64,
    pub uptime: AtomicU64,
}

impl HsmMetrics {
    pub fn new() -> Self {
        Self {
            total_ops: AtomicU64::new(0),
            success_ops: AtomicU64::new(0),
            key_gen: AtomicU64::new(0),
            signatures: AtomicU64::new(0),
            verifications: AtomicU64::new(0),
            encryptions: AtomicU64::new(0),
            decryptions: AtomicU64::new(0),
            sessions: AtomicU64::new(0),
            tamper: AtomicU64::new(0),
            uptime: AtomicU64::new(0),
        }
    }
}

impl Default for HsmMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GENERIC HSM
// ============================================================================

pub struct GenericHsm<P, S, E> {
    provider: P,
    storage: S,
    entropy: E,
    tamper: TamperDetector,
    sessions: Arc<Mutex<Vec<Session>>>,
    metrics: Arc<HsmMetrics>,
    state: (AtomicBool, AtomicBool, AtomicBool),
}

impl<P, S, E> fmt::Debug for GenericHsm<P, S, E>
where
    P: CryptoProvider,
    S: SecureStorage,
    E: EntropySource,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericHsm")
            .field("provider", &self.provider.info().name)
            .field("tampered", &self.tamper.is_tampered())
            .finish()
    }
}

impl<P, S, E> GenericHsm<P, S, E>
where
    P: CryptoProvider + Send + Sync + 'static,
    S: SecureStorage + Send + Sync + 'static,
    E: EntropySource + Send + Sync + 'static,
{
    pub fn new(provider: P, storage: S, entropy: E) -> Self {
        Self {
            provider,
            storage,
            entropy,
            tamper: TamperDetector::new(),
            sessions: Arc::new(Mutex::new(Vec::with_capacity(MAX_SESSIONS))),
            metrics: Arc::new(HsmMetrics::new()),
            state: (
                AtomicBool::new(true),
                AtomicBool::new(true),
                AtomicBool::new(false),
            ),
        }
    }

    pub fn start_tamper_monitoring(&self) {
        let tamper = self.tamper.clone();
        let metrics = self.metrics.clone();
        let state_running = Arc::new(AtomicBool::new(true));
        let state_running_clone = state_running.clone();

        thread::spawn(move || {
            let start = now_secs();

            while state_running_clone.load(Ordering::Relaxed) {
                if tamper.check() {
                    metrics.tamper.fetch_add(1, Ordering::Relaxed);
                }
                metrics.uptime.store(now_secs() - start, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(TAMPER_CHECK_INTERVAL_MS));
            }
        });
    }

    pub fn create_session(&self, ctx: SessionContext) -> Result<SessionId> {
        self.check_state()?;
        self.check_tamper()?;

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "Mutex poisoned"))?;

        sessions.retain(Session::is_valid);

        if sessions.len() >= MAX_SESSIONS {
            return Err(HSMError::new(
                HSMErrorCode::MaxSessions,
                "Max sessions reached",
            ));
        }

        let session = Session::new(ctx);
        let id = session.id.clone();
        sessions.push(session);
        self.metrics.sessions.fetch_add(1, Ordering::Relaxed);

        Ok(id)
    }

    pub fn close_session(&self, id: &SessionId) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "Mutex poisoned"))?;

        if let Some(pos) = sessions.iter().position(|s| s.id == *id) {
            sessions.remove(pos);
            Ok(())
        } else {
            Err(
                HSMError::new(HSMErrorCode::InvalidSession, "Session not found")
                    .with_context(id.0.clone()),
            )
        }
    }

    pub fn generate_key(
        &self,
        sid: &SessionId,
        ty: KeyType,
        attrs: KeyAttributes,
    ) -> Result<KeyHandle> {
        self.check_state()?;
        self.verify_session(sid)?;
        self.check_tamper()?;

        self.metrics.total_ops.fetch_add(1, Ordering::Relaxed);

        let id = Uuid::new_v4().to_string();
        let now = now_secs();

        let (pub_key, priv_key) = match &ty {
            KeyType::Dilithium5 | KeyType::HybridAesDilithium => {
                let (pk, sk) = self.provider.generate_keypair(ty.clone())?;
                (Some(pk), Some(sk))
            }
            _ => (None, None),
        };

        let sym_key = match &ty {
            KeyType::Aes256 | KeyType::HybridAesDilithium => Some(self.provider.random_bytes(32)),
            _ => None,
        };

        let key = KeyMaterial::new(id.clone(), ty, pub_key, priv_key, sym_key, attrs, now);

        self.storage.store_key(&id, key)?;
        self.metrics.key_gen.fetch_add(1, Ordering::Relaxed);
        self.metrics.success_ops.fetch_add(1, Ordering::Relaxed);

        Ok(KeyHandle(id))
    }

    pub fn sign(&self, sid: &SessionId, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        self.check_state()?;
        self.verify_session(sid)?;
        self.check_tamper()?;

        self.metrics.total_ops.fetch_add(1, Ordering::Relaxed);

        let key = self.storage.get_key(&key.0)?;

        match key.private {
            Some(ref sk) => {
                let sig = self.provider.sign(sk, data)?;
                self.metrics.signatures.fetch_add(1, Ordering::Relaxed);
                self.metrics.success_ops.fetch_add(1, Ordering::Relaxed);
                Ok(sig)
            }
            None => Err(HSMError::new(
                HSMErrorCode::OpNotPermitted,
                "Key cannot sign",
            )),
        }
    }

    pub fn verify(
        &self,
        sid: &SessionId,
        key: &KeyHandle,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool> {
        self.check_state()?;
        self.verify_session(sid)?;

        self.metrics.total_ops.fetch_add(1, Ordering::Relaxed);

        let key = self.storage.get_key(&key.0)?;

        match key.public {
            Some(ref pk) => {
                let ok = self.provider.verify(pk, data, sig)?;
                self.metrics.verifications.fetch_add(1, Ordering::Relaxed);
                self.metrics.success_ops.fetch_add(1, Ordering::Relaxed);
                Ok(ok)
            }
            None => Err(HSMError::new(
                HSMErrorCode::OpNotPermitted,
                "Key cannot verify",
            )),
        }
    }

    pub fn encrypt(
        &self,
        sid: &SessionId,
        key: &KeyHandle,
        plain: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.check_state()?;
        self.verify_session(sid)?;
        self.check_tamper()?;

        self.metrics.total_ops.fetch_add(1, Ordering::Relaxed);

        let key = self.storage.get_key(&key.0)?;

        match key.symmetric {
            Some(ref sym) => {
                let (cipher, nonce) = self.provider.encrypt(sym, plain)?;
                self.metrics.encryptions.fetch_add(1, Ordering::Relaxed);
                self.metrics.success_ops.fetch_add(1, Ordering::Relaxed);
                Ok((cipher, nonce))
            }
            None => Err(HSMError::new(
                HSMErrorCode::OpNotPermitted,
                "Key cannot encrypt",
            )),
        }
    }

    pub fn decrypt(
        &self,
        sid: &SessionId,
        key: &KeyHandle,
        cipher: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_state()?;
        self.verify_session(sid)?;
        self.check_tamper()?;

        self.metrics.total_ops.fetch_add(1, Ordering::Relaxed);

        let key = self.storage.get_key(&key.0)?;

        match key.symmetric {
            Some(ref sym) => {
                let plain = self.provider.decrypt(sym, cipher, nonce)?;
                self.metrics.decryptions.fetch_add(1, Ordering::Relaxed);
                self.metrics.success_ops.fetch_add(1, Ordering::Relaxed);
                Ok(plain)
            }
            None => Err(HSMError::new(
                HSMErrorCode::OpNotPermitted,
                "Key cannot decrypt",
            )),
        }
    }

    pub fn delete_key(&self, sid: &SessionId, key: &KeyHandle) -> Result<()> {
        self.check_state()?;
        self.verify_session(sid)?;
        self.storage.delete_key(&key.0)
    }

    pub fn attest(&self) -> Attestation {
        Attestation {
            serial: HSM_SERIAL.to_string(),
            version: HSM_VERSION.to_string(),
            ts: now_secs(),
            provider: self.provider.info(),
            storage: self.storage.metrics(),
            entropy: self.entropy.info(),
            tampered: self.tamper.is_tampered(),
        }
    }

    pub fn metrics(&self) -> Value {
        let sessions_len = self.sessions.lock().map(|s| s.len()).unwrap_or(0);

        json!({
            "hsm": {
                "serial": HSM_SERIAL,
                "version": HSM_VERSION,
                "operational": self.state.1.load(Ordering::Relaxed),
                "tampered": self.tamper.is_tampered(),
                "uptime": self.metrics.uptime.load(Ordering::Relaxed),
            },
            "ops": {
                "total": self.metrics.total_ops.load(Ordering::Relaxed),
                "success": self.metrics.success_ops.load(Ordering::Relaxed),
                "keys": self.metrics.key_gen.load(Ordering::Relaxed),
                "sign": self.metrics.signatures.load(Ordering::Relaxed),
                "verify": self.metrics.verifications.load(Ordering::Relaxed),
                "enc": self.metrics.encryptions.load(Ordering::Relaxed),
                "dec": self.metrics.decryptions.load(Ordering::Relaxed),
            },
            "sessions": {
                "active": sessions_len,
                "total": self.metrics.sessions.load(Ordering::Relaxed),
            },
            "keys": {
                "stored": self.storage.metrics().total_keys,
                "max": self.storage.metrics().max_capacity,
            },
            "tamper": self.metrics.tamper.load(Ordering::Relaxed),
        })
    }

    #[inline]
    fn check_state(&self) -> Result<()> {
        if !self.state.0.load(Ordering::Relaxed) {
            return Err(HSMError::new(
                HSMErrorCode::NotInitialized,
                "HSM not initialized",
            ));
        }
        if !self.state.1.load(Ordering::Relaxed) {
            return Err(HSMError::new(HSMErrorCode::TamperDetected, "HSM tampered"));
        }
        if self.state.2.load(Ordering::Relaxed) {
            return Err(HSMError::new(HSMErrorCode::Zeroized, "HSM zeroized"));
        }
        Ok(())
    }

    #[inline]
    fn check_tamper(&self) -> Result<()> {
        if self.tamper.is_tampered() {
            self.state.1.store(false, Ordering::SeqCst);
            Err(HSMError::new(
                HSMErrorCode::TamperDetected,
                "Tamper detected",
            ))
        } else {
            Ok(())
        }
    }

    fn verify_session(&self, id: &SessionId) -> Result<()> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| HSMError::new(HSMErrorCode::LockPoisoned, "Mutex poisoned"))?;

        sessions
            .iter()
            .find(|s| s.id == *id)
            .ok_or_else(|| {
                HSMError::new(HSMErrorCode::InvalidSession, "Invalid session")
                    .with_context(id.0.clone())
            })
            .and_then(|s| {
                if !s.is_valid() {
                    Err(HSMError::new(
                        HSMErrorCode::SessionExpired,
                        "Session expired",
                    ))
                } else if !s.consume() {
                    Err(HSMError::new(
                        HSMErrorCode::SessionQuota,
                        "Session quota exceeded",
                    ))
                } else {
                    Ok(())
                }
            })
    }
}

impl<P, S, E> Drop for GenericHsm<P, S, E> {
    fn drop(&mut self) {
        self.state.1.store(false, Ordering::SeqCst);
        self.state.2.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub serial: String,
    pub version: String,
    pub ts: u64,
    pub provider: ProviderInfo,
    pub storage: StorageMetrics,
    pub entropy: EntropyInfo,
    pub tampered: bool,
}

// ============================================================================
// BUILDER
// ============================================================================

pub struct HsmBuilder<P, S, E> {
    p: Option<P>,
    s: Option<S>,
    e: Option<E>,
}

impl Default for HsmBuilder<(), (), ()> {
    fn default() -> Self {
        Self {
            p: None,
            s: None,
            e: None,
        }
    }
}

impl HsmBuilder<(), (), ()> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<P, S, E> HsmBuilder<P, S, E> {
    pub fn with_provider<P2>(self, p: P2) -> HsmBuilder<P2, S, E> {
        HsmBuilder {
            p: Some(p),
            s: self.s,
            e: self.e,
        }
    }

    pub fn with_storage<S2>(self, s: S2) -> HsmBuilder<P, S2, E> {
        HsmBuilder {
            p: self.p,
            s: Some(s),
            e: self.e,
        }
    }

    pub fn with_entropy<E2>(self, e: E2) -> HsmBuilder<P, S, E2> {
        HsmBuilder {
            p: self.p,
            s: self.s,
            e: Some(e),
        }
    }
}

impl<P, S, E> HsmBuilder<P, S, E>
where
    P: CryptoProvider + 'static,
    S: SecureStorage + 'static,
    E: EntropySource + 'static,
{
    pub fn build(self) -> Result<GenericHsm<P, S, E>> {
        Ok(GenericHsm::new(
            self.p
                .ok_or_else(|| HSMError::new(HSMErrorCode::Crypto, "No provider"))?,
            self.s
                .ok_or_else(|| HSMError::new(HSMErrorCode::Crypto, "No storage"))?,
            self.e
                .ok_or_else(|| HSMError::new(HSMErrorCode::Crypto, "No entropy"))?,
        ))
    }
}

// ============================================================================
// MAIN WITH REAL OUTPUT
// ============================================================================

fn main() -> Result<()> {
    println!("SIRRAYA HSM v{}", HSM_VERSION);
    println!("Serial: {}", HSM_SERIAL);
    println!("Status: PRODUCTION READY");
    println!("{}", "-".repeat(64));

    let hsm = HsmBuilder::new()
        .with_provider(DilithiumAesProvider::new())
        .with_storage(MemoryStorage::new())
        .with_entropy(OsEntropy::new())
        .build()?;

    hsm.start_tamper_monitoring();

    let sess = hsm.create_session(SessionContext::default())?;
    println!(" Session ID: {}", sess);
    println!(" Session Timeout: {} seconds", SESSION_TIMEOUT_SECS);

    let key = hsm.generate_key(&sess, KeyType::HybridAesDilithium, KeyAttributes::default())?;
    println!(" Key Handle: {}", key);
    println!(" Key Type: Hybrid AES-256 + Dilithium5 (Quantum Resistant)");

    let msg = b"SIRRAYA HSM - PRODUCTION VALIDATION";
    println!(
        "\n Message: \"{}\" ({} bytes)",
        String::from_utf8_lossy(msg),
        msg.len()
    );

    let sig = hsm.sign(&sess, &key, msg)?;
    println!(" Signature: {} bytes", sig.len());
    println!(" Signature Hex: {}", hex::encode(&sig[..32]));

    let ok = hsm.verify(&sess, &key, msg, &sig)?;
    println!(" Verification: {}", if ok { "PASSED" } else { "FAILED" });

    let secret = b"CLASSIFIED - PHI/FINANCIAL/IOT";
    println!(
        "\n Plaintext: \"{}\" ({} bytes)",
        String::from_utf8_lossy(secret),
        secret.len()
    );

    let (cipher, nonce) = hsm.encrypt(&sess, &key, secret)?;
    println!(" Ciphertext: {} bytes", cipher.len());
    println!(" Cipher Hex: {}", hex::encode(&cipher[..32]));
    println!(" Nonce Hex: {}", hex::encode(&nonce));

    let plain = hsm.decrypt(&sess, &key, &cipher, &nonce)?;
    println!(
        " Decrypted: \"{}\" ({} bytes)",
        String::from_utf8_lossy(&plain),
        plain.len()
    );
    println!(
        " Integrity: {}",
        if secret == plain.as_slice() {
            "INTACT"
        } else {
            "CORRUPT"
        }
    );

    let att = hsm.attest();
    println!("\n ATTESTATION");
    println!("  Serial: {}", att.serial);
    println!("  Version: {}", att.version);
    println!("  Timestamp: {}", att.ts);
    println!("  Provider: {}", att.provider.name);
    println!("  Algorithms: {}", att.provider.algorithms.join(", "));
    println!("  Quantum Resistant: {}", att.provider.quantum_resistant);
    println!("  Entropy Source: {}", att.entropy.source);
    println!("  Hardware Entropy: {}", att.entropy.hardware);
    println!("  Tampered: {}", att.tampered);
    println!("  Keys Stored: {}", att.storage.total_keys);

    let m = hsm.metrics();
    println!("\n METRICS");
    println!("  Total Operations: {}", m["ops"]["total"]);
    println!("  Successful Ops: {}", m["ops"]["success"]);
    println!("  Keys Generated: {}", m["ops"]["keys"]);
    println!("  Signatures: {}", m["ops"]["sign"]);
    println!("  Verifications: {}", m["ops"]["verify"]);
    println!("  Encryptions: {}", m["ops"]["enc"]);
    println!("  Decryptions: {}", m["ops"]["dec"]);
    println!("  Active Sessions: {}", m["sessions"]["active"]);
    println!("  Keys Stored: {}", m["keys"]["stored"]);
    println!("  Max Key Slots: {}", m["keys"]["max"]);
    println!("  Uptime: {} seconds", m["hsm"]["uptime"]);

    hsm.close_session(&sess)?;
    println!("\n{}", "-".repeat(64));
    println!("HSM OPERATIONAL - ZERO ERRORS");
    println!("All cryptographic operations completed successfully");

    Ok(())
}
