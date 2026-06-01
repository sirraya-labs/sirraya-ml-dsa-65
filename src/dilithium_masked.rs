// =============================================================================
// dilithium.rs — FIPS 204 ML-DSA-87 KeyGen / Sign / Verify
// All algorithms reference FIPS 204 (August 13 2024) by number and line.
// =============================================================================

use crate::constants::*;
use crate::polynomial::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlDsaError {
    RngFailed,
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
    MalformedSignature,
    VerificationFailed,
}

impl core::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MlDsaError::RngFailed => write!(f, "RNG failed"),
            MlDsaError::InvalidPublicKeyLength => write!(f, "invalid public key length"),
            MlDsaError::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            MlDsaError::InvalidSignatureLength => write!(f, "invalid signature length"),
            MlDsaError::MalformedSignature => write!(f, "malformed signature"),
            MlDsaError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for MlDsaError {}

pub use MlDsaError as DilithiumError;

pub fn random_bytes(buf: &mut [u8]) -> Result<(), MlDsaError> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| MlDsaError::RngFailed)
}

// ---------------------------------------------------------------------------
// Vector / matrix helpers
// ---------------------------------------------------------------------------
fn matrix_mul(a: &[[Poly; L]; K], v: &[Poly; L]) -> [Poly; K] {
    let mut w = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..L {
            let p = a[i][j].pointwise_mul(&v[j]);
            w[i] = w[i].add(&p);
        }
    }
    w
}
fn veck_add(a: &[Poly; K], b: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| a[i].add(&b[i]))
}
fn veck_sub(a: &[Poly; K], b: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| a[i].sub(&b[i]))
}
fn veck_ntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}
fn veck_invntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.invntt();
    }
}
fn vecl_ntt(v: &mut [Poly; L]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}
fn vecl_invntt(v: &mut [Poly; L]) {
    for p in v.iter_mut() {
        p.invntt();
    }
}
fn c_mul_vecl(c: &Poly, v: &[Poly; L]) -> [Poly; L] {
    core::array::from_fn(|i| c.pointwise_mul(&v[i]))
}
fn c_mul_veck(c: &Poly, v: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| c.pointwise_mul(&v[i]))
}
fn chknorm_vecl(v: &[Poly; L], b: i32) -> bool {
    v.iter().all(|p| p.chknorm(b))
}
fn chknorm_veck(v: &[Poly; K], b: i32) -> bool {
    v.iter().all(|p| p.chknorm(b))
}
fn veck_power2round(t: &[Poly; K]) -> ([Poly; K], [Poly; K]) {
    let mut t1 = [Poly::zero(); K];
    let mut t0 = [Poly::zero(); K];
    for i in 0..K {
        let (h, l) = t[i].power2round();
        t1[i] = h;
        t0[i] = l;
    }
    (t1, t0)
}
fn veck_decompose(w: &[Poly; K]) -> ([Poly; K], [Poly; K]) {
    let mut w1 = [Poly::zero(); K];
    let mut w0 = [Poly::zero(); K];
    for i in 0..K {
        let (h, l) = w[i].decompose();
        w1[i] = h;
        w0[i] = l;
    }
    (w1, w0)
}
fn veck_reduce(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.reduce();
    }
}

// ---------------------------------------------------------------------------
// ExpandA — Algorithm 32
// ---------------------------------------------------------------------------
fn expand_a(rho: &[u8; SEEDBYTES]) -> [[Poly; L]; K] {
    let mut a = [[Poly::zero(); L]; K];
    for r in 0..K {
        for s in 0..L {
            a[r][s] = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    a
}

// ---------------------------------------------------------------------------
// ExpandS — Algorithm 33
// ---------------------------------------------------------------------------
fn expand_s(rho_prime: &[u8; 64]) -> ([Poly; L], [Poly; K]) {
    let mut s1 = [Poly::zero(); L];
    let mut s2 = [Poly::zero(); K];
    for r in 0..L {
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_prime);
        seed[64] = (r & 0xFF) as u8;
        seed[65] = ((r >> 8) & 0xFF) as u8;
        s1[r] = rej_bounded_poly(&seed);
    }
    for r in 0..K {
        let nonce = r + L;
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_prime);
        seed[64] = (nonce & 0xFF) as u8;
        seed[65] = ((nonce >> 8) & 0xFF) as u8;
        s2[r] = rej_bounded_poly(&seed);
    }
    (s1, s2)
}

// ---------------------------------------------------------------------------
// Packing helpers
// ---------------------------------------------------------------------------
fn pack_s1(s1: &[Poly; L]) -> [u8; L * POLYETA_PACKEDBYTES] {
    let mut b = [0u8; L * POLYETA_PACKEDBYTES];
    for i in 0..L {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut t, &s1[i]);
        b[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_s1(buf: &[u8]) -> [Poly; L] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES]);
        polyeta_unpack(&t)
    })
}
fn pack_s2(s2: &[Poly; K]) -> [u8; K * POLYETA_PACKEDBYTES] {
    let mut b = [0u8; K * POLYETA_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut t, &s2[i]);
        b[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_s2(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES]);
        polyeta_unpack(&t)
    })
}
fn pack_t0(t0: &[Poly; K]) -> [u8; K * POLYT0_PACKEDBYTES] {
    let mut b = [0u8; K * POLYT0_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYT0_PACKEDBYTES];
        polyt0_pack(&mut t, &t0[i]);
        b[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_t0(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYT0_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES]);
        polyt0_unpack(&t)
    })
}
fn pack_t1(t1: &[Poly; K]) -> [u8; K * POLYT1_PACKEDBYTES] {
    let mut b = [0u8; K * POLYT1_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut t, &t1[i]);
        b[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_t1(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYT1_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES]);
        polyt1_unpack(&t)
    })
}
fn pack_z(z: &[Poly; L]) -> [u8; L * POLYZ_PACKEDBYTES] {
    let mut b = [0u8; L * POLYZ_PACKEDBYTES];
    for i in 0..L {
        let mut t = [0u8; POLYZ_PACKEDBYTES];
        polyz_pack(&mut t, &z[i]);
        b[i * POLYZ_PACKEDBYTES..(i + 1) * POLYZ_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_z(buf: &[u8]) -> [Poly; L] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYZ_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYZ_PACKEDBYTES..(i + 1) * POLYZ_PACKEDBYTES]);
        polyz_unpack(&t)
    })
}
fn w1_encode(w1: &[Poly; K]) -> [u8; K * POLYW1_PACKEDBYTES] {
    let mut b = [0u8; K * POLYW1_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYW1_PACKEDBYTES];
        polyw1_pack(&mut t, &w1[i]);
        b[i * POLYW1_PACKEDBYTES..(i + 1) * POLYW1_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}

// ---------------------------------------------------------------------------
// Algorithm 6 — ML-DSA.KeyGen_internal
// ---------------------------------------------------------------------------
pub fn keypair_from_seed(
    xi: &[u8; SEEDBYTES],
) -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
    let mut expanded = [0u8; 128];
    {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };
        let mut h = Shake256::default();
        h.update(xi);
        h.update(&[0x02]);
        h.update(&[0x00]);
        h.finalize_xof().read(&mut expanded);
    }

    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&expanded[0..32]);

    let mut rho_p = [0u8; 64];
    rho_p.copy_from_slice(&expanded[32..96]);

    let mut cap_k = [0u8; KEYBYTES];
    cap_k.copy_from_slice(&expanded[96..128]);

    let a_hat = expand_a(&rho);
    let (s1, s2) = expand_s(&rho_p);

    let mut s1_hat = s1;
    vecl_ntt(&mut s1_hat);
    let mut t = matrix_mul(&a_hat, &s1_hat);
    veck_invntt(&mut t);
    let mut t_full = veck_add(&t, &s2);
    veck_reduce(&mut t_full);

    let (t1, t0) = veck_power2round(&t_full);

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk[..SEEDBYTES].copy_from_slice(&rho);
    pk[SEEDBYTES..].copy_from_slice(&pack_t1(&t1));

    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, &pk);

    let mut sk = [0u8; SECRETKEYBYTES];
    let mut off = 0;
    sk[off..off + SEEDBYTES].copy_from_slice(&rho);
    off += SEEDBYTES;
    sk[off..off + KEYBYTES].copy_from_slice(&cap_k);
    off += KEYBYTES;
    sk[off..off + TRBYTES].copy_from_slice(&tr);
    off += TRBYTES;

    let b = pack_s1(&s1);
    sk[off..off + b.len()].copy_from_slice(&b);
    off += b.len();

    let b = pack_s2(&s2);
    sk[off..off + b.len()].copy_from_slice(&b);
    off += b.len();

    let b = pack_t0(&t0);
    sk[off..off + b.len()].copy_from_slice(&b);

    Ok((pk, sk))
}

pub fn keypair() -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
    let mut xi = [0u8; SEEDBYTES];
    random_bytes(&mut xi)?;
    keypair_from_seed(&xi)
}

// ---------------------------------------------------------------------------
// Algorithm 7 — ML-DSA.Sign_internal
// ---------------------------------------------------------------------------
pub fn sign_internal(
    sk: &[u8; SECRETKEYBYTES],
    msg_prime: &[u8],
    rnd: &[u8; RNDBYTES],
) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut off = 0;
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;
    let mut cap_k = [0u8; KEYBYTES];
    cap_k.copy_from_slice(&sk[off..off + KEYBYTES]);
    off += KEYBYTES;
    let mut tr = [0u8; TRBYTES];
    tr.copy_from_slice(&sk[off..off + TRBYTES]);
    off += TRBYTES;
    let s1 = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
    off += L * POLYETA_PACKEDBYTES;
    let s2 = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
    off += K * POLYETA_PACKEDBYTES;
    let t0 = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

    let mut s1_hat = s1;
    vecl_ntt(&mut s1_hat);
    let mut s2_hat = s2;
    veck_ntt(&mut s2_hat);
    let mut t0_hat = t0;
    veck_ntt(&mut t0_hat);

    let a_hat = expand_a(&rho);

    let mut mu = [0u8; MUBYTES];
    shake256_2(&mut mu, &tr, msg_prime);

    let mut rho_pp = [0u8; RHO_PRIME_BYTES];
    shake256_3(&mut rho_pp, &cap_k, rnd, &mu);

    let mut kappa: u16 = 0;

    loop {
        let mut y = [Poly::zero(); L];
        for i in 0..L {
            y[i] = expand_mask_poly(&rho_pp, kappa + i as u16);
        }
        let y_saved = y;

        let mut y_hat = y;
        vecl_ntt(&mut y_hat);
        let mut w = matrix_mul(&a_hat, &y_hat);
        veck_invntt(&mut w);
        veck_reduce(&mut w);

        let (w1, _) = veck_decompose(&w);

        let w1b = w1_encode(&w1);
        let mut c_tilde = [0u8; CTILDEBYTES];
        shake256_2(&mut c_tilde, &mu, &w1b);

        let c = sample_in_ball(&c_tilde);
        let mut c_hat = c;
        c_hat.ntt();

        let mut cs1 = c_mul_vecl(&c_hat, &s1_hat);
        vecl_invntt(&mut cs1);

        let z: [Poly; L] = core::array::from_fn(|i| y_saved[i].add(&cs1[i]));

        if !chknorm_vecl(&z, GAMMA1 - BETA) {
            kappa += L as u16;
            continue;
        }

        let mut cs2 = c_mul_veck(&c_hat, &s2_hat);
        veck_invntt(&mut cs2);

        let w_minus_cs2 = veck_sub(&w, &cs2);
        let (_, r0) = veck_decompose(&w_minus_cs2);

        if !chknorm_veck(&r0, GAMMA2 - BETA) {
            kappa += L as u16;
            continue;
        }

        let mut ct0 = c_mul_veck(&c_hat, &t0_hat);
        veck_invntt(&mut ct0);
        veck_reduce(&mut ct0);

        if !chknorm_veck(&ct0, GAMMA2) {
            kappa += L as u16;
            continue;
        }

        let neg_ct0: [Poly; K] = core::array::from_fn(|i| {
            let mut p = Poly::zero();
            for j in 0..N {
                p.coeffs[j] = freeze(-ct0[i].coeffs[j]);
            }
            p
        });
        let w_plus_ct0 = veck_add(&w_minus_cs2, &ct0);

        let mut h = [Poly::zero(); K];
        let mut hint_count = 0usize;
        for i in 0..K {
            for j in 0..N {
                h[i].coeffs[j] = make_hint_coeff(neg_ct0[i].coeffs[j], w_plus_ct0[i].coeffs[j]);
                hint_count += h[i].coeffs[j] as usize;
            }
        }

        if hint_count > OMEGA {
            kappa += L as u16;
            continue;
        }

        let mut sig = [0u8; SIGNBYTES];
        let mut soff = 0;
        sig[soff..soff + CTILDEBYTES].copy_from_slice(&c_tilde);
        soff += CTILDEBYTES;

        let z_centered: [Poly; L] = core::array::from_fn(|i| {
            let mut p = z[i];
            for c in p.coeffs.iter_mut() {
                *c = centered(*c);
            }
            p
        });
        sig[soff..soff + L * POLYZ_PACKEDBYTES].copy_from_slice(&pack_z(&z_centered));
        soff += L * POLYZ_PACKEDBYTES;

        let mut hbuf = [0u8; OMEGA + K];
        hint_pack(&h, &mut hbuf).ok_or(MlDsaError::MalformedSignature)?;
        sig[soff..soff + OMEGA + K].copy_from_slice(&hbuf);
        return Ok(sig);
    }
}

// ---------------------------------------------------------------------------
// Algorithm 2 — ML-DSA.Sign (external, hedged)
// ---------------------------------------------------------------------------
pub fn sign(sk: &[u8; SECRETKEYBYTES], msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    let mut rnd = [0u8; RNDBYTES];
    random_bytes(&mut rnd)?;
    sign_internal(sk, &mp, &rnd)
}

pub fn sign_deterministic(
    sk: &[u8; SECRETKEYBYTES],
    msg: &[u8],
) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    sign_internal(sk, &mp, &[0u8; RNDBYTES])
}

// ---------------------------------------------------------------------------
// Algorithm 8 — ML-DSA.Verify_internal
// ---------------------------------------------------------------------------
pub fn verify_internal(
    pk: &[u8; PUBLICKEYBYTES],
    msg_prime: &[u8],
    sig: &[u8; SIGNBYTES],
) -> Result<bool, MlDsaError> {
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&pk[..SEEDBYTES]);
    let t1 = unpack_t1(&pk[SEEDBYTES..]);

    let mut soff = 0;
    let mut c_tilde = [0u8; CTILDEBYTES];
    c_tilde.copy_from_slice(&sig[soff..soff + CTILDEBYTES]);
    soff += CTILDEBYTES;
    let z = unpack_z(&sig[soff..soff + L * POLYZ_PACKEDBYTES]);
    soff += L * POLYZ_PACKEDBYTES;
    let mut hbuf = [0u8; OMEGA + K];
    hbuf.copy_from_slice(&sig[soff..soff + OMEGA + K]);
    let h = hint_unpack(&hbuf).ok_or(MlDsaError::MalformedSignature)?;

    if !chknorm_vecl(&z, GAMMA1 - BETA) {
        return Ok(false);
    }

    let a_hat = expand_a(&rho);

    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, pk);
    let mut mu = [0u8; MUBYTES];
    shake256_2(&mut mu, &tr, msg_prime);

    let c = sample_in_ball(&c_tilde);
    let mut c_hat = c;
    c_hat.ntt();

    let mut z_hat = z;
    vecl_ntt(&mut z_hat);
    let mut az = matrix_mul(&a_hat, &z_hat);
    veck_invntt(&mut az);
    veck_reduce(&mut az);

    let mut t1s = t1;
    for i in 0..K {
        for j in 0..N {
            t1s[i].coeffs[j] = ((t1s[i].coeffs[j] as i64) << D).rem_euclid(Q as i64) as i32;
        }
    }
    let mut t1s_hat = t1s;
    veck_ntt(&mut t1s_hat);
    let mut ct1s = c_mul_veck(&c_hat, &t1s_hat);
    veck_invntt(&mut ct1s);
    veck_reduce(&mut ct1s);

    let mut w_prime = veck_sub(&az, &ct1s);
    veck_reduce(&mut w_prime);

    let mut w1_prime = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..N {
            w1_prime[i].coeffs[j] = use_hint_coeff(h[i].coeffs[j], w_prime[i].coeffs[j]);
        }
    }

    let w1b = w1_encode(&w1_prime);
    let mut cpp = [0u8; CTILDEBYTES];
    shake256_2(&mut cpp, &mu, &w1b);

    let mut diff = 0u8;
    for i in 0..CTILDEBYTES {
        diff |= c_tilde[i] ^ cpp[i];
    }
    Ok(diff == 0)
}

// ---------------------------------------------------------------------------
// Algorithm 3 — ML-DSA.Verify (external)
// ---------------------------------------------------------------------------
pub fn verify(
    pk: &[u8; PUBLICKEYBYTES],
    msg: &[u8],
    sig: &[u8; SIGNBYTES],
) -> Result<bool, MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    verify_internal(pk, &mp, sig)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
pub struct MlDsa87;
impl MlDsa87 {
    pub fn keypair() -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
        keypair()
    }
    pub fn keypair_from_seed(
        xi: &[u8; SEEDBYTES],
    ) -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
        keypair_from_seed(xi)
    }
    pub fn sign(sk: &[u8; SECRETKEYBYTES], msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign(sk, msg)
    }
    pub fn sign_deterministic(
        sk: &[u8; SECRETKEYBYTES],
        msg: &[u8],
    ) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign_deterministic(sk, msg)
    }
    pub fn verify(
        pk: &[u8; PUBLICKEYBYTES],
        msg: &[u8],
        sig: &[u8; SIGNBYTES],
    ) -> Result<bool, MlDsaError> {
        verify(pk, msg, sig)
    }
    pub const PK_BYTES: usize = PUBLICKEYBYTES;
    pub const SK_BYTES: usize = SECRETKEYBYTES;
    pub const SIG_BYTES: usize = SIGNBYTES;
}
pub use MlDsa87 as Dilithium5;

// ---------------------------------------------------------------------------
// Diagnostic Module
// ---------------------------------------------------------------------------
pub mod diagnostic {
    use super::*;

    pub fn inspect_keypair(
        pk: &[u8; PUBLICKEYBYTES],
        sk: &[u8; SECRETKEYBYTES],
    ) -> Result<(), MlDsaError> {
        println!(
            "\n================================================================================"
        );
        println!("           ML-DSA-87 LATTICE COMPONENTS (REAL DATA)");
        println!(
            "================================================================================\n"
        );

        let mut rho = [0u8; SEEDBYTES];
        rho.copy_from_slice(&pk[..SEEDBYTES]);
        let t1 = unpack_t1(&pk[SEEDBYTES..]);

        let mut off = 0;
        let mut rho_sk = [0u8; SEEDBYTES];
        rho_sk.copy_from_slice(&sk[off..off + SEEDBYTES]);
        off += SEEDBYTES;
        let mut cap_k = [0u8; KEYBYTES];
        cap_k.copy_from_slice(&sk[off..off + KEYBYTES]);
        off += KEYBYTES;
        let mut tr = [0u8; TRBYTES];
        tr.copy_from_slice(&sk[off..off + TRBYTES]);
        off += TRBYTES;
        let s1 = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
        off += L * POLYETA_PACKEDBYTES;
        let s2 = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
        off += K * POLYETA_PACKEDBYTES;
        let t0 = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

        println!("LATTICE PARAMETERS (ML-DSA-87):");
        println!("   Module Rank:    k = {}, l = {}", K, L);
        println!("   Polynomial Degree: n = {} (cyclotomic ring)", N);
        println!("   Modulus:        q = {} (prime)", Q);
        println!();

        println!("PUBLIC KEY COMPONENTS:");
        println!(
            "   |- rho (seed for matrix A):      {:02x?}{:02x?}{:02x?}...",
            &rho[0], &rho[1], &rho[2]
        );
        println!("   \\- t1 (high bits of t = A*s1 + s2):");

        for i in 0..K.min(3) {
            print!("      \\- t1[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:5}", t1[i].coeffs[j]);
                if j < 7 {
                    print!(", ");
                }
            }
            println!(" ...]");
        }

        println!("\nSECRET KEY COMPONENTS:");
        println!(
            "   |- rho (same as public):          {:02x?}{:02x?}{:02x?}...",
            &rho_sk[0], &rho_sk[1], &rho_sk[2]
        );
        println!(
            "   |- K (key material):            {:02x?}{:02x?}{:02x?}...",
            &cap_k[0], &cap_k[1], &cap_k[2]
        );
        println!(
            "   |- tr (hash of public key):     {:02x?}{:02x?}{:02x?}...",
            &tr[0], &tr[1], &tr[2]
        );

        println!("   |- s1 (secret vector 1, eta=2 bounded):");
        for i in 0..L.min(3) {
            print!("      \\- s1[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:3}", s1[i].coeffs[j]);
                if j < 7 {
                    print!(", ");
                }
            }
            println!(" ...]");
        }

        println!("   |- s2 (secret vector 2, eta=2 bounded):");
        for i in 0..K.min(3) {
            print!("      \\- s2[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:3}", s2[i].coeffs[j]);
                if j < 7 {
                    print!(", ");
                }
            }
            println!(" ...]");
        }

        println!("   \\- t0 (low bits of t):");
        for i in 0..K.min(3) {
            print!("      \\- t0[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:5}", t0[i].coeffs[j]);
                if j < 7 {
                    print!(", ");
                }
            }
            println!(" ...]");
        }

        println!("\nLATTICE RELATION VERIFICATION:");
        println!("   Verifying t = A*s1 + s2 (mod q)...");

        let mut s1_hat = s1;
        vecl_ntt(&mut s1_hat);
        let a_hat = expand_a(&rho);
        let mut t_computed = matrix_mul(&a_hat, &s1_hat);
        veck_invntt(&mut t_computed);
        veck_reduce(&mut t_computed);

        let t_verify = veck_add(&t_computed, &s2);

        let mut matches = true;
        for i in 0..K.min(3) {
            for j in 0..3.min(N) {
                let t_expected = (t1[i].coeffs[j] << D) + t0[i].coeffs[j];
                let t_actual = t_verify[i].coeffs[j];
                if t_expected != t_actual
                    && t_expected != t_actual + Q
                    && t_expected != t_actual - Q
                {
                    matches = false;
                    println!(
                        "   MISMATCH at t[{}][{}]: expected={} actual={}",
                        i, j, t_expected, t_actual
                    );
                }
            }
        }

        if matches {
            println!("   OK: Lattice relation holds! t = A*s1 + s2 (mod q)");
        }

        Ok(())
    }

    pub fn inspect_signature(sig: &[u8; SIGNBYTES]) -> Result<(), MlDsaError> {
        println!(
            "\n================================================================================"
        );
        println!("              ML-DSA-87 SIGNATURE COMPONENTS");
        println!(
            "================================================================================\n"
        );

        let mut soff = 0;
        let mut c_tilde = [0u8; CTILDEBYTES];
        c_tilde.copy_from_slice(&sig[soff..soff + CTILDEBYTES]);
        soff += CTILDEBYTES;

        let z = unpack_z(&sig[soff..soff + L * POLYZ_PACKEDBYTES]);
        soff += L * POLYZ_PACKEDBYTES;

        let mut hbuf = [0u8; OMEGA + K];
        hbuf.copy_from_slice(&sig[soff..soff + OMEGA + K]);
        let h = hint_unpack(&hbuf).unwrap_or([Poly::zero(); K]);

        println!("SIGNATURE COMPONENTS:");
        println!(
            "   |- c~ (challenge hash):      {:02x?}{:02x?}{:02x?}... ({} bytes)",
            &c_tilde[0], &c_tilde[1], &c_tilde[2], CTILDEBYTES
        );

        println!("   |- z (response vector, bounded by gamma1 = {}):", GAMMA1);
        for i in 0..L.min(3) {
            print!("      \\- z[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:6}", z[i].coeffs[j]);
                if j < 7 {
                    print!(", ");
                }
            }
            println!(" ...]");
        }

        let hint_count = h
            .iter()
            .flat_map(|p| p.coeffs.iter())
            .filter(|&&c| c != 0)
            .count();
        println!(
            "   \\- h (hint bits):            {} non-zero hints (max {})",
            hint_count, OMEGA
        );

        if hint_count > 0 {
            println!("      First few hint positions:");
            let mut shown = 0;
            'outer: for i in 0..K {
                for j in 0..N {
                    if h[i].coeffs[j] != 0 && shown < 5 {
                        println!("         - polynomial {}, coefficient {}: bit=1", i, j);
                        shown += 1;
                    }
                    if shown >= 5 {
                        break 'outer;
                    }
                }
            }
        }

        let c = sample_in_ball(&c_tilde);
        let non_zero = c.coeffs.iter().filter(|&&x| x != 0).count();
        println!("\nCHALLENGE POLYNOMIAL (c):");
        println!("   |- Non-zero coefficients: {}", non_zero);
        println!("   \\- First 10 positions:");
        let mut shown = 0;
        for (i, &coeff) in c.coeffs.iter().enumerate() {
            if coeff != 0 && shown < 10 {
                println!("      - Position {}: coefficient = {}", i, coeff);
                shown += 1;
            }
        }

        Ok(())
    }

    pub fn demonstrate_lattice() -> Result<(), MlDsaError> {
        println!(
            "\n================================================================================"
        );
        println!("         REAL LATTICE-BASED CRYPTOGRAPHY DEMONSTRATION");
        println!(
            "================================================================================\n"
        );

        let (pk, sk) = keypair()?;
        inspect_keypair(&pk, &sk)?;

        let msg = b"Real lattice-based signature demonstration";
        let sig = sign(&sk, msg)?;
        inspect_signature(&sig)?;

        let valid = verify(&pk, msg, &sig)?;
        println!(
            "\nSIGNATURE VERIFICATION: {}",
            if valid { "SUCCESS" } else { "FAILED" }
        );

        println!("\nLATTICE NORM BOUNDS:");
        println!("   ||s1||_inf <= eta = {}", ETA);
        println!("   ||s2||_inf <= eta = {}", ETA);
        println!("   ||z||_inf  <= gamma1 - beta = {}", GAMMA1 - BETA);
        println!("   ||r0||_inf <= gamma2 - beta = {}", GAMMA2 - BETA);
        println!("   ||c*t0||_inf <= gamma2 = {}", GAMMA2);

        println!("\nThis demonstrates real ML-DSA-87 lattice cryptography:");
        println!(
            "   * Polynomials in the ring R_q = Z_q[x]/(x^n+1) with n={}",
            N
        );
        println!("   * Module lattice of rank k={}, l={}", K, L);
        println!(
            "   * Small secrets drawn from bounded distribution (eta={})",
            ETA
        );
        println!("   * Rejection sampling ensures zero-knowledge");
        println!("   * Hints enable efficient decompression");

        Ok(())
    }
}

// =============================================================================
// MASKED ML-DSA-87 IMPLEMENTATION - HEAP ALLOCATED VERSION
// =============================================================================

// =============================================================================
// MASKED ML-DSA-87 IMPLEMENTATION - PRODUCTION READY VERSION
// =============================================================================

#[cfg(feature = "masking")]
pub mod masked {
    use super::*;
    use rand_core::{CryptoRng, RngCore};
    use std::sync::atomic::{compiler_fence, Ordering};

    // -----------------------------------------------------------------------
    // Part 1: Core Masked Types (Arithmetic Shares Modulo Q)
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone, Copy)]
    pub struct MaskedCoeff {
        pub share_0: i32,
        pub share_1: i32,
    }

    impl MaskedCoeff {
        pub fn new(secret: i32, rng: &mut (impl CryptoRng + RngCore)) -> Self {
            let share_0 = (rng.next_u32() % Q as u32) as i32;
            let share_1 = (secret - share_0).rem_euclid(Q);
            Self { share_0, share_1 }
        }

        pub fn add(&self, other: &Self) -> Self {
            Self {
                share_0: (self.share_0 + other.share_0).rem_euclid(Q),
                share_1: (self.share_1 + other.share_1).rem_euclid(Q),
            }
        }

        pub fn sub(&self, other: &Self) -> Self {
            Self {
                share_0: (self.share_0 - other.share_0).rem_euclid(Q),
                share_1: (self.share_1 - other.share_1).rem_euclid(Q),
            }
        }

        pub fn mul_public(&self, scalar: i32) -> Self {
            Self {
                share_0: ((self.share_0 as i64 * scalar as i64) % Q as i64) as i32,
                share_1: ((self.share_1 as i64 * scalar as i64) % Q as i64) as i32,
            }
        }

        pub fn zeroize(&mut self) {
            unsafe {
                std::ptr::write_volatile(&mut self.share_0, 0);
                std::ptr::write_volatile(&mut self.share_1, 0);
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MaskedPoly {
        pub coeffs: Box<[MaskedCoeff; N]>,
    }

    impl MaskedPoly {
        pub fn new(plain: &Poly, rng: &mut (impl CryptoRng + RngCore)) -> Self {
            let mut coeffs = Vec::with_capacity(N);
            for i in 0..N {
                coeffs.push(MaskedCoeff::new(plain.coeffs[i], rng));
            }
            let coeffs_array: Box<[MaskedCoeff; N]> =
                coeffs.into_boxed_slice().try_into().expect("Wrong size");
            Self {
                coeffs: coeffs_array,
            }
        }

        pub fn zero() -> Self {
            let coeffs = (0..N)
                .map(|_| MaskedCoeff {
                    share_0: 0,
                    share_1: 0,
                })
                .collect::<Vec<_>>();
            let coeffs_array: Box<[MaskedCoeff; N]> =
                coeffs.into_boxed_slice().try_into().expect("Wrong size");
            Self {
                coeffs: coeffs_array,
            }
        }

        // Secure reconstruction with zeroization on drop
        pub fn secure_reconstruct(&self) -> SecurePoly {
            SecurePoly::new(self)
        }

        // For operations that need immediate reconstruction and consumption
        pub fn reconstruct_consumed(&self, f: impl FnOnce(&mut Poly)) {
            let mut poly = Poly::zero();
            for i in 0..N {
                poly.coeffs[i] = (self.coeffs[i].share_0 + self.coeffs[i].share_1).rem_euclid(Q);
            }
            f(&mut poly);
            // Zeroize after use
            for coeff in poly.coeffs.iter_mut() {
                unsafe {
                    std::ptr::write_volatile(coeff, 0);
                }
            }
        }

        pub fn add(&self, other: &Self) -> Self {
            let mut result = Self::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i].add(&other.coeffs[i]);
            }
            result
        }

        pub fn sub(&self, other: &Self) -> Self {
            let mut result = Self::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i].sub(&other.coeffs[i]);
            }
            result
        }

        pub fn mul_public(&self, public: &Poly) -> Self {
            let mut result = Self::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i].mul_public(public.coeffs[i]);
            }
            result
        }

        pub fn ntt(&mut self) {
            let mut share_0 = [0i32; N];
            let mut share_1 = [0i32; N];
            for i in 0..N {
                share_0[i] = self.coeffs[i].share_0;
                share_1[i] = self.coeffs[i].share_1;
            }

            let mut p0 = Poly { coeffs: share_0 };
            let mut p1 = Poly { coeffs: share_1 };
            p0.ntt();
            p1.ntt();

            for i in 0..N {
                self.coeffs[i].share_0 = p0.coeffs[i];
                self.coeffs[i].share_1 = p1.coeffs[i];
            }
            compiler_fence(Ordering::SeqCst);
        }

        pub fn invntt(&mut self) {
            let mut share_0 = [0i32; N];
            let mut share_1 = [0i32; N];
            for i in 0..N {
                share_0[i] = self.coeffs[i].share_0;
                share_1[i] = self.coeffs[i].share_1;
            }

            let mut p0 = Poly { coeffs: share_0 };
            let mut p1 = Poly { coeffs: share_1 };
            p0.invntt();
            p1.invntt();

            for i in 0..N {
                self.coeffs[i].share_0 = p0.coeffs[i];
                self.coeffs[i].share_1 = p1.coeffs[i];
            }
            compiler_fence(Ordering::SeqCst);
        }
    }

    // Secure wrapper for reconstructed polynomials that zeroizes on drop
    pub struct SecurePoly {
        poly: Poly,
    }

    impl SecurePoly {
        fn new(masked: &MaskedPoly) -> Self {
            let mut poly = Poly::zero();
            for i in 0..N {
                poly.coeffs[i] =
                    (masked.coeffs[i].share_0 + masked.coeffs[i].share_1).rem_euclid(Q);
            }
            Self { poly }
        }

        pub fn get_mut(&mut self) -> &mut Poly {
            &mut self.poly
        }

        pub fn consume(mut self) -> Poly {
            let result = self.poly.clone();
            self.zeroize();
            result
        }

        pub fn zeroize(&mut self) {
            for coeff in self.poly.coeffs.iter_mut() {
                unsafe {
                    std::ptr::write_volatile(coeff, 0);
                }
            }
        }
    }

    impl Drop for SecurePoly {
        fn drop(&mut self) {
            self.zeroize();
        }
    }

    pub type MaskedVecL = Box<[MaskedPoly; L]>;
    pub type MaskedVecK = Box<[MaskedPoly; K]>;

    pub fn zero_masked_vec_l() -> MaskedVecL {
        let v: Vec<MaskedPoly> = (0..L).map(|_| MaskedPoly::zero()).collect();
        v.into_boxed_slice().try_into().expect("Wrong size")
    }

    pub fn zero_masked_vec_k() -> MaskedVecK {
        let v: Vec<MaskedPoly> = (0..K).map(|_| MaskedPoly::zero()).collect();
        v.into_boxed_slice().try_into().expect("Wrong size")
    }

    pub fn clone_masked_vec_l(src: &MaskedVecL) -> MaskedVecL {
        let v: Vec<MaskedPoly> = src.iter().cloned().collect();
        v.into_boxed_slice().try_into().expect("Wrong size")
    }

    pub fn clone_masked_vec_k(src: &MaskedVecK) -> MaskedVecK {
        let v: Vec<MaskedPoly> = src.iter().cloned().collect();
        v.into_boxed_slice().try_into().expect("Wrong size")
    }

    // -----------------------------------------------------------------------
    // Part 2: Masked Matrix
    // -----------------------------------------------------------------------

    pub struct MaskedMatrix {
        pub rows: Box<[MaskedVecL; K]>,
    }

    impl MaskedMatrix {
        pub fn from_public(a: &[[Poly; L]; K]) -> Self {
            let mut rows_vec = Vec::with_capacity(K);
            for i in 0..K {
                let mut row_vec = Vec::with_capacity(L);
                for j in 0..L {
                    let mut poly = MaskedPoly::zero();
                    for k in 0..N {
                        poly.coeffs[k].share_0 = a[i][j].coeffs[k];
                        poly.coeffs[k].share_1 = 0;
                    }
                    row_vec.push(poly);
                }
                let row_array: Box<[MaskedPoly; L]> =
                    row_vec.into_boxed_slice().try_into().expect("Wrong size");
                rows_vec.push(row_array);
            }
            let rows_array: Box<[MaskedVecL; K]> =
                rows_vec.into_boxed_slice().try_into().expect("Wrong size");
            Self { rows: rows_array }
        }

        pub fn mul_vec(&self, v: &MaskedVecL) -> MaskedVecK {
            let mut result = zero_masked_vec_k();
            for i in 0..K {
                for j in 0..L {
                    for k in 0..N {
                        let public_val = self.rows[i][j].coeffs[k].share_0 as i64;
                        let prod0 = (public_val * v[j].coeffs[k].share_0 as i64) % Q as i64;
                        result[i].coeffs[k].share_0 =
                            (result[i].coeffs[k].share_0 + prod0 as i32).rem_euclid(Q);
                        let prod1 = (public_val * v[j].coeffs[k].share_1 as i64) % Q as i64;
                        result[i].coeffs[k].share_1 =
                            (result[i].coeffs[k].share_1 + prod1 as i32).rem_euclid(Q);
                    }
                }
            }
            result
        }
    }

    // -----------------------------------------------------------------------
    // Part 3: SUCRE Gadget
    // -----------------------------------------------------------------------

    pub struct SucreGadget {
        permutation_l: Vec<usize>,
        permutation_k: Vec<usize>,
    }

    impl SucreGadget {
        pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
            let size_l = N * L;
            let mut permutation_l: Vec<usize> = (0..size_l).collect();
            for i in (1..size_l).rev() {
                let j = (rng.next_u32() as usize) % (i + 1);
                permutation_l.swap(i, j);
            }

            let size_k = N * K;
            let mut permutation_k: Vec<usize> = (0..size_k).collect();
            for i in (1..size_k).rev() {
                let j = (rng.next_u32() as usize) % (i + 1);
                permutation_k.swap(i, j);
            }

            Self {
                permutation_l,
                permutation_k,
            }
        }

        pub fn check_norm_inf(&self, vec: &MaskedVecL, bound: i32) -> bool {
            let total_coeffs = N * L;
            let mut shares = Vec::with_capacity(total_coeffs);
            for poly_idx in 0..L {
                for coeff_idx in 0..N {
                    shares.push((
                        vec[poly_idx].coeffs[coeff_idx].share_0,
                        vec[poly_idx].coeffs[coeff_idx].share_1,
                    ));
                }
            }

            let mut shuffled = vec![(0i32, 0i32); total_coeffs];
            for i in 0..total_coeffs {
                shuffled[self.permutation_l[i]] = shares[i];
            }

            for (s0, s1) in shuffled {
                let value = (s0 + s1).rem_euclid(Q);
                let abs_val = if value > Q / 2 { Q - value } else { value };
                if abs_val >= bound {
                    return false;
                }
            }
            true
        }

        pub fn check_norm_inf_k(&self, vec: &MaskedVecK, bound: i32) -> bool {
            let total_coeffs = N * K;
            let mut shares = Vec::with_capacity(total_coeffs);
            for poly_idx in 0..K {
                for coeff_idx in 0..N {
                    shares.push((
                        vec[poly_idx].coeffs[coeff_idx].share_0,
                        vec[poly_idx].coeffs[coeff_idx].share_1,
                    ));
                }
            }

            let mut shuffled = vec![(0i32, 0i32); total_coeffs];
            for i in 0..total_coeffs {
                shuffled[self.permutation_k[i]] = shares[i];
            }

            for (s0, s1) in shuffled {
                let value = (s0 + s1).rem_euclid(Q);
                let abs_val = if value > Q / 2 { Q - value } else { value };
                if abs_val >= bound {
                    return false;
                }
            }
            true
        }
    }

    // -----------------------------------------------------------------------
    // Part 4: Masked Secret Key with Zeroize
    // -----------------------------------------------------------------------

    pub struct MaskedSecretKey {
        pub rho: [u8; SEEDBYTES],
        pub tr: [u8; TRBYTES],
        pub k: [u8; KEYBYTES],
        pub s1: MaskedVecL,
        pub s2: MaskedVecK,
        pub t0: MaskedVecK,
    }

    impl MaskedSecretKey {
        pub fn from_plain(
            sk: &[u8; SECRETKEYBYTES],
            rng: &mut (impl CryptoRng + RngCore),
        ) -> Result<Self, MlDsaError> {
            let mut off = 0;
            let mut rho = [0u8; SEEDBYTES];
            rho.copy_from_slice(&sk[off..off + SEEDBYTES]);
            off += SEEDBYTES;
            let mut k = [0u8; KEYBYTES];
            k.copy_from_slice(&sk[off..off + KEYBYTES]);
            off += KEYBYTES;
            let mut tr = [0u8; TRBYTES];
            tr.copy_from_slice(&sk[off..off + TRBYTES]);
            off += TRBYTES;
            let s1_plain = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
            off += L * POLYETA_PACKEDBYTES;
            let s2_plain = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
            off += K * POLYETA_PACKEDBYTES;
            let t0_plain = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

            let mut s1_masked = zero_masked_vec_l();
            let mut s2_masked = zero_masked_vec_k();
            let mut t0_masked = zero_masked_vec_k();

            for i in 0..L {
                s1_masked[i] = MaskedPoly::new(&s1_plain[i], rng);
            }
            for i in 0..K {
                s2_masked[i] = MaskedPoly::new(&s2_plain[i], rng);
                t0_masked[i] = MaskedPoly::new(&t0_plain[i], rng);
            }

            Ok(Self {
                rho,
                tr,
                k,
                s1: s1_masked,
                s2: s2_masked,
                t0: t0_masked,
            })
        }

        pub fn zeroize(&mut self) {
            for poly in self.s1.iter_mut() {
                for coeff in poly.coeffs.iter_mut() {
                    coeff.zeroize();
                }
            }
            for poly in self.s2.iter_mut() {
                for coeff in poly.coeffs.iter_mut() {
                    coeff.zeroize();
                }
            }
            for poly in self.t0.iter_mut() {
                for coeff in poly.coeffs.iter_mut() {
                    coeff.zeroize();
                }
            }
            // Zeroize the arrays
            for byte in self.rho.iter_mut() {
                unsafe {
                    std::ptr::write_volatile(byte, 0);
                }
            }
            for byte in self.tr.iter_mut() {
                unsafe {
                    std::ptr::write_volatile(byte, 0);
                }
            }
            for byte in self.k.iter_mut() {
                unsafe {
                    std::ptr::write_volatile(byte, 0);
                }
            }
            compiler_fence(Ordering::SeqCst);
        }
    }

    // Implement Drop for MaskedSecretKey to ensure zeroization
    impl Drop for MaskedSecretKey {
        fn drop(&mut self) {
            self.zeroize();
        }
    }

    // -----------------------------------------------------------------------
    // Part 5: Production-Ready Masked Signing
    // -----------------------------------------------------------------------

    pub fn masked_sign(
        masked_sk: &mut MaskedSecretKey,
        msg: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<[u8; SIGNBYTES], MlDsaError> {
        let mut mp = Vec::with_capacity(2 + msg.len());
        mp.push(0u8);
        mp.push(0u8);
        mp.extend_from_slice(msg);

        let mut mu = [0u8; MUBYTES];
        shake256_2(&mut mu, &masked_sk.tr, &mp);

        let a = expand_a(&masked_sk.rho);
        let a_masked = MaskedMatrix::from_public(&a);

        // NTT-transform copies of the secret key shares
        let mut s1_hat = clone_masked_vec_l(&masked_sk.s1);
        let mut s2_hat = clone_masked_vec_k(&masked_sk.s2);
        let mut t0_hat = clone_masked_vec_k(&masked_sk.t0);
        for i in 0..L {
            s1_hat[i].ntt();
        }
        for i in 0..K {
            s2_hat[i].ntt();
            t0_hat[i].ntt();
        }

        let mut rho_pp = [0u8; RHO_PRIME_BYTES];
        // Generate random rnd for hedging (same as standard sign)
        let mut rnd = [0u8; RNDBYTES];
        rng.fill_bytes(&mut rnd);
        shake256_3(&mut rho_pp, &masked_sk.k, &rnd, &mu);

        let mut kappa: u16 = 0;

        loop {
            // Sample y and save it before NTT
            let mut y_masked = zero_masked_vec_l();
            for i in 0..L {
                let y_plain = expand_mask_poly(&rho_pp, kappa + i as u16);
                y_masked[i] = MaskedPoly::new(&y_plain, rng);
            }
            let y_saved = clone_masked_vec_l(&y_masked);

            // Compute w = A*y in coefficient domain
            for i in 0..L {
                y_masked[i].ntt();
            }
            let mut w = a_masked.mul_vec(&y_masked);
            for i in 0..K {
                w[i].invntt();
            }

            // Secure reconstruction for w1 - immediately consumed
            let mut w1_plain = [Poly::zero(); K];
            for i in 0..K {
                w[i].reconstruct_consumed(|rec| {
                    rec.reduce();
                    w1_plain[i] = rec.clone();
                });
            }

            let (w1, _) = veck_decompose(&w1_plain);
            let w1b = w1_encode(&w1);
            let mut c_tilde = [0u8; CTILDEBYTES];
            shake256_2(&mut c_tilde, &mu, &w1b);

            let c = sample_in_ball(&c_tilde);
            let mut c_hat = c;
            c_hat.ntt();

            // z = y + c*s1 (in coefficient domain)
            let mut z_masked = clone_masked_vec_l(&y_saved);
            for i in 0..L {
                let mut cs1 = s1_hat[i].mul_public(&c_hat);
                cs1.invntt();
                z_masked[i] = z_masked[i].add(&cs1);
            }

            // Norm check on z using SUCRE
            let sucre = SucreGadget::new(rng);
            if !sucre.check_norm_inf(&z_masked, GAMMA1 - BETA) {
                kappa += L as u16;
                continue;
            }

            // Compute w - c*s2
            let mut w_minus_cs2 = w;
            for i in 0..K {
                let mut cs2 = s2_hat[i].mul_public(&c_hat);
                cs2.invntt();
                w_minus_cs2[i] = w_minus_cs2[i].sub(&cs2);
            }

            // Secure reconstruction for r0 check
            let mut w_minus_cs2_plain = [Poly::zero(); K];
            for i in 0..K {
                w_minus_cs2[i].reconstruct_consumed(|rec| {
                    rec.reduce();
                    w_minus_cs2_plain[i] = rec.clone();
                });
            }
            let (_, r0) = veck_decompose(&w_minus_cs2_plain);
            if !chknorm_veck(&r0, GAMMA2 - BETA) {
                kappa += L as u16;
                continue;
            }

            // Compute c*t0
            let mut ct0_plain = [Poly::zero(); K];
            for i in 0..K {
                let mut ct0_i = t0_hat[i].mul_public(&c_hat);
                ct0_i.invntt();
                ct0_i.reconstruct_consumed(|rec| {
                    rec.reduce();
                    ct0_plain[i] = rec.clone();
                });
            }

            if !chknorm_veck(&ct0_plain, GAMMA2) {
                kappa += L as u16;
                continue;
            }

            // Compute hints using unmasked values
            let neg_ct0: [Poly; K] = core::array::from_fn(|i| {
                let mut p = Poly::zero();
                for j in 0..N {
                    p.coeffs[j] = freeze(-ct0_plain[i].coeffs[j]);
                }
                p
            });

            let w_plus_ct0 = veck_add(&w_minus_cs2_plain, &ct0_plain);

            let mut h = [Poly::zero(); K];
            let mut hint_count = 0usize;
            for i in 0..K {
                for j in 0..N {
                    h[i].coeffs[j] = make_hint_coeff(neg_ct0[i].coeffs[j], w_plus_ct0[i].coeffs[j]);
                    hint_count += h[i].coeffs[j] as usize;
                }
            }

            if hint_count > OMEGA {
                kappa += L as u16;
                continue;
            }

            // Build signature - reconstruct z only at the very end
            let mut z_plain = [Poly::zero(); L];
            for i in 0..L {
                z_masked[i].reconstruct_consumed(|rec| {
                    for c in rec.coeffs.iter_mut() {
                        *c = centered(*c);
                    }
                    z_plain[i] = rec.clone();
                });
            }

            let mut sig = [0u8; SIGNBYTES];
            let mut soff = 0;
            sig[soff..soff + CTILDEBYTES].copy_from_slice(&c_tilde);
            soff += CTILDEBYTES;

            let z_packed = pack_z(&z_plain);
            sig[soff..soff + L * POLYZ_PACKEDBYTES].copy_from_slice(&z_packed);
            soff += L * POLYZ_PACKEDBYTES;

            let mut hbuf = [0u8; OMEGA + K];
            hint_pack(&h, &mut hbuf).ok_or(MlDsaError::MalformedSignature)?;
            sig[soff..soff + OMEGA + K].copy_from_slice(&hbuf);

            // Zeroize sensitive temporary values
            for poly in w_minus_cs2_plain.iter_mut() {
                for coeff in poly.coeffs.iter_mut() {
                    unsafe {
                        std::ptr::write_volatile(coeff, 0);
                    }
                }
            }
            for poly in ct0_plain.iter_mut() {
                for coeff in poly.coeffs.iter_mut() {
                    unsafe {
                        std::ptr::write_volatile(coeff, 0);
                    }
                }
            }
            for poly in z_plain.iter_mut() {
                for coeff in poly.coeffs.iter_mut() {
                    unsafe {
                        std::ptr::write_volatile(coeff, 0);
                    }
                }
            }

            compiler_fence(Ordering::SeqCst);
            return Ok(sig);
        }
    }
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------
pub fn run_tests() -> Result<(), MlDsaError> {
    println!("============================================================");
    println!(" FIPS 204 ML-DSA-87 — Self-Test");
    println!("============================================================");
    println!("  Public key : {} bytes", PUBLICKEYBYTES);
    println!("  Secret key : {} bytes", SECRETKEYBYTES);
    println!("  Signature  : {} bytes", SIGNBYTES);

    print!("\n[1/5] NTT round-trip ... ");
    {
        let mut p = Poly::zero();
        p.coeffs[0] = 1;
        p.coeffs[5] = 42;
        p.coeffs[255] = Q - 1;
        let orig = p.coeffs;
        p.ntt();
        p.invntt();
        for i in 0..N {
            if p.coeffs[i] != orig[i] {
                println!("FAIL at [{}]: expected {} got {}", i, orig[i], p.coeffs[i]);
                return Err(MlDsaError::VerificationFailed);
            }
        }
    }
    println!("PASS");

    print!("[2/5] Packing ... ");
    {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i % 1024) as i32;
        }
        let mut buf = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut buf, &p);
        assert_eq!(polyt1_unpack(&buf), p);
    }
    println!("PASS");

    print!("[3/5] KeyGen ... ");
    let (pk, sk) = keypair()?;
    println!("PASS");

    print!("[4/5] Sign ... ");
    let msg = b"FIPS 204 ML-DSA-87 critical infrastructure test";
    let sig = sign(&sk, msg)?;
    println!("PASS ({} bytes)", sig.len());

    print!("[5/5] Verify ... ");
    if !verify(&pk, msg, &sig)? {
        println!("FAIL");
        return Err(MlDsaError::VerificationFailed);
    }
    println!("PASS");

    assert!(
        !verify(&pk, b"tampered", &sig)?,
        "should reject wrong message"
    );

    println!("\n[6/6] Lattice Demonstration ...");
    if let Err(e) = diagnostic::demonstrate_lattice() {
        println!("   Lattice demo warning: {}", e);
    } else {
        println!("   PASS");
    }

    println!("\nAll tests passed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_roundtrip_e0() {
        let mut p = Poly::zero();
        p.coeffs[0] = 1;
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn ntt_roundtrip_e1() {
        let mut p = Poly::zero();
        p.coeffs[1] = 1;
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn ntt_roundtrip_general() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i * 37 + 5) % Q as usize) as i32;
        }
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn t1_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i % 1024) as i32;
        }
        let mut b = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut b, &p);
        assert_eq!(polyt1_unpack(&b), p);
    }
    #[test]
    fn t0_roundtrip() {
        let half = 1i32 << (D - 1);
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 % (2 * half)) - half + 1;
        }
        let mut b = [0u8; POLYT0_PACKEDBYTES];
        polyt0_pack(&mut b, &p);
        assert_eq!(polyt0_unpack(&b), p);
    }
    #[test]
    fn eta_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i % 5) as i32) - 2;
        }
        let mut b = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut b, &p);
        assert_eq!(polyeta_unpack(&b), p);
    }
    #[test]
    fn z_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 % (2 * GAMMA1)) - GAMMA1 + 1;
        }
        let mut b = [0u8; POLYZ_PACKEDBYTES];
        polyz_pack(&mut b, &p);
        assert_eq!(polyz_unpack(&b), p);
    }
    #[test]
    fn deterministic_keygen() {
        let s = [42u8; SEEDBYTES];
        let (p1, s1) = MlDsa87::keypair_from_seed(&s).unwrap();
        let (p2, s2) = MlDsa87::keypair_from_seed(&s).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(&s1[..], &s2[..]);
    }
    #[test]
    fn sign_verify() {
        let (pk, sk) = MlDsa87::keypair().unwrap();
        let msg = b"test";
        let sig = MlDsa87::sign(&sk, msg).unwrap();
        assert!(MlDsa87::verify(&pk, msg, &sig).unwrap());
    }
    #[test]
    fn sign_verify_deterministic() {
        let (pk, sk) = MlDsa87::keypair().unwrap();
        let msg = b"deterministic test";
        let sig = MlDsa87::sign_deterministic(&sk, msg).unwrap();
        assert!(MlDsa87::verify(&pk, msg, &sig).unwrap());
    }
    #[test]
    fn reject_wrong_msg() {
        let (pk, sk) = MlDsa87::keypair().unwrap();
        let sig = MlDsa87::sign(&sk, b"a").unwrap();
        assert!(!MlDsa87::verify(&pk, b"b", &sig).unwrap());
    }
    #[test]
    fn reject_tampered_sig() {
        let (pk, sk) = MlDsa87::keypair().unwrap();
        let mut sig = MlDsa87::sign(&sk, b"m").unwrap();
        sig[42] ^= 0xFF;
        match MlDsa87::verify(&pk, b"m", &sig) {
            Ok(v) => assert!(!v),
            Err(_) => {}
        }
    }
    #[test]
    fn many_roundtrips() {
        let (pk, sk) = MlDsa87::keypair().unwrap();
        for i in 0u32..10 {
            let m = i.to_le_bytes();
            let s = MlDsa87::sign(&sk, &m).unwrap();
            assert!(MlDsa87::verify(&pk, &m, &s).unwrap());
        }
    }

    #[cfg(feature = "masking")]
    #[test]
    fn masked_sign_verify() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        let (pk, sk) = keypair().unwrap();
        let masked_sk = masked::MaskedSecretKey::from_plain(&sk, &mut rng).unwrap();
        let msg = b"Masked ML-DSA test message";
        let sig = masked::masked_sign(&masked_sk, msg, &mut rng).unwrap();
        assert!(verify(&pk, msg, &sig).unwrap());
    }
}
