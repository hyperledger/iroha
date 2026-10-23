//! GOST R 34.10-2012 signatures backed by `RustCrypto`'s Streebog hash.
//!
//! The elliptic-curve arithmetic uses a fixed-width backend layered on top of
//! `crypto-bigint` Montgomery field arithmetic with Jacobian point operations.
//! All field operations remain deterministic across platforms.
#[cfg(test)]
use core::ops::ShrAssign;
use core::{cmp::Ordering, fmt};
use num_bigint::BigUint;
#[cfg(test)]
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use rand::{RngCore, rngs::OsRng};
use rand_core::TryRngCore;
use std::sync::LazyLock;
use streebog::{Digest, Streebog256, Streebog512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[path = "gost/parameters.rs"]
mod parameters;

#[path = "gost/constant_time.rs"]
mod constant_time;
pub(crate) use constant_time::KeyRejection;

trait DeterministicNonceGenerator {
    fn generate(
        &mut self,
        params: &CurveParams,
        private_scalar: &BigUint,
        message: &[u8],
        extra_entropy: Option<&[u8]>,
    ) -> Result<BigUint, Error>;
}
const NONCE_DOMAIN_TAG: &[u8] = b"iroha:gost:nonce:v1";
struct StreebogNonceGenerator {
    domain_tag: &'static [u8],
}
impl StreebogNonceGenerator {
    fn new() -> Self {
        Self {
            domain_tag: NONCE_DOMAIN_TAG,
        }
    }
    #[cfg(test)]
    fn with_domain(domain_tag: &'static [u8]) -> Self {
        Self { domain_tag }
    }
}
impl Default for StreebogNonceGenerator {
    fn default() -> Self {
        Self::new()
    }
}
impl DeterministicNonceGenerator for StreebogNonceGenerator {
    fn generate(
        &mut self,
        params: &CurveParams,
        private_scalar: &BigUint,
        message: &[u8],
        extra_entropy: Option<&[u8]>,
    ) -> Result<BigUint, Error> {
        use num_traits::Zero as _;
        const BLOCK_LEN: usize = 64;
        let hash_len = params.digest_len;
        let mut k = Zeroizing::new(vec![0_u8; hash_len]);
        let mut v = Zeroizing::new(vec![0x01_u8; hash_len]);
        let private_octets = Zeroizing::new(int_to_octets(private_scalar, params.scalar_len));
        let message_octets = Zeroizing::new(bits_to_octets(params, message));
        k = hmac_streebog_nonce_seed(
            hash_len,
            BLOCK_LEN,
            k.as_slice(),
            NonceSeedParts {
                v: v.as_slice(),
                marker: &[0x00],
                domain_tag: self.domain_tag,
                private_octets: private_octets.as_slice(),
                message_octets: message_octets.as_slice(),
                extra_entropy,
            },
        )?;
        v = hmac_streebog(hash_len, BLOCK_LEN, k.as_slice(), &[v.as_slice()])?;
        k = hmac_streebog_nonce_seed(
            hash_len,
            BLOCK_LEN,
            k.as_slice(),
            NonceSeedParts {
                v: v.as_slice(),
                marker: &[0x01],
                domain_tag: self.domain_tag,
                private_octets: private_octets.as_slice(),
                message_octets: message_octets.as_slice(),
                extra_entropy,
            },
        )?;
        v = hmac_streebog(hash_len, BLOCK_LEN, k.as_slice(), &[v.as_slice()])?;
        loop {
            let mut t = Zeroizing::new(Vec::with_capacity(params.scalar_len));
            while t.len() < params.scalar_len {
                v = hmac_streebog(hash_len, BLOCK_LEN, k.as_slice(), &[v.as_slice()])?;
                t.extend_from_slice(&v);
            }
            let candidate = BigUint::from_bytes_be(&t[..params.scalar_len]);
            let nonce = candidate % &params.q;
            if !nonce.is_zero() {
                return Ok(nonce);
            }
            k = hmac_streebog(hash_len, BLOCK_LEN, k.as_slice(), &[v.as_slice(), &[0x00]])?;
            v = hmac_streebog(hash_len, BLOCK_LEN, k.as_slice(), &[v.as_slice()])?;
        }
    }
}
fn int_to_octets(value: &BigUint, length: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_be();
    match bytes.len().cmp(&length) {
        Ordering::Greater => {
            bytes = bytes[bytes.len() - length..].to_vec();
        }
        Ordering::Less => {
            let mut padded = vec![0_u8; length - bytes.len()];
            padded.extend_from_slice(&bytes);
            bytes = padded;
        }
        Ordering::Equal => {}
    }
    bytes
}
fn bits_to_octets(params: &CurveParams, message: &[u8]) -> Vec<u8> {
    let scalar = hash_to_scalar(params, message);
    int_to_octets(&scalar, params.scalar_len)
}
#[derive(Clone, Copy)]
struct NonceSeedParts<'a> {
    v: &'a [u8],
    marker: &'a [u8],
    domain_tag: &'a [u8],
    private_octets: &'a [u8],
    message_octets: &'a [u8],
    extra_entropy: Option<&'a [u8]>,
}
fn hmac_streebog_nonce_seed(
    digest_len: usize,
    block_len: usize,
    key: &[u8],
    parts: NonceSeedParts<'_>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    parts.extra_entropy.map_or_else(
        || {
            hmac_streebog(
                digest_len,
                block_len,
                key,
                &[
                    parts.v,
                    parts.marker,
                    parts.domain_tag,
                    parts.private_octets,
                    parts.message_octets,
                ],
            )
        },
        |extra| {
            hmac_streebog(
                digest_len,
                block_len,
                key,
                &[
                    parts.v,
                    parts.marker,
                    parts.domain_tag,
                    parts.private_octets,
                    parts.message_octets,
                    extra,
                ],
            )
        },
    )
}
fn hmac_streebog(
    digest_len: usize,
    block_len: usize,
    key: &[u8],
    data: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut key_block = Zeroizing::new(vec![0_u8; block_len]);
    if key.len() > block_len {
        let hashed = Zeroizing::new(streebog_hash(digest_len, &[key])?);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = Zeroizing::new(vec![0x36_u8; block_len]);
    let mut outer_pad = Zeroizing::new(vec![0x5c_u8; block_len]);
    for i in 0..block_len {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }
    let inner_hash = Zeroizing::new(streebog_hash_prefixed(
        digest_len,
        inner_pad.as_slice(),
        data,
    )?);
    Ok(Zeroizing::new(streebog_hash(
        digest_len,
        &[outer_pad.as_slice(), inner_hash.as_slice()],
    )?))
}
fn unsupported_streebog_digest_len(digest_len: usize) -> Error {
    Error::Signing(format!("unsupported Streebog digest length: {digest_len}"))
}
fn streebog_hash_prefixed(
    digest_len: usize,
    prefix: &[u8],
    parts: &[&[u8]],
) -> Result<Vec<u8>, Error> {
    match digest_len {
        32 => {
            let mut hasher = Streebog256::new();
            hasher.update(prefix);
            for part in parts {
                hasher.update(part);
            }
            Ok(hasher.finalize().to_vec())
        }
        64 => {
            let mut hasher = Streebog512::new();
            hasher.update(prefix);
            for part in parts {
                hasher.update(part);
            }
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(unsupported_streebog_digest_len(digest_len)),
    }
}
fn streebog_hash(digest_len: usize, parts: &[&[u8]]) -> Result<Vec<u8>, Error> {
    match digest_len {
        32 => {
            let mut hasher = Streebog256::new();
            for part in parts {
                hasher.update(part);
            }
            Ok(hasher.finalize().to_vec())
        }
        64 => {
            let mut hasher = Streebog512::new();
            for part in parts {
                hasher.update(part);
            }
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(unsupported_streebog_digest_len(digest_len)),
    }
}
use crate::{Algorithm, Error, ParseError, rng::rng_from_seed_slice};
/// Parsed GOST private key (little-endian scalar).
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey {
    bytes_le: Zeroizing<Vec<u8>>,
}
impl PrivateKey {
    /// Borrow the little-endian scalar bytes that back this private key.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes_le.as_ref()
    }
}
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED GOST PrivateKey]")
    }
}
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED GOST PrivateKey]")
    }
}
impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.bytes_le.zeroize();
    }
}
impl ZeroizeOnDrop for PrivateKey {}
/// Parsed GOST public key (little-endian `x || y` form).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    bytes_le: Vec<u8>,
}
impl PublicKey {
    /// Borrow the little-endian concatenated affine coordinates of this public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes_le
    }
}
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GostPublicKey")
            .field(&hex::encode_upper(&self.bytes_le))
            .finish()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AffinePoint {
    x: BigUint,
    y: BigUint,
}
impl AffinePoint {
    fn new(x: BigUint, y: BigUint) -> Self {
        Self { x, y }
    }
}
struct CurveParams {
    name: &'static str,
    p: BigUint,
    q: BigUint,
    a: BigUint,
    b: BigUint,
    gx: BigUint,
    gy: BigUint,
    scalar_len: usize,
    digest_len: usize,
}
impl CurveParams {
    fn generator(&self) -> AffinePoint {
        AffinePoint::new(self.gx.clone(), self.gy.clone())
    }
}
enum Params<'a> {
    Bits256(&'a CurveParams),
    Bits512(&'a CurveParams),
}
impl<'a> Params<'a> {
    fn curve(self) -> &'a CurveParams {
        match self {
            Params::Bits256(params) | Params::Bits512(params) => params,
        }
    }
}
fn params_for_algorithm(algorithm: Algorithm) -> Result<Params<'static>, ParseError> {
    match algorithm {
        Algorithm::Gost3410_2012_256ParamSetA => Ok(Params::Bits256(&PARAM_256_A)),
        Algorithm::Gost3410_2012_256ParamSetB => Ok(Params::Bits256(&PARAM_256_B)),
        Algorithm::Gost3410_2012_256ParamSetC => Ok(Params::Bits256(&PARAM_256_C)),
        Algorithm::Gost3410_2012_512ParamSetA => Ok(Params::Bits512(&PARAM_512_A)),
        Algorithm::Gost3410_2012_512ParamSetB => Ok(Params::Bits512(&PARAM_512_B)),
        other => Err(ParseError::Invalid(format!(
            "algorithm {other:?} is not a supported GOST parameter set"
        ))),
    }
}
fn curve_from_constants(constants: &parameters::CurveConstants) -> CurveParams {
    let p = be_hex(constants.p);
    CurveParams {
        name: constants.name,
        q: be_hex(constants.q),
        a: be_hex(constants.a) % &p,
        b: be_hex(constants.b) % &p,
        gx: be_hex(constants.gx) % &p,
        gy: be_hex(constants.gy) % &p,
        p,
        scalar_len: constants.scalar_len,
        digest_len: constants.scalar_len,
    }
}
static PARAM_256_A: LazyLock<CurveParams> =
    LazyLock::new(|| curve_from_constants(&parameters::PARAM_256_A));
static PARAM_256_B: LazyLock<CurveParams> =
    LazyLock::new(|| curve_from_constants(&parameters::PARAM_256_B));
static PARAM_256_C: LazyLock<CurveParams> =
    LazyLock::new(|| curve_from_constants(&parameters::PARAM_256_C));
static PARAM_512_A: LazyLock<CurveParams> =
    LazyLock::new(|| curve_from_constants(&parameters::PARAM_512_A));
static PARAM_512_B: LazyLock<CurveParams> =
    LazyLock::new(|| curve_from_constants(&parameters::PARAM_512_B));
fn be_hex(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid hex")
}
fn le_bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}
fn scalar_to_le_bytes(value: &BigUint, length: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_le();
    bytes.resize(length, 0);
    bytes
}
fn point_to_le_bytes(point: &AffinePoint, coord_len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coord_len * 2);
    bytes.extend_from_slice(&scalar_to_le_bytes(&point.x, coord_len));
    bytes.extend_from_slice(&scalar_to_le_bytes(&point.y, coord_len));
    bytes
}
fn mod_add(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    let mut sum = a + b;
    if sum >= *modulus {
        sum %= modulus;
    }
    sum
}
#[cfg(test)]
fn mod_sub(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % modulus
    } else {
        (modulus + a - b) % modulus
    }
}
fn mod_mul(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    ((a % modulus) * (b % modulus)) % modulus
}
fn mod_square(a: &BigUint, modulus: &BigUint) -> BigUint {
    a.modpow(&BigUint::from(2u8), modulus)
}
#[cfg(test)]
fn mod_inv(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        return None;
    }
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let mut new_r = BigInt::from_biguint(Sign::Plus, value.clone());
    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let tmp_t = t - &quotient * &new_t;
        t = new_t;
        new_t = tmp_t;
        let tmp_r = r - &quotient * &new_r;
        r = new_r;
        new_r = tmp_r;
    }
    if r != BigInt::one() {
        return None;
    }
    if t.sign() == Sign::Minus {
        t += BigInt::from_biguint(Sign::Plus, modulus.clone());
    }
    t.to_biguint()
}
fn is_on_curve(params: &CurveParams, point: &AffinePoint) -> bool {
    if point.x >= params.p || point.y >= params.p {
        return false;
    }
    let lhs = mod_square(&point.y, &params.p);
    let x2 = mod_square(&point.x, &params.p);
    let x3 = mod_mul(&x2, &point.x, &params.p);
    let ax = mod_mul(&params.a, &point.x, &params.p);
    let rhs = mod_add(&mod_add(&x3, &ax, &params.p), &params.b, &params.p);
    lhs == rhs
}
#[cfg(test)]
fn point_add(params: &CurveParams, p: &AffinePoint, q: &AffinePoint) -> Option<AffinePoint> {
    constant_time::point_add(params, p, q)
}
fn scalar_mul(params: &CurveParams, scalar: &BigUint, point: &AffinePoint) -> Option<AffinePoint> {
    if point.x == params.gx && point.y == params.gy {
        return constant_time::scalar_mul_base(params, scalar);
    }
    constant_time::scalar_mul(params, scalar, point)
}
#[cfg(test)]
#[allow(private_interfaces)]
pub(super) fn compat_point_add(
    params: &CurveParams,
    p: &AffinePoint,
    q: &AffinePoint,
) -> Option<AffinePoint> {
    let modulus = &params.p;
    if p.x == q.x {
        let neg_qy = mod_sub(modulus, &q.y, modulus);
        if p.y == neg_qy {
            return None;
        }
        let numerator = mod_add(
            &mod_mul(&BigUint::from(3u8), &mod_square(&p.x, modulus), modulus),
            &params.a,
            modulus,
        );
        let denominator = mod_mul(&BigUint::from(2u8), &p.y, modulus);
        let inv = mod_inv(&denominator, modulus)?;
        let lambda = mod_mul(&numerator, &inv, modulus);
        let x3 = mod_sub(
            &mod_sub(&mod_square(&lambda, modulus), &p.x, modulus),
            &q.x,
            modulus,
        );
        let y3 = mod_sub(
            &mod_mul(&lambda, &mod_sub(&p.x, &x3, modulus), modulus),
            &p.y,
            modulus,
        );
        Some(AffinePoint::new(x3, y3))
    } else {
        let numerator = mod_sub(&q.y, &p.y, modulus);
        let denominator = mod_sub(&q.x, &p.x, modulus);
        let inv = mod_inv(&denominator, modulus)?;
        let lambda = mod_mul(&numerator, &inv, modulus);
        let x3 = mod_sub(
            &mod_sub(&mod_square(&lambda, modulus), &p.x, modulus),
            &q.x,
            modulus,
        );
        let y3 = mod_sub(
            &mod_mul(&lambda, &mod_sub(&p.x, &x3, modulus), modulus),
            &p.y,
            modulus,
        );
        Some(AffinePoint::new(x3, y3))
    }
}
#[cfg(test)]
#[allow(private_interfaces)]
pub(super) fn compat_scalar_mul(
    params: &CurveParams,
    scalar: &BigUint,
    point: &AffinePoint,
) -> Option<AffinePoint> {
    if scalar.is_zero() {
        return None;
    }
    let mut k = scalar.clone();
    let mut result: Option<AffinePoint> = None;
    let mut addend = point.clone();
    let one = BigUint::one();
    while !k.is_zero() {
        if (&k & &one) == one {
            result = result.as_ref().map_or_else(
                || Some(addend.clone()),
                |current| compat_point_add(params, current, &addend),
            );
        }
        addend = compat_point_add(params, &addend, &addend)?;
        k.shr_assign(1u32);
    }
    result
}
fn hash_to_scalar(params: &CurveParams, message: &[u8]) -> BigUint {
    let mut digest = if params.digest_len == 32 {
        let mut hasher = Streebog256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    } else {
        let mut hasher = Streebog512::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    };
    digest.reverse();
    digest.resize(params.scalar_len, 0);
    let mut value = BigUint::from_bytes_le(&digest);
    value %= &params.q;
    if value.is_zero() {
        BigUint::one()
    } else {
        value
    }
}
fn increment_nonce(params: &CurveParams, current: &BigUint) -> BigUint {
    let mut next = current + BigUint::one();
    next %= &params.q;
    if next.is_zero() { BigUint::one() } else { next }
}
fn parse_private_generic(params: &CurveParams, payload: &[u8]) -> Result<PrivateKey, ParseError> {
    if payload.len() != params.scalar_len {
        return Err(ParseError::Invalid(format!(
            "invalid private key length for {}: expected {}, got {}",
            params.name,
            params.scalar_len,
            payload.len()
        )));
    }
    let scalar = le_bytes_to_biguint(payload);
    if scalar.is_zero() || scalar >= params.q {
        return Err(ParseError::Invalid(format!(
            "private key outside [1, q-1] for {}",
            params.name
        )));
    }
    Ok(PrivateKey {
        bytes_le: Zeroizing::new(payload.to_vec()),
    })
}
fn scalar_from_private(params: &CurveParams, key: &PrivateKey) -> Result<BigUint, Error> {
    if key.as_bytes().len() != params.scalar_len {
        return Err(Error::KeyGen(format!(
            "private key length mismatch for {}",
            params.name
        )));
    }
    Ok(le_bytes_to_biguint(key.as_bytes()))
}
#[cfg(test)]
fn point_from_public(params: &CurveParams, key: &PublicKey) -> Result<AffinePoint, Error> {
    if key.as_bytes().len() != params.scalar_len * 2 {
        return Err(Error::BadSignature);
    }
    if key.as_bytes().iter().all(|&byte| byte == 0) {
        return Err(Error::BadSignature);
    }
    let (x_bytes, y_bytes) = key.as_bytes().split_at(params.scalar_len);
    let point = AffinePoint::new(le_bytes_to_biguint(x_bytes), le_bytes_to_biguint(y_bytes));
    if !is_on_curve(params, &point) {
        return Err(Error::BadSignature);
    }
    Ok(point)
}
fn sign_impl(
    params: &CurveParams,
    message: &[u8],
    private: &PrivateKey,
    nonce_gen: &mut impl DeterministicNonceGenerator,
    extra_entropy: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let private_scalar = scalar_from_private(params, private)?;
    if private_scalar.is_zero() || private_scalar >= params.q {
        return Err(Error::KeyGen(format!(
            "private key outside [1, q-1] for {}",
            params.name
        )));
    }
    let mut message_scalar = hash_to_scalar(params, message);
    if message_scalar.is_zero() {
        message_scalar = BigUint::one();
    }
    let mut nonce = nonce_gen.generate(params, &private_scalar, message, extra_entropy)?;
    let generator = params.generator();
    loop {
        let point = if let Some(point) = scalar_mul(params, &nonce, &generator) {
            point
        } else {
            nonce = increment_nonce(params, &nonce);
            continue;
        };
        let r_component = &point.x % &params.q;
        if r_component.is_zero() {
            nonce = increment_nonce(params, &nonce);
            continue;
        }
        let private_term = (&r_component * &private_scalar) % &params.q;
        let message_term = (&nonce * &message_scalar) % &params.q;
        let s_component = (private_term + message_term) % &params.q;
        if s_component.is_zero() {
            nonce = increment_nonce(params, &nonce);
            continue;
        }
        let mut signature = Vec::with_capacity(params.scalar_len * 2);
        signature.extend_from_slice(&scalar_to_le_bytes(&r_component, params.scalar_len));
        signature.extend_from_slice(&scalar_to_le_bytes(&s_component, params.scalar_len));
        return Ok(signature);
    }
}
fn derive_public_impl(params: &CurveParams, private: &PrivateKey) -> Result<PublicKey, Error> {
    let scalar = scalar_from_private(params, private)?;
    let point = scalar_mul(params, &scalar, &params.generator())
        .ok_or_else(|| Error::KeyGen("failed to derive GOST public key".into()))?;
    if !is_on_curve(params, &point) {
        return Err(Error::KeyGen(
            "derived GOST public key is not on the curve".into(),
        ));
    }
    Ok(PublicKey {
        bytes_le: point_to_le_bytes(&point, params.scalar_len),
    })
}
fn random_scalar<R: RngCore>(params: &CurveParams, rng: &mut R) -> Result<BigUint, Error> {
    const MAX_DETERMINISTIC_SCALAR_ATTEMPTS: usize = 1024;
    let mut buf = Zeroizing::new(vec![0u8; params.scalar_len]);
    for _ in 0..MAX_DETERMINISTIC_SCALAR_ATTEMPTS {
        rng.fill_bytes(buf.as_mut_slice());
        let scalar = BigUint::from_bytes_le(buf.as_slice());
        if scalar.is_zero() || scalar >= params.q {
            continue;
        }
        return Ok(scalar);
    }
    Err(Error::KeyGen(
        "GOST deterministic RNG did not produce a valid scalar".to_owned(),
    ))
}
fn random_scalar_from_os(params: &CurveParams) -> Result<BigUint, Error> {
    random_scalar_from_rng(params, &mut OsRng)
}
fn random_scalar_from_rng<R>(params: &CurveParams, rng: &mut R) -> Result<BigUint, Error>
where
    R: TryRngCore,
    R::Error: fmt::Display,
{
    const MAX_RANDOM_SCALAR_ATTEMPTS: usize = 1024;
    let mut buf = Zeroizing::new(vec![0u8; params.scalar_len]);
    for _ in 0..MAX_RANDOM_SCALAR_ATTEMPTS {
        rng.try_fill_bytes(buf.as_mut_slice())
            .map_err(|err| Error::KeyGen(format!("GOST OS RNG failed: {err}")))?;
        if buf.iter().all(|&byte| byte == 0) {
            return Err(Error::KeyGen(
                "GOST OS RNG returned all-zero scalar material".to_owned(),
            ));
        }
        let scalar = BigUint::from_bytes_le(buf.as_slice());
        if !scalar.is_zero() && scalar < params.q {
            return Ok(scalar);
        }
    }
    Err(Error::KeyGen(
        "GOST OS RNG did not produce a valid scalar".to_owned(),
    ))
}
fn keypair_random_impl(params: &CurveParams) -> Result<(PublicKey, PrivateKey), Error> {
    let scalar = random_scalar_from_os(params)?;
    let private = PrivateKey {
        bytes_le: Zeroizing::new(scalar_to_le_bytes(&scalar, params.scalar_len)),
    };
    let public = derive_public_impl(params, &private)?;
    Ok((public, private))
}
fn keypair_seed_impl(params: &CurveParams, seed: &[u8]) -> Result<(PublicKey, PrivateKey), Error> {
    validate_seed_material_not_all_zero(seed)?;
    let mut rng = rng_from_seed_slice(seed);
    let scalar = random_scalar(params, &mut rng)?;
    let private = PrivateKey {
        bytes_le: Zeroizing::new(scalar_to_le_bytes(&scalar, params.scalar_len)),
    };
    let public = derive_public_impl(params, &private)?;
    Ok((public, private))
}
fn validate_seed_material_not_all_zero(seed: &[u8]) -> Result<(), Error> {
    if !seed.is_empty() && seed.iter().all(|&byte| byte == 0) {
        return Err(Error::KeyGen(
            "GOST seed material must not be all zero".to_owned(),
        ));
    }
    Ok(())
}
fn signing_entropy_from_os(params: &CurveParams) -> Result<Zeroizing<Vec<u8>>, Error> {
    signing_entropy_from_rng(params, &mut OsRng)
}
fn signing_entropy_from_rng<R>(
    params: &CurveParams,
    rng: &mut R,
) -> Result<Zeroizing<Vec<u8>>, Error>
where
    R: TryRngCore,
    R::Error: fmt::Display,
{
    let mut entropy = Zeroizing::new(vec![0u8; params.scalar_len]);
    rng.try_fill_bytes(entropy.as_mut_slice())
        .map_err(|err| Error::KeyGen(format!("GOST OS RNG failed: {err}")))?;
    if entropy.iter().all(|&byte| byte == 0) {
        return Err(Error::KeyGen(
            "GOST OS RNG returned all-zero signing entropy".to_owned(),
        ));
    }
    Ok(entropy)
}
/// Parse a serialized public key for the selected GOST parameter set.
///
/// # Errors
/// Returns [`ParseError`] when `payload` does not encode a valid public key for `algorithm`.
pub fn parse_public_key(algorithm: Algorithm, payload: &[u8]) -> Result<PublicKey, ParseError> {
    validate_public_key(algorithm, payload).map_err(KeyRejection::into_parse_error)?;
    Ok(PublicKey {
        bytes_le: payload.to_vec(),
    })
}
/// Parse a serialized private key for the selected GOST parameter set.
///
/// # Errors
/// Returns [`ParseError`] when `payload` does not encode a valid private key for `algorithm`.
pub fn parse_private_key(algorithm: Algorithm, payload: &[u8]) -> Result<PrivateKey, ParseError> {
    let params = params_for_algorithm(algorithm)?;
    parse_private_generic(params.curve(), payload)
}
/// Generate a random key pair.
///
/// # Errors
/// Returns [`Error::KeyGen`] if the parameter set is unsupported or key generation fails.
pub fn generate_random_keypair(algorithm: Algorithm) -> Result<(PublicKey, PrivateKey), Error> {
    let params = params_for_algorithm(algorithm).map_err(|err| Error::KeyGen(err.to_string()))?;
    keypair_random_impl(params.curve())
}
/// Generate a deterministic key pair from a seed.
///
/// # Errors
/// Returns [`Error::KeyGen`] if the parameter set is unsupported or the seed is rejected.
pub fn generate_seeded_keypair(
    algorithm: Algorithm,
    seed: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {
    let params = params_for_algorithm(algorithm).map_err(|err| Error::KeyGen(err.to_string()))?;
    keypair_seed_impl(params.curve(), seed)
}
/// Derive the matching public key from the given private key.
///
/// # Errors
/// Returns [`Error::KeyGen`] if `private` is invalid for `algorithm`.
pub fn derive_public_key(algorithm: Algorithm, private: &PrivateKey) -> Result<PublicKey, Error> {
    let params = params_for_algorithm(algorithm).map_err(|err| Error::KeyGen(err.to_string()))?;
    derive_public_impl(params.curve(), private)
}
/// Validate that the supplied public and private keys form a pair.
///
/// # Errors
/// Returns [`Error::KeyGen`] when the derived public key does not match `public`.
pub fn validate_key_pair(
    algorithm: Algorithm,
    public: &[u8],
    private: &PrivateKey,
) -> Result<(), Error> {
    let derived = derive_public_key(algorithm, private)?;
    if derived.as_bytes() == public {
        Ok(())
    } else {
        Err(Error::KeyGen("GOST key pair mismatch".into()))
    }
}
/// Sign a message with the specified private key.
///
/// # Errors
/// Returns [`Error::KeyGen`] if `algorithm` is unsupported or signing fails.
pub fn sign(algorithm: Algorithm, message: &[u8], private: &PrivateKey) -> Result<Vec<u8>, Error> {
    let params = params_for_algorithm(algorithm).map_err(|err| Error::KeyGen(err.to_string()))?;
    let curve = params.curve();
    let mut nonce_gen = StreebogNonceGenerator::new();
    let entropy = signing_entropy_from_os(curve)?;
    sign_impl(
        curve,
        message,
        private,
        &mut nonce_gen,
        Some(entropy.as_slice()),
    )
}
/// Verify a signature produced by the specified parameter set.
///
/// # Errors
/// Returns [`Error::BadSignature`] for invalid signatures or keys, and
/// [`Error::KeyGen`] when the parameter set is unsupported.
pub fn verify(
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    verify_bytes(algorithm, message, signature, public_key.as_bytes())
}
/// Validate a borrowed GOST public key without retaining decoded material.
pub(crate) fn validate_public_key(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(), KeyRejection> {
    constant_time::validate_public_key(algorithm, payload)
}

/// Verify borrowed canonical bytes through the shared fixed-width relation.
pub(crate) fn verify_bytes(
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
    public: &[u8],
) -> Result<(), Error> {
    constant_time::verify_bytes(algorithm, message, signature, public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{One, ToPrimitive};
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use std::{hint::black_box, time::Instant};
    const LEGACY_HMAC_BLOCK_LEN: usize = 64;
    fn seed_pair() -> (PublicKey, PrivateKey) {
        let seed = b"iroha-gost-test-seed";
        generate_seeded_keypair(Algorithm::Gost3410_2012_256ParamSetA, seed).unwrap()
    }
    struct FixedTryRng {
        byte: u8,
    }
    impl TryRngCore for FixedTryRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.byte; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.byte; 8]))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            dest.fill(self.byte);
            Ok(())
        }
    }
    fn legacy_hmac_streebog(
        digest_len: usize,
        block_len: usize,
        key: &[u8],
        data: &[&[u8]],
    ) -> Vec<u8> {
        let mut key_block = vec![0_u8; block_len];
        if key.len() > block_len {
            let hashed = streebog_hash(digest_len, &[key]).expect("legacy Streebog hash");
            key_block[..hashed.len()].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut inner_pad = vec![0x36_u8; block_len];
        let mut outer_pad = vec![0x5c_u8; block_len];
        for i in 0..block_len {
            inner_pad[i] ^= key_block[i];
            outer_pad[i] ^= key_block[i];
        }
        let mut inner_segments = Vec::with_capacity(data.len() + 1);
        inner_segments.push(inner_pad.as_slice());
        inner_segments.extend_from_slice(data);
        let inner_hash =
            streebog_hash(digest_len, &inner_segments).expect("legacy inner Streebog hash");
        streebog_hash(digest_len, &[outer_pad.as_slice(), inner_hash.as_slice()])
            .expect("legacy outer Streebog hash")
    }
    fn legacy_streebog_nonce(
        params: &CurveParams,
        domain_tag: &[u8],
        private_scalar: &BigUint,
        message: &[u8],
        extra_entropy: Option<&[u8]>,
    ) -> BigUint {
        let hash_len = params.digest_len;
        let mut k = vec![0_u8; hash_len];
        let mut v = vec![0x01_u8; hash_len];
        let mut seed = Vec::with_capacity(
            domain_tag.len() + params.scalar_len * 2 + extra_entropy.map_or(0, <[u8]>::len),
        );
        seed.extend_from_slice(domain_tag);
        seed.extend_from_slice(&int_to_octets(private_scalar, params.scalar_len));
        seed.extend_from_slice(&bits_to_octets(params, message));
        if let Some(extra) = extra_entropy {
            seed.extend_from_slice(extra);
        }
        k = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v, &[0x00], &seed]);
        v = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v]);
        k = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v, &[0x01], &seed]);
        v = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v]);
        loop {
            let mut t = Vec::with_capacity(params.scalar_len);
            while t.len() < params.scalar_len {
                v = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v]);
                t.extend_from_slice(&v);
            }
            let candidate = BigUint::from_bytes_be(&t[..params.scalar_len]);
            let nonce = candidate % &params.q;
            if !nonce.is_zero() {
                return nonce;
            }
            k = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v, &[0x00]]);
            v = legacy_hmac_streebog(hash_len, LEGACY_HMAC_BLOCK_LEN, &k, &[&v]);
        }
    }
    #[test]
    fn hmac_streebog_streaming_matches_legacy_inner_segments() {
        let key = [0xA5; 97];
        let tail = [0x42, 0x43, 0x44];
        let data: [&[u8]; 4] = [b"alpha", b"", b"beta", tail.as_slice()];
        for digest_len in [32, 64] {
            let actual = hmac_streebog(digest_len, LEGACY_HMAC_BLOCK_LEN, &key, &data)
                .expect("streaming HMAC Streebog");
            assert_eq!(
                actual.as_slice(),
                legacy_hmac_streebog(digest_len, LEGACY_HMAC_BLOCK_LEN, &key, &data).as_slice()
            );
        }
    }
    #[test]
    fn deterministic_nonce_streaming_matches_legacy_contiguous_seed() {
        let message = b"GOST nonce compatibility";
        let private_scalar = BigUint::from(42u32);
        for algorithm in [
            Algorithm::Gost3410_2012_256ParamSetA,
            Algorithm::Gost3410_2012_512ParamSetB,
        ] {
            let params = params_for_algorithm(algorithm).unwrap().curve();
            let extra_entropy = vec![0x5A; params.scalar_len + 7];
            for entropy in [None, Some(extra_entropy.as_slice())] {
                let mut generator = StreebogNonceGenerator::new();
                assert_eq!(
                    generator
                        .generate(params, &private_scalar, message, entropy)
                        .expect("nonce generation"),
                    legacy_streebog_nonce(
                        params,
                        NONCE_DOMAIN_TAG,
                        &private_scalar,
                        message,
                        entropy
                    )
                );
            }
        }
    }
    #[test]
    fn sign_verify_roundtrip() {
        let (public, private) = seed_pair();
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let public_point = point_from_public(params, &public).unwrap();
        assert!(is_on_curve(params, &public_point));
        let message = b"test message for gost";
        let signature = sign(Algorithm::Gost3410_2012_256ParamSetA, message, &private).unwrap();
        let result = verify(
            Algorithm::Gost3410_2012_256ParamSetA,
            message,
            &signature,
            &public,
        );
        result.unwrap();
    }
    #[test]
    fn signature_deterministic_without_extra_entropy() {
        let (_, private) = seed_pair();
        let message = b"deterministic nonce check";
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let mut gen1 = StreebogNonceGenerator::new();
        let sig1 = sign_impl(params, message, &private, &mut gen1, None).unwrap();
        let mut gen2 = StreebogNonceGenerator::new();
        let sig2 = sign_impl(params, message, &private, &mut gen2, None).unwrap();
        assert_eq!(sig1, sig2);
    }
    #[test]
    fn signature_changes_with_extra_entropy() {
        let (_, private) = seed_pair();
        let message = b"hedged entropy nonce check";
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let mut gen1 = StreebogNonceGenerator::new();
        let extra1 = vec![0xAA; params.scalar_len];
        let sig1 = sign_impl(
            params,
            message,
            &private,
            &mut gen1,
            Some(extra1.as_slice()),
        )
        .unwrap();
        let mut gen2 = StreebogNonceGenerator::new();
        let extra2 = vec![0xBB; params.scalar_len];
        let sig2 = sign_impl(
            params,
            message,
            &private,
            &mut gen2,
            Some(extra2.as_slice()),
        )
        .unwrap();
        assert_ne!(sig1, sig2);
    }
    #[test]
    fn gost_sign_constant_time_under_dudect() {
        let algorithms = [
            Algorithm::Gost3410_2012_256ParamSetA,
            Algorithm::Gost3410_2012_256ParamSetB,
            Algorithm::Gost3410_2012_256ParamSetC,
            Algorithm::Gost3410_2012_512ParamSetA,
            Algorithm::Gost3410_2012_512ParamSetB,
        ];
        for algorithm in algorithms {
            run_dudect_timing_check(algorithm);
        }
    }
    fn run_dudect_timing_check(algorithm: Algorithm) {
        const SAMPLES_PER_CLASS: usize = 40;
        const WARMUP_ITERATIONS: usize = 20;
        let params = match params_for_algorithm(algorithm).unwrap() {
            Params::Bits512(params) | Params::Bits256(params) => params,
        };
        let (_, private) = generate_seeded_keypair(algorithm, b"dudect-gost-keyseed")
            .expect("seeded keypair for dudect");
        let zero_message = vec![0u8; 64];
        let mut random_message = zero_message.clone();
        let mut rng = StdRng::from_seed([0x42; 32]);
        let mut class0 = Vec::with_capacity(SAMPLES_PER_CLASS);
        let mut class1 = Vec::with_capacity(SAMPLES_PER_CLASS);
        let total_iterations = (SAMPLES_PER_CLASS * 2) + WARMUP_ITERATIONS;
        for iteration in 0..total_iterations {
            let class_is_zero = iteration % 2 == 0;
            let message = if class_is_zero {
                zero_message.as_slice()
            } else {
                rng.fill_bytes(random_message.as_mut_slice());
                random_message.as_slice()
            };
            let mut nonce_gen = StreebogNonceGenerator::new();
            let start = Instant::now();
            let signature =
                sign_impl(params, message, &private, &mut nonce_gen, None).expect("sign");
            black_box(signature);
            let elapsed = start.elapsed().as_secs_f64();
            if iteration < WARMUP_ITERATIONS {
                continue;
            }
            if class_is_zero {
                class0.push(elapsed);
            } else {
                class1.push(elapsed);
            }
        }
        assert_eq!(
            class0.len(),
            SAMPLES_PER_CLASS,
            "class0 samples missing for {algorithm:?}"
        );
        assert_eq!(
            class1.len(),
            SAMPLES_PER_CLASS,
            "class1 samples missing for {algorithm:?}"
        );
        let t_stat = welch_t(&class0, &class1);
        assert!(
            t_stat.abs() < 5.0,
            "GOST signer for {algorithm:?} failed dudect check: t-statistic={t_stat}"
        );
    }
    #[test]
    fn seeded_keypair_reproducible() {
        let seed = b"seeded gost keypair";
        let (public1, private1) =
            generate_seeded_keypair(Algorithm::Gost3410_2012_256ParamSetB, seed).unwrap();
        let (public2, private2) =
            generate_seeded_keypair(Algorithm::Gost3410_2012_256ParamSetB, seed).unwrap();
        assert_eq!(public1.as_bytes(), public2.as_bytes());
        assert_eq!(private1.as_bytes(), private2.as_bytes());
    }
    #[test]
    fn seeded_keypair_rejects_all_zero_seed_material() {
        let err = generate_seeded_keypair(Algorithm::Gost3410_2012_256ParamSetB, &[0u8; 32])
            .expect_err("all-zero GOST seed material must fail");
        assert!(matches!(
            err,
            Error::KeyGen(message) if message.contains("all zero")
        ));
    }
    #[test]
    fn random_scalar_rejects_all_zero_rng_material() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let mut rng = FixedTryRng { byte: 0 };
        let err = random_scalar_from_rng(params, &mut rng)
            .expect_err("all-zero GOST scalar material must fail");
        assert!(matches!(
            err,
            Error::KeyGen(message) if message.contains("all-zero scalar material")
        ));
    }
    #[test]
    fn signing_entropy_rejects_all_zero_rng_material() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let mut rng = FixedTryRng { byte: 0 };
        let err = signing_entropy_from_rng(params, &mut rng)
            .expect_err("all-zero GOST signing entropy must fail");
        assert!(matches!(
            err,
            Error::KeyGen(message) if message.contains("all-zero signing entropy")
        ));
    }
    #[test]
    fn random_keypair_signs_and_verifies() {
        let (public, private) = generate_random_keypair(Algorithm::Gost3410_2012_256ParamSetA)
            .expect("checked random keypair");
        let message = b"checked GOST random keypair";
        let signature = sign(Algorithm::Gost3410_2012_256ParamSetA, message, &private)
            .expect("checked random signing entropy");
        verify(
            Algorithm::Gost3410_2012_256ParamSetA,
            message,
            &signature,
            &public,
        )
        .expect("verify");
    }
    #[test]
    fn verify_rejects_modified_message() {
        let (public, private) = seed_pair();
        let message = b"sign me";
        let signature = sign(Algorithm::Gost3410_2012_256ParamSetA, message, &private).unwrap();
        let tampered = b"sign me?";
        assert!(
            verify(
                Algorithm::Gost3410_2012_256ParamSetA,
                tampered,
                &signature,
                &public
            )
            .is_err()
        );
    }
    #[test]
    fn sign_verify_roundtrip_512() {
        let seed = b"gost-512-roundtrip";
        let (public, private) =
            generate_seeded_keypair(Algorithm::Gost3410_2012_512ParamSetB, seed).unwrap();
        let message = b"512-bit gost roundtrip";
        let signature =
            sign(Algorithm::Gost3410_2012_512ParamSetB, message, &private).expect("sign");
        verify(
            Algorithm::Gost3410_2012_512ParamSetB,
            message,
            &signature,
            &public,
        )
        .expect("verify");
    }
    #[test]
    fn reject_invalid_key_sizes() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        // Private key must be exactly scalar_len bytes.
        assert!(parse_private_generic(params, &[0x01]).is_err());
        // Public key must be 2 * scalar_len bytes.
        assert!(parse_public_key(Algorithm::Gost3410_2012_256ParamSetA, &[0x02; 10]).is_err());
    }
    #[test]
    fn parse_public_key_rejects_all_zero_payloads() {
        for algorithm in [
            Algorithm::Gost3410_2012_256ParamSetA,
            Algorithm::Gost3410_2012_256ParamSetB,
            Algorithm::Gost3410_2012_256ParamSetC,
            Algorithm::Gost3410_2012_512ParamSetA,
            Algorithm::Gost3410_2012_512ParamSetB,
        ] {
            let params = params_for_algorithm(algorithm).unwrap().curve();
            let payload = vec![0u8; params.scalar_len * 2];
            let err = parse_public_key(algorithm, &payload)
                .expect_err("all-zero GOST public-key payload must fail");
            assert!(
                err.to_string().contains("all zero"),
                "unexpected error for {algorithm:?}: {err}"
            );
        }
    }
    #[test]
    fn verify_rejects_internal_all_zero_public_key() {
        let (public, private) = seed_pair();
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let message = b"reject zero GOST verifier key";
        let signature = sign(Algorithm::Gost3410_2012_256ParamSetA, message, &private)
            .expect("valid GOST signature");
        let zero_public = PublicKey {
            bytes_le: vec![0u8; public.as_bytes().len()],
        };
        let err = verify(
            Algorithm::Gost3410_2012_256ParamSetA,
            message,
            &signature,
            &zero_public,
        )
        .expect_err("all-zero GOST verifier key must fail");
        assert!(matches!(err, Error::BadSignature));
        assert_eq!(zero_public.as_bytes().len(), params.scalar_len * 2);
    }
    #[test]
    fn generator_is_on_curve() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        assert!(is_on_curve(params, &params.generator()));
    }
    #[test]
    fn generator_is_on_curve_512() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_512ParamSetA).unwrap() {
            Params::Bits512(params) => params,
            _ => unreachable!(),
        };
        let generator = params.generator();
        let lhs = mod_square(&generator.y, &params.p);
        let x2 = mod_square(&generator.x, &params.p);
        let x3 = mod_mul(&x2, &generator.x, &params.p);
        let ax = mod_mul(&params.a, &generator.x, &params.p);
        let rhs = mod_add(&mod_add(&x3, &ax, &params.p), &params.b, &params.p);
        assert_eq!(lhs, rhs);
        assert!(is_on_curve(params, &generator));
    }
    #[test]
    fn scalar_mul_matches_repeated_addition() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let generator = params.generator();
        let two = scalar_mul(params, &BigUint::from(2u8), &generator).unwrap();
        let expected_two = point_add(params, &generator, &generator).unwrap();
        assert_eq!(two.x, expected_two.x);
        assert_eq!(two.y, expected_two.y);
        let three = scalar_mul(params, &BigUint::from(3u8), &generator).unwrap();
        let expected_three = point_add(params, &expected_two, &generator).unwrap();
        assert_eq!(three.x, expected_three.x);
        assert_eq!(three.y, expected_three.y);
    }
    #[test]
    fn mul_add_matches_compat() {
        let mut rng = crate::rng::rng_from_seed(b"gost-mul-add".to_vec());
        for algorithm in [
            Algorithm::Gost3410_2012_256ParamSetA,
            Algorithm::Gost3410_2012_256ParamSetB,
            Algorithm::Gost3410_2012_256ParamSetC,
            Algorithm::Gost3410_2012_512ParamSetA,
            Algorithm::Gost3410_2012_512ParamSetB,
        ] {
            let params_variant = params_for_algorithm(algorithm).unwrap();
            let params = params_variant.curve();
            for _ in 0..8 {
                let scalar_g = random_scalar(params, &mut rng).expect("valid scalar g");
                let scalar_q = random_scalar(params, &mut rng).expect("valid scalar q");
                let point_scalar = random_scalar(params, &mut rng).expect("valid point scalar");
                let q_point = match compat_scalar_mul(params, &point_scalar, &params.generator()) {
                    Some(point) => point,
                    None => continue,
                };
                let actual =
                    constant_time::mul_add_for_test(algorithm, &scalar_g, &scalar_q, &q_point);
                let expected = {
                    let part_g = compat_scalar_mul(params, &scalar_g, &params.generator());
                    let part_q = compat_scalar_mul(params, &scalar_q, &q_point);
                    match (part_g, part_q) {
                        (Some(g), Some(q)) => compat_point_add(params, &g, &q),
                        (Some(g), None) => Some(g),
                        (None, Some(q)) => Some(q),
                        (None, None) => None,
                    }
                };
                match (actual, expected) {
                    (None, None) => {}
                    (Some(a), Some(e)) => {
                        assert_eq!(a.x, e.x, "algorithm {algorithm:?}");
                        assert_eq!(a.y, e.y, "algorithm {algorithm:?}");
                        assert!(is_on_curve(params, &a));
                    }
                    (left, right) => {
                        panic!(
                            "mul_add mismatch for {algorithm:?}: actual={left:?}, expected={right:?}"
                        )
                    }
                }
            }
        }
    }
    #[test]
    fn deterministic_nonce_uses_domain_separation() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let secret = BigUint::from(42u32);
        let message = b"domain separation check";
        let mut generator_with_tag = StreebogNonceGenerator::new();
        let nonce_with_domain = generator_with_tag
            .generate(params, &secret, message, None)
            .expect("nonce with domain");
        let mut generator_without_tag = StreebogNonceGenerator::with_domain(b"");
        let nonce_without_domain = generator_without_tag
            .generate(params, &secret, message, None)
            .expect("nonce without domain");
        assert_ne!(nonce_with_domain, nonce_without_domain);
    }
    #[test]
    fn deterministic_nonce_rejects_unsupported_streebog_digest_len_without_panic() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let invalid_params = CurveParams {
            name: "invalid-streebog-digest-test",
            p: params.p.clone(),
            q: params.q.clone(),
            a: params.a.clone(),
            b: params.b.clone(),
            gx: params.gx.clone(),
            gy: params.gy.clone(),
            scalar_len: params.scalar_len,
            digest_len: 48,
        };
        let mut generator = StreebogNonceGenerator::new();
        let err = generator
            .generate(
                &invalid_params,
                &BigUint::from(42_u32),
                b"invalid digest length",
                None,
            )
            .expect_err("unsupported digest length must fail closed");
        assert!(
            matches!(err, Error::Signing(ref message) if message.contains("unsupported Streebog digest length: 48")),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    #[ignore = "emits fixture data for Wycheproof compatibility checks"]
    fn dump_wycheproof_vectors() {
        let message = b"Wycheproof deterministic message";
        for (algorithm, seed) in [
            (
                Algorithm::Gost3410_2012_256ParamSetA,
                b"wycheproof-gost-256-a".as_slice(),
            ),
            (
                Algorithm::Gost3410_2012_256ParamSetB,
                b"wycheproof-gost-256-b".as_slice(),
            ),
            (
                Algorithm::Gost3410_2012_256ParamSetC,
                b"wycheproof-gost-256-c".as_slice(),
            ),
            (
                Algorithm::Gost3410_2012_512ParamSetA,
                b"wycheproof-gost-512-a".as_slice(),
            ),
            (
                Algorithm::Gost3410_2012_512ParamSetB,
                b"wycheproof-gost-512-b".as_slice(),
            ),
        ] {
            let (public, private) = generate_seeded_keypair(algorithm, seed).expect("keypair");
            let params = params_for_algorithm(algorithm).expect("params").curve();
            let mut generator = StreebogNonceGenerator::new();
            let signature =
                sign_impl(params, message, &private, &mut generator, None).expect("sign");
            let mut invalid_signature = signature.clone();
            invalid_signature[0] ^= 0x01;
            println!(
                "{{\"algorithm\":\"{alg:?}\",\"public\":\"{public}\",\"message\":\"{msg}\",\"valid\":\"{sig}\",\"invalid\":\"{bad}\"}}",
                alg = algorithm,
                public = hex::encode(public.as_bytes()),
                msg = hex::encode(message),
                sig = hex::encode(signature),
                bad = hex::encode(invalid_signature),
            );
        }
    }
    fn welch_t(class0: &[f64], class1: &[f64]) -> f64 {
        fn mean(samples: &[f64]) -> f64 {
            let len = samples.len();
            if len == 0 {
                return 0.0;
            }
            let len = len.to_f64().expect("sample length fits into f64 mantissa");
            samples.iter().sum::<f64>() / len
        }
        fn variance(samples: &[f64], mean: f64) -> f64 {
            if samples.len() < 2 {
                return 0.0;
            }
            let sum = samples
                .iter()
                .map(|value| {
                    let diff = value - mean;
                    diff * diff
                })
                .sum::<f64>();
            let denom = (samples.len() - 1)
                .to_f64()
                .expect("sample length fits into f64 mantissa");
            sum / denom
        }
        let mean0 = mean(class0);
        let mean1 = mean(class1);
        let var0 = variance(class0, mean0);
        let var1 = variance(class1, mean1);
        let len0 = class0
            .len()
            .to_f64()
            .expect("class length fits into f64 mantissa");
        let len1 = class1
            .len()
            .to_f64()
            .expect("class length fits into f64 mantissa");
        let denom = (var0 / len0) + (var1 / len1);
        if denom == 0.0 {
            0.0
        } else {
            (mean0 - mean1) / denom.sqrt()
        }
    }
    fn increment_le_bytes(bytes: &mut [u8]) {
        let mut carry = 1u16;
        for byte in bytes.iter_mut() {
            let sum = u16::from(*byte) + carry;
            *byte = u8::try_from(sum & 0x00ff).expect("low byte must fit");
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }
    struct StubRng {
        samples: Vec<Vec<u8>>,
        idx: usize,
    }
    impl StubRng {
        fn new(samples: Vec<Vec<u8>>) -> Self {
            Self { samples, idx: 0 }
        }
    }
    impl RngCore for StubRng {
        fn next_u32(&mut self) -> u32 {
            panic!("next_u32 not supported in StubRng");
        }
        fn next_u64(&mut self) -> u64 {
            panic!("next_u64 not supported in StubRng");
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let sample = self
                .samples
                .get(self.idx)
                .expect("StubRng ran out of samples");
            self.idx += 1;
            assert_eq!(
                sample.len(),
                dest.len(),
                "StubRng sample length must match destination length"
            );
            dest.copy_from_slice(sample);
        }
    }
    struct FixedRng {
        byte: u8,
    }
    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.byte; 4])
        }
        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.byte; 8])
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.byte);
        }
    }
    #[test]
    fn random_scalar_rejects_zero_and_out_of_range_samples() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let zero = vec![0u8; params.scalar_len];
        let mut q_bytes = params.q.to_bytes_le();
        q_bytes.resize(params.scalar_len, 0);
        let mut q_plus_one = q_bytes.clone();
        increment_le_bytes(&mut q_plus_one);
        let mut high = vec![0xFF; params.scalar_len];
        // Ensure `high` is still >= q by setting high bit if needed.
        if high < q_bytes {
            high[params.scalar_len - 1] = 0xFF;
        }
        let mut valid = (&params.q - BigUint::one()).to_bytes_le();
        valid.resize(params.scalar_len, 0);
        let samples = vec![zero, q_bytes, q_plus_one, high, valid.clone()];
        let mut rng = StubRng::new(samples);
        let scalar = random_scalar(params, &mut rng).expect("valid scalar after invalid samples");
        assert_eq!(scalar, &params.q - BigUint::one());
    }
    #[test]
    fn random_scalar_rejects_repeated_invalid_deterministic_samples() {
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_256ParamSetA).unwrap() {
            Params::Bits256(params) => params,
            _ => unreachable!(),
        };
        let mut rng = FixedRng { byte: 0 };
        let err = random_scalar(params, &mut rng)
            .expect_err("repeated all-zero deterministic scalar samples must fail");
        assert!(matches!(
            err,
            Error::KeyGen(message) if message.contains("did not produce a valid scalar")
        ));
    }
    #[test]
    fn biguint_mod_matches_python() {
        use num_bigint::BigUint as NumBigUint;
        let p = NumBigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
            16,
        )
        .unwrap();
        let gy = NumBigUint::parse_bytes(
            b"7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4",
            16,
        )
        .unwrap();
        let params = match params_for_algorithm(Algorithm::Gost3410_2012_512ParamSetA).unwrap() {
            Params::Bits512(params) => params,
            _ => unreachable!(),
        };
        assert_eq!(params.gy, gy);
        assert_eq!(params.p, p);
        let lhs = (&gy * &gy) % &p;
        assert_eq!(
            lhs.to_str_radix(16),
            "e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c772"
        );
    }
}
