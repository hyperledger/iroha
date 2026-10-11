//! Support types for SM2/SM3/SM4 primitives.
#[cfg(feature = "sm-ffi-openssl")]
pub use self::openssl_sm::{OpenSslSmBackend, OpenSslSmError};
#[cfg(feature = "sm-ffi-openssl")]
mod openssl_dispatch;
pub(crate) mod verification;

use crate::Algorithm;
use crate::{
    Error, ParseError,
    secrecy::{ExposeSecret, Secret},
    signature::sm,
};
use core::{convert::TryFrom, fmt, str::FromStr};
use derive_more::{Deref, DerefMut};
use hex_literal::hex;
use iroha_schema::{IntoSchema, TypeId};
#[cfg(feature = "json")]
use norito::json::{self, FastJsonWrite, JsonDeserialize, JsonSerialize};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha512};
use signature::Signer;
use sm2::{
    PublicKey as Sm2EcPublicKey, SecretKey,
    dsa::{Signature as Sm2RawSignature, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use sm3::digest::Digest as _;
use sm4::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit as Sm4BlockKeyInit};
use sm4_gcm::{Sm4Key as Sm4AeadKey, sm4_gcm_aad_decrypt, sm4_gcm_aad_encrypt};
use std::sync::{OnceLock, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
const SM2_DISTID_INITIAL: &str = "1234567812345678";
const SM2_EQUATION_A_BYTES: [u8; 32] =
    hex!("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
const SM2_EQUATION_B_BYTES: [u8; 32] =
    hex!("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
const SM2_GENERATOR_X_BYTES: [u8; 32] =
    hex!("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
const SM2_GENERATOR_Y_BYTES: [u8; 32] =
    hex!("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
const SM2_DISTID_LEN_BYTES: usize = 2;
const SM2_PRIVATE_KEY_LEN: usize = 32;
const SM2_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
const SM2_RANDOM_KEY_ATTEMPTS: usize = 1024;
fn validate_distid(distid: &str) -> Result<(), ParseError> {
    verification::identity_bits(distid)
        .map(drop)
        .map_err(verification::KeyRejection::into_parse_error)
}
fn distid_len_prefix(distid: &str) -> Result<[u8; SM2_DISTID_LEN_BYTES], ParseError> {
    validate_distid(distid)?;
    let len = u16::try_from(distid.len())
        .map_err(|_| ParseError("SM2 distinguishing identifier length exceeds u16".into()))?;
    Ok(len.to_be_bytes())
}
fn split_sm2_payload(payload: &[u8]) -> Result<(&str, &[u8]), ParseError> {
    verification::split_payload(payload).map_err(verification::KeyRejection::into_parse_error)
}
fn encode_pem(label: &str, der: &[u8]) -> String {
    const PEM_WRAP: usize = 64;
    let encoded = base64_encode(der);
    let mut pem = String::new();
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for start in (0..encoded.len()).step_by(PEM_WRAP) {
        let end = start.saturating_add(PEM_WRAP).min(encoded.len());
        pem.push_str(&encoded[start..end]);
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}
const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let n = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        out.push(BASE64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(BASE64_TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(BASE64_TABLE[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut n = u32::from(rem[0]) << 16;
        if rem.len() == 2 {
            n |= u32::from(rem[1]) << 8;
        }
        out.push(BASE64_TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_TABLE[((n >> 12) & 0x3F) as usize] as char);
        if rem.len() == 2 {
            out.push(BASE64_TABLE[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}
fn distid_lock() -> &'static RwLock<String> {
    static LOCK: OnceLock<RwLock<String>> = OnceLock::new();
    LOCK.get_or_init(|| RwLock::new(SM2_DISTID_INITIAL.to_owned()))
}
/// SM2 private key wrapper retaining the distinguishing ID (`distid`) used during signing.
#[derive(Clone)]
pub struct Sm2PrivateKey {
    distid: String,
    secret: Secret<Zeroizing<[u8; 32]>>,
}
/// Wrapper around an SM2 verifying key (public key).
#[derive(Clone, TypeId)]
pub struct Sm2PublicKey(VerifyingKey);
impl fmt::Debug for Sm2PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Sm2PublicKey")
            .field(&hex::encode_upper(self.to_sec1_bytes(false)))
            .finish()
    }
}
impl Sm2PublicKey {
    /// Default distinguishing ID used when none is supplied by higher layers.
    pub const DEFAULT_DISTID: &'static str = SM2_DISTID_INITIAL;
    fn read_default_distid() -> String {
        match distid_lock().read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
    fn write_default_distid(distid: impl Into<String>) {
        let mut guard = match distid_lock().write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = distid.into();
    }
    /// Return the currently configured default distinguishing identifier.
    pub fn default_distid() -> String {
        Self::read_default_distid()
    }
    /// Override the global default distinguishing identifier used when callers omit one.
    ///
    /// # Errors
    /// Returns [`ParseError`] when `distid` is invalid.
    pub fn set_default_distid(distid: impl Into<String>) -> Result<(), ParseError> {
        let distid = distid.into();
        validate_distid(&distid)?;
        Self::write_default_distid(distid);
        Ok(())
    }
    pub(crate) fn from_verifying_key(key: VerifyingKey) -> Self {
        Self(key)
    }
    /// Construct a public key from SEC1-encoded bytes.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the provided bytes are not a valid SM2 point.
    pub fn from_sec1_bytes(distid: impl AsRef<str>, bytes: &[u8]) -> Result<Self, ParseError> {
        let distid = distid.as_ref();
        let point = verification::parse_point(distid, bytes)
            .map_err(verification::KeyRejection::into_parse_error)?;
        VerifyingKey::new(distid, point)
            .map(Self)
            .map_err(|_| ParseError("invalid SM2 public key".to_owned()))
    }
    /// Construct a public key from a hex-encoded SEC1 byte string.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the string is not valid hex or the key is malformed.
    pub fn from_hex(distid: impl AsRef<str>, bytes: impl AsRef<str>) -> Result<Self, ParseError> {
        let raw =
            hex::decode(bytes.as_ref()).map_err(|err| ParseError(format!("invalid hex: {err}")))?;
        Self::from_sec1_bytes(distid, &raw)
    }
    /// Export the public key as SEC1 bytes.
    pub fn to_sec1_bytes(&self, compressed: bool) -> Vec<u8> {
        self.0.to_encoded_point(compressed).as_bytes().to_vec()
    }
    /// Return the distinguishing identifier embedded in this verifying key.
    pub fn distid(&self) -> &str {
        self.0.distid()
    }
    /// Construct a public key from a PEM-encoded `SubjectPublicKeyInfo` document.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the PEM cannot be decoded or contains an invalid SM2 key.
    pub fn from_public_key_pem(distid: impl AsRef<str>, pem: &str) -> Result<Self, ParseError> {
        use sm2::pkcs8::DecodePublicKey;
        let encoded_point = Sm2EcPublicKey::from_public_key_pem(pem)
            .map_err(|err| ParseError(format!("failed to decode SM2 public key PEM: {err}")))?
            .to_encoded_point(false);
        Self::from_sec1_bytes(distid, encoded_point.as_bytes())
    }
    /// Export the public key as a `SubjectPublicKeyInfo` DER document.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the key cannot be encoded.
    pub fn to_public_key_der(&self) -> Result<Vec<u8>, ParseError> {
        let public = Sm2EcPublicKey::from_affine(*self.0.as_affine()).map_err(|_| {
            ParseError("failed to project SM2 public key into affine coordinates".into())
        })?;
        public
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|err| ParseError(format!("failed to encode SM2 public key to DER: {err}")))
    }
    /// Export the public key as a PEM-encoded `SubjectPublicKeyInfo` string.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the key cannot be encoded.
    pub fn to_public_key_pem(&self) -> Result<String, ParseError> {
        self.to_public_key_der()
            .map(|der| encode_pem("PUBLIC KEY", &der))
    }
    /// Fallibly format as an algorithm-prefixed multihash string (e.g., `sm2:...`),
    /// embedding the distinguishing identifier alongside the SEC1 payload.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the public key payload cannot be encoded into
    /// the canonical SM2 multihash form.
    pub fn try_to_prefixed_string(&self) -> Result<String, ParseError> {
        let sec1 = self.to_sec1_bytes(false);
        let payload = encode_sm2_public_key_payload(self.distid(), &sec1)?;
        Ok(crate::multihash::encode_public_key_prefixed(
            Algorithm::Sm2,
            &payload,
        ))
    }
    /// Format as an algorithm-prefixed multihash string (e.g., `sm2:...`),
    /// embedding the distinguishing identifier alongside the SEC1 payload.
    #[must_use]
    pub fn to_prefixed_string(&self) -> String {
        self.try_to_prefixed_string().unwrap_or_else(|_| {
            format!(
                "invalid-sm2-public-key:{}",
                hex::encode(self.to_sec1_bytes(false))
            )
        })
    }
    /// Verify a message against the provided signature.
    ///
    /// # Errors
    /// Returns [`Error::BadSignature`] when verification fails.
    /// The canonical SM2 relation is independent of optional OpenSSL SM3/SM4 acceleration.
    pub fn verify(&self, message: &[u8], signature: &Sm2Signature) -> Result<(), Error> {
        let identity_hash = verification::identity_hash(self.distid(), self.0.as_affine())
            .map_err(|_| Error::BadSignature)?;
        verification::verify(
            self.0.as_affine(),
            &identity_hash,
            message,
            &signature.as_bytes(),
        )
    }

    pub(crate) fn into_compact(self) -> Result<crate::PublicKey, ParseError> {
        let encoded = self.0.to_encoded_point(false);
        let payload = encode_sm2_public_key_payload(self.distid(), encoded.as_bytes())?;
        Ok(crate::PublicKey(crate::PublicKeyCompact::new(
            Algorithm::Sm2,
            &payload,
        )))
    }
    /// Borrow the inner SM2 verifying key.
    pub fn as_inner(&self) -> &VerifyingKey {
        &self.0
    }
    /// Compute the SM2 user information hash (`Z`) for the provided distinguishing identifier.
    ///
    /// The output follows GM/T 0003-2012 Annex D (`ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)`).
    ///
    /// # Errors
    /// Returns [`ParseError`] when the distinguishing identifier length exceeds `u16::MAX` bits or the public key
    /// cannot be represented as an uncompressed SEC1 point.
    pub fn compute_z(&self, distid: &str) -> Result<[u8; 32], ParseError> {
        verification::identity_hash(distid, self.0.as_affine())
            .map_err(verification::KeyRejection::into_parse_error)
    }
}
impl PartialEq for Sm2PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.distid() == other.distid()
            && self.0.to_encoded_point(false) == other.0.to_encoded_point(false)
    }
}
impl Eq for Sm2PublicKey {}
impl Sm2PrivateKey {
    /// Construct an SM2 private key from raw 32-byte secret material.
    ///
    /// # Errors
    /// Returns [`ParseError`] if `secret` is not a valid SM2 scalar.
    pub fn new(distid: impl Into<String>, mut secret: [u8; 32]) -> Result<Self, ParseError> {
        let key = Self::from_bytes(distid, &secret);
        secret.zeroize();
        key
    }
    /// Parse an SM2 private key from a byte slice.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the slice is not exactly 32 bytes or contains an invalid scalar.
    pub fn from_bytes(distid: impl Into<String>, secret: &[u8]) -> Result<Self, ParseError> {
        if secret.len() != 32 {
            return Err(ParseError("SM2 private key must be 32 bytes".into()));
        }
        if secret.iter().all(|&byte| byte == 0) {
            return Err(ParseError(
                "SM2 private key material must not be all zero".into(),
            ));
        }
        let distid = distid.into();
        validate_distid(&distid)?;
        let mut buf = Zeroizing::new([0u8; 32]);
        buf.copy_from_slice(secret);
        SecretKey::from_slice(buf.as_ref())
            .map_err(|_| ParseError("invalid SM2 private key".into()))?;
        Ok(Self {
            distid,
            secret: Secret::new(buf),
        })
    }
    /// Parse an SM2 private key from a PKCS#8 PEM document.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the PEM cannot be decoded or does not contain a valid SM2 key.
    pub fn from_pkcs8_pem(distid: impl Into<String>, pem: &str) -> Result<Self, ParseError> {
        let distid = distid.into();
        let secret = SecretKey::from_pkcs8_pem(pem)
            .map_err(|err| ParseError(format!("failed to decode SM2 PKCS#8 private key: {err}")))?;
        Self::from_secret_key(distid, &secret)
    }
    /// Generate a random SM2 private key using the provided RNG.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the distinguishing identifier is invalid,
    /// the RNG fails, or the RNG cannot produce valid scalar material within
    /// the retry budget.
    pub fn try_random<R>(distid: impl Into<String>, rng: &mut R) -> Result<Self, ParseError>
    where
        R: TryCryptoRng,
    {
        let distid = distid.into();
        validate_distid(&distid)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        for _ in 0..SM2_RANDOM_KEY_ATTEMPTS {
            rng.try_fill_bytes(secret.as_mut())
                .map_err(|err| ParseError(format!("SM2 RNG failed: {err}")))?;
            if secret.iter().all(|&byte| byte == 0) {
                return Err(ParseError(
                    "SM2 RNG returned all-zero seed material".to_owned(),
                ));
            }
            if let Ok(private) = Self::from_bytes(distid.clone(), secret.as_ref()) {
                return Ok(private);
            }
        }
        Err(ParseError(
            "SM2 RNG did not produce a valid private key".into(),
        ))
    }
    /// Generate a random SM2 private key using checked operating-system entropy.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the distinguishing identifier is invalid,
    /// the OS RNG fails, or the RNG cannot produce valid scalar material within
    /// the retry budget.
    pub fn try_random_from_os(distid: impl Into<String>) -> Result<Self, ParseError> {
        let mut rng = rand::rngs::OsRng;
        Self::try_random(distid, &mut rng)
    }
    /// Deterministically derive an SM2 private key from an arbitrary seed.
    ///
    /// # Errors
    /// Returns [`ParseError`] when a valid key cannot be derived within the retry budget.
    pub fn from_seed(distid: impl Into<String>, seed: &[u8]) -> Result<Self, ParseError> {
        let distid = distid.into();
        validate_distid(&distid)?;
        validate_seed_material_not_all_zero(seed)?;
        let mut counter: u32 = 0;
        loop {
            let mut hasher = Sha512::new();
            hasher.update(seed);
            hasher.update(counter.to_be_bytes());
            let mut digest = hasher.finalize();
            let mut candidate = Zeroizing::new([0u8; 32]);
            candidate.copy_from_slice(&digest[..32]);
            let key = Self::from_bytes(distid.clone(), candidate.as_ref());
            digest.zeroize();
            if let Ok(key) = key {
                return Ok(key);
            }
            counter = counter
                .checked_add(1)
                .ok_or_else(|| ParseError("failed to derive SM2 key from seed".into()))?;
            if counter > 1024 {
                return Err(ParseError("failed to derive SM2 key from seed".into()));
            }
        }
    }
    /// Return the canonical 32-byte representation of the private scalar.
    pub fn secret_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.secret.expose_secret().as_ref());
        out
    }
    /// Borrow the distinguishing identifier used for signing operations.
    pub fn distid(&self) -> &str {
        &self.distid
    }
    /// Derive the SM2 public key corresponding to this private key.
    pub fn public_key(&self) -> Sm2PublicKey {
        self.try_public_key()
            .expect("validated SM2 private key should derive a public key")
    }
    /// Derive the SM2 public key corresponding to this private key.
    ///
    /// # Errors
    /// Returns [`ParseError`] if the stored secret or distinguishing identifier
    /// can no longer be rebuilt into an SM2 signing key.
    pub fn try_public_key(&self) -> Result<Sm2PublicKey, ParseError> {
        Ok(Sm2PublicKey::from_verifying_key(
            self.try_signing_key()?.verifying_key().clone(),
        ))
    }
    /// Sign a message with this private key using SM2 DSA.
    pub fn sign(&self, message: &[u8]) -> Sm2Signature {
        self.try_sign(message)
            .expect("validated SM2 private key should sign messages")
    }
    /// Sign a message with this private key using SM2 DSA.
    ///
    /// # Errors
    /// Returns [`Error::Signing`] if the stored secret or distinguishing
    /// identifier can no longer be rebuilt into an SM2 signing key.
    pub fn try_sign(&self, message: &[u8]) -> Result<Sm2Signature, Error> {
        let signature = self
            .try_signing_key()
            .map_err(|err| Error::Signing(err.to_string()))?
            .sign(message);
        Ok(Sm2Signature::from_raw(signature))
    }
    /// Export the private key as a PKCS#8 DER document.
    ///
    /// # Errors
    /// Returns [`ParseError`] when encoding fails.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, ParseError> {
        self.secret_key()?
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|err| {
                ParseError(format!(
                    "failed to encode SM2 private key to PKCS#8 DER: {err}"
                ))
            })
    }
    /// Export the private key as a PEM-encoded PKCS#8 document.
    ///
    /// # Errors
    /// Returns [`ParseError`] when encoding fails.
    pub fn to_pkcs8_pem(&self) -> Result<String, ParseError> {
        self.to_pkcs8_der()
            .map(|der| encode_pem("PRIVATE KEY", &der))
    }
    fn secret_key(&self) -> Result<SecretKey, ParseError> {
        SecretKey::from_slice(self.secret.expose_secret().as_ref())
            .map_err(|_| ParseError("invalid SM2 private key".into()))
    }
    fn try_signing_key(&self) -> Result<SigningKey, ParseError> {
        let secret = self.secret_key()?;
        SigningKey::new(&self.distid, &secret)
            .map_err(|_| ParseError("invalid SM2 private key or distinguishing identifier".into()))
    }
    pub(crate) fn from_secret_key(distid: String, secret: &SecretKey) -> Result<Self, ParseError> {
        let mut bytes = secret.to_bytes();
        let mut buf = Zeroizing::new([0u8; 32]);
        buf.copy_from_slice(bytes.as_ref());
        bytes.zeroize();
        Self::from_bytes(distid, buf.as_ref())
    }
}
fn validate_seed_material_not_all_zero(seed: &[u8]) -> Result<(), ParseError> {
    if !seed.is_empty() && seed.iter().all(|&byte| byte == 0) {
        return Err(ParseError(
            "SM2 seed material must not be all zero".to_owned(),
        ));
    }
    Ok(())
}
/// Encode an SM2 public key payload with an explicit distinguishing identifier.
///
/// Layout: `distid_len (u16 BE)` || `distid bytes` || `SEC1 uncompressed (65 bytes)`.
///
/// # Errors
/// Returns [`ParseError`] when `distid` is invalid or `sec1` has the wrong length.
pub fn encode_sm2_public_key_payload(distid: &str, sec1: &[u8]) -> Result<Vec<u8>, ParseError> {
    if sec1.len() != SM2_PUBLIC_KEY_UNCOMPRESSED_LEN {
        return Err(ParseError(format!(
            "SM2 public key must be {SM2_PUBLIC_KEY_UNCOMPRESSED_LEN} bytes"
        )));
    }
    let prefix = distid_len_prefix(distid)?;
    let mut out =
        Vec::with_capacity(SM2_DISTID_LEN_BYTES + distid.len() + SM2_PUBLIC_KEY_UNCOMPRESSED_LEN);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(distid.as_bytes());
    out.extend_from_slice(sec1);
    Ok(out)
}
/// Encode an SM2 private key payload with an explicit distinguishing identifier.
///
/// Layout: `distid_len (u16 BE)` || `distid bytes` || `secret (32 bytes)`.
///
/// # Errors
/// Returns [`ParseError`] when `distid` is invalid or `secret` has the wrong length.
pub fn encode_sm2_private_key_payload(distid: &str, secret: &[u8]) -> Result<Vec<u8>, ParseError> {
    if secret.len() != SM2_PRIVATE_KEY_LEN {
        return Err(ParseError(format!(
            "SM2 private key must be {SM2_PRIVATE_KEY_LEN} bytes"
        )));
    }
    let prefix = distid_len_prefix(distid)?;
    let mut out = Vec::with_capacity(SM2_DISTID_LEN_BYTES + distid.len() + SM2_PRIVATE_KEY_LEN);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(distid.as_bytes());
    out.extend_from_slice(secret);
    Ok(out)
}
/// Decode an SM2 public key payload that embeds the distinguishing identifier.
///
/// # Errors
/// Returns [`ParseError`] when the payload is malformed, the key bytes are invalid,
/// or the encoding is not canonical.
pub fn decode_sm2_public_key_payload(payload: &[u8]) -> Result<Sm2PublicKey, ParseError> {
    let (distid, rest) = split_sm2_payload(payload)?;
    if rest.len() != SM2_PUBLIC_KEY_UNCOMPRESSED_LEN {
        return Err(ParseError(format!(
            "SM2 public key payload must be {SM2_PUBLIC_KEY_UNCOMPRESSED_LEN} bytes"
        )));
    }
    let key = Sm2PublicKey::from_sec1_bytes(distid, rest)?;
    if key.0.to_encoded_point(false).as_bytes() != rest {
        return Err(ParseError("non-canonical SM2 public key encoding".into()));
    }
    Ok(key)
}
/// Decode an SM2 private key payload that embeds the distinguishing identifier.
///
/// # Errors
/// Returns [`ParseError`] when the payload is malformed or the key bytes are invalid.
pub fn decode_sm2_private_key_payload(payload: &[u8]) -> Result<Sm2PrivateKey, ParseError> {
    let (distid, rest) = split_sm2_payload(payload)?;
    if rest.len() != SM2_PRIVATE_KEY_LEN {
        return Err(ParseError(format!(
            "SM2 private key payload must be {SM2_PRIVATE_KEY_LEN} bytes"
        )));
    }
    Sm2PrivateKey::from_bytes(distid, rest)
}
impl PartialEq for Sm2PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.distid == other.distid
            && self.secret.expose_secret().as_ref() == other.secret.expose_secret().as_ref()
    }
}
impl Eq for Sm2PrivateKey {}
impl Zeroize for Sm2PrivateKey {
    fn zeroize(&mut self) {
        self.secret = Secret::new(Zeroizing::new([0u8; 32]));
    }
}
impl ZeroizeOnDrop for Sm2PrivateKey {}
impl IntoSchema for Sm2PublicKey {
    fn type_name() -> String {
        "Sm2PublicKey".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        map.insert::<Self>(iroha_schema::Metadata::Tuple(
            iroha_schema::UnnamedFieldsMeta {
                types: vec![core::any::TypeId::of::<Vec<u8>>()],
            },
        ));
    }
}
impl IntoSchema for Sm2Signature {
    fn type_name() -> String {
        "Sm2Signature".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        map.insert::<Self>(iroha_schema::Metadata::Tuple(
            iroha_schema::UnnamedFieldsMeta {
                types: vec![
                    core::any::TypeId::of::<[u8; 32]>(),
                    core::any::TypeId::of::<[u8; 32]>(),
                ],
            },
        ));
    }
}
/// Fixed-width SM2 signature helper exposing canonical `r` and `s` components.
#[derive(Clone, Copy, PartialEq, Eq, TypeId)]
pub struct Sm2Signature {
    /// Canonical `r` component (big-endian, width = 32 bytes).
    pub r: [u8; 32],
    /// Canonical `s` component (big-endian, width = 32 bytes).
    pub s: [u8; 32],
}
impl fmt::Debug for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sm2Signature")
            .field("r", &hex::encode_upper(self.r))
            .field("s", &hex::encode_upper(self.s))
            .finish()
    }
}
impl Sm2Signature {
    /// Canonical byte length of an SM2 signature (r∥s).
    pub const LENGTH: usize = 64;
    /// Construct a signature from canonical 64-byte encoding.
    ///
    /// # Errors
    /// Returns [`ParseError`] when `bytes` do not describe a valid SM2 signature.
    pub fn from_bytes(bytes: &[u8; Self::LENGTH]) -> Result<Self, ParseError> {
        if bytes.iter().all(|&byte| byte == 0) {
            return Err(ParseError("invalid SM2 signature: all-zero payload".into()));
        }
        if bytes[..32].iter().all(|&byte| byte == 0) || bytes[32..].iter().all(|&byte| byte == 0) {
            return Err(ParseError("invalid SM2 signature: zero scalar".into()));
        }
        sm::parse_signature(bytes).map_err(|_| ParseError("invalid SM2 signature".into()))?;
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        Ok(Self { r, s })
    }
    /// Construct a signature from a hex string (canonical r∥s).
    ///
    /// # Errors
    /// Returns [`ParseError`] when the string is not valid hex or the signature is malformed.
    pub fn from_hex(hex_str: impl AsRef<str>) -> Result<Self, ParseError> {
        let bytes = hex::decode(hex_str.as_ref())
            .map_err(|err| ParseError(format!("invalid hex: {err}")))?;
        let bytes: [u8; Self::LENGTH] = bytes.try_into().map_err(|_| {
            ParseError(format!("expected {} bytes for SM2 signature", Self::LENGTH))
        })?;
        Self::from_bytes(&bytes)
    }
    /// Construct from an existing `sm2::Signature`.
    pub fn from_raw(signature: Sm2RawSignature) -> Self {
        let bytes = signature.to_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..]);
        Self { r, s }
    }
    /// Return the canonical byte representation (r∥s).
    pub fn as_bytes(&self) -> [u8; Self::LENGTH] {
        let mut out = [0u8; Self::LENGTH];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }
    /// Return the canonical byte representation (r∥s).
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.as_bytes()
    }
    /// Fallibly export the signature as a DER-encoded `SEQUENCE` of two INTEGERs.
    ///
    /// # Errors
    /// Returns [`ParseError`] if the internally bounded SM2 integer lengths ever
    /// exceed DER short-form length encoding.
    pub fn try_as_der(&self) -> Result<Vec<u8>, ParseError> {
        fn encode_integer(component: &[u8; 32]) -> Vec<u8> {
            let mut bytes = component.to_vec();
            while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
                bytes.remove(0);
            }
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
            bytes
        }
        let r = encode_integer(&self.r);
        let s = encode_integer(&self.s);
        let len = 2 + r.len() + 2 + s.len();
        let mut der = Vec::with_capacity(2 + len);
        der.push(0x30);
        push_der_short_len(&mut der, len, "sequence")?;
        der.push(0x02);
        push_der_short_len(&mut der, r.len(), "r")?;
        der.extend_from_slice(&r);
        der.push(0x02);
        push_der_short_len(&mut der, s.len(), "s")?;
        der.extend_from_slice(&s);
        Ok(der)
    }
    /// Export the signature as a DER-encoded `SEQUENCE` of two INTEGERs.
    ///
    /// Prefer [`Self::try_as_der`] on production error-propagating paths.
    #[must_use]
    pub fn as_der(&self) -> Vec<u8> {
        self.try_as_der()
            .expect("SM2 DER export should fit short-form lengths for 32-byte integers")
    }
}
fn push_der_short_len(output: &mut Vec<u8>, len: usize, context: &str) -> Result<(), ParseError> {
    let len = u8::try_from(len).map_err(|_| {
        ParseError(format!(
            "SM2 DER signature {context} length exceeds short form"
        ))
    })?;
    output.push(len);
    Ok(())
}
impl Sm2Signature {
    /// Parse a DER-encoded SM2 signature (`SEQUENCE { INTEGER r, INTEGER s }`).
    ///
    /// # Errors
    /// Returns [`ParseError`] when the DER structure is malformed, uses a non-canonical INTEGER
    /// encoding, or the decoded signature is invalid.
    pub fn from_der(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 2 || bytes[0] != 0x30 {
            return Err(ParseError("SM2 DER signature must start with 0x30".into()));
        }
        let len = usize::from(bytes[1]);
        if len + 2 != bytes.len() {
            return Err(ParseError("SM2 DER signature length mismatch".into()));
        }
        let mut cursor = 2;
        let r = parse_der_integer(bytes, &mut cursor)?;
        let s = parse_der_integer(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(ParseError("SM2 DER signature has trailing data".into()));
        }
        let mut raw = [0u8; Self::LENGTH];
        raw[..32].copy_from_slice(&r);
        raw[32..].copy_from_slice(&s);
        Self::from_bytes(&raw)
    }
}
impl From<Sm2RawSignature> for Sm2Signature {
    fn from(value: Sm2RawSignature) -> Self {
        Self::from_raw(value)
    }
}
fn parse_der_integer(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], ParseError> {
    if *cursor >= bytes.len() || bytes[*cursor] != 0x02 {
        return Err(ParseError("expected INTEGER in SM2 DER signature".into()));
    }
    *cursor += 1;
    if *cursor >= bytes.len() {
        return Err(ParseError(
            "SM2 DER signature missing INTEGER length".into(),
        ));
    }
    let len = usize::from(bytes[*cursor]);
    *cursor += 1;
    if len == 0 || *cursor + len > bytes.len() {
        return Err(ParseError(
            "SM2 DER signature INTEGER length invalid".into(),
        ));
    }
    if len > 33 {
        return Err(ParseError(
            "SM2 DER signature INTEGER exceeds 33 bytes".into(),
        ));
    }
    let slice = &bytes[*cursor..*cursor + len];
    *cursor += len;
    if slice[0] & 0x80 != 0 {
        return Err(ParseError(
            "SM2 DER signature INTEGER must be non-negative".into(),
        ));
    }
    if len > 1 && slice[0] == 0x00 && slice[1] & 0x80 == 0 {
        return Err(ParseError(
            "SM2 DER signature INTEGER has non-canonical leading zero".into(),
        ));
    }
    let value = if slice[0] == 0 { &slice[1..] } else { slice };
    if value.len() > 32 {
        return Err(ParseError(
            "SM2 DER signature integer exceeds 32 bytes".into(),
        ));
    }
    let mut out = [0u8; 32];
    let offset = 32 - value.len();
    out[offset..].copy_from_slice(value);
    Ok(out)
}
#[inline]
fn sm3_digest_scalar(message: &[u8]) -> [u8; 32] {
    let mut hasher = sm3::Sm3::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}
#[inline]
fn sm4_block_cipher(key: &[u8; 16]) -> sm4::Sm4 {
    sm4::Sm4::new(key.into())
}
#[inline]
fn sm4_encrypt_block_scalar(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = sm4_block_cipher(key);
    let mut buf = Block::<sm4::Sm4>::default();
    buf.clone_from_slice(block);
    cipher.encrypt_block(&mut buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(buf.as_ref());
    out
}
#[inline]
fn sm4_decrypt_block_scalar(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = sm4_block_cipher(key);
    let mut buf = Block::<sm4::Sm4>::default();
    buf.clone_from_slice(block);
    cipher.decrypt_block(&mut buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(buf.as_ref());
    out
}
mod sm_accel {
    use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    #[inline]
    pub fn sm3_digest(message: &[u8]) -> Option<[u8; 32]> {
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        {
            if neon::is_sm3_enabled() {
                return sm3_neon::digest(message);
            }
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
        {
            if let Some(bytes) = portable::sm3_digest(message) {
                return Some(bytes);
            }
        }
        let _ = message;
        None
    }
    #[inline]
    pub fn sm4_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        {
            if let Some(bytes) = neon::encrypt_block(key, block) {
                return Some(bytes);
            }
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
        {
            if let Some(bytes) = portable::encrypt_block(key, block) {
                return Some(bytes);
            }
        }
        let _ = (key, block);
        None
    }
    #[inline]
    pub fn sm4_decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        {
            if let Some(bytes) = neon::decrypt_block(key, block) {
                return Some(bytes);
            }
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
        {
            if let Some(bytes) = portable::decrypt_block(key, block) {
                return Some(bytes);
            }
        }
        let _ = (key, block);
        None
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum IntrinsicOverride {
        Auto = 0,
        ForceEnable = 1,
        ForceDisable = 2,
    }
    static INTRINSIC_OVERRIDE: AtomicU8 = AtomicU8::new(IntrinsicOverride::Auto as u8);
    pub(super) fn set_intrinsic_policy(policy: super::SmIntrinsicPolicy) {
        let override_value = match policy {
            super::SmIntrinsicPolicy::ForceEnable => IntrinsicOverride::ForceEnable,
            super::SmIntrinsicPolicy::ForceDisable | super::SmIntrinsicPolicy::ScalarOnly => {
                IntrinsicOverride::ForceDisable
            }
            super::SmIntrinsicPolicy::Auto => IntrinsicOverride::Auto,
        };
        INTRINSIC_OVERRIDE.store(override_value as u8, Ordering::SeqCst);
    }
    pub(super) fn configured_policy() -> super::SmIntrinsicPolicy {
        match current_override() {
            IntrinsicOverride::ForceEnable => super::SmIntrinsicPolicy::ForceEnable,
            IntrinsicOverride::ForceDisable => super::SmIntrinsicPolicy::ForceDisable,
            IntrinsicOverride::Auto => super::SmIntrinsicPolicy::Auto,
        }
    }
    fn current_override() -> IntrinsicOverride {
        match INTRINSIC_OVERRIDE.load(Ordering::Relaxed) {
            x if x == IntrinsicOverride::ForceEnable as u8 => IntrinsicOverride::ForceEnable,
            x if x == IntrinsicOverride::ForceDisable as u8 => IntrinsicOverride::ForceDisable,
            _ => IntrinsicOverride::Auto,
        }
    }
    fn forced_override() -> Option<bool> {
        match current_override() {
            IntrinsicOverride::ForceEnable => Some(true),
            IntrinsicOverride::ForceDisable => Some(false),
            IntrinsicOverride::Auto if cfg!(feature = "sm-neon-force") => Some(true),
            IntrinsicOverride::Auto => None,
        }
    }
    #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
    mod neon {
        use super::{
            super::{sm4_decrypt_block_scalar, sm4_encrypt_block_scalar},
            AtomicBool, Ordering,
        };
        static FORCE_DISABLED: AtomicBool = AtomicBool::new(false);
        pub fn encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
            if !is_enabled() {
                return None;
            }
            sm4_neon::encrypt_block(key, block)
                .or_else(|| Some(sm4_encrypt_block_scalar(key, block)))
        }
        pub fn decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
            if !is_enabled() {
                return None;
            }
            sm4_neon::decrypt_block(key, block)
                .or_else(|| Some(sm4_decrypt_block_scalar(key, block)))
        }
        pub(super) fn is_sm3_enabled() -> bool {
            if FORCE_DISABLED.load(Ordering::Relaxed) {
                return false;
            }
            if let Some(force) = forced_override() {
                return force;
            }
            sm3_neon::is_supported()
        }
        pub(super) fn is_enabled() -> bool {
            if FORCE_DISABLED.load(Ordering::Relaxed) {
                return false;
            }
            if let Some(force) = forced_override() {
                return force;
            }
            sm4_neon::is_supported()
        }
        pub(super) fn forced_override() -> Option<bool> {
            super::forced_override()
        }
        #[cfg(test)]
        pub fn force_disable_all_for_tests() -> SmAccelDisableGuard {
            let previous = FORCE_DISABLED.swap(true, Ordering::SeqCst);
            SmAccelDisableGuard { previous }
        }
        #[cfg(all(test, feature = "sm-neon-force"))]
        pub fn is_enabled_for_tests() -> bool {
            is_enabled()
        }
        #[cfg(test)]
        pub struct SmAccelDisableGuard {
            previous: bool,
        }
        #[cfg(test)]
        impl Drop for SmAccelDisableGuard {
            fn drop(&mut self) {
                FORCE_DISABLED.store(self.previous, Ordering::SeqCst);
            }
        }
    }
    #[cfg(not(all(feature = "sm-neon", target_arch = "aarch64")))]
    mod neon {
        #[cfg(test)]
        pub struct SmAccelDisableGuard;
        #[cfg(test)]
        pub fn force_disable_all_for_tests() -> SmAccelDisableGuard {
            SmAccelDisableGuard
        }
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    mod portable {
        use super::{
            super::{sm3_digest_scalar, sm4_decrypt_block_scalar, sm4_encrypt_block_scalar},
            AtomicBool, Ordering, forced_override,
        };
        static FORCE_DISABLED: AtomicBool = AtomicBool::new(false);
        pub fn sm3_digest(message: &[u8]) -> Option<[u8; 32]> {
            if !is_enabled() {
                return None;
            }
            Some(sm3_digest_scalar(message))
        }
        pub fn encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
            if !is_enabled() {
                return None;
            }
            Some(sm4_encrypt_block_scalar(key, block))
        }
        pub fn decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Option<[u8; 16]> {
            if !is_enabled() {
                return None;
            }
            Some(sm4_decrypt_block_scalar(key, block))
        }
        fn is_enabled() -> bool {
            if FORCE_DISABLED.load(Ordering::Relaxed) {
                return false;
            }
            if let Some(force) = forced_override() {
                return force;
            }
            true
        }
        #[cfg(test)]
        pub struct SmAccelDisableGuard {
            previous: bool,
        }
        #[cfg(test)]
        pub fn force_disable_all_for_tests() -> SmAccelDisableGuard {
            let previous = FORCE_DISABLED.swap(true, Ordering::SeqCst);
            SmAccelDisableGuard { previous }
        }
        #[cfg(test)]
        impl Drop for SmAccelDisableGuard {
            fn drop(&mut self) {
                FORCE_DISABLED.store(self.previous, Ordering::SeqCst);
            }
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NeonPolicy {
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        Auto,
        ForceEnable,
        ForceDisable,
        #[cfg(not(all(feature = "sm-neon", target_arch = "aarch64")))]
        Unsupported,
    }
    pub fn neon_enabled() -> bool {
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        {
            neon::is_enabled() || neon::is_sm3_enabled()
        }
        #[cfg(not(all(feature = "sm-neon", target_arch = "aarch64")))]
        {
            false
        }
    }
    pub fn neon_policy() -> NeonPolicy {
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        {
            match forced_override() {
                Some(true) => NeonPolicy::ForceEnable,
                Some(false) => NeonPolicy::ForceDisable,
                None => NeonPolicy::Auto,
            }
        }
        #[cfg(not(all(feature = "sm-neon", target_arch = "aarch64")))]
        {
            match forced_override() {
                Some(true) => NeonPolicy::ForceEnable,
                Some(false) => NeonPolicy::ForceDisable,
                None => NeonPolicy::Unsupported,
            }
        }
    }
    #[cfg(test)]
    pub mod tests {
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        use super::super::sm3_digest_scalar;
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        use super::super::sm4_encrypt_block_scalar;
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        fn parity_seeds() -> [u8; 12] {
            [
                0x00, 0x01, 0x02, 0x10, 0x22, 0x45, 0x7F, 0x80, 0xA5, 0xC3, 0xEE, 0xFF,
            ]
        }
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        fn parity_case(seed: u8) -> ([u8; 16], [u8; 16]) {
            let mut key = [0u8; 16];
            let mut block = [0u8; 16];
            for (idx, slot) in key.iter_mut().enumerate() {
                let idx_byte = u8::try_from(idx).expect("key index fits into u8");
                *slot = seed
                    .wrapping_mul(0x11)
                    .wrapping_add(idx_byte.wrapping_mul(0x07));
            }
            for (idx, slot) in block.iter_mut().enumerate() {
                let idx_byte = u8::try_from(idx).expect("block index fits into u8");
                *slot = seed
                    .wrapping_mul(0x31)
                    .wrapping_add(idx_byte.wrapping_mul(0x0B));
            }
            (key, block)
        }
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        const SM4_BLOCK_FIXTURES: [([u8; 16], [u8; 16]); 4] = [
            (
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ],
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ],
            ),
            ([0x00; 16], [0xFF; 16]),
            (
                [
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0xEF, 0xCD, 0xAB, 0x89, 0x67,
                    0x45, 0x23, 0x01,
                ],
                [
                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xAB, 0xCD, 0xEF,
                ],
            ),
            ([0xA5; 16], [0x5A; 16]),
        ];
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        const SM4_KEY_FIXTURES: [([u8; 16], [u8; 16]); 3] = [
            (
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ],
                [
                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xAB, 0xCD, 0xEF,
                ],
            ),
            ([0xFF; 16], [0x00; 16]),
            ([0xA5; 16], [0x5A; 16]),
        ];
        /// Guard that disables every SM acceleration path available to this build.
        pub struct SmAccelDisableGuard {
            _neon: super::neon::SmAccelDisableGuard,
            #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
            _portable: super::portable::SmAccelDisableGuard,
        }
        /// Disable every SM acceleration path available to this build for the guard lifetime.
        pub fn force_disable_all_for_tests() -> SmAccelDisableGuard {
            SmAccelDisableGuard {
                _neon: super::neon::force_disable_all_for_tests(),
                #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
                _portable: super::portable::force_disable_all_for_tests(),
            }
        }
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        struct IntrinsicPolicyGuard(super::super::SmIntrinsicPolicy);
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        impl IntrinsicPolicyGuard {
            fn set(policy: super::super::SmIntrinsicPolicy) -> Self {
                let previous = super::super::configured_intrinsic_policy();
                super::super::set_intrinsic_policy(policy);
                Self(previous)
            }
        }
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        impl Drop for IntrinsicPolicyGuard {
            fn drop(&mut self) {
                super::super::set_intrinsic_policy(self.0);
            }
        }
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        #[test]
        fn neon_force_disable_disables_accel() {
            if !sm4_neon::is_supported() {
                eprintln!("skipping NEON disable test: NEON not available");
                return;
            }
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            let key = [0x11u8; 16];
            let block = [0x22u8; 16];
            let baseline = sm4_neon::encrypt_block(&key, &block)
                .expect("baseline NEON encryption should succeed");
            let guard = force_disable_all_for_tests();
            assert!(
                super::neon::encrypt_block(&key, &block).is_none(),
                "runtime disable must bypass NEON acceleration"
            );
            drop(guard);
            let resumed = super::neon::encrypt_block(&key, &block)
                .expect("acceleration should resume after guard drop");
            assert_eq!(
                baseline, resumed,
                "re-enabled NEON should produce identical ciphertext"
            );
        }
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        #[test]
        fn neon_force_feature_enables_accel() {
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            assert!(
                super::neon::is_enabled_for_tests(),
                "sm-neon-force feature must report acceleration as enabled"
            );
            let key = [0x55u8; 16];
            let block = [0xAAu8; 16];
            let accel = super::neon::encrypt_block(&key, &block)
                .expect("forced NEON feature should drive acceleration");
            let scalar = sm4_encrypt_block_scalar(&key, &block);
            assert_eq!(
                accel, scalar,
                "forced NEON path must remain deterministic vs scalar reference"
            );
        }
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        #[test]
        fn neon_force_feature_parity() {
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            assert!(
                super::neon::is_enabled_for_tests(),
                "sm-neon-force feature must report acceleration as enabled"
            );
            for seed in parity_seeds() {
                let (key, block) = parity_case(seed);
                let accel_enc = crate::sm::sm_accel::sm4_encrypt_block(&key, &block)
                    .expect("forced feature must return accelerated encrypt result");
                let scalar_enc = sm4_encrypt_block_scalar(&key, &block);
                assert_eq!(
                    accel_enc, scalar_enc,
                    "SM4 forced NEON encrypt mismatch for seed {seed:#04x}"
                );
                let accel_dec = crate::sm::sm_accel::sm4_decrypt_block(&key, &scalar_enc)
                    .expect("forced feature must return accelerated decrypt result");
                assert_eq!(
                    block, accel_dec,
                    "SM4 forced NEON decrypt mismatch for seed {seed:#04x}"
                );
            }
        }
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        #[test]
        fn neon_runtime_parity_when_available() {
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            for seed in parity_seeds() {
                let (key, block) = parity_case(seed);
                let Some(accel_enc) = crate::sm::sm_accel::sm4_encrypt_block(&key, &block) else {
                    eprintln!("skipping SM4 NEON parity test: acceleration not available");
                    return;
                };
                let scalar_enc = sm4_encrypt_block_scalar(&key, &block);
                assert_eq!(
                    accel_enc, scalar_enc,
                    "SM4 NEON encrypt mismatch for seed {seed:#04x}"
                );
                let Some(accel_dec) = crate::sm::sm_accel::sm4_decrypt_block(&key, &scalar_enc)
                else {
                    panic!("SM4 NEON decrypt unexpectedly disabled for seed {seed:#04x}");
                };
                assert_eq!(
                    block, accel_dec,
                    "SM4 NEON decrypt mismatch for seed {seed:#04x}"
                );
            }
        }
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        #[test]
        fn neon_sm3_digest_matches_scalar_under_force() {
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            assert!(
                super::neon::is_enabled_for_tests(),
                "sm-neon-force feature must report acceleration as enabled"
            );
            let message = b"neon sm3 force smoke";
            let accel = crate::sm::sm_accel::sm3_digest(message)
                .expect("forced feature should enable SM3 digest acceleration");
            let scalar = sm3_digest_scalar(message);
            assert_eq!(
                accel, scalar,
                "SM3 accelerated digest must match scalar output"
            );
        }
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        #[test]
        fn neon_sm3_digest_respects_runtime_disable() {
            if !sm3_neon::is_supported() {
                eprintln!("skipping SM3 NEON disable test: NEON not available");
                return;
            }
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            let guard = force_disable_all_for_tests();
            assert!(
                crate::sm::sm_accel::sm3_digest(b"disable-check").is_none(),
                "runtime disable must bypass SM3 NEON acceleration"
            );
            drop(guard);
            assert!(
                crate::sm::sm_accel::sm3_digest(b"disable-check").is_some(),
                "SM3 NEON digest should resume once the guard is dropped"
            );
        }
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        #[test]
        fn neon_sm4_block_cipher_matches_scalar_fixtures() {
            use super::super::{sm4_decrypt_block_scalar, sm4_encrypt_block_scalar};
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            assert!(
                super::neon::is_enabled_for_tests(),
                "sm-neon-force feature must report acceleration as enabled"
            );
            for (index, &(key_bytes, block_bytes)) in SM4_BLOCK_FIXTURES.iter().enumerate() {
                let neon_cipher = super::neon::encrypt_block(&key_bytes, &block_bytes)
                    .expect("forced feature should route to NEON encrypt");
                let scalar_cipher = sm4_encrypt_block_scalar(&key_bytes, &block_bytes);
                assert_eq!(
                    neon_cipher, scalar_cipher,
                    "SM4 NEON encrypt mismatch for fixture #{index}"
                );
                let neon_plain = super::neon::decrypt_block(&key_bytes, &neon_cipher)
                    .expect("forced feature should route to NEON decrypt");
                let scalar_plain = sm4_decrypt_block_scalar(&key_bytes, &neon_cipher);
                assert_eq!(
                    neon_plain, scalar_plain,
                    "SM4 NEON decrypt mismatch for fixture #{index}"
                );
                assert_eq!(
                    neon_plain, block_bytes,
                    "SM4 NEON decrypt must recover original block for fixture #{index}"
                );
            }
        }
        #[cfg(all(feature = "sm-neon-force", target_arch = "aarch64"))]
        #[test]
        fn neon_sm4_key_round_trip_matches_scalar() {
            use crate::sm::Sm4Key;
            let _accel_lock = super::super::test_support::lock_accel_state();
            let _policy_guard = IntrinsicPolicyGuard::set(super::super::SmIntrinsicPolicy::Auto);
            assert!(
                super::neon::is_enabled_for_tests(),
                "sm-neon-force feature must report acceleration as enabled"
            );
            for (index, &(key_bytes, block_bytes)) in SM4_KEY_FIXTURES.iter().enumerate() {
                let key = Sm4Key::new(key_bytes);
                let guard = force_disable_all_for_tests();
                let scalar_cipher = key.encrypt_block(&block_bytes);
                let scalar_plain = key.decrypt_block(&scalar_cipher);
                drop(guard);
                assert_eq!(
                    scalar_plain, block_bytes,
                    "SM4 scalar decrypt must recover original block for fixture #{index}"
                );
                let neon_cipher = key.encrypt_block(&block_bytes);
                assert_eq!(
                    neon_cipher, scalar_cipher,
                    "SM4 NEON encrypt via Sm4Key mismatch for fixture #{index}"
                );
                let neon_plain = key.decrypt_block(&scalar_cipher);
                assert_eq!(
                    neon_plain, block_bytes,
                    "SM4 NEON decrypt via Sm4Key must recover original block for fixture #{index}"
                );
            }
        }
    }
}
/// Digest helper for SM3 hashes.
#[derive(Clone, Copy, PartialEq, Eq, Deref, DerefMut, TypeId)]
#[repr(transparent)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::sm::Sm3Digest")]
pub struct Sm3Digest([u8; 32]);
impl Sm3Digest {
    /// Length of an SM3 digest in bytes.
    pub const LENGTH: usize = 32;
    /// Hash the provided message using SM3.
    pub fn hash(message: impl AsRef<[u8]>) -> Self {
        #[cfg(feature = "sm-ffi-openssl")]
        if let Ok(bytes) = OpenSslSmBackend::sm3_digest(message.as_ref()) {
            return Self(bytes);
        }
        if let Some(bytes) = sm_accel::sm3_digest(message.as_ref()) {
            return Self(bytes);
        }
        Self(sm3_digest_scalar(message.as_ref()))
    }
    /// Borrow the underlying digest bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}
impl fmt::Debug for Sm3Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Sm3Digest")
            .field(&hex::encode_upper(self.0))
            .finish()
    }
}
impl IntoSchema for Sm3Digest {
    fn type_name() -> String {
        "Sm3Digest".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        map.insert::<Self>(iroha_schema::Metadata::Tuple(
            iroha_schema::UnnamedFieldsMeta {
                types: vec![core::any::TypeId::of::<[u8; 32]>()],
            },
        ));
    }
}
#[cfg(feature = "json")]
impl FastJsonWrite for Sm3Digest {
    fn write_json(&self, out: &mut String) {
        json::write_json_string(&hex::encode_upper(self.0), out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_upper_hex_json_string_to(&self.0, out)
    }
}
#[cfg(feature = "json")]
impl JsonDeserialize for Sm3Digest {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let encoded = parser.parse_string()?;
        let bytes = hex::decode(&encoded)
            .map_err(|err| json::Error::Message(format!("invalid hex: {err}")))?;
        let bytes: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| json::Error::Message("expected 32-byte SM3 digest".into()))?;
        Ok(Self(bytes))
    }
}

impl norito::core::SerializePayload for Sm3Digest {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::LENGTH)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::LENGTH)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for Sm3Digest {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical raw SM3 digest decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let mut offset = 0;
        let bytes = norito::core::decode_context_byte_array::<{ Self::LENGTH }>(ptr, &mut offset)?;
        norito::core::finish_context_fields(ptr, offset)?;
        Ok(Sm3Digest(bytes))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Sm3Digest {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        if bytes.len() < Sm3Digest::LENGTH {
            return Err(norito::core::Error::LengthMismatch);
        }
        let mut buf = [0u8; Sm3Digest::LENGTH];
        buf.copy_from_slice(&bytes[..Sm3Digest::LENGTH]);
        Ok((Sm3Digest(buf), Sm3Digest::LENGTH))
    }
}
#[cfg(feature = "sm-ccm")]
mod sm4_ccm_compat {
    use super::Error;
    use core::convert::TryFrom;
    use sm4::{
        Sm4,
        cipher::{Block, BlockEncrypt, KeyInit},
    };
    const BLOCK_SIZE: usize = 16;
    fn is_valid_tag_len(len: usize) -> bool {
        (4..=16).contains(&len) && len.is_multiple_of(2)
    }
    fn is_valid_nonce_len(len: usize) -> bool {
        (7..=13).contains(&len)
    }
    fn m_tick(tag_len: usize) -> Result<u8, Error> {
        if !is_valid_tag_len(tag_len) {
            return Err(Error::Other("invalid SM4-CCM tag length".into()));
        }
        let tag_len = u8::try_from(tag_len)
            .map_err(|_| Error::Other("SM4-CCM tag length exceeds u8".into()))?;
        Ok(tag_len.saturating_sub(2) / 2)
    }
    fn l_parameter(nonce_len: usize) -> Result<u8, Error> {
        if !is_valid_nonce_len(nonce_len) {
            return Err(Error::Other("invalid SM4-CCM nonce length".into()));
        }
        let nonce_len = u8::try_from(nonce_len)
            .map_err(|_| Error::Other("SM4-CCM nonce length exceeds u8".into()))?;
        Ok(15u8.saturating_sub(nonce_len))
    }
    fn max_payload(nonce_len: usize) -> Result<usize, Error> {
        let l = u128::from(l_parameter(nonce_len)?);
        let max = (1u128 << (8 * l)) - 1;
        Ok(usize::try_from(max).unwrap_or(usize::MAX))
    }
    struct CbcMac<'a> {
        cipher: &'a Sm4,
        state: [u8; BLOCK_SIZE],
    }
    impl<'a> CbcMac<'a> {
        fn new(cipher: &'a Sm4) -> Self {
            Self {
                cipher,
                state: [0u8; BLOCK_SIZE],
            }
        }
        fn update(&mut self, data: &[u8]) {
            for chunk in data.chunks(BLOCK_SIZE) {
                let mut block = [0u8; BLOCK_SIZE];
                let len = chunk.len();
                block[..len].copy_from_slice(chunk);
                self.block_update(&block);
            }
        }
        fn block_update(&mut self, block: &[u8; BLOCK_SIZE]) {
            xor_full(&mut self.state, block);
            encrypt_block_raw(self.cipher, &mut self.state);
        }
        fn finalize(self) -> [u8; BLOCK_SIZE] {
            self.state
        }
    }
    fn encrypt_block_raw(cipher: &Sm4, block: &mut [u8; BLOCK_SIZE]) {
        let mut buf = Block::<Sm4>::default();
        buf.copy_from_slice(block);
        cipher.encrypt_block(&mut buf);
        block.copy_from_slice(buf.as_ref());
    }
    fn xor_full(target: &mut [u8; BLOCK_SIZE], other: &[u8; BLOCK_SIZE]) {
        for (dst, src) in target.iter_mut().zip(other.iter()) {
            *dst ^= *src;
        }
    }
    fn xor_partial(target: &mut [u8], stream: &[u8]) {
        for (dst, src) in target.iter_mut().zip(stream.iter()) {
            *dst ^= *src;
        }
    }
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (left, right) in a.iter().zip(b.iter()) {
            diff |= left ^ right;
        }
        diff == 0
    }
    fn fill_aad_header(len: usize) -> Result<(usize, [u8; BLOCK_SIZE]), Error> {
        let mut header = [0u8; BLOCK_SIZE];
        let used = if len < 0xFF00 {
            let value = u16::try_from(len)
                .map_err(|_| Error::Other("SM4-CCM AAD length exceeds u16".into()))?;
            header[..2].copy_from_slice(&value.to_be_bytes());
            2
        } else if let Ok(value) = u32::try_from(len) {
            header[0] = 0xFF;
            header[1] = 0xFE;
            header[2..6].copy_from_slice(&value.to_be_bytes());
            6
        } else {
            header[0] = 0xFF;
            header[1] = 0xFF;
            let value = u64::try_from(len)
                .map_err(|_| Error::Other("SM4-CCM AAD length exceeds u64".into()))?;
            header[2..10].copy_from_slice(&value.to_be_bytes());
            10
        };
        Ok((used, header))
    }
    fn gen_ctr_block<const NONCE_LEN: usize>(
        block: &mut [u8; BLOCK_SIZE],
        nonce: &[u8],
        counter: usize,
    ) -> Result<(), Error> {
        let l = l_parameter(NONCE_LEN)?;
        block[0] = l - 1;
        let n = nonce.len();
        block[1..=n].copy_from_slice(nonce);
        let remaining = BLOCK_SIZE - 1 - n;
        let ctr_bytes = counter.to_be_bytes();
        let start = ctr_bytes.len() - remaining;
        block[1 + n..].copy_from_slice(&ctr_bytes[start..]);
        Ok(())
    }
    fn calc_mac<const TAG_LEN: usize, const NONCE_LEN: usize>(
        cipher: &Sm4,
        nonce: &[u8],
        aad: &[u8],
        buffer: &[u8],
    ) -> Result<[u8; BLOCK_SIZE], Error> {
        debug_assert!(is_valid_tag_len(TAG_LEN));
        debug_assert!(is_valid_nonce_len(NONCE_LEN));
        if buffer.len() > max_payload(NONCE_LEN)? {
            return Err(Error::Other(
                "SM4-CCM payload length exceeds supported range".into(),
            ));
        }
        let mut b0 = [0u8; BLOCK_SIZE];
        let l = l_parameter(NONCE_LEN)?;
        let flags = 64 * u8::from(!aad.is_empty()) + 8 * m_tick(TAG_LEN)? + (l - 1);
        b0[0] = flags;
        let n = nonce.len();
        b0[1..=n].copy_from_slice(nonce);
        let cb = BLOCK_SIZE - 1 - n;
        if cb > 4 {
            let bytes = u64::try_from(buffer.len())
                .map_err(|_| Error::Other("SM4-CCM payload length exceeds u64".into()))?;
            let bytes = bytes.to_be_bytes();
            let start = bytes.len() - cb;
            b0[1 + n..].copy_from_slice(&bytes[start..]);
        } else {
            let bytes = u32::try_from(buffer.len())
                .map_err(|_| Error::Other("SM4-CCM payload length exceeds u32".into()))?;
            let bytes = bytes.to_be_bytes();
            let start = bytes.len() - cb;
            b0[1 + n..].copy_from_slice(&bytes[start..]);
        }
        let mut mac = CbcMac::new(cipher);
        mac.block_update(&b0);
        if !aad.is_empty() {
            let (prefix_len, mut header) = fill_aad_header(aad.len())?;
            let head_copy = core::cmp::min(aad.len(), BLOCK_SIZE - prefix_len);
            header[prefix_len..prefix_len + head_copy].copy_from_slice(&aad[..head_copy]);
            mac.block_update(&header);
            if head_copy < aad.len() {
                mac.update(&aad[head_copy..]);
            }
        }
        mac.update(buffer);
        Ok(mac.finalize())
    }
    pub(super) fn encrypt<const TAG_LEN: usize, const NONCE_LEN: usize>(
        key_bytes: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug_assert!(is_valid_tag_len(TAG_LEN));
        debug_assert!(is_valid_nonce_len(NONCE_LEN));
        let cipher = Sm4::new_from_slice(key_bytes)
            .map_err(|err| Error::Other(format!("invalid SM4 key length: {err}")))?;
        if nonce.len() != NONCE_LEN {
            return Err(Error::Other(
                "SM4-CCM nonce length does not match selected variant".into(),
            ));
        }
        let mut buffer = plaintext.to_vec();
        let mut tag_block = calc_mac::<TAG_LEN, NONCE_LEN>(&cipher, nonce, aad, &buffer)?;
        let mut ctr = [0u8; BLOCK_SIZE];
        gen_ctr_block::<NONCE_LEN>(&mut ctr, nonce, 0)?;
        encrypt_block_raw(&cipher, &mut ctr);
        xor_full(&mut tag_block, &ctr);
        let mut counter = 1usize;
        {
            let mut chunks = buffer.chunks_exact_mut(BLOCK_SIZE);
            for chunk in &mut chunks {
                gen_ctr_block::<NONCE_LEN>(&mut ctr, nonce, counter)?;
                encrypt_block_raw(&cipher, &mut ctr);
                xor_partial(chunk, &ctr);
                counter += 1;
            }
            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                gen_ctr_block::<NONCE_LEN>(&mut ctr, nonce, counter)?;
                encrypt_block_raw(&cipher, &mut ctr);
                xor_partial(rem, &ctr[..rem.len()]);
            }
        }
        let tag = tag_block[..TAG_LEN].to_vec();
        Ok((buffer, tag))
    }
    pub(super) fn decrypt<const TAG_LEN: usize, const NONCE_LEN: usize>(
        key_bytes: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        debug_assert!(is_valid_tag_len(TAG_LEN));
        debug_assert!(is_valid_nonce_len(NONCE_LEN));
        if nonce.len() != NONCE_LEN {
            return Err(Error::Other(
                "SM4-CCM nonce length does not match selected variant".into(),
            ));
        }
        if tag.len() != TAG_LEN {
            return Err(Error::Other(
                "SM4-CCM tag length does not match selected variant".into(),
            ));
        }
        let cipher = Sm4::new_from_slice(key_bytes)
            .map_err(|err| Error::Other(format!("invalid SM4 key length: {err}")))?;
        let mut buffer = ciphertext.to_vec();
        let mut ctr = [0u8; BLOCK_SIZE];
        gen_ctr_block::<NONCE_LEN>(&mut ctr, nonce, 0)?;
        encrypt_block_raw(&cipher, &mut ctr);
        let s0 = ctr;
        let mut counter = 1usize;
        {
            let mut chunks = buffer.chunks_exact_mut(BLOCK_SIZE);
            for chunk in &mut chunks {
                gen_ctr_block::<NONCE_LEN>(&mut ctr, nonce, counter)?;
                encrypt_block_raw(&cipher, &mut ctr);
                xor_partial(chunk, &ctr);
                counter += 1;
            }
            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                gen_ctr_block::<NONCE_LEN>(&mut ctr, nonce, counter)?;
                encrypt_block_raw(&cipher, &mut ctr);
                xor_partial(rem, &ctr[..rem.len()]);
            }
        }
        let mut tag_block = calc_mac::<TAG_LEN, NONCE_LEN>(&cipher, nonce, aad, &buffer)?;
        xor_full(&mut tag_block, &s0);
        if constant_time_eq(&tag_block[..tag.len()], tag) {
            Ok(buffer)
        } else {
            buffer.fill(0);
            Err(Error::Other("SM4-CCM decryption failed".into()))
        }
    }
}
/// Zeroizing SM4 key wrapper for block operations and authenticated encryption.
///
/// Configured OpenSSL operations preserve the Rust result on backend failure.
/// A backend error on valid input quarantines that operation until process restart;
/// authentication and parameter rejection retain the canonical Rust error.
#[derive(Clone, TypeId)]
pub struct Sm4Key(Secret<Zeroizing<[u8; 16]>>);
impl Sm4Key {
    /// Construct a new SM4 key.
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(Secret::new(Zeroizing::new(bytes)))
    }
    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        if let Some(bytes) = sm_accel::sm4_encrypt_block(self.0.expose_secret(), block) {
            return bytes;
        }
        sm4_encrypt_block_scalar(self.0.expose_secret(), block)
    }
    /// Decrypt a single 16-byte block.
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        if let Some(bytes) = sm_accel::sm4_decrypt_block(self.0.expose_secret(), block) {
            return bytes;
        }
        sm4_decrypt_block_scalar(self.0.expose_secret(), block)
    }
    /// Encrypt a message with SM4-GCM.
    ///
    /// Returns the ciphertext and 16-byte authentication tag.
    ///
    /// # Errors
    /// Returns [`Error::Other`] when the encryption routine produces an unexpected output length.
    pub fn encrypt_gcm(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), Error> {
        let canonical = || {
            let sm4_key = Sm4AeadKey::from_slice(self.0.expose_secret().as_ref())
                .map_err(|err| Error::Other(format!("invalid SM4 key length: {err}")))?;
            let mut output = sm4_gcm_aad_encrypt(&sm4_key, nonce, aad, plaintext);
            if output.len() < 16 {
                return Err(Error::Other("SM4-GCM output truncated".into()));
            }
            let tag_vec = output.split_off(output.len() - 16);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_vec);
            Ok((output, tag))
        };
        #[cfg(feature = "sm-ffi-openssl")]
        {
            openssl_dispatch::execute(
                openssl_dispatch::Operation::GcmEncrypt,
                || {
                    OpenSslSmBackend::sm4_gcm_encrypt(
                        self.0.expose_secret().as_ref(),
                        nonce,
                        aad,
                        plaintext,
                    )
                },
                canonical,
            )
        }
        #[cfg(not(feature = "sm-ffi-openssl"))]
        {
            canonical()
        }
    }
    /// Decrypt a message with SM4-GCM, returning the plaintext.
    ///
    /// # Errors
    /// Returns [`Error::Other`] when the tag validation fails.
    pub fn decrypt_gcm(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error> {
        let canonical = || {
            let sm4_key = Sm4AeadKey::from_slice(self.0.expose_secret().as_ref())
                .map_err(|err| Error::Other(format!("invalid SM4 key length: {err}")))?;
            let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
            combined.extend_from_slice(ciphertext);
            combined.extend_from_slice(tag);
            sm4_gcm_aad_decrypt(&sm4_key, nonce, aad, &combined)
                .map_err(|err| Error::Other(format!("SM4-GCM decryption failed: {err}")))
        };
        #[cfg(feature = "sm-ffi-openssl")]
        {
            openssl_dispatch::execute(
                openssl_dispatch::Operation::GcmDecrypt,
                || {
                    OpenSslSmBackend::sm4_gcm_decrypt(
                        self.0.expose_secret().as_ref(),
                        nonce,
                        aad,
                        ciphertext,
                        tag,
                    )
                },
                canonical,
            )
        }
        #[cfg(not(feature = "sm-ffi-openssl"))]
        {
            canonical()
        }
    }
    #[cfg(feature = "sm-ccm")]
    fn encrypt_ccm_for_tag<const TAG_LEN: usize>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match nonce.len() {
            7 => self.encrypt_ccm_with::<TAG_LEN, 7>(nonce, aad, plaintext),
            8 => self.encrypt_ccm_with::<TAG_LEN, 8>(nonce, aad, plaintext),
            9 => self.encrypt_ccm_with::<TAG_LEN, 9>(nonce, aad, plaintext),
            10 => self.encrypt_ccm_with::<TAG_LEN, 10>(nonce, aad, plaintext),
            11 => self.encrypt_ccm_with::<TAG_LEN, 11>(nonce, aad, plaintext),
            12 => self.encrypt_ccm_with::<TAG_LEN, 12>(nonce, aad, plaintext),
            13 => self.encrypt_ccm_with::<TAG_LEN, 13>(nonce, aad, plaintext),
            _ => Err(Error::Other(
                "SM4-CCM nonce must be between 7 and 13 bytes".into(),
            )),
        }
    }
    #[cfg(feature = "sm-ccm")]
    fn encrypt_ccm_with<const TAG_LEN: usize, const NONCE_LEN: usize>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let canonical = || {
            sm4_ccm_compat::encrypt::<TAG_LEN, NONCE_LEN>(
                self.0.expose_secret().as_ref(),
                nonce,
                aad,
                plaintext,
            )
        };
        #[cfg(feature = "sm-ffi-openssl")]
        {
            openssl_dispatch::execute(
                openssl_dispatch::Operation::CcmEncrypt,
                || {
                    OpenSslSmBackend::sm4_ccm_encrypt(
                        self.0.expose_secret().as_ref(),
                        nonce,
                        aad,
                        plaintext,
                        TAG_LEN,
                    )
                },
                canonical,
            )
        }
        #[cfg(not(feature = "sm-ffi-openssl"))]
        {
            canonical()
        }
    }
    #[cfg(feature = "sm-ccm")]
    fn decrypt_ccm_for_tag<const TAG_LEN: usize>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match nonce.len() {
            7 => self.decrypt_ccm_with::<TAG_LEN, 7>(nonce, aad, ciphertext, tag),
            8 => self.decrypt_ccm_with::<TAG_LEN, 8>(nonce, aad, ciphertext, tag),
            9 => self.decrypt_ccm_with::<TAG_LEN, 9>(nonce, aad, ciphertext, tag),
            10 => self.decrypt_ccm_with::<TAG_LEN, 10>(nonce, aad, ciphertext, tag),
            11 => self.decrypt_ccm_with::<TAG_LEN, 11>(nonce, aad, ciphertext, tag),
            12 => self.decrypt_ccm_with::<TAG_LEN, 12>(nonce, aad, ciphertext, tag),
            13 => self.decrypt_ccm_with::<TAG_LEN, 13>(nonce, aad, ciphertext, tag),
            _ => Err(Error::Other(
                "SM4-CCM nonce must be between 7 and 13 bytes".into(),
            )),
        }
    }
    #[cfg(feature = "sm-ccm")]
    fn decrypt_ccm_with<const TAG_LEN: usize, const NONCE_LEN: usize>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let canonical = || {
            sm4_ccm_compat::decrypt::<TAG_LEN, NONCE_LEN>(
                self.0.expose_secret().as_ref(),
                nonce,
                aad,
                ciphertext,
                tag,
            )
        };
        #[cfg(feature = "sm-ffi-openssl")]
        {
            openssl_dispatch::execute(
                openssl_dispatch::Operation::CcmDecrypt,
                || {
                    OpenSslSmBackend::sm4_ccm_decrypt(
                        self.0.expose_secret().as_ref(),
                        nonce,
                        aad,
                        ciphertext,
                        tag,
                    )
                },
                canonical,
            )
        }
        #[cfg(not(feature = "sm-ffi-openssl"))]
        {
            canonical()
        }
    }
    /// Encrypt a message with SM4-CCM.
    ///
    /// Returns the ciphertext and authentication tag (length determined by `tag_len`).
    ///
    /// # Errors
    /// Returns [`Error::Other`] when unsupported tag/nonce sizes are requested or the underlying
    /// encryption fails.
    #[cfg(feature = "sm-ccm")]
    pub fn encrypt_ccm(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        tag_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match tag_len {
            4 => self.encrypt_ccm_for_tag::<4>(nonce, aad, plaintext),
            6 => self.encrypt_ccm_for_tag::<6>(nonce, aad, plaintext),
            8 => self.encrypt_ccm_for_tag::<8>(nonce, aad, plaintext),
            10 => self.encrypt_ccm_for_tag::<10>(nonce, aad, plaintext),
            12 => self.encrypt_ccm_for_tag::<12>(nonce, aad, plaintext),
            14 => self.encrypt_ccm_for_tag::<14>(nonce, aad, plaintext),
            16 => self.encrypt_ccm_for_tag::<16>(nonce, aad, plaintext),
            _ => Err(Error::Other(
                "SM4-CCM tag length must be one of {4,6,8,10,12,14,16} bytes".into(),
            )),
        }
    }
    /// Decrypt a message with SM4-CCM.
    ///
    /// # Errors
    /// Returns [`Error::Other`] when tag/nonce sizes are unsupported or authentication fails.
    #[cfg(feature = "sm-ccm")]
    pub fn decrypt_ccm(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match tag.len() {
            4 => self.decrypt_ccm_for_tag::<4>(nonce, aad, ciphertext, tag),
            6 => self.decrypt_ccm_for_tag::<6>(nonce, aad, ciphertext, tag),
            8 => self.decrypt_ccm_for_tag::<8>(nonce, aad, ciphertext, tag),
            10 => self.decrypt_ccm_for_tag::<10>(nonce, aad, ciphertext, tag),
            12 => self.decrypt_ccm_for_tag::<12>(nonce, aad, ciphertext, tag),
            14 => self.decrypt_ccm_for_tag::<14>(nonce, aad, ciphertext, tag),
            16 => self.decrypt_ccm_for_tag::<16>(nonce, aad, ciphertext, tag),
            _ => Err(Error::Other(
                "SM4-CCM tag length must be one of {4,6,8,10,12,14,16} bytes".into(),
            )),
        }
    }
}
impl Zeroize for Sm4Key {
    fn zeroize(&mut self) {
        *self = Sm4Key::new([0u8; 16]);
    }
}
impl ZeroizeOnDrop for Sm4Key {}
impl IntoSchema for Sm4Key {
    fn type_name() -> String {
        "Sm4Key".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        map.insert::<Self>(iroha_schema::Metadata::Tuple(
            iroha_schema::UnnamedFieldsMeta {
                types: vec![core::any::TypeId::of::<[u8; 16]>()],
            },
        ));
    }
}
/// Intrinsic dispatch policy applied to SM acceleration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmIntrinsicPolicy {
    /// Runtime decides at startup based on hardware support (default).
    #[default]
    Auto,
    /// Intrinsics forced on via compile-time or environment override.
    ForceEnable,
    /// Intrinsics forcibly disabled via environment override.
    ForceDisable,
    /// Intrinsics unsupported (non-AArch64 build or feature disabled).
    ScalarOnly,
}
impl SmIntrinsicPolicy {
    #[must_use]
    /// Returns the persistent string identifier for the policy.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ForceEnable => "force-enable",
            Self::ForceDisable => "force-disable",
            Self::ScalarOnly => "scalar-only",
        }
    }
}
impl fmt::Display for SmIntrinsicPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Error returned when parsing [`SmIntrinsicPolicy`] from a string fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmIntrinsicPolicyParseError;
impl fmt::Display for SmIntrinsicPolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "invalid SM intrinsic policy (expected auto|force-enable|force-disable|scalar-only)",
        )
    }
}
impl std::error::Error for SmIntrinsicPolicyParseError {}
impl FromStr for SmIntrinsicPolicy {
    type Err = SmIntrinsicPolicyParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "force-enable" | "force_enable" => Ok(Self::ForceEnable),
            "force-disable" | "force_disable" => Ok(Self::ForceDisable),
            "scalar-only" | "scalar_only" => Ok(Self::ScalarOnly),
            _ => Err(SmIntrinsicPolicyParseError),
        }
    }
}
#[cfg(feature = "json")]
impl JsonSerialize for SmIntrinsicPolicy {
    fn json_serialize(&self, out: &mut String) {
        json::write_json_string(self.as_str(), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(self.as_str(), out)
    }
}
#[cfg(feature = "json")]
impl JsonDeserialize for SmIntrinsicPolicy {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let text = parser.parse_string()?;
        Self::from_str(&text).map_err(|err| json::Error::InvalidField {
            field: "sm_intrinsic_policy".into(),
            message: err.to_string(),
        })
    }
}
/// Apply the configured SM intrinsic dispatch policy.
pub fn set_intrinsic_policy(policy: SmIntrinsicPolicy) {
    sm_accel::set_intrinsic_policy(policy);
}
/// Returns the configured intrinsic policy before hardware detection.
#[must_use]
pub fn configured_intrinsic_policy() -> SmIntrinsicPolicy {
    sm_accel::configured_policy()
}
#[cfg(test)]
mod test_support {
    use std::sync::{Mutex, MutexGuard};
    static SM_ACCEL_STATE_LOCK: Mutex<()> = Mutex::new(());
    pub(super) fn lock_accel_state() -> MutexGuard<'static, ()> {
        SM_ACCEL_STATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
/// Summary of SM acceleration capabilities at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmAccelerationAdvert {
    /// Scalar implementation is always available.
    pub scalar: bool,
    /// `ARMv8` NEON intrinsics usable for SM3 hashing.
    pub neon_sm3: bool,
    /// `ARMv8` NEON intrinsics usable for SM4 block operations.
    pub neon_sm4: bool,
    /// Dispatch policy describing how intrinsics are selected.
    pub policy: SmIntrinsicPolicy,
}
impl SmAccelerationAdvert {
    #[must_use]
    /// Returns the string identifier corresponding to the dispatch policy.
    pub fn as_policy_str(self) -> &'static str {
        self.policy.as_str()
    }
}
/// Return the current SM acceleration advert (scalar + optional intrinsics).
#[must_use]
pub fn acceleration_advert() -> SmAccelerationAdvert {
    let neon_enabled = sm_accel::neon_enabled();
    let policy = match sm_accel::neon_policy() {
        sm_accel::NeonPolicy::ForceEnable => SmIntrinsicPolicy::ForceEnable,
        sm_accel::NeonPolicy::ForceDisable => SmIntrinsicPolicy::ForceDisable,
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        sm_accel::NeonPolicy::Auto => SmIntrinsicPolicy::Auto,
        #[cfg(not(all(feature = "sm-neon", target_arch = "aarch64")))]
        sm_accel::NeonPolicy::Unsupported => SmIntrinsicPolicy::ScalarOnly,
    };
    SmAccelerationAdvert {
        scalar: true,
        neon_sm3: neon_enabled,
        neon_sm4: neon_enabled,
        policy,
    }
}
/// Report the intrinsic dispatch policy applied to SM acceleration.
#[must_use]
pub fn intrinsic_policy() -> SmIntrinsicPolicy {
    match sm_accel::neon_policy() {
        sm_accel::NeonPolicy::ForceEnable => SmIntrinsicPolicy::ForceEnable,
        sm_accel::NeonPolicy::ForceDisable => SmIntrinsicPolicy::ForceDisable,
        #[cfg(all(feature = "sm-neon", target_arch = "aarch64"))]
        sm_accel::NeonPolicy::Auto => SmIntrinsicPolicy::Auto,
        #[cfg(not(all(feature = "sm-neon", target_arch = "aarch64")))]
        sm_accel::NeonPolicy::Unsupported => SmIntrinsicPolicy::ScalarOnly,
    }
}
#[cfg(test)]
mod intrinsic_policy_tests {
    use super::{
        SmIntrinsicPolicy, configured_intrinsic_policy, intrinsic_policy, set_intrinsic_policy,
        test_support,
    };
    struct PolicyGuard {
        previous: SmIntrinsicPolicy,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl PolicyGuard {
        fn new() -> Self {
            let lock = test_support::lock_accel_state();
            Self {
                previous: configured_intrinsic_policy(),
                _lock: lock,
            }
        }
    }
    impl Drop for PolicyGuard {
        fn drop(&mut self) {
            set_intrinsic_policy(self.previous);
        }
    }
    #[test]
    fn setter_overrides_intrinsic_policy() {
        let _guard = PolicyGuard::new();
        set_intrinsic_policy(SmIntrinsicPolicy::ForceDisable);
        assert_eq!(
            configured_intrinsic_policy(),
            SmIntrinsicPolicy::ForceDisable,
            "configured policy should track setter"
        );
        assert_eq!(
            intrinsic_policy(),
            SmIntrinsicPolicy::ForceDisable,
            "runtime policy should honour forced disable"
        );
        set_intrinsic_policy(SmIntrinsicPolicy::ForceEnable);
        assert_eq!(
            configured_intrinsic_policy(),
            SmIntrinsicPolicy::ForceEnable,
            "configured policy should reflect forced enable"
        );
        assert_eq!(
            intrinsic_policy(),
            SmIntrinsicPolicy::ForceEnable,
            "runtime policy should switch to forced enable"
        );
    }
}
#[cfg(feature = "sm-ffi-openssl")]
/// Preview metadata and guard rails for the optional OpenSSL-backed SM provider.
pub mod openssl_provider {
    // The optional provider uses the pinned OpenSSL 3 API. Dependency-private
    // cfg flags do not propagate here; query the actual runtime capabilities.
    use super::openssl_dispatch::Operation;
    use openssl::cipher::Cipher;
    use openssl::{
        hash::{Hasher, MessageDigest},
        version,
    };
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    };
    use thiserror::Error;
    /// Errors that can occur while initialising or querying the OpenSSL provider preview.
    #[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum OpenSslProviderError {
        /// The linked OpenSSL provider does not expose the required SM capabilities.
        #[error("OpenSSL SM provider capability unavailable")]
        NotImplemented,
        /// The OpenSSL preview guard has not been enabled via configuration.
        #[error("OpenSSL SM provider preview is disabled")]
        PreviewDisabled,
        /// OpenSSL runtime symbols are missing or report an unexpected version.
        #[error("OpenSSL unavailable: {0}")]
        OpenSslUnavailable(&'static str),
    }
    /// Preview provider exposing OpenSSL metadata and SM capability checks.
    #[derive(Debug, Clone, Copy)]
    pub struct OpenSslProvider;
    /// Process-lifetime configuration and health for the linked provider.
    #[derive(Default)]
    pub(super) struct RuntimeState {
        enabled: AtomicBool,
        quarantined: AtomicU8,
    }
    impl RuntimeState {
        pub(super) fn set_enabled(&self, enabled: bool) {
            self.enabled.store(enabled, Ordering::SeqCst);
        }
        fn is_enabled(&self) -> bool {
            self.enabled.load(Ordering::SeqCst)
        }
        pub(super) fn can_attempt(&self, operation: Operation) -> bool {
            self.is_enabled() && self.quarantined.load(Ordering::SeqCst) & operation.mask() == 0
        }
        pub(super) fn quarantine(&self, operation: Operation) {
            self.quarantined
                .fetch_or(operation.mask(), Ordering::SeqCst);
        }
    }
    pub(super) fn runtime_state() -> &'static RuntimeState {
        static STATE: OnceLock<RuntimeState> = OnceLock::new();
        STATE.get_or_init(RuntimeState::default)
    }
    impl OpenSslProvider {
        /// Attempt to load the OpenSSL-backed provider.
        ///
        /// The loader enforces the preview guard and validates that the linked OpenSSL build
        /// exposes the SM3 digest and SM4-GCM cipher before
        /// returning success. Deployments lacking these capabilities surface `NotImplemented`
        /// so callers can fall back to the pure-Rust implementation.
        ///
        /// # Errors
        ///
        /// Returns an error when the preview backend is disabled, OpenSSL is unavailable,
        /// or the required SM primitives cannot be fetched.
        pub fn load() -> Result<Self, OpenSslProviderError> {
            if !Self::is_enabled() {
                return Err(OpenSslProviderError::PreviewDisabled);
            }
            if version::number() == 0 {
                return Err(OpenSslProviderError::OpenSslUnavailable(
                    "openssl::version::number returned 0",
                ));
            }
            Hasher::new(MessageDigest::sm3()).map_err(|_| OpenSslProviderError::NotImplemented)?;
            let cipher = Cipher::fetch(None, "SM4-GCM", None)
                .map_err(|_| OpenSslProviderError::NotImplemented)?;
            drop(cipher);
            Ok(Self)
        }
        /// Enable or disable the OpenSSL preview backend explicitly.
        ///
        /// This changes configuration only. Operations quarantined after an operational
        /// failure remain on the canonical Rust path until the process restarts.
        pub fn set_preview_enabled(enabled: bool) {
            runtime_state().set_enabled(enabled);
        }
        /// Returns `true` when the preview backend is toggled on via configuration.
        pub fn is_enabled() -> bool {
            runtime_state().is_enabled()
        }
        /// Returns `true` when OpenSSL runtime symbols are available.
        pub fn is_available() -> bool {
            version::number() != 0
        }
        /// Report the OpenSSL version string for diagnostics.
        pub fn openssl_version() -> &'static str {
            version::version()
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[cfg(feature = "sm-ffi-openssl")]
        struct PreviewFlagGuard {
            previous: bool,
            _lock: std::sync::MutexGuard<'static, ()>,
        }
        #[cfg(feature = "sm-ffi-openssl")]
        impl PreviewFlagGuard {
            fn set(enabled: bool) -> Self {
                let lock = super::super::test_support::lock_accel_state();
                let previous = OpenSslProvider::is_enabled();
                OpenSslProvider::set_preview_enabled(enabled);
                Self {
                    previous,
                    _lock: lock,
                }
            }
            fn enable() -> Self {
                Self::set(true)
            }
        }
        #[cfg(feature = "sm-ffi-openssl")]
        impl Drop for PreviewFlagGuard {
            fn drop(&mut self) {
                OpenSslProvider::set_preview_enabled(self.previous);
            }
        }
        #[test]
        fn load_requires_preview_flag() {
            let _guard = PreviewFlagGuard::set(false);
            let err = OpenSslProvider::load().expect_err("preview disabled blocks load");
            assert_eq!(err, OpenSslProviderError::PreviewDisabled);
        }
        #[test]
        fn unavailable_capability_error_uses_provider_wording() {
            let message = OpenSslProviderError::NotImplemented.to_string();
            assert_eq!(message, "OpenSSL SM provider capability unavailable");
            assert!(
                !message.contains("not implemented"),
                "provider capability errors must not look like unfinished code"
            );
        }
        #[test]
        fn load_matches_linked_provider_capabilities() {
            let _guard = PreviewFlagGuard::enable();
            let expected = version::number() != 0
                && Hasher::new(MessageDigest::sm3()).is_ok()
                && Cipher::fetch(None, "SM4-GCM", None).is_ok();
            assert_eq!(OpenSslProvider::load().is_ok(), expected);
        }
        #[test]
        fn load_validates_backend_capabilities_when_enabled() {
            let _guard = PreviewFlagGuard::enable();
            match OpenSslProvider::load() {
                Ok(_) => {
                    assert!(
                        !OpenSslProvider::openssl_version().is_empty(),
                        "OpenSSL version string should not be empty"
                    );
                }
                Err(OpenSslProviderError::NotImplemented) => {
                    eprintln!("skipping OpenSSL load test: SM capabilities unavailable");
                }
                Err(OpenSslProviderError::OpenSslUnavailable(reason)) => {
                    eprintln!("skipping OpenSSL load test: OpenSSL unavailable ({reason})");
                }
                Err(OpenSslProviderError::PreviewDisabled) => {
                    panic!("preview disabled despite guard enabling it");
                }
            }
        }
    }
}
#[cfg(feature = "sm-ffi-openssl")]
pub use openssl_provider::{OpenSslProvider, OpenSslProviderError};
#[cfg(feature = "sm-ffi-openssl")]
/// Preview OpenSSL-backed implementations for SM primitives.
pub mod openssl_sm {
    use super::OpenSslProvider;
    use openssl::{
        cipher::{Cipher, CipherRef},
        cipher_ctx::CipherCtx,
        error::ErrorStack,
        hash::{Hasher, MessageDigest},
    };
    use thiserror::Error;
    /// Errors returned by the preview OpenSSL SM backend.
    #[derive(Debug, Error)]
    pub enum OpenSslSmError {
        /// Wrapper for lower-level OpenSSL failures.
        #[error("OpenSSL error: {0}")]
        OpenSsl(#[from] ErrorStack),
        /// Raised when the configured preview flag is disabled.
        #[error("OpenSSL SM provider preview is disabled")]
        PreviewDisabled,
        /// Indicates that the linked OpenSSL build does not provide SM4-GCM.
        #[error("SM4 GCM via OpenSSL is unavailable")]
        Sm4GcmNotImplemented,
        /// Indicates that the linked OpenSSL build does not provide SM4-CCM.
        #[error("SM4 CCM via OpenSSL is unavailable")]
        Sm4CcmNotImplemented,
        /// Indicates that the provided SM4 GCM tag has an unexpected length.
        #[error("Invalid SM4 GCM tag length: expected 16 bytes, got {0}")]
        InvalidGcmTagLength(usize),
        /// Indicates that the provided SM4 CCM tag has an unexpected length.
        #[error("Invalid SM4 CCM tag length: expected one of {{4,6,8,10,12,14,16}} bytes, got {0}")]
        InvalidCcmTagLength(usize),
        /// Indicates that the provided SM4 key has an unexpected length.
        #[error("Invalid SM4 key length: expected 16 bytes, got {0}")]
        InvalidKeyLength(usize),
        /// Indicates that the provided SM4 nonce has an unexpected length.
        #[error("Invalid SM4 nonce length: expected 12 bytes, got {0}")]
        InvalidNonceLength(usize),
        /// Indicates that the provided SM4 CCM nonce has an unexpected length.
        #[error("Invalid SM4 CCM nonce length: expected between 7 and 13 bytes, got {0}")]
        InvalidCcmNonceLength(usize),
    }
    /// Preview-only facade over the optional OpenSSL-backed SM primitives.
    #[derive(Debug, Clone, Copy)]
    pub struct OpenSslSmBackend;
    fn fetch_sm4_gcm_cipher() -> Result<Cipher, OpenSslSmError> {
        Cipher::fetch(None, "SM4-GCM", None).map_err(|_| OpenSslSmError::Sm4GcmNotImplemented)
    }
    #[cfg(feature = "sm-ccm")]
    #[allow(dead_code)]
    fn fetch_sm4_ccm_cipher() -> Result<Cipher, OpenSslSmError> {
        Cipher::fetch(None, "SM4-CCM", None).map_err(|_| OpenSslSmError::Sm4CcmNotImplemented)
    }
    fn validate_sm4_gcm_params(
        key: &[u8],
        nonce: &[u8],
        tag_len: usize,
    ) -> Result<(), OpenSslSmError> {
        if key.len() != 16 {
            return Err(OpenSslSmError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != 12 {
            return Err(OpenSslSmError::InvalidNonceLength(nonce.len()));
        }
        if tag_len != 16 {
            return Err(OpenSslSmError::InvalidGcmTagLength(tag_len));
        }
        Ok(())
    }
    #[cfg(feature = "sm-ccm")]
    fn validate_sm4_ccm_params(
        key: &[u8],
        nonce: &[u8],
        tag_len: usize,
    ) -> Result<(), OpenSslSmError> {
        const VALID_TAG_LENS: [usize; 7] = [4, 6, 8, 10, 12, 14, 16];
        if key.len() != 16 {
            return Err(OpenSslSmError::InvalidKeyLength(key.len()));
        }
        if !(7..=13).contains(&nonce.len()) {
            return Err(OpenSslSmError::InvalidCcmNonceLength(nonce.len()));
        }
        if !VALID_TAG_LENS.contains(&tag_len) {
            return Err(OpenSslSmError::InvalidCcmTagLength(tag_len));
        }
        Ok(())
    }
    impl OpenSslSmBackend {
        /// Hashes input bytes using OpenSSL's SM3 implementation when the preview is enabled.
        ///
        /// # Errors
        ///
        /// Returns `Err` if the preview backend is disabled or OpenSSL hashing fails.
        pub fn sm3_digest(input: &[u8]) -> Result<[u8; 32], OpenSslSmError> {
            if !OpenSslProvider::is_enabled() {
                return Err(OpenSslSmError::PreviewDisabled);
            }
            let mut hasher = Hasher::new(MessageDigest::sm3())?;
            hasher.update(input)?;
            let digest = hasher.finish()?;
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        /// Encrypt data using OpenSSL's SM4-GCM implementation.
        ///
        /// # Errors
        ///
        /// Returns `Err` when preview support is disabled or the underlying OpenSSL calls fail.
        pub fn sm4_gcm_encrypt(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<(Vec<u8>, [u8; 16]), OpenSslSmError> {
            if !OpenSslProvider::is_enabled() {
                return Err(OpenSslSmError::PreviewDisabled);
            }
            validate_sm4_gcm_params(key, nonce, 16)?;
            let cipher = fetch_sm4_gcm_cipher()?;
            let mut ctx = CipherCtx::new()?;
            let cipher_ref: &CipherRef = &cipher;
            ctx.encrypt_init(Some(cipher_ref), None, None)?;
            ctx.set_iv_length(nonce.len())?;
            ctx.encrypt_init(None, Some(key), Some(nonce))?;
            if !aad.is_empty() {
                ctx.cipher_update(aad, None)?;
            }
            let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
            let mut written = ctx.cipher_update(plaintext, Some(&mut ciphertext))?;
            written += ctx.cipher_final(&mut ciphertext[written..])?;
            ciphertext.truncate(written);
            let mut tag = [0u8; 16];
            ctx.tag(&mut tag)?;
            Ok((ciphertext, tag))
        }
        /// Decrypt data using OpenSSL's SM4-GCM implementation.
        ///
        /// # Errors
        ///
        /// Returns `Err` when preview support is disabled, validation fails, or OpenSSL reports an error.
        pub fn sm4_gcm_decrypt(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8; 16],
        ) -> Result<Vec<u8>, OpenSslSmError> {
            if !OpenSslProvider::is_enabled() {
                return Err(OpenSslSmError::PreviewDisabled);
            }
            validate_sm4_gcm_params(key, nonce, tag.len())?;
            let cipher = fetch_sm4_gcm_cipher()?;
            let mut ctx = CipherCtx::new()?;
            let cipher_ref: &CipherRef = &cipher;
            ctx.decrypt_init(Some(cipher_ref), None, None)?;
            ctx.set_iv_length(nonce.len())?;
            ctx.decrypt_init(None, Some(key), Some(nonce))?;
            if !aad.is_empty() {
                ctx.cipher_update(aad, None)?;
            }
            ctx.set_tag(tag)?;
            let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
            let mut written = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
            written += ctx.cipher_final(&mut plaintext[written..])?;
            plaintext.truncate(written);
            Ok(plaintext)
        }
        /// Encrypt data using OpenSSL's SM4-CCM implementation when preview support is enabled.
        ///
        /// # Errors
        ///
        /// Returns `Err` when preview support is disabled, parameter validation fails, or the
        /// provider does not implement SM4-CCM.
        #[cfg(feature = "sm-ccm")]
        pub fn sm4_ccm_encrypt(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
            tag_len: usize,
        ) -> Result<(Vec<u8>, Vec<u8>), OpenSslSmError> {
            if !OpenSslProvider::is_enabled() {
                return Err(OpenSslSmError::PreviewDisabled);
            }
            validate_sm4_ccm_params(key, nonce, tag_len)?;
            let cipher = fetch_sm4_ccm_cipher()?;
            let mut ctx = CipherCtx::new()?;
            let cipher_ref: &CipherRef = &cipher;
            ctx.encrypt_init(Some(cipher_ref), None, None)?;
            ctx.set_iv_length(nonce.len())?;
            ctx.set_tag_length(tag_len)?;
            ctx.encrypt_init(None, Some(key), Some(nonce))?;
            ctx.set_data_len(plaintext.len())?;
            if !aad.is_empty() {
                ctx.cipher_update(aad, None)?;
            }
            let mut ciphertext = Vec::with_capacity(plaintext.len());
            ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
            ctx.cipher_final_vec(&mut ciphertext)?;
            let mut tag = vec![0u8; tag_len];
            ctx.tag(&mut tag)?;
            Ok((ciphertext, tag))
        }
        /// Decrypt data using OpenSSL's SM4-CCM implementation when preview support is enabled.
        ///
        /// # Errors
        ///
        /// Returns `Err` when preview support is disabled, validation fails, or the provider lacks
        /// SM4-CCM support.
        #[cfg(feature = "sm-ccm")]
        pub fn sm4_ccm_decrypt(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8],
        ) -> Result<Vec<u8>, OpenSslSmError> {
            if !OpenSslProvider::is_enabled() {
                return Err(OpenSslSmError::PreviewDisabled);
            }
            validate_sm4_ccm_params(key, nonce, tag.len())?;
            let cipher = fetch_sm4_ccm_cipher()?;
            let mut ctx = CipherCtx::new()?;
            let cipher_ref: &CipherRef = &cipher;
            ctx.decrypt_init(Some(cipher_ref), None, None)?;
            ctx.set_iv_length(nonce.len())?;
            ctx.set_tag(tag)?;
            ctx.decrypt_init(None, Some(key), Some(nonce))?;
            ctx.set_data_len(ciphertext.len())?;
            if !aad.is_empty() {
                ctx.cipher_update(aad, None)?;
            }
            let mut plaintext = Vec::with_capacity(ciphertext.len());
            ctx.cipher_update_vec(ciphertext, &mut plaintext)?;
            Ok(plaintext)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{sm_accel, *};
    use hex::decode as hex_decode;
    use rand_core::{OsRng, TryCryptoRng, TryRngCore};
    use signature::hazmat::PrehashVerifier;
    use sm2::elliptic_curve::sec1::ToEncodedPoint;
    use sm3::Sm3;
    use std::str::FromStr;
    const ANNEX_SIG_HEX: &str = "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D16FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7";
    const ANNEX_SIG_DER_HEX: &str = "3044022040F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D102206FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7";
    const ANNEX_PUBKEY_HEX: &str = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
    const ANNEX_Z_HEX: &str = "F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A";
    const SM3_ABC_HEX: &str = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";
    const SM4_GMT_VECTOR_KEY: &str = "0123456789abcdeffedcba9876543210";
    const SM4_GMT_VECTOR_BLOCK: &str = "0123456789abcdeffedcba9876543210";
    const SM4_GMT_VECTOR_CIPHERTEXT: &str = "681EDF34D206965E86B3E94F536E4246";
    struct FailingTryRng;
    #[derive(Debug)]
    struct FailingTryRngError;
    impl std::fmt::Display for FailingTryRngError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("failing SM2 RNG")
        }
    }
    impl TryRngCore for FailingTryRng {
        type Error = FailingTryRngError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(FailingTryRngError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(FailingTryRngError)
        }
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
            Err(FailingTryRngError)
        }
    }
    impl TryCryptoRng for FailingTryRng {}
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
    impl TryCryptoRng for FixedTryRng {}
    struct IntrinsicPolicyGuard {
        previous: SmIntrinsicPolicy,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl IntrinsicPolicyGuard {
        fn set(policy: SmIntrinsicPolicy) -> Self {
            let lock = test_support::lock_accel_state();
            let previous = configured_intrinsic_policy();
            set_intrinsic_policy(policy);
            Self {
                previous,
                _lock: lock,
            }
        }
    }
    impl Drop for IntrinsicPolicyGuard {
        fn drop(&mut self) {
            set_intrinsic_policy(self.previous);
        }
    }
    #[cfg(all(feature = "sm-ffi-openssl", feature = "sm-ccm"))]
    struct OpenSslPreviewGuard {
        previous: bool,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    #[cfg(all(feature = "sm-ffi-openssl", feature = "sm-ccm"))]
    impl OpenSslPreviewGuard {
        fn set(enabled: bool) -> Self {
            let lock = test_support::lock_accel_state();
            let previous = OpenSslProvider::is_enabled();
            OpenSslProvider::set_preview_enabled(enabled);
            Self {
                previous,
                _lock: lock,
            }
        }
    }
    #[cfg(all(feature = "sm-ffi-openssl", feature = "sm-ccm"))]
    impl Drop for OpenSslPreviewGuard {
        fn drop(&mut self) {
            OpenSslProvider::set_preview_enabled(self.previous);
        }
    }
    #[test]
    fn sm_intrinsic_policy_parse_accepts_aliases() {
        assert_eq!(
            SmIntrinsicPolicy::from_str("auto").unwrap(),
            SmIntrinsicPolicy::Auto
        );
        assert_eq!(
            SmIntrinsicPolicy::from_str("force-enable").unwrap(),
            SmIntrinsicPolicy::ForceEnable
        );
        assert_eq!(
            SmIntrinsicPolicy::from_str("force_disable").unwrap(),
            SmIntrinsicPolicy::ForceDisable
        );
        assert_eq!(
            SmIntrinsicPolicy::from_str("scalar-only").unwrap(),
            SmIntrinsicPolicy::ScalarOnly
        );
        assert!(SmIntrinsicPolicy::from_str("not-a-policy").is_err());
    }
    #[test]
    fn sm_intrinsic_policy_setter_updates_configuration() {
        let _guard = IntrinsicPolicyGuard::set(SmIntrinsicPolicy::ForceDisable);
        assert_eq!(
            configured_intrinsic_policy(),
            SmIntrinsicPolicy::ForceDisable
        );
    }
    fn hex_to_vec(hex: &str) -> Vec<u8> {
        hex_decode(hex).expect("valid hex")
    }
    fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_to_vec(hex);
        bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("expected {N} bytes"))
    }
    fn manual_compute_z(distid: &str, public: &Sm2PublicKey) -> [u8; 32] {
        let entla_bits = distid
            .len()
            .checked_mul(8)
            .expect("distid length fits in usize");
        let entla = u16::try_from(entla_bits)
            .expect("distid length fits in u16 bits")
            .to_be_bytes();
        let mut hasher = Sm3::new();
        hasher.update(entla);
        hasher.update(distid.as_bytes());
        hasher.update(SM2_EQUATION_A_BYTES);
        hasher.update(SM2_EQUATION_B_BYTES);
        hasher.update(SM2_GENERATOR_X_BYTES);
        hasher.update(SM2_GENERATOR_Y_BYTES);
        let encoded = public.as_inner().as_affine().to_encoded_point(false);
        let sm2::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } = encoded.coordinates()
        else {
            panic!("SM2 public key must encode as uncompressed SEC1 point");
        };
        hasher.update(x);
        hasher.update(y);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
    #[test]
    fn sm3_digest_has_expected_length() {
        let digest = Sm3Digest::hash(b"Iroha");
        assert_eq!(digest.as_bytes().len(), 32);
    }
    #[test]
    fn sm4_block_encrypt_roundtrip() {
        let key = Sm4Key::new([0x11; 16]);
        let plaintext = [0u8; 16];
        let ciphertext = key.encrypt_block(&plaintext);
        let decrypted = key.decrypt_block(&ciphertext);
        assert_eq!(plaintext, decrypted);
    }
    #[test]
    fn sm3_digest_matches_gm_standard_vector() {
        let digest = Sm3Digest::hash(b"abc");
        assert_eq!(hex::encode_upper(digest.as_bytes()), SM3_ABC_HEX);
    }
    #[test]
    fn sm3_digest_fallback_produces_expected_bytes() {
        let _accel_lock = test_support::lock_accel_state();
        let _guard = sm_accel::tests::force_disable_all_for_tests();
        let digest = Sm3Digest::hash(b"abc");
        assert_eq!(hex::encode_upper(digest.as_bytes()), SM3_ABC_HEX);
    }
    #[test]
    fn sm4_block_encrypt_matches_gm_standard_vector() {
        let key = Sm4Key::new(hex_to_array::<16>(SM4_GMT_VECTOR_KEY));
        let block = hex_to_array::<16>(SM4_GMT_VECTOR_BLOCK);
        let ciphertext = key.encrypt_block(&block);
        assert_eq!(hex::encode_upper(ciphertext), SM4_GMT_VECTOR_CIPHERTEXT);
    }
    #[test]
    fn sm4_block_encrypt_fallback_matches_reference_vector() {
        let _accel_lock = test_support::lock_accel_state();
        let _guard = sm_accel::tests::force_disable_all_for_tests();
        let key = Sm4Key::new(hex_to_array::<16>(SM4_GMT_VECTOR_KEY));
        let block = hex_to_array::<16>(SM4_GMT_VECTOR_BLOCK);
        let ciphertext = key.encrypt_block(&block);
        assert_eq!(hex::encode_upper(ciphertext), SM4_GMT_VECTOR_CIPHERTEXT);
    }
    #[test]
    fn sm4_scalar_fixed_key_constructor_matches_fallible_reference() {
        let key = hex_to_array::<16>(SM4_GMT_VECTOR_KEY);
        let block = hex_to_array::<16>(SM4_GMT_VECTOR_BLOCK);
        let reference_cipher = sm4::Sm4::new_from_slice(&key).expect("valid reference SM4 key");
        let mut reference_ciphertext_block = Block::<sm4::Sm4>::default();
        reference_ciphertext_block.clone_from_slice(&block);
        reference_cipher.encrypt_block(&mut reference_ciphertext_block);
        let mut reference_ciphertext = [0u8; 16];
        reference_ciphertext.copy_from_slice(reference_ciphertext_block.as_ref());
        let scalar_ciphertext = sm4_encrypt_block_scalar(&key, &block);
        assert_eq!(scalar_ciphertext, reference_ciphertext);
        let mut reference_plaintext_block = Block::<sm4::Sm4>::default();
        reference_plaintext_block.clone_from_slice(&scalar_ciphertext);
        reference_cipher.decrypt_block(&mut reference_plaintext_block);
        let mut reference_plaintext = [0u8; 16];
        reference_plaintext.copy_from_slice(reference_plaintext_block.as_ref());
        let scalar_plaintext = sm4_decrypt_block_scalar(&key, &scalar_ciphertext);
        assert_eq!(scalar_plaintext, reference_plaintext);
        assert_eq!(scalar_plaintext, block);
    }
    #[test]
    fn sm2_public_key_pem_roundtrip() {
        let mut rng = OsRng;
        let private = Sm2PrivateKey::try_random("custom-distid", &mut rng).expect("valid distid");
        let public = private.public_key();
        let pem = public
            .to_public_key_pem()
            .expect("encode SM2 public key to PEM");
        let decoded = Sm2PublicKey::from_public_key_pem("custom-distid", &pem)
            .expect("decode SM2 public key");
        assert_eq!(decoded.to_sec1_bytes(false), public.to_sec1_bytes(false));
    }
    #[test]
    fn sm2_pem_wrapping_uses_ascii_base64_string_slices() {
        let der = [0x42_u8; 49];
        let pem = encode_pem("TEST OBJECT", &der);
        let lines = pem.lines().collect::<Vec<_>>();
        assert_eq!(lines.first().copied(), Some("-----BEGIN TEST OBJECT-----"));
        assert_eq!(lines.last().copied(), Some("-----END TEST OBJECT-----"));
        assert_eq!(
            lines.get(1).map(|line| line.len()),
            Some(64),
            "first base64 PEM line must be wrapped at 64 characters"
        );
        assert_eq!(
            lines.get(2).map(|line| line.len()),
            Some(4),
            "remaining base64 PEM line must preserve the tail"
        );
    }
    #[test]
    fn sm2_compute_z_matches_annex_example() {
        let distid = "ALICE123@YAHOO.COM";
        match Sm2PublicKey::from_sec1_bytes(distid, &hex_to_vec(ANNEX_PUBKEY_HEX)) {
            Ok(public) => {
                let za = public.compute_z(distid).expect("compute ZA");
                assert_eq!(hex::encode_upper(za), ANNEX_Z_HEX);
            }
            Err(err) => {
                assert_eq!(
                    err,
                    crate::ParseError("invalid SM2 public key".to_owned()),
                    "unexpected error parsing Annex Example 1 public key"
                );
            }
        }
    }
    #[test]
    fn sm2_compute_z_aligns_with_signing_key() {
        let mut rng = OsRng;
        let distid = "device:alpha";
        let private = Sm2PrivateKey::try_random(distid, &mut rng).expect("valid distid");
        let public = private.public_key();
        let za = public.compute_z(distid).expect("compute ZA");
        let message = b"za alignment check";
        let signature = private.sign(message);
        let raw_signature =
            Sm2RawSignature::from_bytes(&signature.as_bytes()).expect("convert to raw signature");
        let mut sm3 = Sm3::new();
        sm3.update(za);
        sm3.update(message);
        let prehash = sm3.finalize();
        let verifier = sm2::dsa::VerifyingKey::from_affine(distid, *public.as_inner().as_affine())
            .expect("construct verifier");
        verifier
            .verify_prehash(prehash.as_slice(), &raw_signature)
            .expect("signature verifies with computed ZA");
    }
    #[test]
    fn sm2_compute_z_matches_manual_formula_samples() {
        use rand::{RngCore as _, SeedableRng as _};
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_seed([0xA5; 32]);
        for _ in 0..128 {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let length = (rng.next_u32() as usize) % 64;
            let distid: String = if length == 0 {
                Sm2PublicKey::DEFAULT_DISTID.to_owned()
            } else {
                (0..length)
                    .map(|_| {
                        let byte = b'!' + (rng.next_u32() % 94) as u8;
                        byte as char
                    })
                    .collect()
            };
            let private = match Sm2PrivateKey::from_seed(&distid, &seed) {
                Ok(private) => private,
                Err(_) => continue,
            };
            let public = private.public_key();
            let manual = manual_compute_z(&distid, &public);
            let computed = public.compute_z(&distid).expect("compute ZA");
            assert_eq!(
                manual, computed,
                "ZA mismatch for distinguishing identifier {distid}"
            );
        }
    }
    #[test]
    fn sm4_gcm_vector_matches_rfc8998() {
        let key = Sm4Key::new(hex_to_array::<16>("0123456789abcdeffedcba9876543210"));
        let nonce = hex_to_array::<12>("00001234567800000000abcd");
        let aad = hex_to_vec("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_to_vec("d9313225f88406e5a55909c5aff5269a");
        let (ciphertext, tag) = key.encrypt_gcm(&nonce, &aad, &plaintext).expect("encrypt");
        let decrypted = key
            .decrypt_gcm(&nonce, &aad, &ciphertext, &tag)
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
    #[test]
    fn sm4_gcm_rejects_modified_tag() {
        let key = Sm4Key::new(hex_to_array::<16>("0123456789abcdeffedcba9876543210"));
        let nonce = hex_to_array::<12>("00001234567800000000abcd");
        let aad = hex_to_vec("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_to_vec("d9313225f88406e5a55909c5aff5269a");
        let (ciphertext, mut tag) = key.encrypt_gcm(&nonce, &aad, &plaintext).expect("encrypt");
        tag[0] ^= 0xFF;
        let result = key.decrypt_gcm(&nonce, &aad, &ciphertext, &tag);
        assert!(result.is_err(), "tampering must fail verification");
    }
    #[test]
    fn sm4_ccm_vector_matches_rfc8998() {
        let key = Sm4Key::new(hex_to_array::<16>("404142434445464748494a4b4c4d4e4f"));
        let nonce = hex_to_vec("10111213141516");
        let aad = hex_to_vec("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_to_vec("202122232425262728292a2b2c2d2e2f");
        let (ciphertext, tag) = key
            .encrypt_ccm(&nonce, &aad, &plaintext, 4)
            .expect("SM4-CCM encryption must succeed");
        let decrypted = key
            .decrypt_ccm(&nonce, &aad, &ciphertext, &tag)
            .expect("SM4-CCM decryption must succeed");
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext, hex_to_vec("a9550cebab5f227d9590e8979caafd1f"));
        assert_eq!(tag, hex_to_vec("03a1f305"));
    }
    #[test]
    fn sm4_ccm_rejects_modified_tag() {
        let key = Sm4Key::new(hex_to_array::<16>("404142434445464748494a4b4c4d4e4f"));
        let nonce = hex_to_vec("10111213141516");
        let aad = hex_to_vec("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_to_vec("202122232425262728292a2b2c2d2e2f");
        let (ciphertext, mut tag) = key
            .encrypt_ccm(&nonce, &aad, &plaintext, 4)
            .expect("SM4-CCM encryption must succeed");
        tag[0] ^= 0xFF;
        assert!(
            key.decrypt_ccm(&nonce, &aad, &ciphertext, &tag).is_err(),
            "altered tag must fail verification"
        );
    }
    #[test]
    fn sm4_ccm_rejects_invalid_parameters() {
        let key = Sm4Key::new([0x01; 16]);
        let nonce = vec![0u8; 6];
        assert!(
            key.encrypt_ccm(&nonce, &[], &[], 4).is_err(),
            "nonce shorter than 7 bytes must be rejected"
        );
        let nonce = vec![0u8; 7];
        assert!(
            key.encrypt_ccm(&nonce, &[], &[], 5).is_err(),
            "unsupported tag length must be rejected"
        );
    }
    #[cfg(all(feature = "sm-ffi-openssl", feature = "sm-ccm"))]
    #[test]
    fn openssl_sm4_ccm_preview_matches_rfc8998_when_available() {
        let _guard = OpenSslPreviewGuard::set(true);
        let key_bytes = hex_to_array::<16>("404142434445464748494a4b4c4d4e4f");
        let nonce = hex_to_vec("10111213141516");
        let aad = hex_to_vec("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex_to_vec("202122232425262728292a2b2c2d2e2f");
        let expected_ciphertext = hex_to_vec("a9550cebab5f227d9590e8979caafd1f");
        let expected_tag = hex_to_vec("03a1f305");
        let (ciphertext, tag) =
            match OpenSslSmBackend::sm4_ccm_encrypt(&key_bytes, &nonce, &aad, &plaintext, 4) {
                Ok(result) => result,
                Err(OpenSslSmError::Sm4CcmNotImplemented) => {
                    eprintln!("skipping OpenSSL SM4-CCM test: provider cipher unavailable");
                    return;
                }
                Err(OpenSslSmError::PreviewDisabled) => {
                    panic!("OpenSSL SM4-CCM preview disabled despite test guard");
                }
                Err(err) => panic!("unexpected OpenSSL SM4-CCM encrypt error: {err:?}"),
            };
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);
        assert_eq!(
            OpenSslSmBackend::sm4_ccm_decrypt(&key_bytes, &nonce, &aad, &ciphertext, &tag)
                .expect("OpenSSL SM4-CCM decrypts RFC8998 vector"),
            plaintext
        );
        let mut tampered_tag = tag.clone();
        tampered_tag[0] ^= 0xff;
        assert!(
            OpenSslSmBackend::sm4_ccm_decrypt(
                &key_bytes,
                &nonce,
                &aad,
                &ciphertext,
                &tampered_tag,
            )
            .is_err(),
            "OpenSSL SM4-CCM must reject modified tags"
        );
        let key = Sm4Key::new(key_bytes);
        let (routed_ciphertext, routed_tag) = key
            .encrypt_ccm(&nonce, &aad, &plaintext, 4)
            .expect("public SM4-CCM path encrypts with OpenSSL preview or fallback");
        assert_eq!(routed_ciphertext, expected_ciphertext);
        assert_eq!(routed_tag, expected_tag);
        assert_eq!(
            key.decrypt_ccm(&nonce, &aad, &routed_ciphertext, &routed_tag)
                .expect("public SM4-CCM path decrypts with OpenSSL preview or fallback"),
            plaintext
        );
    }
    #[test]
    fn sm2_signature_roundtrip_and_verify() {
        let private =
            Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, [0x11; 32]).expect("secret key");
        let message = b"hello world";
        let signature = private.sign(message);
        let public = private.public_key();
        public
            .verify(message, &signature)
            .expect("signature verifies");
    }
    #[test]
    fn sm2_signature_from_bytes_rejects_zero_scalars_before_backend() {
        let all_zero = [0u8; Sm2Signature::LENGTH];
        let err = Sm2Signature::from_bytes(&all_zero)
            .expect_err("all-zero SM2 signature must fail before backend parsing");
        assert!(err.to_string().contains("all-zero"));
        let mut zero_r = [0u8; Sm2Signature::LENGTH];
        zero_r[Sm2Signature::LENGTH - 1] = 1;
        let err =
            Sm2Signature::from_bytes(&zero_r).expect_err("zero r scalar must fail before backend");
        assert!(err.to_string().contains("zero scalar"));
        let mut zero_s = [0u8; Sm2Signature::LENGTH];
        zero_s[31] = 1;
        let err =
            Sm2Signature::from_bytes(&zero_s).expect_err("zero s scalar must fail before backend");
        assert!(err.to_string().contains("zero scalar"));
    }
    #[test]
    fn sm2_public_key_from_sec1_bytes_rejects_all_zero_material_before_backend() {
        let all_zero = [0u8; 65];
        let err = Sm2PublicKey::from_sec1_bytes(Sm2PublicKey::DEFAULT_DISTID, &all_zero)
            .expect_err("all-zero SM2 SEC1 public key must fail before backend parsing");
        assert!(
            err.to_string().contains("all-zero"),
            "unexpected all-zero public key error: {err}"
        );
    }
    #[test]
    fn sm2_public_key_from_sec1_bytes_rejects_zero_coordinate_material_before_backend() {
        let mut zero_coordinates = [0u8; SM2_PUBLIC_KEY_UNCOMPRESSED_LEN];
        zero_coordinates[0] = 0x04;
        let err = Sm2PublicKey::from_sec1_bytes(Sm2PublicKey::DEFAULT_DISTID, &zero_coordinates)
            .expect_err("zero-coordinate SM2 SEC1 public key must fail before backend parsing");
        assert!(
            err.to_string().contains("all-zero SEC1 coordinate"),
            "unexpected zero-coordinate public key error: {err}"
        );
    }
    #[test]
    fn sm2_public_key_verify_maps_malformed_signature_to_bad_signature() {
        let private =
            Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, [0x13; 32]).expect("secret key");
        let public = private.public_key();
        let mut s = [0u8; 32];
        s[31] = 1;
        let malformed = Sm2Signature { r: [0u8; 32], s };
        let err = public
            .verify(b"message", &malformed)
            .expect_err("malformed in-memory signature must fail closed");
        assert!(matches!(err, Error::BadSignature));
    }
    #[test]
    fn sm2_try_sign_roundtrip_and_verify() {
        let private =
            Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, [0x12; 32]).expect("secret key");
        let message = b"hello checked sm2";
        let signature = private.try_sign(message).expect("checked SM2 signing");
        let public = private.try_public_key().expect("checked public key");
        public
            .verify(message, &signature)
            .expect("signature verifies");
    }
    #[test]
    fn sm2_random_private_key_roundtrip() {
        let mut rng = OsRng;
        let private = Sm2PrivateKey::try_random(Sm2PublicKey::DEFAULT_DISTID, &mut rng)
            .expect("valid distid");
        let message = b"random sm2";
        let signature = private.sign(message);
        let public = private.public_key();
        public
            .verify(message, &signature)
            .expect("signature verifies");
    }
    #[test]
    fn sm2_try_random_reports_rng_failure() {
        let mut rng = FailingTryRng;
        match Sm2PrivateKey::try_random(Sm2PublicKey::DEFAULT_DISTID, &mut rng) {
            Err(ParseError(message)) => {
                assert!(message.contains("SM2 RNG failed"));
                assert!(message.contains("failing SM2 RNG"));
            }
            Ok(_) => panic!("RNG failure must be reported"),
        }
    }
    #[test]
    fn sm2_try_random_from_os_roundtrip() {
        let private =
            Sm2PrivateKey::try_random_from_os(Sm2PublicKey::DEFAULT_DISTID).expect("OS SM2 key");
        let message = b"checked OS random sm2";
        let signature = private.sign(message);
        let public = private.public_key();
        public
            .verify(message, &signature)
            .expect("signature verifies");
    }
    #[test]
    fn sm2_default_distid_can_be_overridden() {
        let original = Sm2PublicKey::default_distid();
        Sm2PublicKey::set_default_distid("override-distid").expect("valid distid should set");
        assert_eq!(Sm2PublicKey::default_distid(), "override-distid");
        Sm2PublicKey::set_default_distid(original).expect("restore distid");
    }
    #[test]
    fn sm2_default_distid_rejects_invalid_value() {
        let original = Sm2PublicKey::default_distid();
        let distid = "a".repeat(8192);
        assert!(
            Sm2PublicKey::set_default_distid(distid).is_err(),
            "expected invalid distid to be rejected"
        );
        assert_eq!(Sm2PublicKey::default_distid(), original);
    }
    #[test]
    fn sm2_public_key_equality_includes_distid() {
        let secret = [0x44u8; 32];
        let a = Sm2PrivateKey::new("distid-a", secret).expect("sm2 key a");
        let b = Sm2PrivateKey::new("distid-b", secret).expect("sm2 key b");
        let pk_a = a.public_key();
        let pk_b = b.public_key();
        assert_eq!(pk_a.to_sec1_bytes(false), pk_b.to_sec1_bytes(false));
        assert_ne!(pk_a, pk_b);
    }
    #[test]
    fn sm2_private_key_pkcs8_roundtrip() {
        let original = Sm2PrivateKey::from_seed("roundtrip-distid", b"deterministic-seed")
            .expect("seeded key");
        let pem = original.to_pkcs8_pem().expect("encode pkcs8 pem");
        let restored =
            Sm2PrivateKey::from_pkcs8_pem("roundtrip-distid", &pem).expect("decode pkcs8 pem");
        assert_eq!(
            original.public_key().to_sec1_bytes(false),
            restored.public_key().to_sec1_bytes(false)
        );
    }
    #[test]
    fn sm2_from_seed_rejects_all_zero_seed_material() {
        match Sm2PrivateKey::from_seed(Sm2PublicKey::DEFAULT_DISTID, &[0u8; 32]) {
            Err(err) => assert!(
                err.to_string().contains("all zero"),
                "unexpected all-zero seed error: {err:?}"
            ),
            Ok(_) => panic!("all-zero SM2 seed material must fail"),
        }
    }
    #[test]
    fn sm2_private_key_from_bytes_rejects_all_zero_material() {
        let err = match Sm2PrivateKey::from_bytes(Sm2PublicKey::DEFAULT_DISTID, &[0u8; 32]) {
            Ok(_) => panic!("all-zero SM2 private-key material must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero private-key error: {err}"
        );
    }
    #[test]
    fn sm2_try_random_rejects_all_zero_rng_material() {
        let mut rng = FixedTryRng { byte: 0 };
        match Sm2PrivateKey::try_random(Sm2PublicKey::DEFAULT_DISTID, &mut rng) {
            Err(err) => assert!(
                err.to_string().contains("all-zero seed material"),
                "unexpected all-zero RNG error: {err:?}"
            ),
            Ok(_) => panic!("all-zero SM2 RNG material must fail"),
        }
    }
    #[test]
    fn sm2_from_seed_rejects_invalid_distid_before_derivation() {
        let oversized_distid = "x".repeat((u16::MAX as usize / 8) + 1);
        match Sm2PrivateKey::from_seed(&oversized_distid, b"valid-seed") {
            Err(err) => assert!(
                err.to_string().contains("exceeds 65535 bits"),
                "unexpected distid error: {err:?}"
            ),
            Ok(_) => panic!("oversized SM2 distinguishing identifier must fail"),
        }
    }
    #[test]
    fn sm2_payload_roundtrip_preserves_distid() {
        let distid = "payload-distid";
        let private = Sm2PrivateKey::from_seed(distid, b"payload-seed").expect("seeded key");
        let public = private.public_key();
        let sec1 = public.to_sec1_bytes(false);
        let public_payload =
            encode_sm2_public_key_payload(distid, &sec1).expect("encode public payload");
        let decoded_public =
            decode_sm2_public_key_payload(&public_payload).expect("decode public payload");
        assert_eq!(decoded_public.to_sec1_bytes(false), sec1);
        assert_eq!(decoded_public.distid(), distid);
        let secret = private.secret_bytes();
        let private_payload =
            encode_sm2_private_key_payload(distid, &secret).expect("encode private payload");
        let decoded_private =
            decode_sm2_private_key_payload(&private_payload).expect("decode private payload");
        assert_eq!(decoded_private.secret_bytes(), secret);
        assert_eq!(decoded_private.distid(), distid);
    }
    #[test]
    fn sm2_payload_decode_rejects_short_length_prefix() {
        let err = match decode_sm2_public_key_payload(&[0x01]) {
            Ok(_) => panic!("short SM2 public payload prefix must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("missing distid length prefix"),
            "unexpected error: {err}"
        );
        let err = match decode_sm2_private_key_payload(&[0x01]) {
            Ok(_) => panic!("short SM2 private payload prefix must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("missing distid length prefix"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn sm2_distid_length_overflow_is_rejected() {
        let distid = "a".repeat(8192);
        let secret = [0x11u8; 32];
        assert!(
            Sm2PrivateKey::from_bytes(distid.clone(), &secret).is_err(),
            "expected oversized distid to be rejected"
        );
        let key = Sm2PrivateKey::from_seed("short-distid", b"seed").expect("seeded key");
        let sec1 = key.public_key().to_sec1_bytes(false);
        assert!(
            Sm2PublicKey::from_sec1_bytes(&distid, &sec1).is_err(),
            "expected oversized distid to be rejected"
        );
    }
    #[test]
    fn sm2_try_random_rejects_invalid_distid() {
        let mut rng = OsRng;
        let distid = "a".repeat(8192);
        assert!(Sm2PrivateKey::try_random(distid, &mut rng).is_err());
    }
    #[test]
    fn sm2_public_key_prefixed_string_matches_public_key_helper() {
        use crate::{Algorithm, PublicKey};
        let private =
            Sm2PrivateKey::from_seed("prefixed-distid", b"prefixed-seed").expect("derive key");
        let public = private.public_key();
        let prefixed = public
            .try_to_prefixed_string()
            .expect("checked SM2 prefixed formatting");
        assert!(
            prefixed.starts_with("sm2:"),
            "prefixed multihash must include sm2 prefix"
        );
        assert_eq!(public.to_prefixed_string(), prefixed);
        let sec1 = public.to_sec1_bytes(false);
        let payload = encode_sm2_public_key_payload(public.distid(), &sec1).expect("SM2 payload");
        let general =
            PublicKey::from_bytes(Algorithm::Sm2, &payload).expect("construct public key wrapper");
        assert_eq!(
            prefixed,
            general
                .try_to_prefixed_string()
                .expect("generic checked SM2 prefixed formatting")
        );
    }
    #[test]
    fn sm2_signature_der_roundtrip_matches_annex() {
        let signature = Sm2Signature::from_hex(ANNEX_SIG_HEX).expect("Annex signature");
        let der = signature.as_der();
        assert_eq!(hex::encode_upper(&der), ANNEX_SIG_DER_HEX);
        let parsed = Sm2Signature::from_der(&hex::decode(ANNEX_SIG_DER_HEX).expect("DER hex"))
            .expect("parse DER");
        assert_eq!(signature, parsed);
    }
    #[test]
    fn sm2_signature_try_as_der_matches_compatibility_export() {
        let signature = Sm2Signature::from_hex(ANNEX_SIG_HEX).expect("Annex signature");
        let checked = signature
            .try_as_der()
            .expect("SM2 DER short-form lengths fit");
        assert_eq!(checked, signature.as_der());
        assert!(!checked.is_empty(), "SM2 DER export must not be empty");
        assert_eq!(
            checked.get(1).copied().map(usize::from),
            Some(checked.len() - 2)
        );
    }
    #[test]
    fn sm2_signature_der_handles_high_bit_components() {
        let mut rng = OsRng;
        for attempt in 0..1024usize {
            let private =
                Sm2PrivateKey::try_random("interop-highbit", &mut rng).expect("valid distid");
            let message = format!("attempt-{attempt}").into_bytes();
            let signature = private.sign(&message);
            if signature.r[0] & 0x80 != 0 || signature.s[0] & 0x80 != 0 {
                let der = signature.as_der();
                let parsed = Sm2Signature::from_der(&der).expect("parse DER signature");
                assert_eq!(signature, parsed);
                return;
            }
        }
        panic!("failed to produce SM2 signature with high-bit component after 1024 attempts");
    }
    #[test]
    fn sm2_signature_der_rejects_non_canonical_leading_zero() {
        let der = hex::decode(ANNEX_SIG_DER_HEX).expect("DER hex");
        let r_start = 4;
        let r_end = r_start + 32;
        let s_start = r_end + 2;
        let s_end = s_start + 32;
        let r = &der[r_start..r_end];
        let s = &der[s_start..s_end];
        let seq_len = der[1].checked_add(1).expect("sequence length fits");
        let mut non_canonical = Vec::with_capacity(der.len() + 1);
        non_canonical.push(0x30);
        non_canonical.push(seq_len);
        non_canonical.push(0x02);
        non_canonical.push(0x21);
        non_canonical.push(0x00);
        non_canonical.extend_from_slice(r);
        non_canonical.push(0x02);
        non_canonical.push(0x20);
        non_canonical.extend_from_slice(s);
        assert!(Sm2Signature::from_der(&non_canonical).is_err());
    }
    #[test]
    fn sm2_signature_der_rejects_negative_integer_encoding() {
        let mut r = [0u8; 32];
        r[0] = 0x80;
        let mut s = [0u8; 32];
        s[31] = 0x01;
        let mut der = Vec::with_capacity(70);
        der.push(0x30);
        der.push(0x44);
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&r);
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&s);
        assert!(Sm2Signature::from_der(&der).is_err());
    }
    #[test]
    fn sm2_signature_der_rejects_negative_single_byte_integer() {
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        assert!(Sm2Signature::from_der(&der).is_err());
    }
}

#[cfg(test)]
#[path = "sm2_verification_tests.rs"]
mod sm2_verification_tests;

#[cfg(test)]
#[path = "sm2_payload_tests.rs"]
mod sm2_payload_tests;

#[cfg(test)]
mod sm3_digest_raw_wire_tests {
    use super::*;

    #[test]
    fn sm3_digest_keeps_sole_raw_wire_and_zero_storage_charge() {
        #[repr(align(16))]
        struct Aligned([u8; 512]);
        let value = Sm3Digest::hash(b"explicit raw Norito layout");
        let raw = *value.as_bytes();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut encoded = Vec::new();
            norito::core::serialize_to_buffer(&value, &mut encoded).unwrap();
            assert_eq!(encoded, raw);
            let mut aligned = Aligned([0; 512]);
            aligned.0[..encoded.len()].copy_from_slice(&encoded);
            let bytes = &aligned.0[..encoded.len()];
            let zero = norito::DecodeLimits::new(0, usize::MAX, 0, 0, 8);
            let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                let _context = norito::core::PayloadCtxGuard::enter(bytes);
                let decoded = norito::core::decode_field_canonical::<Sm3Digest>(bytes)?;
                assert_eq!(
                    norito::core::payload_ctx(),
                    Some((bytes.as_ptr() as usize, bytes.len()))
                );
                Ok::<_, norito::Error>(decoded)
            });
            assert_eq!(decoded.unwrap(), (value, bytes.len()));
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
            let mut alternate = Vec::new();
            norito::core::serialize_to_buffer(&raw, &mut alternate).unwrap();
            let mut extra = raw.to_vec();
            extra.push(0);
            for invalid in [&raw[..raw.len() - 1], &extra[..], &alternate[..]] {
                aligned.0[..invalid.len()].copy_from_slice(invalid);
                let bytes = &aligned.0[..invalid.len()];
                let (decoded, usage) = norito::core::with_decode_limits_measured(zero, || {
                    norito::core::decode_field_canonical::<Sm3Digest>(bytes)
                });
                assert!(matches!(decoded, Err(norito::Error::LengthMismatch)));
                assert_eq!(usage.total_allocated_bytes(), 0);
                assert_eq!(usage.total_elements(), 0);
            }
        }
    }
}
