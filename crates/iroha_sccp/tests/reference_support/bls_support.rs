//! BLS12-381 support of the reference generators: the §11.3 test keys, signing, and the
//! point and field forms the fixtures print.
//!
//! Nothing here is read from a fixture. The test keys come from the IETF `KeyGen`
//! (`specs/sccp.md` §11.3), consensus signatures from `iroha_crypto::bls::consensus`, and
//! every other value from `blstrs` and from `iroha_sccp::v1::committee`. Three things have no
//! API in those crates and are built here from their definitions:
//!
//! - `KeyGen` itself (HKDF over HMAC-SHA-256), because `iroha_crypto` derives keys from seeds
//!   by its own rule;
//! - a signature under another domain separation tag ([`sign_under_dst`]), because the
//!   consensus API signs under `DST_SIG` only, by design;
//! - a point of the curve outside the G2 subgroup ([`curve_point_outside_g2`]), because every
//!   hash-to-curve API clears the cofactor.

use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::{Curve as _, Group as _, ff::Field as _, prime::PrimeCurveAffine as _};
use halo2curves::{
    bls12381::{Fq, Fq2},
    ff::PrimeField as _,
};
use iroha_crypto::{
    Algorithm, PrivateKey, PublicKey, Signature,
    bls::consensus::{aggregate, sign_preimage},
};
use iroha_sccp::v1::{
    committee::{
        BLS12_381_P, EIP2537_G1_LEN, EIP2537_G2_LEN, EVM_SIGNATURE_LEN, FP_LEN, KEY_LEN,
        SIGNATURE_LEN, key_to_eip2537, signature_to_eip2537, signature_to_evm192,
    },
    hashes::to_hex,
};
use norito::json::Value;
use sha2::{Digest as _, Sha256};

use super::{hx, obj};

/// Tag of the §11.3 test key material: `IKM_i = SHA-256(tag ‖ u8 i)`.
pub const TEST_IKM_TAG: &[u8] = b"sccp-finality-test-ikm";
/// Initial salt of the IETF `KeyGen` (draft-irtf-cfrg-bls-signature-05 §2.3).
const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
/// Output length `L` of `KeyGen` for BLS12-381: `ceil(1.5 · ceil(log2(r)) / 8)`.
const KEYGEN_OKM_LEN: usize = 48;
/// Block length of SHA-256, the HMAC key pad length.
const SHA256_BLOCK_LEN: usize = 64;

// ---------------------------------------------------------------------------------------------
// KeyGen
// ---------------------------------------------------------------------------------------------

/// HMAC-SHA-256 (RFC 2104).
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let mut block = [0_u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    for part in message {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// `HKDF-Expand(prk, info, 48)` with SHA-256 (RFC 5869): two blocks, cut to 48 bytes.
fn hkdf_expand_48(prk: &[u8; 32], info: &[u8]) -> [u8; KEYGEN_OKM_LEN] {
    let first = hmac_sha256(prk, &[info, &[1]]);
    let second = hmac_sha256(prk, &[&first, info, &[2]]);
    let mut out = [0_u8; KEYGEN_OKM_LEN];
    out[..32].copy_from_slice(&first);
    out[32..].copy_from_slice(&second[..KEYGEN_OKM_LEN - 32]);
    out
}

/// The IETF `KeyGen` with an empty `key_info`: the secret scalar of `ikm`.
///
/// ```text
/// salt = "BLS-SIG-KEYGEN-SALT-"
/// repeat: salt = SHA-256(salt)
///         PRK  = HKDF-Extract(salt, IKM ‖ 0x00)
///         OKM  = HKDF-Expand(PRK, I2OSP(48, 2), 48)
///         SK   = OS2IP(OKM) mod r
/// until SK ≠ 0
/// ```
///
/// # Panics
/// When `ikm` is shorter than 32 bytes, which `KeyGen` forbids.
pub fn keygen(ikm: &[u8]) -> Scalar {
    assert!(ikm.len() >= 32, "KeyGen needs at least 32 bytes of IKM");
    let mut salt = KEYGEN_SALT.to_vec();
    loop {
        salt = Sha256::digest(&salt).to_vec();
        let prk = hmac_sha256(&salt, &[ikm, &[0]]);
        let okm = hkdf_expand_48(&prk, &[0, 48]);
        // `OS2IP(OKM) mod r` by Horner's rule: the 384-bit value does not fit a scalar.
        let secret = okm.iter().fold(Scalar::ZERO, |acc, byte| {
            acc * Scalar::from(256_u64) + Scalar::from(u64::from(*byte))
        });
        if !bool::from(secret.is_zero()) {
            return secret;
        }
    }
}

/// One §11.3 test key: `sk_i = KeyGen(IKM = SHA-256("sccp-finality-test-ikm" ‖ u8 i))`.
#[derive(Debug)]
pub struct TestKey {
    /// The index `i`.
    pub index: u8,
    /// `IKM_i`.
    pub ikm: [u8; 32],
    /// `sk_i` as a big-endian scalar, the form the fixtures print.
    pub secret: [u8; 32],
    /// `pk_i = sk_i · g1`, compressed.
    pub public: [u8; KEY_LEN],
    scalar: Scalar,
    private: PrivateKey,
}

/// The test key of index `index`, derived once per process.
pub fn test_key(index: u8) -> &'static TestKey {
    static KEYS: OnceLock<Mutex<BTreeMap<u8, &'static TestKey>>> = OnceLock::new();
    let mut keys = KEYS
        .get_or_init(Mutex::default)
        .lock()
        .expect("no test panics while it holds the key cache");
    keys.entry(index)
        .or_insert_with(|| Box::leak(Box::new(derive_test_key(index))))
}

fn derive_test_key(index: u8) -> TestKey {
    let ikm: [u8; 32] = Sha256::new()
        .chain_update(TEST_IKM_TAG)
        .chain_update([index])
        .finalize()
        .into();
    let scalar = keygen(&ikm);
    let secret = scalar.to_bytes_be();
    // An Iroha BLS-normal private key is the little-endian scalar.
    let private = PrivateKey::from_bytes(Algorithm::BlsNormal, &scalar.to_bytes_le())
        .expect("a nonzero scalar below r is a BLS-normal private key");
    let derived = PublicKey::from_private_key(&private).expect("a BLS-normal public key");
    let (algorithm, payload) = derived.to_bytes();
    assert_eq!(algorithm, Algorithm::BlsNormal);
    let public = <[u8; KEY_LEN]>::try_from(payload).expect("a compressed G1 point");
    // `iroha_crypto` derives the public key by its own code path; it is `sk · g1`.
    assert_eq!(
        public,
        (G1Affine::generator() * scalar).to_affine().to_compressed(),
        "test key {index}: iroha_crypto and blstrs disagree on the public key"
    );
    TestKey {
        index,
        ikm,
        secret,
        public,
        scalar,
        private,
    }
}

// ---------------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------------

/// `hash_to_G2(message, dst)` of RFC 9380 (`expand_message_xmd` with SHA-256, SSWU, random
/// oracle), compressed.
pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> [u8; SIGNATURE_LEN] {
    G2Projective::hash_to_curve(message, dst, &[])
        .to_affine()
        .to_compressed()
}

/// The aggregate consensus signature of `signers` over the allowlisted preimage `preimage`:
/// one share per signer through `iroha_crypto::bls::consensus`, then their sum.
///
/// # Panics
/// When `preimage` is not a consensus signing context or there is no signer.
pub fn sign_consensus(signers: &[&TestKey], preimage: &[u8]) -> [u8; SIGNATURE_LEN] {
    let shares: Vec<[u8; SIGNATURE_LEN]> = signers
        .iter()
        .map(|key| {
            sign_preimage(&key.private, preimage).expect("an allowlisted consensus preimage")
        })
        .collect();
    aggregate(shares).expect("at least one share")
}

/// `(Σ sk_i) · hash_to_G2(message, dst)`: the aggregate signature of `signers` over `message`
/// under any domain separation tag, compressed. Under `DST_SIG` it equals
/// [`sign_consensus`] of the preimage whose SHA-256 is `message`.
pub fn sign_under_dst(signers: &[&TestKey], message: &[u8], dst: &[u8]) -> [u8; SIGNATURE_LEN] {
    let secret = signers
        .iter()
        .fold(Scalar::ZERO, |sum, key| sum + key.scalar);
    (G2Projective::hash_to_curve(message, dst, &[]) * secret)
        .to_affine()
        .to_compressed()
}

/// The sum of the signatures that the generic signing API of `iroha_crypto`
/// (`Signature::new`, the w3f transcript) makes for `signers` over `payload`.
///
/// It is a point of G2 that no destination accepts as a certificate signature: the w3f
/// transcript hashes under another domain (`specs/sccp.md` §3.8).
///
/// The transcript is pinned here, not only inherited from the API: the result must be
/// `(Σ sk_i) · hash_to_G2(W3F_SIGNING_PREFIX ‖ payload, W3F_SIGNING_DST)`, so a change of the
/// generic API's transcript fails the generator instead of silently changing what the
/// `w3f` row of `finality_rust_v1.json` holds.
///
/// # Panics
/// When there is no signer, or when the generic API no longer signs the pinned transcript.
pub fn sign_w3f(signers: &[&TestKey], payload: &[u8]) -> [u8; SIGNATURE_LEN] {
    let shares: Vec<[u8; SIGNATURE_LEN]> = signers
        .iter()
        .map(|key| {
            <[u8; SIGNATURE_LEN]>::try_from(Signature::new(&key.private, payload).payload())
                .expect("a BLS-normal signature is a compressed G2 point")
        })
        .collect();
    let sum = aggregate(shares).expect("at least one share");
    let transcript = [W3F_SIGNING_PREFIX, payload].concat();
    assert_eq!(
        sum,
        sign_under_dst(signers, &transcript, W3F_SIGNING_DST),
        "the generic signing API of iroha_crypto no longer signs the w3f transcript"
    );
    sum
}

/// The message prefix of the w3f transcript that `iroha_crypto::Signature::new` signs with a
/// BLS-normal key (`crates/iroha_crypto/src/signature/bls/uncached.rs`, `NORMAL_PREFIX`). The
/// constant is private to that crate, so it is restated here.
pub const W3F_SIGNING_PREFIX: &[u8] =
    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_for signing messages";
/// The hash-to-field tag of the same transcript (`HASH_TO_FIELD_DST`): one byte, `0x01`.
pub const W3F_SIGNING_DST: &[u8] = &[1];

// ---------------------------------------------------------------------------------------------
// Points of the curve outside G1
// ---------------------------------------------------------------------------------------------

/// The effective cofactor of G1 (RFC 9380 §8.8.1): `H_EFF_G1 · P` is in G1 for every point
/// `P` of the curve.
const H_EFF_G1: u64 = 0xd201_0000_0001_0001;

/// The curve point with the smallest `x ≥ 1` (and the smaller `y`) that lies outside the G1
/// subgroup, compressed.
///
/// # Panics
/// When no `x` below 256 gives such a point.
pub fn curve_point_outside_g1() -> [u8; KEY_LEN] {
    (1..=u8::MAX)
        .map(|low| {
            let mut key = [0_u8; KEY_LEN];
            key[0] = 0x80;
            key[KEY_LEN - 1] = low;
            key
        })
        .find(|key| {
            G1Affine::from_compressed_unchecked(key)
                .into_option()
                .is_some_and(|point| !bool::from(point.is_torsion_free()))
        })
        .expect("a small curve point outside G1")
}

/// A nonzero point `T` of the curve with `H_EFF_G1 · T = O`: adding it to a key leaves every
/// pairing value unchanged and takes the key out of G1.
///
/// `T = W − (H_EFF_G1⁻¹ mod r) · (H_EFF_G1 · W)` for `W =` [`curve_point_outside_g1`]: the
/// component of `W` outside the `r`-torsion.
pub fn g1_shift_outside_subgroup() -> G1Projective {
    // `scalar · point` by double-and-add, for a point in or out of the subgroup.
    let times = |point: G1Projective, scalar: u64| {
        (0..u64::BITS)
            .rev()
            .fold(G1Projective::identity(), |sum, bit| {
                let doubled = sum.double();
                if (scalar >> bit) & 1 == 1 {
                    doubled + point
                } else {
                    doubled
                }
            })
    };
    let w = G1Projective::from(
        G1Affine::from_compressed_unchecked(&curve_point_outside_g1())
            .into_option()
            .expect("a point of the curve"),
    );
    let in_subgroup = times(w, H_EFF_G1);
    assert!(bool::from(in_subgroup.to_affine().is_torsion_free()));
    let inverse = Option::<Scalar>::from(Scalar::from(H_EFF_G1).invert()).expect("nonzero");
    let shift = w - in_subgroup * inverse;
    assert!(!bool::from(shift.is_identity()));
    assert!(bool::from(shift.to_affine().is_on_curve()));
    assert!(!bool::from(shift.to_affine().is_torsion_free()));
    assert!(bool::from(times(shift, H_EFF_G1).is_identity()));
    shift
}

/// A compressed key as a point of the curve, with no subgroup check.
fn g1_point(key: &[u8; KEY_LEN]) -> G1Projective {
    G1Projective::from(
        G1Affine::from_compressed_unchecked(key)
            .into_option()
            .expect("a point of the curve"),
    )
}

/// `key + shift`, compressed.
pub fn g1_plus(key: &[u8; KEY_LEN], shift: &G1Projective) -> [u8; KEY_LEN] {
    (g1_point(key) + shift).to_affine().to_compressed()
}

/// `key − shift`, compressed.
pub fn g1_minus(key: &[u8; KEY_LEN], shift: &G1Projective) -> [u8; KEY_LEN] {
    (g1_point(key) - shift).to_affine().to_compressed()
}

/// `−(a + b)`, compressed: the key that cancels `a` and `b`.
pub fn g1_negated_sum(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    (-(g1_point(a) + g1_point(b))).to_affine().to_compressed()
}

// ---------------------------------------------------------------------------------------------
// Point and field forms
// ---------------------------------------------------------------------------------------------

/// The compressed generator of G1.
pub fn g1_generator() -> [u8; KEY_LEN] {
    G1Affine::generator().to_compressed()
}

/// `−g1`, compressed: the fixed G1 input of the EVM pairing check.
pub fn negated_g1_generator() -> [u8; KEY_LEN] {
    (-G1Affine::generator()).to_compressed()
}

/// The compressed generator of G2.
pub fn g2_generator() -> [u8; SIGNATURE_LEN] {
    G2Affine::generator().to_compressed()
}

/// The order `r` of G1 and G2, big-endian.
pub fn group_order() -> [u8; 32] {
    // `−1 mod r` is `r − 1`, and `r` is odd, so the increment does not carry.
    let mut order = (-Scalar::ONE).to_bytes_be();
    assert_eq!(order[31] & 1, 0);
    order[31] |= 1;
    order
}

/// The EIP-2537 form of a compressed G1 point.
///
/// # Panics
/// When `point` is not the canonical encoding of a point of the curve.
pub fn g1_eip2537(point: &[u8; KEY_LEN]) -> [u8; EIP2537_G1_LEN] {
    key_to_eip2537(point).expect("a canonical point of the curve")
}

/// The EVM calldata form `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` of a compressed G2 point.
///
/// # Panics
/// When `point` is not the canonical encoding of a point of the curve.
pub fn g2_evm192(point: &[u8; SIGNATURE_LEN]) -> [u8; EVM_SIGNATURE_LEN] {
    signature_to_evm192(point).expect("a canonical point of the curve")
}

/// The EIP-2537 form of a compressed G2 point.
///
/// # Panics
/// When `point` is not the canonical encoding of a point of the curve.
pub fn g2_eip2537(point: &[u8; SIGNATURE_LEN]) -> [u8; EIP2537_G2_LEN] {
    signature_to_eip2537(point).expect("a canonical point of the curve")
}

/// The fixture object of a G1 point: `{compressed, eip2537}`.
pub fn g1_json(point: &[u8; KEY_LEN]) -> Value {
    obj([
        ("compressed", hx(point)),
        ("eip2537", hx(&g1_eip2537(point))),
    ])
}

/// The fixture object of a G2 point: `{compressed, evm192, eip2537}`.
pub fn g2_json(point: &[u8; SIGNATURE_LEN]) -> Value {
    obj([
        ("compressed", hx(point)),
        ("evm192", hx(&g2_evm192(point))),
        ("eip2537", hx(&g2_eip2537(point))),
    ])
}

/// The 768-byte EIP-2537 `PAIRING_CHECK` input `apk ‖ Q ‖ (−g1) ‖ σ` (`specs/sccp.md` §5.2.4):
/// the check `e(apk, Q) · e(−g1, σ) = 1`.
pub fn pairing_input(
    apk: &[u8; KEY_LEN],
    hash_point: &[u8; SIGNATURE_LEN],
    sigma: &[u8; SIGNATURE_LEN],
) -> Vec<u8> {
    [
        &g1_eip2537(apk)[..],
        &g2_eip2537(hash_point),
        &g1_eip2537(&negated_g1_generator()),
        &g2_eip2537(sigma),
    ]
    .concat()
}

/// `a + b` of two 48-byte big-endian integers, without reduction: `y + p` and `limb + p` of
/// the encodings a destination must refuse.
///
/// # Panics
/// When the sum does not fit 48 bytes.
pub fn fp_add(a: &[u8; FP_LEN], b: &[u8; FP_LEN]) -> [u8; FP_LEN] {
    let mut out = [0_u8; FP_LEN];
    let mut carry = 0_u16;
    for index in (0..FP_LEN).rev() {
        let sum = u16::from(a[index]) + u16::from(b[index]) + carry;
        out[index] = sum.to_be_bytes()[1];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "the sum exceeds 48 bytes");
    out
}

/// `a − b` of two 48-byte big-endian integers.
///
/// # Panics
/// When `a < b`.
pub fn fp_sub(a: &[u8; FP_LEN], b: &[u8; FP_LEN]) -> [u8; FP_LEN] {
    let mut out = [0_u8; FP_LEN];
    let mut borrow = 0_i16;
    for index in (0..FP_LEN).rev() {
        let difference = i16::from(a[index]) - i16::from(b[index]) - borrow;
        borrow = i16::from(difference < 0);
        out[index] = difference.rem_euclid(256).to_be_bytes()[1];
    }
    assert_eq!(borrow, 0, "the difference is negative");
    out
}

/// `(a + small) mod p` for a field element `a < p`.
pub fn fp_add_small(a: &[u8; FP_LEN], small: u8) -> [u8; FP_LEN] {
    let mut addend = [0_u8; FP_LEN];
    addend[FP_LEN - 1] = small;
    let sum = fp_add(a, &addend);
    if sum < BLS12_381_P {
        sum
    } else {
        fp_sub(&sum, &BLS12_381_P)
    }
}

/// `0x` and the hexadecimal digits of a big-endian integer without leading zeros: Python's
/// `hex()`, the form the fixtures give field elements and scalars.
pub fn hex_integer(big_endian: &[u8]) -> Value {
    let digits = to_hex(big_endian);
    let digits = digits.trim_start_matches('0');
    Value::from(format!(
        "0x{}",
        if digits.is_empty() { "0" } else { digits }
    ))
}

// ---------------------------------------------------------------------------------------------
// A point of the curve outside G2
// ---------------------------------------------------------------------------------------------

// RFC 9380 §8.8.2: the curve E2' isogenous to E2 is `y² = x³ + A'x + B'` with `A' = 240·i`
// and `B' = 1012·(1 + i)`, and the SSWU constant is `Z = −(2 + i)`.
const ISO_A: (u64, u64) = (0, 240);
const ISO_B: (u64, u64) = (1012, 1012);

// RFC 9380 Appendix E.3: the 3-isogeny E2' → E2 as four polynomials in `x'`, coefficients
// from degree 0 up, each `(c0, c1)` of `c0 + c1·i` in decimal.
const ISO_X_NUM: [(&str, &str); 4] = [
    (
        "889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542",
        "889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542",
    ),
    (
        "0",
        "2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706522",
    ),
    (
        "2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706526",
        "1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853261",
    ),
    (
        "3557697382419259905260257622876359250272784728834673675850718343221361467102966990615722337003569479144794908942033",
        "0",
    ),
];
const ISO_X_DEN: [(&str, &str); 3] = [
    (
        "0",
        "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559715",
    ),
    (
        "12",
        "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559775",
    ),
    ("1", "0"),
];
const ISO_Y_NUM: [(&str, &str); 4] = [
    (
        "3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558",
        "3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558",
    ),
    (
        "0",
        "889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235518",
    ),
    (
        "2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706524",
        "1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853263",
    ),
    (
        "2816510427748580758331037284777117739799287910327449993381818688383577828123182200904113516794492504322962636245776",
        "0",
    ),
];
const ISO_Y_DEN: [(&str, &str); 4] = [
    (
        "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355",
        "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355",
    ),
    (
        "0",
        "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559571",
    ),
    (
        "18",
        "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559769",
    ),
    ("1", "0"),
];

fn fq2(c0: u64, c1: u64) -> Fq2 {
    Fq2::new(Fq::from(c0), Fq::from(c1))
}

/// The two coordinates of an `Fq2` element as big-endian integers, `(c0, c1)`.
fn fq2_coordinates(value: &Fq2) -> ([u8; FP_LEN], [u8; FP_LEN]) {
    // `Fq2::to_bytes` is `c0 ‖ c1`, each in the big-endian byte order of the BLS12-381 base
    // field of `halo2curves`.
    assert_eq!(Fq::ONE.to_bytes()[FP_LEN - 1], 1, "Fq prints big-endian");
    let bytes = value.to_bytes();
    let (c0, c1) = bytes.split_at(FP_LEN);
    (
        c0.try_into().expect("48 bytes"),
        c1.try_into().expect("48 bytes"),
    )
}

/// `sgn0` of RFC 9380 §4.1 for an element of a quadratic extension.
fn sgn0(value: &Fq2) -> bool {
    let (c0, c1) = fq2_coordinates(value);
    let sign_0 = c0[FP_LEN - 1] & 1 == 1;
    let zero_0 = c0 == [0; FP_LEN];
    let sign_1 = c1[FP_LEN - 1] & 1 == 1;
    sign_0 || (zero_0 && sign_1)
}

/// The simplified SWU map onto E2' (RFC 9380 §6.6.2, the straight-line form).
fn map_to_curve_sswu(u: Fq2) -> (Fq2, Fq2) {
    let iso_a = fq2(ISO_A.0, ISO_A.1);
    let iso_b = fq2(ISO_B.0, ISO_B.1);
    let sswu_z = -fq2(2, 1);
    let inverse = |value: Fq2| Option::<Fq2>::from(value.invert()).expect("a nonzero element");
    let curve = |x: Fq2| x.square() * x + iso_a * x + iso_b;
    let z_u2 = sswu_z * u.square();
    let tv1 = z_u2.square() + z_u2;
    let x1 = if bool::from(tv1.is_zero()) {
        iso_b * inverse(sswu_z * iso_a)
    } else {
        -iso_b * inverse(iso_a) * (Fq2::ONE + inverse(tv1))
    };
    // `g(x1)` or `g(x2)` is a square for every `u`.
    let (x, y) = Option::<Fq2>::from(curve(x1).sqrt()).map_or_else(
        || {
            let x2 = z_u2 * x1;
            let root = Option::<Fq2>::from(curve(x2).sqrt()).expect("g(x2) is a square");
            (x2, root)
        },
        |root| (x1, root),
    );
    (x, if sgn0(&u) == sgn0(&y) { y } else { -y })
}

/// A polynomial with the decimal coefficients `coefficients`, from degree 0 up, at `x`.
fn polynomial(coefficients: &[(&str, &str)], x: Fq2) -> Fq2 {
    let element = |decimal: &str| Fq::from_str_vartime(decimal).expect("a decimal field element");
    coefficients.iter().rev().fold(Fq2::ZERO, |acc, (c0, c1)| {
        acc * x + Fq2::new(element(c0), element(c1))
    })
}

/// The 3-isogeny E2' → E2 (RFC 9380 Appendix E.3).
fn iso_map_g2((x, y): (Fq2, Fq2)) -> (Fq2, Fq2) {
    let inverse = |value: Fq2| Option::<Fq2>::from(value.invert()).expect("no pole at this point");
    (
        polynomial(&ISO_X_NUM, x) * inverse(polynomial(&ISO_X_DEN, x)),
        y * polynomial(&ISO_Y_NUM, x) * inverse(polynomial(&ISO_Y_DEN, x)),
    )
}

/// A point of the curve E2 that is not in the G2 subgroup, compressed:
/// `iso_map(map_to_curve_simple_swu(5 + 7·i))` of RFC 9380, **without** clearing the cofactor.
///
/// A destination must refuse it as a signature (`BadSignature`): the EVM pairing precompile
/// and TON's aggregate-verify opcode both check the subgroup.
pub fn curve_point_outside_g2() -> [u8; SIGNATURE_LEN] {
    let (x, y) = iso_map_g2(map_to_curve_sswu(fq2(5, 7)));
    let (x0, x1) = fq2_coordinates(&x);
    let (y0, y1) = fq2_coordinates(&y);
    // The uncompressed Zcash form stores each coordinate as `c1 ‖ c0`.
    let mut uncompressed = [0_u8; EVM_SIGNATURE_LEN];
    for (target, source) in uncompressed.chunks_exact_mut(FP_LEN).zip([x1, x0, y1, y0]) {
        target.copy_from_slice(&source);
    }
    let point = G2Affine::from_uncompressed_unchecked(&uncompressed)
        .into_option()
        .expect("the isogeny maps onto the curve");
    assert!(bool::from(point.is_on_curve()));
    assert!(
        !bool::from(point.is_torsion_free()),
        "the point is in G2: the cofactor was cleared"
    );
    point.to_compressed()
}
