//! Committee geometry and root, the EVM point forms of keys and signatures, and the
//! destination committee state machine (`specs/sccp.md` §3.7, §3.8 and §5.1.2, revision 5).
//!
//! A committee is `n ∈ {4, 7, …, 31}` compressed BLS12-381 public keys in canonical order
//! (strictly ascending key bytes); signer bit `i` of a certificate is key `i`, and a quorum is
//! exactly `q = n − f` signers with `f = (n − 1) / 3`. Destinations know a committee by its
//! [`committee_root`].
//!
//! The module has three parts:
//!
//! - **Geometry and root**: [`is_valid_committee_size`], [`quorum`], [`is_canonical_order`],
//!   [`signer_indices`], [`committee_root`] and the key lists a destination takes
//!   ([`committee_keys`], [`successor_keys_match`]).
//! - **Point forms** (§3.7). TON and Taira carry compressed points. EVM takes the aggregate
//!   signature as four 48-byte limbs `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` ([`signature_to_evm192`],
//!   [`signature_from_evm192`]) and each signer's `y` from calldata ([`key_y`],
//!   [`signer_ys`]), and zero-extends every coordinate to the 64-byte field elements of
//!   EIP-2537 ([`eip2537_g1`], [`eip2537_g2`]).
//! - **The §5.1.2 state machine** as a pure function of `(state, X, stored checkpoint, now)`:
//!   [`CommitteeStateV1`] with the CUR classification, the violation predicates V1–V3, the
//!   checkpoint and rotation updates, and the rule that decides which stored checkpoint a
//!   `*FromCheckpoint` entry point may still use (§5.1.3). It is the reference for both
//!   contracts. No update aborts for arithmetic: X6 bounds what a rotation adds to, and the
//!   successor deadline saturates. The checkpoint store, certificate verification and the
//!   entry points around it belong to the destination model.

use blstrs::{G1Affine, G1Projective, G2Affine};
use group::{Curve as _, Group as _, prime::PrimeCurveAffine as _};
use iroha_crypto::bls::consensus::key_validate;
pub use iroha_data_model::{
    block::consensus::is_valid_committee_size,
    sumeragi_finality::certified_result::{COMMITTEE_TAG, committee_root},
};

use super::finality::{SccpFinalityHeaderV1, checkpoint_id};

/// Smallest committee: `f = 1`.
pub const MIN_COMMITTEE_SIZE: usize = 4;
/// Largest committee: `f = 10`. The `signers` field of `QC_FIXED` has 32 bits.
pub const MAX_COMMITTEE_SIZE: usize = 31;
/// Length of a compressed committee key (a G1 point).
pub const KEY_LEN: usize = 48;
/// Length of a compressed aggregate signature (a G2 point): the TON and Taira wire form.
pub const SIGNATURE_LEN: usize = 96;
/// Length of the EVM calldata form of an aggregate signature: four 48-byte limbs.
pub const EVM_SIGNATURE_LEN: usize = 192;
/// Length of one base-field element as a big-endian integer.
pub const FP_LEN: usize = 48;
/// Length of the EIP-2537 encoding of a G1 point: `x ‖ y`, 64 bytes each.
pub const EIP2537_G1_LEN: usize = 128;
/// Length of the EIP-2537 encoding of a G2 point: `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`, 64 bytes each.
pub const EIP2537_G2_LEN: usize = 256;

/// The BLS12-381 base-field modulus `p`, big-endian.
pub const BLS12_381_P: [u8; FP_LEN] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];
/// `HALF_P = (p − 1) / 2`, big-endian: a compressed point's sign flag is set iff `y > HALF_P`.
pub const BLS12_381_HALF_P: [u8; FP_LEN] = [
    0x0d, 0x00, 0x88, 0xf5, 0x1c, 0xbf, 0xf3, 0x4d, 0x25, 0x8d, 0xd3, 0xdb, 0x21, 0xa5, 0xd6, 0x6b,
    0xb2, 0x3b, 0xa5, 0xc2, 0x79, 0xc2, 0x89, 0x5f, 0xb3, 0x98, 0x69, 0x50, 0x7b, 0x58, 0x7b, 0x12,
    0x0f, 0x55, 0xff, 0xff, 0x58, 0xa9, 0xff, 0xff, 0xdc, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xd5, 0x55,
];

/// Compression flag of a Zcash point encoding (bit 7 of byte 0).
const FLAG_COMPRESSED: u8 = 0x80;
/// Infinity flag of a Zcash point encoding (bit 6 of byte 0).
const FLAG_INFINITY: u8 = 0x40;
/// Sign flag of a compressed point (bit 5 of byte 0).
const FLAG_SIGN: u8 = 0x20;
/// The compressed identity of G1, `0xc0` followed by 47 zero bytes. It is no committee key:
/// `KeyValidate` refuses it, and it is what the signer keys sum to when `apk = O`.
pub const IDENTITY_KEY: [u8; KEY_LEN] = {
    let mut bytes = [0; KEY_LEN];
    bytes[0] = FLAG_COMPRESSED | FLAG_INFINITY;
    bytes
};
/// The compressed identity of G2, `0xc0` followed by 95 zero bytes: the TON and Taira wire
/// form of `σ = O`. No destination accepts it as a signature (§5.1.3 step 6).
pub const IDENTITY_SIGNATURE: [u8; SIGNATURE_LEN] = {
    let mut bytes = [0; SIGNATURE_LEN];
    bytes[0] = FLAG_COMPRESSED | FLAG_INFINITY;
    bytes
};
/// The EVM calldata form of `σ = O`: 192 zero bytes. No destination accepts it either.
pub const IDENTITY_SIGNATURE_EVM: [u8; EVM_SIGNATURE_LEN] = [0; EVM_SIGNATURE_LEN];

const _: () = assert!(KEY_LEN == iroha_crypto::bls::consensus::PUBLIC_KEY_LEN);
const _: () = assert!(SIGNATURE_LEN == iroha_crypto::bls::consensus::SIGNATURE_LEN);
const _: () = assert!(
    is_valid_committee_size(MIN_COMMITTEE_SIZE)
        && is_valid_committee_size(MAX_COMMITTEE_SIZE)
        && !is_valid_committee_size(MIN_COMMITTEE_SIZE - 1)
        && !is_valid_committee_size(MAX_COMMITTEE_SIZE + 3)
);

// ---------------------------------------------------------------------------------------------
// Geometry and root (§3.7, §3.8 step 1)
// ---------------------------------------------------------------------------------------------

/// `q = n − f` with `f = (n − 1) / 3`: the exact signer count of a certificate.
///
/// Returns `None` unless `n ∈ {4, 7, …, 31}`.
#[must_use]
pub const fn quorum(n: usize) -> Option<usize> {
    if is_valid_committee_size(n) {
        Some(n - (n - 1) / 3)
    } else {
        None
    }
}

/// Whether `keys` are in canonical order: strictly ascending key bytes, hence no repeated key.
#[must_use]
pub fn is_canonical_order(keys: &[[u8; KEY_LEN]]) -> bool {
    keys.is_sorted_by(|left, right| left < right)
}

/// The canonical indices a `signers` field names for a committee of `n` keys, ascending.
///
/// Returns `None` when a bit at or above `n` is set (a spare bit).
#[must_use]
pub fn signer_indices(signers: u32, n: usize) -> Option<Vec<usize>> {
    if n < 32 && signers >> n != 0 {
        return None;
    }
    Some(
        (0..32_usize)
            .filter(|index| (signers >> index) & 1 == 1)
            .collect(),
    )
}

/// The keys of an EVM `committee` argument: `48n` bytes of compressed keys with
/// `n ∈ {4, 7, …, 31}` (`specs/sccp.md` §5.1.3 step 1).
///
/// Only the length is checked. The keys are authenticated by [`committee_root`] against the
/// destination's current root.
#[must_use]
pub fn committee_keys(committee: &[u8]) -> Option<Vec<[u8; KEY_LEN]>> {
    let (keys, rest) = committee.as_chunks::<KEY_LEN>();
    (rest.is_empty() && is_valid_committee_size(keys.len())).then(|| keys.to_vec())
}

/// Whether `next_keys` are the committee a rotation to `next_root` installs: a valid `n` of
/// strictly ascending keys whose [`committee_root`] is `next_root` (§5.1.2 update 3).
///
/// TON stores the current keys, so a rotation whose successor root differs from the current
/// one must supply them; a destination answers `BadCommittee` otherwise.
#[must_use]
pub fn successor_keys_match(next_keys: &[[u8; KEY_LEN]], next_root: &[u8; 32]) -> bool {
    is_valid_committee_size(next_keys.len())
        && is_canonical_order(next_keys)
        && committee_root(next_keys) == Some(*next_root)
}

/// The sum of the keys `signers` names as points of the curve, compressed, with no subgroup
/// check: what `G1ADD` computes on EVM (`specs/sccp.md` §5.1.3 step 10). An identity sum is
/// [`IDENTITY_KEY`].
///
/// Returns `None` when `signers` names no key or a key outside the committee, or when a named
/// key is not the canonical encoding of a finite point of the curve. A key outside the G1
/// subgroup is added like any other point: [`aggregate_public_key`] is the sum that applies
/// `KeyValidate`.
#[must_use]
pub fn signer_point_sum(keys: &[[u8; KEY_LEN]], signers: u32) -> Option<[u8; KEY_LEN]> {
    let indices = signer_indices(signers, keys.len())?;
    if indices.is_empty() {
        return None;
    }
    let mut sum = G1Projective::identity();
    for index in indices {
        sum += decompress_key(&keys[index])?;
    }
    Some(sum.to_affine().to_compressed())
}

/// `apk = Σ PK_i` over the keys `signers` names, compressed (`specs/sccp.md` §3.8 step 7).
///
/// Returns `None` when `signers` names no key or a key outside the committee, when a named
/// key fails `KeyValidate` (canonical, on the curve, in the subgroup, not the identity), or
/// when the sum is the identity.
#[must_use]
pub fn aggregate_public_key(keys: &[[u8; KEY_LEN]], signers: u32) -> Option<[u8; KEY_LEN]> {
    if signers == 0 || (keys.len() < u32::BITS as usize && signers >> keys.len() != 0) {
        return None;
    }
    let mut sum = G1Projective::identity();
    for (index, key) in keys.iter().take(u32::BITS as usize).enumerate() {
        if signers & (1_u32 << index) == 0 {
            continue;
        }
        if !key_validate(key) {
            return None;
        }
        sum += decompress_key(key)?;
    }
    (!bool::from(sum.is_identity())).then(|| sum.to_affine().to_compressed())
}

// ---------------------------------------------------------------------------------------------
// Point forms (§3.7)
// ---------------------------------------------------------------------------------------------

unit_error! {
    /// Why 192 bytes are not the EVM form of a G2 point.
    ///
    /// A destination answers `BadSignature` for both.
    pub enum PointFormError {
        /// A limb is not below the field modulus `p`.
        NotReduced => "a signature limb is not below the field modulus",
        /// The limbs are reduced but name no point of the curve.
        NotOnCurve => "the signature limbs are not a point of the curve",
    }
}

/// Whether the big-endian integer `value` is a canonical field element: `value < p`.
#[must_use]
pub fn fp_is_canonical(value: &[u8; FP_LEN]) -> bool {
    *value < BLS12_381_P
}

/// The EVM form of a compressed aggregate signature: the same point uncompressed, as
/// `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` (Zcash compression stores `c1` first).
///
/// The compressed identity maps to `0^192`. No subgroup check is made: the pairing check is
/// the authority. Returns `None` when `signature` is not the canonical encoding of a point of
/// the curve.
#[must_use]
pub fn signature_to_evm192(signature: &[u8; SIGNATURE_LEN]) -> Option<[u8; EVM_SIGNATURE_LEN]> {
    let point = G2Affine::from_compressed_unchecked(signature).into_option()?;
    if point.to_compressed() != *signature {
        return None;
    }
    if bool::from(point.is_identity()) {
        return Some(IDENTITY_SIGNATURE_EVM);
    }
    Some(swap_fp2_limbs(&point.to_uncompressed()))
}

/// The compressed form of an EVM aggregate signature: the inverse of [`signature_to_evm192`].
///
/// `0^192` maps to the compressed identity, which every verifier refuses. No subgroup check
/// is made.
///
/// # Errors
/// [`PointFormError::NotReduced`] when a limb is `≥ p`, then [`PointFormError::NotOnCurve`]
/// when the limbs are not zero and not a point of the curve.
pub fn signature_from_evm192(
    limbs: &[u8; EVM_SIGNATURE_LEN],
) -> Result<[u8; SIGNATURE_LEN], PointFormError> {
    let (elements, _) = limbs.as_chunks::<FP_LEN>();
    if !elements.iter().all(fp_is_canonical) {
        return Err(PointFormError::NotReduced);
    }
    if *limbs == IDENTITY_SIGNATURE_EVM {
        return Ok(IDENTITY_SIGNATURE);
    }
    // Reduced limbs have their top three bits clear, so the bytes read as an uncompressed,
    // finite Zcash encoding.
    G2Affine::from_uncompressed_unchecked(&swap_fp2_limbs(limbs))
        .into_option()
        .filter(|point| bool::from(point.is_on_curve()))
        .map(|point| point.to_compressed())
        .ok_or(PointFormError::NotOnCurve)
}

/// The `y` coordinate of a compressed key, big-endian.
///
/// Returns `None` when `key` is not the canonical encoding of a finite point of the curve.
/// No subgroup check is made.
#[must_use]
pub fn key_y(key: &[u8; KEY_LEN]) -> Option<[u8; FP_LEN]> {
    decompress_key(key)?.to_uncompressed().last_chunk().copied()
}

/// `signerYs`: the `y` of every key that `signers` names, in ascending index order, `48`
/// bytes each.
///
/// Returns `None` when `signers` names a key outside the committee or a key without a `y`
/// ([`key_y`]).
#[must_use]
pub fn signer_ys(keys: &[[u8; KEY_LEN]], signers: u32) -> Option<Vec<u8>> {
    let indices = signer_indices(signers, keys.len())?;
    let mut out = Vec::with_capacity(FP_LEN * indices.len());
    for index in indices {
        out.extend_from_slice(&key_y(&keys[index])?);
    }
    Some(out)
}

/// The `x` coordinate an EVM destination reads from a compressed key: the key bytes with the
/// three flag bits of byte 0 cleared.
#[must_use]
pub fn signer_key_x(key: &[u8; KEY_LEN]) -> [u8; FP_LEN] {
    let mut x = *key;
    x[0] &= !(FLAG_COMPRESSED | FLAG_INFINITY | FLAG_SIGN);
    x
}

/// Whether a signer key's flags agree with the `y` supplied for it (§5.1.3 step 6): byte 0
/// has the compression flag without the infinity flag, and the sign flag is set iff
/// `y > HALF_P`.
///
/// A destination answers `BadCommittee` otherwise.
#[must_use]
pub fn signer_key_flags_match(key: &[u8; KEY_LEN], y: &[u8; FP_LEN]) -> bool {
    key[0] & (FLAG_COMPRESSED | FLAG_INFINITY) == FLAG_COMPRESSED
        && (key[0] & FLAG_SIGN != 0) == (*y > BLS12_381_HALF_P)
}

/// Whether the coordinates an EVM destination reads for a signer are a precompile input that
/// names a finite point (§5.1.3 step 6): `x` = [`signer_key_x`] of `key` is below `p`, and
/// `(x, y)` is not `(0, 0)`, which EIP-2537 reads as the point at infinity.
///
/// The check precedes every precompile, on the cheap path too: `G1ADD` would take `(0, 0)`
/// for the identity and drop the signer from the aggregate, and on `x ≥ p` it fails and
/// burns the gas forwarded to it. The bound on `y` is its own check ([`fp_is_canonical`]).
/// A destination answers `BadCommittee` otherwise.
#[must_use]
pub fn signer_coordinates_name_a_finite_point(key: &[u8; KEY_LEN], y: &[u8; FP_LEN]) -> bool {
    let x = signer_key_x(key);
    fp_is_canonical(&x) && (x != [0; FP_LEN] || *y != [0; FP_LEN])
}

/// Whether `(x, y)` with `x` = [`signer_key_x`] of `key` is a finite point of the curve with
/// both coordinates below `p` (§5.1.3 step 10, where `G1ADD` rejects any other input).
///
/// A destination answers `BadCommittee` otherwise.
#[must_use]
pub fn signer_point_is_on_curve(key: &[u8; KEY_LEN], y: &[u8; FP_LEN]) -> bool {
    let x = signer_key_x(key);
    if !fp_is_canonical(&x) || !fp_is_canonical(y) {
        return false;
    }
    let mut point = [0_u8; 2 * FP_LEN];
    point[..FP_LEN].copy_from_slice(&x);
    point[FP_LEN..].copy_from_slice(y);
    G1Affine::from_uncompressed_unchecked(&point)
        .into_option()
        .is_some_and(|point| bool::from(point.is_on_curve()) && !bool::from(point.is_identity()))
}

/// The EIP-2537 G1 input of the coordinates `(x, y)`: each zero-extended to 64 bytes
/// (16 zero bytes, then the 48-byte value). The bytes are laid out as given.
#[must_use]
pub fn eip2537_g1(x: &[u8; FP_LEN], y: &[u8; FP_LEN]) -> [u8; EIP2537_G1_LEN] {
    let mut out = [0_u8; EIP2537_G1_LEN];
    out[16..64].copy_from_slice(x);
    out[80..].copy_from_slice(y);
    out
}

/// The EIP-2537 G2 input of an EVM signature: the four limbs `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`,
/// each zero-extended to 64 bytes. The bytes are laid out as given.
#[must_use]
pub fn eip2537_g2(limbs: &[u8; EVM_SIGNATURE_LEN]) -> [u8; EIP2537_G2_LEN] {
    let (elements, _) = limbs.as_chunks::<FP_LEN>();
    let mut out = [0_u8; EIP2537_G2_LEN];
    for (target, element) in out.chunks_exact_mut(64).zip(elements) {
        target[16..].copy_from_slice(element);
    }
    out
}

/// The EIP-2537 G1 encoding of a compressed G1 point; the identity is `0^128`.
///
/// Returns `None` when `key` is not the canonical encoding of a point of the curve. No
/// subgroup check is made.
#[must_use]
pub fn key_to_eip2537(key: &[u8; KEY_LEN]) -> Option<[u8; EIP2537_G1_LEN]> {
    let point = G1Affine::from_compressed_unchecked(key).into_option()?;
    if point.to_compressed() != *key {
        return None;
    }
    if bool::from(point.is_identity()) {
        return Some([0; EIP2537_G1_LEN]);
    }
    let uncompressed = point.to_uncompressed();
    let (x, y) = uncompressed.split_at(FP_LEN);
    Some(eip2537_g1(x.try_into().ok()?, y.try_into().ok()?))
}

/// The EIP-2537 G2 encoding of a compressed G2 point; the identity is `0^256`.
///
/// Returns `None` when [`signature_to_evm192`] does.
#[must_use]
pub fn signature_to_eip2537(signature: &[u8; SIGNATURE_LEN]) -> Option<[u8; EIP2537_G2_LEN]> {
    signature_to_evm192(signature).map(|limbs| eip2537_g2(&limbs))
}

// A canonical, finite point of the curve. The subgroup is the caller's concern.
fn decompress_key(key: &[u8; KEY_LEN]) -> Option<G1Affine> {
    let point = G1Affine::from_compressed_unchecked(key).into_option()?;
    (!bool::from(point.is_identity()) && point.to_compressed() == *key).then_some(point)
}

// Zcash stores an Fp2 coordinate as `c1 ‖ c0`, EIP-2537 and the EVM form as `c0 ‖ c1`. The
// swap of the two limbs of each coordinate converts either way.
fn swap_fp2_limbs(bytes: &[u8; EVM_SIGNATURE_LEN]) -> [u8; EVM_SIGNATURE_LEN] {
    let mut out = [0_u8; EVM_SIGNATURE_LEN];
    for (target, source) in out
        .chunks_exact_mut(2 * FP_LEN)
        .zip(bytes.chunks_exact(2 * FP_LEN))
    {
        target[..FP_LEN].copy_from_slice(&source[FP_LEN..]);
        target[FP_LEN..].copy_from_slice(&source[..FP_LEN]);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Committee state machine (§5.1.2)
// ---------------------------------------------------------------------------------------------

unit_error! {
    /// Why the committee state machine refuses a certified header. A refusal changes nothing.
    pub enum CommitteeError {
        /// Not `Live`: the latch is set.
        Equivocated => "the destination is latched",
        /// Not `Live`: the current generation's deadline `untilMs` has passed.
        Expired => "the current committee generation has expired",
        /// The header is not CUR: another generation or another committee root.
        NotCurrent => "the header is not of the current committee generation",
        /// An inline entry point met a violation V1–V3. Only `submitCheckpoints` latches.
        LatchRequired => "the header conflicts with the current generation and must latch",
        /// A stored checkpoint is neither of the current generation nor the handoff that
        /// installed it, so a `*FromCheckpoint` entry point may no longer use it.
        CheckpointRetired => "the stored header belongs to a retired committee generation",
    }
}

impl CommitteeError {
    /// The `specs/sccp.md` §5.2.2 error a destination reports.
    #[must_use]
    pub const fn destination_error(self) -> &'static str {
        match self {
            Self::Equivocated => "Equivocated",
            Self::Expired | Self::NotCurrent | Self::CheckpointRetired => "CommitteeNotAccepted",
            Self::LatchRequired => "LatchRequired",
        }
    }
}

/// Which violation predicate of §5.1.2 a certified header trips.
///
/// Each is a conflict signed by the current generation itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LatchReasonV1 {
    /// V1: the checkpoint stored at `X.height` is not `keccak256(X)`: two different `X`
    /// certified at one height.
    ConflictingCheckpoint,
    /// V2: `X.height < cur.start`: signed before its own tenure.
    BelowStart,
    /// V3: `ROTATION` with `X.height < cur.high`: a handoff below a height the same
    /// generation already certified.
    RotationBelowHigh,
}

impl LatchReasonV1 {
    /// The reason code of `SccpLatched`: 1, 2 or 3.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ConflictingCheckpoint => 1,
            Self::BelowStart => 2,
            Self::RotationBelowHigh => 3,
        }
    }
}

/// A violation, with the fields of `SccpLatched(reason, generation, height, a, b)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViolationV1 {
    /// The predicate that fired.
    pub reason: LatchReasonV1,
    /// `X.generation`.
    pub generation: u64,
    /// `X.height`.
    pub height: u64,
    /// V1: the stored checkpoint id. V2 and V3: `X.committee_root`.
    pub a: [u8; 32],
    /// `keccak256(X)` of the conflicting header.
    pub b: [u8; 32],
}

/// An installed successor, with the fields of
/// `SccpCommitteeRotated(generation, root, untilMs, start)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationV1 {
    /// The successor generation: the rotated generation plus one.
    pub generation: u64,
    /// The successor's committee root, `X.next_committee_root`.
    pub root: [u8; 32],
    /// The successor's deadline, [`rotation_deadline`]: `t_eff(X) + X.validity_ms`, saturating
    /// at `2^64 − 1`.
    pub until_ms: u64,
    /// The successor's first height, `X.height + 1`.
    pub start: u64,
}

/// What `submitCheckpoints` did with one certified header ([`CommitteeStateV1::apply_checkpoint`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointOutcomeV1 {
    /// A violation latched the destination. The state persists and processing stops.
    Latched(ViolationV1),
    /// The header was applied.
    Applied {
        /// Whether `cur.high` rose (a rotation raises it to `X.height` as well).
        high_raised: bool,
        /// The successor a rotation installed.
        rotation: Option<RotationV1>,
        /// Whether the destination is still `Live`. A rotation whose successor deadline has
        /// already passed leaves it frozen: the state persists and processing stops.
        live: bool,
    },
}

/// `t_eff(X) = min(X.timestamp_ms, now_ms)`: a future-dated header counts from the
/// destination's own clock.
#[must_use]
pub fn effective_time(header: &SccpFinalityHeaderV1, now_ms: u64) -> u64 {
    header.timestamp_ms().min(now_ms)
}

/// The deadline a rotation `X` gives its successor at `now_ms` (§5.1.2 update 3):
/// `min(t_eff(X) + X.validity_ms, 2^64 − 1)`.
///
/// The sum saturates, so applying a rotation never aborts for arithmetic. It exceeds `u64`
/// only when the destination clock is within `MAX_VALIDITY_MS` of `2^64` milliseconds.
#[must_use]
pub fn rotation_deadline(header: &SccpFinalityHeaderV1, now_ms: u64) -> u64 {
    effective_time(header, now_ms).saturating_add(header.validity_ms())
}

/// The committee state of a destination: `cur` of `specs/sccp.md` §5.1.1 and the latch.
///
/// Together with the checkpoints, which the caller stores, this is the whole state of the
/// §5.1.2 machine. There are no records of past generations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeStateV1 {
    /// `cur.root`: the committee root of the current generation.
    pub root: [u8; 32],
    /// `cur.generation`.
    pub generation: u64,
    /// `cur.start`: the first height of the current generation.
    pub start: u64,
    /// `cur.high`: the highest height the current generation certified here.
    pub high: u64,
    /// `cur.untilMs`: the trust deadline of the current generation; 0 once latched.
    pub until_ms: u64,
    /// The latch. It never clears.
    pub equivocated: bool,
}

impl CommitteeStateV1 {
    /// The initial state of a pin: `cur = {root, generation, start, high = start − 1,
    /// untilMs}`, not latched.
    ///
    /// Returns `None` for a pin no destination deploys: generation 0, a zero root or start
    /// height 0 (§5.2.1). The bound on `until_ms` depends on the deployment time and is not
    /// checked here: `super::destination::init_until_ms_is_valid` is that check.
    #[must_use]
    pub fn from_pin(
        generation: u64,
        committee_root: [u8; 32],
        start_height: u64,
        until_ms: u64,
    ) -> Option<Self> {
        if generation == 0 || committee_root == [0; 32] {
            return None;
        }
        Some(Self {
            root: committee_root,
            generation,
            start: start_height,
            high: start_height.checked_sub(1)?,
            until_ms,
            equivocated: false,
        })
    }

    /// `Live ⇔ ¬equivocated ∧ now_ms ≤ cur.untilMs`. A destination that is not `Live` is
    /// `Frozen`, permanently.
    #[must_use]
    pub const fn is_live(&self, now_ms: u64) -> bool {
        !self.equivocated && now_ms <= self.until_ms
    }

    /// The `Live` check with its two answers.
    ///
    /// # Errors
    /// [`CommitteeError::Equivocated`] when the latch is set, else
    /// [`CommitteeError::Expired`] when `now_ms > cur.untilMs`.
    pub const fn require_live(&self, now_ms: u64) -> Result<(), CommitteeError> {
        if self.equivocated {
            Err(CommitteeError::Equivocated)
        } else if now_ms > self.until_ms {
            Err(CommitteeError::Expired)
        } else {
            Ok(())
        }
    }

    /// CUR ⇔ `X.generation = cur.generation ∧ X.committee_root = cur.root`.
    ///
    /// Every other certificate is refused before any signature check: it never changes state
    /// and never latches, whether genuine or not.
    #[must_use]
    pub fn is_current(&self, header: &SccpFinalityHeaderV1) -> bool {
        header.generation() == self.generation && header.committee_root() == self.root
    }

    /// The first of V1, V2, V3 that a certified CUR header trips, if any.
    ///
    /// `stored` is the checkpoint id the destination holds at `X.height`, if it holds one.
    /// The predicates are meaningful only for a CUR header whose certificate verified.
    #[must_use]
    pub fn violation(
        &self,
        header: &SccpFinalityHeaderV1,
        stored: Option<&[u8; 32]>,
    ) -> Option<ViolationV1> {
        let id = checkpoint_id(header.as_bytes());
        let (reason, a) = match stored {
            Some(stored) if *stored != id => (LatchReasonV1::ConflictingCheckpoint, *stored),
            _ if header.height() < self.start => {
                (LatchReasonV1::BelowStart, header.committee_root())
            }
            _ if header.is_rotation() && header.height() < self.high => {
                (LatchReasonV1::RotationBelowHigh, header.committee_root())
            }
            _ => return None,
        };
        Some(ViolationV1 {
            reason,
            generation: header.generation(),
            height: header.height(),
            a,
            b: id,
        })
    }

    /// One certificate of `submitCheckpoints` (`sccp_checkpoint` on TON), after its
    /// verification: the violation check, then the updates of §5.1.2.
    ///
    /// A violation latches (`equivocated = true`, `cur.untilMs = 0`) and is an outcome, not an
    /// error: latching never reverts. Otherwise `cur.high` rises to `X.height`, and a
    /// rotation installs `{X.next_committee_root, generation + 1, X.height + 1, X.height,
    /// rotation_deadline(X)}`. Nothing else changes `cur.untilMs`: a non-rotation
    /// certificate, or the same certificate replayed, never extends trust.
    ///
    /// No update aborts for arithmetic. X6 bounds a rotation's height and generation by
    /// `2^64 − 2`, so the successor's start and generation are `u64` values, and its deadline
    /// saturates ([`rotation_deadline`]).
    ///
    /// The caller records the checkpoint `X.height → keccak256(X)` when it is absent.
    ///
    /// A TON caller also owns the successor keys, and the order matters: V1–V3 come first.
    /// It reads [`Self::successor_needs_keys`] before this call, because the answer compares
    /// with the root this call may replace, and checks the key list
    /// ([`successor_keys_match`]) after it, only when the outcome is a rotation. A missing or
    /// wrong list is `BadCommittee` and reverts the whole call, so the caller restores the
    /// state it saved before this function ran. A caller that refused the list before this
    /// call would answer `BadCommittee` where a violating certificate must latch.
    ///
    /// # Errors
    /// [`CommitteeError::Equivocated`] or [`CommitteeError::Expired`] when the destination is
    /// not `Live`, and [`CommitteeError::NotCurrent`] when the header is not CUR. An error
    /// leaves the state unchanged.
    pub fn apply_checkpoint(
        &mut self,
        header: &SccpFinalityHeaderV1,
        stored: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> Result<CheckpointOutcomeV1, CommitteeError> {
        self.require_live(now_ms)?;
        if !self.is_current(header) {
            return Err(CommitteeError::NotCurrent);
        }
        if let Some(violation) = self.violation(header, stored) {
            self.equivocated = true;
            self.until_ms = 0;
            return Ok(CheckpointOutcomeV1::Latched(violation));
        }
        let rotation = header.is_rotation().then(|| self.successor(header, now_ms));
        let high_raised = header.height() > self.high;
        if high_raised {
            self.high = header.height();
        }
        if let Some(successor) = rotation {
            self.root = successor.root;
            self.generation = successor.generation;
            self.start = successor.start;
            // No V3 fired, so the handoff height is the highest height this generation
            // certified: `high` already equals it.
            self.high = header.height();
            self.until_ms = successor.until_ms;
        }
        Ok(CheckpointOutcomeV1::Applied {
            high_raised,
            rotation,
            live: self.is_live(now_ms),
        })
    }

    /// The certificate of an inline entry point (`finalizeFromTaira`, `applyControl`,
    /// `voidExpired` and the TON equivalents), after its verification: `cur.high` rises to
    /// `X.height`, and no successor is installed even when `X` is a rotation.
    ///
    /// Returns whether `cur.high` rose. The caller records the checkpoint when it is absent.
    ///
    /// # Errors
    /// In this order: [`CommitteeError::NotCurrent`]; [`CommitteeError::LatchRequired`] when
    /// a violation V1–V3 holds (the relayer resubmits through `submitCheckpoints`, which
    /// latches); [`CommitteeError::Equivocated`] or [`CommitteeError::Expired`] when the
    /// destination is not `Live`. An error leaves the state unchanged.
    pub fn apply_inline(
        &mut self,
        header: &SccpFinalityHeaderV1,
        stored: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> Result<bool, CommitteeError> {
        if !self.is_current(header) {
            return Err(CommitteeError::NotCurrent);
        }
        if self.violation(header, stored).is_some() {
            return Err(CommitteeError::LatchRequired);
        }
        self.require_live(now_ms)?;
        let high_raised = header.height() > self.high;
        if high_raised {
            self.high = header.height();
        }
        Ok(high_raised)
    }

    /// Whether applying the CUR header `X` installs a committee with other keys: `X` is a
    /// rotation and `X.next_committee_root ≠ cur.root` (§5.1.2 update 3).
    ///
    /// TON stores the current keys, so `sccp_checkpoint` needs `next_keys` exactly then, and
    /// they must satisfy [`successor_keys_match`] for `X.next_committee_root` (else
    /// `BadCommittee`). At a heartbeat the stored keys are kept and none are needed. EVM
    /// stores no keys. The answer reads `cur.root` before the rotation: ask before
    /// [`Self::apply_checkpoint`].
    #[must_use]
    pub fn successor_needs_keys(&self, header: &SccpFinalityHeaderV1) -> bool {
        header.is_rotation() && header.next_committee_root() != self.root
    }

    /// Whether a stored checkpoint header may still be used by a `*FromCheckpoint` entry point
    /// (`specs/sccp.md` §5.1.3, "Using a checkpoint"):
    ///
    /// - **U1.** `X` is of the current generation: [`Self::is_current`].
    /// - **U2.** `X` is the handoff that installed `cur`: `ROTATION` is set,
    ///   `X.generation + 1 = cur.generation`, `X.height + 1 = cur.start` and
    ///   `X.next_committee_root = cur.root`.
    ///
    /// Every other stored header belongs to a retired generation and gives no new
    /// authorization: its messages and controls are proven under the handoff or under a newer
    /// certificate of the current generation, with a history proof. U2 applies to checkpoint
    /// references only. It never makes a certificate CUR, so an old certificate still cannot
    /// rotate, latch or raise `high`.
    #[must_use]
    pub fn accepts_checkpoint(&self, header: &SccpFinalityHeaderV1) -> bool {
        // X6 bounds a rotation's generation and height by 2^64 − 2, so neither sum overflows;
        // `checked_add` keeps the comparison total over any header all the same.
        self.is_current(header)
            || (header.is_rotation()
                && header.generation().checked_add(1) == Some(self.generation)
                && header.height().checked_add(1) == Some(self.start)
                && header.next_committee_root() == self.root)
    }

    /// The checks of a `*FromCheckpoint` entry point that follow the checkpoint lookup
    /// (`UnknownCheckpoint`) and the header parse (`BadHeader`): `Live`, then
    /// [`Self::accepts_checkpoint`]. The state does not change.
    ///
    /// # Errors
    /// In this order: [`CommitteeError::Equivocated`] or [`CommitteeError::Expired`] when the
    /// destination is not `Live`; [`CommitteeError::CheckpointRetired`] when the header is
    /// neither U1 nor U2.
    pub fn require_checkpoint_use(
        &self,
        header: &SccpFinalityHeaderV1,
        now_ms: u64,
    ) -> Result<(), CommitteeError> {
        self.require_live(now_ms)?;
        if self.accepts_checkpoint(header) {
            Ok(())
        } else {
            Err(CommitteeError::CheckpointRetired)
        }
    }

    // The successor of a CUR rotation header (§5.1.2 update 3 and "Arithmetic"). X6 bounds
    // the header's generation, which is `cur.generation`, and its height by 2^64 − 2, so
    // neither `+ 1` saturates; the deadline may.
    fn successor(&self, header: &SccpFinalityHeaderV1, now_ms: u64) -> RotationV1 {
        RotationV1 {
            generation: self.generation.saturating_add(1),
            root: header.next_committee_root(),
            until_ms: rotation_deadline(header, now_ms),
            start: header.height().saturating_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use norito::json::Value;

    use super::{
        super::finality::{
            CertificateError, FLAG_ACTIVE, FLAG_ROTATION, FinalityHeaderError, MAX_VALIDITY_MS,
            QC_FIXED_LEN, QcFixedV1, SccpFinalityHeaderFieldsV1, X_LEN, check_signers,
            vectors::{
                bytes, field, finality, hex, key, keys, number, reference, rows, text, word,
            },
            verify_certificate,
        },
        *,
    };

    const T0: u64 = 1_800_000_000_000;
    const VALIDITY: u64 = 1_209_600_000;
    const ROOT: [u8; 32] = [0xa1; 32];
    const NEXT_ROOT: [u8; 32] = [0xb2; 32];

    /// A destination pinned at generation 5, height 1000, valid until `T0 + VALIDITY`.
    fn pinned() -> CommitteeStateV1 {
        CommitteeStateV1::from_pin(5, ROOT, 1000, T0 + VALIDITY).unwrap()
    }

    /// An active non-rotation header of the pinned generation.
    fn header_fields(height: u64) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: [0x11; 32],
            height,
            timestamp_ms: T0.saturating_add(height),
            flags: FLAG_ACTIVE,
            message_count: 1,
            sccp_root: [0x22; 32],
            history_size: 1,
            history_root: [0x33; 32],
            generation: 5,
            committee_root: ROOT,
            validity_ms: 0,
            next_committee_root: [0; 32],
        }
    }

    fn header(height: u64) -> SccpFinalityHeaderV1 {
        SccpFinalityHeaderV1::from_fields(&header_fields(height)).unwrap()
    }

    fn rotation_fields(height: u64, next: [u8; 32]) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            flags: FLAG_ACTIVE | FLAG_ROTATION,
            validity_ms: VALIDITY,
            next_committee_root: next,
            ..header_fields(height)
        }
    }

    fn rotation(height: u64, next: [u8; 32]) -> SccpFinalityHeaderV1 {
        SccpFinalityHeaderV1::from_fields(&rotation_fields(height, next)).unwrap()
    }

    fn id(header: &SccpFinalityHeaderV1) -> [u8; 32] {
        checkpoint_id(header.as_bytes())
    }

    fn applied(high_raised: bool) -> CheckpointOutcomeV1 {
        CheckpointOutcomeV1::Applied {
            high_raised,
            rotation: None,
            live: true,
        }
    }

    /// A field element of the reference as 48 big-endian bytes (the file drops leading zeros).
    fn field_element(value: &Value, name: &str) -> [u8; FP_LEN] {
        let digits = text(value, name).strip_prefix("0x").unwrap();
        bytes(&format!("0x{digits:0>96}")).try_into().unwrap()
    }

    fn signature(value: &Value, name: &str) -> [u8; SIGNATURE_LEN] {
        bytes(text(value, name)).try_into().unwrap()
    }

    fn evm_signature(value: &Value, name: &str) -> [u8; EVM_SIGNATURE_LEN] {
        bytes(text(value, name)).try_into().unwrap()
    }

    fn signers_of(row: &Value) -> u32 {
        u32::try_from(number(field(row, "qc_fixed_fields"), "signers")).unwrap()
    }

    #[test]
    fn quorum_is_n_minus_f_for_every_valid_size() {
        let mut valid = Vec::new();
        for n in 0..=40_usize {
            let expected = (4..=31).contains(&n) && (n - 1) % 3 == 0;
            assert_eq!(is_valid_committee_size(n), expected, "n = {n}");
            match quorum(n) {
                Some(q) => {
                    let f = (n - 1) / 3;
                    assert!(expected);
                    assert_eq!(n, 3 * f + 1);
                    assert_eq!(q, n - f);
                    assert_eq!(q, 2 * f + 1);
                    valid.push((n, q));
                }
                None => assert!(!expected, "n = {n}"),
            }
        }
        assert_eq!(
            valid,
            [
                (4, 3),
                (7, 5),
                (10, 7),
                (13, 9),
                (16, 11),
                (19, 13),
                (22, 15),
                (25, 17),
                (28, 19),
                (31, 21)
            ]
        );
        assert_eq!((MIN_COMMITTEE_SIZE, MAX_COMMITTEE_SIZE), (4, 31));
    }

    #[test]
    fn canonical_order_is_strictly_ascending_key_bytes() {
        let key = |byte: u8| [byte; KEY_LEN];
        assert!(is_canonical_order(&[]));
        assert!(is_canonical_order(&[key(9)]));
        assert!(is_canonical_order(&[key(1), key(2), key(3), key(4)]));
        // A repeated key and a descending pair are both refused.
        assert!(!is_canonical_order(&[key(1), key(2), key(2), key(4)]));
        assert!(!is_canonical_order(&[key(1), key(3), key(2), key(4)]));
        // The order is over the whole key, most significant byte first.
        let mut low = key(5);
        let mut high = key(5);
        low[KEY_LEN - 1] = 4;
        high[0] = 6;
        assert!(is_canonical_order(&[low, key(5), high]));
        assert!(!is_canonical_order(&[key(5), low, high]));
    }

    #[test]
    fn signer_indices_are_ascending_and_refuse_spare_bits() {
        assert_eq!(signer_indices(0, 4), Some(vec![]));
        assert_eq!(signer_indices(0b0111, 4), Some(vec![0, 1, 2]));
        assert_eq!(signer_indices(0b1110, 4), Some(vec![1, 2, 3]));
        assert_eq!(signer_indices(0b1_0011, 4), None);
        assert_eq!(signer_indices(0x4000_0201, 31), Some(vec![0, 9, 30]));
        assert_eq!(signer_indices(0x8000_0000, 31), None);
        // The field has 32 bits, so no committee size leaves a bit to spare above them.
        assert_eq!(signer_indices(0x8000_0001, 32), Some(vec![0, 31]));
        assert_eq!(signer_indices(u32::MAX, 40).map(|i| i.len()), Some(32));
        assert_eq!(signer_indices(1, 0), None);
    }

    #[test]
    fn committee_root_matches_spec_example_and_binds_count_and_order() {
        // §3.7: synthetic keys 0x01^48 … 0x04^48 (not points).
        let synthetic = [[1; KEY_LEN], [2; KEY_LEN], [3; KEY_LEN], [4; KEY_LEN]];
        assert_eq!(COMMITTEE_TAG, b"SCCP/COMMITTEE/V1");
        let root = committee_root(&synthetic).expect("four keys have a root");
        assert_eq!(
            hex(&root),
            "fe8902a93a6592a748b8528a9f49312e9cbc5d1abcccb1ff7431b0acba92b2b9"
        );
        let mut swapped = synthetic;
        swapped.swap(0, 1);
        assert!(committee_root(&swapped).is_some_and(|other| other != root));
        assert!(committee_root(&synthetic[..3]).is_some_and(|other| other != root));
        // The root is defined for 1 to 255 keys: no other list has one.
        assert_eq!(committee_root(&[]), None);
        assert!(committee_root(&synthetic[..1]).is_some());
        assert!(committee_root(&vec![[7; KEY_LEN]; 255]).is_some());
        assert_eq!(committee_root(&vec![[7; KEY_LEN]; 256]), None);

        let transitions = reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        );
        let control = reference("control_v1.json", "iroha.sccp.control.v1");
        let reference = finality();
        assert_eq!(
            text(field(&reference, "constants"), "committee_tag").as_bytes(),
            COMMITTEE_TAG
        );
        let example = field(
            field(&reference, "worked_examples"),
            "synthetic_committee_root",
        );
        assert_eq!(keys(example, "keys"), synthetic);
        assert_eq!(
            committee_root(&keys(example, "keys")),
            Some(word(example, "root"))
        );
        // Every committee of the three reference files: its size, quorum, order and root.
        let mut sizes = std::collections::BTreeSet::new();
        let mut checked = 0;
        for file in [&reference, &transitions, &control] {
            let committees = field(file, "committees")
                .as_object()
                .expect("committees by name");
            for (name, committee) in committees {
                let members = keys(committee, "keys");
                let n = usize::try_from(number(committee, "n")).unwrap();
                assert_eq!(members.len(), n, "{name}");
                assert_eq!(
                    quorum(n),
                    usize::try_from(number(committee, "q")).ok(),
                    "{name}"
                );
                assert!(is_canonical_order(&members), "{name}");
                assert_eq!(
                    committee_root(&members),
                    Some(word(committee, "root")),
                    "{name}"
                );
                assert!(
                    successor_keys_match(&members, &word(committee, "root")),
                    "{name}"
                );
                sizes.insert(n);
                checked += 1;
            }
        }
        // `n4`, `n7`, `n31` and `n4_other`; `K0`…`K16`; `K0`.
        assert!(checked >= 22, "{checked} committees");
        assert_eq!(sizes.into_iter().collect::<Vec<_>>(), [4, 7, 31]);
    }

    #[test]
    fn committee_keys_takes_48n_bytes_of_a_valid_n() {
        for n in 0..=33_usize {
            let calldata = vec![0x5a; KEY_LEN * n];
            let parsed = committee_keys(&calldata);
            assert_eq!(parsed.is_some(), is_valid_committee_size(n), "n = {n}");
            if let Some(parsed) = parsed {
                assert_eq!(parsed.len(), n);
                assert_eq!(parsed.as_flattened(), &calldata[..]);
            }
        }
        // A length that is not a multiple of 48 is no committee.
        assert_eq!(committee_keys(&[0; KEY_LEN * 4 - 1]), None);
        assert_eq!(committee_keys(&[0; KEY_LEN * 4 + 1]), None);
    }

    #[test]
    fn successor_keys_must_be_a_valid_ascending_committee_of_the_root() {
        let reference = finality();
        let committees = field(&reference, "committees");
        let members = keys(field(committees, "n4"), "keys");
        let root_of = |keys: &[[u8; KEY_LEN]]| committee_root(keys).expect("a root");
        let root = root_of(&members);
        assert!(successor_keys_match(&members, &root));
        // Another root.
        assert!(!successor_keys_match(&members, &[0x01; 32]));
        // The same keys out of order: the root of that order does not make them a committee.
        let mut reordered = members.clone();
        reordered.swap(1, 2);
        assert!(!successor_keys_match(&reordered, &root));
        assert!(!successor_keys_match(&reordered, &root_of(&reordered)));
        // A repeated key.
        let mut repeated = members.clone();
        repeated[1] = repeated[0];
        assert!(!successor_keys_match(&repeated, &root_of(&repeated)));
        // An invalid size, under its own root.
        let five = &keys(field(committees, "n7"), "keys")[..5];
        assert!(is_canonical_order(five));
        assert!(!successor_keys_match(five, &root_of(five)));
        // No keys: there is no root to match, whatever root a header names.
        assert_eq!(committee_root(&[]), None);
        assert!(!successor_keys_match(&[], &[0; 32]));
        assert!(!successor_keys_match(&[], &root));
    }

    #[test]
    fn field_constants_match_the_reference() {
        let reference = finality();
        let curve = field(field(&reference, "constants"), "bls12_381");
        assert_eq!(BLS12_381_P, field_element(curve, "p"));
        assert_eq!(BLS12_381_HALF_P, field_element(curve, "half_p"));
        // HALF_P = (p − 1) / 2: doubling it and adding one gives p.
        let mut carry = 1_u16;
        let mut doubled = [0_u8; FP_LEN];
        for (out, half) in doubled.iter_mut().zip(BLS12_381_HALF_P).rev() {
            let sum = u16::from(half) * 2 + carry;
            *out = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        assert_eq!((doubled, carry), (BLS12_381_P, 0));

        assert!(fp_is_canonical(&[0; FP_LEN]));
        assert!(fp_is_canonical(&BLS12_381_HALF_P));
        assert!(!fp_is_canonical(&BLS12_381_P));
        assert!(!fp_is_canonical(&[0xff; FP_LEN]));
        let mut below = BLS12_381_P;
        below[FP_LEN - 1] -= 1;
        assert!(fp_is_canonical(&below));
    }

    #[test]
    fn signature_evm192_roundtrip_and_limb_order() {
        let reference = finality();
        let generator = field(field(field(&reference, "constants"), "bls12_381"), "g2");
        let compressed = signature(generator, "compressed");
        let limbs = evm_signature(generator, "evm192");
        assert_eq!(signature_to_evm192(&compressed), Some(limbs));
        assert_eq!(signature_from_evm192(&limbs), Ok(compressed));
        // Compression stores `x.c1 ‖ x.c0` under three flag bits; the EVM form is
        // `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` with no flag.
        assert_eq!(limbs[..48], compressed[48..]);
        assert_eq!(limbs[49..96], compressed[1..48]);
        assert_eq!(limbs[48], compressed[0] & 0x1f);
        assert_eq!(
            signature_to_eip2537(&compressed).unwrap()[..],
            bytes(text(generator, "eip2537"))[..]
        );

        // The identity is `0^192` on EVM and the flagged zero point compressed.
        assert_eq!(
            signature_to_evm192(&IDENTITY_SIGNATURE),
            Some([0; EVM_SIGNATURE_LEN])
        );
        assert_eq!(
            signature_from_evm192(&[0; EVM_SIGNATURE_LEN]),
            Ok(IDENTITY_SIGNATURE)
        );
        assert_eq!(
            signature_to_eip2537(&IDENTITY_SIGNATURE),
            Some([0; EIP2537_G2_LEN])
        );
        // Non-canonical compressed encodings have no EVM form.
        let mut uncompressed_flag = compressed;
        uncompressed_flag[0] &= 0x7f;
        assert_eq!(signature_to_evm192(&uncompressed_flag), None);
        let mut dirty_identity = IDENTITY_SIGNATURE;
        dirty_identity[95] = 1;
        assert_eq!(signature_to_evm192(&dirty_identity), None);
        assert_eq!(signature_to_evm192(&[0xff; SIGNATURE_LEN]), None);

        // Every certificate of the reference carries both forms of one point, except the
        // rows that corrupt one of them.
        let mut seen = std::collections::BTreeSet::new();
        for list in ["certificates", "negative_certificates"] {
            for row in rows(&reference, list) {
                let label = text(row, "label");
                let evm = bytes(text(field(row, "evm"), "signature"));
                let ton = bytes(text(field(row, "ton"), "signature"));
                let (Ok(evm), Ok(ton)) = (
                    <[u8; EVM_SIGNATURE_LEN]>::try_from(evm),
                    <[u8; SIGNATURE_LEN]>::try_from(ton),
                ) else {
                    assert!(label.contains("signature_length"), "{label}");
                    continue;
                };
                match label {
                    "sigma_limb_x_c0_ge_p"
                    | "sigma_limb_x_c1_ge_p"
                    | "sigma_limb_y_c0_ge_p"
                    | "sigma_limb_y_c1_ge_p" => {
                        assert_eq!(signature_from_evm192(&evm), Err(PointFormError::NotReduced));
                    }
                    "sigma_c0_c1_swapped"
                    | "sigma_off_curve"
                    | "aggregate_key_identity_sigma_off_curve" => {
                        assert_eq!(signature_from_evm192(&evm), Err(PointFormError::NotOnCurve));
                    }
                    "sigma_ton_uncompressed_flag" => {
                        assert_eq!(signature_to_evm192(&ton), None);
                    }
                    _ => {
                        assert_eq!(signature_to_evm192(&ton), Some(evm), "{label}");
                        assert_eq!(signature_from_evm192(&evm), Ok(ton), "{label}");
                    }
                }
                seen.insert(label);
            }
        }
        // The point outside the subgroup and the identity convert like any other point.
        for label in [
            "sigma_not_in_subgroup",
            "sigma_zero",
            "sigma_limb_y_c1_ge_p",
            "sigma_c0_c1_swapped",
            "sigma_off_curve",
            "sigma_ton_uncompressed_flag",
            "n31_scattered_q",
        ] {
            assert!(seen.contains(label), "the reference lost row `{label}`");
        }
    }

    #[test]
    fn signer_ys_follow_ascending_index_order() {
        let reference = finality();
        let committees = field(&reference, "committees");
        // `y` of every test key.
        let mut y_of = std::collections::BTreeMap::new();
        for row in rows(&reference, "test_keys") {
            let public = key(row, "pk");
            let y: [u8; FP_LEN] = bytes(text(row, "pk_y")).try_into().unwrap();
            assert_eq!(key_y(&public), Some(y));
            assert!(signer_key_flags_match(&public, &y));
            assert!(signer_point_is_on_curve(&public, &y));
            assert_eq!(
                key_to_eip2537(&public).unwrap()[..],
                bytes(text(row, "pk_eip2537"))[..]
            );
            assert_eq!(
                key_to_eip2537(&public),
                Some(eip2537_g1(&signer_key_x(&public), &y))
            );
            y_of.insert(public, y);
        }
        assert_eq!(y_of.len(), 35);

        for row in rows(&reference, "certificates") {
            let label = text(row, "label");
            let members = keys(field(committees, text(row, "committee")), "keys");
            let signers = signers_of(row);
            let ys = signer_ys(&members, signers).unwrap();
            assert_eq!(ys, bytes(text(field(row, "evm"), "signerYs")), "{label}");
            // One `y` per signer, in ascending canonical index order.
            let indices = signer_indices(signers, members.len()).unwrap();
            assert_eq!(Some(indices.len()), quorum(members.len()));
            assert!(indices.is_sorted_by(|left, right| left < right));
            let expected: Vec<u8> = rows(row, "signer_indices")
                .iter()
                .map(|index| usize::try_from(index.as_u64().unwrap()).unwrap())
                .flat_map(|index| y_of[&members[index]])
                .collect();
            assert_eq!(ys, expected, "{label}");
            assert_eq!(
                indices,
                rows(row, "signer_indices")
                    .iter()
                    .map(|index| usize::try_from(index.as_u64().unwrap()).unwrap())
                    .collect::<Vec<_>>()
            );
        }

        let members = keys(field(committees, "n4"), "keys");
        assert_eq!(signer_ys(&members, 0), Some(vec![]));
        // A bit outside the committee names no key.
        assert_eq!(signer_ys(&members, 0b1_0011), None);
        // A key that is not a point has no `y`.
        let mut broken = members.clone();
        broken[2] = [0xff; KEY_LEN];
        assert_eq!(signer_ys(&broken, 0b0111), None);
        assert!(signer_ys(&broken, 0b1011).is_some());
        // Neither does the identity.
        let mut identity = [0_u8; KEY_LEN];
        identity[0] = 0xc0;
        assert_eq!(key_y(&identity), None);
        assert_eq!(key_to_eip2537(&identity), Some([0; EIP2537_G1_LEN]));
    }

    #[test]
    fn signer_y_checks_refuse_the_reference_negatives() {
        let reference = finality();
        let genuine = keys(field(field(&reference, "committees"), "n4"), "keys");
        let mut seen = 0;
        for row in rows(&reference, "negative_certificates") {
            let label = text(row, "label");
            if !matches!(
                label,
                "signer_y_wrong_sign"
                    | "signer_y_ge_p"
                    | "signer_y_off_curve"
                    | "key_flag_infinity_0xc0"
                    | "key_flag_uncompressed"
                    | "signer_x_ge_p"
                    | "signer_zero_coordinates"
            ) {
                continue;
            }
            let evm = field(row, "evm");
            let members = committee_keys(&bytes(text(evm, "committee")))
                .expect("a four-member malformed-signer fixture");
            let ys = bytes(text(evm, "signerYs"));
            let (ys, rest) = ys.as_chunks::<FP_LEN>();
            assert!(rest.is_empty(), "{label}");
            // A malformed key may change its canonical seat. Pair each witness with the
            // signer the certificate actually names, then locate the row's malformed key.
            let signers = signers_of(row);
            let indices = signer_indices(signers, members.len()).expect("valid signer seats");
            assert_eq!(indices.len(), ys.len(), "{label}");
            let suspects: Vec<_> = indices
                .iter()
                .map(|index| &members[*index])
                .zip(ys)
                .filter(|(key, _)| match label {
                    "signer_y_wrong_sign" => **key == genuine[0],
                    "signer_y_ge_p" => **key == genuine[1],
                    "signer_y_off_curve" => **key == genuine[2],
                    "key_flag_infinity_0xc0" => key[0] & 0x40 != 0,
                    "key_flag_uncompressed" => key[0] & 0x80 == 0,
                    "signer_x_ge_p" => signer_key_x(key)[0] == 0x1f,
                    "signer_zero_coordinates" => signer_key_x(key) == [0; FP_LEN],
                    _ => false,
                })
                .collect();
            assert_eq!(suspects.len(), 1, "{label}");
            let suspect = suspects[0];
            match label {
                "signer_y_wrong_sign" => {
                    assert!(fp_is_canonical(suspect.1));
                    assert!(!signer_key_flags_match(suspect.0, suspect.1));
                    // `p − y` is still on the curve: only the sign flag tells it apart.
                    assert!(signer_coordinates_name_a_finite_point(suspect.0, suspect.1));
                    assert!(signer_point_is_on_curve(suspect.0, suspect.1));
                    assert_ne!(key_y(suspect.0).as_ref(), Some(suspect.1));
                }
                "signer_y_ge_p" => {
                    assert!(!fp_is_canonical(suspect.1));
                    assert!(!signer_point_is_on_curve(suspect.0, suspect.1));
                }
                "signer_y_off_curve" => {
                    assert!(fp_is_canonical(suspect.1));
                    assert!(signer_key_flags_match(suspect.0, suspect.1));
                    // Finite coordinates that only the curve equation refuses (step 10).
                    assert!(signer_coordinates_name_a_finite_point(suspect.0, suspect.1));
                    assert!(!signer_point_is_on_curve(suspect.0, suspect.1));
                }
                "key_flag_infinity_0xc0" | "key_flag_uncompressed" => {
                    // The `y` is the genuine key's, the flag byte is not a compressed key's.
                    assert!(!signer_key_flags_match(suspect.0, suspect.1));
                    assert!(signer_point_is_on_curve(suspect.0, suspect.1));
                    assert_eq!(key_y(suspect.0), None);
                    assert_eq!(aggregate_public_key(&members, signers), None);
                }
                // The two rows below keep valid flags and a reduced `y`, so only the
                // coordinate check of step 6 refuses them; each is pinned under the root of
                // its own key bytes.
                "signer_x_ge_p" => {
                    assert!(fp_is_canonical(suspect.1));
                    assert!(signer_key_flags_match(suspect.0, suspect.1));
                    assert!(!fp_is_canonical(&signer_key_x(suspect.0)));
                    assert_eq!(signer_key_x(suspect.0)[0], 0x1f);
                    assert!(!signer_coordinates_name_a_finite_point(
                        suspect.0, suspect.1
                    ));
                    assert!(!signer_point_is_on_curve(suspect.0, suspect.1));
                }
                "signer_zero_coordinates" => {
                    assert_eq!(suspect.0[0], 0x80);
                    assert_eq!(signer_key_x(suspect.0), [0; FP_LEN]);
                    assert_eq!(*suspect.1, [0; FP_LEN]);
                    assert!(signer_key_flags_match(suspect.0, suspect.1));
                    assert!(!signer_coordinates_name_a_finite_point(
                        suspect.0, suspect.1
                    ));
                    assert!(!signer_point_is_on_curve(suspect.0, suspect.1));
                }
                _ => continue,
            }
            if matches!(label, "signer_x_ge_p" | "signer_zero_coordinates") {
                let pin = field(row, "pin");
                assert_eq!(keys(pin, "keys"), members, "{label}");
                assert_eq!(
                    committee_root(&members),
                    Some(word(pin, "committee_root")),
                    "{label}"
                );
                let expected = field(row, "expected");
                assert_eq!(field(expected, "evm").as_str(), Some("BadCommittee"));
                assert_eq!(field(expected, "ton").as_str(), Some("BadSignature"));
            }
            seen += 1;
        }
        assert_eq!(seen, 7);
    }

    #[test]
    fn signer_coordinates_must_be_reduced_and_not_the_zero_pair() {
        let reference = finality();
        let members = keys(field(field(&reference, "committees"), "n4"), "keys");
        let genuine = members[0];
        let y = key_y(&genuine).unwrap();
        assert!(signer_coordinates_name_a_finite_point(&genuine, &y));

        // x ≥ p: the three flag bits leave 381 coordinate bits, and p is below 2^381.
        let mut x_is_p = BLS12_381_P;
        x_is_p[0] |= FLAG_COMPRESSED;
        assert_eq!(signer_key_x(&x_is_p), BLS12_381_P);
        assert!(!signer_coordinates_name_a_finite_point(&x_is_p, &y));
        let mut below_p = BLS12_381_P;
        below_p[FP_LEN - 1] -= 1;
        below_p[0] |= FLAG_COMPRESSED;
        assert!(signer_coordinates_name_a_finite_point(&below_p, &y));
        let mut all_ones = [0xff_u8; KEY_LEN];
        all_ones[0] = FLAG_COMPRESSED | 0x1f;
        assert!(!signer_coordinates_name_a_finite_point(&all_ones, &y));
        // The flag bits are no part of `x`: a key with every flag set and `x = 0`.
        let mut flags_only = [0_u8; KEY_LEN];
        flags_only[0] = FLAG_COMPRESSED | FLAG_INFINITY | FLAG_SIGN;
        assert_eq!(signer_key_x(&flags_only), [0; FP_LEN]);

        // (0, 0) is the EIP-2537 point at infinity; every other pair with a zero is finite
        // as an input, whatever the curve says about it.
        let mut zero_x = [0_u8; KEY_LEN];
        zero_x[0] = FLAG_COMPRESSED;
        let zero = [0_u8; FP_LEN];
        let mut one = zero;
        one[FP_LEN - 1] = 1;
        assert!(!signer_coordinates_name_a_finite_point(&zero_x, &zero));
        assert!(!signer_coordinates_name_a_finite_point(&flags_only, &zero));
        assert!(signer_coordinates_name_a_finite_point(&zero_x, &one));
        assert!(signer_coordinates_name_a_finite_point(&genuine, &zero));
        // Neither is a point of the curve, which step 10 would answer.
        assert!(!signer_point_is_on_curve(&zero_x, &one));
        assert!(!signer_point_is_on_curve(&genuine, &zero));
        // The bound on `y` is not this check's.
        assert!(signer_coordinates_name_a_finite_point(
            &genuine,
            &BLS12_381_P
        ));
        assert!(!fp_is_canonical(&BLS12_381_P));
    }

    #[test]
    fn eip2537_encodings_zero_extend_every_coordinate() {
        let byte = |index: usize| u8::try_from(index).unwrap();
        let x: [u8; FP_LEN] = core::array::from_fn(|index| 0x10 + byte(index));
        let y: [u8; FP_LEN] = core::array::from_fn(|index| 0x80 + byte(index));
        let g1 = eip2537_g1(&x, &y);
        assert_eq!(g1.len(), 128);
        assert_eq!(g1[..16], [0; 16]);
        assert_eq!(g1[16..64], x);
        assert_eq!(g1[64..80], [0; 16]);
        assert_eq!(g1[80..], y);

        let limbs: [u8; EVM_SIGNATURE_LEN] = core::array::from_fn(byte);
        let g2 = eip2537_g2(&limbs);
        assert_eq!(g2.len(), 256);
        for limb in 0..4 {
            assert_eq!(g2[64 * limb..64 * limb + 16], [0; 16]);
            assert_eq!(
                g2[64 * limb + 16..64 * limb + 64],
                limbs[48 * limb..48 * limb + 48]
            );
        }

        // A compressed key keeps its flags in byte 0; the EVM `x` clears them.
        let mut flagged = [0xff_u8; KEY_LEN];
        assert_eq!(signer_key_x(&flagged)[0], 0x1f);
        assert_eq!(signer_key_x(&flagged)[1..], [0xff; KEY_LEN - 1]);
        flagged[0] = 0x80;
        assert_eq!(signer_key_x(&flagged)[0], 0);

        let reference = finality();
        let curve = field(field(&reference, "constants"), "bls12_381");
        for name in ["g1", "neg_g1"] {
            let point = field(curve, name);
            assert_eq!(
                key_to_eip2537(&key(point, "compressed")).unwrap()[..],
                bytes(text(point, "eip2537"))[..],
                "{name}"
            );
        }
        // −g1 has the generator's `x` and the `y` the reference pins.
        let negated = key(field(curve, "neg_g1"), "compressed");
        assert_eq!(key_y(&negated), Some(field_element(curve, "neg_g1_y")));
        assert_eq!(
            signer_key_x(&negated),
            signer_key_x(&key(field(curve, "g1"), "compressed"))
        );
        assert_eq!(key_to_eip2537(&[0xff; KEY_LEN]), None);
    }

    /// Positive rows: `apk`, the hashed message point and `σ` in every form, and the
    /// 768-byte `PAIRING_CHECK` input `apk ‖ Q ‖ −g1 ‖ σ` they make up.
    #[test]
    fn aggregate_key_and_pairing_input_match_the_reference() {
        let reference = finality();
        let committees = field(&reference, "committees");
        let negated_generator = key(
            field(field(field(&reference, "constants"), "bls12_381"), "neg_g1"),
            "compressed",
        );
        for row in rows(&reference, "certificates") {
            let label = text(row, "label");
            let members = keys(field(committees, text(row, "committee")), "keys");
            let aggregate_key = field(row, "aggregate_public_key");
            let apk = aggregate_public_key(&members, signers_of(row)).unwrap();
            assert_eq!(apk, key(aggregate_key, "compressed"), "{label}");
            let apk_input = key_to_eip2537(&apk).unwrap();
            assert_eq!(apk_input[..], bytes(text(aggregate_key, "eip2537"))[..]);

            let sigma = field(row, "aggregate_signature");
            let compressed = signature(sigma, "compressed");
            assert_eq!(
                compressed[..],
                bytes(text(field(row, "ton"), "signature"))[..]
            );
            assert_eq!(
                signature_to_evm192(&compressed),
                Some(evm_signature(sigma, "evm192"))
            );
            let sigma_input = signature_to_eip2537(&compressed).unwrap();
            assert_eq!(sigma_input[..], bytes(text(sigma, "eip2537"))[..]);

            let hashed = field(row, "hash_to_g2_m");
            let hashed_input = signature_to_eip2537(&signature(hashed, "compressed")).unwrap();
            assert_eq!(hashed_input[..], bytes(text(hashed, "eip2537"))[..]);
            assert_eq!(
                signature_to_evm192(&signature(hashed, "compressed")),
                Some(evm_signature(hashed, "evm192"))
            );

            let pairing_input = [
                &apk_input[..],
                &hashed_input,
                &key_to_eip2537(&negated_generator).unwrap(),
                &sigma_input,
            ]
            .concat();
            assert_eq!(pairing_input.len(), 768);
            assert_eq!(pairing_input, bytes(text(row, "pairing_input")), "{label}");
        }
    }

    #[test]
    fn aggregate_public_key_checks_bitmap_width_without_signer_allocation() {
        let reference = finality();
        let members = keys(field(field(&reference, "committees"), "n4"), "keys");
        assert_eq!(aggregate_public_key(&[], 1), None);
        assert_eq!(aggregate_public_key(&members, 0), None);
        let full = [members[0]; 32];
        assert_eq!(aggregate_public_key(&full, 1_u32 << 31), Some(members[0]));
        assert_eq!(aggregate_public_key(&full[..31], 1_u32 << 31), None);
        let mut longer = [members[0]; 33];
        longer[32] = [0; KEY_LEN];
        assert_eq!(aggregate_public_key(&longer, 1_u32 << 31), Some(members[0]));
    }

    #[test]
    fn aggregate_public_key_requires_valid_signer_keys_and_a_nonzero_sum() {
        let reference = finality();
        let members = keys(field(field(&reference, "committees"), "n4"), "keys");
        assert!(aggregate_public_key(&members, 0b0111).is_some());
        assert_ne!(
            aggregate_public_key(&members, 0b0111),
            aggregate_public_key(&members, 0b1110)
        );
        // One key is its own aggregate.
        assert_eq!(aggregate_public_key(&members, 0b0100), Some(members[2]));
        // No signer, and a signer outside the committee.
        assert_eq!(aggregate_public_key(&members, 0), None);
        assert_eq!(aggregate_public_key(&members, 0b1_0001), None);
        // A key that fails KeyValidate is refused only when it signs.
        let mut identity = [0_u8; KEY_LEN];
        identity[0] = 0xc0;
        let mut with_identity = members.clone();
        with_identity[3] = identity;
        assert_eq!(aggregate_public_key(&with_identity, 0b1001), None);
        assert!(aggregate_public_key(&with_identity, 0b0111).is_some());
        // A key and its negation sum to the identity: flipping the sign flag negates.
        let mut negated = members[0];
        negated[0] ^= 0x20;
        assert!(key_validate(&negated));
        let cancelling = [members[0], negated, members[2], members[3]];
        assert_eq!(aggregate_public_key(&cancelling, 0b0011), None);
        assert_eq!(aggregate_public_key(&cancelling, 0b0111), Some(members[2]));
    }

    #[test]
    fn signer_point_sum_adds_points_without_a_subgroup_check() {
        let reference = finality();
        let members = keys(field(field(&reference, "committees"), "n4"), "keys");
        assert_eq!(IDENTITY_KEY[0], 0xc0);
        assert!(IDENTITY_KEY[1..].iter().all(|byte| *byte == 0));
        assert!(!key_validate(&IDENTITY_KEY));
        // Over valid keys it is the aggregate key.
        for signers in [0b0100, 0b0111, 0b1110, 0b1111] {
            assert_eq!(
                signer_point_sum(&members, signers),
                aggregate_public_key(&members, signers)
            );
        }
        // No signer, and a signer outside the committee.
        assert_eq!(signer_point_sum(&members, 0), None);
        assert_eq!(signer_point_sum(&members, 0b1_0001), None);
        // A key and its negation sum to the identity, which the aggregate key never is.
        let mut negated = members[0];
        negated[0] ^= 0x20;
        let cancelling = [members[0], negated, members[2], members[3]];
        assert_eq!(signer_point_sum(&cancelling, 0b0011), Some(IDENTITY_KEY));
        assert_eq!(signer_point_sum(&cancelling, 0b0111), Some(members[2]));
        // The identity key and a string that is no point have no sum, when they sign.
        let with_identity = [IDENTITY_KEY, members[1], members[2], members[3]];
        assert_eq!(signer_point_sum(&with_identity, 0b0011), None);
        assert!(signer_point_sum(&with_identity, 0b1110).is_some());
        let no_point = [[0x01; KEY_LEN], members[1], members[2], members[3]];
        assert_eq!(signer_point_sum(&no_point, 0b0011), None);
        // A point of the curve outside G1 is added like any other: the first small `x` that
        // gives one. `KeyValidate` refuses it, and the sum leaves the subgroup with it.
        let outside = (1..=u8::MAX)
            .map(|low| {
                let mut key = [0_u8; KEY_LEN];
                key[0] = 0x80;
                key[KEY_LEN - 1] = low;
                key
            })
            .find(|key| decompress_key(key).is_some() && !key_validate(key))
            .unwrap();
        let odd = [outside, members[1], members[2], members[3]];
        let sum = signer_point_sum(&odd, 0b0011).unwrap();
        assert!(!key_validate(&sum));
        assert_eq!(aggregate_public_key(&odd, 0b0011), None);
        assert_eq!(signer_point_sum(&odd, 0b0001), Some(outside));
    }

    #[test]
    fn pin_gives_the_initial_state() {
        let state = pinned();
        assert_eq!(
            state,
            CommitteeStateV1 {
                root: ROOT,
                generation: 5,
                start: 1000,
                high: 999,
                until_ms: T0 + VALIDITY,
                equivocated: false,
            }
        );
        // `Live` includes the deadline itself.
        assert!(state.is_live(0));
        assert!(state.is_live(T0 + VALIDITY));
        assert!(!state.is_live(T0 + VALIDITY + 1));
        assert_eq!(state.require_live(T0 + VALIDITY), Ok(()));
        assert_eq!(
            state.require_live(T0 + VALIDITY + 1),
            Err(CommitteeError::Expired)
        );
        // The first height of a chain is 1, so `high` starts at 0.
        assert_eq!(
            CommitteeStateV1::from_pin(1, ROOT, 1, 7).map(|pin| pin.high),
            Some(0)
        );
        // Pins that no destination deploys.
        assert_eq!(CommitteeStateV1::from_pin(0, ROOT, 1000, T0), None);
        assert_eq!(CommitteeStateV1::from_pin(5, [0; 32], 1000, T0), None);
        assert_eq!(CommitteeStateV1::from_pin(5, ROOT, 0, T0), None);
    }

    #[test]
    fn classification_is_generation_and_root() {
        let state = pinned();
        assert!(state.is_current(&header(1000)));
        // Height and time do not classify.
        assert!(state.is_current(&header(1)));
        assert!(state.is_current(&rotation(2000, NEXT_ROOT)));
        for fields in [
            SccpFinalityHeaderFieldsV1 {
                generation: 4,
                ..header_fields(1000)
            },
            SccpFinalityHeaderFieldsV1 {
                generation: 6,
                ..header_fields(1000)
            },
            SccpFinalityHeaderFieldsV1 {
                committee_root: NEXT_ROOT,
                ..header_fields(1000)
            },
        ] {
            let other = SccpFinalityHeaderV1::from_fields(&fields).unwrap();
            assert!(!state.is_current(&other));
            // Refused without effect, by both entry points, and never a latch.
            let mut machine = state;
            assert_eq!(
                machine.apply_checkpoint(&other, None, T0),
                Err(CommitteeError::NotCurrent)
            );
            assert_eq!(
                machine.apply_inline(&other, Some(&[0x77; 32]), T0),
                Err(CommitteeError::NotCurrent)
            );
            assert_eq!(machine, state);
        }
    }

    #[test]
    fn checkpoint_raises_high_and_keeps_until_ms() {
        let mut state = pinned();
        assert_eq!(
            state.apply_checkpoint(&header(1005), None, T0),
            Ok(applied(true))
        );
        assert_eq!(state.high, 1005);
        // A height at or below `high` is accepted and changes nothing.
        assert_eq!(
            state.apply_checkpoint(&header(1002), None, T0),
            Ok(applied(false))
        );
        assert_eq!(
            state.apply_checkpoint(&header(1005), Some(&id(&header(1005))), T0),
            Ok(applied(false))
        );
        assert_eq!(
            state,
            CommitteeStateV1 {
                high: 1005,
                ..pinned()
            }
        );
    }

    #[test]
    fn non_rotation_never_extends_until_ms() {
        let mut state = pinned();
        let deadline = state.until_ms;
        // Future-dated, replayed and late certificates alike.
        let far = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            timestamp_ms: deadline + 10 * VALIDITY,
            ..header_fields(1500)
        })
        .unwrap();
        for now_ms in [T0, T0 + 1000, deadline - 1000, deadline] {
            for certified in [header(1001), far, header(1200)] {
                let outcome = state.apply_checkpoint(&certified, None, now_ms).unwrap();
                assert!(matches!(
                    outcome,
                    CheckpointOutcomeV1::Applied {
                        rotation: None,
                        live: true,
                        ..
                    }
                ));
                assert_eq!(state.until_ms, deadline);
            }
        }
        assert_eq!(state.high, 1500);
        // Once the deadline has passed nothing is accepted, and nothing extends it.
        for certified in [header(1600), far, rotation(1700, NEXT_ROOT)] {
            let before = state;
            assert_eq!(
                state.apply_checkpoint(&certified, None, deadline + 1000),
                Err(CommitteeError::Expired)
            );
            assert_eq!(
                state.apply_inline(&certified, None, deadline + 1000),
                Err(CommitteeError::Expired)
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn rotation_deadline_uses_t_eff() {
        // A rotation certified in the past: the deadline counts from the header's time.
        let handoff = rotation(1100, NEXT_ROOT);
        let certified_at = handoff.timestamp_ms();
        let now_ms = certified_at + 5000;
        assert_eq!(effective_time(&handoff, now_ms), certified_at);
        let mut state = pinned();
        let successor = RotationV1 {
            generation: 6,
            root: NEXT_ROOT,
            until_ms: certified_at + VALIDITY,
            start: 1101,
        };
        assert_eq!(
            state.apply_checkpoint(&handoff, None, now_ms),
            Ok(CheckpointOutcomeV1::Applied {
                high_raised: true,
                rotation: Some(successor),
                live: true,
            })
        );
        assert_eq!(
            state,
            CommitteeStateV1 {
                root: NEXT_ROOT,
                generation: 6,
                start: 1101,
                high: 1100,
                until_ms: certified_at + VALIDITY,
                equivocated: false,
            }
        );
        // The same certificate is no longer CUR: no second rotation, no extension.
        assert_eq!(
            state.apply_checkpoint(&handoff, Some(&id(&handoff)), now_ms),
            Err(CommitteeError::NotCurrent)
        );

        // A future-dated rotation: at most `validity_ms` from the destination's own clock.
        let future = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            timestamp_ms: T0 + 10 * VALIDITY,
            ..rotation_fields(1100, NEXT_ROOT)
        })
        .unwrap();
        assert_eq!(effective_time(&future, T0), T0);
        let mut state = pinned();
        state.apply_checkpoint(&future, None, T0).unwrap();
        assert_eq!(state.until_ms, T0 + VALIDITY);

        // A lowered validity, and a heartbeat that keeps the root.
        let heartbeat = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            validity_ms: 1,
            ..rotation_fields(1000, ROOT)
        })
        .unwrap();
        let mut state = pinned();
        let outcome = state.apply_checkpoint(&heartbeat, None, T0 + 1_000_000);
        assert_eq!(
            outcome,
            Ok(CheckpointOutcomeV1::Applied {
                high_raised: true,
                rotation: Some(RotationV1 {
                    generation: 6,
                    root: ROOT,
                    until_ms: heartbeat.timestamp_ms() + 1,
                    start: 1001,
                }),
                // The successor's deadline has already passed: applied, then frozen.
                live: false,
            })
        );
        assert_eq!((state.generation, state.root), (6, ROOT));
        assert!(!state.equivocated);
        assert_eq!(
            state.require_live(T0 + 1_000_000),
            Err(CommitteeError::Expired)
        );

        // The largest validity is installed as it is.
        let longest = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            validity_ms: MAX_VALIDITY_MS,
            ..rotation_fields(1000, NEXT_ROOT)
        })
        .unwrap();
        let mut state = pinned();
        state.apply_checkpoint(&longest, None, T0).unwrap();
        assert_eq!(state.until_ms, T0 + MAX_VALIDITY_MS);
    }

    #[test]
    fn violations_v1_v2_v3_latch_with_reason_codes() {
        assert_eq!(LatchReasonV1::ConflictingCheckpoint.code(), 1);
        assert_eq!(LatchReasonV1::BelowStart.code(), 2);
        assert_eq!(LatchReasonV1::RotationBelowHigh.code(), 3);

        let mut at_1010 = pinned();
        at_1010.apply_checkpoint(&header(1010), None, T0).unwrap();
        let latched = |state: CommitteeStateV1| CommitteeStateV1 {
            until_ms: 0,
            equivocated: true,
            ..state
        };

        // V1: another `X` is stored at the height. `a` is the stored id, `b` the new one.
        let certified = header(1005);
        let other = [0x5c; 32];
        let v1 = ViolationV1 {
            reason: LatchReasonV1::ConflictingCheckpoint,
            generation: 5,
            height: 1005,
            a: other,
            b: id(&certified),
        };
        let mut state = at_1010;
        assert_eq!(state.violation(&certified, Some(&other)), Some(v1));
        assert_eq!(
            state.apply_checkpoint(&certified, Some(&other), T0),
            Ok(CheckpointOutcomeV1::Latched(v1))
        );
        assert_eq!(state, latched(at_1010));
        // Neighbour: the same `X` stored, or nothing stored.
        assert_eq!(at_1010.violation(&certified, Some(&id(&certified))), None);
        assert_eq!(at_1010.violation(&certified, None), None);

        // V2: a height before the generation's start. `a` is the committee root.
        let early = header(999);
        let v2 = ViolationV1 {
            reason: LatchReasonV1::BelowStart,
            generation: 5,
            height: 999,
            a: ROOT,
            b: id(&early),
        };
        let mut state = at_1010;
        assert_eq!(
            state.apply_checkpoint(&early, None, T0),
            Ok(CheckpointOutcomeV1::Latched(v2))
        );
        assert_eq!(state, latched(at_1010));
        // Neighbour: the start height itself.
        assert_eq!(at_1010.violation(&header(1000), None), None);

        // V3: a rotation below a height this generation already certified.
        let handoff = rotation(1009, NEXT_ROOT);
        let v3 = ViolationV1 {
            reason: LatchReasonV1::RotationBelowHigh,
            generation: 5,
            height: 1009,
            a: ROOT,
            b: id(&handoff),
        };
        let mut state = at_1010;
        assert_eq!(
            state.apply_checkpoint(&handoff, None, T0),
            Ok(CheckpointOutcomeV1::Latched(v3))
        );
        // The latch installs no successor.
        assert_eq!(state, latched(at_1010));
        // Neighbours: a rotation at `high`, and a non-rotation below it.
        assert_eq!(at_1010.violation(&rotation(1010, NEXT_ROOT), None), None);
        assert_eq!(at_1010.violation(&header(1009), None), None);

        // V1 is reported before V2, and V2 before V3.
        let early_handoff = rotation(998, NEXT_ROOT);
        assert_eq!(
            at_1010
                .violation(&early_handoff, Some(&other))
                .map(|violation| violation.reason.code()),
            Some(1)
        );
        assert_eq!(
            at_1010
                .violation(&early_handoff, None)
                .map(|violation| violation.reason.code()),
            Some(2)
        );

        // Once latched, the destination is frozen for good: nothing is applied or latched
        // again, whatever the clock says.
        let frozen = latched(at_1010);
        for now_ms in [0, T0] {
            let mut state = frozen;
            assert!(!state.is_live(now_ms));
            assert_eq!(
                state.apply_checkpoint(&header(1011), None, now_ms),
                Err(CommitteeError::Equivocated)
            );
            assert_eq!(
                state.apply_checkpoint(&early, None, now_ms),
                Err(CommitteeError::Equivocated)
            );
            assert_eq!(
                state.apply_inline(&header(1011), None, now_ms),
                Err(CommitteeError::Equivocated)
            );
            assert_eq!(state, frozen);
        }
    }

    #[test]
    fn inline_violation_reverts_latch_required() {
        let mut at_1010 = pinned();
        at_1010.apply_checkpoint(&header(1010), None, T0).unwrap();
        let conflicting = [0x5c; 32];
        let cases = [
            (header(1005), Some(&conflicting)),
            (header(999), None),
            (rotation(1009, NEXT_ROOT), None),
        ];
        for (certified, stored) in cases {
            let mut state = at_1010;
            assert!(state.violation(&certified, stored).is_some());
            assert_eq!(
                state.apply_inline(&certified, stored, T0),
                Err(CommitteeError::LatchRequired)
            );
            // Nothing latched and nothing changed: only `submitCheckpoints` latches.
            assert_eq!(state, at_1010);
            // A violation is reported before the `Live` check.
            assert_eq!(
                state.apply_inline(&certified, stored, T0 + 2 * VALIDITY),
                Err(CommitteeError::LatchRequired)
            );
        }

        // A clean inline certificate raises `high`.
        let mut state = at_1010;
        assert_eq!(state.apply_inline(&header(1020), None, T0), Ok(true));
        assert_eq!(state.apply_inline(&header(1015), None, T0), Ok(false));
        assert_eq!(
            state,
            CommitteeStateV1 {
                high: 1020,
                ..at_1010
            }
        );
        // An inline rotation raises `high` and installs no successor.
        let handoff = rotation(1030, NEXT_ROOT);
        assert_eq!(state.apply_inline(&handoff, None, T0), Ok(true));
        assert_eq!(
            state,
            CommitteeStateV1 {
                high: 1030,
                ..at_1010
            }
        );
        // `submitCheckpoints` installs it afterwards from the same header.
        let outcome = state.apply_checkpoint(&handoff, Some(&id(&handoff)), T0);
        assert!(matches!(
            outcome,
            Ok(CheckpointOutcomeV1::Applied {
                high_raised: false,
                rotation: Some(RotationV1 { generation: 6, .. }),
                live: true,
            })
        ));
    }

    #[test]
    fn rotation_never_aborts_for_arithmetic() {
        // The deadline saturates: only a clock within `validity_ms` of 2^64 ms reaches the end.
        let end_of_time = CommitteeStateV1::from_pin(5, ROOT, 1000, u64::MAX).unwrap();
        let late = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            timestamp_ms: u64::MAX,
            ..rotation_fields(1100, NEXT_ROOT)
        })
        .unwrap();
        for (now_ms, until_ms) in [
            (u64::MAX - VALIDITY - 1, u64::MAX - 1),
            // The sum that fits exactly, then the sums beyond `u64`.
            (u64::MAX - VALIDITY, u64::MAX),
            (u64::MAX - VALIDITY + 1, u64::MAX),
            (u64::MAX, u64::MAX),
        ] {
            assert_eq!(rotation_deadline(&late, now_ms), until_ms, "now {now_ms}");
            let mut state = end_of_time;
            assert_eq!(
                state.apply_checkpoint(&late, None, now_ms),
                Ok(CheckpointOutcomeV1::Applied {
                    high_raised: true,
                    rotation: Some(RotationV1 {
                        generation: 6,
                        root: NEXT_ROOT,
                        until_ms,
                        start: 1101,
                    }),
                    live: true,
                })
            );
            assert_eq!(state.until_ms, until_ms);
        }
        // The deadline counts from `t_eff`, and an ordinary sum is not changed.
        assert_eq!(
            rotation_deadline(&late, T0),
            effective_time(&late, T0) + VALIDITY
        );
        let early = rotation(1100, NEXT_ROOT);
        assert_eq!(
            rotation_deadline(&early, u64::MAX),
            early.timestamp_ms() + VALIDITY
        );

        // X6 keeps a rotation's height at or below 2^64 − 2, so `start = height + 1` fits.
        let highest =
            SccpFinalityHeaderV1::from_fields(&rotation_fields(u64::MAX - 1, NEXT_ROOT)).unwrap();
        let mut state = pinned();
        state.apply_checkpoint(&highest, None, T0).unwrap();
        assert_eq!((state.start, state.high), (u64::MAX, u64::MAX - 1));
        assert!(SccpFinalityHeaderV1::from_fields(&rotation_fields(u64::MAX, NEXT_ROOT)).is_err());

        // X6 keeps a rotation's generation at or below 2^64 − 2 as well: the generation before
        // the last rotates into the last one, which has no rotation header at all.
        let penultimate =
            CommitteeStateV1::from_pin(u64::MAX - 1, ROOT, 1000, T0 + VALIDITY).unwrap();
        let handoff = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            generation: u64::MAX - 1,
            ..rotation_fields(1100, NEXT_ROOT)
        })
        .unwrap();
        let mut state = penultimate;
        let outcome = state.apply_checkpoint(&handoff, None, T0).unwrap();
        assert!(matches!(
            outcome,
            CheckpointOutcomeV1::Applied {
                rotation: Some(RotationV1 {
                    generation: u64::MAX,
                    start: 1101,
                    ..
                }),
                live: true,
                ..
            }
        ));
        assert_eq!(state.generation, u64::MAX);
        let last_rotation = SccpFinalityHeaderFieldsV1 {
            generation: u64::MAX,
            ..rotation_fields(1200, ROOT)
        };
        assert_eq!(
            SccpFinalityHeaderV1::from_fields(&last_rotation),
            Err(FinalityHeaderError::X6)
        );
        // The last generation still certifies non-rotation headers.
        let plain = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            generation: u64::MAX,
            committee_root: NEXT_ROOT,
            ..header_fields(1200)
        })
        .unwrap();
        assert_eq!(state.apply_checkpoint(&plain, None, T0), Ok(applied(true)));
        assert_eq!((state.generation, state.high), (u64::MAX, 1200));
    }

    #[test]
    fn checkpoint_use_is_the_current_generation_or_its_installing_handoff() {
        let handoff = rotation(1100, NEXT_ROOT);
        let at_pin = pinned();
        // At the pin: the headers of generation 5 under the pinned root (U1).
        assert!(at_pin.accepts_checkpoint(&header(1010)));
        assert!(at_pin.accepts_checkpoint(&handoff));
        let other_generation = |generation, base: SccpFinalityHeaderFieldsV1| {
            SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 { generation, ..base })
                .unwrap()
        };
        assert!(!at_pin.accepts_checkpoint(&other_generation(4, header_fields(1010))));
        assert!(!at_pin.accepts_checkpoint(&other_generation(6, header_fields(1010))));
        // U2 as a predicate: the rotation of generation 4 at height 999 that names the pin.
        // No destination holds it, because it stores only headers it verified as CUR.
        let pin_handoff = other_generation(
            4,
            SccpFinalityHeaderFieldsV1 {
                committee_root: NEXT_ROOT,
                ..rotation_fields(999, ROOT)
            },
        );
        assert!(at_pin.accepts_checkpoint(&pin_handoff));

        // After the handoff: generation 6 from height 1101 under the successor root.
        let mut state = at_pin;
        state
            .apply_checkpoint(&header(1010), None, T0 + 2000)
            .unwrap();
        state.apply_checkpoint(&handoff, None, T0 + 2000).unwrap();
        assert_eq!(
            (state.generation, state.start, state.root),
            (6, 1101, NEXT_ROOT)
        );
        let own = other_generation(
            6,
            SccpFinalityHeaderFieldsV1 {
                committee_root: NEXT_ROOT,
                ..header_fields(1150)
            },
        );
        // U1: its own headers. U2: the handoff that installed it. Nothing else of generation 5.
        assert!(state.accepts_checkpoint(&own));
        assert!(state.accepts_checkpoint(&handoff));
        assert!(!state.is_current(&handoff));
        assert!(!state.accepts_checkpoint(&header(1010)));
        let not_the_handoff = [
            // A rotation of generation 5 at another height, or to another root.
            rotation_fields(1099, NEXT_ROOT),
            rotation_fields(1101, NEXT_ROOT),
            rotation_fields(1100, [0xc3; 32]),
            rotation_fields(1100, ROOT),
            // The same rotation claimed by another generation.
            SccpFinalityHeaderFieldsV1 {
                generation: 4,
                ..rotation_fields(1100, NEXT_ROOT)
            },
            SccpFinalityHeaderFieldsV1 {
                generation: 6,
                ..rotation_fields(1100, NEXT_ROOT)
            },
            // The handoff height without the rotation.
            header_fields(1100),
        ];
        for fields in not_the_handoff {
            let other = SccpFinalityHeaderV1::from_fields(&fields).unwrap();
            assert!(!state.accepts_checkpoint(&other), "{fields:?}");
            assert_eq!(
                state.require_checkpoint_use(&other, T0 + 2000),
                Err(CommitteeError::CheckpointRetired)
            );
        }

        // `Live` is checked before eligibility, with its two answers.
        assert_eq!(state.require_checkpoint_use(&handoff, T0 + 2000), Ok(()));
        assert_eq!(state.require_checkpoint_use(&own, state.until_ms), Ok(()));
        for certified in [handoff, header(1010)] {
            assert_eq!(
                state.require_checkpoint_use(&certified, state.until_ms + 1000),
                Err(CommitteeError::Expired)
            );
            let latched = CommitteeStateV1 {
                equivocated: true,
                until_ms: 0,
                ..state
            };
            assert_eq!(
                latched.require_checkpoint_use(&certified, T0 + 2000),
                Err(CommitteeError::Equivocated)
            );
        }
        // U2 is a checkpoint rule only: the handoff certificate itself is no longer CUR, so
        // it cannot rotate, raise `high` or latch again.
        let before = state;
        assert_eq!(
            state.apply_checkpoint(&handoff, Some(&id(&handoff)), T0 + 2000),
            Err(CommitteeError::NotCurrent)
        );
        assert_eq!(
            state.apply_inline(&handoff, Some(&id(&handoff)), T0 + 2000),
            Err(CommitteeError::NotCurrent)
        );
        assert_eq!(state, before);

        // The next rotation retires the handoff of generation 5 and makes its own usable.
        let next_handoff = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            generation: 6,
            committee_root: NEXT_ROOT,
            ..rotation_fields(1200, [0xc3; 32])
        })
        .unwrap();
        state
            .apply_checkpoint(&next_handoff, None, T0 + 3000)
            .unwrap();
        assert_eq!(state.generation, 7);
        assert!(state.accepts_checkpoint(&next_handoff));
        for retired in [handoff, own, header(1010)] {
            assert!(!state.accepts_checkpoint(&retired));
        }

        // A heartbeat keeps the root, and still retires the non-handoff headers of its
        // generation: the generation number tells them apart.
        let heartbeat = rotation(1100, ROOT);
        let mut state = pinned();
        state.apply_checkpoint(&heartbeat, None, T0 + 2000).unwrap();
        assert_eq!((state.generation, state.root), (6, ROOT));
        assert!(state.accepts_checkpoint(&heartbeat));
        assert!(!state.accepts_checkpoint(&header(1010)));
        assert!(state.accepts_checkpoint(&other_generation(6, header_fields(1150))));
    }

    #[test]
    fn ton_rotation_requires_next_keys_on_key_change() {
        let transitions = reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        );
        let reference = finality();
        let committees = field(&reference, "committees");
        let current = keys(field(committees, "n4"), "keys");
        let successor = keys(field(committees, "n4_other"), "keys");
        let root = committee_root(&current).expect("a root");
        let next_root = committee_root(&successor).expect("a root");
        let state = CommitteeStateV1::from_pin(5, root, 1000, T0 + VALIDITY).unwrap();
        let certified = |fields: SccpFinalityHeaderFieldsV1| {
            SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
                committee_root: root,
                ..fields
            })
            .unwrap()
        };
        let key_change = certified(rotation_fields(1100, next_root));
        let heartbeat = certified(rotation_fields(1100, root));
        let plain = certified(header_fields(1100));
        for header in [&key_change, &heartbeat, &plain] {
            assert!(state.is_current(header));
        }

        // A rotation to another root installs other keys: TON needs them, and only the
        // committee of that root will do.
        assert!(state.successor_needs_keys(&key_change));
        let named = key_change.next_committee_root();
        assert!(successor_keys_match(&successor, &named));
        assert!(!successor_keys_match(&current, &named));
        assert!(!successor_keys_match(&[], &named));
        assert!(!successor_keys_match(&successor[..3], &named));
        let mut reordered = successor.clone();
        reordered.swap(0, 1);
        assert!(!successor_keys_match(&reordered, &named));
        // A heartbeat keeps the stored keys, and a non-rotation installs nothing.
        assert!(!state.successor_needs_keys(&heartbeat));
        assert!(!state.successor_needs_keys(&plain));

        // The rule reads the root before the rotation. Once K′ is installed, a return to the
        // earlier keys (K → K′ → K) is a key change again, and a heartbeat of K′ is not.
        let mut rotated = state;
        rotated.apply_checkpoint(&key_change, None, T0).unwrap();
        assert_eq!((rotated.generation, rotated.root), (6, next_root));
        let of_successor = |next: [u8; 32]| {
            SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
                generation: 6,
                committee_root: next_root,
                ..rotation_fields(1200, next)
            })
            .unwrap()
        };
        assert!(rotated.successor_needs_keys(&of_successor(root)));
        assert!(successor_keys_match(&current, &root));
        assert!(!rotated.successor_needs_keys(&of_successor(next_root)));

        // The TON rows of the reference: a key change without keys, or with the keys of
        // another committee, is `BadCommittee`; a heartbeat carries none.
        let pool = field(&transitions, "certificates");
        let (mut refused, mut with_keys, mut heartbeats) = (0, 0, 0);
        for scenario in rows(&transitions, "scenarios") {
            for step in rows(scenario, "steps") {
                if text(step, "call") != "sccp_checkpoint" {
                    continue;
                }
                let outcome = text(field(step, "expected"), "outcome");
                let ids = rows(step, "certificates");
                let supplied = rows(step, "next_keys");
                assert_eq!((ids.len(), supplied.len()), (1, 1));
                let entry = field(pool, ids[0].as_str().expect("a pool id"));
                let header =
                    SccpFinalityHeaderV1::parse(&bytes(text(field(entry, "evm"), "header")));
                let Ok(header) = header else { continue };
                let supplied = supplied[0]
                    .as_str()
                    .map(|name| keys(field(field(&transitions, "committees"), name), "keys"));
                let matches = supplied
                    .as_deref()
                    .is_some_and(|keys| successor_keys_match(keys, &header.next_committee_root()));
                // The successor the pool recorded for the certificate, if it changes keys.
                let recorded = field(entry, "ton_next_keys").as_str();
                if outcome == "BadCommittee" {
                    assert!(header.is_rotation() && recorded.is_some() && !matches);
                    refused += 1;
                } else if outcome == "ok" && header.is_rotation() {
                    if recorded.is_some() {
                        assert!(matches, "a key change is accepted with its keys only");
                        with_keys += 1;
                    } else {
                        assert_eq!(header.next_committee_root(), header.committee_root());
                        assert!(supplied.is_none());
                        heartbeats += 1;
                    }
                }
            }
        }
        assert!(
            refused >= 2 && with_keys >= 1 && heartbeats >= 1,
            "{refused} refused, {with_keys} key changes, {heartbeats} heartbeats"
        );
    }

    /// An event of the reference scenarios that certificate verification and the committee
    /// machine account for, in the fields they return.
    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        /// `SccpCertificate`: a full-path verification published the pooled certificate `id`.
        Certificate {
            height: u64,
            generation: u64,
            id: String,
        },
        Checkpointed {
            height: u64,
            id: [u8; 32],
        },
        Rotated(RotationV1),
        Latched(ViolationV1),
    }

    /// `MAX_CERTIFICATES_PER_CALL` of §3.9: the largest `submitCheckpoints` batch.
    const MAX_CERTIFICATES_PER_CALL: usize = 16;
    /// The checkpoint slots of a TON destination (§3.9).
    const TON_CHECKPOINT_SLOTS: usize = 3;

    /// The checkpoint store of a destination: every height on EVM, three slots on TON, where
    /// a new height enters only above the lowest stored one and evicts it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Checkpoints {
        slots: std::collections::BTreeMap<u64, [u8; 32]>,
        limit: Option<usize>,
    }

    impl Checkpoints {
        fn record(&mut self, height: u64, id: [u8; 32]) -> bool {
            if self.slots.contains_key(&height) {
                return false;
            }
            if self.limit.is_some_and(|limit| self.slots.len() >= limit) {
                let lowest = *self.slots.keys().next().expect("a full store");
                if height <= lowest {
                    return false;
                }
                self.slots.remove(&lowest);
            }
            self.slots.insert(height, id);
            true
        }
    }

    /// An active header of the scenario's network, as §5.1.3 step 2 requires it.
    fn certified_header(raw: &[u8]) -> Result<SccpFinalityHeaderV1, &'static str> {
        SccpFinalityHeaderV1::parse(raw)
            .ok()
            .filter(|header| header.is_active() && header.network_id() == [0x11; 32])
            .ok_or("BadHeader")
    }

    /// The header a `*FromCheckpoint` entry point names (§5.1.3): 221 bytes whose id is the
    /// one stored at their height, and an active header.
    fn checkpoint_header(
        store: &Checkpoints,
        raw: &[u8],
    ) -> Result<SccpFinalityHeaderV1, &'static str> {
        let raw = <&[u8; X_LEN]>::try_from(raw).map_err(|_| "BadHeader")?;
        let mut height = [0_u8; 8];
        height.copy_from_slice(&raw[48..56]);
        if store.slots.get(&u64::from_be_bytes(height)) != Some(&checkpoint_id(raw)) {
            return Err("UnknownCheckpoint");
        }
        SccpFinalityHeaderV1::parse(raw)
            .ok()
            .filter(SccpFinalityHeaderV1::is_active)
            .ok_or("BadHeader")
    }

    /// A certificate of a scenario step in its TON and Taira form, with the pool id that
    /// names it and the successor keys a TON message supplies with it.
    struct Certified {
        id: String,
        qc: Vec<u8>,
        header: Vec<u8>,
        signature: Vec<u8>,
        next_keys: Option<Vec<[u8; KEY_LEN]>>,
    }

    /// What the destination of a scenario verifies against: the pinned instance `I`, and the
    /// committees of the file, which give the keys of every root it can be at.
    struct Verifier<'a> {
        instance: [u8; 32],
        committees: &'a Value,
    }

    /// The §5.2.2 name of a refusal by the certificate relation. The scenario rows hold
    /// validated keys only, on which the two flavours report the same names.
    fn relation_error(error: CertificateError) -> &'static str {
        error.destination_error().name()
    }

    impl Verifier<'_> {
        fn keys_of(&self, root: &[u8; 32]) -> Vec<[u8; KEY_LEN]> {
            self.committees
                .as_object()
                .expect("committees by name")
                .values()
                .find(|committee| word(committee, "root") == *root)
                .map(|committee| keys(committee, "keys"))
                .expect("the current root is a committee of the file")
        }

        /// `VerifyCertificate` steps 1–12 (§5.1.3) over the keys of the current generation.
        /// It pushes `SccpCertificate` exactly when the full path ran: a certificate whose
        /// `X` is stored takes the mandatory cheap path, after the identity check of step 6.
        fn verify(
            &self,
            state: &CommitteeStateV1,
            store: &Checkpoints,
            certificate: &Certified,
            events: &mut Vec<Event>,
        ) -> Result<SccpFinalityHeaderV1, &'static str> {
            // Step 1: exact lengths.
            if certificate.qc.len() != QC_FIXED_LEN {
                return Err("BadCertificate");
            }
            if certificate.header.len() != X_LEN {
                return Err("BadHeader");
            }
            let signature = <[u8; SIGNATURE_LEN]>::try_from(&certificate.signature[..])
                .map_err(|_| "BadCertificate")?;
            // Steps 2 and 3.
            let header = certified_header(&certificate.header)?;
            if !state.is_current(&header) {
                return Err("CommitteeNotAccepted");
            }
            // Step 5.
            let committee = self.keys_of(&state.root);
            let qc = QcFixedV1::parse(&certificate.qc).map_err(relation_error)?;
            check_signers(qc.signers, committee.len()).map_err(relation_error)?;
            // Step 6: `σ = O` is refused before the cheap path.
            if signature == IDENTITY_SIGNATURE {
                return Err("BadSignature");
            }
            // Steps 7 and 8.
            if store.slots.get(&header.height()) == Some(&checkpoint_id(header.as_bytes())) {
                return Ok(header);
            }
            // Steps 9–12.
            verify_certificate(
                &self.instance,
                &certificate.qc,
                &certificate.header,
                &signature,
                &committee,
            )
            .map_err(relation_error)?;
            events.push(Event::Certificate {
                height: header.height(),
                generation: header.generation(),
                id: certificate.id.clone(),
            });
            Ok(header)
        }
    }

    /// `submitCheckpoints` (one `sccp_checkpoint` per certificate on TON): the batch rules of
    /// §5.1.3 around certificate verification and [`CommitteeStateV1::apply_checkpoint`]. An
    /// error reverts the call, which the caller does; `Ok` carries the reason processing
    /// stopped early, if it did.
    fn submit(
        verifier: &Verifier<'_>,
        state: &mut CommitteeStateV1,
        store: &mut Checkpoints,
        batch: &[Certified],
        now_ms: u64,
        events: &mut Vec<Event>,
    ) -> Result<Option<&'static str>, &'static str> {
        if batch.len() > MAX_CERTIFICATES_PER_CALL {
            return Err("TooManyCertificates");
        }
        if batch.is_empty() {
            return Err("NothingToDo");
        }
        state
            .require_live(now_ms)
            .map_err(CommitteeError::destination_error)?;
        let mut changed = false;
        for certificate in batch {
            let header = verifier.verify(state, store, certificate, events)?;
            // TON stores keys, so a rotation to another root must bring them.
            let needs_keys = store.limit.is_some() && state.successor_needs_keys(&header);
            let stored = store.slots.get(&header.height()).copied();
            let outcome = state
                .apply_checkpoint(&header, stored.as_ref(), now_ms)
                .map_err(CommitteeError::destination_error)?;
            match outcome {
                CheckpointOutcomeV1::Latched(violation) => {
                    events.push(Event::Latched(violation));
                    return Ok(Some("latch"));
                }
                CheckpointOutcomeV1::Applied {
                    high_raised,
                    rotation,
                    live,
                } => {
                    let id = checkpoint_id(header.as_bytes());
                    if store.record(header.height(), id) {
                        events.push(Event::Checkpointed {
                            height: header.height(),
                            id,
                        });
                        changed = true;
                    }
                    changed |= high_raised;
                    if let Some(rotation) = rotation {
                        let keys_match = certificate
                            .next_keys
                            .as_deref()
                            .is_some_and(|keys| successor_keys_match(keys, &rotation.root));
                        if needs_keys && !keys_match {
                            return Err("BadCommittee");
                        }
                        events.push(Event::Rotated(rotation));
                        changed = true;
                    }
                    if !live {
                        return Ok(Some("frozen"));
                    }
                }
            }
        }
        if changed {
            Ok(None)
        } else {
            Err("NothingToDo")
        }
    }

    fn state_of(value: &Value, limit: Option<usize>) -> (CommitteeStateV1, Checkpoints) {
        let committee = field(value, "committee");
        let state = CommitteeStateV1 {
            root: word(committee, "root"),
            generation: number(committee, "generation"),
            start: number(committee, "start"),
            high: number(committee, "high"),
            until_ms: number(committee, "until_ms"),
            equivocated: field(value, "equivocated").as_bool().expect("a flag"),
        };
        let slots = field(value, "checkpoints")
            .as_array()
            .expect("a checkpoint list")
            .iter()
            .map(|checkpoint| (number(checkpoint, "height"), word(checkpoint, "id")))
            .collect();
        (state, Checkpoints { slots, limit })
    }

    /// The certificate and committee events among the events a scenario step expects.
    fn expected_events(expected: &Value) -> Vec<Event> {
        let Some(events) = expected.get("events").and_then(Value::as_array) else {
            return Vec::new();
        };
        events
            .iter()
            .filter_map(|event| match text(event, "event") {
                "SccpCertificate" => Some(Event::Certificate {
                    height: number(event, "height"),
                    generation: number(event, "generation"),
                    id: text(event, "certificate").to_owned(),
                }),
                "SccpCheckpointed" => Some(Event::Checkpointed {
                    height: number(event, "height"),
                    id: word(event, "header"),
                }),
                "SccpCommitteeRotated" => Some(Event::Rotated(RotationV1 {
                    generation: number(event, "generation"),
                    root: word(event, "root"),
                    until_ms: number(event, "untilMs"),
                    start: number(event, "startHeight"),
                })),
                "SccpLatched" => Some(Event::Latched(ViolationV1 {
                    reason: match number(event, "reason") {
                        1 => LatchReasonV1::ConflictingCheckpoint,
                        2 => LatchReasonV1::BelowStart,
                        3 => LatchReasonV1::RotationBelowHigh,
                        other => panic!("unknown latch reason {other}"),
                    },
                    generation: number(event, "generation"),
                    height: number(event, "height"),
                    a: word(event, "a"),
                    b: word(event, "b"),
                })),
                _ => None,
            })
            .collect()
    }

    /// What a replay met, so that no scenario list is replayed vacuously.
    #[derive(Debug, Default)]
    struct Replayed {
        scenarios: usize,
        steps: usize,
        /// `SccpLatched` events.
        latches: usize,
        /// `SccpCommitteeRotated` events.
        rotations: usize,
        /// Batches that stopped at a rotation into an expired successor.
        frozen: usize,
        /// Calls that certificate verification or the machine refused.
        refusals: usize,
        /// `SccpCertificate` events: full-path verifications.
        published: usize,
        /// Checkpoint uses refused because the header is neither U1 nor U2.
        retired: usize,
    }

    /// Replays every scenario of `reference[list]` (the scenario shape of
    /// `fixtures/sccp/committee_transitions_v1.json`) through certificate verification and
    /// the machine: after each step the committee state, the latch, the checkpoints, and the
    /// certificate and committee events are the ones the independent Python model recorded.
    /// Every certificate is verified in its TON and Taira form over the keys of the current
    /// root, with the identity check of step 6 and the mandatory cheap path of step 8, so
    /// `SccpCertificate` appears exactly on the full path. A `*FromCheckpoint` step is
    /// decided by the checkpoint lookup and [`CommitteeStateV1::require_checkpoint_use`].
    /// Proofs, payloads, controls, voids and reads are outside the machine: such a step must
    /// leave the committee state unchanged.
    fn replay(reference: &Value, list: &str) -> Replayed {
        let pool = field(reference, "certificates");
        let committees = field(reference, "committees");
        let certificate = |id: &Value, next_keys: Option<Vec<[u8; KEY_LEN]>>| {
            let id = id.as_str().expect("a pool id");
            let entry = field(pool, id);
            Certified {
                id: id.to_owned(),
                qc: bytes(text(field(entry, "evm"), "qc")),
                header: bytes(text(field(entry, "evm"), "header")),
                signature: bytes(text(field(entry, "ton"), "signature")),
                next_keys,
            }
        };
        // The limits the harness applies are the ones the file states (§3.9).
        if let Some(constants) = reference.get("constants") {
            assert_eq!(
                usize::try_from(number(constants, "max_certificates_per_call")),
                Ok(MAX_CERTIFICATES_PER_CALL)
            );
            assert_eq!(
                usize::try_from(number(constants, "ton_checkpoint_slots")),
                Ok(TON_CHECKPOINT_SLOTS)
            );
        }
        let mut replayed = Replayed::default();
        for scenario in rows(reference, list) {
            let name = text(scenario, "name");
            // The refusals of this row are the EVM calldata encodings of §5.1.3 step 6
            // (`signerYs` and the limbs of `σ`), which the destination model checks before
            // the cheap path. The verifier of this replay reads the TON form only, and the
            // committee machine is never asked.
            if name == "cheap_path_checks_encodings" {
                continue;
            }
            let limit = match text(scenario, "flavor") {
                "evm" => None,
                "ton" => Some(TON_CHECKPOINT_SLOTS),
                other => panic!("unknown flavor `{other}`"),
            };
            let (mut state, mut store) = state_of(field(scenario, "initial_state"), limit);
            let deployment = field(scenario, "deployment");
            // The cheap path is mandatory: no deployment carries a switch for it.
            assert!(deployment.get("cheap_path").is_none(), "{name}");
            let verifier = Verifier {
                instance: word(deployment, "consensus_instance"),
                committees,
            };
            let pin = field(deployment, "pin");
            assert_eq!(
                CommitteeStateV1::from_pin(
                    number(pin, "generation"),
                    word(pin, "committee_root"),
                    number(pin, "start_height"),
                    number(pin, "until_ms"),
                ),
                Some(state),
                "{name}"
            );
            assert!(store.slots.is_empty(), "{name}");

            for (index, step) in rows(scenario, "steps").iter().enumerate() {
                let at = format!("{name}, step {index}");
                let now_ms = number(step, "now_ms");
                let expected = field(step, "expected");
                let outcome = expected.get("outcome").and_then(Value::as_str);
                let saved = (state, store.clone());
                let mut events = Vec::new();
                // A TON row names the message of §5.3.2; the machine has one entry per kind.
                let call = match text(step, "call") {
                    "sccp_checkpoint" => "submitCheckpoints",
                    "sccp_finalize" => "finalizeFromTaira",
                    "sccp_finalize_checkpoint" => "finalizeFromCheckpoint",
                    "sccp_apply_control" => "applyControl",
                    "sccp_apply_control_checkpoint" => "applyControlFromCheckpoint",
                    "sccp_void_expired" => "voidExpired",
                    "sccp_void_expired_checkpoint" => "voidExpiredFromCheckpoint",
                    "sccp_void_frozen" => "voidFrozen",
                    evm => evm,
                };
                // A TON minter checks the payload of a finalize or a void before it obtains
                // `X` (§5.3.4), so such a refusal comes before the machine is asked.
                let refused_before_x = limit.is_some()
                    && (call.starts_with("finalize") || call.starts_with("voidExpired"))
                    && matches!(outcome, Some("BadPayload" | "BadRecipient"));
                let result = match call {
                    _ if refused_before_x => None,
                    "submitCheckpoints" => {
                        let ids = field(step, "certificates").as_array().expect("ids");
                        let next_keys = step.get("next_keys").and_then(Value::as_array);
                        let batch: Vec<Certified> = ids
                            .iter()
                            .enumerate()
                            .map(|(position, id)| {
                                let supplied = next_keys
                                    .and_then(|names| names[position].as_str())
                                    .map(|committee| keys(field(committees, committee), "keys"));
                                certificate(id, supplied)
                            })
                            .collect();
                        let result = submit(
                            &verifier,
                            &mut state,
                            &mut store,
                            &batch,
                            now_ms,
                            &mut events,
                        );
                        if let Ok(stopped) = result {
                            assert_eq!(outcome, Some("ok"), "{at}");
                            assert_eq!(
                                expected.get("stopped").and_then(Value::as_str),
                                stopped,
                                "{at}"
                            );
                        }
                        Some(result.map(|_| ()))
                    }
                    // An inline entry point: `X` is obtained as CUR, then `Live` is required.
                    "finalizeFromTaira" | "applyControl" | "voidExpired" => {
                        let inline = certificate(field(step, "certificate"), None);
                        let obtained = verifier
                            .verify(&state, &store, &inline, &mut events)
                            .and_then(|header| {
                                let stored = store.slots.get(&header.height()).copied();
                                state
                                    .apply_inline(&header, stored.as_ref(), now_ms)
                                    .map_err(CommitteeError::destination_error)?;
                                let id = checkpoint_id(header.as_bytes());
                                if store.record(header.height(), id) {
                                    events.push(Event::Checkpointed {
                                        height: header.height(),
                                        id,
                                    });
                                }
                                Ok(())
                            });
                        // A later check of the entry point (the pause, the proof, the payload,
                        // the control) can still fail the call; the machine has no part in that.
                        if obtained.is_ok() && outcome != Some("ok") {
                            None
                        } else {
                            Some(obtained)
                        }
                    }
                    // A checkpoint reference: the stored id and an active header, then `Live`
                    // and U1 or U2. The use changes no committee state.
                    call if call.ends_with("FromCheckpoint") => {
                        let raw = bytes(text(field(step, "checkpoint"), "header"));
                        let obtained = checkpoint_header(&store, &raw).and_then(|header| {
                            let verdict = state.require_checkpoint_use(&header, now_ms);
                            if verdict == Err(CommitteeError::CheckpointRetired) {
                                replayed.retired += 1;
                            }
                            verdict.map_err(CommitteeError::destination_error)
                        });
                        if obtained.is_ok() && outcome != Some("ok") {
                            None
                        } else {
                            Some(obtained)
                        }
                    }
                    call => {
                        assert!(matches!(call, "voidFrozen" | "views"), "{at}: {call}");
                        assert_eq!(outcome.is_none(), call == "views", "{at}");
                        Some(Ok(()))
                    }
                };
                let applied = match result {
                    Some(Ok(())) => true,
                    Some(Err(refusal)) => {
                        assert_eq!(outcome, Some(refusal), "{at}");
                        replayed.refusals += 1;
                        false
                    }
                    None => false,
                };
                if !applied {
                    // A failed call reverts: no state change and no event.
                    (state, store) = saved;
                    events.clear();
                }

                assert_eq!(events, expected_events(expected), "{at}");
                let (state_after, store_after) = state_of(field(step, "state_after"), limit);
                assert_eq!(state, state_after, "{at}");
                assert_eq!(store, store_after, "{at}");
                assert_eq!(
                    field(field(step, "state_after"), "live").as_bool(),
                    Some(state.is_live(now_ms)),
                    "{at}"
                );
                for event in &events {
                    match event {
                        Event::Certificate { .. } => replayed.published += 1,
                        Event::Latched(_) => replayed.latches += 1,
                        Event::Rotated(_) => replayed.rotations += 1,
                        Event::Checkpointed { .. } => {}
                    }
                }
                if expected.get("stopped").and_then(Value::as_str) == Some("frozen") {
                    replayed.frozen += 1;
                }
                replayed.steps += 1;
            }
            replayed.scenarios += 1;
        }
        replayed
    }

    /// Every scenario of `fixtures/sccp/committee_transitions_v1.json` ([`replay`]).
    #[test]
    fn state_machine_replays_the_reference_transitions() {
        let reference = reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        );
        let replayed = replay(&reference, "scenarios");
        // The rows §11.1 requires are all there: V1, V2 and V3 latches, rotations (16 of them
        // in one batch), a rotation into an expired successor, refusals without effect, and
        // the checkpoints of retired generations refused for finalize, control and void on
        // EVM and for finalize and control on TON.
        assert!(replayed.scenarios >= 39, "{replayed:?}");
        assert!(replayed.steps >= 184, "{replayed:?}");
        assert!(replayed.latches >= 7, "{replayed:?}");
        assert!(replayed.rotations >= 31, "{replayed:?}");
        assert!(replayed.frozen >= 1, "{replayed:?}");
        assert!(replayed.refusals >= 39, "{replayed:?}");
        assert!(replayed.published >= 60, "{replayed:?}");
        assert!(replayed.retired >= 10, "{replayed:?}");
    }

    /// Every `applyControl` scenario of `fixtures/sccp/control_v1.json` ([`replay`]): the
    /// inline and checkpoint forms of a control obtain `X` exactly as a finalization does,
    /// and no control changes the committee state beyond the checkpoint and `high` of its
    /// certificate.
    #[test]
    fn state_machine_replays_the_reference_control_scenarios() {
        let reference = reference("control_v1.json", "iroha.sccp.control.v1");
        let replayed = replay(&reference, "destination_effects");
        assert!(replayed.scenarios >= 10, "{replayed:?}");
        assert!(replayed.steps >= 42, "{replayed:?}");
        assert!(replayed.published >= 11, "{replayed:?}");
        // A control on an expired destination, and a checkpoint the destination never stored.
        assert!(replayed.refusals >= 2, "{replayed:?}");
        // Controls neither rotate nor latch.
        assert_eq!(
            (replayed.rotations, replayed.latches, replayed.frozen),
            (0, 0, 0),
            "{replayed:?}"
        );
    }

    #[test]
    fn committee_errors_name_their_destination_error() {
        // Every refusal has a §5.2.2 name: no call aborts without one.
        let names = [
            (CommitteeError::Equivocated, "Equivocated"),
            (CommitteeError::Expired, "CommitteeNotAccepted"),
            (CommitteeError::NotCurrent, "CommitteeNotAccepted"),
            (CommitteeError::LatchRequired, "LatchRequired"),
            (CommitteeError::CheckpointRetired, "CommitteeNotAccepted"),
        ];
        for (error, name) in names {
            assert_eq!(error.destination_error(), name);
            assert!(!error.to_string().is_empty());
        }
        assert!(!PointFormError::NotReduced.to_string().is_empty());
        assert!(!PointFormError::NotOnCurve.to_string().is_empty());
    }
}
