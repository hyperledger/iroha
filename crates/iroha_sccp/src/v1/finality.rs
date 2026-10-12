//! Certificate encodings and the destination verification relation
//! (`specs/sccp.md` §3.6–§3.8, revision 5; `specs/sumeragi.md` §3.3, §3.3.1 and §4.1.1).
//!
//! A Taira `CommitQC` certifies the result `R`, which binds the 221-byte finality header `X`:
//!
//! ```text
//! R  = SHA-256(RESULT_TAG ‖ X ‖ D_body)                                  // outer_result
//! P  = "sumeragi/sig" ‖ 0x03 ‖ I ‖ be64(epoch) ‖ epoch_context
//!      ‖ be64(X.height) ‖ be64(view) ‖ block_hash ‖ R                    // 165 bytes
//! m  = SHA-256(P)
//! σ  = Σ sk_i · hash_to_G2(m, DST_SIG)   over exactly q = n − f signers
//! ```
//!
//! A destination receives `X`, the fields of the QC it cannot derive (`QC_FIXED`, 116 bytes)
//! and the aggregate signature `σ`, and checks them against the keys of its current
//! committee generation. [`verify_certificate`] is that relation, and the reference for the
//! EVM and TON contracts, for Torii, which verifies every bundle it serves with it, and for
//! Taira's forgery evidence.
//!
//! The header `X`, the result `R` and the reader of `X ‖ body` live in
//! `iroha_data_model::sumeragi_finality::certified_result`, below this crate, because nodes
//! produce and read them. They are re-exported here. This module adds [`QcFixedV1`], the
//! signer bitmap conversion, the Commit preimage and message, [`checkpoint_id`] and the
//! relation. The Commit preimage is built here independently of `iroha_sumeragi` and proved
//! equal to its `vote_preimage` by a test: the layout is a frozen external surface.
//!
//! Signatures are checked only through `iroha_crypto::bls::consensus`, the one API that
//! hashes under `DST_SIG`.

use core::fmt;

pub use iroha_crypto::bls::consensus::DST_SIG;
use iroha_crypto::bls::consensus::{
    ConsensusDigest, key_validate, verify_fast_aggregate_committed,
};
pub use iroha_data_model::sumeragi_finality::{
    MAX_RESULT_PREIMAGE_BYTES, RESULT_TAG,
    certified_result::{
        CertifiedResultError, CertifiedResultScope, CertifiedResultV1, FLAG_ACTIVE, FLAG_ROTATION,
        FinalityHeaderError, MAX_HISTORY_SIZE, MAX_RESULT_BODY_BYTES, MAX_VALIDITY_MS,
        RESULT_BODY_TAG, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1, X_HEAD_LEN, X_LEN,
        X_MAGIC, X_TAIL_LEN, body_digest, outer_result, result_of_preimage,
    },
};
use sha2::{Digest as _, Sha256};

use super::{
    committee::{
        IDENTITY_KEY, IDENTITY_SIGNATURE, KEY_LEN, MAX_COMMITTEE_SIZE, SIGNATURE_LEN,
        aggregate_public_key, quorum, signer_indices, signer_point_sum,
    },
    destination_abi::DestinationError,
    hashes::keccak256,
};

/// Exact byte length of `QC_FIXED`.
pub const QC_FIXED_LEN: usize = 116;
/// Exact byte length of the Commit vote preimage `P`.
pub const COMMIT_PREIMAGE_LEN: usize = 165;
/// Domain tag of every Sumeragi signing preimage (`specs/sumeragi.md` §3.1).
pub const TAG_SIG: &[u8] = b"sumeragi/sig";
/// Kind byte of a Commit vote. A destination accepts no other kind: a `PrepareQC` is never a
/// certificate.
pub const KIND_COMMIT: u8 = 0x03;

// Field offsets of `QC_FIXED` (`specs/sccp.md` §3.7). Every integer is big-endian.
const QC_OFFSET_EPOCH_CONTEXT: usize = 8;
const QC_OFFSET_VIEW: usize = 40;
const QC_OFFSET_BLOCK_HASH: usize = 48;
const QC_OFFSET_RESULT_BODY: usize = 80;
const QC_OFFSET_SIGNERS: usize = 112;

// Field offsets of `P` (`specs/sumeragi.md` §3.3).
const P_OFFSET_KIND: usize = 12;
const P_OFFSET_INSTANCE: usize = 13;
const P_OFFSET_EPOCH: usize = 45;
const P_OFFSET_EPOCH_CONTEXT: usize = 53;
const P_OFFSET_HEIGHT: usize = 85;
const P_OFFSET_VIEW: usize = 93;
const P_OFFSET_BLOCK_HASH: usize = 101;
const P_OFFSET_RESULT: usize = 133;

const _: () = assert!(QC_OFFSET_SIGNERS + 4 == QC_FIXED_LEN);
const _: () =
    assert!(TAG_SIG.len() == P_OFFSET_KIND && P_OFFSET_RESULT + 32 == COMMIT_PREIMAGE_LEN);
// `signers` is 32 bits wide and every committee leaves bit 31 spare.
const _: () = assert!(MAX_COMMITTEE_SIZE < 32);

/// Why a certificate fails the destination verification relation.
///
/// [`verify_certificate`] and [`verify_certificate_by_aggregate`] document the order in which
/// they report them: the order a destination checks the same things in (`specs/sccp.md`
/// §5.1.3), cheapest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateError {
    /// `QC_FIXED` is not exactly [`QC_FIXED_LEN`] bytes: a truncation, trailing bytes or an
    /// extension field (§3.8 step 3).
    QcFixedLength,
    /// `X` is not a finality header, so the certificate has no `R` (§3.8 step 4).
    Header(FinalityHeaderError),
    /// The committee size is not in `{4, 7, …, 31}` (§3.8 step 1).
    CommitteeSize,
    /// A signer bit at or above the committee size is set (§3.8 step 2).
    SpareSignerBits,
    /// The signer count is not exactly `q = n − f` (§3.8 step 2).
    SignerCount,
    /// `σ` is the identity, `0xc0` followed by 95 zero bytes (§3.8 step 9: `σ ≠ O`). A
    /// destination refuses it at §5.1.3 step 6, before the cheap path and before any curve
    /// operation, so both flavours agree on a certificate whose `X` is already stored.
    IdentitySignature,
    /// A signer's key fails `KeyValidate` ([`verify_certificate`]), or is not the canonical
    /// encoding of a finite point of the curve ([`verify_certificate_by_aggregate`]).
    SignerKey,
    /// The signer keys sum to the identity: `apk = O` (§3.8 step 7).
    AggregateIdentity,
    /// The signer keys sum to a point of the curve outside the G1 subgroup. Only
    /// [`verify_certificate_by_aggregate`] reports it: with `KeyValidate` on every signer key
    /// the sum is always in G1.
    AggregateSubgroup,
    /// `σ` is not the canonical encoding of a point of the G2 subgroup, or the pairing check
    /// fails (§3.8 steps 8–9).
    Signature,
}

impl CertificateError {
    /// The `specs/sccp.md` §5.2.2 error an EVM destination reports for this failure (§5.1.3).
    ///
    /// `apk = O` is `BadCommittee` (step 10). A signer key or an aggregate key outside G1 is
    /// `BadSignature`: the pairing precompile refuses the aggregate (step 11).
    #[must_use]
    pub const fn destination_error(self) -> DestinationError {
        match self {
            Self::QcFixedLength | Self::SpareSignerBits | Self::SignerCount => {
                DestinationError::BadCertificate
            }
            Self::Header(_) => DestinationError::BadHeader,
            Self::CommitteeSize | Self::AggregateIdentity => DestinationError::BadCommittee,
            Self::IdentitySignature
            | Self::SignerKey
            | Self::AggregateSubgroup
            | Self::Signature => DestinationError::BadSignature,
        }
    }

    /// The §5.2.2 error a TON destination reports for this failure.
    ///
    /// It differs from [`Self::destination_error`] for `apk = O` only: the minter has one
    /// verdict for the keys, the aggregate and the signature, the result of
    /// `BLS_FASTAGGREGATEVERIFY`, and `false` throws `BadSignature` (§5.3.4 item 5).
    #[must_use]
    pub const fn ton_destination_error(self) -> DestinationError {
        match self {
            Self::AggregateIdentity => DestinationError::BadSignature,
            other => other.destination_error(),
        }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QcFixedLength => formatter.write_str("QC_FIXED is exactly 116 bytes"),
            Self::Header(error) => write!(formatter, "invalid finality header: {error}"),
            Self::CommitteeSize => formatter.write_str("the committee size is not 3f + 1 ≤ 31"),
            Self::SpareSignerBits => {
                formatter.write_str("a signer bit names no member of the committee")
            }
            Self::SignerCount => formatter.write_str("the signer count is not the quorum n − f"),
            Self::IdentitySignature => {
                formatter.write_str("the aggregate signature is the identity")
            }
            Self::SignerKey => formatter.write_str("a signer key is not a valid key"),
            Self::AggregateIdentity => formatter.write_str("the aggregate key is the identity"),
            Self::AggregateSubgroup => {
                formatter.write_str("the aggregate key is outside the G1 subgroup")
            }
            Self::Signature => formatter.write_str("the aggregate signature does not verify"),
        }
    }
}

impl std::error::Error for CertificateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FinalityHeaderError> for CertificateError {
    fn from(error: FinalityHeaderError) -> Self {
        Self::Header(error)
    }
}

/// `QC_FIXED`: the fields of a `CommitQC` that a destination cannot derive from `X`.
///
/// | Offset | Size | Field |
/// |---|---|---|
/// | 0 | 8 | `epoch` |
/// | 8 | 32 | `epoch_context` |
/// | 40 | 8 | `view` |
/// | 48 | 32 | `block_hash` |
/// | 80 | 32 | `result_body` |
/// | 112 | 4 | `signers` |
///
/// A destination takes `epoch`, `epoch_context`, `view` and `block_hash` unverified: they
/// only enter the signed preimage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QcFixedV1 {
    /// `qc.epoch.epoch`: the scheduling epoch.
    pub epoch: u64,
    /// `qc.epoch.context`: the digest of the epoch context.
    pub epoch_context: [u8; 32],
    /// `qc.view`.
    pub view: u64,
    /// `qc.block_hash`: the Sumeragi core block hash.
    pub block_hash: [u8; 32],
    /// `D_body`: the digest of the result body ([`body_digest`]).
    pub result_body: [u8; 32],
    /// The signer set: bit `i` is canonical index `i` ([`signers_from_bitmap`]).
    pub signers: u32,
}

impl QcFixedV1 {
    /// The canonical 116 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; QC_FIXED_LEN] {
        let mut out = [0_u8; QC_FIXED_LEN];
        out[..QC_OFFSET_EPOCH_CONTEXT].copy_from_slice(&self.epoch.to_be_bytes());
        out[QC_OFFSET_EPOCH_CONTEXT..QC_OFFSET_VIEW].copy_from_slice(&self.epoch_context);
        out[QC_OFFSET_VIEW..QC_OFFSET_BLOCK_HASH].copy_from_slice(&self.view.to_be_bytes());
        out[QC_OFFSET_BLOCK_HASH..QC_OFFSET_RESULT_BODY].copy_from_slice(&self.block_hash);
        out[QC_OFFSET_RESULT_BODY..QC_OFFSET_SIGNERS].copy_from_slice(&self.result_body);
        out[QC_OFFSET_SIGNERS..].copy_from_slice(&self.signers.to_be_bytes());
        out
    }

    /// Parse the canonical layout. Every 116-byte string is a `QC_FIXED`; the signer set is
    /// checked against a committee by [`check_signers`].
    ///
    /// # Errors
    /// [`CertificateError::QcFixedLength`] unless `bytes` is exactly [`QC_FIXED_LEN`] bytes:
    /// extension fields and trailing bytes are rejected.
    pub fn parse(bytes: &[u8]) -> Result<Self, CertificateError> {
        let raw =
            <&[u8; QC_FIXED_LEN]>::try_from(bytes).map_err(|_| CertificateError::QcFixedLength)?;
        Ok(Self {
            epoch: u64::from_be_bytes(array_at(raw, 0)),
            epoch_context: array_at(raw, QC_OFFSET_EPOCH_CONTEXT),
            view: u64::from_be_bytes(array_at(raw, QC_OFFSET_VIEW)),
            block_hash: array_at(raw, QC_OFFSET_BLOCK_HASH),
            result_body: array_at(raw, QC_OFFSET_RESULT_BODY),
            signers: u32::from_be_bytes(array_at(raw, QC_OFFSET_SIGNERS)),
        })
    }
}

// Every call names a constant offset of the layout table with `offset + N ≤ QC_FIXED_LEN`.
fn array_at<const N: usize>(raw: &[u8; QC_FIXED_LEN], offset: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&raw[offset..offset + N]);
    out
}

/// `signers = Σ_j bitmap[j] << 8j` of a Sumeragi signer bitmap for a committee of `n`.
///
/// The bitmap is `ceil(n / 8)` bytes in which bit `i` is canonical index `i`, least
/// significant bit first within each byte, so the field is the bitmap read as a
/// little-endian integer and bit `i` of the field is index `i`. Reading the bitmap bytes as a
/// big-endian integer instead is wrong: `n = 31` with signers `{0, 9, 30}` has the bitmap
/// `01 02 00 40` and `signers = 0x40000201`, not `0x01020040`.
///
/// Returns `None` unless `1 ≤ n ≤ 31`, the bitmap has exactly `ceil(n / 8)` bytes and no bit
/// at or above `n` is set.
#[must_use]
pub fn signers_from_bitmap(bitmap: &[u8], n: usize) -> Option<u32> {
    if !(1..=MAX_COMMITTEE_SIZE).contains(&n) || bitmap.len() != n.div_ceil(8) {
        return None;
    }
    let mut bytes = [0_u8; 4];
    bytes[..bitmap.len()].copy_from_slice(bitmap);
    let signers = u32::from_le_bytes(bytes);
    (signers >> n == 0).then_some(signers)
}

/// The Sumeragi signer bitmap of a `signers` field for a committee of `n`: the inverse of
/// [`signers_from_bitmap`].
///
/// Returns `None` unless `1 ≤ n ≤ 31` and no bit at or above `n` is set.
#[must_use]
pub fn bitmap_from_signers(signers: u32, n: usize) -> Option<Vec<u8>> {
    if !(1..=MAX_COMMITTEE_SIZE).contains(&n) || signers >> n != 0 {
        return None;
    }
    Some(signers.to_le_bytes()[..n.div_ceil(8)].to_vec())
}

/// Steps 1 and 2 of the relation for a committee of `n` keys: `n ∈ {4, 7, …, 31}`, no signer
/// bit at or above `n`, and exactly `q = n − f` signers. A superset of a quorum is refused.
///
/// # Errors
/// [`CertificateError::CommitteeSize`], then [`CertificateError::SpareSignerBits`], then
/// [`CertificateError::SignerCount`].
pub fn check_signers(signers: u32, n: usize) -> Result<(), CertificateError> {
    let quorum = quorum(n).ok_or(CertificateError::CommitteeSize)?;
    if signers >> n != 0 {
        return Err(CertificateError::SpareSignerBits);
    }
    if usize::try_from(signers.count_ones()) != Ok(quorum) {
        return Err(CertificateError::SignerCount);
    }
    Ok(())
}

/// The Commit vote preimage `P` of a certificate (`specs/sumeragi.md` §3.3):
///
/// ```text
/// "sumeragi/sig" ‖ 0x03 ‖ I ‖ be64(epoch) ‖ epoch_context ‖ be64(height) ‖ be64(view)
///     ‖ block_hash ‖ R
/// ```
///
/// `instance` is the pinned consensus instance `I`, `height` is `X.height` and `result` is
/// `R`. The `result_body` and `signers` of `qc` are not part of `P`.
#[must_use]
pub fn commit_preimage(
    instance: &[u8; 32],
    qc: &QcFixedV1,
    height: u64,
    result: &[u8; 32],
) -> [u8; COMMIT_PREIMAGE_LEN] {
    let mut out = [0_u8; COMMIT_PREIMAGE_LEN];
    out[..P_OFFSET_KIND].copy_from_slice(TAG_SIG);
    out[P_OFFSET_KIND] = KIND_COMMIT;
    out[P_OFFSET_INSTANCE..P_OFFSET_EPOCH].copy_from_slice(instance);
    out[P_OFFSET_EPOCH..P_OFFSET_EPOCH_CONTEXT].copy_from_slice(&qc.epoch.to_be_bytes());
    out[P_OFFSET_EPOCH_CONTEXT..P_OFFSET_HEIGHT].copy_from_slice(&qc.epoch_context);
    out[P_OFFSET_HEIGHT..P_OFFSET_VIEW].copy_from_slice(&height.to_be_bytes());
    out[P_OFFSET_VIEW..P_OFFSET_BLOCK_HASH].copy_from_slice(&qc.view.to_be_bytes());
    out[P_OFFSET_BLOCK_HASH..P_OFFSET_RESULT].copy_from_slice(&qc.block_hash);
    out[P_OFFSET_RESULT..].copy_from_slice(result);
    out
}

/// `m = SHA-256(P)`: the message the committee signs under [`DST_SIG`].
#[must_use]
pub fn commit_message(preimage: &[u8; COMMIT_PREIMAGE_LEN]) -> [u8; 32] {
    Sha256::digest(preimage).into()
}

/// `checkpoint_id(X) = keccak256(X)`: the identity a destination stores for a certified
/// header.
///
/// It is defined over the 221 bytes, so a destination can look a checkpoint up before it
/// parses the header.
#[must_use]
pub fn checkpoint_id(header: &[u8; X_LEN]) -> [u8; 32] {
    keccak256(&[header])
}

/// What a verified certificate establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCertificateV1 {
    /// The certified finality header `X`.
    pub header: SccpFinalityHeaderV1,
    /// The parsed `QC_FIXED`.
    pub qc: QcFixedV1,
    /// `R = SHA-256(RESULT_TAG ‖ X ‖ result_body)`.
    pub result: [u8; 32],
    /// `m = SHA-256(P)`, the signed message.
    pub message: [u8; 32],
    /// `keccak256(X)`.
    pub checkpoint_id: [u8; 32],
}

/// Steps 1–6 of the relation and the encoding of `σ`: what both forms of the relation check
/// before they read a key. Returns the header, the parsed `QC_FIXED`, `R` and the digest of
/// the Commit preimage.
fn certified_message(
    instance: &[u8; 32],
    qc_fixed: &[u8],
    x: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    committee_size: usize,
) -> Result<(SccpFinalityHeaderV1, QcFixedV1, [u8; 32], ConsensusDigest), CertificateError> {
    // Step 3, and the length a header needs: exact layouts before anything is read.
    let qc = QcFixedV1::parse(qc_fixed)?;
    if x.len() != X_LEN {
        return Err(FinalityHeaderError::Length.into());
    }
    // Step 1.
    if quorum(committee_size).is_none() {
        return Err(CertificateError::CommitteeSize);
    }
    let header = SccpFinalityHeaderV1::parse(x)?;
    // Step 2.
    check_signers(qc.signers, committee_size)?;
    // `σ ≠ O` of step 9, refused here as an encoding, where §5.1.3 step 6 places it: before
    // the result, the aggregate key and any curve operation.
    if *signature == IDENTITY_SIGNATURE {
        return Err(CertificateError::IdentitySignature);
    }
    // Steps 4–6. Kind 0x03 is part of `P`.
    let result = outer_result(&header, &qc.result_body).0;
    let preimage = commit_preimage(instance, &qc, header.height(), &result);
    let digest = ConsensusDigest::from_preimage(&preimage).ok_or(CertificateError::Signature)?;
    Ok((header, qc, result, digest))
}

/// The destination verification relation (`specs/sccp.md` §3.8 steps 1–9), with `KeyValidate`
/// on every signer key.
///
/// `instance` is the pinned consensus instance `I`; `qc_fixed` and `x` are the certificate's
/// `QC_FIXED` and finality header; `signature` is the compressed aggregate `σ`; `keys` are
/// the compressed keys `PK_0..PK_{n−1}` of the generation that must have signed, in
/// canonical order. The caller takes `keys` from an authenticated committee root.
///
/// The relation proves that exactly `q = n − f` of `keys` signed the Commit preimage of `X`.
/// It does not decide whether the destination should trust that generation or act on `X`:
/// the network identity, the `ACTIVE` flag, the classification against the current
/// generation and the violation predicates are the caller's checks
/// ([`super::committee::CommitteeStateV1`]).
///
/// This is the form Taira and Torii use, and what TON's `BLS_FASTAGGREGATEVERIFY` decides: a
/// signer key that is not canonical, is the identity or lies outside G1 fails it. An EVM
/// destination sees the aggregate key only ([`verify_certificate_by_aggregate`]). The two
/// forms agree on every committee whose keys pass `KeyValidate`, which is every committee
/// under a root Taira admitted (§3.8).
///
/// The relation always runs in full. The cheap path of §5.1.3 step 8, which skips the
/// signature check for an `X` whose checkpoint is stored, belongs to the destination: such a
/// caller still refuses [`IDENTITY_SIGNATURE`] first, as step 6 requires on both flavours.
///
/// # Errors
/// The first failure, in this order: [`CertificateError::QcFixedLength`];
/// [`CertificateError::Header`] for the length of `x`; [`CertificateError::CommitteeSize`];
/// [`CertificateError::Header`] for X1–X7; [`CertificateError::SpareSignerBits`];
/// [`CertificateError::SignerCount`]; [`CertificateError::IdentitySignature`];
/// [`CertificateError::SignerKey`]; [`CertificateError::AggregateIdentity`];
/// [`CertificateError::Signature`].
pub fn verify_certificate(
    instance: &[u8; 32],
    qc_fixed: &[u8],
    x: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    keys: &[[u8; KEY_LEN]],
) -> Result<VerifiedCertificateV1, CertificateError> {
    let (header, qc, result, digest) =
        certified_message(instance, qc_fixed, x, signature, keys.len())?;
    // Step 7, with `KeyValidate` on every signer key.
    let signer_keys: Vec<[u8; KEY_LEN]> = signer_indices(qc.signers, keys.len())
        .ok_or(CertificateError::SpareSignerBits)?
        .into_iter()
        .map(|index| keys[index])
        .collect();
    if !signer_keys.iter().all(key_validate) {
        return Err(CertificateError::SignerKey);
    }
    aggregate_public_key(keys, qc.signers).ok_or(CertificateError::AggregateIdentity)?;
    // Steps 8–9.
    if !verify_fast_aggregate_committed(&signer_keys, &digest, signature) {
        return Err(CertificateError::Signature);
    }
    Ok(VerifiedCertificateV1 {
        header,
        qc,
        result,
        message: *digest.as_bytes(),
        checkpoint_id: checkpoint_id(header.as_bytes()),
    })
}

/// The relation as an EVM destination evaluates it (`specs/sccp.md` §5.1.3 steps 10–11):
/// the signer keys enter as points of the curve, and only their sum is validated.
///
/// `G1ADD` adds any points of the curve, and `PAIRING_CHECK` requires its inputs to be in
/// their subgroups, so the contract observes the aggregate key and never a single signer
/// key. The arguments are those of [`verify_certificate`]. The two functions agree whenever
/// every signer key passes `KeyValidate`. They differ on signer keys outside G1 whose
/// components outside the subgroup cancel: the aggregate is then a valid key, and this form
/// accepts a signature that verifies under it.
///
/// # Errors
/// As [`verify_certificate`] up to [`CertificateError::IdentitySignature`], then:
/// [`CertificateError::SignerKey`] for a signer key that is not the canonical encoding of a
/// finite point of the curve; [`CertificateError::AggregateIdentity`];
/// [`CertificateError::AggregateSubgroup`]; [`CertificateError::Signature`].
pub fn verify_certificate_by_aggregate(
    instance: &[u8; 32],
    qc_fixed: &[u8],
    x: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    keys: &[[u8; KEY_LEN]],
) -> Result<VerifiedCertificateV1, CertificateError> {
    let (header, qc, result, digest) =
        certified_message(instance, qc_fixed, x, signature, keys.len())?;
    // Step 7 over points of the curve.
    let aggregate = signer_point_sum(keys, qc.signers).ok_or(CertificateError::SignerKey)?;
    if aggregate == IDENTITY_KEY {
        return Err(CertificateError::AggregateIdentity);
    }
    // The sum is a canonical finite point, so `KeyValidate` decides its subgroup alone.
    if !key_validate(&aggregate) {
        return Err(CertificateError::AggregateSubgroup);
    }
    // Steps 8–9 under the aggregate key: `e(apk, H(m)) = e(g1, σ)`.
    if !verify_fast_aggregate_committed(&[aggregate], &digest, signature) {
        return Err(CertificateError::Signature);
    }
    Ok(VerifiedCertificateV1 {
        header,
        qc,
        result,
        message: *digest.as_bytes(),
        checkpoint_id: checkpoint_id(header.as_bytes()),
    })
}

/// Readers of the shared reference vectors (`fixtures/sccp/*.json`) for the `v1` unit tests.
///
/// A missing file or field fails the test that asks for it, so no table-driven test passes
/// vacuously.
#[cfg(test)]
pub(super) mod vectors {
    use std::path::PathBuf;

    use norito::json::Value;

    use super::super::committee::KEY_LEN;

    /// The document `fixtures/sccp/<file>`, checked against its schema name.
    pub fn reference(file: &str, schema: &str) -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sccp")
            .join(file);
        let document = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let value: Value = norito::json::from_str(&document)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        assert_eq!(text(&value, "schema"), schema);
        value
    }

    /// `fixtures/sccp/finality_v1.json`.
    pub fn finality() -> Value {
        reference("finality_v1.json", "iroha.sccp.finality.v1")
    }

    pub fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
        value
            .get(name)
            .unwrap_or_else(|| panic!("reference field `{name}` is missing"))
    }

    pub fn text<'a>(value: &'a Value, name: &str) -> &'a str {
        field(value, name)
            .as_str()
            .unwrap_or_else(|| panic!("reference field `{name}` is not a string"))
    }

    pub fn number(value: &Value, name: &str) -> u64 {
        field(value, name)
            .as_u64()
            .unwrap_or_else(|| panic!("reference field `{name}` is not an unsigned integer"))
    }

    /// A non-empty array field.
    pub fn rows<'a>(value: &'a Value, name: &str) -> &'a [Value] {
        let rows = field(value, name)
            .as_array()
            .unwrap_or_else(|| panic!("reference field `{name}` is not an array"));
        assert!(!rows.is_empty(), "reference field `{name}` is empty");
        rows
    }

    /// Bytes of a `0x`-prefixed lowercase hex string, the byte-string form of the vectors.
    pub fn bytes(hex: &str) -> Vec<u8> {
        crate::decode_hex_bytes(hex)
            .unwrap_or_else(|| panic!("`{hex}` is not 0x-prefixed lowercase hex"))
    }

    /// Lowercase hex without a prefix, for comparison with the literals of the spec.
    pub fn hex(bytes: &[u8]) -> String {
        super::super::hashes::to_hex(bytes)
    }

    pub fn word(value: &Value, name: &str) -> [u8; 32] {
        bytes(text(value, name))
            .try_into()
            .unwrap_or_else(|_| panic!("reference field `{name}` is not 32 bytes"))
    }

    /// A compressed public key field.
    pub fn key(value: &Value, name: &str) -> [u8; KEY_LEN] {
        bytes(text(value, name))
            .try_into()
            .unwrap_or_else(|_| panic!("reference field `{name}` is not 48 bytes"))
    }

    /// An array of compressed public keys.
    pub fn keys(value: &Value, name: &str) -> Vec<[u8; KEY_LEN]> {
        rows(value, name)
            .iter()
            .map(|key| {
                bytes(key.as_str().expect("a key is a hex string"))
                    .try_into()
                    .unwrap_or_else(|_| panic!("a key of `{name}` is not 48 bytes"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{
        Algorithm, KeyPair, PrivateKey, Signature,
        bls::consensus::{aggregate, sign_preimage},
    };
    use iroha_sumeragi::{
        message::VoteKind,
        preimage::{self, vote_preimage},
        types::{Bitmap, EpochId, Hash32},
    };
    use norito::json::Value;

    use super::{
        super::committee::{
            CommitteeStateV1, EVM_SIGNATURE_LEN, FP_LEN, IDENTITY_SIGNATURE_EVM, PointFormError,
            committee_keys, committee_root, fp_is_canonical, signature_from_evm192,
            signature_to_evm192, signer_coordinates_name_a_finite_point, signer_key_flags_match,
            signer_point_is_on_curve,
        },
        super::destination_abi::DestinationError,
        vectors::{bytes, field, finality, hex, keys, number, rows, text, word},
        *,
    };

    /// Block time of the §11.2 worked examples.
    const T0: u64 = 1_790_000_000_000;
    const INSTANCE: [u8; 32] = [0x77; 32];

    /// The non-rotation example of §11.2: the common fields at height 7199.
    fn non_rotation_example() -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: [0x11; 32],
            height: 7199,
            timestamp_ms: T0 - 1000,
            flags: FLAG_ACTIVE,
            message_count: 2,
            sccp_root: [0x22; 32],
            history_size: 5,
            history_root: [0x33; 32],
            generation: 3,
            committee_root: [0x44; 32],
            validity_ms: 0,
            next_committee_root: [0; 32],
        }
    }

    /// The rotation example of §11.2: a key change to `0x55^32` at height 7200.
    fn rotation_example() -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            height: 7200,
            timestamp_ms: T0,
            flags: FLAG_ACTIVE | FLAG_ROTATION,
            validity_ms: 1_209_600_000,
            next_committee_root: [0x55; 32],
            ..non_rotation_example()
        }
    }

    /// The heartbeat example of §11.2: the rotation with the committee's own root as successor.
    fn heartbeat_example() -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            next_committee_root: [0x44; 32],
            ..rotation_example()
        }
    }

    fn header_of(fields: &SccpFinalityHeaderFieldsV1) -> SccpFinalityHeaderV1 {
        SccpFinalityHeaderV1::from_fields(fields).unwrap()
    }

    /// `QC_FIXED` of §11.2: epoch 2, context `0x88^32`, view 1, `bh = 0x99^32`,
    /// `result_body = 0x66^32`, signers {0, 9, 30}.
    fn qc_example() -> QcFixedV1 {
        QcFixedV1 {
            epoch: 2,
            epoch_context: [0x88; 32],
            view: 1,
            block_hash: [0x99; 32],
            result_body: [0x66; 32],
            signers: 0x4000_0201,
        }
    }

    fn qc_of(fields: &Value) -> QcFixedV1 {
        QcFixedV1 {
            epoch: number(fields, "epoch"),
            epoch_context: word(fields, "epoch_context"),
            view: number(fields, "view"),
            block_hash: word(fields, "block_hash"),
            result_body: word(fields, "result_body"),
            signers: u32::try_from(number(fields, "signers")).unwrap(),
        }
    }

    fn header_fields_of(fields: &Value) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: word(fields, "network_id"),
            height: number(fields, "height"),
            timestamp_ms: number(fields, "timestamp_ms"),
            flags: u8::try_from(number(fields, "flags")).unwrap(),
            message_count: u32::try_from(number(fields, "message_count")).unwrap(),
            sccp_root: word(fields, "sccp_root"),
            history_size: number(fields, "history_size"),
            history_root: word(fields, "history_root"),
            generation: number(fields, "generation"),
            committee_root: word(fields, "committee_root"),
            validity_ms: number(fields, "validity_ms"),
            next_committee_root: word(fields, "next_committee_root"),
        }
    }

    /// The wire fields of one certificate row, in the TON and Taira form: `QC_FIXED` is the
    /// `QcFixed` cell and the `signers` field, `X` is its two cells, `σ` is compressed.
    struct Wire {
        qc: Vec<u8>,
        header: Vec<u8>,
        signature: Vec<u8>,
    }

    fn wire_of(row: &Value) -> Wire {
        let ton = field(row, "ton");
        let evm = field(row, "evm");
        let signers = u32::try_from(number(ton, "signers")).unwrap();
        let qc = [
            bytes(text(ton, "qc_fixed_cell")),
            signers.to_be_bytes().to_vec(),
        ]
        .concat();
        let header = [bytes(text(ton, "x_head")), bytes(text(ton, "x_tail"))].concat();
        // Both flavours carry the same `QC_FIXED` and `X`.
        assert_eq!(qc, bytes(text(evm, "qc")));
        assert_eq!(header, bytes(text(evm, "header")));
        Wire {
            qc,
            header,
            signature: bytes(text(ton, "signature")),
        }
    }

    /// The keys of the committee that signed the row.
    fn signing_keys(reference: &Value, row: &Value) -> Vec<[u8; KEY_LEN]> {
        keys(
            field(field(reference, "committees"), text(row, "committee")),
            "keys",
        )
    }

    /// The destination of a row: its committee state right after deployment with the row's
    /// pin, and the keys of the pinned root as a TON destination stores them.
    fn pinned(reference: &Value, row: &Value) -> (CommitteeStateV1, Vec<[u8; KEY_LEN]>) {
        let pin = field(row, "pin");
        let root = word(pin, "committee_root");
        let state = CommitteeStateV1::from_pin(
            number(pin, "generation"),
            root,
            number(pin, "start_height"),
            number(pin, "until_ms"),
        )
        .unwrap();
        let stored = if pin.get("keys").is_some() {
            keys(pin, "keys")
        } else {
            field(reference, "committees")
                .as_object()
                .expect("committees by name")
                .values()
                .find(|committee| word(committee, "root") == root)
                .map(|committee| keys(committee, "keys"))
                .expect("a pin names a committee of the file")
        };
        assert_eq!(committee_root(&stored), Some(root));
        (state, stored)
    }

    /// The checks of §5.1.3 steps 2 and 3 that lie outside the relation: the network
    /// identity, the `ACTIVE` flag and the classification as CUR.
    fn destination_refusal(
        reference: &Value,
        state: &CommitteeStateV1,
        header: &[u8],
        now_ms: u64,
    ) -> Option<&'static str> {
        let network = word(field(reference, "verification_context"), "taira_network_id");
        // Every row is presented to a live destination.
        assert!(state.is_live(now_ms));
        let Ok(header) = SccpFinalityHeaderV1::parse(header) else {
            return Some("BadHeader");
        };
        if header.network_id() != network || !header.is_active() {
            return Some("BadHeader");
        }
        (!state.is_current(&header)).then_some("CommitteeNotAccepted")
    }

    /// The outcome of the relation on an EVM destination.
    fn outcome(result: &Result<VerifiedCertificateV1, CertificateError>) -> &'static str {
        match result {
            Ok(_) => "ok",
            Err(error) => error.destination_error().name(),
        }
    }

    /// The outcome of the relation on a TON destination.
    fn ton_relation_outcome(
        result: &Result<VerifiedCertificateV1, CertificateError>,
    ) -> &'static str {
        match result {
            Ok(_) => "ok",
            Err(error) => error.ton_destination_error().name(),
        }
    }

    fn instance_of(reference: &Value) -> [u8; 32] {
        word(
            field(reference, "verification_context"),
            "consensus_instance",
        )
    }

    /// `VerifyCertificate` steps 1–12 of a TON destination freshly deployed with the row's
    /// pin: the destination's own checks, then the relation over the stored keys.
    fn ton_outcome(reference: &Value, row: &Value) -> &'static str {
        let wire = wire_of(row);
        // Step 1: exact lengths, in the order `QC_FIXED`, `X`, signature.
        if wire.qc.len() != QC_FIXED_LEN {
            return "BadCertificate";
        }
        if wire.header.len() != X_LEN {
            return "BadHeader";
        }
        let Ok(signature) = <[u8; SIGNATURE_LEN]>::try_from(wire.signature) else {
            return "BadCertificate";
        };
        let (state, stored) = pinned(reference, row);
        let now_ms = number(row, "now_ms");
        if let Some(refusal) = destination_refusal(reference, &state, &wire.header, now_ms) {
            return refusal;
        }
        ton_relation_outcome(&verify_certificate(
            &instance_of(reference),
            &wire.qc,
            &wire.header,
            &signature,
            &stored,
        ))
    }

    /// `VerifyCertificate` steps 1–12 of an EVM destination freshly deployed with the row's
    /// pin: the committee and each signer's `y` come from calldata, and `σ` is four limbs.
    fn evm_outcome(reference: &Value, row: &Value) -> &'static str {
        let evm = field(row, "evm");
        let qc = bytes(text(evm, "qc"));
        let header = bytes(text(evm, "header"));
        // Step 1: exact lengths.
        if qc.len() != QC_FIXED_LEN {
            return "BadCertificate";
        }
        if header.len() != X_LEN {
            return "BadHeader";
        }
        let Ok(limbs) = <[u8; EVM_SIGNATURE_LEN]>::try_from(bytes(text(evm, "signature"))) else {
            return "BadCertificate";
        };
        let Some(committee) = committee_keys(&bytes(text(evm, "committee"))) else {
            return "BadCommittee";
        };
        let signer_ys = bytes(text(evm, "signerYs"));
        let (ys, rest) = signer_ys.as_chunks::<FP_LEN>();
        if !rest.is_empty() || Some(ys.len()) != quorum(committee.len()) {
            return "BadCertificate";
        }
        // Steps 2 and 3.
        let (state, _) = pinned(reference, row);
        let now_ms = number(row, "now_ms");
        if let Some(refusal) = destination_refusal(reference, &state, &header, now_ms) {
            return refusal;
        }
        // Step 4: the calldata committee is the current one.
        if committee_root(&committee) != Some(state.root) {
            return "BadCommittee";
        }
        // Step 5.
        let signers = QcFixedV1::parse(&qc).unwrap().signers;
        if let Err(error) = check_signers(signers, committee.len()) {
            return error.destination_error().name();
        }
        let indices = signer_indices(signers, committee.len()).unwrap();
        // Step 6: encodings, in this order, before the cheap path and before any curve
        // operation. `σ` is not the identity; every signer `y` is below `p`; every limb of
        // `σ` is below `p`; every signer key has its flags, an `x` below `p` and coordinates
        // other than `(0, 0)`.
        if limbs == IDENTITY_SIGNATURE_EVM {
            return "BadSignature";
        }
        if !ys.iter().all(fp_is_canonical) {
            return "BadCommittee";
        }
        let signature = signature_from_evm192(&limbs);
        if signature == Err(PointFormError::NotReduced) {
            return "BadSignature";
        }
        let signer_points = || indices.iter().map(|index| &committee[*index]).zip(ys);
        if !signer_points().all(|(key, y)| {
            signer_key_flags_match(key, y) && signer_coordinates_name_a_finite_point(key, y)
        }) {
            return "BadCommittee";
        }
        // Step 10: every signer point is on the curve, and their sum is not the identity.
        if !signer_points().all(|(key, y)| signer_point_is_on_curve(key, y)) {
            return "BadCommittee";
        }
        if signer_point_sum(&committee, signers) == Some(IDENTITY_KEY) {
            return "BadCommittee";
        }
        // Step 11: `σ` is a point; the relation checks the subgroups and the pairing, over the
        // aggregate key as the precompile does.
        let Ok(signature) = signature else {
            return "BadSignature";
        };
        outcome(&verify_certificate_by_aggregate(
            &instance_of(reference),
            &qc,
            &header,
            &signature,
            &committee,
        ))
    }

    /// A committee of four keys made by `iroha_crypto`, in canonical order.
    fn rust_committee() -> Vec<([u8; KEY_LEN], PrivateKey)> {
        let mut members: Vec<([u8; KEY_LEN], PrivateKey)> = (0_u8..4)
            .map(|index| {
                let pair =
                    KeyPair::from_seed(vec![b's', b'c', b'c', b'p', index], Algorithm::BlsNormal);
                let (public, private) = pair.into_parts();
                let (algorithm, raw) = public.to_bytes();
                assert_eq!(algorithm, Algorithm::BlsNormal);
                (<[u8; KEY_LEN]>::try_from(raw).unwrap(), private)
            })
            .collect();
        members.sort_by(|left, right| left.0.cmp(&right.0));
        members
    }

    /// A certificate of `header` by the members that `signers` names, with each share made
    /// by `sign`.
    fn certify(
        members: &[([u8; KEY_LEN], PrivateKey)],
        header: &SccpFinalityHeaderV1,
        signers: u32,
        sign: impl Fn(&PrivateKey, &[u8; COMMIT_PREIMAGE_LEN]) -> [u8; SIGNATURE_LEN],
    ) -> ([u8; QC_FIXED_LEN], [u8; SIGNATURE_LEN]) {
        let qc = QcFixedV1 {
            signers,
            ..qc_example()
        };
        let result = outer_result(header, &qc.result_body).0;
        let preimage = commit_preimage(&INSTANCE, &qc, header.height(), &result);
        let shares: Vec<[u8; SIGNATURE_LEN]> = signer_indices(signers, members.len())
            .unwrap()
            .into_iter()
            .map(|index| sign(&members[index].1, &preimage))
            .collect();
        (qc.encode(), aggregate(shares).unwrap())
    }

    fn consensus_share(
        key: &PrivateKey,
        preimage: &[u8; COMMIT_PREIMAGE_LEN],
    ) -> [u8; SIGNATURE_LEN] {
        sign_preimage(key, preimage).unwrap()
    }

    /// A header certified by `members`' own committee root.
    fn rust_header(members: &[([u8; KEY_LEN], PrivateKey)]) -> SccpFinalityHeaderV1 {
        let member_keys: Vec<[u8; KEY_LEN]> = members.iter().map(|member| member.0).collect();
        header_of(&SccpFinalityHeaderFieldsV1 {
            committee_root: committee_root(&member_keys).expect("four keys have a root"),
            ..rotation_example()
        })
    }

    #[test]
    fn layout_constants_are_pinned() {
        assert_eq!(QC_FIXED_LEN, 116);
        assert_eq!(COMMIT_PREIMAGE_LEN, 165);
        assert_eq!(X_LEN, 221);
        assert_eq!((X_HEAD_LEN, X_TAIL_LEN), (109, 112));
        assert_eq!(X_MAGIC, b"SCCP/FINALITY/V1");
        assert_eq!(TAG_SIG, b"sumeragi/sig");
        assert_eq!(TAG_SIG, preimage::TAG_SIG);
        assert_eq!(KIND_COMMIT, 0x03);
        assert_eq!(KIND_COMMIT, preimage::KIND_COMMIT);
        assert_eq!(RESULT_TAG, b"iroha/sumeragi/result/v1");
        assert_eq!(RESULT_BODY_TAG, b"iroha/sumeragi/result-body/v1");
        assert_eq!(MAX_RESULT_PREIMAGE_BYTES, 65_536);
        assert_eq!(MAX_RESULT_BODY_BYTES, 65_315);
        assert_eq!(MAX_VALIDITY_MS, 2_592_000_000);
        assert_eq!(MAX_HISTORY_SIZE, 1 << 32);
        assert_eq!((FLAG_ACTIVE, FLAG_ROTATION), (0x01, 0x02));
        assert_eq!(&DST_SIG[..], b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
        assert_eq!(DST_SIG.len(), 43);

        // The same constants as the reference file states them.
        let reference = finality();
        let constants = field(&reference, "constants");
        for (name, value) in [
            ("x_len", X_LEN),
            ("x_head_len", X_HEAD_LEN),
            ("x_tail_len", X_TAIL_LEN),
            ("qc_fixed_len", QC_FIXED_LEN),
            ("commit_preimage_len", COMMIT_PREIMAGE_LEN),
        ] {
            assert_eq!(
                usize::try_from(number(constants, name)),
                Ok(value),
                "{name}"
            );
        }
        for (name, tag) in [
            ("x_magic", X_MAGIC),
            ("result_tag", RESULT_TAG),
            ("result_body_tag", RESULT_BODY_TAG),
            ("tag_sig", TAG_SIG),
            ("dst_sig", &DST_SIG[..]),
        ] {
            let row = field(constants, name);
            assert_eq!(text(row, "ascii").as_bytes(), tag, "{name}");
            assert_eq!(bytes(text(row, "hex")), tag, "{name}");
        }
        assert_eq!(number(constants, "max_validity_ms"), MAX_VALIDITY_MS);
        // Wide integers are decimal strings in the file.
        assert_eq!(
            text(constants, "max_history_size"),
            MAX_HISTORY_SIZE.to_string()
        );
        assert_eq!(
            usize::try_from(number(field(constants, "dst_sig"), "len")),
            Ok(DST_SIG.len())
        );
    }

    #[test]
    fn qc_fixed_layout_and_spec_example() {
        let qc = qc_example();
        let encoded = qc.encode();
        // §11.2: `0000000000000002 88…88 0000000000000001 99…99 66…66 40000201`.
        let spelled = [
            "0000000000000002",
            &"88".repeat(32),
            "0000000000000001",
            &"99".repeat(32),
            &"66".repeat(32),
            "40000201",
        ]
        .concat();
        assert_eq!(hex(&encoded), spelled);
        assert_eq!(QcFixedV1::parse(&encoded), Ok(qc));

        // Every field sits at its offset of the §3.7 table.
        let distinct = QcFixedV1 {
            epoch: 0x0102_0304_0506_0708,
            epoch_context: [0xa1; 32],
            view: 0x1112_1314_1516_1718,
            block_hash: [0xb2; 32],
            result_body: [0xc3; 32],
            signers: 0x2122_2324,
        };
        let raw = distinct.encode();
        assert_eq!(raw[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(raw[8..40], [0xa1; 32]);
        assert_eq!(
            raw[40..48],
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
        assert_eq!(raw[48..80], [0xb2; 32]);
        assert_eq!(raw[80..112], [0xc3; 32]);
        assert_eq!(raw[112..], [0x21, 0x22, 0x23, 0x24]);
        assert_eq!(QcFixedV1::parse(&raw), Ok(distinct));

        // Any other length is refused: truncation, a trailing byte, and the retired
        // extension byte between `block_hash` and `result_body`.
        assert_eq!(
            QcFixedV1::parse(&encoded[..115]),
            Err(CertificateError::QcFixedLength)
        );
        let trailing = [&encoded[..], &[0]].concat();
        assert_eq!(
            QcFixedV1::parse(&trailing),
            Err(CertificateError::QcFixedLength)
        );
        let extended = [&encoded[..80], &[1], &encoded[80..]].concat();
        assert_eq!(extended.len(), 117);
        assert_eq!(
            QcFixedV1::parse(&extended),
            Err(CertificateError::QcFixedLength)
        );
        assert_eq!(QcFixedV1::parse(&[]), Err(CertificateError::QcFixedLength));

        let reference = finality();
        let example = field(field(&reference, "worked_examples"), "qc_fixed");
        assert_eq!(qc_of(field(example, "fields")), qc);
        assert_eq!(encoded[..], bytes(text(example, "encoded"))[..]);
    }

    #[test]
    fn signers_are_lsb_first_and_raw_bitmap_is_rejected_value() {
        // §3.7: n = 31, indices {0, 9, 30}.
        let bitmap = [0x01, 0x02, 0x00, 0x40];
        assert_eq!(signers_from_bitmap(&bitmap, 31), Some(0x4000_0201));
        assert_eq!(0x4000_0201_u32.to_be_bytes(), [0x40, 0x00, 0x02, 0x01]);
        assert_eq!(
            bitmap_from_signers(0x4000_0201, 31).as_deref(),
            Some(&bitmap[..])
        );
        assert_eq!(signer_indices(0x4000_0201, 31), Some(vec![0, 9, 30]));
        // Copying the bitmap bytes raw gives another signer set: the negative vector.
        let raw = u32::from_be_bytes(bitmap);
        assert_eq!(raw, 0x0102_0040);
        assert_ne!(signers_from_bitmap(&bitmap, 31), Some(raw));
        assert_eq!(signer_indices(raw, 31), Some(vec![6, 17, 24]));

        // The core bitmap type agrees bit for bit.
        let core = Bitmap::from_indices(31, [0, 9, 30]).unwrap();
        assert_eq!(core.as_bytes(), bitmap);
        for n in 1..=31_usize {
            for signers in [
                0,
                1,
                1 << (n - 1),
                (1_u32 << n) - 1,
                0x5555_5555 & ((1 << n) - 1),
            ] {
                let bytes = bitmap_from_signers(signers, n).unwrap();
                assert_eq!(bytes.len(), n.div_ceil(8));
                assert_eq!(signers_from_bitmap(&bytes, n), Some(signers));
                let core = Bitmap::from_bytes(bytes);
                assert!(core.is_well_formed(n));
                let ones: Vec<usize> = core
                    .ones()
                    .map(|index| usize::try_from(index).unwrap())
                    .collect();
                assert_eq!(Some(ones), signer_indices(signers, n));
            }
            // A bit at index n is a spare bit in both directions.
            assert_eq!(bitmap_from_signers(1 << n, n), None);
        }

        // Wrong lengths, spare bits and sizes without a `signers` field.
        assert_eq!(signers_from_bitmap(&[0x07], 4), Some(7));
        assert_eq!(signers_from_bitmap(&[0x17], 4), None);
        assert_eq!(signers_from_bitmap(&[0x07, 0x00], 4), None);
        assert_eq!(signers_from_bitmap(&[], 4), None);
        assert_eq!(
            signers_from_bitmap(&[0xff, 0xff, 0xff, 0x7f], 31),
            Some(0x7fff_ffff)
        );
        assert_eq!(signers_from_bitmap(&[0xff, 0xff, 0xff, 0xff], 31), None);
        assert_eq!(signers_from_bitmap(&[], 0), None);
        assert_eq!(signers_from_bitmap(&[0; 4], 32), None);
        assert_eq!(signers_from_bitmap(&[0; 5], 33), None);
        assert_eq!(bitmap_from_signers(0, 0), None);
        assert_eq!(bitmap_from_signers(1, 32), None);

        let reference = finality();
        let example = field(field(&reference, "worked_examples"), "qc_fixed");
        assert_eq!(bytes(text(example, "bitmap")), bitmap);
        assert_eq!(
            text(example, "raw_bitmap_signers_negative"),
            format!("{raw:#x}")
        );
        for row in rows(&reference, "signer_encodings") {
            let label = text(row, "label");
            let n = usize::try_from(number(row, "n")).unwrap();
            let signers = u32::try_from(number(row, "signers")).unwrap();
            let bitmap = bytes(text(row, "bitmap"));
            assert_eq!(signers_from_bitmap(&bitmap, n), Some(signers), "{label}");
            assert_eq!(
                bitmap_from_signers(signers, n),
                Some(bitmap.clone()),
                "{label}"
            );
            assert_eq!(
                signers.to_be_bytes()[..],
                bytes(text(row, "signers_be32"))[..],
                "{label}"
            );
            let indices: Vec<usize> = rows(row, "indices")
                .iter()
                .map(|index| usize::try_from(index.as_u64().unwrap()).unwrap())
                .collect();
            assert_eq!(signer_indices(signers, n), Some(indices), "{label}");
            // The misreading is pinned where the bitmap has more than one byte.
            if let Some(misreading) = field(row, "raw_bitmap_misreading").as_str() {
                let raw = bitmap
                    .iter()
                    .fold(0_u32, |raw, byte| (raw << 8) | u32::from(*byte));
                assert_eq!(misreading, format!("{raw:#x}"), "{label}");
            } else {
                assert_eq!(bitmap.len(), 1, "{label}");
            }
        }
    }

    #[test]
    fn commit_preimage_is_165_bytes_and_equals_core_vote_preimage() {
        let qc = qc_example();
        let result = outer_result(&header_of(&rotation_example()), &qc.result_body).0;
        let preimage = commit_preimage(&INSTANCE, &qc, 7200, &result);
        assert_eq!(preimage.len(), 165);
        // The layout, field by field.
        assert_eq!(&preimage[..12], b"sumeragi/sig");
        assert_eq!(preimage[12], 0x03);
        assert_eq!(preimage[13..45], INSTANCE);
        assert_eq!(preimage[45..53], 2_u64.to_be_bytes());
        assert_eq!(preimage[53..85], [0x88; 32]);
        assert_eq!(preimage[85..93], 7200_u64.to_be_bytes());
        assert_eq!(preimage[93..101], 1_u64.to_be_bytes());
        assert_eq!(preimage[101..133], [0x99; 32]);
        assert_eq!(preimage[133..], result);

        // The Sumeragi core builds the same bytes for a Commit vote, and other bytes for a
        // Prepare vote.
        let core = |kind, qc: &QcFixedV1, height, result: &[u8; 32]| {
            vote_preimage(
                kind,
                &Hash32(INSTANCE),
                &EpochId {
                    epoch: qc.epoch,
                    context: Hash32(qc.epoch_context),
                },
                height,
                qc.view,
                &Hash32(qc.block_hash),
                &Hash32(*result),
            )
        };
        assert_eq!(core(VoteKind::Commit, &qc, 7200, &result), preimage);
        assert_ne!(core(VoteKind::Prepare, &qc, 7200, &result), preimage);
        let distinct = QcFixedV1 {
            epoch: 0x0102_0304_0506_0708,
            epoch_context: [0xa1; 32],
            view: 0x1112_1314_1516_1718,
            block_hash: [0xb2; 32],
            result_body: [0xc3; 32],
            signers: 7,
        };
        for height in [1, 7200, u64::MAX] {
            assert_eq!(
                core(VoteKind::Commit, &distinct, height, &[0xd4; 32]),
                commit_preimage(&INSTANCE, &distinct, height, &[0xd4; 32])
            );
        }
        // `result_body` and `signers` enter `P` only through `R` and the signer set.
        let other = QcFixedV1 {
            result_body: [0; 32],
            signers: 0,
            ..qc
        };
        assert_eq!(commit_preimage(&INSTANCE, &other, 7200, &result), preimage);
        assert_ne!(commit_preimage(&[0x78; 32], &qc, 7200, &result), preimage);
        assert_ne!(commit_preimage(&INSTANCE, &qc, 7201, &result), preimage);

        // The consensus allowlist admits exactly this layout.
        let digest = ConsensusDigest::from_preimage(&preimage).unwrap();
        assert_eq!(*digest.as_bytes(), commit_message(&preimage));
        assert!(ConsensusDigest::from_preimage(&preimage[..164]).is_none());

        let reference = finality();
        let example = field(field(&reference, "worked_examples"), "commit");
        assert_eq!(word(example, "instance"), INSTANCE);
        assert_eq!(number(example, "height"), 7200);
        assert_eq!(word(example, "r"), result);
        assert_eq!(preimage[..], bytes(text(example, "preimage"))[..]);
    }

    #[test]
    fn commit_message_matches_spec_m() {
        let qc = qc_example();
        let result = outer_result(&header_of(&rotation_example()), &qc.result_body).0;
        assert_eq!(
            hex(&result),
            "3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7"
        );
        let message = commit_message(&commit_preimage(&INSTANCE, &qc, 7200, &result));
        assert_eq!(
            hex(&message),
            "85c684fac5aab78b197a5e2d40329ec518bc038abd99974a37064ea26e4943e0"
        );
        let reference = finality();
        let example = field(field(&reference, "worked_examples"), "commit");
        assert_eq!(word(example, "m"), message);
    }

    #[test]
    fn checkpoint_id_matches_spec() {
        let expected = [
            (
                rotation_example(),
                "b0a93737e03cec3ff52c920efa7db18859883ecb598ff7bdd2bf19f67c1086f6",
            ),
            (
                heartbeat_example(),
                "0ae4bff13d50fc7129b3fcd5926df55d5da6afc8a33445abed1a1a7e650537a4",
            ),
            (
                non_rotation_example(),
                "2d519a8ba8b000583ee3d0e6ec06843d95c3f7de32bf5ff9a76e6fad0fbbda6c",
            ),
        ];
        for (fields, id) in expected {
            let header = header_of(&fields);
            assert_eq!(hex(&checkpoint_id(header.as_bytes())), id);
            assert_eq!(
                checkpoint_id(header.as_bytes()),
                keccak256(&[header.as_bytes()])
            );
        }
        // The id is over the bytes: it needs no valid header.
        assert_eq!(checkpoint_id(&[0; X_LEN]), keccak256(&[&[0; X_LEN]]));

        let reference = finality();
        let cases = field(field(&reference, "worked_examples"), "cases");
        for (name, fields) in [
            ("rotation", rotation_example()),
            ("heartbeat", heartbeat_example()),
            ("non_rotation", non_rotation_example()),
        ] {
            let case = field(cases, name);
            let header = header_of(&fields);
            assert_eq!(header_fields_of(field(case, "fields")), fields, "{name}");
            assert_eq!(header.as_bytes()[..], bytes(text(case, "x"))[..], "{name}");
            assert_eq!(
                checkpoint_id(header.as_bytes()),
                word(case, "checkpoint_id"),
                "{name}"
            );
            assert_eq!(
                outer_result(&header, &word(case, "d_body")).0,
                word(case, "r"),
                "{name}"
            );
        }
        for row in rows(field(&reference, "headers"), "valid") {
            let raw = bytes(text(row, "x"));
            let header = SccpFinalityHeaderV1::parse(&raw).unwrap();
            assert_eq!(
                checkpoint_id(header.as_bytes()),
                word(row, "checkpoint_id"),
                "{}",
                text(row, "label")
            );
        }
    }

    /// §11.2: every case with its `X` bytes and its `R`, through the header and result
    /// functions this module re-exports.
    #[test]
    fn worked_examples_pin_x_and_r_of_every_case() {
        let inactive = SccpFinalityHeaderV1::inactive([0x11; 32], 9, T0).unwrap();
        let cases = [
            (
                "rotation",
                header_of(&rotation_example()),
                "3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7",
            ),
            (
                "heartbeat",
                header_of(&heartbeat_example()),
                "ec15d2c034f21de8f6a6192bd246d5ee7acf99ae452c7a70f7c6003b567b1ed4",
            ),
            (
                "non_rotation",
                header_of(&non_rotation_example()),
                "93d642e5cd5e489a395a937a88c63834fceaa8db9ef267e600f70ba58027c9ac",
            ),
            (
                "inactive",
                inactive,
                "541b29c5e6058adb34edef96855cb321fdcdc635fc92e4ac25777d1b3ea07b1a",
            ),
        ];
        let reference = finality();
        let table = field(field(&reference, "worked_examples"), "cases");
        assert_eq!(table.as_object().expect("cases by name").len(), cases.len());
        for (name, header, r) in cases {
            // `D_body = 0x66^32` in every case.
            let result = outer_result(&header, &[0x66; 32]).0;
            assert_eq!(hex(&result), r, "{name}");
            let case = field(table, name);
            assert_eq!(
                header.fields(),
                header_fields_of(field(case, "fields")),
                "{name}"
            );
            assert_eq!(header.as_bytes()[..], bytes(text(case, "x"))[..], "{name}");
            assert_eq!(word(case, "d_body"), [0x66; 32], "{name}");
            assert_eq!(word(case, "r"), result, "{name}");
            // The table gives a checkpoint id to the headers a destination can store.
            assert_eq!(
                case.get("checkpoint_id").is_some(),
                header.is_active(),
                "{name}"
            );
        }

        // The `X` bytes the spec spells out.
        let rotation = [
            "534343502f46494e414c4954592f5631",
            &"11".repeat(32),
            "0000000000001c20",
            "000001a0c4506c00",
            "03",
            "00000002",
            &"22".repeat(32),
            "0000000000000005",
            &"33".repeat(32),
            "0000000000000003",
            &"44".repeat(32),
            "0000000048190800",
            &"55".repeat(32),
        ]
        .concat();
        assert_eq!(hex(header_of(&rotation_example()).as_bytes()), rotation);
        let non_rotation = [
            "534343502f46494e414c4954592f5631",
            &"11".repeat(32),
            "0000000000001c1f",
            "000001a0c4506818",
            "01",
            "00000002",
            &"22".repeat(32),
            "0000000000000005",
            &"33".repeat(32),
            "0000000000000003",
            &"44".repeat(32),
            "0000000000000000",
            &"00".repeat(32),
        ]
        .concat();
        assert_eq!(
            hex(header_of(&non_rotation_example()).as_bytes()),
            non_rotation
        );
        // The inactive form: magic ‖ network_id ‖ be64(h) ‖ be64(t(h)) ‖ 0x00 ‖ 0^156.
        let raw = inactive.as_bytes();
        assert_eq!(raw[..16], *X_MAGIC);
        assert_eq!(raw[16..48], [0x11; 32]);
        assert_eq!(raw[48..56], 9_u64.to_be_bytes());
        assert_eq!(raw[56..64], T0.to_be_bytes());
        assert_eq!(raw[64..], [0; 157]);
        assert!(!inactive.is_active() && !inactive.is_rotation());
    }

    /// Every header row of the reference, through the relation: an invalid `X` is refused
    /// with the first violated check of §3.6, which a destination reports as `BadHeader`,
    /// and a valid `X` passes the header checks whatever its flags.
    #[test]
    fn verify_certificate_reports_the_header_check_of_every_reference_header() {
        let reference = finality();
        let instance = instance_of(&reference);
        let network = word(
            field(&reference, "verification_context"),
            "taira_network_id",
        );
        let committee = keys(field(field(&reference, "committees"), "n4"), "keys");
        // A quorum-shaped `QC_FIXED` and the genuine signature of another certificate: the
        // header is all that differs between the rows.
        let qc = QcFixedV1 {
            signers: 0b0111,
            ..qc_example()
        }
        .encode();
        let donor = wire_of(&rows(&reference, "certificates")[0]);
        let signature = <[u8; SIGNATURE_LEN]>::try_from(donor.signature).unwrap();
        let verify = |x: &[u8]| verify_certificate(&instance, &qc, x, &signature, &committee);
        let headers = field(&reference, "headers");

        let (mut active, mut inactive, mut rotations) = (0, 0, 0);
        for row in rows(headers, "valid") {
            let label = text(row, "label");
            let x = bytes(text(row, "x"));
            let header =
                SccpFinalityHeaderV1::parse(&x).unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(
                header.fields(),
                header_fields_of(field(row, "fields")),
                "{label}"
            );
            assert_eq!(
                SccpFinalityHeaderV1::from_fields(&header.fields()),
                Ok(header),
                "{label}"
            );
            // TON carries `X` as two cells, split at offset 109.
            assert_eq!(header.head()[..], bytes(text(row, "x_head"))[..], "{label}");
            assert_eq!(header.tail()[..], bytes(text(row, "x_tail"))[..], "{label}");
            assert_eq!(
                field(row, "active").as_bool(),
                Some(header.is_active()),
                "{label}"
            );
            assert_eq!(
                field(row, "rotation").as_bool(),
                Some(header.is_rotation()),
                "{label}"
            );
            // The relation gets past the header: the signature is what it refuses.
            assert_eq!(verify(&x), Err(CertificateError::Signature), "{label}");
            // A destination also requires its own network and `ACTIVE` (§5.1.3 step 2).
            let destination = if header.network_id() == network && header.is_active() {
                "accept"
            } else {
                "BadHeader"
            };
            assert_eq!(text(row, "destination"), destination, "{label}");
            if header.is_active() {
                active += 1;
            } else {
                inactive += 1;
            }
            rotations += usize::from(header.is_rotation());
        }
        assert!(
            active >= 6 && inactive >= 2 && rotations >= 3,
            "{active} active, {inactive} inactive, {rotations} rotations"
        );

        let mut seen = std::collections::BTreeSet::new();
        for row in rows(headers, "invalid") {
            let label = text(row, "label");
            let x = bytes(text(row, "x"));
            let error = SccpFinalityHeaderV1::parse(&x).expect_err(label);
            assert_eq!(error.name(), text(row, "error"), "{label}");
            assert_eq!(verify(&x), Err(CertificateError::Header(error)), "{label}");
            assert_eq!(
                CertificateError::Header(error).destination_error().name(),
                text(row, "destination"),
                "{label}"
            );
            // Such an `X` has no `R` either, whatever body follows it.
            if x.len() == X_LEN {
                assert_eq!(
                    result_of_preimage(&[&x[..], &[0x01]].concat()),
                    None,
                    "{label}"
                );
            } else {
                assert_eq!(error, FinalityHeaderError::Length, "{label}");
            }
            seen.insert((error.name(), label));
        }
        // The length and each of X1–X7 occur.
        let names: std::collections::BTreeSet<&str> = seen.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            ["Length", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]
        );
        // X6 also refuses a rotation whose successor would have no start height or no
        // generation number.
        for label in ["rotation_at_max_height", "rotation_at_max_generation"] {
            assert!(
                seen.contains(&("X6", label)),
                "the reference lost `{label}`"
            );
        }
    }

    /// Every row of `result_of_preimage`: the stored preimage `X ‖ body` has the result
    /// `SHA-256(RESULT_TAG ‖ X ‖ H_iroha(RESULT_BODY_TAG ‖ body))`, or none when it is out of
    /// bounds or its `X` does not parse.
    #[test]
    fn result_of_preimage_matches_every_reference_row() {
        let reference = finality();
        let table = rows(&reference, "result_of_preimage");
        assert_eq!(text(&table[0], "label"), "one_byte_body");
        let first_x = bytes(text(&table[0], "preimage"))[..X_LEN].to_vec();
        let (mut with_result, mut without) = (0, 0);
        for row in table {
            let label = text(row, "label");
            let preimage = if row.get("preimage").is_some() {
                bytes(text(row, "preimage"))
            } else {
                // The two rows at the bound are spelled as a construction: the `X` of the
                // first row followed by zero bytes up to `preimage_len`.
                assert!(
                    text(row, "construction").contains("one_byte_body"),
                    "{label}"
                );
                let mut preimage = first_x.clone();
                preimage.resize(usize::try_from(number(row, "preimage_len")).unwrap(), 0);
                preimage
            };
            let result = result_of_preimage(&preimage).map(|result| result.0);
            if field(row, "r").is_null() {
                assert_eq!(result, None, "{label}");
                without += 1;
                continue;
            }
            assert_eq!(result, Some(word(row, "r")), "{label}");
            let (x, body) = preimage.split_at(X_LEN);
            let d_body = body_digest(body);
            assert_eq!(d_body, word(row, "d_body"), "{label}");
            let header = SccpFinalityHeaderV1::parse(x).unwrap();
            assert_eq!(outer_result(&header, &d_body).0, word(row, "r"), "{label}");
            with_result += 1;
        }
        // An active and an inactive `X`, the largest body, and the four refusals: a body one
        // byte too long, no body, a truncated `X` and an `X` that does not parse.
        assert!(
            with_result >= 4 && without >= 4,
            "{with_result} results, {without} refusals"
        );
        assert_eq!(MAX_RESULT_PREIMAGE_BYTES, X_LEN + MAX_RESULT_BODY_BYTES);
        let mut largest = first_x.clone();
        largest.resize(MAX_RESULT_PREIMAGE_BYTES, 0);
        assert!(result_of_preimage(&largest).is_some());
        largest.push(0);
        assert_eq!(result_of_preimage(&largest), None);
        assert_eq!(result_of_preimage(&first_x), None);
    }

    #[test]
    fn check_signers_requires_exact_quorum_for_every_committee_size() {
        for n in 0..=40_usize {
            let Some(q) = quorum(n) else {
                assert_eq!(check_signers(0, n), Err(CertificateError::CommitteeSize));
                assert_eq!(check_signers(7, n), Err(CertificateError::CommitteeSize));
                continue;
            };
            let lowest = (1_u32 << q) - 1;
            let highest = lowest << (n - q);
            let everyone = (1_u32 << n) - 1;
            assert_eq!(check_signers(lowest, n), Ok(()));
            assert_eq!(check_signers(highest, n), Ok(()));
            // One signer fewer, one more, and the whole committee: a superset is no quorum.
            assert_eq!(
                check_signers(lowest >> 1, n),
                Err(CertificateError::SignerCount)
            );
            assert_eq!(
                check_signers(lowest | (1 << q), n),
                Err(CertificateError::SignerCount)
            );
            assert_eq!(
                check_signers(everyone, n),
                Err(CertificateError::SignerCount)
            );
            assert_eq!(check_signers(0, n), Err(CertificateError::SignerCount));
            // A bit at index n, with a quorum-sized set, is a spare bit.
            assert_eq!(
                check_signers((lowest >> 1) | (1 << n), n),
                Err(CertificateError::SpareSignerBits)
            );
            assert_eq!(
                check_signers(lowest | 0x8000_0000, n),
                Err(CertificateError::SpareSignerBits)
            );
        }
    }

    #[test]
    fn verify_certificate_requires_exact_quorum_and_no_spare_bits() {
        let members = rust_committee();
        let member_keys: Vec<[u8; KEY_LEN]> = members.iter().map(|member| member.0).collect();
        let header = rust_header(&members);
        let verify = |signers: u32| {
            let (qc, signature) = certify(&members, &header, signers, consensus_share);
            verify_certificate(&INSTANCE, &qc, header.as_bytes(), &signature, &member_keys)
        };
        // q = 3 of n = 4: every quorum verifies.
        for signers in [0b0111, 0b1011, 0b1101, 0b1110] {
            let verified = verify(signers).unwrap();
            assert_eq!(verified.qc.signers, signers);
            assert_eq!(verified.header, header);
        }
        // Genuine signatures of q − 1 members and of the whole committee are refused.
        for signers in [0b0001, 0b0011, 0b0110, 0b1111] {
            assert_eq!(verify(signers), Err(CertificateError::SignerCount));
        }

        // A quorum's signature under a `signers` field with a spare bit.
        let (qc, signature) = certify(&members, &header, 0b0111, consensus_share);
        let with_signers = |signers: u32| {
            let qc = QcFixedV1 {
                signers,
                ..QcFixedV1::parse(&qc).unwrap()
            };
            verify_certificate(
                &INSTANCE,
                &qc.encode(),
                header.as_bytes(),
                &signature,
                &member_keys,
            )
        };
        assert!(with_signers(0b0111).is_ok());
        assert_eq!(
            with_signers(0b1_0011),
            Err(CertificateError::SpareSignerBits)
        );
        assert_eq!(
            with_signers(0x8000_0007),
            Err(CertificateError::SpareSignerBits)
        );
        // The right count of other members: the signature is not theirs.
        assert_eq!(with_signers(0b1110), Err(CertificateError::Signature));
    }

    #[test]
    fn verify_certificate_reports_the_first_failure_in_order() {
        let members = rust_committee();
        let member_keys: Vec<[u8; KEY_LEN]> = members.iter().map(|member| member.0).collect();
        let header = rust_header(&members);
        let x = header.as_bytes();
        let (qc, signature) = certify(&members, &header, 0b0111, consensus_share);
        let verified = verify_certificate(&INSTANCE, &qc, x, &signature, &member_keys).unwrap();
        let result = outer_result(&header, &[0x66; 32]).0;
        assert_eq!(
            verified,
            VerifiedCertificateV1 {
                header,
                qc: QcFixedV1::parse(&qc).unwrap(),
                result,
                message: commit_message(&commit_preimage(
                    &INSTANCE,
                    &QcFixedV1::parse(&qc).unwrap(),
                    header.height(),
                    &result
                )),
                checkpoint_id: checkpoint_id(x),
            }
        );

        // Wrong in every way at once, then one defect less each time.
        let five_keys = [&member_keys[..], &member_keys[..1]].concat();
        let spare = QcFixedV1 {
            signers: 0b1_0011,
            ..QcFixedV1::parse(&qc).unwrap()
        }
        .encode();
        let mut inactive_with_fields = *x;
        inactive_with_fields[64] = 0;
        assert_eq!(
            verify_certificate(&INSTANCE, &qc[..115], &x[..220], &signature, &five_keys),
            Err(CertificateError::QcFixedLength)
        );
        assert_eq!(
            verify_certificate(&INSTANCE, &spare, &x[..220], &signature, &five_keys),
            Err(CertificateError::Header(FinalityHeaderError::Length))
        );
        assert_eq!(
            verify_certificate(
                &INSTANCE,
                &spare,
                &inactive_with_fields,
                &signature,
                &five_keys
            ),
            Err(CertificateError::CommitteeSize)
        );
        assert_eq!(
            verify_certificate(
                &INSTANCE,
                &spare,
                &inactive_with_fields,
                &signature,
                &member_keys
            ),
            Err(CertificateError::Header(FinalityHeaderError::X2))
        );
        assert_eq!(
            verify_certificate(&INSTANCE, &spare, x, &signature, &member_keys),
            Err(CertificateError::SpareSignerBits)
        );
        // An empty committee and one below the smallest size.
        for count in [0, 3] {
            assert_eq!(
                verify_certificate(&INSTANCE, &qc, x, &signature, &member_keys[..count]),
                Err(CertificateError::CommitteeSize)
            );
        }

        // Step 7: a signer key that is not a valid key, and a signer set whose keys cancel.
        let mut identity = [0_u8; KEY_LEN];
        identity[0] = 0xc0;
        let mut with_identity = member_keys.clone();
        with_identity[1] = identity;
        assert_eq!(
            verify_certificate(&INSTANCE, &qc, x, &signature, &with_identity),
            Err(CertificateError::SignerKey)
        );
        assert_eq!(
            verify_certificate_by_aggregate(&INSTANCE, &qc, x, &signature, &with_identity),
            Err(CertificateError::SignerKey)
        );
        // The same key outside the signer set is never read.
        let mut unused_identity = member_keys.clone();
        unused_identity[3] = identity;
        assert!(verify_certificate(&INSTANCE, &qc, x, &signature, &unused_identity).is_ok());
        // Flipping the sign flag of a compressed point negates it, so the third key below is
        // −(PK_0 + PK_1) and the three signer keys sum to the identity.
        let mut negated_sum = aggregate_public_key(&member_keys, 0b0011).unwrap();
        negated_sum[0] ^= 0x20;
        let cancelling = [member_keys[0], member_keys[1], negated_sum, member_keys[3]];
        for relation in [verify_certificate, verify_certificate_by_aggregate] {
            assert_eq!(
                relation(&INSTANCE, &qc, x, &signature, &cancelling),
                Err(CertificateError::AggregateIdentity)
            );
            // Every key valid: the two forms of the relation are one.
            assert_eq!(
                relation(&INSTANCE, &qc, x, &signature, &member_keys),
                verify_certificate(&INSTANCE, &qc, x, &signature, &member_keys)
            );
        }
        assert!(
            verify_certificate_by_aggregate(&INSTANCE, &qc, x, &signature, &member_keys).is_ok()
        );

        // The identity signature is refused before the aggregate key is formed.
        for committee in [&member_keys[..], &with_identity[..], &cancelling[..]] {
            assert_eq!(
                verify_certificate(&INSTANCE, &qc, x, &IDENTITY_SIGNATURE, committee),
                Err(CertificateError::IdentitySignature)
            );
        }
        // Steps 8–9: everything else is the signature's fault.
        let mut flipped = signature;
        flipped[SIGNATURE_LEN - 1] ^= 1;
        for bad in [[0; SIGNATURE_LEN], flipped] {
            assert_eq!(
                verify_certificate(&INSTANCE, &qc, x, &bad, &member_keys),
                Err(CertificateError::Signature)
            );
        }
        assert_eq!(
            verify_certificate(&[0x78; 32], &qc, x, &signature, &member_keys),
            Err(CertificateError::Signature)
        );
        // Another `X`, another `result_body`, another view: each changes the signed message.
        let other_header = header_of(&SccpFinalityHeaderFieldsV1 {
            sccp_root: [0xee; 32],
            ..header.fields()
        });
        assert_eq!(
            verify_certificate(
                &INSTANCE,
                &qc,
                other_header.as_bytes(),
                &signature,
                &member_keys
            ),
            Err(CertificateError::Signature)
        );
        for change in [
            |qc: &mut QcFixedV1| qc.result_body = [0x67; 32],
            |qc: &mut QcFixedV1| qc.view += 1,
            |qc: &mut QcFixedV1| qc.epoch += 1,
            |qc: &mut QcFixedV1| qc.epoch_context[0] ^= 1,
            |qc: &mut QcFixedV1| qc.block_hash[31] ^= 1,
        ] {
            let mut changed = QcFixedV1::parse(&qc).unwrap();
            change(&mut changed);
            assert_eq!(
                verify_certificate(&INSTANCE, &changed.encode(), x, &signature, &member_keys),
                Err(CertificateError::Signature)
            );
        }
    }

    /// `σ = O` is refused as an encoding, where §5.1.3 step 6 places it on both flavours:
    /// after the signer set and before the aggregate key and the pairing.
    #[test]
    fn verify_certificate_rejects_the_identity_signature_explicitly() {
        let members = rust_committee();
        let member_keys: Vec<[u8; KEY_LEN]> = members.iter().map(|member| member.0).collect();
        let header = rust_header(&members);
        let x = header.as_bytes();
        let (qc, signature) = certify(&members, &header, 0b0111, consensus_share);
        let verify = |qc: &[u8], sigma: &[u8; SIGNATURE_LEN]| {
            verify_certificate(&INSTANCE, qc, x, sigma, &member_keys)
        };
        assert!(verify(&qc, &signature).is_ok());

        // The two wire forms of the identity: 0xc0 then 95 zero bytes, and 192 zero bytes.
        assert_eq!(IDENTITY_SIGNATURE[0], 0xc0);
        assert_eq!(IDENTITY_SIGNATURE[1..], [0; SIGNATURE_LEN - 1]);
        assert_eq!(
            signature_to_evm192(&IDENTITY_SIGNATURE),
            Some(IDENTITY_SIGNATURE_EVM)
        );
        assert_eq!(
            signature_from_evm192(&IDENTITY_SIGNATURE_EVM),
            Ok(IDENTITY_SIGNATURE)
        );
        assert_eq!(IDENTITY_SIGNATURE_EVM, [0; EVM_SIGNATURE_LEN]);
        assert_eq!(
            verify(&qc, &IDENTITY_SIGNATURE),
            Err(CertificateError::IdentitySignature)
        );
        assert_eq!(
            CertificateError::IdentitySignature.destination_error(),
            DestinationError::BadSignature
        );

        // The signer set is checked first.
        let spare = QcFixedV1 {
            signers: 0b1_0011,
            ..QcFixedV1::parse(&qc).unwrap()
        };
        assert_eq!(
            verify(&spare.encode(), &IDENTITY_SIGNATURE),
            Err(CertificateError::SpareSignerBits)
        );
        let short = QcFixedV1 {
            signers: 0b0011,
            ..QcFixedV1::parse(&qc).unwrap()
        };
        assert_eq!(
            verify(&short.encode(), &IDENTITY_SIGNATURE),
            Err(CertificateError::SignerCount)
        );

        // Only the canonical identity is this refusal. Its neighbours are not encodings of
        // any point, which the signature check answers.
        let mut trailing_bit = IDENTITY_SIGNATURE;
        trailing_bit[SIGNATURE_LEN - 1] = 1;
        let mut with_sign_flag = IDENTITY_SIGNATURE;
        with_sign_flag[0] |= 0x20;
        for other in [trailing_bit, with_sign_flag, [0; SIGNATURE_LEN]] {
            assert_eq!(verify(&qc, &other), Err(CertificateError::Signature));
        }

        // The reference row `sigma_zero` carries exactly these two forms, and both
        // destination flavours refuse it with `BadSignature`.
        let reference = finality();
        let row = rows(&reference, "negative_certificates")
            .iter()
            .find(|row| text(row, "label") == "sigma_zero")
            .expect("the reference row");
        let wire = wire_of(row);
        assert_eq!(wire.signature, IDENTITY_SIGNATURE);
        assert_eq!(
            bytes(text(field(row, "evm"), "signature")),
            IDENTITY_SIGNATURE_EVM
        );
        assert_eq!(
            verify_certificate(
                &instance_of(&reference),
                &wire.qc,
                &wire.header,
                &IDENTITY_SIGNATURE,
                &signing_keys(&reference, row)
            ),
            Err(CertificateError::IdentitySignature)
        );
        assert_eq!(evm_outcome(&reference, row), "BadSignature");
        assert_eq!(ton_outcome(&reference, row), "BadSignature");
    }

    /// The generic signing API of `iroha_crypto` keeps the w3f transcript, so its signature
    /// over the same message is never a consensus signature (`specs/sccp.md` §3.8).
    #[test]
    fn verify_certificate_rejects_a_w3f_transcript_signature() {
        let members = rust_committee();
        let member_keys: Vec<[u8; KEY_LEN]> = members.iter().map(|member| member.0).collect();
        let header = rust_header(&members);
        let over_the_message = |key: &PrivateKey, preimage: &[u8; COMMIT_PREIMAGE_LEN]| {
            let signature = Signature::new(key, &commit_message(preimage));
            <[u8; SIGNATURE_LEN]>::try_from(signature.payload()).unwrap()
        };
        let over_the_preimage = |key: &PrivateKey, preimage: &[u8; COMMIT_PREIMAGE_LEN]| {
            let signature = Signature::new(key, preimage);
            <[u8; SIGNATURE_LEN]>::try_from(signature.payload()).unwrap()
        };
        let (qc, genuine) = certify(&members, &header, 0b0111, consensus_share);
        assert!(
            verify_certificate(&INSTANCE, &qc, header.as_bytes(), &genuine, &member_keys).is_ok()
        );
        for (qc, foreign) in [
            certify(&members, &header, 0b0111, over_the_message),
            certify(&members, &header, 0b0111, over_the_preimage),
        ] {
            assert_ne!(foreign, genuine);
            assert_eq!(
                verify_certificate(&INSTANCE, &qc, header.as_bytes(), &foreign, &member_keys),
                Err(CertificateError::Signature)
            );
        }
    }

    #[test]
    fn verify_certificate_accepts_reference_positives() {
        let reference = finality();
        let instance = instance_of(&reference);
        let mut sizes = std::collections::BTreeSet::new();
        let (mut rotations, mut heartbeats) = (0, 0);
        for row in rows(&reference, "certificates") {
            let label = text(row, "label");
            let wire = wire_of(row);
            let signature = <[u8; SIGNATURE_LEN]>::try_from(&wire.signature[..]).unwrap();
            let committee = signing_keys(&reference, row);
            let verified =
                verify_certificate(&instance, &wire.qc, &wire.header, &signature, &committee)
                    .unwrap_or_else(|error| panic!("{label}: {error}"));

            // Everything the relation derives is what the reference derived.
            let qc = qc_of(field(row, "qc_fixed_fields"));
            assert_eq!(verified.qc, qc, "{label}");
            assert_eq!(qc.encode()[..], wire.qc[..], "{label}");
            assert_eq!(
                verified.header.fields(),
                header_fields_of(field(row, "header_fields")),
                "{label}"
            );
            assert_eq!(verified.result, word(row, "r"), "{label}");
            assert_eq!(verified.message, word(row, "m"), "{label}");
            assert_eq!(
                verified.checkpoint_id,
                word(row, "checkpoint_id"),
                "{label}"
            );
            assert_eq!(number(row, "commit_kind"), u64::from(KIND_COMMIT));
            assert_eq!(text(row, "dst").as_bytes(), &DST_SIG[..]);
            let preimage =
                commit_preimage(&instance, &qc, verified.header.height(), &verified.result);
            assert_eq!(preimage[..], bytes(text(row, "commit_preimage"))[..]);
            assert_eq!(commit_message(&preimage), verified.message);

            // The signer set, as a bitmap and as indices.
            let n = committee.len();
            assert_eq!(
                signers_from_bitmap(&bytes(text(row, "bitmap")), n),
                Some(qc.signers),
                "{label}"
            );
            assert_eq!(check_signers(qc.signers, n), Ok(()));

            // Both destination flavours accept it on a fresh deployment.
            let expected = field(row, "expected");
            assert_eq!((text(expected, "evm"), text(expected, "ton")), ("ok", "ok"));
            assert_eq!(evm_outcome(&reference, row), "ok", "{label}");
            assert_eq!(ton_outcome(&reference, row), "ok", "{label}");

            // Another instance, or a `result_body` the committee did not sign, is refused.
            assert_eq!(
                verify_certificate(&[0x78; 32], &wire.qc, &wire.header, &signature, &committee),
                Err(CertificateError::Signature),
                "{label}"
            );
            let other_body = QcFixedV1 {
                result_body: [0x01; 32],
                ..qc
            };
            assert_eq!(
                verify_certificate(
                    &instance,
                    &other_body.encode(),
                    &wire.header,
                    &signature,
                    &committee
                ),
                Err(CertificateError::Signature),
                "{label}"
            );

            sizes.insert(n);
            if verified.header.is_rotation() {
                rotations += 1;
                if verified.header.next_committee_root() == verified.header.committee_root() {
                    heartbeats += 1;
                }
            }
        }
        // n = 4, 7 and 31, a key change and a heartbeat (§11.3).
        assert_eq!(sizes.into_iter().collect::<Vec<_>>(), [4, 7, 31]);
        assert_eq!((rotations, heartbeats), (2, 1));
    }

    #[test]
    fn verify_certificate_rejects_reference_negatives() {
        let reference = finality();
        let instance = instance_of(&reference);
        let mut names = std::collections::BTreeSet::new();
        let (mut evm_rows, mut ton_rows) = (0, 0);
        for row in rows(&reference, "negative_certificates") {
            let label = text(row, "label");
            let expected = field(row, "expected");
            if let Some(name) = field(expected, "evm").as_str() {
                assert_ne!(name, "ok", "{label}");
                assert_eq!(evm_outcome(&reference, row), name, "{label} (EVM)");
                names.insert(name.to_owned());
                evm_rows += 1;
            }
            if let Some(name) = field(expected, "ton").as_str() {
                assert_ne!(name, "ok", "{label}");
                assert_eq!(ton_outcome(&reference, row), name, "{label} (TON)");
                names.insert(name.to_owned());
                ton_rows += 1;
            }

            // The relation alone, over the keys of the committee that signed the row. A row
            // about keys that are points but no valid keys is checked over the keys it pins.
            let wire = wire_of(row);
            let Ok(signature) = <[u8; SIGNATURE_LEN]>::try_from(&wire.signature[..]) else {
                continue;
            };
            let odd_keys = matches!(
                label,
                "signer_key_outside_g1"
                    | "aggregate_key_identity"
                    | "aggregate_key_identity_sigma_off_curve"
            );
            let relation_keys = if odd_keys {
                pinned(&reference, row).1
            } else {
                signing_keys(&reference, row)
            };
            let relation = verify_certificate(
                &instance,
                &wire.qc,
                &wire.header,
                &signature,
                &relation_keys,
            );
            if label == "signer_key_outside_g1" {
                // The key fails `KeyValidate`; an EVM destination sees the aggregate outside G1.
                assert_eq!(relation, Err(CertificateError::SignerKey));
                assert_eq!(
                    verify_certificate_by_aggregate(
                        &instance,
                        &wire.qc,
                        &wire.header,
                        &signature,
                        &relation_keys
                    ),
                    Err(CertificateError::AggregateSubgroup)
                );
            }
            match label {
                // Genuine certificates that only the destination's own checks refuse:
                // another network, an inactive `X`, another generation, another committee.
                "wrong_network"
                | "dirty_inactive_x"
                | "past_generation"
                | "foreign_committee_root" => {
                    assert!(relation.is_ok(), "{label}");
                }
                // An EVM-only row whose signer keys sum to the identity: both forms of the
                // relation refuse the aggregate.
                "aggregate_key_identity_sigma_off_curve" => {
                    assert_eq!(
                        relation,
                        Err(CertificateError::AggregateIdentity),
                        "{label}"
                    );
                }
                // Rows whose defect is in the EVM calldata only: the TON form is genuine.
                _ if field(expected, "ton").is_null() => {
                    assert!(relation.is_ok(), "{label}");
                }
                _ => {
                    let error = relation.expect_err(label);
                    assert_eq!(
                        Some(error.ton_destination_error().name()),
                        field(expected, "ton").as_str(),
                        "{label}"
                    );
                }
            }
        }
        // 50 rows: 17 exist on EVM only and 2 on TON only.
        assert!(
            evm_rows >= 48 && ton_rows >= 33,
            "{evm_rows} EVM, {ton_rows} TON"
        );
        // Every error name of §5.1.3 occurs.
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            [
                "BadCertificate",
                "BadCommittee",
                "BadHeader",
                "BadSignature",
                "CommitteeNotAccepted"
            ]
        );
    }

    /// Signer keys outside G1 whose odd components cancel: the aggregate is a valid key, so
    /// the EVM form of the relation accepts the genuine signature, and `KeyValidate` refuses
    /// each key.
    #[test]
    fn aggregate_relation_accepts_what_only_the_per_key_check_refuses() {
        let reference = finality();
        let instance = instance_of(&reference);
        let specific = rows(&reference, "flavor_specific_certificates");
        assert_eq!(specific.len(), 1);
        for row in specific {
            let label = text(row, "label");
            assert_eq!(label, "signer_keys_outside_g1_cancelling");
            let expected = field(row, "expected");
            assert_eq!(field(expected, "evm").as_str(), Some("ok"));
            assert!(field(expected, "ton").is_null());
            assert_eq!(evm_outcome(&reference, row), "ok", "{label} (EVM)");
            // The reference reads the TON opcode as `KeyValidate` on every key.
            assert_eq!(
                ton_outcome(&reference, row),
                "BadSignature",
                "{label} (TON)"
            );
            let wire = wire_of(row);
            let signature = <[u8; SIGNATURE_LEN]>::try_from(&wire.signature[..]).unwrap();
            let keys = pinned(&reference, row).1;
            let signers = QcFixedV1::parse(&wire.qc).unwrap().signers;
            let odd = signer_indices(signers, keys.len())
                .unwrap()
                .into_iter()
                .filter(|index| !key_validate(&keys[*index]))
                .count();
            assert_eq!(odd, 2);
            let aggregate = signer_point_sum(&keys, signers).unwrap();
            assert!(key_validate(&aggregate));
            assert_eq!(aggregate_public_key(&keys, signers), None);
            assert_eq!(
                verify_certificate(&instance, &wire.qc, &wire.header, &signature, &keys),
                Err(CertificateError::SignerKey)
            );
            let verified = verify_certificate_by_aggregate(
                &instance,
                &wire.qc,
                &wire.header,
                &signature,
                &keys,
            )
            .unwrap();
            assert_eq!(verified.message, word(row, "m"));
            // Under the aggregate key any other signature fails the pairing.
            let other = &rows(&reference, "certificates")[0];
            let foreign = <[u8; SIGNATURE_LEN]>::try_from(&wire_of(other).signature[..]).unwrap();
            assert_eq!(
                verify_certificate_by_aggregate(&instance, &wire.qc, &wire.header, &foreign, &keys),
                Err(CertificateError::Signature)
            );
        }
    }

    #[test]
    fn certificate_errors_name_their_destination_error() {
        let names = [
            (CertificateError::QcFixedLength, "BadCertificate"),
            (
                CertificateError::Header(FinalityHeaderError::X6),
                "BadHeader",
            ),
            (CertificateError::CommitteeSize, "BadCommittee"),
            (CertificateError::SpareSignerBits, "BadCertificate"),
            (CertificateError::SignerCount, "BadCertificate"),
            (CertificateError::IdentitySignature, "BadSignature"),
            (CertificateError::SignerKey, "BadSignature"),
            (CertificateError::AggregateIdentity, "BadCommittee"),
            (CertificateError::AggregateSubgroup, "BadSignature"),
            (CertificateError::Signature, "BadSignature"),
        ];
        for (error, name) in names {
            assert_eq!(error.destination_error().name(), name);
            assert!(!error.to_string().is_empty());
            // TON has one verdict for the keys, the aggregate and the signature.
            let ton = error.ton_destination_error();
            if error == CertificateError::AggregateIdentity {
                assert_eq!(ton, DestinationError::BadSignature);
            } else {
                assert_eq!(ton, error.destination_error());
            }
        }
        let wrapped = CertificateError::from(FinalityHeaderError::X1);
        assert_eq!(wrapped, CertificateError::Header(FinalityHeaderError::X1));
        assert!(wrapped.to_string().contains("X1"));
        assert!(std::error::Error::source(&wrapped).is_some());
        assert!(std::error::Error::source(&CertificateError::Signature).is_none());
    }
}
