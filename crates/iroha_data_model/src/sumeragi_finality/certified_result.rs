//! Finality header `X`, the certified result `R` it binds and the reader of `X ‖ body`.
//!
//! `specs/sccp.md` §3.6 and §3.7 (revision 5), `specs/sumeragi.md` §4.1.1 and
//! `specs/bridge_finality.md`. Every instance whose result is an
//! [`ExecutionResultCommitment`] certifies
//!
//! ```text
//! body   = norito::encode_canonical(ExecutionResultCommitment)   // ≤ MAX_RESULT_BODY_BYTES
//! D_body = H_iroha(RESULT_BODY_TAG ‖ body)                        // opaque to destinations
//! R      = SHA-256(RESULT_TAG ‖ X ‖ D_body)                       // 277-byte input
//! ```
//!
//! and stores `X ‖ body` as the certificate's result preimage. `X` is
//! [`SccpFinalityHeaderV1`], a fixed 221-byte layout that external destinations parse, so
//! [`SccpFinalityHeaderV1::parse`] is the one place its invariants X1–X7 are enforced, for
//! producers and parsers alike. [`result_of_preimage`] is the one `R` function and
//! [`CertifiedResultV1`] the one reader of `X ‖ body`.
//!
//! `R` is a raw SHA-256 output carried as an opaque [`Hash32`]. It is not an Iroha hash: it
//! never passes through `Hash::prehashed`, `HashOf` or any type that checks or sets the marker
//! bit.
//!
//! TODO(WP-C2): this module is additive. The node still certifies the body-only
//! `H(RESULT_TAG ‖ body)` of [`super::result_of_preimage`]. WP-C2 moves producers and readers
//! to this module, deletes that function and `ExecutionResultCommitment::result`, and
//! re-exports [`result_of_preimage`] at `sumeragi_finality`.

use iroha_crypto::{Algorithm, Hash, keccak256};
use iroha_sumeragi::types::Hash32;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::{
    CommitmentError, EpochValidationScope, ExecutionResultCommitment, MAX_RESULT_PREIMAGE_BYTES,
    RESULT_TAG,
};
use crate::{
    sccp::params::SCCP_MESSAGES_MAX_PER_BLOCK_V1, sumeragi::epoch::ValidatorEpochContextV1,
};

/// Exact byte length of the finality header `X`.
pub const X_LEN: usize = 221;
/// Byte length of `XHead = X[0..109)`, the first of the two TON cells that carry `X`.
pub const X_HEAD_LEN: usize = 109;
/// Byte length of `XTail = X[109..221)`.
pub const X_TAIL_LEN: usize = X_LEN - X_HEAD_LEN;
/// `magic`, the first 16 bytes of every `X`.
pub const X_MAGIC: &[u8] = b"SCCP/FINALITY/V1";
/// `flags` bit 0: the header carries SCCP state. Destinations reject a header without it.
pub const FLAG_ACTIVE: u8 = 0x01;
/// `flags` bit 1: the block ends its committee generation, at a key change or a heartbeat.
pub const FLAG_ROTATION: u8 = 0x02;
/// Largest validity, in milliseconds, a rotation may grant the successor generation (30 days).
pub const MAX_VALIDITY_MS: u64 = 2_592_000_000;
/// Largest history accumulator size (`2^32` leaves, so a history path has at most 32 siblings).
pub const MAX_HISTORY_SIZE: u64 = 1 << 32;
/// Domain tag of the body digest `D_body`.
pub const RESULT_BODY_TAG: &[u8] = b"iroha/sumeragi/result-body/v1";
/// Largest canonical body: the stored preimage `X ‖ body` is bounded by
/// [`MAX_RESULT_PREIMAGE_BYTES`].
pub const MAX_RESULT_BODY_BYTES: usize = 65_315;
/// Domain tag of [`committee_root`].
pub const COMMITTEE_TAG: &[u8] = b"SCCP/COMMITTEE/V1";

const _: () = assert!(MAX_RESULT_BODY_BYTES == MAX_RESULT_PREIMAGE_BYTES - X_LEN);
const _: () =
    assert!(X_MAGIC.len() == OFFSET_NETWORK_ID && OFFSET_NEXT_COMMITTEE_ROOT + 32 == X_LEN);
const _: () = assert!(OFFSET_HISTORY_ROOT == X_HEAD_LEN && X_TAIL_LEN == 112);
const _: () = assert!(RESULT_TAG.len() == 24 && RESULT_BODY_TAG.len() == 29);
const _: () = assert!(COMMITTEE_TAG.len() == 17);

// Field offsets of `X` (`specs/sccp.md` §3.6). Every integer is big-endian.
const OFFSET_NETWORK_ID: usize = 16;
const OFFSET_HEIGHT: usize = 48;
const OFFSET_TIMESTAMP_MS: usize = 56;
const OFFSET_FLAGS: usize = 64;
const OFFSET_MESSAGE_COUNT: usize = 65;
const OFFSET_SCCP_ROOT: usize = 69;
const OFFSET_HISTORY_SIZE: usize = 101;
const OFFSET_HISTORY_ROOT: usize = 109;
const OFFSET_GENERATION: usize = 141;
const OFFSET_COMMITTEE_ROOT: usize = 149;
const OFFSET_VALIDITY_MS: usize = 181;
const OFFSET_NEXT_COMMITTEE_ROOT: usize = 189;

const ZERO_ROOT: [u8; 32] = [0; 32];

/// Why bytes are not a finality header: the length, or the first violated invariant in the
/// order X1, X2 (inactive) or X3 (active), X4, X5, X6, X7.
///
/// The order is part of the contract: the shared vectors pin it
/// (`fixtures/sccp/finality_v1.json`, `headers.invalid[].error`). A destination reports every
/// variant as `BadHeader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FinalityHeaderError {
    /// The input is not exactly [`X_LEN`] bytes.
    #[error("a finality header is exactly 221 bytes")]
    Length,
    /// The magic is not [`X_MAGIC`], or a reserved flag bit (bits 2–7) is set.
    #[error("X1: wrong magic or a reserved flag bit")]
    X1,
    /// An inactive header is not zero after its flags, or sets `ROTATION`.
    #[error("X2: an inactive header carries fields after its flags")]
    X2,
    /// An active header has generation 0 or a zero committee root.
    #[error("X3: an active header needs a generation and a committee root")]
    X3,
    /// The message count and the SCCP root disagree, or the count exceeds the block bound.
    #[error("X4: message count and SCCP root disagree, or the count is above 512")]
    X4,
    /// The history size and root disagree, or the size exceeds [`MAX_HISTORY_SIZE`].
    #[error("X5: history size and root disagree, or the size is above 2^32")]
    X5,
    /// The successor fields contradict `ROTATION`: a rotation without a successor root, with
    /// a validity outside `1..=MAX_VALIDITY_MS`, or at height or generation `2^64 − 1` (the
    /// successor's start `height + 1` and its generation `generation + 1` must fit `u64`);
    /// or a non-rotation that carries a successor root or a validity.
    #[error("X6: successor root, validity, height or generation contradict the rotation flag")]
    X6,
    /// The height is 0.
    #[error("X7: the height is zero")]
    X7,
}

impl FinalityHeaderError {
    /// The name the shared vectors give this failure: `Length` or `X1`…`X7`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Length => "Length",
            Self::X1 => "X1",
            Self::X2 => "X2",
            Self::X3 => "X3",
            Self::X4 => "X4",
            Self::X5 => "X5",
            Self::X6 => "X6",
            Self::X7 => "X7",
        }
    }
}

/// The twelve fields of `X` after its magic, in layout order.
///
/// This is plain data: it can describe a header that violates X1–X7. Only
/// [`SccpFinalityHeaderV1::from_fields`] turns it into a header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SccpFinalityHeaderFieldsV1 {
    /// The instance's genesis-derived network identity (offset 16).
    pub network_id: [u8; 32],
    /// Block height `h` (offset 48).
    pub height: u64,
    /// Block time `t(h)` in milliseconds (offset 56).
    pub timestamp_ms: u64,
    /// [`FLAG_ACTIVE`] and [`FLAG_ROTATION`]; every other bit is zero (offset 64).
    pub flags: u8,
    /// Number of SCCP leaves the block committed (offset 65).
    pub message_count: u32,
    /// Root over the block's SCCP leaves; zero when it committed none (offset 69).
    pub sccp_root: [u8; 32],
    /// History accumulator size after the block (offset 101).
    pub history_size: u64,
    /// History accumulator root after the block (offset 109).
    pub history_root: [u8; 32],
    /// Committee generation that certifies the block (offset 141).
    pub generation: u64,
    /// [`committee_root`] of that generation's keys (offset 149).
    pub committee_root: [u8; 32],
    /// With `ROTATION`, the validity granted to the successor generation; otherwise 0
    /// (offset 181).
    pub validity_ms: u64,
    /// With `ROTATION`, the successor's committee root (the same root at a heartbeat);
    /// otherwise zero (offset 189).
    pub next_committee_root: [u8; 32],
}

impl SccpFinalityHeaderFieldsV1 {
    /// The 221-byte layout of these fields, **without** checking X1–X7.
    ///
    /// The result is raw bytes, not a header: vector generators use it to build negative
    /// cases, and everything else goes through [`SccpFinalityHeaderV1::from_fields`].
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X_LEN] {
        let mut out = [0; X_LEN];
        out[..OFFSET_NETWORK_ID].copy_from_slice(X_MAGIC);
        out[OFFSET_NETWORK_ID..OFFSET_HEIGHT].copy_from_slice(&self.network_id);
        out[OFFSET_HEIGHT..OFFSET_TIMESTAMP_MS].copy_from_slice(&self.height.to_be_bytes());
        out[OFFSET_TIMESTAMP_MS..OFFSET_FLAGS].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        out[OFFSET_FLAGS] = self.flags;
        out[OFFSET_MESSAGE_COUNT..OFFSET_SCCP_ROOT]
            .copy_from_slice(&self.message_count.to_be_bytes());
        out[OFFSET_SCCP_ROOT..OFFSET_HISTORY_SIZE].copy_from_slice(&self.sccp_root);
        out[OFFSET_HISTORY_SIZE..OFFSET_HISTORY_ROOT]
            .copy_from_slice(&self.history_size.to_be_bytes());
        out[OFFSET_HISTORY_ROOT..OFFSET_GENERATION].copy_from_slice(&self.history_root);
        out[OFFSET_GENERATION..OFFSET_COMMITTEE_ROOT]
            .copy_from_slice(&self.generation.to_be_bytes());
        out[OFFSET_COMMITTEE_ROOT..OFFSET_VALIDITY_MS].copy_from_slice(&self.committee_root);
        out[OFFSET_VALIDITY_MS..OFFSET_NEXT_COMMITTEE_ROOT]
            .copy_from_slice(&self.validity_ms.to_be_bytes());
        out[OFFSET_NEXT_COMMITTEE_ROOT..].copy_from_slice(&self.next_committee_root);
        out
    }
}

/// The finality header `X`: 221 bytes that satisfy X1–X7.
///
/// The only constructors are [`Self::parse`] and the two that run it ([`Self::from_fields`],
/// [`Self::inactive`]), so holding a value proves the invariants. It is a fixed-size inline
/// array with no owned allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpFinalityHeaderV1([u8; X_LEN]);

impl SccpFinalityHeaderV1 {
    /// Parse `X`: the single enforcement point of X1–X7 for producers and parsers.
    ///
    /// # Errors
    /// [`FinalityHeaderError::Length`] unless `bytes` is exactly [`X_LEN`] bytes; otherwise
    /// the first violated invariant in the order X1, X2 or X3, X4, X5, X6, X7.
    pub fn parse(bytes: &[u8]) -> Result<Self, FinalityHeaderError> {
        let raw = <[u8; X_LEN]>::try_from(bytes).map_err(|_| FinalityHeaderError::Length)?;
        let header = Self(raw);
        if raw[..OFFSET_NETWORK_ID] != *X_MAGIC
            || header.flags() & !(FLAG_ACTIVE | FLAG_ROTATION) != 0
        {
            return Err(FinalityHeaderError::X1);
        }
        if header.is_active() {
            if header.generation() == 0 || header.committee_root() == ZERO_ROOT {
                return Err(FinalityHeaderError::X3);
            }
        } else if header.is_rotation() || raw[OFFSET_MESSAGE_COUNT..].iter().any(|byte| *byte != 0)
        {
            return Err(FinalityHeaderError::X2);
        }
        let message_count = header.message_count();
        if (message_count == 0) != (header.sccp_root() == ZERO_ROOT)
            || message_count > SCCP_MESSAGES_MAX_PER_BLOCK_V1
        {
            return Err(FinalityHeaderError::X4);
        }
        let history_size = header.history_size();
        if (history_size == 0) != (header.history_root() == ZERO_ROOT)
            || history_size > MAX_HISTORY_SIZE
        {
            return Err(FinalityHeaderError::X5);
        }
        let validity_ms = header.validity_ms();
        let successor = header.next_committee_root();
        if header.is_rotation() {
            // The successor is generation `generation + 1` and starts at `height + 1`. Both
            // must fit `u64`, so X6 also refuses a rotation at height or generation `2^64 − 1`.
            if successor == ZERO_ROOT
                || !(1..=MAX_VALIDITY_MS).contains(&validity_ms)
                || header.height() == u64::MAX
                || header.generation() == u64::MAX
            {
                return Err(FinalityHeaderError::X6);
            }
        } else if successor != ZERO_ROOT || validity_ms != 0 {
            return Err(FinalityHeaderError::X6);
        }
        if header.height() == 0 {
            return Err(FinalityHeaderError::X7);
        }
        Ok(header)
    }

    /// Build a header from its fields and check it with [`Self::parse`].
    ///
    /// # Errors
    /// The first violated invariant, as [`Self::parse`] reports it.
    pub fn from_fields(fields: &SccpFinalityHeaderFieldsV1) -> Result<Self, FinalityHeaderError> {
        Self::parse(&fields.to_bytes())
    }

    /// The inactive form `magic ‖ network_id ‖ be64(height) ‖ be64(timestamp_ms) ‖ 0x00 ‖ 0^156`.
    ///
    /// Every non-global root uses it, and so does the global chain before SCCP exists or when
    /// the SCCP inputs of the height are missing.
    ///
    /// # Errors
    /// [`FinalityHeaderError::X7`] for height 0.
    pub fn inactive(
        network_id: [u8; 32],
        height: u64,
        timestamp_ms: u64,
    ) -> Result<Self, FinalityHeaderError> {
        Self::from_fields(&SccpFinalityHeaderFieldsV1 {
            network_id,
            height,
            timestamp_ms,
            ..SccpFinalityHeaderFieldsV1::default()
        })
    }

    /// The 221 bytes of `X`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; X_LEN] {
        &self.0
    }

    /// `XHead = X[0..109)`: magic, network, height, time, flags, message count, SCCP root and
    /// history size.
    #[must_use]
    pub fn head(&self) -> &[u8; X_HEAD_LEN] {
        self.0
            .first_chunk()
            .expect("the head is shorter than the header")
    }

    /// `XTail = X[109..221)`: history root, generation, committee root, validity and successor
    /// root.
    #[must_use]
    pub fn tail(&self) -> &[u8; X_TAIL_LEN] {
        self.0
            .last_chunk()
            .expect("the tail is shorter than the header")
    }

    /// Every field after the magic.
    #[must_use]
    pub fn fields(&self) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: self.network_id(),
            height: self.height(),
            timestamp_ms: self.timestamp_ms(),
            flags: self.flags(),
            message_count: self.message_count(),
            sccp_root: self.sccp_root(),
            history_size: self.history_size(),
            history_root: self.history_root(),
            generation: self.generation(),
            committee_root: self.committee_root(),
            validity_ms: self.validity_ms(),
            next_committee_root: self.next_committee_root(),
        }
    }

    /// `network_id`: the instance's genesis-derived network identity.
    #[must_use]
    pub fn network_id(&self) -> [u8; 32] {
        self.array(OFFSET_NETWORK_ID)
    }

    /// `height`: the block height `h`, at least 1.
    #[must_use]
    pub fn height(&self) -> u64 {
        u64::from_be_bytes(self.array(OFFSET_HEIGHT))
    }

    /// `timestamp_ms`: the block time `t(h)`.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        u64::from_be_bytes(self.array(OFFSET_TIMESTAMP_MS))
    }

    /// `flags`: [`FLAG_ACTIVE`] and [`FLAG_ROTATION`] only.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.0[OFFSET_FLAGS]
    }

    /// Whether `ACTIVE` is set.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.flags() & FLAG_ACTIVE != 0
    }

    /// Whether `ROTATION` is set. A parsed header sets it only together with `ACTIVE`.
    #[must_use]
    pub const fn is_rotation(&self) -> bool {
        self.flags() & FLAG_ROTATION != 0
    }

    /// `message_count`: the SCCP leaves the block committed, at most 512.
    #[must_use]
    pub fn message_count(&self) -> u32 {
        u32::from_be_bytes(self.array(OFFSET_MESSAGE_COUNT))
    }

    /// `sccp_root`: zero iff `message_count` is 0.
    #[must_use]
    pub fn sccp_root(&self) -> [u8; 32] {
        self.array(OFFSET_SCCP_ROOT)
    }

    /// `history_size`: the accumulator size after the block, at most [`MAX_HISTORY_SIZE`].
    #[must_use]
    pub fn history_size(&self) -> u64 {
        u64::from_be_bytes(self.array(OFFSET_HISTORY_SIZE))
    }

    /// `history_root`: zero iff `history_size` is 0.
    #[must_use]
    pub fn history_root(&self) -> [u8; 32] {
        self.array(OFFSET_HISTORY_ROOT)
    }

    /// `generation`: the committee generation that certifies the block; 0 iff inactive.
    #[must_use]
    pub fn generation(&self) -> u64 {
        u64::from_be_bytes(self.array(OFFSET_GENERATION))
    }

    /// `committee_root`: [`committee_root`] of that generation; zero iff inactive.
    #[must_use]
    pub fn committee_root(&self) -> [u8; 32] {
        self.array(OFFSET_COMMITTEE_ROOT)
    }

    /// `validity_ms`: with `ROTATION`, `1..=MAX_VALIDITY_MS`; otherwise 0.
    #[must_use]
    pub fn validity_ms(&self) -> u64 {
        u64::from_be_bytes(self.array(OFFSET_VALIDITY_MS))
    }

    /// `next_committee_root`: with `ROTATION`, the successor's root; otherwise zero.
    #[must_use]
    pub fn next_committee_root(&self) -> [u8; 32] {
        self.array(OFFSET_NEXT_COMMITTEE_ROOT)
    }

    // Every call names a constant offset of the layout table with `offset + N ≤ X_LEN`.
    fn array<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut out = [0; N];
        out.copy_from_slice(&self.0[offset..offset + N]);
        out
    }
}

impl AsRef<[u8]> for SccpFinalityHeaderV1 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// `D_body = H_iroha(RESULT_BODY_TAG ‖ body)`: the Iroha hash (Blake2b-256 with the marker
/// bit) of the canonical body. It is the `result_body` field of `QC_FIXED` and is opaque to
/// destinations.
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    Hash::new_from_chunks(&[RESULT_BODY_TAG, body]).into()
}

/// `R = SHA-256(RESULT_TAG ‖ X ‖ D_body)` over exactly 277 bytes.
///
/// The output is raw SHA-256 in an opaque [`Hash32`]; it carries no Iroha hash marker.
#[must_use]
pub fn outer_result(header: &SccpFinalityHeaderV1, d_body: &[u8; 32]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(RESULT_TAG);
    hasher.update(header.as_bytes());
    hasher.update(d_body);
    Hash32(hasher.finalize().into())
}

/// `R` of a stored result preimage `X ‖ body`: the only `R` function, for voters and readers.
///
/// Returns `None` when the preimage is shorter than 222 bytes, longer than
/// [`MAX_RESULT_PREIMAGE_BYTES`], or when its first 221 bytes do not parse as `X`. Callers
/// treat `None` as a mismatch with the certified result, never as a local fault.
#[must_use]
pub fn result_of_preimage(preimage: &[u8]) -> Option<Hash32> {
    let (header, body) = split_preimage(preimage).ok()?;
    Some(outer_result(&header, &body_digest(body)))
}

// The bounds and the header parse shared by `result_of_preimage` and `CertifiedResultV1`.
fn split_preimage(preimage: &[u8]) -> Result<(SccpFinalityHeaderV1, &[u8]), CertifiedResultError> {
    if preimage.len() <= X_LEN || preimage.len() > MAX_RESULT_PREIMAGE_BYTES {
        return Err(CertifiedResultError::PreimageLength(preimage.len()));
    }
    let (header, body) = preimage.split_at(X_LEN);
    Ok((SccpFinalityHeaderV1::parse(header)?, body))
}

/// `keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ PK_0 ‖ … ‖ PK_{n−1})` over `18 + 48n` bytes.
///
/// `keys` are the committee's 48-byte compressed BLS12-381 public keys in canonical order
/// (strictly ascending key bytes), so signer bitmap index `i` is `keys[i]`. The function
/// hashes what it is given: the committee geometry and the key order are the caller's checks.
///
/// The root is defined for `1 ≤ n ≤ 255` keys only, the counts the `u8` names. Returns `None`
/// for any other list: an empty one, or one of more than 255 keys.
#[must_use]
pub fn committee_root(keys: &[[u8; 48]]) -> Option<[u8; 32]> {
    let count = u8::try_from(keys.len()).ok().filter(|count| *count != 0)?;
    let keys = keys.as_flattened();
    let mut preimage = Vec::with_capacity(COMMITTEE_TAG.len() + 1 + keys.len());
    preimage.extend_from_slice(COMMITTEE_TAG);
    preimage.push(count);
    preimage.extend_from_slice(keys);
    Some(keccak256(preimage))
}

/// [`committee_root`] of an epoch context's committee, in the context's own (canonical) order.
///
/// Producers and readers derive the root an active `X` must carry through this one function.
/// Returns `None` when a member is not a 48-byte BLS-normal key, or when the committee has
/// no root (no member, or more than 255); a validated context is never either.
#[must_use]
pub fn context_committee_root(context: &ValidatorEpochContextV1) -> Option<[u8; 32]> {
    let mut keys = Vec::with_capacity(context.committee.len());
    for member in &context.committee {
        let (algorithm, key) = member.validator.public_key().try_to_bytes().ok()?;
        if algorithm != Algorithm::BlsNormal {
            return None;
        }
        keys.push(<[u8; 48]>::try_from(key).ok()?);
    }
    committee_root(&keys)
}

/// Which root a stored result preimage belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertifiedResultScope {
    /// The global chain (Taira; instance kind 0, index 0). Its `X` may be active.
    TairaGlobal,
    /// Every other root that uses [`ExecutionResultCommitment`] (dataspace roots, private
    /// developer anchors). Its `X` must be inactive.
    NonGlobal,
}

/// Why `X ‖ body` is not a certified result of its scope, or of the block a reader holds.
///
/// Every variant is a deterministic verdict about the input except a
/// [`CommitmentError::Resource`] inside [`Self::Body`], which is a local decoder refusal.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CertifiedResultError {
    /// The preimage is shorter than `X` plus one body byte, or above
    /// [`MAX_RESULT_PREIMAGE_BYTES`].
    #[error("result preimage length {0} is outside 222..=65536")]
    PreimageLength(usize),
    /// C1: the first 221 bytes violate X1–X7.
    #[error("invalid finality header: {0}")]
    Header(#[from] FinalityHeaderError),
    /// The body is not one valid canonical [`ExecutionResultCommitment`].
    #[error("invalid result body: {0}")]
    Body(#[from] CommitmentError),
    /// C1: the header and the body name different heights.
    #[error("finality header height {header} differs from the body height {body}")]
    HeightMismatch {
        /// `X.height`.
        header: u64,
        /// The body's height.
        body: u64,
    },
    /// C2: the header's network is not the network of the body's current epoch context.
    #[error("finality header network differs from the scheduled epoch context")]
    NetworkMismatch,
    /// C3: an active header's committee root is not the root of the current context's keys.
    #[error("finality header committee root differs from the scheduled committee")]
    CommitteeRootMismatch,
    /// C4: the header's rotation and the body's boundary decision disagree about a key change.
    #[error("finality header rotation differs from the body's boundary decision")]
    RotationMismatch,
    /// Scope: a non-global root carries an active header.
    #[error("a non-global root carries an active finality header")]
    ActiveOutsideGlobal,
    /// C5: the header's height or time is not the block's.
    #[error("finality header height or time differs from the block")]
    BlockMismatch,
}

/// A stored result preimage `X ‖ body` whose header and body agree (C1–C4 and the scope rule
/// of `specs/sccp.md` §3.6).
///
/// It is a structural reading, not an authentication: the SCCP fields of an active `X`
/// (commitment root, message count, history, generation, validity, heartbeat rotations)
/// cannot be derived from the body, and their only authority is the quorum signature over `R`.
///
/// **Which values are checked.** [`Self::new`] and the `decode` family return a value only
/// after C1–C4, the scope rule and the body bound hold, so such a value has a preimage and an
/// `R`. [`Self::from_parts_unvalidated`] moves a header and a body together with no check: its
/// value proves nothing until [`Self::validate`] (or [`Self::validate_with_validation`])
/// accepts it for a scope. That pair is for a producer that must assemble the value inside
/// an allocation-preserving move and can only fail afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedResultV1 {
    header: SccpFinalityHeaderV1,
    commitment: ExecutionResultCommitment,
}

impl CertifiedResultV1 {
    /// Bind a header to a body: the producer-side counterpart of [`Self::decode`]. It is
    /// [`Self::from_parts_unvalidated`] followed by [`Self::validate`]; the body is dropped
    /// when the check fails.
    ///
    /// # Errors
    /// The same as [`Self::validate`].
    pub fn new(
        header: SccpFinalityHeaderV1,
        commitment: ExecutionResultCommitment,
        scope: CertifiedResultScope,
    ) -> Result<Self, CertifiedResultError> {
        let result = Self::from_parts_unvalidated(header, commitment);
        result.validate(scope)?;
        Ok(result)
    }

    /// Put a header and a body together with no check: a move of the two fields that
    /// allocates nothing, drops nothing and cannot fail.
    ///
    /// The value is not a certified result of any scope until [`Self::validate`] accepts it.
    /// Validate it before it is trusted, signed, stored or sent.
    #[must_use]
    pub fn from_parts_unvalidated(
        header: SccpFinalityHeaderV1,
        commitment: ExecutionResultCommitment,
    ) -> Self {
        Self { header, commitment }
    }

    /// Check a value against `scope`: what [`Self::new`] and [`Self::decode`] establish.
    ///
    /// # Errors
    /// The first failure, in the order of [`Self::decode`] for a header that already parsed:
    /// the body bound ([`CertifiedResultError::PreimageLength`], a canonical body above
    /// [`MAX_RESULT_BODY_BYTES`]); the scope rule
    /// ([`CertifiedResultError::ActiveOutsideGlobal`]); the body's own validation
    /// ([`CertifiedResultError::Body`]); then C1–C4.
    pub fn validate(&self, scope: CertifiedResultScope) -> Result<(), CertifiedResultError> {
        self.validate_with_validation(scope, &mut EpochValidationScope::new())
    }

    /// [`Self::validate`] with the epoch validation work of an enclosing walk.
    ///
    /// # Errors
    /// The same as [`Self::validate`].
    pub fn validate_with_validation(
        &self,
        scope: CertifiedResultScope,
        validation: &mut EpochValidationScope,
    ) -> Result<(), CertifiedResultError> {
        // A value without a preimage has no `R`: the bound comes first, as the preimage
        // length does in `decode`.
        self.body_len()?;
        check_scope(&self.header, scope)?;
        self.commitment.validate_with_validation(validation)?;
        check_binding(&self.header, &self.commitment)
    }

    // The canonical length of the body, when it fits a stored preimage.
    fn body_len(&self) -> Result<usize, CertifiedResultError> {
        let body_len = norito::canonical_frame_len(&self.commitment)
            .map_err(|error| CommitmentError::Encoding(error.to_string()))?;
        check_body_len(body_len)?;
        Ok(body_len)
    }

    /// Decode `X ‖ body` and check C1–C4 and the scope rule.
    ///
    /// C2–C4 need no argument besides the scope, because the body carries its own inputs: C2
    /// and C3 read the epoch context its schedule assigns to its height (`schedule.current`:
    /// the network and the committee keys), and C4 reads its boundary decision
    /// (`schedule.boundary`, whose `next` context is the successor committee). C5 needs the
    /// block and is [`Self::check_block`].
    ///
    /// # Errors
    /// The first failure, in this pinned order: the preimage length
    /// ([`CertifiedResultError::PreimageLength`], outside `222..=MAX_RESULT_PREIMAGE_BYTES`);
    /// the header parse, X1–X7 ([`CertifiedResultError::Header`]); the scope rule
    /// ([`CertifiedResultError::ActiveOutsideGlobal`]); the body decode and its own
    /// validation ([`CertifiedResultError::Body`]); then C1's height equality
    /// ([`CertifiedResultError::HeightMismatch`]), C2
    /// ([`CertifiedResultError::NetworkMismatch`]), C3
    /// ([`CertifiedResultError::CommitteeRootMismatch`]) and C4
    /// ([`CertifiedResultError::RotationMismatch`]).
    pub fn decode(
        preimage: &[u8],
        scope: CertifiedResultScope,
    ) -> Result<Self, CertifiedResultError> {
        Self::decode_with_validation(preimage, scope, &mut EpochValidationScope::new())
    }

    /// [`Self::decode`] with the epoch validation work of an enclosing walk.
    ///
    /// # Errors
    /// The same as [`Self::decode`].
    pub fn decode_with_validation(
        preimage: &[u8],
        scope: CertifiedResultScope,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, CertifiedResultError> {
        Self::decode_with_validation_into(preimage, scope, validation, |decoded| decoded)
    }

    /// [`Self::decode_with_validation`] that hands the value to a consuming owner. `finish`
    /// runs exactly once, after every check has passed, and never on a rejected preimage or a
    /// local decoder refusal.
    ///
    /// # Errors
    /// The same as [`Self::decode`].
    pub fn decode_with_validation_into<Output>(
        preimage: &[u8],
        scope: CertifiedResultScope,
        validation: &mut EpochValidationScope,
        finish: impl FnOnce(Self) -> Output,
    ) -> Result<Output, CertifiedResultError> {
        let (header, body) = split_preimage(preimage)?;
        // The scope rule needs only the header: refuse before the body is decoded.
        check_scope(&header, scope)?;
        // `body` is at most `MAX_RESULT_BODY_BYTES`, because the whole preimage is bounded.
        ExecutionResultCommitment::decode_with_validation_into(
            body,
            validation,
            |commitment| -> Result<Output, CertifiedResultError> {
                check_binding(&header, &commitment)?;
                Ok(finish(Self { header, commitment }))
            },
        )?
    }

    /// C5, for a reader that holds the block: `X.height` is the block height and
    /// `X.timestamp_ms` is the block time `t(X.height)` (the block header's creation time).
    ///
    /// # Errors
    /// [`CertifiedResultError::BlockMismatch`] when either differs.
    pub fn check_block(&self, height: u64, timestamp_ms: u64) -> Result<(), CertifiedResultError> {
        if self.header.height() != height || self.header.timestamp_ms() != timestamp_ms {
            return Err(CertifiedResultError::BlockMismatch);
        }
        Ok(())
    }

    /// The finality header `X`.
    #[must_use]
    pub const fn header(&self) -> &SccpFinalityHeaderV1 {
        &self.header
    }

    /// The body.
    #[must_use]
    pub const fn commitment(&self) -> &ExecutionResultCommitment {
        &self.commitment
    }

    /// The header and the body.
    #[must_use]
    pub fn into_parts(self) -> (SccpFinalityHeaderV1, ExecutionResultCommitment) {
        (self.header, self.commitment)
    }

    /// The stored result preimage `X ‖ body`, in one buffer.
    ///
    /// # Errors
    /// A Norito serialization failure, or a canonical body above [`MAX_RESULT_BODY_BYTES`]. A
    /// value that [`Self::new`], [`Self::decode`] or [`Self::validate`] accepted has neither.
    pub fn preimage(&self) -> Result<Vec<u8>, CertifiedResultError> {
        let body_len = self.body_len()?;
        let mut preimage = Vec::with_capacity(X_LEN + body_len);
        preimage.extend_from_slice(self.header.as_bytes());
        norito::core::write_canonical_to_writer(&self.commitment, &mut preimage)
            .map_err(|error| CommitmentError::Encoding(error.to_string()))?;
        Ok(preimage)
    }

    /// `R` of this result: [`result_of_preimage`] of [`Self::preimage`].
    ///
    /// # Errors
    /// The same as [`Self::preimage`].
    pub fn result(&self) -> Result<Hash32, CertifiedResultError> {
        let preimage = self.preimage()?;
        result_of_preimage(&preimage).ok_or(CertifiedResultError::PreimageLength(preimage.len()))
    }
}

// The body bound of every certified result: a canonical body of at most
// `MAX_RESULT_BODY_BYTES`, so that `X ‖ body` fits `MAX_RESULT_PREIMAGE_BYTES`. The error names
// the preimage length the body would give.
fn check_body_len(body_len: usize) -> Result<(), CertifiedResultError> {
    if body_len > MAX_RESULT_BODY_BYTES {
        return Err(CertifiedResultError::PreimageLength(
            X_LEN.saturating_add(body_len),
        ));
    }
    Ok(())
}

// Scope rule: only the global chain may carry an active header.
fn check_scope(
    header: &SccpFinalityHeaderV1,
    scope: CertifiedResultScope,
) -> Result<(), CertifiedResultError> {
    if header.is_active() && scope == CertifiedResultScope::NonGlobal {
        return Err(CertifiedResultError::ActiveOutsideGlobal);
    }
    Ok(())
}

// C1 (height), C2, C3 and C4 against a body that already passed its own validation, so that
// `schedule.current` is the context its schedule assigns to `commitment.height`.
fn check_binding(
    header: &SccpFinalityHeaderV1,
    commitment: &ExecutionResultCommitment,
) -> Result<(), CertifiedResultError> {
    if header.height() != commitment.height {
        return Err(CertifiedResultError::HeightMismatch {
            header: header.height(),
            body: commitment.height,
        });
    }
    let current = &commitment.schedule.current;
    if header.network_id() != *current.network_id.as_bytes() {
        return Err(CertifiedResultError::NetworkMismatch);
    }
    if !header.is_active() {
        return Ok(());
    }
    let committee = header.committee_root();
    if context_committee_root(current) != Some(committee) {
        return Err(CertifiedResultError::CommitteeRootMismatch);
    }
    let successor = commitment
        .schedule
        .boundary
        .as_ref()
        .map(|boundary| {
            context_committee_root(&boundary.next).ok_or(CertifiedResultError::RotationMismatch)
        })
        .transpose()?;
    let announced = header.next_committee_root();
    let body_changes_keys = successor.is_some_and(|root| root != committee);
    let header_changes_keys = header.is_rotation() && announced != committee;
    // A key change on either side must be the same key change on both: a rotation to exactly
    // the boundary's successor root. A heartbeat (`announced == committee`) and a boundary
    // that retains the committee need nothing from each other.
    if (body_changes_keys || header_changes_keys)
        && (!header.is_rotation() || successor != Some(announced))
    {
        return Err(CertifiedResultError::RotationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
