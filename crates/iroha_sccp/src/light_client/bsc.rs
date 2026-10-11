//! BSC skipping light client (spec `specs/sccp.md` §4.13.3).
//!
//! **Stored set:** a Parlia validator set (consensus address and BLS vote key per validator, in
//! address order) with its turn length, keyed by the height of the epoch checkpoint that
//! announced it. A set covers vote targets from `checkpoint + minerHistoryCheckLen(previous) + 1`
//! (Parlia switches to the announced set once `(n_prev / 2 + 1) * turn_prev - 1` blocks follow the
//! checkpoint and verifies the votes on a target with the set of the target's parent). Each set
//! names the set that finalized its checkpoint, so a proof under an older set names that set's
//! successor and the target must precede the successor's first covered height.
//!
//! **Finality:** a fast-finality vote attestation `(source → source + 1)` finalizes `source`. It
//! is checked under the stored set covering `source + 1`: the vote bitmap names only members, at
//! least `⌈2n/3⌉` of them signed, and the fast-aggregate BLS signature (proof-of-possession DST)
//! over `keccak256(rlp(VoteData))` verifies. The set must be fresh: a superseded set until
//! `ws_bound_ms` after the checkpoint time of its successor, the newest set until `ws_bound_ms`
//! after the newest finalized epoch checkpoint that (re-)announces it (`head.latest_finalized`).
//! Finalized blocks without such a checkpoint never extend the newest set's freshness, so a set
//! the chain no longer announces ages out like a superseded one.
//!
//! **Roster keys:** a roster's BLS vote keys are validated once, when its set is learned (the
//! bootstrap set or a transition). Stored sets, and the announcements compared with them, are
//! only checked structurally, so a verification costs its charged BLS checks and no unmetered
//! key validation.
//!
//! **Advance (skipping):** at most `min(params.max_updates_per_advance, 16)` steps. A step is at
//! most 256 parent-linked headers ending at a block the step's attestation finalizes. When its
//! first header is an epoch checkpoint above the newest set's checkpoint that announces another
//! set (or turn length), the step is a set transition: the attestation must come from the newest
//! set and its target must precede the new set's first covered height. Any other epoch
//! checkpoint above the newest set's checkpoint in a step, proof or evidence record must announce
//! the newest set, so every transition is learned by a step of its own. Cost is O(set changes)
//! plus the refreshes: when the set is unchanged, one step from a later epoch checkpoint (which
//! re-announces it) to a finalized descendant advances `latest_finalized` to that checkpoint.
//! Steps without an epoch checkpoint record checkpoints but leave the head.
//!
//! **Backfill:** at most 256 parent-linked headers ending at a stored checkpoint; the first header
//! becomes a checkpoint (`origin: Backfill`).
//!
//! **Proof:** at most 256 parent-linked headers from the event block `B` to an anchor block that
//! an attestation finalizes or that is a stored checkpoint, then the receipt MPT under `B`'s
//! receipts root and the selected `SccpTransferToTaira` log or run of `SccpVoided` logs (the
//! Solidity contracts and events are the Ethereum ones).
//!
//! **Fork bound:** every header lies in the compiled `[supported_from, supported_until]` window
//! and at most a minute ahead of the Taira block time.
//!
//! **Equivocation:** a record is an attestation, optionally with parent-linked headers ending at
//! its finalized block. Two records conflict when quorums voted different targets at one height,
//! or the blocks they assert cannot share one chain: one height with different hashes, or heights
//! and times ordered inconsistently (Parlia timestamps strictly increase).

use std::collections::BTreeMap;

use core::fmt;

use iroha_crypto::{ethereum_bls_pop_fast_aggregate_verify, ethereum_bls_pop_validate_public_key};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceLocatorV1,
        light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1,
            SccpLcConsensusSetV1, SccpLcEquivocationFreezeV1, SccpLcFreezeReasonV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
    },
};

use super::{
    SccpLcConflictV1, SccpLcError, SccpVerifierWorkV1,
    ethereum::{self, EthereumEventSelectorV1, EthereumLcError},
    profile::{
        BSC_MAX_SEGMENT_HEADERS, BSC_MAX_STEPS_PER_ADVANCE, BSC_MAX_VALIDATORS, BscChainProfileV1,
        MAX_SOURCE_FUTURE_MS,
    },
    proof::{SccpLcSetDataV1, SccpVerifiedProofV1},
    state::{
        CheckpointRecorder, SccpLcDeltaV1, SccpLcInitialStateV1, SccpLcPurgeV1, SccpLcStateView,
        SccpLcSupersessionV1, is_set_fresh, state_hash,
    },
};
use crate::{
    ethereum_source::{
        EthereumNativeMptProofV1, canonical_u64, parse_rlp_list, rlp_bytes, rlp_encode_bytes,
        rlp_encode_list, rlp_encode_u64, rlp_h256, rlp_list_items,
    },
    v1::{hashes::keccak256, network::tag},
};

const NETWORK: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
const EXTRA_VANITY_BYTES: usize = 32;
const EXTRA_SEAL_BYTES: usize = 65;
const VALIDATOR_BYTES: usize = 20 + 48;
const HEADER_FIELDS: usize = 21;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_ATTESTATION_BYTES: usize = 1_024;
const MAX_ATTESTATION_EXTRA_BYTES: usize = 256;
const MAX_TURN_LENGTH: u8 = 64;

// ---------------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------------

/// One Parlia validator.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscValidatorV1")]
pub struct BscValidatorV1 {
    /// 20-byte consensus address.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub consensus_address: Vec<u8>,
    /// 48-byte compressed BLS12-381 vote public key.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub vote_public_key: Vec<u8>,
}

/// Stored Parlia validator set (`SccpLcConsensusSetV1.set_bytes`); the set id is
/// `checkpoint_height`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscValidatorSetV1")]
pub struct BscValidatorSetV1 {
    /// Height of the epoch checkpoint that announced the set.
    #[norito(with = "crate::json_utils::u64_string")]
    pub checkpoint_height: u64,
    /// Hash of that checkpoint.
    #[norito(with = "crate::json_utils::hex32")]
    pub checkpoint_hash: [u8; 32],
    /// The stored set whose attestation finalized the checkpoint; `None` for a bootstrap set.
    #[norito(required)]
    pub previous_set_id: Option<u64>,
    /// Consecutive blocks each validator produces.
    pub turn_length: u8,
    /// Validators in ascending consensus-address order (the vote-bitmap order).
    pub validators: Vec<BscValidatorV1>,
}

/// A fast-finality vote attestation `(source → source + 1)`, checked under a stored set.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscFinalityV1")]
pub struct BscFinalityV1 {
    /// Stored set covering the attestation's target.
    #[norito(with = "crate::json_utils::u64_string")]
    pub set_id: u64,
    /// The stored set succeeding `set_id`, required unless `set_id` is the newest set.
    #[norito(required)]
    pub successor_set_id: Option<u64>,
    /// RLP `VoteAttestation` as carried in a descendant header's `extraData`.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub attestation: Vec<u8>,
}

/// One advance step: parent-linked header RLPs, ascending, the last one finalized by `finality`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscAdvanceStepV1")]
pub struct BscAdvanceStepV1 {
    /// Header RLPs; the first one is a set-transition checkpoint or any block.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub headers: Vec<Vec<u8>>,
    /// Attestation finalizing the last header.
    pub finality: BscFinalityV1,
}

/// BSC advance: steps, oldest first.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscLcAdvanceV1")]
pub struct BscLcAdvanceV1 {
    /// Steps; set transitions in source order.
    pub steps: Vec<BscAdvanceStepV1>,
}

/// Parent-linked BSC header RLPs, ascending.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscHeaderSegmentV1")]
pub struct BscHeaderSegmentV1 {
    /// Header RLPs.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub headers: Vec<Vec<u8>>,
}

/// Reference to a stored checkpoint.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscStoredCheckpointRefV1")]
pub struct BscStoredCheckpointRefV1 {
    /// Source height of the checkpoint.
    #[norito(with = "crate::json_utils::u64_string")]
    pub source_height: u64,
}

/// What finalizes the last header of a proof.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "kind", content = "value", rename_all = "snake_case")]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscProofAnchorV1")]
pub enum BscProofAnchorV1 {
    /// A vote attestation under a fresh stored set.
    Finality(BscFinalityV1),
    /// A stored checkpoint.
    StoredCheckpoint(BscStoredCheckpointRefV1),
}

/// BSC inbound or void proof.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscSourceProofV1")]
pub struct BscSourceProofV1 {
    /// Finality of the last header.
    pub anchor: BscProofAnchorV1,
    /// Parent-linked header RLPs from the event block (first) to the anchor block (last).
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub headers: Vec<Vec<u8>>,
    /// Index of the transaction and receipt in the event block.
    pub transaction_index: u32,
    /// Receipt MPT proof under the event block's receipts root.
    pub receipt_proof: EthereumNativeMptProofV1,
    /// Selected log or log run.
    pub event: EthereumEventSelectorV1,
}

/// One quorum-valid BSC equivocation record.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscLcEvidenceV1")]
pub struct BscLcEvidenceV1 {
    /// Attestation finalizing a block.
    pub finality: BscFinalityV1,
    /// Parent-linked header RLPs ending at the finalized block; may be empty.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub headers: Vec<Vec<u8>>,
}

/// BSC weak-subjectivity bootstrap (`SccpLcBootstrapV1.bytes`).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::light_client::bsc::BscLcBootstrapV1")]
pub struct BscLcBootstrapV1 {
    /// Trusted epoch checkpoint header whose announced set is installed.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub checkpoint_header: Vec<u8>,
    /// The epoch checkpoint header one epoch earlier; its set size and turn length fix the
    /// height from which the installed set covers votes.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub previous_checkpoint_header: Vec<u8>,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// BSC-specific verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BscLcError {
    /// A header is not a bounded canonical 21-field Parlia header RLP.
    MalformedHeader,
    /// A header's `extraData` (vanity, epoch roster, attestation, seal) is malformed.
    MalformedExtra,
    /// An epoch checkpoint's validator roster is empty, oversized, unsorted, duplicated or
    /// carries an invalid BLS key, or its turn length is out of range.
    InvalidRoster,
    /// A vote attestation is malformed or does not vote a direct child of its source.
    MalformedAttestation,
    /// The vote bitmap names a non-member or fewer than `⌈2n/3⌉` validators.
    InsufficientQuorum {
        /// Signing validators.
        signers: u32,
        /// Required signers.
        required: u32,
    },
    /// The aggregate BLS signature does not verify.
    InvalidAggregateSignature,
    /// The stored set does not cover the attestation's target, or the named successor is not
    /// the set's successor.
    SetDoesNotCover {
        /// Set id.
        set_id: u64,
        /// Target height.
        target: u64,
    },
    /// A header lies outside the compiled fork window.
    UnsupportedFork {
        /// Header time (ms).
        time_ms: u64,
    },
    /// A header does not link to its predecessor (parent hash, height and strictly later time).
    AncestryBroken {
        /// Index of the unlinked header.
        index: usize,
    },
    /// The attestation finalizes another block than the last header.
    FinalityMismatch,
    /// A stored checkpoint anchor or backfill end does not match the last header.
    CheckpointMismatch {
        /// Source height.
        source_height: u64,
    },
    /// An epoch checkpoint above the newest set announces another set outside a transition step.
    UnlearnedTransition {
        /// Checkpoint height.
        checkpoint_height: u64,
    },
    /// A set transition is not attested by the newest set, or its target is already covered by
    /// the announced set.
    InvalidTransition {
        /// Checkpoint height.
        checkpoint_height: u64,
    },
    /// The bootstrap headers are not consecutive epoch checkpoints.
    InvalidBootstrap,
    /// A stored consensus set does not decode as a BSC set with its id.
    MalformedStoredSet {
        /// Set id.
        set_id: u64,
    },
    /// A height or time overflows.
    Overflow,
    /// The receipt or event opening failed (the EVM rules shared with Ethereum).
    Receipt(EthereumLcError),
}

impl fmt::Display for BscLcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHeader => formatter.write_str("malformed BSC header"),
            Self::MalformedExtra => formatter.write_str("malformed Parlia extraData"),
            Self::InvalidRoster => formatter.write_str("invalid Parlia validator roster"),
            Self::MalformedAttestation => formatter.write_str("malformed vote attestation"),
            Self::InsufficientQuorum { signers, required } => write!(
                formatter,
                "{signers} vote signers; at least {required} set members are required"
            ),
            Self::InvalidAggregateSignature => {
                formatter.write_str("aggregate vote signature does not verify")
            }
            Self::SetDoesNotCover { set_id, target } => {
                write!(
                    formatter,
                    "set {set_id} does not cover vote target {target}"
                )
            }
            Self::UnsupportedFork { time_ms } => write!(
                formatter,
                "header time {time_ms} ms is outside the compiled BSC fork window"
            ),
            Self::AncestryBroken { index } => {
                write!(formatter, "header {index} does not link to its predecessor")
            }
            Self::FinalityMismatch => {
                formatter.write_str("the attestation does not finalize the last header")
            }
            Self::CheckpointMismatch { source_height } => write!(
                formatter,
                "the last header is not the stored checkpoint at {source_height}"
            ),
            Self::UnlearnedTransition { checkpoint_height } => write!(
                formatter,
                "checkpoint {checkpoint_height} announces an unlearned set; advance it first"
            ),
            Self::InvalidTransition { checkpoint_height } => {
                write!(formatter, "invalid set transition at {checkpoint_height}")
            }
            Self::InvalidBootstrap => {
                formatter.write_str("bootstrap headers are not consecutive epoch checkpoints")
            }
            Self::MalformedStoredSet { set_id } => {
                write!(formatter, "stored set {set_id} is not a BSC validator set")
            }
            Self::Overflow => formatter.write_str("source height or time overflows"),
            Self::Receipt(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for BscLcError {}

impl From<BscLcError> for SccpLcError {
    fn from(value: BscLcError) -> Self {
        Self::Bsc(value)
    }
}

/// Re-tag a receipt or event error of the shared EVM helpers as a BSC error.
fn receipt_error(error: SccpLcError) -> SccpLcError {
    match error {
        SccpLcError::Ethereum(inner) => BscLcError::Receipt(inner).into(),
        other => other,
    }
}

// ---------------------------------------------------------------------------------------------
// Parlia primitives
// ---------------------------------------------------------------------------------------------

/// Fields of a decoded Parlia header.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HeaderV1 {
    hash: [u8; 32],
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    number: u64,
    time_ms: u64,
    extra: Vec<u8>,
}

impl HeaderV1 {
    const fn point(&self) -> SccpLcPointV1 {
        SccpLcPointV1 {
            source_height: self.number,
            block_hash: self.hash,
            source_time_ms: self.time_ms,
        }
    }

    const fn checkpoint(&self) -> SccpLcCheckpointDataV1 {
        SccpLcCheckpointDataV1 {
            source_height: self.number,
            block_hash: self.hash,
            state_root: Some(self.state_root),
            receipts_or_tx_root: self.receipts_root,
            source_time_ms: self.time_ms,
        }
    }
}

/// Decode a 21-field post-Mendel header RLP: fields 0, 3, 5 and 13 are 32-byte strings, 8 and
/// 11 canonical integers, 12 the `extraData`; the millisecond part of the timestamp is the
/// big-endian `u64` in the last 8 bytes of the mix digest (field 13), below 1 000, with the
/// first 24 bytes zero. The remaining fields are bound by the hash only.
fn decode_header(rlp: &[u8]) -> Result<HeaderV1, BscLcError> {
    if rlp.len() > MAX_HEADER_BYTES {
        return Err(BscLcError::MalformedHeader);
    }
    let items = parse_rlp_list(rlp, HEADER_FIELDS).ok_or(BscLcError::MalformedHeader)?;
    if items.len() != HEADER_FIELDS {
        return Err(BscLcError::MalformedHeader);
    }
    let hash32 = |index: usize| rlp_h256(items[index]).ok_or(BscLcError::MalformedHeader);
    let integer = |index: usize| canonical_u64(items[index]).ok_or(BscLcError::MalformedHeader);
    let mix = hash32(13)?;
    if mix[..24] != [0; 24] {
        return Err(BscLcError::MalformedHeader);
    }
    let mut millis = [0_u8; 8];
    millis.copy_from_slice(&mix[24..]);
    let millis = u64::from_be_bytes(millis);
    if millis >= 1_000 {
        return Err(BscLcError::MalformedHeader);
    }
    let time_ms = integer(11)?
        .checked_mul(1_000)
        .and_then(|ms| ms.checked_add(millis))
        .ok_or(BscLcError::Overflow)?;
    Ok(HeaderV1 {
        hash: keccak256(&[rlp]),
        parent_hash: hash32(0)?,
        state_root: hash32(3)?,
        receipts_root: hash32(5)?,
        number: integer(8)?,
        time_ms,
        extra: rlp_bytes(items[12])
            .ok_or(BscLcError::MalformedHeader)?
            .to_vec(),
    })
}

/// A validator set announced by an epoch checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AnnouncedSetV1 {
    validators: Vec<BscValidatorV1>,
    turn_length: u8,
}

#[cfg(test)]
std::thread_local! {
    static BLS_KEY_VALIDATIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Check a roster's structure and return its vote keys: 1..=64 members, strictly ascending
/// nonzero addresses, distinct 48-byte keys. The keys themselves are validated once, when the set
/// is learned ([`validate_roster_keys`]).
fn roster_keys(validators: &[BscValidatorV1]) -> Result<Vec<[u8; 48]>, BscLcError> {
    if validators.is_empty() || validators.len() > BSC_MAX_VALIDATORS {
        return Err(BscLcError::InvalidRoster);
    }
    let mut keys = Vec::with_capacity(validators.len());
    let mut previous: Option<[u8; 20]> = None;
    for validator in validators {
        let address = <[u8; 20]>::try_from(validator.consensus_address.as_slice())
            .map_err(|_| BscLcError::InvalidRoster)?;
        let key = <[u8; 48]>::try_from(validator.vote_public_key.as_slice())
            .map_err(|_| BscLcError::InvalidRoster)?;
        if address == [0; 20]
            || previous.is_some_and(|prior| prior >= address)
            || keys.contains(&key)
        {
            return Err(BscLcError::InvalidRoster);
        }
        previous = Some(address);
        keys.push(key);
    }
    Ok(keys)
}

/// Validate every BLS vote key of a set being learned (point encoding and subgroup checks). A
/// learned set is stored only after this succeeds, so stored sets are never re-validated.
fn validate_roster_keys(validators: &[BscValidatorV1]) -> Result<(), BscLcError> {
    for key in roster_keys(validators)? {
        #[cfg(test)]
        BLS_KEY_VALIDATIONS.with(|count| count.set(count.get().saturating_add(1)));
        ethereum_bls_pop_validate_public_key(&key).map_err(|_| BscLcError::InvalidRoster)?;
    }
    Ok(())
}

/// The set an epoch checkpoint announces: after the 32-byte vanity, a count byte, `count`
/// `(address ‖ BLS key)` entries and the turn length; then an optional attestation and the
/// 65-byte seal. The roster is checked structurally; its keys are validated only if it is
/// learned.
fn announced_set(header: &HeaderV1) -> Result<AnnouncedSetV1, BscLcError> {
    let middle = extra_middle(&header.extra)?;
    let count = usize::from(*middle.first().ok_or(BscLcError::MalformedExtra)?);
    let roster_end = count
        .checked_mul(VALIDATOR_BYTES)
        .and_then(|len| len.checked_add(1))
        .ok_or(BscLcError::MalformedExtra)?;
    let roster = middle
        .get(1..roster_end)
        .ok_or(BscLcError::MalformedExtra)?;
    let turn_length = *middle.get(roster_end).ok_or(BscLcError::MalformedExtra)?;
    if turn_length == 0 || turn_length > MAX_TURN_LENGTH {
        return Err(BscLcError::InvalidRoster);
    }
    let validators = roster
        .chunks_exact(VALIDATOR_BYTES)
        .map(|entry| BscValidatorV1 {
            consensus_address: entry[..20].to_vec(),
            vote_public_key: entry[20..].to_vec(),
        })
        .collect::<Vec<_>>();
    roster_keys(&validators)?;
    Ok(AnnouncedSetV1 {
        validators,
        turn_length,
    })
}

fn extra_middle(extra: &[u8]) -> Result<&[u8], BscLcError> {
    let seal_start = extra
        .len()
        .checked_sub(EXTRA_SEAL_BYTES)
        .filter(|start| *start >= EXTRA_VANITY_BYTES)
        .ok_or(BscLcError::MalformedExtra)?;
    Ok(&extra[EXTRA_VANITY_BYTES..seal_start])
}

/// Parlia `minerHistoryCheckLen`: `(n / 2 + 1) * turn_length - 1`.
fn miner_history_check_len(validators: usize, turn_length: u8) -> Result<u64, BscLcError> {
    u64::try_from(validators / 2 + 1)
        .ok()
        .and_then(|majority| majority.checked_mul(u64::from(turn_length)))
        .and_then(|len| len.checked_sub(1))
        .ok_or(BscLcError::Overflow)
}

/// Source and target of a vote attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BscVoteV1 {
    /// Justified source height.
    pub source_number: u64,
    /// Justified source hash.
    pub source_hash: [u8; 32],
    /// Voted target height.
    pub target_number: u64,
    /// Voted target hash.
    pub target_hash: [u8; 32],
}

impl BscVoteV1 {
    /// Whether the vote targets the direct child of its source, finalizing the source.
    #[must_use]
    pub fn finalizes_source(&self) -> bool {
        self.source_number.checked_add(1) == Some(self.target_number)
    }
}

/// Height, hash, parent and time (ms) of a header RLP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BscHeaderSummaryV1 {
    /// Height.
    pub number: u64,
    /// Block hash.
    pub hash: [u8; 32],
    /// Parent hash.
    pub parent_hash: [u8; 32],
    /// Time (ms).
    pub time_ms: u64,
}

/// Summarize a header RLP (the fields the light client reads).
///
/// # Errors
///
/// Returns [`BscLcError::MalformedHeader`].
pub fn header_summary(header_rlp: &[u8]) -> Result<BscHeaderSummaryV1, BscLcError> {
    let header = decode_header(header_rlp)?;
    Ok(BscHeaderSummaryV1 {
        number: header.number,
        hash: header.hash,
        parent_hash: header.parent_hash,
        time_ms: header.time_ms,
    })
}

/// The raw vote attestation a header carries in its `extraData`, with its vote.
///
/// # Errors
///
/// Returns a header, `extraData` or attestation error.
pub fn header_attestation(
    profile: &BscChainProfileV1,
    header_rlp: &[u8],
) -> Result<Option<(Vec<u8>, BscVoteV1)>, BscLcError> {
    let header = decode_header(header_rlp)?;
    let middle = extra_middle(&header.extra)?;
    let raw = if profile.is_epoch_checkpoint(header.number) {
        let count = usize::from(*middle.first().ok_or(BscLcError::MalformedExtra)?);
        let skip = count
            .checked_mul(VALIDATOR_BYTES)
            .and_then(|len| len.checked_add(2))
            .ok_or(BscLcError::MalformedExtra)?;
        middle.get(skip..).ok_or(BscLcError::MalformedExtra)?
    } else {
        middle
    };
    if raw.is_empty() {
        return Ok(None);
    }
    let data = parse_attestation(raw)?.data;
    Ok(Some((
        raw.to_vec(),
        BscVoteV1 {
            source_number: data.source_number,
            source_hash: data.source_hash,
            target_number: data.target_number,
            target_hash: data.target_hash,
        },
    )))
}

/// The validators and turn length an epoch checkpoint header announces.
///
/// # Errors
///
/// Returns a header, `extraData` or roster error.
pub fn header_announced_set(header_rlp: &[u8]) -> Result<(Vec<BscValidatorV1>, u8), BscLcError> {
    let announced = announced_set(&decode_header(header_rlp)?)?;
    Ok((announced.validators, announced.turn_length))
}

/// Blocks after an epoch checkpoint before its announced set takes over, given the previous
/// set's size and turn length (Parlia `minerHistoryCheckLen`); the set covers vote targets from
/// `checkpoint + offset + 1`.
///
/// # Errors
///
/// Returns [`BscLcError::Overflow`].
pub fn activation_offset(
    previous_validators: usize,
    previous_turn_length: u8,
) -> Result<u64, BscLcError> {
    miner_history_check_len(previous_validators, previous_turn_length)
}

/// Parlia `VoteData`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VoteDataV1 {
    source_number: u64,
    source_hash: [u8; 32],
    target_number: u64,
    target_hash: [u8; 32],
}

impl VoteDataV1 {
    /// `keccak256(rlp([source_number, source_hash, target_number, target_hash]))`.
    fn hash(&self) -> [u8; 32] {
        keccak256(&[&rlp_encode_list(&[
            rlp_encode_u64(self.source_number),
            rlp_encode_bytes(&self.source_hash),
            rlp_encode_u64(self.target_number),
            rlp_encode_bytes(&self.target_hash),
        ])])
    }
}

/// `keccak256(rlp(VoteData))`, the message a Parlia vote signs.
#[must_use]
pub fn vote_data_hash(
    source_number: u64,
    source_hash: [u8; 32],
    target_number: u64,
    target_hash: [u8; 32],
) -> [u8; 32] {
    VoteDataV1 {
        source_number,
        source_hash,
        target_number,
        target_hash,
    }
    .hash()
}

/// Parlia `VoteAttestation`.
struct AttestationV1 {
    vote_address_set: u64,
    signature: [u8; 96],
    data: VoteDataV1,
}

/// Decode `rlp([vote_address_set, aggregate_signature, [source_number, source_hash,
/// target_number, target_hash], extra])` voting a direct child of its source.
fn decode_attestation(bytes: &[u8]) -> Result<AttestationV1, BscLcError> {
    let attestation = parse_attestation(bytes)?;
    if attestation.data.source_number.checked_add(1) != Some(attestation.data.target_number) {
        return Err(BscLcError::MalformedAttestation);
    }
    Ok(attestation)
}

/// Decode a vote attestation with any target above its source.
fn parse_attestation(bytes: &[u8]) -> Result<AttestationV1, BscLcError> {
    if bytes.len() > MAX_ATTESTATION_BYTES {
        return Err(BscLcError::MalformedAttestation);
    }
    let malformed = || BscLcError::MalformedAttestation;
    let fields = parse_rlp_list(bytes, 4).ok_or_else(malformed)?;
    if fields.len() != 4 {
        return Err(malformed());
    }
    let vote_address_set = canonical_u64(fields[0]).ok_or_else(malformed)?;
    let signature = rlp_bytes(fields[1])
        .and_then(|signature| <[u8; 96]>::try_from(signature).ok())
        .ok_or_else(malformed)?;
    let data = rlp_list_items(fields[2], 4).ok_or_else(malformed)?;
    if data.len() != 4 {
        return Err(malformed());
    }
    let data = VoteDataV1 {
        source_number: canonical_u64(data[0]).ok_or_else(malformed)?,
        source_hash: rlp_h256(data[1]).ok_or_else(malformed)?,
        target_number: canonical_u64(data[2]).ok_or_else(malformed)?,
        target_hash: rlp_h256(data[3]).ok_or_else(malformed)?,
    };
    let extra = rlp_bytes(fields[3]).ok_or_else(malformed)?;
    if extra.len() > MAX_ATTESTATION_EXTRA_BYTES
        || data.source_number >= data.target_number
        || data.source_hash == [0; 32]
        || data.target_hash == [0; 32]
    {
        return Err(malformed());
    }
    Ok(AttestationV1 {
        vote_address_set,
        signature,
        data,
    })
}

/// Check that at least `⌈2n/3⌉` members of the stored set `validators` signed `attestation`.
/// The stored keys were validated when the set was learned.
fn verify_quorum(
    validators: &[BscValidatorV1],
    attestation: &AttestationV1,
) -> Result<(), SccpLcError> {
    let keys = roster_keys(validators)?;
    let members = keys.len();
    if members < 64 && attestation.vote_address_set >> members != 0 {
        return Err(BscLcError::InsufficientQuorum {
            signers: attestation.vote_address_set.count_ones(),
            required: quorum(members),
        }
        .into());
    }
    let signers = keys
        .iter()
        .enumerate()
        .filter(|(index, _)| attestation.vote_address_set & (1_u64 << index) != 0)
        .map(|(_, key)| *key)
        .collect::<Vec<_>>();
    let required = quorum(members);
    let count = u32::try_from(signers.len()).unwrap_or(u32::MAX);
    if count < required {
        return Err(BscLcError::InsufficientQuorum {
            signers: count,
            required,
        }
        .into());
    }
    ethereum_bls_pop_fast_aggregate_verify(
        &signers,
        &attestation.data.hash(),
        &attestation.signature,
    )
    .map_err(|_| BscLcError::InvalidAggregateSignature.into())
}

/// `⌈2n/3⌉`.
fn quorum(members: usize) -> u32 {
    u32::try_from((members * 2).div_ceil(3)).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------------------------
// Sets
// ---------------------------------------------------------------------------------------------

fn decode_set(set: &SccpLcConsensusSetV1) -> Result<BscValidatorSetV1, SccpLcError> {
    let malformed = BscLcError::MalformedStoredSet { set_id: set.set_id };
    let decoded = SccpLcSetDataV1::from_frame(&set.set_bytes).map_err(|_| malformed)?;
    let SccpLcSetDataV1::Bsc(data) = decoded else {
        return Err(malformed.into());
    };
    if data.checkpoint_height != set.set_id {
        return Err(malformed.into());
    }
    Ok(data)
}

fn set_record(
    data: BscValidatorSetV1,
    valid_from_source_height: u64,
) -> Result<SccpLcConsensusSetV1, SccpLcError> {
    Ok(SccpLcConsensusSetV1 {
        set_id: data.checkpoint_height,
        valid_from_source_height,
        superseded_at_source_ms: None,
        set_bytes: SccpLcSetDataV1::Bsc(data).to_frame()?,
    })
}

/// Stored sets plus the sets an advance learns.
struct Sets<'a, V: SccpLcStateView + ?Sized> {
    view: &'a V,
    learned: BTreeMap<u64, SccpLcConsensusSetV1>,
    superseded: BTreeMap<u64, u64>,
}

impl<'a, V: SccpLcStateView + ?Sized> Sets<'a, V> {
    const fn new(view: &'a V) -> Self {
        Self {
            view,
            learned: BTreeMap::new(),
            superseded: BTreeMap::new(),
        }
    }

    fn get(&self, set_id: u64) -> Option<SccpLcConsensusSetV1> {
        self.learned.get(&set_id).cloned().or_else(|| {
            self.view.consensus_set(NETWORK, set_id).map(|mut set| {
                if let Some(at) = self.superseded.get(&set_id) {
                    set.superseded_at_source_ms = Some(*at);
                }
                set
            })
        })
    }

    /// Learn `next`, announced at time `announced_ms`, as the successor of `previous`.
    fn learn(
        &mut self,
        previous: u64,
        next: SccpLcConsensusSetV1,
        announced_ms: u64,
    ) -> Result<(), SccpLcError> {
        if let Some(existing) = self.get(next.set_id) {
            if existing.set_bytes != next.set_bytes
                || existing.valid_from_source_height != next.valid_from_source_height
            {
                return Err(SccpLcError::ConflictsWithStoredData(
                    SccpLcConflictV1::ConsensusSet {
                        set_id: next.set_id,
                    },
                ));
            }
            return Ok(());
        }
        if let Some(pending) = self.learned.get_mut(&previous) {
            pending.superseded_at_source_ms = Some(announced_ms);
        } else {
            self.superseded.insert(previous, announced_ms);
        }
        self.learned.insert(next.set_id, next);
        Ok(())
    }

    /// The delta of an advance: the learned and superseded sets, then `checkpoints` and `head`.
    fn into_delta(
        self,
        checkpoints: Vec<SccpLcCheckpointV1>,
        head: Option<SccpLcHeadV1>,
    ) -> SccpLcDeltaV1 {
        SccpLcDeltaV1 {
            new_sets: self.learned.into_values().collect(),
            superseded_sets: self
                .superseded
                .into_iter()
                .map(|(set_id, superseded_at_source_ms)| SccpLcSupersessionV1 {
                    set_id,
                    superseded_at_source_ms,
                })
                .collect(),
            checkpoints,
            head,
        }
    }
}

/// The light client's view of freshness while a call runs.
struct Ctx<'a> {
    profile: &'a BscChainProfileV1,
    params: &'a SccpLightClientParamsV1,
    now: u64,
    /// Newest set id.
    newest: u64,
    /// Time of the newest finalized epoch checkpoint announcing the newest set: it was the
    /// announced set then.
    newest_seen_ms: u64,
}

impl Ctx<'_> {
    fn check_header_time(&self, header: &HeaderV1) -> Result<(), SccpLcError> {
        if !self.profile.supports_time(header.time_ms) {
            return Err(BscLcError::UnsupportedFork {
                time_ms: header.time_ms,
            }
            .into());
        }
        if header.time_ms > self.now.saturating_add(MAX_SOURCE_FUTURE_MS) {
            return Err(SccpLcError::SourceTimeInFuture {
                source_ms: header.time_ms,
                taira_now_ms: self.now,
            });
        }
        Ok(())
    }

    fn check_fresh(&self, set: &SccpLcConsensusSetV1) -> Result<(), SccpLcError> {
        let expiry = set.superseded_at_source_ms.unwrap_or(self.newest_seen_ms);
        if is_set_fresh(Some(expiry), self.params.ws_bound_ms, self.now) {
            Ok(())
        } else {
            Err(SccpLcError::StaleSigningSet {
                set_id: set.set_id,
                stale_from_ms: expiry.saturating_add(self.params.ws_bound_ms),
            })
        }
    }

    /// Decode and link `headers` (1..=`max`), each in the fork window.
    fn linked(
        &self,
        headers: &[Vec<u8>],
        max: usize,
        kind: &'static str,
    ) -> Result<Vec<HeaderV1>, SccpLcError> {
        let count = headers.len();
        if count == 0 {
            return Err(SccpLcError::TooFewItems {
                kind,
                count,
                min: 1,
            });
        }
        if count > max {
            return Err(SccpLcError::TooManyItems { kind, count, max });
        }
        let decoded = headers
            .iter()
            .map(|header| decode_header(header))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, pair) in decoded.windows(2).enumerate() {
            let (parent, child) = (&pair[0], &pair[1]);
            if child.parent_hash != parent.hash
                || parent.number.checked_add(1) != Some(child.number)
                || child.time_ms <= parent.time_ms
            {
                return Err(BscLcError::AncestryBroken { index: index + 1 }.into());
            }
        }
        for header in &decoded {
            self.check_header_time(header)?;
        }
        Ok(decoded)
    }

    /// Verify `finality` under the stored set it names and return the vote data.
    fn verify_finality<V: SccpLcStateView + ?Sized>(
        &self,
        sets: &Sets<'_, V>,
        finality: &BscFinalityV1,
    ) -> Result<VoteDataV1, SccpLcError> {
        let attestation = decode_attestation(&finality.attestation)?;
        let target = attestation.data.target_number;
        let set = sets
            .get(finality.set_id)
            .ok_or(SccpLcError::UnknownSigningSet {
                set_id: finality.set_id,
            })?;
        let not_covering = BscLcError::SetDoesNotCover {
            set_id: finality.set_id,
            target,
        };
        if set.valid_from_source_height > target {
            return Err(not_covering.into());
        }
        match finality.successor_set_id {
            None if finality.set_id == self.newest => {}
            Some(successor_id) if finality.set_id != self.newest => {
                let successor = sets
                    .get(successor_id)
                    .ok_or(SccpLcError::UnknownSigningSet {
                        set_id: successor_id,
                    })?;
                if decode_set(&successor)?.previous_set_id != Some(finality.set_id)
                    || target >= successor.valid_from_source_height
                {
                    return Err(not_covering.into());
                }
            }
            _ => return Err(not_covering.into()),
        }
        self.check_fresh(&set)?;
        verify_quorum(&decode_set(&set)?.validators, &attestation)?;
        Ok(attestation.data)
    }

    /// Reject an epoch checkpoint above the newest set's checkpoint that announces another set;
    /// a checkpoint at a stored set's height must announce that set.
    fn check_announcements<V: SccpLcStateView + ?Sized>(
        &self,
        sets: &Sets<'_, V>,
        headers: &[HeaderV1],
    ) -> Result<(), SccpLcError> {
        let newest = newest_set(sets, self.newest)?;
        for header in headers
            .iter()
            .filter(|header| self.profile.is_epoch_checkpoint(header.number))
        {
            let announced = announced_set(header)?;
            if header.number > newest.checkpoint_height {
                if !announces(&newest, &announced) {
                    return Err(BscLcError::UnlearnedTransition {
                        checkpoint_height: header.number,
                    }
                    .into());
                }
            } else if let Some(stored) = sets.get(header.number) {
                let stored = decode_set(&stored)?;
                if stored.checkpoint_hash != header.hash || !announces(&stored, &announced) {
                    return Err(SccpLcError::ConflictsWithStoredData(
                        SccpLcConflictV1::ConsensusSet {
                            set_id: header.number,
                        },
                    ));
                }
            }
        }
        Ok(())
    }
}

fn newest_set<V: SccpLcStateView + ?Sized>(
    sets: &Sets<'_, V>,
    newest: u64,
) -> Result<BscValidatorSetV1, SccpLcError> {
    decode_set(
        &sets
            .get(newest)
            .ok_or(SccpLcError::UnknownSigningSet { set_id: newest })?,
    )
}

fn announces(set: &BscValidatorSetV1, announced: &AnnouncedSetV1) -> bool {
    set.validators == announced.validators && set.turn_length == announced.turn_length
}

fn count_bound(param: u32, hard: usize) -> usize {
    usize::try_from(param).unwrap_or(usize::MAX).min(hard)
}

fn check_source(data: &VoteDataV1, header: &HeaderV1) -> Result<(), SccpLcError> {
    if data.source_number == header.number && data.source_hash == header.hash {
        Ok(())
    } else {
        Err(BscLcError::FinalityMismatch.into())
    }
}

// ---------------------------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------------------------

/// Verify a BSC bootstrap (§4.13.2, §4.14.3 `InitializeLightClient`).
///
/// Both headers are consecutive epoch checkpoints in the fork window and not in the future, the
/// checkpoint is fresh at `taira_now_ms`, and both rosters are valid. The installed set covers
/// targets from `checkpoint + minerHistoryCheckLen(previous) + 1`.
pub(super) fn verify_bootstrap(
    profile: &BscChainProfileV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &BscLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    let checkpoint = decode_header(&bootstrap.checkpoint_header)?;
    let previous = decode_header(&bootstrap.previous_checkpoint_header)?;
    let ctx = Ctx {
        profile,
        params,
        now: taira_now_ms,
        newest: checkpoint.number,
        newest_seen_ms: checkpoint.time_ms,
    };
    ctx.check_header_time(&checkpoint)?;
    if !profile.is_epoch_checkpoint(checkpoint.number)
        || previous.number.checked_add(profile.epoch_length) != Some(checkpoint.number)
        || previous.time_ms >= checkpoint.time_ms
    {
        return Err(BscLcError::InvalidBootstrap.into());
    }
    let announced = announced_set(&checkpoint)?;
    validate_roster_keys(&announced.validators)?;
    let prior = announced_set(&previous)?;
    let valid_from = checkpoint
        .number
        .checked_add(miner_history_check_len(
            prior.validators.len(),
            prior.turn_length,
        )?)
        .and_then(|height| height.checked_add(1))
        .ok_or(BscLcError::Overflow)?;
    let set = set_record(
        BscValidatorSetV1 {
            checkpoint_height: checkpoint.number,
            checkpoint_hash: checkpoint.hash,
            previous_set_id: None,
            turn_length: announced.turn_length,
            validators: announced.validators,
        },
        valid_from,
    )?;
    ctx.check_fresh(&set)?;
    let head = SccpLcHeadV1 {
        latest_set_id: checkpoint.number,
        latest_finalized: checkpoint.point(),
        last_progress_taira_ms: taira_now_ms,
    };
    Ok(SccpLcInitialStateV1 {
        light_client: SccpLightClientV1 {
            params: *params,
            head,
            frozen: None,
            state_hash: state_hash(params, &head, None),
        },
        purge: SccpLcPurgeV1::DiscardUnvetted,
        superseded_sets: Vec::new(),
        sets: vec![set],
        checkpoints: vec![SccpLcCheckpointV1 {
            data: checkpoint.checkpoint(),
            recorded_at_taira_ms: taira_now_ms,
            origin: SccpLcCheckpointOriginV1::Parliament,
        }],
    })
}

// ---------------------------------------------------------------------------------------------
// Advance
// ---------------------------------------------------------------------------------------------

/// Verify a BSC advance and return what to write.
pub(super) fn apply_advance<V: SccpLcStateView + ?Sized>(
    profile: &BscChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    advance: &BscLcAdvanceV1,
    taira_now_ms: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    let params = &light_client.params;
    let count = advance.steps.len();
    if count == 0 {
        return Err(SccpLcError::TooFewItems {
            kind: "advance steps",
            count,
            min: 1,
        });
    }
    let max = count_bound(params.max_updates_per_advance, BSC_MAX_STEPS_PER_ADVANCE);
    if count > max {
        return Err(SccpLcError::TooManyItems {
            kind: "advance steps",
            count,
            max,
        });
    }
    let mut ctx = Ctx {
        profile,
        params,
        now: taira_now_ms,
        newest: light_client.head.latest_set_id,
        newest_seen_ms: light_client.head.latest_finalized.source_time_ms,
    };
    let mut sets = Sets::new(view);
    let mut recorder = CheckpointRecorder::new(
        view,
        NETWORK,
        SccpLcCheckpointOriginV1::Advance,
        taira_now_ms,
    );
    let mut latest_finalized = light_client.head.latest_finalized;
    let max_headers = count_bound(params.max_segment_headers, BSC_MAX_SEGMENT_HEADERS);
    for step in &advance.steps {
        let headers = ctx.linked(&step.headers, max_headers, "advance headers")?;
        let (first, last) = (&headers[0], &headers[headers.len() - 1]);
        let data = ctx.verify_finality(&sets, &step.finality)?;
        check_source(&data, last)?;
        let newest = newest_set(&sets, ctx.newest)?;
        let transition = if profile.is_epoch_checkpoint(first.number)
            && first.number > newest.checkpoint_height
        {
            let announced = announced_set(first)?;
            (!announces(&newest, &announced)).then_some(announced)
        } else {
            None
        };
        match transition {
            Some(announced) => {
                let invalid = BscLcError::InvalidTransition {
                    checkpoint_height: first.number,
                };
                let valid_from = first
                    .number
                    .checked_add(miner_history_check_len(
                        newest.validators.len(),
                        newest.turn_length,
                    )?)
                    .and_then(|height| height.checked_add(1))
                    .ok_or(BscLcError::Overflow)?;
                if step.finality.set_id != ctx.newest || data.target_number >= valid_from {
                    return Err(invalid.into());
                }
                ctx.check_announcements(&sets, &headers[1..])?;
                validate_roster_keys(&announced.validators)?;
                let next = set_record(
                    BscValidatorSetV1 {
                        checkpoint_height: first.number,
                        checkpoint_hash: first.hash,
                        previous_set_id: Some(ctx.newest),
                        turn_length: announced.turn_length,
                        validators: announced.validators,
                    },
                    valid_from,
                )?;
                sets.learn(ctx.newest, next, first.time_ms)?;
                ctx.newest = first.number;
            }
            None => ctx.check_announcements(&sets, &headers)?,
        }
        recorder.record(first.checkpoint())?;
        recorder.record(last.checkpoint())?;
        // Every epoch checkpoint at or above the newest set's own announces the newest set (the
        // transition and `check_announcements` ensure it); the newest finalized one refreshes it.
        if let Some(announcement) = headers.iter().rev().find(|header| {
            profile.is_epoch_checkpoint(header.number) && header.number >= ctx.newest
        }) && announcement.number > latest_finalized.source_height
        {
            recorder.record(announcement.checkpoint())?;
            latest_finalized = announcement.point();
            ctx.newest_seen_ms = announcement.time_ms;
        }
    }
    let moved = ctx.newest != light_client.head.latest_set_id
        || latest_finalized != light_client.head.latest_finalized;
    Ok(sets.into_delta(
        recorder.into_vec(),
        moved.then_some(SccpLcHeadV1 {
            latest_set_id: ctx.newest,
            latest_finalized,
            last_progress_taira_ms: taira_now_ms,
        }),
    ))
}

/// Verify a `Backfill` segment and return the checkpoint of its first header.
pub(super) fn apply_backfill<V: SccpLcStateView + ?Sized>(
    profile: &BscChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    segment: &BscHeaderSegmentV1,
    taira_now_ms: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    let count = segment.headers.len();
    if count < 2 {
        return Err(SccpLcError::TooFewItems {
            kind: "backfill headers",
            count,
            min: 2,
        });
    }
    let params = &light_client.params;
    let ctx = Ctx {
        profile,
        params,
        now: taira_now_ms,
        newest: light_client.head.latest_set_id,
        newest_seen_ms: light_client.head.latest_finalized.source_time_ms,
    };
    let max = count_bound(params.max_backfill_headers, BSC_MAX_SEGMENT_HEADERS);
    let headers = ctx.linked(&segment.headers, max, "backfill headers")?;
    let last = &headers[headers.len() - 1];
    let stored = view
        .checkpoint(NETWORK, last.number)
        .ok_or(SccpLcError::UnknownCheckpoint {
            source_height: last.number,
        })?;
    if stored.data.block_hash != last.hash {
        return Err(BscLcError::CheckpointMismatch {
            source_height: last.number,
        }
        .into());
    }
    let mut recorder = CheckpointRecorder::new(
        view,
        NETWORK,
        SccpLcCheckpointOriginV1::Backfill,
        taira_now_ms,
    );
    recorder.record(headers[0].checkpoint())?;
    Ok(SccpLcDeltaV1 {
        checkpoints: recorder.into_vec(),
        ..SccpLcDeltaV1::default()
    })
}

// ---------------------------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------------------------

/// Verify a BSC inbound or void proof.
pub(super) fn verify_proof<V: SccpLcStateView + ?Sized>(
    profile: &BscChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    proof: &BscSourceProofV1,
    taira_now_ms: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    let params = &light_client.params;
    let ctx = Ctx {
        profile,
        params,
        now: taira_now_ms,
        newest: light_client.head.latest_set_id,
        newest_seen_ms: light_client.head.latest_finalized.source_time_ms,
    };
    let sets = Sets::new(view);
    let max = count_bound(params.max_ancestry_headers, BSC_MAX_SEGMENT_HEADERS);
    let headers = ctx.linked(&proof.headers, max, "ancestry headers")?;
    ctx.check_announcements(&sets, &headers)?;
    let (event, last) = (&headers[0], &headers[headers.len() - 1]);
    let mut recorder =
        CheckpointRecorder::new(view, NETWORK, SccpLcCheckpointOriginV1::Proof, taira_now_ms);
    match &proof.anchor {
        BscProofAnchorV1::Finality(finality) => {
            check_source(&ctx.verify_finality(&sets, finality)?, last)?;
            recorder.record(last.checkpoint())?;
        }
        BscProofAnchorV1::StoredCheckpoint(reference) => {
            let stored = view.checkpoint(NETWORK, reference.source_height).ok_or(
                SccpLcError::UnknownCheckpoint {
                    source_height: reference.source_height,
                },
            )?;
            if reference.source_height != last.number || stored.data.block_hash != last.hash {
                return Err(BscLcError::CheckpointMismatch {
                    source_height: reference.source_height,
                }
                .into());
            }
        }
    }
    recorder.record(event.checkpoint())?;
    let receipt = ethereum::open_receipt(
        event.receipts_root,
        proof.transaction_index,
        &proof.receipt_proof,
    )
    .map_err(receipt_error)?;
    let locator = SccpSourceLocatorV1 {
        source_height: event.number,
        block_hash: event.hash,
        index_in_block: proof.transaction_index,
    };
    let event = ethereum::select_event(&receipt, proof.event, locator).map_err(receipt_error)?;
    Ok(SccpVerifiedProofV1 {
        event,
        checkpoints: recorder.into_vec(),
    })
}

// ---------------------------------------------------------------------------------------------
// Equivocation
// ---------------------------------------------------------------------------------------------

/// What one verified record asserts: the voted target and the finalized blocks.
struct ClaimsV1 {
    target: (u64, [u8; 32]),
    /// `(height, hash, time)`; the attested source has no time without headers.
    blocks: Vec<(u64, [u8; 32], Option<u64>)>,
}

fn verify_evidence<V: SccpLcStateView + ?Sized>(
    ctx: &Ctx<'_>,
    view: &V,
    evidence: &BscLcEvidenceV1,
) -> Result<ClaimsV1, SccpLcError> {
    let sets = Sets::new(view);
    let data = ctx.verify_finality(&sets, &evidence.finality)?;
    let blocks = if evidence.headers.is_empty() {
        vec![(data.source_number, data.source_hash, None)]
    } else {
        let max = count_bound(ctx.params.max_ancestry_headers, BSC_MAX_SEGMENT_HEADERS);
        let headers = ctx.linked(&evidence.headers, max, "evidence headers")?;
        check_source(&data, &headers[headers.len() - 1])?;
        headers
            .iter()
            .map(|header| (header.number, header.hash, Some(header.time_ms)))
            .collect()
    };
    Ok(ClaimsV1 {
        target: (data.target_number, data.target_hash),
        blocks,
    })
}

fn blocks_conflict(
    (a_height, a_hash, a_time): (u64, [u8; 32], Option<u64>),
    (b_height, b_hash, b_time): (u64, [u8; 32], Option<u64>),
) -> bool {
    if a_height == b_height {
        return a_hash != b_hash;
    }
    match (a_time, b_time) {
        (Some(a_time), Some(b_time)) => (a_height < b_height) != (a_time < b_time),
        _ => false,
    }
}

/// Verify two conflicting BSC records and return the freeze reason.
pub(super) fn verify_equivocation<V: SccpLcStateView + ?Sized>(
    profile: &BscChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    first: (&BscLcEvidenceV1, &[u8]),
    second: (&BscLcEvidenceV1, &[u8]),
    taira_now_ms: u64,
) -> Result<SccpLcFreezeReasonV1, SccpLcError> {
    if first.1 == second.1 {
        return Err(SccpLcError::EvidenceNotConflicting);
    }
    let ctx = Ctx {
        profile,
        params: &light_client.params,
        now: taira_now_ms,
        newest: light_client.head.latest_set_id,
        newest_seen_ms: light_client.head.latest_finalized.source_time_ms,
    };
    let a = verify_evidence(&ctx, view, first.0)?;
    let b = verify_evidence(&ctx, view, second.0)?;
    let double_vote = a.target.0 == b.target.0 && a.target.1 != b.target.1;
    let blocks = a
        .blocks
        .iter()
        .any(|x| b.blocks.iter().any(|y| blocks_conflict(*x, *y)));
    if !double_vote && !blocks {
        return Err(SccpLcError::EvidenceNotConflicting);
    }
    let mut hashes = [keccak256(&[first.1]), keccak256(&[second.1])];
    hashes.sort_unstable();
    Ok(SccpLcFreezeReasonV1::Equivocation(
        SccpLcEquivocationFreezeV1 {
            evidence_hash: keccak256(&[
                b"SCCP/LC/EVIDENCE/V1",
                &[tag(NETWORK)],
                &hashes[0],
                &hashes[1],
            ]),
        },
    ))
}

// ---------------------------------------------------------------------------------------------
// Freshness and work
// ---------------------------------------------------------------------------------------------

/// Taira time from which the newest set is stale: `ws_bound_ms` after the newest finalized epoch
/// checkpoint that (re-)announces it.
pub(super) fn weak_subjectivity_deadline_ms(light_client: &SccpLightClientV1) -> u64 {
    light_client
        .head
        .latest_finalized
        .source_time_ms
        .saturating_add(light_client.params.ws_bound_ms)
}

/// Whether the newest set is beyond the weak-subjectivity bound.
pub(super) fn is_aged(light_client: &SccpLightClientV1, taira_now_ms: u64) -> bool {
    weak_subjectivity_deadline_ms(light_client) <= taira_now_ms
}

/// Supersession of an aged light client's newest set, recorded when a fresh bootstrap
/// re-initializes it without a purge: the set was last seen announced at the newest finalized
/// epoch checkpoint.
pub(super) fn aged_supersessions<V: SccpLcStateView + ?Sized>(
    view: &V,
    light_client: &SccpLightClientV1,
) -> Vec<SccpLcSupersessionV1> {
    let set_id = light_client.head.latest_set_id;
    if view
        .consensus_set(NETWORK, set_id)
        .is_some_and(|set| set.is_current())
    {
        vec![SccpLcSupersessionV1 {
            set_id,
            superseded_at_source_ms: light_client.head.latest_finalized.source_time_ms,
        }]
    } else {
        Vec::new()
    }
}

fn headers_work(headers: &[Vec<u8>]) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        native_headers: u32::try_from(headers.len()).unwrap_or(u32::MAX),
        native_header_bytes: headers
            .iter()
            .map(|header| u64::try_from(header.len()).unwrap_or(u64::MAX))
            .fold(0, u64::saturating_add),
        ..SccpVerifierWorkV1::default()
    }
}

/// Work of an advance: its headers and one BLS check per step.
pub(super) fn advance_work(advance: &BscLcAdvanceV1) -> SccpVerifierWorkV1 {
    advance
        .steps
        .iter()
        .map(|step| SccpVerifierWorkV1 {
            bls_vote_attestations: 1,
            ..headers_work(&step.headers)
        })
        .fold(SccpVerifierWorkV1::default(), |total, work| {
            total.checked_add(&work).unwrap_or(total)
        })
}

/// Work of a backfill: its headers.
pub(super) fn segment_work(segment: &BscHeaderSegmentV1) -> SccpVerifierWorkV1 {
    headers_work(&segment.headers)
}

/// Work of a proof: one proof, its headers and its attestation.
pub(super) fn proof_work(proof: &BscSourceProofV1) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        proofs: 1,
        bls_vote_attestations: u32::from(matches!(proof.anchor, BscProofAnchorV1::Finality(_))),
        ..headers_work(&proof.headers)
    }
}

/// Work of one evidence record: its attestation and headers.
pub(super) fn evidence_work(evidence: &BscLcEvidenceV1) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        bls_vote_attestations: 1,
        ..headers_work(&evidence.headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        light_client::{
            SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcEvidenceV1, SccpLcSegmentV1,
            SccpNormalizedEventV1, SccpSourceEmitterV1, SccpSourceProofV1,
            apply_advance_with_profiles, ethereum::EthereumLogRefV1,
            initialize_light_client_with_profiles, is_aged_with_profiles,
            profile::SccpChainProfilesV1, state::SccpLcMemoryStateV1,
            verify_equivocation_with_profiles, verify_proof_with_profiles,
        },
        test_support::{
            bsc::SyntheticParliaChainV1,
            ethereum::{receipt_root_and_proof, successful_receipt, transfer_log},
        },
        v1::evm_abi::TransferToTairaLogV1,
    };
    use iroha_data_model::sccp::light_client::SccpLcInitExpectationV1;

    const EMITTER: [u8; 20] = [0x42; 20];

    fn profiles(chain: &SyntheticParliaChainV1) -> SccpChainProfilesV1 {
        SccpChainProfilesV1::genesis().with_bsc(*chain.profile())
    }

    fn params() -> SccpLightClientParamsV1 {
        SccpLightClientParamsV1::defaults_for(NETWORK).expect("external")
    }

    /// Install a light client from the checkpoint of `epoch` and return the storage and the
    /// Taira time.
    fn installed(chain: &SyntheticParliaChainV1, epoch: u64) -> (SccpLcMemoryStateV1, u64) {
        let now = SyntheticParliaChainV1::time_ms(epoch * 1_000) + 1_000;
        let mut memory = SccpLcMemoryStateV1::new();
        let initial = initialize_light_client_with_profiles(
            &profiles(chain),
            &memory,
            NETWORK,
            SccpLcInitExpectationV1::Absent,
            &params(),
            &chain.bootstrap(epoch),
            now,
        )
        .expect("bootstrap verifies");
        memory.install(NETWORK, &initial);
        (memory, now)
    }

    fn advance(
        chain: &SyntheticParliaChainV1,
        memory: &mut SccpLcMemoryStateV1,
        steps: Vec<BscAdvanceStepV1>,
        now: u64,
    ) -> Result<SccpLcDeltaV1, SccpLcError> {
        let bytes = SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 { steps })
            .to_bytes()
            .expect("bounded");
        let delta = apply_advance_with_profiles(&profiles(chain), memory, NETWORK, &bytes, now)?;
        memory.apply(NETWORK, &delta);
        Ok(delta)
    }

    fn initialize(
        chain: &SyntheticParliaChainV1,
        bootstrap: BscLcBootstrapV1,
        now: u64,
    ) -> Result<SccpLcInitialStateV1, SccpLcError> {
        initialize_light_client_with_profiles(
            &profiles(chain),
            &SccpLcMemoryStateV1::new(),
            NETWORK,
            SccpLcInitExpectationV1::Absent,
            &params(),
            &SccpLcBootstrapDataV1::Bsc(bootstrap)
                .to_bootstrap()
                .expect("frame"),
            now,
        )
    }

    #[test]
    fn bootstrap_installs_the_announced_set_from_its_activation_height() {
        let chain = SyntheticParliaChainV1::new([1; 32], 21, 16);
        let (memory, _) = installed(&chain, 5);
        let light_client = memory.light_client(NETWORK).expect("installed");
        assert_eq!(light_client.head.latest_set_id, 5_000);
        let set = memory.consensus_set(NETWORK, 5_000).expect("set");
        // (21 / 2 + 1) * 16 - 1 = 175.
        assert_eq!(set.valid_from_source_height, 5_176);
        assert_eq!(decode_set(&set).expect("decodes").validators.len(), 21);
        let stale = SyntheticParliaChainV1::time_ms(5_000) + params().ws_bound_ms;
        assert!(matches!(
            initialize(&chain, chain.bootstrap_data(5), stale),
            Err(SccpLcError::StaleSigningSet { set_id: 5_000, .. })
        ));
        let mut skewed = chain.bootstrap_data(5);
        skewed.previous_checkpoint_header = chain.header(3_000).rlp;
        assert_eq!(
            initialize(&chain, skewed, stale - 1),
            Err(BscLcError::InvalidBootstrap.into())
        );
        let mut unsupported = chain.bootstrap_data(5);
        unsupported.checkpoint_header = chain.header(5_001).rlp;
        assert_eq!(
            initialize(&chain, unsupported, stale - 1),
            Err(BscLcError::InvalidBootstrap.into())
        );
    }

    #[test]
    fn unchanged_set_advances_move_the_head_at_re_announcements_and_are_idempotent() {
        let chain = SyntheticParliaChainV1::new([2; 32], 21, 16);
        let (mut memory, _) = installed(&chain, 5);
        let now = SyntheticParliaChainV1::time_ms(6_010) + 2_000;
        // A finalized block without an epoch checkpoint records checkpoints, not a head.
        let plain = chain.step(5_397, 5_400, 5_000, None);
        let delta = advance(&chain, &mut memory, vec![plain], now).expect("advances");
        assert!(delta.head.is_none());
        assert_eq!(delta.checkpoints.len(), 2);
        // The next epoch checkpoint re-announces the set and becomes the head.
        let step = chain.step(6_000, 6_003, 5_000, None);
        let delta = advance(&chain, &mut memory, vec![step.clone()], now).expect("advances");
        let head = delta.head.expect("moved");
        assert_eq!(head.latest_finalized.source_height, 6_000);
        assert_eq!(head.latest_set_id, 5_000);
        assert!(delta.new_sets.is_empty());
        assert_eq!(delta.checkpoints.len(), 2);
        let again = advance(&chain, &mut memory, vec![step], now).expect("idempotent");
        assert!(again.is_empty());
        let early = chain.step(5_100, 5_100, 5_000, None);
        assert_eq!(
            advance(&chain, &mut memory, vec![early], now),
            Err(BscLcError::SetDoesNotCover {
                set_id: 5_000,
                target: 5_101
            }
            .into())
        );
        assert!(matches!(
            advance(&chain, &mut memory, Vec::new(), now),
            Err(SccpLcError::TooFewItems { .. })
        ));
    }

    #[test]
    fn the_newest_set_stays_fresh_only_from_its_newest_re_announcement() {
        let chain = SyntheticParliaChainV1::new([12; 32], 21, 16);
        let (mut memory, _) = installed(&chain, 5);
        let ws = params().ws_bound_ms;
        let stale = SyntheticParliaChainV1::time_ms(5_000) + ws;
        // Finalized blocks after the bootstrap checkpoint do not extend the set's freshness.
        advance(
            &chain,
            &mut memory,
            vec![chain.step(5_900, 5_901, 5_000, None)],
            stale - 1,
        )
        .expect("fresh until the bound");
        let light_client = memory.light_client(NETWORK).expect("installed");
        assert_eq!(weak_subjectivity_deadline_ms(&light_client), stale);
        assert!(matches!(
            advance(
                &chain,
                &mut memory,
                vec![chain.step(5_950, 5_951, 5_000, None)],
                stale
            ),
            Err(SccpLcError::StaleSigningSet { set_id: 5_000, .. })
        ));
        // A re-announcement does.
        let (mut memory, _) = installed(&chain, 5);
        advance(
            &chain,
            &mut memory,
            vec![chain.step(7_000, 7_002, 5_000, None)],
            stale - 1,
        )
        .expect("re-announced");
        let light_client = memory.light_client(NETWORK).expect("installed");
        assert_eq!(
            weak_subjectivity_deadline_ms(&light_client),
            SyntheticParliaChainV1::time_ms(7_000) + ws
        );
        advance(
            &chain,
            &mut memory,
            vec![chain.step(7_500, 7_501, 5_000, None)],
            stale,
        )
        .expect("fresh from the re-announcement");
    }

    fn key_validations() -> usize {
        BLS_KEY_VALIDATIONS.with(core::cell::Cell::get)
    }

    #[test]
    fn roster_keys_are_validated_once_when_a_set_is_learned() {
        let chain = SyntheticParliaChainV1::new([13; 32], 21, 16).with_transition(7, 1, 24, 8);
        let before = key_validations();
        let (mut memory, _) = installed(&chain, 5);
        assert_eq!(key_validations() - before, 21, "the installed set only");
        let now = SyntheticParliaChainV1::time_ms(7_010) + 2_000;
        let before = key_validations();
        advance(
            &chain,
            &mut memory,
            vec![chain.step(6_000, 6_002, 5_000, None)],
            now,
        )
        .expect("re-announcement");
        assert_eq!(key_validations(), before, "stored and re-announced sets");
        advance(
            &chain,
            &mut memory,
            vec![chain.step(7_000, 7_002, 5_000, None)],
            now,
        )
        .expect("transition");
        assert_eq!(key_validations() - before, 24, "the learned set once");
        let before = key_validations();
        let again = advance(
            &chain,
            &mut memory,
            vec![chain.step(7_000, 7_002, 5_000, Some(7_000))],
            now,
        )
        .expect("idempotent");
        assert!(again.is_empty());
        assert_eq!(
            key_validations(),
            before,
            "a stored transition is not re-validated"
        );
        let (receipt_chain, receipt_proof) = burn_chain(14, 5_390);
        let (proof_memory, _) = installed(&receipt_chain, 5);
        let before_proof = key_validations();
        let step = receipt_chain.step(5_390, 5_400, 5_000, None);
        let proof = BscSourceProofV1 {
            anchor: BscProofAnchorV1::Finality(step.finality),
            headers: step.headers,
            transaction_index: 0,
            receipt_proof,
            event: transfer_selector(),
        };
        let bytes = SccpSourceProofV1::Bsc(proof).to_bytes().expect("bounded");
        verify_proof_with_profiles(
            &profiles(&receipt_chain),
            &proof_memory,
            NETWORK,
            &bytes,
            SyntheticParliaChainV1::time_ms(5_400) + 2_000,
        )
        .expect("proof verifies");
        assert_eq!(key_validations(), before_proof, "proofs use stored keys");
        assert_eq!(before_proof - before, 21, "the proof client's bootstrap");
    }

    #[test]
    fn quorum_and_signature_are_enforced() {
        let chain = SyntheticParliaChainV1::new([3; 32], 21, 16);
        let (mut memory, _) = installed(&chain, 5);
        let now = SyntheticParliaChainV1::time_ms(5_400) + 2_000;
        let mut thin = chain.step(5_400, 5_400, 5_000, None);
        thin.finality.attestation = chain.attestation(5_000, 13, 5_400);
        assert_eq!(
            advance(&chain, &mut memory, vec![thin], now),
            Err(BscLcError::InsufficientQuorum {
                signers: 13,
                required: 14
            }
            .into())
        );
        let mut quorum_only = chain.step(5_400, 5_400, 5_000, None);
        quorum_only.finality.attestation = chain.attestation(5_000, 14, 5_400);
        advance(&chain, &mut memory, vec![quorum_only], now).expect("exactly ⌈2n/3⌉ signers");
        let mut forged = chain.step(5_401, 5_401, 5_000, None);
        forged.finality.attestation = chain.misattributed_attestation(5_000, 5_401);
        assert_eq!(
            advance(&chain, &mut memory, vec![forged], now),
            Err(BscLcError::InvalidAggregateSignature.into())
        );
        let mut mismatched = chain.step(5_402, 5_402, 5_000, None);
        mismatched.finality.attestation = chain.attestation(5_000, 21, 5_401);
        assert_eq!(
            advance(&chain, &mut memory, vec![mismatched], now),
            Err(BscLcError::FinalityMismatch.into())
        );
    }

    #[test]
    fn transitions_are_learned_in_order_and_old_sets_need_their_successor() {
        let chain = SyntheticParliaChainV1::new([4; 32], 21, 16).with_transition(7, 1, 24, 8);
        let (mut memory, _) = installed(&chain, 5);
        let now = SyntheticParliaChainV1::time_ms(7_010) + 2_000;
        let skipping = chain.step(6_990, 7_010, 5_000, None);
        assert_eq!(
            advance(&chain, &mut memory, vec![skipping], now),
            Err(BscLcError::UnlearnedTransition {
                checkpoint_height: 7_000
            }
            .into())
        );
        let transition = chain.step(7_000, 7_002, 5_000, None);
        let delta = advance(&chain, &mut memory, vec![transition], now).expect("transition");
        assert_eq!(delta.new_sets.len(), 1);
        assert_eq!(delta.new_sets[0].set_id, 7_000);
        assert_eq!(delta.new_sets[0].valid_from_source_height, 7_176);
        assert_eq!(delta.superseded_sets[0].set_id, 5_000);
        assert_eq!(delta.head.expect("moved").latest_set_id, 7_000);
        let now = SyntheticParliaChainV1::time_ms(7_300) + 2_000;
        advance(
            &chain,
            &mut memory,
            vec![chain.step(7_300, 7_300, 7_000, None)],
            now,
        )
        .expect("the new set signs");
        assert_eq!(
            advance(
                &chain,
                &mut memory,
                vec![chain.step(7_100, 7_100, 5_000, None)],
                now
            ),
            Err(BscLcError::SetDoesNotCover {
                set_id: 5_000,
                target: 7_101
            }
            .into())
        );
        advance(
            &chain,
            &mut memory,
            vec![chain.step(7_100, 7_100, 5_000, Some(7_000))],
            now,
        )
        .expect("the old set with its successor");
        assert_eq!(
            advance(
                &chain,
                &mut memory,
                vec![chain.step(7_200, 7_200, 5_000, Some(7_000))],
                now
            ),
            Err(BscLcError::SetDoesNotCover {
                set_id: 5_000,
                target: 7_201
            }
            .into())
        );
    }

    #[test]
    fn transition_targets_must_precede_the_new_set() {
        let chain = SyntheticParliaChainV1::new([10; 32], 21, 16).with_transition(7, 1, 24, 8);
        let (mut memory, _) = installed(&chain, 5);
        let now = SyntheticParliaChainV1::time_ms(7_200) + 2_000;
        let late = chain.step(7_000, 7_180, 5_000, None);
        assert_eq!(
            advance(&chain, &mut memory, vec![late], now),
            Err(BscLcError::InvalidTransition {
                checkpoint_height: 7_000
            }
            .into())
        );
    }

    #[test]
    fn stale_sets_are_refused_and_aged_light_clients_are_reported() {
        let chain = SyntheticParliaChainV1::new([5; 32], 21, 16);
        let (mut memory, now) = installed(&chain, 5);
        let light_client = memory.light_client(NETWORK).expect("installed");
        let deadline = weak_subjectivity_deadline_ms(&light_client);
        assert_eq!(
            deadline,
            SyntheticParliaChainV1::time_ms(5_000) + params().ws_bound_ms
        );
        assert!(!is_aged(&light_client, now));
        assert!(is_aged(&light_client, deadline));
        assert_eq!(
            is_aged_with_profiles(&profiles(&chain), &memory, NETWORK, deadline),
            Ok(true)
        );
        let step = chain.step(5_400, 5_400, 5_000, None);
        assert!(matches!(
            advance(&chain, &mut memory, vec![step], deadline),
            Err(SccpLcError::StaleSigningSet { set_id: 5_000, .. })
        ));
        assert_eq!(aged_supersessions(&memory, &light_client).len(), 1);
    }

    /// A chain with a burn receipt at `height` and the receipt's proof.
    fn burn_chain(seed: u8, height: u64) -> (SyntheticParliaChainV1, EthereumNativeMptProofV1) {
        let log = TransferToTairaLogV1 {
            message_id: [9; 32],
            sender: [3; 20],
            nonce: 4,
            payload: vec![1, 2, 3],
        };
        let receipts = vec![successful_receipt(vec![transfer_log(EMITTER, &log)])];
        let (root, proof) = receipt_root_and_proof(&receipts, 0);
        (
            SyntheticParliaChainV1::new([seed; 32], 21, 16).with_receipts_root(height, root),
            proof,
        )
    }

    fn transfer_selector() -> EthereumEventSelectorV1 {
        EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 })
    }

    #[test]
    fn proofs_open_the_receipt_of_a_finalized_block() {
        let (chain, receipt_proof) = burn_chain(6, 5_390);
        let (memory, _) = installed(&chain, 5);
        let now = SyntheticParliaChainV1::time_ms(5_400) + 2_000;
        let step = chain.step(5_390, 5_400, 5_000, None);
        let proof = BscSourceProofV1 {
            anchor: BscProofAnchorV1::Finality(step.finality),
            headers: step.headers,
            transaction_index: 0,
            receipt_proof,
            event: transfer_selector(),
        };
        let bytes = SccpSourceProofV1::Bsc(proof.clone())
            .to_bytes()
            .expect("bounded");
        let verified = verify_proof_with_profiles(&profiles(&chain), &memory, NETWORK, &bytes, now)
            .expect("proof verifies");
        let SccpNormalizedEventV1::TransferToTaira {
            emitter,
            nonce,
            locator,
            ..
        } = verified.event
        else {
            panic!("transfer expected");
        };
        assert_eq!(emitter, SccpSourceEmitterV1::Evm(EMITTER));
        assert_eq!(nonce, 4);
        assert_eq!(locator.source_height, 5_390);
        assert_eq!(locator.block_hash, chain.header(5_390).hash);
        assert_eq!(verified.checkpoints.len(), 2);
        let mut broken = proof;
        broken.headers.remove(3);
        let bytes = SccpSourceProofV1::Bsc(broken).to_bytes().expect("bounded");
        assert_eq!(
            verify_proof_with_profiles(&profiles(&chain), &memory, NETWORK, &bytes, now),
            Err(BscLcError::AncestryBroken { index: 3 }.into())
        );
    }

    #[test]
    fn backfill_and_stored_checkpoint_anchors_prove_older_blocks() {
        let (chain, receipt_proof) = burn_chain(7, 4_985);
        let (mut memory, now) = installed(&chain, 5);
        let segment = BscHeaderSegmentV1 {
            headers: (4_990..=5_000)
                .map(|height| chain.header(height).rlp)
                .collect(),
        };
        let bytes = SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Bsc(segment),
        }
        .to_bytes()
        .expect("bounded");
        let delta = apply_advance_with_profiles(&profiles(&chain), &memory, NETWORK, &bytes, now)
            .expect("backfill");
        assert_eq!(delta.checkpoints[0].data.source_height, 4_990);
        assert_eq!(
            delta.checkpoints[0].origin,
            SccpLcCheckpointOriginV1::Backfill
        );
        memory.apply(NETWORK, &delta);
        let proof = BscSourceProofV1 {
            anchor: BscProofAnchorV1::StoredCheckpoint(BscStoredCheckpointRefV1 {
                source_height: 4_990,
            }),
            headers: (4_985..=4_990)
                .map(|height| chain.header(height).rlp)
                .collect(),
            transaction_index: 0,
            receipt_proof,
            event: transfer_selector(),
        };
        let bytes = SccpSourceProofV1::Bsc(proof.clone())
            .to_bytes()
            .expect("bounded");
        let verified = verify_proof_with_profiles(&profiles(&chain), &memory, NETWORK, &bytes, now)
            .expect("anchored on the backfilled checkpoint");
        assert_eq!(verified.event.locator().source_height, 4_985);
        let mut wrong = proof;
        wrong.transaction_index = 1;
        let bytes = SccpSourceProofV1::Bsc(wrong).to_bytes().expect("bounded");
        assert!(matches!(
            verify_proof_with_profiles(&profiles(&chain), &memory, NETWORK, &bytes, now),
            Err(SccpLcError::Bsc(BscLcError::Receipt(_)))
        ));
    }

    #[test]
    fn double_votes_freeze_and_identical_records_do_not() {
        let chain = SyntheticParliaChainV1::new([8; 32], 21, 16);
        let (memory, _) = installed(&chain, 5);
        let now = SyntheticParliaChainV1::time_ms(5_400) + 2_000;
        let honest = BscLcEvidenceV1 {
            finality: chain.step(5_400, 5_400, 5_000, None).finality,
            headers: vec![chain.header(5_400).rlp],
        };
        let double = BscLcEvidenceV1 {
            finality: BscFinalityV1 {
                set_id: 5_000,
                successor_set_id: None,
                attestation: chain.double_vote(5_000, 5_400),
            },
            headers: Vec::new(),
        };
        let a = SccpLcEvidenceV1::Bsc(honest.clone())
            .to_bytes()
            .expect("bounded");
        let b = SccpLcEvidenceV1::Bsc(double).to_bytes().expect("bounded");
        let reason =
            verify_equivocation_with_profiles(&profiles(&chain), &memory, NETWORK, &a, &b, now)
                .expect("conflict");
        assert!(matches!(reason, SccpLcFreezeReasonV1::Equivocation(_)));
        assert_eq!(
            verify_equivocation_with_profiles(&profiles(&chain), &memory, NETWORK, &a, &a, now),
            Err(SccpLcError::EvidenceNotConflicting)
        );
        let later = BscLcEvidenceV1 {
            finality: chain.step(5_401, 5_401, 5_000, None).finality,
            headers: Vec::new(),
        };
        let c = SccpLcEvidenceV1::Bsc(later).to_bytes().expect("bounded");
        assert_eq!(
            verify_equivocation_with_profiles(&profiles(&chain), &memory, NETWORK, &a, &c, now),
            Err(SccpLcError::EvidenceNotConflicting)
        );
    }

    #[test]
    fn header_and_attestation_codecs_are_strict() {
        let chain = SyntheticParliaChainV1::new([9; 32], 4, 1);
        let header = chain.header(1_000);
        let decoded = decode_header(&header.rlp).expect("decodes");
        assert_eq!(decoded.hash, header.hash);
        assert_eq!(decoded.number, 1_000);
        assert_eq!(decoded.time_ms, SyntheticParliaChainV1::time_ms(1_000));
        assert_eq!(announced_set(&decoded).expect("roster").validators.len(), 4);
        assert_eq!(decode_header(&[0xc0]), Err(BscLcError::MalformedHeader));
        assert_eq!(
            announced_set(&decode_header(&chain.header(1_001).rlp).expect("decodes")),
            Err(BscLcError::MalformedExtra)
        );
        assert_eq!(miner_history_check_len(4, 1), Ok(2));
        assert_eq!(miner_history_check_len(21, 16), Ok(175));
        assert_eq!(quorum(21), 14);
        assert_eq!(quorum(3), 2);
        assert!(decode_attestation(&chain.attestation(1_000, 3, 1_000)).is_ok());
        assert!(decode_attestation(&[0xc0]).is_err());
        assert_ne!(vote_data_hash(1, [1; 32], 2, [2; 32]), [0; 32]);
        let work = advance_work(&BscLcAdvanceV1 {
            steps: vec![chain.step(1_200, 1_201, 1_000, None)],
        });
        assert_eq!(work.bls_vote_attestations, 1);
        assert_eq!(work.native_headers, 2);
        assert_eq!(
            segment_work(&BscHeaderSegmentV1 {
                headers: vec![vec![1]]
            })
            .native_headers,
            1
        );
    }

    #[test]
    fn builder_helpers_read_headers_and_attestations() {
        let chain = SyntheticParliaChainV1::new([11; 32], 4, 2);
        let header = chain.header(2_000);
        let summary = header_summary(&header.rlp).expect("summary");
        assert_eq!(summary.number, 2_000);
        assert_eq!(summary.hash, header.hash);
        assert_eq!(summary.parent_hash, chain.header(1_999).hash);
        assert_eq!(
            header_announced_set(&header.rlp).expect("roster").0,
            chain.validators(2_000)
        );
        assert_eq!(header_attestation(chain.profile(), &header.rlp), Ok(None));
        assert_eq!(activation_offset(4, 2), Ok(5));
        let vote = BscVoteV1 {
            source_number: 1,
            source_hash: [1; 32],
            target_number: 2,
            target_hash: [2; 32],
        };
        assert!(vote.finalizes_source());
        assert!(
            !BscVoteV1 {
                target_number: 3,
                ..vote
            }
            .finalizes_source()
        );
        let attestation = chain.attestation(0, 3, 10);
        let parsed = parse_attestation(&attestation).expect("parses");
        assert_eq!(parsed.data.source_number, 10);
    }
}
