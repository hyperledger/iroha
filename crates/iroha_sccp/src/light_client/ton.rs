//! TON light client (spec `specs/sccp.md` §4.13.3).
//!
//! **Stored set:** the validator epoch of a masterchain key block (set id = its seqno): config
//! 34 (with the config-28 shuffle flag) and config 15 `stake_held_for`, read from the key
//! block's state. A masterchain block is signed by the masterchain subset (config 34's first
//! `main` validators, shuffled per catchain session when config 28 says so) of the epoch named
//! by its `prev_key_block_seqno`, with more than two thirds of the subset weight. An epoch is
//! fresh until `(utime_until + stake_held_for) · 1000 − margin` (the compiled profile's margin).
//!
//! **Advance:** at most `min(params.max_updates_per_advance, 16)` key-block hops, in order: each
//! hop is a key block whose `prev_key_block_seqno` is the newest stored epoch, signed by that
//! epoch, with a proof of its state's config; it becomes the newest epoch and the head.
//!
//! **Proof:** a masterchain block signed by a fresh stored epoch, or an `OldMcBlocksInfo`
//! back-link from such a block to an older masterchain block; the shard block the masterchain
//! block registers for the minter's shard; at most 32 predecessor links (both predecessors
//! after a merge, the parent shard after a split) down to the event block; and in it the
//! minter's successful transaction and its transfer, finalized-mint or void
//! external-out message (§5.3.3). A transfer's payload must carry the event's amount, nonce and
//! sender. Shard-link and transaction proofs may prune the block's `state_update`. TON keeps no
//! checkpoints (stride or Parliament-installed): old masterchain blocks stay reachable through
//! `OldMcBlocksInfo`.
//!
//! **Simplex transcripts:** the signed `consensus.dataToSign` carries the session id as given.
//! The candidate data binds the signed block id, and the subset is fixed by the header's catchain
//! session and validator-list hash, so another session's votes can only finalize the same block.
//! TODO(WP13): optional stronger session-origin validation would need the consensus options
//! hash (config 29) and the epoch state's vertical seqno, which the stored epoch does not carry.
//! This is beyond the native signed-transcript relation required by v1.
//!
//! **Equivocation:** two signed masterchain blocks, each by a fresh stored epoch, with one seqno
//! and different root hashes.

use super::state::SccpLcConsensusSetRefV1;
#[cfg(test)]
use super::state::{SccpLcInitialStateV1, SccpLcPurgeV1, state_hash};
use super::{
    prepared::{LcMemory, LcSetOwner, SccpLcAttemptErrorV1, SccpNativeEventV1, SccpSourceSenderV1},
    set_ref::{SetFrameRef, TonEpochRef},
    state::writer::DeltaWriter,
};
use crate::native_memory::AttemptError;
use crate::ton_native::{
    TonValidatorConfigOwner, ton_open_masterchain_block_with,
    ton_open_previous_masterchain_block_with, ton_open_sccp_event_with, ton_open_shard_block_with,
    ton_open_state_config_with, ton_verify_masterchain_signatures_with,
};

use core::fmt;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceLocatorV1,
        light_client::{
            SccpLcEquivocationFreezeV1, SccpLcFreezeReasonV1, SccpLcHeadV1, SccpLcPointV1,
            SccpLightClientParamsV1, SccpLightClientV1,
        },
        outbound::SccpVoidKindV1,
    },
};

use super::{
    SccpLcConflictV1, SccpLcError, SccpVerifierWorkV1,
    profile::{
        MAX_SOURCE_FUTURE_MS, TON_MAX_HOPS_PER_ADVANCE, TON_MAX_SHARD_LINKS, TonChainProfileV1,
    },
    proof::{SccpLcSetDataV1, SccpNormalizedEventV1, SccpSourceEmitterV1, SccpVerifiedProofV1},
    state::{SccpLcDeltaV1, SccpLcStateView, SccpLcSupersessionV1},
};
use crate::{
    ton_native::{
        TonBlockIdExtV1, TonBlockSignaturesV1, TonMcHeaderV1, TonNativeSourceError, TonSccpEventV1,
        TonValidatorConfigV1,
    },
    v1::{
        constants::MAX_VOID_FROZEN_RANGE_TON,
        hashes::{keccak256, payload_hash},
        network::tag,
        payload::SccpTransferPayloadRefV1,
    },
};

#[cfg(test)]
use crate::v1::constants::CODEC_TON_ACCOUNT36;

pub mod wallet_state;

const NETWORK: SccpNetworkV1 = SccpNetworkV1::TonMainnet;

// ---------------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------------

/// Stored validator epoch of one key block (`SccpLcConsensusSetV1.set_bytes`).
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonEpochV1")]
pub struct TonEpochV1 {
    /// Key block seqno (the set id).
    pub key_block_seqno: u32,
    /// Key block root hash.
    #[norito(with = "crate::json_utils::hex32")]
    pub key_block_root_hash: [u8; 32],
    /// Config 34 with the config-28 shuffle flag.
    pub validators: TonValidatorConfigV1,
    /// Config 15 `stake_held_for` (seconds).
    pub stake_held_for: u32,
}

/// A masterchain block, its header proof and its validator signatures.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonSignedBlockV1")]
pub struct TonSignedBlockV1 {
    /// Signed block id.
    pub block_id: TonBlockIdExtV1,
    /// Canonical header proof `BoC` rooted at `block_id.root_hash`.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub header_proof: Vec<u8>,
    /// Validator signatures.
    pub signatures: TonBlockSignaturesV1,
}

/// One key-block hop: the signed key block and a proof of its state's config.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonKeyBlockHopV1")]
pub struct TonKeyBlockHopV1 {
    /// Signed key block.
    pub block: TonSignedBlockV1,
    /// Canonical state proof `BoC` rooted at the key block's post-state hash, opening configs
    /// 34, 28 and 15.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub config_proof: Vec<u8>,
}

/// TON advance: key-block hops, oldest first.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonLcAdvanceV1")]
pub struct TonLcAdvanceV1 {
    /// Key-block hops.
    pub hops: Vec<TonKeyBlockHopV1>,
}

/// An `OldMcBlocksInfo` back-link from a fresh signed block to an older masterchain block.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonBackLinkV1")]
pub struct TonBackLinkV1 {
    /// Fresh signed masterchain block.
    pub fresh: TonSignedBlockV1,
    /// Canonical state proof `BoC` of the fresh block opening `prev_blocks[seqno]`.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub state_proof: Vec<u8>,
    /// The older masterchain block.
    pub block_id: TonBlockIdExtV1,
    /// Its canonical header proof (with the `ShardHashes` path).
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub header_proof: Vec<u8>,
}

/// The masterchain block a proof hangs from.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonMasterchainAnchorV1")]
pub enum TonMasterchainAnchorV1 {
    /// A masterchain block signed by a fresh stored epoch.
    Signed(TonSignedBlockV1),
    /// An older masterchain block reached from a fresh one.
    BackLink(TonBackLinkV1),
}

/// A shard block and its header proof.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonShardLinkV1")]
pub struct TonShardLinkV1 {
    /// Shard block id.
    pub block_id: TonBlockIdExtV1,
    /// Canonical header proof `BoC`.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub header_proof: Vec<u8>,
}

/// TON inbound, finalized-mint or void proof.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonSourceProofV1")]
pub struct TonSourceProofV1 {
    /// Masterchain block registering the first shard block.
    pub masterchain: TonMasterchainAnchorV1,
    /// Shard blocks from the registered one down to the event block, each a predecessor of the
    /// one before.
    pub shard_blocks: Vec<TonShardLinkV1>,
    /// Canonical proof `BoC` of the event block reaching the transaction.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub event_block_proof: Vec<u8>,
    /// Canonical `BoC` of the transaction.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub transaction: Vec<u8>,
    /// Logical time of the transaction.
    #[norito(with = "crate::json_utils::u64_string")]
    pub transaction_lt: u64,
    /// Index of the external-out message in the transaction.
    pub message_index: u16,
    /// The minter account (workchain 0).
    #[norito(with = "crate::json_utils::hex32")]
    pub minter: [u8; 32],
}

/// One TON equivocation record: a signed masterchain block.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonLcEvidenceV1")]
pub struct TonLcEvidenceV1 {
    /// Signed masterchain block.
    pub block: TonSignedBlockV1,
}

/// TON weak-subjectivity bootstrap (`SccpLcBootstrapV1.bytes`): a trusted key block.
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
#[norito_schema(name = "iroha_sccp::light_client::ton::TonLcBootstrapV1")]
pub struct TonLcBootstrapV1 {
    /// Key block id.
    pub block_id: TonBlockIdExtV1,
    /// Its canonical header proof.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub header_proof: Vec<u8>,
    /// Canonical state proof opening configs 34, 28 and 15.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub config_proof: Vec<u8>,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// TON-specific verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TonLcError {
    /// A native TON check failed.
    Native(TonNativeSourceError),
    /// A hop is not a key block following the newest stored epoch.
    NotNextKeyBlock {
        /// Hop key block seqno.
        seqno: u32,
    },
    /// A block is later than the compiled `supported_until`.
    UnsupportedFork {
        /// Block time (ms).
        time_ms: u64,
    },
    /// A shard block is not a predecessor of the block before it, or the first is not the one
    /// the masterchain block registers.
    BrokenShardWalk {
        /// Index of the offending link.
        index: usize,
    },
    /// A stored epoch does not decode as a TON epoch with its id.
    MalformedStoredSet {
        /// Set id.
        set_id: u64,
    },
    /// A back-link target is not older than its fresh block.
    InvalidBackLink,
    /// The event's payload is malformed or disagrees with the event's amount, nonce or sender,
    /// or a void range is empty or too long.
    MalformedEvent,
}

impl fmt::Display for TonLcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => write!(formatter, "{error}"),
            Self::NotNextKeyBlock { seqno } => write!(
                formatter,
                "block {seqno} is not the key block after the newest stored epoch"
            ),
            Self::UnsupportedFork { time_ms } => write!(
                formatter,
                "block time {time_ms} ms is after the compiled TON supported_until"
            ),
            Self::BrokenShardWalk { index } => {
                write!(formatter, "shard link {index} breaks the predecessor walk")
            }
            Self::MalformedStoredSet { set_id } => {
                write!(formatter, "stored epoch {set_id} is not a TON epoch")
            }
            Self::InvalidBackLink => formatter.write_str("invalid OldMcBlocksInfo back-link"),
            Self::MalformedEvent => formatter.write_str("malformed SCCP TON event"),
        }
    }
}

impl std::error::Error for TonLcError {}

impl From<TonLcError> for SccpLcError {
    fn from(value: TonLcError) -> Self {
        Self::Ton(value)
    }
}

impl From<TonNativeSourceError> for SccpLcError {
    fn from(value: TonNativeSourceError) -> Self {
        Self::Ton(TonLcError::Native(value))
    }
}

// ---------------------------------------------------------------------------------------------
// Epochs
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
fn decode_epoch(set: &SccpLcConsensusSetRefV1<'_>) -> Result<TonEpochV1, SccpLcError> {
    let malformed = TonLcError::MalformedStoredSet { set_id: set.set_id };
    let SccpLcSetDataV1::Ton(epoch) =
        SccpLcSetDataV1::from_frame(set.set_bytes).map_err(|_| malformed)?
    else {
        return Err(malformed.into());
    };
    if u64::from(epoch.key_block_seqno) != set.set_id {
        return Err(malformed.into());
    }
    Ok(epoch)
}

fn decode_epoch_native(
    set: &SccpLcConsensusSetRefV1<'_>,
    memory: &LcMemory<'_>,
) -> Result<LcSetOwner, SccpLcAttemptErrorV1> {
    let malformed = SccpLcError::from(TonLcError::MalformedStoredSet { set_id: set.set_id });
    let owner = memory
        .decode_set(set.set_bytes, set.set_bytes.len())
        .map_err(|error| match error {
            SccpLcAttemptErrorV1::Protocol(SccpLcError::MalformedFrame(_)) => malformed.into(),
            other => other,
        })?;
    if !matches!(owner.get(), SccpLcSetDataV1::Ton(epoch) if u64::from(epoch.key_block_seqno) == set.set_id)
    {
        return Err(malformed.into());
    }
    Ok(owner)
}
fn epoch_data(owner: &LcSetOwner) -> Result<&TonEpochV1, SccpLcAttemptErrorV1> {
    match owner.get() {
        SccpLcSetDataV1::Ton(epoch) => Ok(epoch),
        _ => Err(SccpLcAttemptErrorV1::Invariant("TON epoch owner tag")),
    }
}

/// Check a masterchain block's time against the fork bound and the Taira clock.
fn check_time(
    profile: &TonChainProfileV1,
    now: u64,
    header: &TonMcHeaderV1,
) -> Result<u64, SccpLcError> {
    let time_ms = u64::from(header.gen_utime) * 1_000;
    if time_ms > profile.supported_until_ms {
        return Err(TonLcError::UnsupportedFork { time_ms }.into());
    }
    if time_ms > now.saturating_add(MAX_SOURCE_FUTURE_MS) {
        return Err(SccpLcError::SourceTimeInFuture {
            source_ms: time_ms,
            taira_now_ms: now,
        });
    }
    Ok(time_ms)
}

fn detached_error(error: &SccpLcAttemptErrorV1) -> SccpLcError {
    match error {
        SccpLcAttemptErrorV1::Protocol(error) => *error,
        _ => TonNativeSourceError::ResourceLimit.into(),
    }
}

fn native_result<T>(
    memory: &LcMemory<'_>,
    result: Result<T, TonNativeSourceError>,
) -> Result<T, SccpLcAttemptErrorV1> {
    match memory.native().finish(result) {
        Ok(value) => Ok(value),
        Err(AttemptError::Protocol(error)) => Err(SccpLcError::from(error).into()),
        Err(AttemptError::Allocation(error)) => Err(error.into()),
    }
}

fn epoch_ref(epoch: &TonEpochV1) -> TonEpochRef<'_> {
    TonEpochRef {
        key_block_seqno: epoch.key_block_seqno,
        key_block_root_hash: epoch.key_block_root_hash,
        validators: (&epoch.validators).into(),
        stake_held_for: epoch.stake_held_for,
    }
}

fn stale_ref(profile: &TonChainProfileV1, epoch: &TonEpochRef<'_>) -> u64 {
    (u64::from(epoch.validators.valid_until) + u64::from(epoch.stake_held_for))
        .saturating_mul(1000)
        .saturating_sub(profile.freshness_margin_ms)
}

struct Ctx<'a, V: SccpLcStateView + ?Sized> {
    profile: &'a TonChainProfileV1,
    view: &'a V,
    now: u64,
    memory: &'a LcMemory<'a>,
}

impl<V: SccpLcStateView + ?Sized> Ctx<'_, V> {
    fn verify_epoch(
        &self,
        header: &TonMcHeaderV1,
        epoch: &TonEpochRef<'_>,
        signatures: &TonBlockSignaturesV1,
    ) -> Result<(), SccpLcAttemptErrorV1> {
        let stale_from = stale_ref(self.profile, epoch);
        if self.now >= stale_from {
            return Err(SccpLcError::StaleSigningSet {
                set_id: u64::from(epoch.key_block_seqno),
                stale_from_ms: stale_from,
            }
            .into());
        }
        native_result(
            self.memory,
            ton_verify_masterchain_signatures_with(
                header,
                epoch.validators,
                signatures,
                self.memory.native(),
            ),
        )
    }
    /// Open the signed block and borrow its pending or originally funded epoch.
    fn signed_block(
        &self,
        block: &TonSignedBlockV1,
        account: Option<[u8; 32]>,
        pending: Option<TonEpochRef<'_>>,
    ) -> Result<(TonMcHeaderV1, Option<TonBlockIdExtV1>), SccpLcAttemptErrorV1> {
        let (header, shard) = native_result(
            self.memory,
            ton_open_masterchain_block_with(
                block.block_id,
                &block.header_proof,
                account,
                self.memory.native(),
            ),
        )?;
        check_time(self.profile, self.now, &header)?;
        if let Some(epoch) =
            pending.filter(|epoch| epoch.key_block_seqno == header.prev_key_block_seqno)
        {
            self.verify_epoch(&header, &epoch, &block.signatures)?;
        } else {
            let set_id = u64::from(header.prev_key_block_seqno);
            let set = self
                .view
                .consensus_set(NETWORK, set_id)
                .ok_or(SccpLcError::UnknownSigningSet { set_id })?;
            let owner = decode_epoch_native(&set, self.memory)?;
            let epoch = epoch_data(&owner)?;
            self.verify_epoch(&header, &epoch_ref(epoch), &block.signatures)?;
        }
        Ok((header, shard))
    }
}

struct EpochOwner {
    key_block_seqno: u32,
    key_block_root_hash: [u8; 32],
    validators: TonValidatorConfigOwner,
    stake_held_for: u32,
}
impl EpochOwner {
    fn as_ref(&self) -> TonEpochRef<'_> {
        TonEpochRef {
            key_block_seqno: self.key_block_seqno,
            key_block_root_hash: self.key_block_root_hash,
            validators: self.validators.as_ref(),
            stake_held_for: self.stake_held_for,
        }
    }
}
fn open_epoch_with(
    header: &TonMcHeaderV1,
    config_proof: &[u8],
    memory: &LcMemory<'_>,
) -> Result<EpochOwner, SccpLcAttemptErrorV1> {
    let hash = header
        .new_state_hash
        .ok_or_else(|| SccpLcError::from(TonNativeSourceError::InvalidValidatorTransition))?;
    let config = native_result(
        memory,
        ton_open_state_config_with(&hash, config_proof, memory.native()),
    )?;
    Ok(EpochOwner {
        key_block_seqno: header.block_id.seqno,
        key_block_root_hash: header.block_id.root_hash,
        validators: config.validators,
        stake_held_for: config.stake_held_for,
    })
}

fn epoch_equal(left: &TonEpochRef<'_>, right: &TonEpochV1) -> bool {
    left.key_block_seqno == right.key_block_seqno
        && left.key_block_root_hash == right.key_block_root_hash
        && left.stake_held_for == right.stake_held_for
        && left.validators.valid_since == right.validators.valid_since
        && left.validators.valid_until == right.validators.valid_until
        && left.validators.main_validator_count == right.validators.main_validator_count
        && left.validators.shuffle_masterchain_validators
            == right.validators.shuffle_masterchain_validators
        && left.validators.validators == right.validators.validators
}

fn point(header: &TonMcHeaderV1) -> SccpLcPointV1 {
    SccpLcPointV1 {
        source_height: u64::from(header.block_id.seqno),
        block_hash: header.block_id.root_hash,
        source_time_ms: u64::from(header.gen_utime) * 1_000,
    }
}

// ---------------------------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------------------------

/// Verify a TON bootstrap (§4.13.2, §4.14.3 `InitializeLightClient`): a key block within the
/// fork bound and not in the future whose epoch is fresh at `taira_now_ms`.
#[cfg(test)]
pub(super) fn verify_bootstrap(
    profile: &TonChainProfileV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &TonLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    let mut delta = SccpLcDeltaV1::default();
    let head = verify_bootstrap_into(
        profile,
        params,
        bootstrap,
        taira_now_ms,
        &LcMemory::detached(),
        &mut delta,
    )
    .map_err(|error| detached_error(&error))?;
    Ok(SccpLcInitialStateV1 {
        light_client: SccpLightClientV1 {
            params: *params,
            head,
            frozen: None,
            state_hash: state_hash(params, &head, None),
        },
        purge: SccpLcPurgeV1::DiscardUnvetted,
        superseded_sets: delta.superseded_sets,
        sets: delta.new_sets,
        checkpoints: delta.checkpoints,
    })
}

/// Bootstrap uses the same canonical proof kernel and writes borrowed epoch bytes into the
/// caller's original-pool output; only scalar head metadata escapes its scratch.
pub(super) fn verify_bootstrap_into<D: DeltaWriter>(
    profile: &TonChainProfileV1,
    _params: &SccpLightClientParamsV1,
    bootstrap: &TonLcBootstrapV1,
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
    out: &mut D,
) -> Result<SccpLcHeadV1, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let (header, _) = native_result(
        memory,
        ton_open_masterchain_block_with(
            bootstrap.block_id,
            &bootstrap.header_proof,
            None,
            memory.native(),
        ),
    )?;
    check_time(profile, taira_now_ms, &header)?;
    if !header.key_block {
        return Err(SccpLcError::from(TonLcError::NotNextKeyBlock {
            seqno: header.block_id.seqno,
        })
        .into());
    }
    let owner = open_epoch_with(&header, &bootstrap.config_proof, memory)?;
    let epoch = owner.as_ref();
    let stale_from = stale_ref(profile, &epoch);
    if taira_now_ms >= stale_from {
        return Err(SccpLcError::StaleSigningSet {
            set_id: u64::from(epoch.key_block_seqno),
            stale_from_ms: stale_from,
        }
        .into());
    }
    let set_id = u64::from(epoch.key_block_seqno);
    out.encode_set(set_id, set_id, None, &SetFrameRef::ton(&epoch))
        .map_err(Into::into)?;
    Ok(SccpLcHeadV1 {
        latest_set_id: set_id,
        latest_finalized: point(&header),
        last_progress_taira_ms: taira_now_ms,
    })
}

// ---------------------------------------------------------------------------------------------
// Advance
// ---------------------------------------------------------------------------------------------

/// Verify a TON advance and return what to write.
pub(super) fn apply_advance<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    advance: &TonLcAdvanceV1,
    taira_now_ms: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    let mut output = SccpLcDeltaV1::default();
    output.head = apply_advance_into(
        profile,
        view,
        light_client,
        advance,
        taira_now_ms,
        &LcMemory::detached(),
        &mut output,
    )
    .map_err(|error| detached_error(&error))?;
    Ok(output)
}

pub(super) fn apply_advance_into<V: SccpLcStateView + ?Sized, D: DeltaWriter>(
    profile: &TonChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    advance: &TonLcAdvanceV1,
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
    output: &mut D,
) -> Result<Option<SccpLcHeadV1>, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let count = advance.hops.len();
    if count == 0 {
        return Err(SccpLcError::TooFewItems {
            kind: "key-block hops",
            count,
            min: 1,
        }
        .into());
    }
    let max = usize::try_from(light_client.params.max_updates_per_advance)
        .unwrap_or(usize::MAX)
        .min(TON_MAX_HOPS_PER_ADVANCE);
    if count > max {
        return Err(SccpLcError::TooManyItems {
            kind: "key-block hops",
            count,
            max,
        }
        .into());
    }
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
        memory,
    };
    let mut newest = u32::try_from(light_client.head.latest_set_id).map_err(|_| {
        SccpLcError::from(TonLcError::MalformedStoredSet {
            set_id: light_client.head.latest_set_id,
        })
    })?;
    let mut latest_finalized = light_client.head.latest_finalized;
    let mut pending: Option<EpochOwner> = None;
    for hop in &advance.hops {
        let (header, _) =
            ctx.signed_block(&hop.block, None, pending.as_ref().map(EpochOwner::as_ref))?;
        let not_next = SccpLcError::from(TonLcError::NotNextKeyBlock {
            seqno: header.block_id.seqno,
        });
        if !header.key_block {
            return Err(not_next.into());
        }
        let epoch = open_epoch_with(&header, &hop.config_proof, memory)?;
        let record_id = u64::from(epoch.key_block_seqno);
        let stored = view.consensus_set(NETWORK, record_id);
        if let Some(stored) = stored {
            let owner = memory.decode_set(stored.set_bytes, stored.set_bytes.len())?;
            let matches = match owner.get() {
                SccpLcSetDataV1::Ton(value) => epoch_equal(&epoch.as_ref(), value),
                _ => false,
            };
            if !matches {
                return Err(
                    SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::ConsensusSet {
                        set_id: record_id,
                    })
                    .into(),
                );
            }
        }
        if header.prev_key_block_seqno != newest {
            if stored.is_some() {
                continue;
            }
            return Err(not_next.into());
        }
        if stored.is_none() {
            output
                .supersede(u64::from(newest), u64::from(header.gen_utime) * 1000)
                .map_err(Into::into)?;
            output
                .encode_set(
                    record_id,
                    record_id,
                    None,
                    &SetFrameRef::ton(&epoch.as_ref()),
                )
                .map_err(Into::into)?;
        }
        newest = header.block_id.seqno;
        if u64::from(newest) > latest_finalized.source_height {
            latest_finalized = point(&header);
        }
        pending = Some(epoch);
    }
    let moved = u64::from(newest) != light_client.head.latest_set_id
        || latest_finalized != light_client.head.latest_finalized;
    Ok(moved.then_some(SccpLcHeadV1 {
        latest_set_id: u64::from(newest),
        latest_finalized,
        last_progress_taira_ms: taira_now_ms,
    }))
}

// ---------------------------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------------------------

/// The masterchain header of a proof's anchor and the shard block it registers for `account`.
fn open_anchor<V: SccpLcStateView + ?Sized>(
    ctx: &Ctx<'_, V>,
    anchor: &TonMasterchainAnchorV1,
    account: [u8; 32],
) -> Result<(TonMcHeaderV1, TonBlockIdExtV1), SccpLcAttemptErrorV1> {
    let (header, shard) = match anchor {
        TonMasterchainAnchorV1::Signed(block) => ctx.signed_block(block, Some(account), None)?,
        TonMasterchainAnchorV1::BackLink(link) => {
            let (fresh, _) = ctx.signed_block(&link.fresh, None, None)?;
            if link.block_id.seqno >= fresh.block_id.seqno {
                return Err(SccpLcError::from(TonLcError::InvalidBackLink).into());
            }
            let state_hash = fresh
                .new_state_hash
                .ok_or_else(|| SccpLcError::from(TonNativeSourceError::BrokenMasterchainLink))?;
            let named = native_result(
                ctx.memory,
                ton_open_previous_masterchain_block_with(
                    &state_hash,
                    &link.state_proof,
                    link.block_id.seqno,
                    ctx.memory.native(),
                ),
            )?;
            if named != link.block_id {
                return Err(SccpLcError::from(TonLcError::InvalidBackLink).into());
            }
            native_result(
                ctx.memory,
                ton_open_masterchain_block_with(
                    link.block_id,
                    &link.header_proof,
                    Some(account),
                    ctx.memory.native(),
                ),
            )?
        }
    };
    Ok((
        header,
        shard.ok_or_else(|| SccpLcError::from(TonNativeSourceError::ShardNotFinalized))?,
    ))
}

/// Check that a `sccp_transfer_to_taira` event's fields are the ones its payload carries: the
/// minter burns `amount` from `sender` under `nonce` and builds the payload from them (§5.3.4),
/// so a payload that disagrees with the event's own fields is refused.
fn check_event_payload(
    payload: &[u8],
    nonce: u64,
    sender: SccpSourceSenderV1,
    amount: u128,
) -> Result<(), TonLcError> {
    let decoded =
        SccpTransferPayloadRefV1::decode(payload).map_err(|_| TonLcError::MalformedEvent)?;
    if decoded.amount == amount
        && decoded.nonce == nonce
        && decoded.sender.codec == sender.codec()
        && decoded.sender.bytes == sender.bytes()
    {
        Ok(())
    } else {
        Err(TonLcError::MalformedEvent)
    }
}

/// Verify a TON inbound, finalized-mint or void proof.
pub(super) fn verify_proof<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    proof: &TonSourceProofV1,
    taira_now_ms: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    let event = verify_proof_native(profile, view, proof, taira_now_ms, &LcMemory::detached())
        .map_err(|error| detached_error(&error))?;
    Ok(SccpVerifiedProofV1 {
        event: event.into_detached(),
        checkpoints: Vec::new(),
    })
}

pub(super) fn verify_proof_native<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    proof: &TonSourceProofV1,
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
) -> Result<SccpNativeEventV1, SccpLcAttemptErrorV1> {
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
        memory,
    };
    let (_, registered) = open_anchor(&ctx, &proof.masterchain, proof.minter)?;
    let count = proof.shard_blocks.len();
    if count == 0 {
        return Err(SccpLcError::TooFewItems {
            kind: "shard blocks",
            count,
            min: 1,
        }
        .into());
    }
    if count > TON_MAX_SHARD_LINKS {
        return Err(SccpLcError::TooManyItems {
            kind: "shard blocks",
            count,
            max: TON_MAX_SHARD_LINKS,
        }
        .into());
    }
    let mut expected = [Some(registered), None];
    for (index, link) in proof.shard_blocks.iter().enumerate() {
        if !expected.contains(&Some(link.block_id)) {
            return Err(SccpLcError::from(TonLcError::BrokenShardWalk { index }).into());
        }
        let header = native_result(
            memory,
            ton_open_shard_block_with(link.block_id, &link.header_proof, memory.native()),
        )?;
        expected = match (header.previous, header.merged_previous) {
            (Some(previous), _) => [Some(previous), None],
            (None, Some((left, right))) => [Some(left), Some(right)],
            (None, None) => [None, None],
        };
    }
    let event_block = proof.shard_blocks[count - 1].block_id;
    let event = native_result(
        memory,
        ton_open_sccp_event_with(
            event_block,
            &proof.event_block_proof,
            &proof.transaction,
            proof.minter,
            proof.transaction_lt,
            proof.message_index,
            memory.native(),
        ),
    )?;
    let emitter = SccpSourceEmitterV1::Ton(proof.minter);
    let locator = SccpSourceLocatorV1 {
        source_height: u64::from(event_block.seqno),
        block_hash: event_block.root_hash,
        index_in_block: u32::from(proof.message_index),
    };
    let event = match event {
        TonSccpEventV1::Finalized { message_id, nonce } => SccpNormalizedEventV1::Finalized {
            emitter,
            message_id,
            nonce,
            amount: None,
            locator,
        },
        TonSccpEventV1::TransferToTaira {
            message_id,
            nonce,
            sender,
            amount,
            payload,
        } => {
            let mut sender_bytes = [0_u8; 36];
            sender_bytes[4..].copy_from_slice(&sender);
            let sender = SccpSourceSenderV1::Ton(sender_bytes);
            check_event_payload(&payload, nonce, sender, amount).map_err(SccpLcError::from)?;
            SccpNormalizedEventV1::TransferToTaira {
                emitter,
                message_id,
                sender,
                nonce,
                payload_hash: payload_hash(&payload),
                locator,
            }
        }
        TonSccpEventV1::Voided {
            message_id,
            first_nonce,
            count,
        } => {
            if count == 0 || u64::from(count) > MAX_VOID_FROZEN_RANGE_TON {
                return Err(SccpLcError::from(TonLcError::MalformedEvent).into());
            }
            SccpNormalizedEventV1::Void {
                emitter,
                kind: if message_id == [0; 32] {
                    SccpVoidKindV1::Frozen
                } else {
                    SccpVoidKindV1::Expired
                },
                first_nonce,
                count: u64::from(count),
                message_id_or_zero: message_id,
                locator,
            }
        }
    };
    Ok(event)
}

// ---------------------------------------------------------------------------------------------
// Equivocation
// ---------------------------------------------------------------------------------------------

/// Verify two conflicting TON records and return the freeze reason.
pub(super) fn verify_equivocation<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    first: (&TonLcEvidenceV1, &[u8]),
    second: (&TonLcEvidenceV1, &[u8]),
    taira_now_ms: u64,
) -> Result<SccpLcFreezeReasonV1, SccpLcError> {
    verify_equivocation_native(
        profile,
        view,
        first,
        second,
        taira_now_ms,
        &LcMemory::detached(),
    )
    .map_err(|error| detached_error(&error))
}

/// Verify original signed evidence without detaching its canonical source or native scratch.
pub(super) fn verify_equivocation_native<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    first: (&TonLcEvidenceV1, &[u8]),
    second: (&TonLcEvidenceV1, &[u8]),
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
) -> Result<SccpLcFreezeReasonV1, SccpLcAttemptErrorV1> {
    if first.1 == second.1 {
        return Err(SccpLcError::EvidenceNotConflicting.into());
    }
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
        memory,
    };
    let (a, _) = ctx.signed_block(&first.0.block, None, None)?;
    let (b, _) = ctx.signed_block(&second.0.block, None, None)?;
    if a.block_id.seqno != b.block_id.seqno || a.block_id.root_hash == b.block_id.root_hash {
        return Err(SccpLcError::EvidenceNotConflicting.into());
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

/// Taira time from which the newest epoch is stale (`(utime_until + stake_held_for) · 1000 −
/// margin`), or `u64::MAX` when it is not stored.
pub(super) fn weak_subjectivity_deadline_ms<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
) -> u64 {
    weak_subjectivity_deadline_ms_native(profile, view, light_client, &LcMemory::detached())
        .unwrap_or(u64::MAX)
}

/// Decode the original stored epoch under the caller's pool; resource refusal is never age.
pub(super) fn weak_subjectivity_deadline_ms_native<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    memory: &LcMemory<'_>,
) -> Result<u64, SccpLcAttemptErrorV1> {
    let Some(set) = view.consensus_set(NETWORK, light_client.head.latest_set_id) else {
        return Ok(u64::MAX);
    };
    let owner = decode_epoch_native(&set, memory)?;
    Ok(stale_ref(profile, &epoch_ref(epoch_data(&owner)?)))
}

/// Whether the newest epoch is stale.
pub(super) fn is_aged<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    taira_now_ms: u64,
) -> bool {
    weak_subjectivity_deadline_ms(profile, view, light_client) <= taira_now_ms
}

/// Scalar optional supersession, retaining no copy of the stored validator graph.
pub(super) fn aged_supersession_native<V: SccpLcStateView + ?Sized>(
    view: &V,
    light_client: &SccpLightClientV1,
    memory: &LcMemory<'_>,
) -> Result<Option<SccpLcSupersessionV1>, SccpLcAttemptErrorV1> {
    let Some(set) = view
        .consensus_set(NETWORK, light_client.head.latest_set_id)
        .filter(SccpLcConsensusSetRefV1::is_current)
    else {
        return Ok(None);
    };
    let owner = decode_epoch_native(&set, memory)?;
    let epoch = epoch_data(&owner)?;
    Ok(Some(SccpLcSupersessionV1 {
        set_id: u64::from(epoch.key_block_seqno),
        superseded_at_source_ms: u64::from(epoch.validators.valid_until) * 1_000,
    }))
}

fn signature_count(signatures: &TonBlockSignaturesV1) -> u32 {
    let count = match signatures {
        TonBlockSignaturesV1::Ordinary(proof) => proof.signatures.len(),
        TonBlockSignaturesV1::Simplex(proof) => proof.signatures.len(),
    };
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn block_work(block: &TonSignedBlockV1) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        native_headers: 1,
        native_header_bytes: u64::try_from(block.header_proof.len()).unwrap_or(u64::MAX),
        ed25519_signature_checks: signature_count(&block.signatures),
        ..SccpVerifierWorkV1::default()
    }
}

/// Work of an advance: every hop's signatures.
pub(super) fn advance_work(advance: &TonLcAdvanceV1) -> SccpVerifierWorkV1 {
    advance
        .hops
        .iter()
        .map(|hop| block_work(&hop.block))
        .fold(SccpVerifierWorkV1::default(), |total, work| {
            total.checked_add(&work).unwrap_or(total)
        })
}

/// Work of a proof: one proof, its signed block(s) and shard headers.
pub(super) fn proof_work(proof: &TonSourceProofV1) -> SccpVerifierWorkV1 {
    let anchor = match &proof.masterchain {
        TonMasterchainAnchorV1::Signed(block) => block_work(block),
        TonMasterchainAnchorV1::BackLink(link) => block_work(&link.fresh),
    };
    SccpVerifierWorkV1 {
        proofs: 1,
        native_headers: anchor
            .native_headers
            .saturating_add(u32::try_from(proof.shard_blocks.len()).unwrap_or(u32::MAX)),
        ..anchor
    }
}

/// Work of one evidence record: its signed block.
pub(super) fn evidence_work(evidence: &TonLcEvidenceV1) -> SccpVerifierWorkV1 {
    block_work(&evidence.block)
}

#[cfg(test)]
mod tests;
