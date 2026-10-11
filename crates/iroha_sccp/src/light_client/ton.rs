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
//! minter's successful transaction and its `sccp_transfer_to_taira` or `sccp_voided`
//! external-out message (§5.3.3). A transfer's payload must carry the event's amount, nonce and
//! sender. Shard-link and transaction proofs may prune the block's `state_update`. TON keeps no
//! checkpoints (stride or Parliament-installed): old masterchain blocks stay reachable through
//! `OldMcBlocksInfo`.
//!
//! **Simplex transcripts:** the signed `consensus.dataToSign` carries the session id as given.
//! The candidate data binds the signed block id, and the subset is fixed by the header's catchain
//! session and validator-list hash, so another session's votes can only finalize the same block.
//! TODO(WP13): binding `session_id` itself needs the consensus options hash (config 29) and the
//! vertical seqno of the epoch's state, which the stored epoch does not carry.
//!
//! **Equivocation:** two signed masterchain blocks, each by a fresh stored epoch, with one seqno
//! and different root hashes.

use core::fmt;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceLocatorV1,
        light_client::{
            SccpLcConsensusSetV1, SccpLcEquivocationFreezeV1, SccpLcFreezeReasonV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
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
    state::{
        SccpLcDeltaV1, SccpLcInitialStateV1, SccpLcPurgeV1, SccpLcStateView, SccpLcSupersessionV1,
        state_hash,
    },
};
use crate::{
    ton_native::{
        TonBlockIdExtV1, TonBlockSignaturesV1, TonMcHeaderV1, TonNativeSourceError, TonSccpEventV1,
        TonValidatorConfigV1, ton_open_masterchain_block, ton_open_previous_masterchain_block,
        ton_open_sccp_event, ton_open_shard_block, ton_open_state_config,
        ton_verify_masterchain_signatures,
    },
    v1::{
        constants::{CODEC_TON_ACCOUNT36, MAX_VOID_FROZEN_RANGE_TON},
        hashes::{keccak256, payload_hash},
        network::tag,
        payload::{PayloadAccountV1, SccpTransferPayloadV1},
    },
};

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

/// TON inbound or void proof.
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

fn decode_epoch(set: &SccpLcConsensusSetV1) -> Result<TonEpochV1, SccpLcError> {
    let malformed = TonLcError::MalformedStoredSet { set_id: set.set_id };
    let SccpLcSetDataV1::Ton(epoch) =
        SccpLcSetDataV1::from_frame(&set.set_bytes).map_err(|_| malformed)?
    else {
        return Err(malformed.into());
    };
    if u64::from(epoch.key_block_seqno) != set.set_id {
        return Err(malformed.into());
    }
    Ok(epoch)
}

fn epoch_record(epoch: TonEpochV1) -> Result<SccpLcConsensusSetV1, SccpLcError> {
    Ok(SccpLcConsensusSetV1 {
        set_id: u64::from(epoch.key_block_seqno),
        valid_from_source_height: u64::from(epoch.key_block_seqno),
        superseded_at_source_ms: None,
        set_bytes: SccpLcSetDataV1::Ton(epoch).to_frame()?,
    })
}

/// Taira time (ms) from which `epoch` is stale.
fn stale_from_ms(profile: &TonChainProfileV1, epoch: &TonEpochV1) -> u64 {
    (u64::from(epoch.validators.valid_until) + u64::from(epoch.stake_held_for))
        .saturating_mul(1_000)
        .saturating_sub(profile.freshness_margin_ms)
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

struct Ctx<'a, V: SccpLcStateView + ?Sized> {
    profile: &'a TonChainProfileV1,
    view: &'a V,
    now: u64,
}

impl<V: SccpLcStateView + ?Sized> Ctx<'_, V> {
    /// The fresh stored (or `pending`) epoch of key block `seqno`.
    fn fresh_epoch(
        &self,
        seqno: u32,
        pending: Option<&TonEpochV1>,
    ) -> Result<TonEpochV1, SccpLcError> {
        let epoch = match pending.filter(|epoch| epoch.key_block_seqno == seqno) {
            Some(epoch) => epoch.clone(),
            None => decode_epoch(
                &self
                    .view
                    .consensus_set(NETWORK, u64::from(seqno))
                    .ok_or_else(|| SccpLcError::UnknownSigningSet {
                        set_id: u64::from(seqno),
                    })?,
            )?,
        };
        let stale_from = stale_from_ms(self.profile, &epoch);
        if self.now >= stale_from {
            return Err(SccpLcError::StaleSigningSet {
                set_id: u64::from(seqno),
                stale_from_ms: stale_from,
            });
        }
        Ok(epoch)
    }

    /// Open and verify a signed masterchain block under the fresh epoch it names.
    fn signed_block(
        &self,
        block: &TonSignedBlockV1,
        account: Option<[u8; 32]>,
        pending: Option<&TonEpochV1>,
    ) -> Result<(TonMcHeaderV1, Option<TonBlockIdExtV1>), SccpLcError> {
        let (header, shard) =
            ton_open_masterchain_block(block.block_id, &block.header_proof, account)?;
        check_time(self.profile, self.now, &header)?;
        let epoch = self.fresh_epoch(header.prev_key_block_seqno, pending)?;
        ton_verify_masterchain_signatures(&header, &epoch.validators, &block.signatures)?;
        Ok((header, shard))
    }
}

fn point(header: &TonMcHeaderV1) -> SccpLcPointV1 {
    SccpLcPointV1 {
        source_height: u64::from(header.block_id.seqno),
        block_hash: header.block_id.root_hash,
        source_time_ms: u64::from(header.gen_utime) * 1_000,
    }
}

fn open_epoch(header: &TonMcHeaderV1, config_proof: &[u8]) -> Result<TonEpochV1, SccpLcError> {
    let state_hash = header
        .new_state_hash
        .ok_or(TonNativeSourceError::InvalidValidatorTransition)?;
    let config = ton_open_state_config(&state_hash, config_proof)?;
    Ok(TonEpochV1 {
        key_block_seqno: header.block_id.seqno,
        key_block_root_hash: header.block_id.root_hash,
        validators: config.validators,
        stake_held_for: config.stake_held_for,
    })
}

// ---------------------------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------------------------

/// Verify a TON bootstrap (§4.13.2, §4.14.3 `InitializeLightClient`): a key block within the
/// fork bound and not in the future whose epoch is fresh at `taira_now_ms`.
pub(super) fn verify_bootstrap(
    profile: &TonChainProfileV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &TonLcBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    let (header, _) =
        ton_open_masterchain_block(bootstrap.block_id, &bootstrap.header_proof, None)?;
    check_time(profile, taira_now_ms, &header)?;
    if !header.key_block {
        return Err(TonLcError::NotNextKeyBlock {
            seqno: header.block_id.seqno,
        }
        .into());
    }
    let epoch = open_epoch(&header, &bootstrap.config_proof)?;
    let stale_from = stale_from_ms(profile, &epoch);
    if taira_now_ms >= stale_from {
        return Err(SccpLcError::StaleSigningSet {
            set_id: u64::from(epoch.key_block_seqno),
            stale_from_ms: stale_from,
        });
    }
    let head = SccpLcHeadV1 {
        latest_set_id: u64::from(header.block_id.seqno),
        latest_finalized: point(&header),
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
        sets: vec![epoch_record(epoch)?],
        checkpoints: Vec::new(),
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
    let count = advance.hops.len();
    if count == 0 {
        return Err(SccpLcError::TooFewItems {
            kind: "key-block hops",
            count,
            min: 1,
        });
    }
    let max = usize::try_from(light_client.params.max_updates_per_advance)
        .unwrap_or(usize::MAX)
        .min(TON_MAX_HOPS_PER_ADVANCE);
    if count > max {
        return Err(SccpLcError::TooManyItems {
            kind: "key-block hops",
            count,
            max,
        });
    }
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
    };
    let mut newest = u32::try_from(light_client.head.latest_set_id).map_err(|_| {
        TonLcError::MalformedStoredSet {
            set_id: light_client.head.latest_set_id,
        }
    })?;
    let mut latest_finalized = light_client.head.latest_finalized;
    let mut pending: Option<TonEpochV1> = None;
    let mut new_sets: Vec<SccpLcConsensusSetV1> = Vec::new();
    let mut superseded = Vec::new();
    for hop in &advance.hops {
        let (header, _) = ctx.signed_block(&hop.block, None, pending.as_ref())?;
        let not_next = TonLcError::NotNextKeyBlock {
            seqno: header.block_id.seqno,
        };
        if !header.key_block {
            return Err(not_next.into());
        }
        let epoch = open_epoch(&header, &hop.config_proof)?;
        let record = epoch_record(epoch.clone())?;
        let stored = view.consensus_set(NETWORK, record.set_id);
        if let Some(stored) = &stored
            && stored.set_bytes != record.set_bytes
        {
            return Err(SccpLcError::ConflictsWithStoredData(
                SccpLcConflictV1::ConsensusSet {
                    set_id: record.set_id,
                },
            ));
        }
        if header.prev_key_block_seqno != newest {
            // Re-proving a stored hop changes nothing; any other hop must follow the newest.
            if stored.is_some() {
                continue;
            }
            return Err(not_next.into());
        }
        if stored.is_none() {
            let superseded_at = u64::from(header.gen_utime) * 1_000;
            match new_sets.last_mut() {
                Some(previous) => previous.superseded_at_source_ms = Some(superseded_at),
                None => superseded.push(SccpLcSupersessionV1 {
                    set_id: u64::from(newest),
                    superseded_at_source_ms: superseded_at,
                }),
            }
            new_sets.push(record);
        }
        newest = header.block_id.seqno;
        if u64::from(header.block_id.seqno) > latest_finalized.source_height {
            latest_finalized = point(&header);
        }
        pending = Some(epoch);
    }
    let moved = u64::from(newest) != light_client.head.latest_set_id
        || latest_finalized != light_client.head.latest_finalized;
    Ok(SccpLcDeltaV1 {
        new_sets,
        superseded_sets: superseded,
        checkpoints: Vec::new(),
        head: moved.then_some(SccpLcHeadV1 {
            latest_set_id: u64::from(newest),
            latest_finalized,
            last_progress_taira_ms: taira_now_ms,
        }),
    })
}

// ---------------------------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------------------------

/// The masterchain header of a proof's anchor and the shard block it registers for `account`.
fn open_anchor<V: SccpLcStateView + ?Sized>(
    ctx: &Ctx<'_, V>,
    anchor: &TonMasterchainAnchorV1,
    account: [u8; 32],
) -> Result<(TonMcHeaderV1, TonBlockIdExtV1), SccpLcError> {
    let (header, shard) = match anchor {
        TonMasterchainAnchorV1::Signed(block) => ctx.signed_block(block, Some(account), None)?,
        TonMasterchainAnchorV1::BackLink(link) => {
            let (fresh, _) = ctx.signed_block(&link.fresh, None, None)?;
            if link.block_id.seqno >= fresh.block_id.seqno {
                return Err(TonLcError::InvalidBackLink.into());
            }
            let state_hash = fresh
                .new_state_hash
                .ok_or(TonNativeSourceError::BrokenMasterchainLink)?;
            let named = ton_open_previous_masterchain_block(
                &state_hash,
                &link.state_proof,
                link.block_id.seqno,
            )?;
            if named != link.block_id {
                return Err(TonLcError::InvalidBackLink.into());
            }
            ton_open_masterchain_block(link.block_id, &link.header_proof, Some(account))?
        }
    };
    Ok((
        header,
        shard.ok_or(TonNativeSourceError::ShardNotFinalized)?,
    ))
}

/// Check that a `sccp_transfer_to_taira` event's fields are the ones its payload carries: the
/// minter burns `amount` from `sender` under `nonce` and builds the payload from them (§5.3.4),
/// so a payload that disagrees with the event's own fields is refused.
fn check_event_payload(
    payload: &[u8],
    nonce: u64,
    sender: &PayloadAccountV1,
    amount: u128,
) -> Result<(), TonLcError> {
    let decoded = SccpTransferPayloadV1::decode(payload).map_err(|_| TonLcError::MalformedEvent)?;
    if decoded.amount == amount && decoded.nonce == nonce && decoded.sender == *sender {
        Ok(())
    } else {
        Err(TonLcError::MalformedEvent)
    }
}

/// Verify a TON inbound or void proof.
pub(super) fn verify_proof<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    proof: &TonSourceProofV1,
    taira_now_ms: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
    };
    let (_, registered) = open_anchor(&ctx, &proof.masterchain, proof.minter)?;
    let count = proof.shard_blocks.len();
    if count == 0 {
        return Err(SccpLcError::TooFewItems {
            kind: "shard blocks",
            count,
            min: 1,
        });
    }
    if count > TON_MAX_SHARD_LINKS {
        return Err(SccpLcError::TooManyItems {
            kind: "shard blocks",
            count,
            max: TON_MAX_SHARD_LINKS,
        });
    }
    let mut expected: Vec<TonBlockIdExtV1> = vec![registered];
    for (index, link) in proof.shard_blocks.iter().enumerate() {
        if !expected.contains(&link.block_id) {
            return Err(TonLcError::BrokenShardWalk { index }.into());
        }
        let header = ton_open_shard_block(link.block_id, &link.header_proof)?;
        expected = match (header.previous, header.merged_previous) {
            (Some(previous), _) => vec![previous],
            (None, Some((left, right))) => vec![left, right],
            (None, None) => Vec::new(),
        };
    }
    let event_block = proof.shard_blocks[count - 1].block_id;
    let event = ton_open_sccp_event(
        event_block,
        &proof.event_block_proof,
        &proof.transaction,
        proof.minter,
        proof.transaction_lt,
        proof.message_index,
    )?;
    let emitter = SccpSourceEmitterV1::Ton(proof.minter);
    let locator = SccpSourceLocatorV1 {
        source_height: u64::from(event_block.seqno),
        block_hash: event_block.root_hash,
        index_in_block: u32::from(proof.message_index),
    };
    let event = match event {
        TonSccpEventV1::TransferToTaira {
            message_id,
            nonce,
            sender,
            amount,
            payload,
        } => {
            let mut sender_bytes = vec![0_u8; 4];
            sender_bytes.extend_from_slice(&sender);
            let sender = PayloadAccountV1::new(CODEC_TON_ACCOUNT36, sender_bytes);
            check_event_payload(&payload, nonce, &sender, amount)?;
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
                return Err(TonLcError::MalformedEvent.into());
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
    Ok(SccpVerifiedProofV1 {
        event,
        checkpoints: Vec::new(),
    })
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
    if first.1 == second.1 {
        return Err(SccpLcError::EvidenceNotConflicting);
    }
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
    };
    let (a, _) = ctx.signed_block(&first.0.block, None, None)?;
    let (b, _) = ctx.signed_block(&second.0.block, None, None)?;
    if a.block_id.seqno != b.block_id.seqno || a.block_id.root_hash == b.block_id.root_hash {
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

/// Taira time from which the newest epoch is stale (`(utime_until + stake_held_for) · 1000 −
/// margin`), or `u64::MAX` when it is not stored.
pub(super) fn weak_subjectivity_deadline_ms<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
) -> u64 {
    view.consensus_set(NETWORK, light_client.head.latest_set_id)
        .and_then(|set| decode_epoch(&set).ok())
        .map_or(u64::MAX, |epoch| stale_from_ms(profile, &epoch))
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

/// Supersession of an aged light client's newest epoch at its `utime_until`.
pub(super) fn aged_supersessions<V: SccpLcStateView + ?Sized>(
    view: &V,
    light_client: &SccpLightClientV1,
) -> Vec<SccpLcSupersessionV1> {
    view.consensus_set(NETWORK, light_client.head.latest_set_id)
        .filter(SccpLcConsensusSetV1::is_current)
        .and_then(|set| decode_epoch(&set).ok())
        .map(|epoch| SccpLcSupersessionV1 {
            set_id: u64::from(epoch.key_block_seqno),
            superseded_at_source_ms: u64::from(epoch.validators.valid_until) * 1_000,
        })
        .into_iter()
        .collect()
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
