//! Ethereum light client (spec `specs/sccp.md` §4.13.3).
//!
//! **Stored set:** the sync committee of each period, learned only from finalized updates (a
//! `next_sync_committee` is accepted only when the attested and finalized headers share a
//! period). Set id = sync-committee period; `valid_from_source_height` = the period's first
//! beacon slot; a set is superseded when the next period starts, and is fresh until
//! `ws_bound_ms` after that.
//!
//! **Advance:** at most `min(params.max_updates_per_advance, 16)` `LightClientUpdate`s, each with a
//! finality branch, at least 342 participants, `signature_slot > attested.slot >=
//! finalized.slot`, signed by the stored fresh committee of `period(signature_slot)` under the
//! fork version of `max(signature_slot, 1) - 1`. Each finalized execution block becomes a
//! checkpoint (keyed by execution block number). Earlier updates of the same advance may teach
//! the committees later ones are signed by.
//!
//! **Backfill:** at most 256 parent-linked execution header RLPs ending at a stored checkpoint;
//! the first header becomes a checkpoint (`origin: Backfill`).
//!
//! **Proof:** a finality update under the advance rules (or a stored checkpoint) gives the anchor
//! block `E`. Ancestry from the event block `B` is `SameBlock`, `HeaderChain` (at most 256
//! parent-linked headers from `B` to `E`) or `HistoryContract` (EIP-2935 account and storage
//! proof under `E`'s state root, `1 <= E - B <= 8191`). Then `B`'s header RLP (whose keccak is
//! its hash), the receipt MPT under `B`'s receipts root, a successful receipt, and the selected
//! `SccpTransferToTaira` log or run of `SccpVoided` logs.
//!
//! **Fork bound:** every slot an update names must lie at or before the compiled
//! `supported_until` epoch; later evidence fails closed until a release extends the profile.
//!
//! **Execution time bound:** a finalized execution payload's timestamp must not lie after the
//! start of the update's signature slot (on the source chain it equals the finalized slot's
//! time). This bounds every accepted finalized block to the recent past, so a forged block far
//! ahead of the canonical chain becomes reportable as soon as the canonical chain finalizes past
//! its time.
//!
//! **Equivocation:** a record is a signed update ([`EthereumLcEvidenceV1::Update`]) or a signed
//! update plus ancestry proving an execution header canonical below its finalized block
//! ([`EthereumLcEvidenceV1::FinalizedAncestor`]). Two records conflict when they finalize
//! different beacon blocks at one slot, teach different committees for one period, or assert
//! finalized execution blocks that cannot share one chain: one height with different content
//! (hash, roots or time), or heights and times ordered inconsistently (block times strictly
//! increase with height). Honest records never conflict. A forged checkpoint at any height,
//! including one between the epoch-boundary blocks honest updates finalize, is reportable with a
//! `FinalizedAncestor` record for the canonical block at that height, or by time order when it
//! claims a height the canonical chain has not reached. The signature slot is not part of the
//! signed message (only the fork version it selects is), so updates sharing a signature slot are
//! not a conflict: relabelling honest aggregates would otherwise let anyone freeze an honest
//! light client.

use super::set_ref::{EthereumSetRef, SetFrameRef};
use super::state::SccpLcConsensusSetRefV1;
#[cfg(test)]
use super::state::{SccpLcInitialStateV1, SccpLcPurgeV1, state_hash};
use std::cmp::Ordering;

use core::fmt;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceLocatorV1,
        light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1,
            SccpLcEquivocationFreezeV1, SccpLcFreezeReasonV1, SccpLcHeadV1, SccpLcPointV1,
            SccpLightClientParamsV1, SccpLightClientV1,
        },
        outbound::SccpVoidKindV1,
    },
};

use super::{
    SccpLcConflictV1, SccpLcError, SccpVerifierWorkV1,
    prepared::{LcMemory, SccpLcAttemptErrorV1, SccpNativeEventV1, SccpSourceSenderV1},
    profile::{
        ETHEREUM_MAX_ANCESTRY_HEADERS, ETHEREUM_MAX_BACKFILL_HEADERS,
        ETHEREUM_MAX_UPDATES_PER_ADVANCE, EthereumChainProfileV1, MAX_SOURCE_FUTURE_MS,
    },
    proof::{SccpLcSetDataV1, SccpNormalizedEventV1, SccpSourceEmitterV1, SccpVerifiedProofV1},
    state::{
        CheckpointRecorder, SccpLcDeltaV1, SccpLcStateView, is_set_fresh, same_checkpoint_block,
        writer::DeltaWriter,
    },
};
use crate::{
    ethereum_native::{
        AuthenticatedExecutionBlock, EthereumLightClientError, ForkSchedule, Root, SLOTS_PER_EPOCH,
        SyncCommittee, sync_committee_period_at_slot,
    },
    ethereum_source::{
        EthereumExecutionError, EthereumExecutionHeaderFieldsV1, EthereumMptRoleV1,
        EthereumNativeLightClientBootstrapV1, EthereumNativeLightClientUpdateV1,
        EthereumNativeMptProofV1, EthereumNativeSyncCommitteeV1, decode_account,
        decode_execution_header, decode_storage_word,
    },
    v1::{
        constants::MAX_VOID_FROZEN_RANGE_EVM,
        evm_abi::{AbiError, FinalizedLogV1, TransferToTairaLogV1, VoidedLogV1},
        hashes::{keccak256, payload_hash, word_u64},
        network::tag,
    },
};

use super::state::SccpLcSupersessionV1;

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

// ---------------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------------

/// Advance of finalized `LightClientUpdate`s, oldest first.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumLcAdvanceV1")]
pub struct EthereumLcAdvanceV1 {
    /// Updates, each with a finality branch.
    pub updates: Vec<EthereumNativeLightClientUpdateV1>,
}

/// Parent-linked execution header RLPs in ascending block order.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumHeaderSegmentV1")]
pub struct EthereumHeaderSegmentV1 {
    /// Header RLPs; each header's parent hash is the previous header's keccak.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub headers: Vec<Vec<u8>>,
}

/// Reference to a stored checkpoint used as a proof anchor.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumStoredCheckpointRefV1")]
pub struct EthereumStoredCheckpointRefV1 {
    /// Execution block number of the stored checkpoint.
    #[norito(with = "crate::json_utils::u64_string")]
    pub source_height: u64,
}

/// Finalized anchor `E` of a proof.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "anchor", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumProofAnchorV1")]
pub enum EthereumProofAnchorV1 {
    /// A finality update verified under the advance rules; `E` is its finalized execution block.
    FinalityUpdate(Box<EthereumNativeLightClientUpdateV1>),
    /// A stored checkpoint.
    StoredCheckpoint(EthereumStoredCheckpointRefV1),
}

/// EIP-2935 account and storage proof under `E`'s state root.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumHistoryProofV1")]
pub struct EthereumHistoryProofV1 {
    /// Account proof of the history storage contract.
    pub account_proof: EthereumNativeMptProofV1,
    /// Storage proof of slot `B mod 8191`.
    pub storage_proof: EthereumNativeMptProofV1,
}

/// Ancestry from the event block `B` to the anchor `E`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "ancestry", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumAncestryV1")]
pub enum EthereumAncestryV1 {
    /// `B = E`.
    SameBlock,
    /// Headers `B + 1 ..= E`, parent-linked from `B`.
    HeaderChain(EthereumHeaderSegmentV1),
    /// EIP-2935 history contract proof under `E`'s state root.
    HistoryContract(EthereumHistoryProofV1),
}

/// One log in a receipt.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumLogRefV1")]
pub struct EthereumLogRefV1 {
    /// Index of the log within the receipt.
    pub log_index: u32,
}

/// Consecutive logs in a receipt.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumLogRangeV1")]
pub struct EthereumLogRangeV1 {
    /// Index of the first log within the receipt.
    pub first_log_index: u32,
    /// Number of logs (`1..=256`).
    pub log_count: u32,
}

/// The event a proof selects in the receipt.
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
)]
#[norito(tag = "event", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumEventSelectorV1")]
pub enum EthereumEventSelectorV1 {
    /// One `SccpTransferToTaira` log.
    TransferToTaira(EthereumLogRefV1),
    /// One `voidExpired` log, or a run of `voidFrozen` logs of consecutive nonces.
    Void(EthereumLogRangeV1),
    /// One `SccpFinalized` mint log.
    Finalized(EthereumLogRefV1),
}

/// Ethereum inbound, finalized-mint or void proof.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumSourceProofV1")]
pub struct EthereumSourceProofV1 {
    /// Finalized anchor `E`.
    pub anchor: EthereumProofAnchorV1,
    /// Ancestry from `B` to `E`.
    pub ancestry: EthereumAncestryV1,
    /// RLP header of the event block `B`.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub event_header: Vec<u8>,
    /// Transaction index of the receipt in `B` (the receipts-trie key is `rlp(index)`).
    pub transaction_index: u32,
    /// Receipt inclusion proof under `B`'s receipts root.
    pub receipt_proof: EthereumNativeMptProofV1,
    /// Selected event logs.
    pub event: EthereumEventSelectorV1,
}

/// A signed update plus ancestry proving an execution header canonical below the update's
/// finalized execution block.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumFinalizedAncestorV1")]
pub struct EthereumFinalizedAncestorV1 {
    /// A signed update verified under the advance rules; its finalized execution block is `E`.
    pub update: EthereumNativeLightClientUpdateV1,
    /// Ancestry from `header` to `E`, under the proof rules (`SameBlock`, `HeaderChain` or
    /// `HistoryContract`).
    pub ancestry: EthereumAncestryV1,
    /// RLP of the ancestor execution header (its keccak is its hash).
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub header: Vec<u8>,
}

/// One quorum-valid record of equivocation evidence.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "record", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumLcEvidenceV1")]
pub enum EthereumLcEvidenceV1 {
    /// A signed update: its finalized beacon header, finalized execution block and, when carried,
    /// next sync committee.
    Update(Box<EthereumNativeLightClientUpdateV1>),
    /// A signed update and a canonical execution ancestor of its finalized block: everything an
    /// `Update` asserts, plus the ancestor's height, hash, roots and time.
    FinalizedAncestor(Box<EthereumFinalizedAncestorV1>),
}

/// Stored sync committee of one period.
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
#[norito_schema(name = "iroha_sccp::light_client::ethereum::EthereumSyncCommitteeSetV1")]
pub struct EthereumSyncCommitteeSetV1 {
    /// Sync-committee period (the set id).
    #[norito(with = "crate::json_utils::u64_string")]
    pub period: u64,
    /// The committee.
    pub committee: EthereumNativeSyncCommitteeV1,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Ethereum-specific verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthereumLcError {
    /// A consensus-layer rule failed (forks, branches, threshold, signature).
    Consensus(EthereumLightClientError),
    /// An execution-layer opening or wire conversion failed.
    Execution(EthereumExecutionError),
    /// The finalized header predates Capella and authenticates no execution block.
    MissingExecutionPayload,
    /// A slot or timestamp overflows the millisecond clock.
    TimeOverflow,
    /// A stored consensus set does not decode as an Ethereum sync committee of its period.
    MalformedStoredSet {
        /// Set id.
        set_id: u64,
    },
    /// A header does not link to its predecessor (`parent_hash` and `number + 1`).
    AncestryBroken {
        /// Index of the unlinked header in the segment.
        index: usize,
    },
    /// The ancestry does not end at the anchor block.
    AncestryAnchorMismatch,
    /// A backfill segment does not end at the stored checkpoint of its last height.
    BackfillAnchorMismatch {
        /// Height of the last header.
        source_height: u64,
    },
    /// The anchor has no state root or predates the EIP-2935 history contract.
    HistoryContractUnavailable,
    /// `E - B` is outside `1..=8191`.
    HistoryWindow {
        /// Event block number.
        event_height: u64,
        /// Anchor block number.
        anchor_height: u64,
    },
    /// The history storage account has another code hash.
    HistoryCodeHashMismatch,
    /// The history storage slot does not hold the event block hash.
    HistoryValueMismatch,
    /// The receipt has `status = 0`.
    FailedReceipt,
    /// The selected log index is outside the receipt.
    LogIndexOutOfRange {
        /// Selected index.
        index: u32,
        /// Logs in the receipt.
        logs: usize,
    },
    /// The selected log is not a canonical SCCP event.
    Event(AbiError),
    /// The void logs are not one `voidExpired` log or a run of `voidFrozen` logs of consecutive
    /// nonces from one contract, or the run length is outside `1..=256`.
    VoidRangeInvalid,
    /// A finalized execution payload is timestamped after the start of the update's signature
    /// slot, which no source-chain block can be.
    ExecutionAfterSignature {
        /// Execution timestamp (ms).
        execution_ms: u64,
        /// Start of the signature slot (ms).
        signature_ms: u64,
    },
}

impl fmt::Display for EthereumLcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(error) => write!(formatter, "{error}"),
            Self::Execution(error) => write!(formatter, "{error}"),
            Self::MissingExecutionPayload => {
                formatter.write_str("finalized header carries no execution payload")
            }
            Self::TimeOverflow => formatter.write_str("source time overflows"),
            Self::MalformedStoredSet { set_id } => {
                write!(
                    formatter,
                    "stored set {set_id} is not a sync committee of its period"
                )
            }
            Self::AncestryBroken { index } => {
                write!(formatter, "header {index} does not link to its predecessor")
            }
            Self::AncestryAnchorMismatch => {
                formatter.write_str("ancestry does not end at the anchor")
            }
            Self::BackfillAnchorMismatch { source_height } => write!(
                formatter,
                "backfill segment does not end at the stored checkpoint {source_height}"
            ),
            Self::HistoryContractUnavailable => {
                formatter.write_str("the anchor cannot open the EIP-2935 history contract")
            }
            Self::HistoryWindow {
                event_height,
                anchor_height,
            } => write!(
                formatter,
                "history distance from {event_height} to {anchor_height} is outside 1..=8191"
            ),
            Self::HistoryCodeHashMismatch => {
                formatter.write_str("history storage account has an unexpected code hash")
            }
            Self::HistoryValueMismatch => {
                formatter.write_str("history storage slot does not hold the event block hash")
            }
            Self::FailedReceipt => formatter.write_str("receipt status is not successful"),
            Self::LogIndexOutOfRange { index, logs } => {
                write!(formatter, "log {index} is outside a receipt of {logs} logs")
            }
            Self::Event(error) => write!(formatter, "selected log is not an SCCP event: {error}"),
            Self::VoidRangeInvalid => formatter.write_str("invalid SccpVoided log run"),
            Self::ExecutionAfterSignature {
                execution_ms,
                signature_ms,
            } => write!(
                formatter,
                "finalized execution time {execution_ms} ms is after the signature slot start \
                 {signature_ms} ms"
            ),
        }
    }
}

impl std::error::Error for EthereumLcError {}

fn consensus(error: EthereumLightClientError) -> SccpLcError {
    SccpLcError::Ethereum(EthereumLcError::Consensus(error))
}

fn execution(error: EthereumExecutionError) -> SccpLcError {
    SccpLcError::Ethereum(EthereumLcError::Execution(error))
}

// ---------------------------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------------------------

struct Ctx<'a> {
    profile: &'a EthereumChainProfileV1,
    schedule: ForkSchedule,
    ws_bound_ms: u64,
    now: u64,
}

impl<'a> Ctx<'a> {
    fn new(
        profile: &'a EthereumChainProfileV1,
        params: &SccpLightClientParamsV1,
        now: u64,
    ) -> Result<Self, SccpLcError> {
        Ok(Self {
            profile,
            schedule: profile.schedule().map_err(consensus)?,
            ws_bound_ms: params.ws_bound_ms,
            now,
        })
    }

    fn check_supported(&self, slot: u64) -> Result<(), SccpLcError> {
        if self.profile.supports_slot(slot) {
            Ok(())
        } else {
            Err(SccpLcError::ForkBeyondSupported {
                epoch: slot / SLOTS_PER_EPOCH,
                supported_until: self.profile.supported_until_epoch,
            })
        }
    }

    fn check_not_future(&self, slot: u64) -> Result<(), SccpLcError> {
        let source_ms = self
            .profile
            .slot_start_ms(slot)
            .ok_or(EthereumLcError::TimeOverflow)?;
        if source_ms > self.now.saturating_add(MAX_SOURCE_FUTURE_MS) {
            return Err(SccpLcError::SourceTimeInFuture {
                source_ms,
                taira_now_ms: self.now,
            });
        }
        Ok(())
    }

    fn check_fresh(&self, period: u64) -> Result<(), SccpLcError> {
        let expiry = self
            .profile
            .period_end_ms(period)
            .ok_or(EthereumLcError::TimeOverflow)?;
        if is_set_fresh(Some(expiry), self.ws_bound_ms, self.now) {
            Ok(())
        } else {
            Err(SccpLcError::StaleSigningSet {
                set_id: period,
                stale_from_ms: expiry.saturating_add(self.ws_bound_ms),
            })
        }
    }
}

/// A committee learned from a finalized update.
struct LearnedCommitteeV1<'a> {
    period: u64,
    root: Root,
    wire: &'a EthereumNativeSyncCommitteeV1,
}

/// An update that passed every rule.
struct VerifiedUpdateV1<'a> {
    finalized_slot: u64,
    finalized_root: Root,
    execution: AuthenticatedExecutionBlock,
    next_committee: Option<LearnedCommitteeV1<'a>>,
}

fn detached_error(error: &SccpLcAttemptErrorV1) -> SccpLcError {
    match error {
        SccpLcAttemptErrorV1::Protocol(error) => *error,
        _ => execution(EthereumExecutionError::ResourceLimit),
    }
}
#[cfg(test)]
fn stored_committee(set: &SccpLcConsensusSetRefV1<'_>) -> Result<SyncCommittee, SccpLcError> {
    stored_committee_with(set, &LcMemory::detached()).map_err(|error| detached_error(&error))
}
fn stored_committee_with(
    set: &SccpLcConsensusSetRefV1<'_>,
    memory: &LcMemory<'_>,
) -> Result<SyncCommittee, SccpLcAttemptErrorV1> {
    let malformed =
        || SccpLcError::from(EthereumLcError::MalformedStoredSet { set_id: set.set_id });
    let owner = memory
        .decode_set(set.set_bytes, set.set_bytes.len())
        .map_err(|error| match error {
            SccpLcAttemptErrorV1::Protocol(_) => SccpLcAttemptErrorV1::Protocol(malformed()),
            other => other,
        })?;
    let SccpLcSetDataV1::Ethereum(data) = owner.get() else {
        return Err(malformed().into());
    };
    if data.period != set.set_id {
        return Err(malformed().into());
    }
    data.committee.to_native().map_err(|_| malformed().into())
}

fn verify_update_with<'a, 'wire, F>(
    ctx: &Ctx<'_>,
    lookup: F,
    update: &'wire EthereumNativeLightClientUpdateV1,
    memory: &LcMemory<'_>,
) -> Result<VerifiedUpdateV1<'wire>, SccpLcAttemptErrorV1>
where
    F: Fn(u64) -> Option<SccpLcConsensusSetRefV1<'a>>,
{
    let native = update.to_native().map_err(execution)?;
    let attested_slot = native.attested_header.beacon().slot;
    let finalized_slot = native.finalized_header.beacon().slot;
    for slot in [native.signature_slot, attested_slot, finalized_slot] {
        ctx.check_supported(slot)?;
    }
    ctx.check_not_future(native.signature_slot)?;
    native.verify_structure(&ctx.schedule).map_err(consensus)?;
    let execution_block = native
        .finalized_header
        .authenticated_execution_block()
        .ok_or_else(|| SccpLcError::from(EthereumLcError::MissingExecutionPayload))?;
    let execution_ms = seconds_to_ms(execution_block.timestamp)?;
    let signature_ms = ctx
        .profile
        .slot_start_ms(native.signature_slot)
        .ok_or_else(|| SccpLcError::from(EthereumLcError::TimeOverflow))?;
    if execution_ms > signature_ms {
        return Err(SccpLcError::from(EthereumLcError::ExecutionAfterSignature {
            execution_ms,
            signature_ms,
        })
        .into());
    }
    let period = native.signature_period();
    let set = lookup(period).ok_or(SccpLcError::UnknownSigningSet { set_id: period })?;
    ctx.check_fresh(period)?;
    let committee = stored_committee_with(&set, memory)?;
    native
        .verify_signature(&committee, &ctx.schedule)
        .map_err(consensus)?;
    let next_committee = match (&native.next_sync_committee, &update.next_sync_committee) {
        (Some(next), Some(wire)) => Some(LearnedCommitteeV1 {
            period: sync_committee_period_at_slot(attested_slot)
                .checked_add(1)
                .ok_or_else(|| SccpLcError::from(EthereumLcError::TimeOverflow))?,
            root: next.committee.hash_tree_root(),
            wire: &wire.committee,
        }),
        _ => None,
    };
    Ok(VerifiedUpdateV1 {
        finalized_slot,
        finalized_root: native.finalized_header.beacon().hash_tree_root(),
        execution: execution_block,
        next_committee,
    })
}

fn seconds_to_ms(seconds: u64) -> Result<u64, SccpLcError> {
    seconds
        .checked_mul(1_000)
        .ok_or_else(|| EthereumLcError::TimeOverflow.into())
}

fn execution_checkpoint(
    block: &AuthenticatedExecutionBlock,
) -> Result<SccpLcCheckpointDataV1, SccpLcError> {
    Ok(SccpLcCheckpointDataV1 {
        source_height: block.block_number,
        block_hash: block.block_hash,
        state_root: Some(block.state_root),
        receipts_or_tx_root: block.receipts_root,
        source_time_ms: seconds_to_ms(block.timestamp)?,
    })
}

fn header_checkpoint(
    header: &EthereumExecutionHeaderFieldsV1,
) -> Result<SccpLcCheckpointDataV1, SccpLcError> {
    Ok(SccpLcCheckpointDataV1 {
        source_height: header.number,
        block_hash: header.hash,
        state_root: Some(header.state_root),
        receipts_or_tx_root: header.receipts_root,
        source_time_ms: seconds_to_ms(header.timestamp)?,
    })
}

const fn point(data: &SccpLcCheckpointDataV1) -> SccpLcPointV1 {
    SccpLcPointV1 {
        source_height: data.source_height,
        block_hash: data.block_hash,
        source_time_ms: data.source_time_ms,
    }
}

/// Check one bounded header chain without retaining a second header graph.
fn link_headers(
    start: EthereumExecutionHeaderFieldsV1,
    headers: &[Vec<u8>],
) -> Result<EthereumExecutionHeaderFieldsV1, SccpLcError> {
    let mut previous = start;
    for (index, wire) in headers.iter().enumerate() {
        let header = decode_execution_header(wire).map_err(execution)?;
        if header.parent_hash != previous.hash
            || previous.number.checked_add(1) != Some(header.number)
        {
            return Err(EthereumLcError::AncestryBroken { index }.into());
        }
        previous = header;
    }
    Ok(previous)
}

fn count_bound(param: u32, hard: usize) -> usize {
    usize::try_from(param).unwrap_or(usize::MAX).min(hard)
}

// ---------------------------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------------------------

/// Verify an Ethereum bootstrap (§4.13.2, §4.14.3 `InitializeLightClient`).
///
/// The header lies within the compiled fork bound and not in the future, carries an execution
/// payload, and its period's committee is fresh at `taira_now_ms` and proven by the
/// current-committee branch.
#[cfg(test)]
pub(super) fn verify_bootstrap(
    profile: &EthereumChainProfileV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &EthereumNativeLightClientBootstrapV1,
    taira_now_ms: u64,
) -> Result<SccpLcInitialStateV1, SccpLcError> {
    let mut output = SccpLcDeltaV1::default();
    let head = verify_bootstrap_into(
        profile,
        params,
        bootstrap,
        taira_now_ms,
        &LcMemory::detached(),
        &mut output,
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
        superseded_sets: output.superseded_sets,
        sets: output.new_sets,
        checkpoints: output.checkpoints,
    })
}

pub(super) fn verify_bootstrap_into<D: DeltaWriter>(
    profile: &EthereumChainProfileV1,
    params: &SccpLightClientParamsV1,
    bootstrap: &EthereumNativeLightClientBootstrapV1,
    taira_now_ms: u64,
    _memory: &LcMemory<'_>,
    output: &mut D,
) -> Result<SccpLcHeadV1, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let ctx = Ctx::new(profile, params, taira_now_ms)?;
    let native = bootstrap.to_native().map_err(execution)?;
    let slot = native.header.beacon().slot;
    ctx.check_supported(slot)?;
    ctx.check_not_future(slot)?;
    let execution_block = native
        .header
        .authenticated_execution_block()
        .ok_or(EthereumLcError::MissingExecutionPayload)?;
    let period = sync_committee_period_at_slot(slot);
    ctx.check_fresh(period)?;
    native.verify(&ctx.schedule).map_err(consensus)?;
    let first = period
        .checked_mul(8_192)
        .ok_or(EthereumLcError::TimeOverflow)?;
    output
        .encode_set(
            period,
            first,
            None,
            &SetFrameRef::ethereum(&EthereumSetRef {
                period,
                committee: &bootstrap.current_sync_committee,
            }),
        )
        .map_err(Into::into)?;
    let data = execution_checkpoint(&execution_block)?;
    output
        .checkpoint(SccpLcCheckpointV1 {
            data,
            recorded_at_taira_ms: taira_now_ms,
            origin: SccpLcCheckpointOriginV1::Parliament,
        })
        .map_err(Into::into)?;
    Ok(SccpLcHeadV1 {
        latest_set_id: period,
        latest_finalized: point(&data),
        last_progress_taira_ms: taira_now_ms,
    })
}

// ---------------------------------------------------------------------------------------------
// Advance
// ---------------------------------------------------------------------------------------------

struct CommitteeLearner<'a, V: SccpLcStateView + ?Sized, D: DeltaWriter> {
    view: &'a V,
    profile: &'a EthereumChainProfileV1,
    output: &'a mut D,
    memory: &'a LcMemory<'a>,
}

impl<'a, V: SccpLcStateView + ?Sized, D: DeltaWriter> CommitteeLearner<'a, V, D>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    const fn new(
        view: &'a V,
        profile: &'a EthereumChainProfileV1,
        output: &'a mut D,
        memory: &'a LcMemory<'a>,
    ) -> Self {
        Self {
            view,
            profile,
            output,
            memory,
        }
    }

    fn lookup(&self, period: u64) -> Option<SccpLcConsensusSetRefV1<'_>> {
        self.output
            .find_set(period)
            .or_else(|| self.view.consensus_set(NETWORK, period))
    }

    fn learn(&mut self, next: &LearnedCommitteeV1<'_>) -> Result<(), SccpLcAttemptErrorV1> {
        if let Some(existing) = self.lookup(next.period) {
            if stored_committee_with(&existing, self.memory)?.hash_tree_root() != next.root {
                return Err(
                    SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::ConsensusSet {
                        set_id: next.period,
                    })
                    .into(),
                );
            }
            return Ok(());
        }
        let successor = next
            .period
            .checked_add(1)
            .ok_or_else(|| SccpLcError::from(EthereumLcError::TimeOverflow))?;
        let superseded = if self.lookup(successor).is_some() {
            Some(
                self.profile
                    .period_start_ms(successor)
                    .ok_or_else(|| SccpLcError::from(EthereumLcError::TimeOverflow))?,
            )
        } else {
            None
        };
        if let Some(previous) = next.period.checked_sub(1) {
            let superseded_at = self
                .profile
                .period_start_ms(next.period)
                .ok_or_else(|| SccpLcError::from(EthereumLcError::TimeOverflow))?;
            if self.output.find_set(previous).is_some()
                || self
                    .view
                    .consensus_set(NETWORK, previous)
                    .is_some_and(|stored| stored.superseded_at_source_ms.is_none())
            {
                self.output
                    .supersede(previous, superseded_at)
                    .map_err(Into::into)?;
            }
        }
        let first_height = EthereumChainProfileV1::period_start_slot(next.period)
            .ok_or_else(|| SccpLcError::from(EthereumLcError::TimeOverflow))?;
        self.output
            .encode_set(
                next.period,
                first_height,
                superseded,
                &super::set_ref::SetFrameRef::ethereum(&super::set_ref::EthereumSetRef {
                    period: next.period,
                    committee: next.wire,
                }),
            )
            .map_err(Into::into)
    }
}

/// Verify an Ethereum advance and return what to write.
pub(super) fn apply_advance<V: SccpLcStateView + ?Sized>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    advance: &EthereumLcAdvanceV1,
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

/// One verification algorithm writing into the caller's actual delta owner.
pub(super) fn apply_advance_into<V: SccpLcStateView + ?Sized, D: DeltaWriter>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    advance: &EthereumLcAdvanceV1,
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
    output: &mut D,
) -> Result<Option<SccpLcHeadV1>, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let params = &light_client.params;
    let count = advance.updates.len();
    if count == 0 {
        return Err(SccpLcError::TooFewItems {
            kind: "light-client updates",
            count,
            min: 1,
        }
        .into());
    }
    let max = count_bound(
        params.max_updates_per_advance,
        ETHEREUM_MAX_UPDATES_PER_ADVANCE,
    );
    if count > max {
        return Err(SccpLcError::TooManyItems {
            kind: "light-client updates",
            count,
            max,
        }
        .into());
    }
    let ctx = Ctx::new(profile, params, taira_now_ms)?;
    let mut learner = CommitteeLearner::new(view, profile, output, memory);
    let mut recorder = CheckpointRecorder::new(
        view,
        NETWORK,
        SccpLcCheckpointOriginV1::Advance,
        taira_now_ms,
    );
    let mut latest_set_id = light_client.head.latest_set_id;
    let mut latest_finalized = light_client.head.latest_finalized;
    for update in &advance.updates {
        let verified = verify_update_with(&ctx, |period| learner.lookup(period), update, memory)?;
        let data = execution_checkpoint(&verified.execution)?;
        recorder.record(data)?;
        if data.source_height > latest_finalized.source_height {
            latest_finalized = point(&data);
        }
        if let Some(next) = verified.next_committee {
            latest_set_id = latest_set_id.max(next.period);
            learner.learn(&next)?;
        }
    }
    let moved = latest_set_id != light_client.head.latest_set_id
        || latest_finalized != light_client.head.latest_finalized;
    for checkpoint in recorder.into_records() {
        learner.output.checkpoint(checkpoint).map_err(Into::into)?;
    }
    Ok(moved.then_some(SccpLcHeadV1 {
        latest_set_id,
        latest_finalized,
        last_progress_taira_ms: taira_now_ms,
    }))
}

/// Verify a `Backfill` segment and return the checkpoint of its first header.
pub(super) fn apply_backfill<V: SccpLcStateView + ?Sized>(
    view: &V,
    light_client: &SccpLightClientV1,
    segment: &EthereumHeaderSegmentV1,
    taira_now_ms: u64,
) -> Result<SccpLcDeltaV1, SccpLcError> {
    let mut output = SccpLcDeltaV1::default();
    apply_backfill_into(view, light_client, segment, taira_now_ms, &mut output)
        .map_err(|error| detached_error(&error))?;
    Ok(output)
}

pub(super) fn apply_backfill_into<V: SccpLcStateView + ?Sized, D: DeltaWriter>(
    view: &V,
    light_client: &SccpLightClientV1,
    segment: &EthereumHeaderSegmentV1,
    taira_now_ms: u64,
    output: &mut D,
) -> Result<(), SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let count = segment.headers.len();
    if count < 2 {
        return Err(SccpLcError::TooFewItems {
            kind: "backfill headers",
            count,
            min: 2,
        }
        .into());
    }
    let max = count_bound(
        light_client.params.max_backfill_headers,
        ETHEREUM_MAX_BACKFILL_HEADERS,
    );
    if count > max {
        return Err(SccpLcError::TooManyItems {
            kind: "backfill headers",
            count,
            max,
        }
        .into());
    }
    let first = decode_execution_header(&segment.headers[0]).map_err(execution)?;
    let last = link_headers(first, &segment.headers[1..])?;
    let stored = view
        .checkpoint(NETWORK, last.number)
        .ok_or(SccpLcError::UnknownCheckpoint {
            source_height: last.number,
        })?;
    if stored.data.block_hash != last.hash {
        return Err(EthereumLcError::BackfillAnchorMismatch {
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
    recorder.record(header_checkpoint(&first)?)?;
    for checkpoint in recorder.into_records() {
        output.checkpoint(checkpoint).map_err(Into::into)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------------------------

fn verify_history(
    ctx: &Ctx<'_>,
    event: &EthereumExecutionHeaderFieldsV1,
    anchor: &SccpLcCheckpointDataV1,
    history: &EthereumHistoryProofV1,
) -> Result<(), SccpLcError> {
    let state_root = anchor
        .state_root
        .ok_or(EthereumLcError::HistoryContractUnavailable)?;
    let active_from = ctx
        .profile
        .history_contract_active_from_ms()
        .ok_or(EthereumLcError::TimeOverflow)?;
    if anchor.source_time_ms < active_from {
        return Err(EthereumLcError::HistoryContractUnavailable.into());
    }
    let window = ctx.profile.history_serve_window;
    let in_window = anchor
        .source_height
        .checked_sub(event.number)
        .is_some_and(|distance| (1..=window).contains(&distance));
    if !in_window || window == 0 {
        return Err(EthereumLcError::HistoryWindow {
            event_height: event.number,
            anchor_height: anchor.source_height,
        }
        .into());
    }
    let account_key = keccak256(&[&ctx.profile.history_storage_address]);
    let account_value = crate::ethereum_source::verify_mpt_inclusion_ref(
        state_root,
        &account_key,
        &history.account_proof,
        EthereumMptRoleV1::Account,
    )
    .map_err(execution)?;
    let account = decode_account(account_value).map_err(execution)?;
    if account.code_hash != ctx.profile.history_storage_code_hash {
        return Err(EthereumLcError::HistoryCodeHashMismatch.into());
    }
    let storage_key = keccak256(&[&word_u64(event.number % window)]);
    let storage_value = crate::ethereum_source::verify_mpt_inclusion_ref(
        account.storage_root,
        &storage_key,
        &history.storage_proof,
        EthereumMptRoleV1::Storage,
    )
    .map_err(execution)?;
    if decode_storage_word(storage_value).map_err(execution)? != event.hash {
        return Err(EthereumLcError::HistoryValueMismatch.into());
    }
    Ok(())
}

fn verify_ancestry(
    ctx: &Ctx<'_>,
    params: &SccpLightClientParamsV1,
    event: &EthereumExecutionHeaderFieldsV1,
    anchor: &SccpLcCheckpointDataV1,
    ancestry: &EthereumAncestryV1,
) -> Result<(), SccpLcError> {
    let end = match ancestry {
        EthereumAncestryV1::SameBlock => *event,
        EthereumAncestryV1::HeaderChain(segment) => {
            let count = segment.headers.len();
            if count == 0 {
                return Err(SccpLcError::TooFewItems {
                    kind: "ancestry headers",
                    count,
                    min: 1,
                });
            }
            let max = count_bound(params.max_ancestry_headers, ETHEREUM_MAX_ANCESTRY_HEADERS);
            if count > max {
                return Err(SccpLcError::TooManyItems {
                    kind: "ancestry headers",
                    count,
                    max,
                });
            }
            link_headers(*event, &segment.headers)?
        }
        EthereumAncestryV1::HistoryContract(history) => {
            return verify_history(ctx, event, anchor, history);
        }
    };
    if end.hash == anchor.block_hash && end.number == anchor.source_height {
        Ok(())
    } else {
        Err(EthereumLcError::AncestryAnchorMismatch.into())
    }
}

/// Open the successful receipt `transaction_index` under `receipts_root` (shared with BSC).
pub(super) fn open_receipt<'a>(
    receipts_root: [u8; 32],
    transaction_index: u32,
    proof: &'a EthereumNativeMptProofV1,
    memory: &LcMemory<'_>,
) -> Result<crate::ethereum_source::EthereumReceiptOwner<'a>, SccpLcAttemptErrorV1> {
    // Canonical RLP u32 key is at most five bytes, including its scalar prefix.
    let bytes = transaction_index.to_be_bytes();
    let leading = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut key = [0u8; 5];
    let key_len = if transaction_index == 0 {
        key[0] = 0x80;
        1
    } else if transaction_index < 0x80 {
        key[0] = bytes[3];
        1
    } else {
        let count = 4 - leading;
        key[0] = 0x80 + u8::try_from(count).expect("u32 RLP keys contain at most four bytes");
        key[1..=count].copy_from_slice(&bytes[leading..]);
        count + 1
    };
    let value = crate::ethereum_source::verify_mpt_inclusion_ref(
        receipts_root,
        &key[..key_len],
        proof,
        EthereumMptRoleV1::Receipt,
    )
    .map_err(execution)?;
    let receipt = memory
        .native()
        .finish(crate::ethereum_source::decode_receipt_native(
            value,
            memory.native(),
        ))
        .map_err(|error| match error {
            crate::native_memory::AttemptError::Protocol(error) => {
                SccpLcAttemptErrorV1::Protocol(execution(error))
            }
            crate::native_memory::AttemptError::Allocation(error) => error.into(),
        })?;
    if !receipt.success {
        return Err(SccpLcError::from(EthereumLcError::FailedReceipt).into());
    }
    Ok(receipt)
}

fn log_at<'a, 'wire>(
    receipt: &'a crate::ethereum_source::EthereumReceiptOwner<'wire>,
    index: u32,
) -> Result<&'a crate::ethereum_source::EthereumLogRef<'wire>, SccpLcError> {
    usize::try_from(index)
        .ok()
        .and_then(|position| receipt.logs.get(position))
        .ok_or_else(|| {
            EthereumLcError::LogIndexOutOfRange {
                index,
                logs: receipt.logs.len(),
            }
            .into()
        })
}

/// Select the SCCP event of `receipt` named by `selector` (shared with BSC).
pub(super) fn select_event(
    receipt: &crate::ethereum_source::EthereumReceiptOwner<'_>,
    selector: EthereumEventSelectorV1,
    locator: SccpSourceLocatorV1,
) -> Result<SccpNativeEventV1, SccpLcError> {
    match selector {
        EthereumEventSelectorV1::Finalized(reference) => {
            let log = log_at(receipt, reference.log_index)?;
            let decoded =
                FinalizedLogV1::decode(log.topics(), log.data).map_err(EthereumLcError::Event)?;
            Ok(SccpNormalizedEventV1::Finalized {
                emitter: SccpSourceEmitterV1::Evm(log.address),
                message_id: decoded.message_id,
                nonce: decoded.nonce,
                amount: Some(decoded.token_amount),
                locator,
            })
        }
        EthereumEventSelectorV1::TransferToTaira(reference) => {
            let log = log_at(receipt, reference.log_index)?;
            let decoded = TransferToTairaLogV1::decode_ref(log.topics(), log.data)
                .map_err(EthereumLcError::Event)?;
            Ok(SccpNormalizedEventV1::TransferToTaira {
                emitter: SccpSourceEmitterV1::Evm(log.address),
                message_id: decoded.message_id,
                sender: SccpSourceSenderV1::Evm(decoded.sender),
                nonce: decoded.nonce,
                payload_hash: payload_hash(decoded.payload),
                locator,
            })
        }
        EthereumEventSelectorV1::Void(range) => select_voids(receipt, range, locator),
    }
}

fn select_voids(
    receipt: &crate::ethereum_source::EthereumReceiptOwner<'_>,
    range: EthereumLogRangeV1,
    locator: SccpSourceLocatorV1,
) -> Result<SccpNativeEventV1, SccpLcError> {
    let count = u64::from(range.log_count);
    if count == 0 || count > MAX_VOID_FROZEN_RANGE_EVM {
        return Err(EthereumLcError::VoidRangeInvalid.into());
    }
    let emitter = log_at(receipt, range.first_log_index)?.address;
    let mut first = None;
    let mut consecutive = true;
    for offset in 0..range.log_count {
        let index = range
            .first_log_index
            .checked_add(offset)
            .ok_or(EthereumLcError::VoidRangeInvalid)?;
        let log = log_at(receipt, index)?;
        if log.address != emitter {
            return Err(EthereumLcError::VoidRangeInvalid.into());
        }
        let void = VoidedLogV1::decode(log.topics(), log.data).map_err(EthereumLcError::Event)?;
        let initial = *first.get_or_insert(void);
        consecutive &=
            void.is_frozen() && initial.nonce.checked_add(u64::from(offset)) == Some(void.nonce);
    }
    let first = first.ok_or(EthereumLcError::VoidRangeInvalid)?;
    if count == 1 && !first.is_frozen() {
        return Ok(SccpNormalizedEventV1::Void {
            emitter: SccpSourceEmitterV1::Evm(emitter),
            kind: SccpVoidKindV1::Expired,
            first_nonce: first.nonce,
            count: 1,
            message_id_or_zero: first.message_id,
            locator,
        });
    }
    if !consecutive {
        return Err(EthereumLcError::VoidRangeInvalid.into());
    }
    Ok(SccpNormalizedEventV1::Void {
        emitter: SccpSourceEmitterV1::Evm(emitter),
        kind: SccpVoidKindV1::Frozen,
        first_nonce: first.nonce,
        count,
        message_id_or_zero: [0; 32],
        locator,
    })
}

/// Verify an Ethereum inbound, finalized-mint or void proof.
pub(super) fn verify_proof<V: SccpLcStateView + ?Sized>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    proof: &EthereumSourceProofV1,
    taira_now_ms: u64,
) -> Result<SccpVerifiedProofV1, SccpLcError> {
    let mut output = SccpLcDeltaV1::default();
    let event = verify_proof_native(
        profile,
        view,
        light_client,
        proof,
        taira_now_ms,
        &LcMemory::detached(),
        &mut output,
    )
    .map_err(|error| detached_error(&error))?;
    Ok(SccpVerifiedProofV1 {
        event: event.into_detached(),
        checkpoints: output.checkpoints,
    })
}

pub(super) fn verify_proof_native<V: SccpLcStateView + ?Sized, D: DeltaWriter>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    proof: &EthereumSourceProofV1,
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
    output: &mut D,
) -> Result<SccpNativeEventV1, SccpLcAttemptErrorV1>
where
    D::Error: Into<SccpLcAttemptErrorV1>,
{
    let params = &light_client.params;
    let ctx = Ctx::new(profile, params, taira_now_ms)?;
    let mut recorder =
        CheckpointRecorder::new(view, NETWORK, SccpLcCheckpointOriginV1::Proof, taira_now_ms);
    let anchor = match &proof.anchor {
        EthereumProofAnchorV1::FinalityUpdate(update) => {
            let verified = verify_update_with(
                &ctx,
                |period| view.consensus_set(NETWORK, period),
                update,
                memory,
            )?;
            let data = execution_checkpoint(&verified.execution)?;
            recorder.record(data)?;
            data
        }
        EthereumProofAnchorV1::StoredCheckpoint(reference) => {
            view.checkpoint(NETWORK, reference.source_height)
                .ok_or(SccpLcError::UnknownCheckpoint {
                    source_height: reference.source_height,
                })?
                .data
        }
    };
    let event_block = decode_execution_header(&proof.event_header).map_err(execution)?;
    verify_ancestry(&ctx, params, &event_block, &anchor, &proof.ancestry)?;
    recorder.record(header_checkpoint(&event_block)?)?;
    let receipt = open_receipt(
        event_block.receipts_root,
        proof.transaction_index,
        &proof.receipt_proof,
        memory,
    )?;
    let locator = SccpSourceLocatorV1 {
        source_height: event_block.number,
        block_hash: event_block.hash,
        index_in_block: proof.transaction_index,
    };
    let event = select_event(&receipt, proof.event, locator)?;
    for checkpoint in recorder.into_records() {
        output.checkpoint(checkpoint).map_err(Into::into)?;
    }
    Ok(event)
}

// ---------------------------------------------------------------------------------------------
// Equivocation
// ---------------------------------------------------------------------------------------------

/// What one verified evidence record asserts about the source chain.
struct EvidenceClaimsV1 {
    finalized_slot: u64,
    finalized_root: Root,
    next_committee: Option<(u64, Root)>,
    /// Finalized execution blocks: the update's, and a `FinalizedAncestor`'s ancestor.
    blocks: [Option<SccpLcCheckpointDataV1>; 2],
}

fn verify_evidence<V: SccpLcStateView + ?Sized>(
    ctx: &Ctx<'_>,
    params: &SccpLightClientParamsV1,
    view: &V,
    evidence: &EthereumLcEvidenceV1,
    memory: &LcMemory<'_>,
) -> Result<EvidenceClaimsV1, SccpLcAttemptErrorV1> {
    let (update, ancestor) = match evidence {
        EthereumLcEvidenceV1::Update(update) => (update.as_ref(), None),
        EthereumLcEvidenceV1::FinalizedAncestor(record) => (&record.update, Some(record.as_ref())),
    };
    let verified = verify_update_with(
        ctx,
        |period| view.consensus_set(NETWORK, period),
        update,
        memory,
    )?;
    let finalized = execution_checkpoint(&verified.execution)?;
    let mut blocks = [Some(finalized), None];
    if let Some(record) = ancestor {
        let header = decode_execution_header(&record.header).map_err(execution)?;
        verify_ancestry(ctx, params, &header, &finalized, &record.ancestry)?;
        blocks[1] = Some(header_checkpoint(&header)?);
    }
    Ok(EvidenceClaimsV1 {
        finalized_slot: verified.finalized_slot,
        finalized_root: verified.finalized_root,
        next_committee: verified
            .next_committee
            .map(|committee| (committee.period, committee.root)),
        blocks,
    })
}

/// Whether two finalized execution blocks cannot lie on one chain: one height with different
/// content, or heights and times ordered inconsistently.
fn blocks_conflict(a: &SccpLcCheckpointDataV1, b: &SccpLcCheckpointDataV1) -> bool {
    match a.source_height.cmp(&b.source_height) {
        Ordering::Equal => !same_checkpoint_block(a, b),
        Ordering::Less => a.source_time_ms >= b.source_time_ms,
        Ordering::Greater => a.source_time_ms <= b.source_time_ms,
    }
}

fn claims_conflict(a: &EvidenceClaimsV1, b: &EvidenceClaimsV1) -> bool {
    let finalized = a.finalized_slot == b.finalized_slot && a.finalized_root != b.finalized_root;
    let committee = matches!(
        (a.next_committee, b.next_committee),
        (Some((x_period, x_root)), Some((y_period, y_root)))
            if x_period == y_period && x_root != y_root
    );
    let execution = a
        .blocks
        .iter()
        .flatten()
        .any(|x| b.blocks.iter().flatten().any(|y| blocks_conflict(x, y)));
    finalized || committee || execution
}

/// Verify two conflicting Ethereum records and return the freeze reason.
///
/// Both records must pass every advance rule under fresh stored committees (and, for a
/// `FinalizedAncestor`, the proof ancestry rules). They conflict when they finalize different
/// beacon blocks at one slot, teach different next committees for one period, or assert
/// finalized execution blocks that cannot share one chain (see the module documentation).
pub(super) fn verify_equivocation<V: SccpLcStateView + ?Sized>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    first: (&EthereumLcEvidenceV1, &[u8]),
    second: (&EthereumLcEvidenceV1, &[u8]),
    taira_now_ms: u64,
) -> Result<SccpLcFreezeReasonV1, SccpLcError> {
    verify_equivocation_native(
        profile,
        view,
        light_client,
        first,
        second,
        taira_now_ms,
        &LcMemory::detached(),
    )
    .map_err(|error| detached_error(&error))
}

pub(super) fn verify_equivocation_native<V: SccpLcStateView + ?Sized>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
    first: (&EthereumLcEvidenceV1, &[u8]),
    second: (&EthereumLcEvidenceV1, &[u8]),
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
) -> Result<SccpLcFreezeReasonV1, SccpLcAttemptErrorV1> {
    if first.1 == second.1 {
        return Err(SccpLcError::EvidenceNotConflicting.into());
    }
    let params = &light_client.params;
    let ctx = Ctx::new(profile, params, taira_now_ms)?;
    let a = verify_evidence(&ctx, params, view, first.0, memory)?;
    let b = verify_evidence(&ctx, params, view, second.0, memory)?;
    if !claims_conflict(&a, &b) {
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

/// Whether the newest stored committee is beyond the weak-subjectivity bound.
pub(super) fn is_aged(
    profile: &EthereumChainProfileV1,
    light_client: &SccpLightClientV1,
    taira_now_ms: u64,
) -> bool {
    let expiry = profile
        .period_end_ms(light_client.head.latest_set_id)
        .unwrap_or(u64::MAX);
    !is_set_fresh(Some(expiry), light_client.params.ws_bound_ms, taira_now_ms)
}

/// Taira time from which the newest stored committee is stale: the end of its period plus
/// `ws_bound_ms`.
pub(super) fn weak_subjectivity_deadline_ms(
    profile: &EthereumChainProfileV1,
    light_client: &SccpLightClientV1,
) -> u64 {
    profile
        .period_end_ms(light_client.head.latest_set_id)
        .unwrap_or(u64::MAX)
        .saturating_add(light_client.params.ws_bound_ms)
}

/// Supersession of an aged light client's newest committee, recorded when a fresh bootstrap
/// re-initializes it without a purge: the committee's period ended when the next one started.
pub(super) fn aged_supersession<V: SccpLcStateView + ?Sized>(
    profile: &EthereumChainProfileV1,
    view: &V,
    light_client: &SccpLightClientV1,
) -> Result<Option<SccpLcSupersessionV1>, SccpLcError> {
    let period = light_client.head.latest_set_id;
    if !view
        .consensus_set(NETWORK, period)
        .is_some_and(|set| set.is_current())
    {
        return Ok(None);
    }
    let successor = period.checked_add(1).ok_or(EthereumLcError::TimeOverflow)?;
    Ok(Some(SccpLcSupersessionV1 {
        set_id: period,
        superseded_at_source_ms: profile
            .period_start_ms(successor)
            .ok_or(EthereumLcError::TimeOverflow)?,
    }))
}

fn header_bytes(headers: &[Vec<u8>]) -> u64 {
    headers
        .iter()
        .map(|header| u64::try_from(header.len()).unwrap_or(u64::MAX))
        .fold(0, u64::saturating_add)
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Work of an advance: one BLS check per update.
pub(super) fn advance_work(advance: &EthereumLcAdvanceV1) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        ethereum_light_client_updates: saturating_u32(advance.updates.len()),
        ..SccpVerifierWorkV1::default()
    }
}

/// Work of a backfill: its headers.
pub(super) fn segment_work(segment: &EthereumHeaderSegmentV1) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        native_headers: saturating_u32(segment.headers.len()),
        native_header_bytes: header_bytes(&segment.headers),
        ..SccpVerifierWorkV1::default()
    }
}

/// Headers hashed for `ancestry` plus the `header` it starts from.
fn ancestry_work(ancestry: &EthereumAncestryV1, header: &[u8]) -> SccpVerifierWorkV1 {
    let chain: &[Vec<u8>] = match ancestry {
        EthereumAncestryV1::HeaderChain(segment) => &segment.headers,
        EthereumAncestryV1::SameBlock | EthereumAncestryV1::HistoryContract(_) => &[],
    };
    SccpVerifierWorkV1 {
        native_headers: saturating_u32(chain.len()).saturating_add(1),
        native_header_bytes: header_bytes(chain)
            .saturating_add(u64::try_from(header.len()).unwrap_or(u64::MAX)),
        ..SccpVerifierWorkV1::default()
    }
}

/// Work of a proof: one proof, its finality update and every header it hashes.
pub(super) fn proof_work(proof: &EthereumSourceProofV1) -> SccpVerifierWorkV1 {
    SccpVerifierWorkV1 {
        proofs: 1,
        ethereum_light_client_updates: u32::from(matches!(
            proof.anchor,
            EthereumProofAnchorV1::FinalityUpdate(_)
        )),
        ..ancestry_work(&proof.ancestry, &proof.event_header)
    }
}

/// Work of one evidence record: one BLS check, plus the headers of a `FinalizedAncestor`.
pub(super) fn evidence_work(evidence: &EthereumLcEvidenceV1) -> SccpVerifierWorkV1 {
    let hashed = match evidence {
        EthereumLcEvidenceV1::Update(_) => SccpVerifierWorkV1::default(),
        EthereumLcEvidenceV1::FinalizedAncestor(record) => {
            ancestry_work(&record.ancestry, &record.header)
        }
    };
    SccpVerifierWorkV1 {
        ethereum_light_client_updates: 1,
        ..hashed
    }
}

#[cfg(test)]
mod tests {
    use crate::ethereum_source::EthereumReceiptV1;
    use crate::v1::{constants::CODEC_EVM_ADDRESS20, payload::PayloadAccountV1};

    // Test-only convenience inputs enter the same borrowed receipt decoder and selector.
    fn select_voids(
        receipt: &EthereumReceiptV1,
        range: super::EthereumLogRangeV1,
        locator: iroha_data_model::sccp::inbound::SccpSourceLocatorV1,
    ) -> Result<super::SccpNormalizedEventV1, super::SccpLcError> {
        let bytes = crate::ethereum_source::encode_receipt(receipt, &[0; 256]);
        let memory = super::LcMemory::detached();
        let receipt = crate::ethereum_source::decode_receipt_native(&bytes, memory.native())
            .map_err(super::execution)?;
        super::select_voids(&receipt, range, locator).map(super::SccpNativeEventV1::into_detached)
    }
    use super::*;
    use crate::{
        ethereum_native::{FINALITY_PARTICIPANT_THRESHOLD, SYNC_COMMITTEE_SIZE},
        ethereum_source::EthereumLogV1,
        light_client::{
            profile::ETHEREUM_MAINNET,
            state::{SccpLcMemoryStateV1, SccpLcRetentionClassV1, retention_class},
        },
        test_support::ethereum::{
            SyntheticBeaconChainV1, SyntheticBlockFieldsV1, SyntheticExecutionHeaderV1,
            SyntheticUpdateSpecV1, execution_header_rlp, execution_of, header_chain, history_state,
            receipt_root_and_proof, successful_receipt, transfer_log, voided_log,
        },
    };

    const PERIOD: u64 = 1_868;
    const EMITTER: [u8; 20] = [0xe1; 20];

    fn slot(offset: u64) -> u64 {
        PERIOD * 8_192 + offset
    }

    fn params() -> SccpLightClientParamsV1 {
        SccpLightClientParamsV1::defaults_for(NETWORK).expect("external")
    }

    fn installed(chain: &SyntheticBeaconChainV1, now: u64) -> SccpLcMemoryStateV1 {
        let data = SccpLcSetDataV1::Ethereum(EthereumSyncCommitteeSetV1 {
            period: PERIOD,
            committee: chain.committee(PERIOD),
        });
        let bootstrap = chain.bootstrap_wire(slot(64), &chain.synthetic_execution(slot(64)));
        let initial =
            verify_bootstrap(chain.profile(), &params(), &bootstrap, now).expect("fresh bootstrap");
        assert_eq!(
            initial.sets[0].set_bytes,
            data.to_frame().expect("set frame")
        );
        let mut memory = SccpLcMemoryStateV1::new();
        memory.install(NETWORK, &initial);
        memory
    }

    fn light_client(memory: &SccpLcMemoryStateV1) -> SccpLightClientV1 {
        memory.light_client(NETWORK).expect("installed")
    }

    fn spec(chain: &SyntheticBeaconChainV1, signature_offset: u64) -> SyntheticUpdateSpecV1 {
        SyntheticUpdateSpecV1 {
            attested_slot: slot(signature_offset - 1),
            finalized_slot: slot(signature_offset - 40),
            finalized_execution: chain.synthetic_execution(slot(signature_offset - 40)),
            signature_slot: slot(signature_offset),
            include_next_committee: true,
            participants: SYNC_COMMITTEE_SIZE,
            signing_period: None,
            next_committee_period: None,
        }
    }

    fn advance_of(updates: Vec<EthereumNativeLightClientUpdateV1>) -> EthereumLcAdvanceV1 {
        EthereumLcAdvanceV1 { updates }
    }

    #[test]
    fn bootstrap_installs_the_period_set_checkpoint_and_head() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(100));
        let memory = installed(&chain, now);
        let client = light_client(&memory);
        assert_eq!(client.head.latest_set_id, PERIOD);
        assert_eq!(client.head.latest_finalized.source_height, slot(64));
        assert_eq!(client.head.last_progress_taira_ms, now);
        assert_eq!(
            client.state_hash,
            state_hash(&client.params, &client.head, None)
        );
        let set = memory.consensus_set(NETWORK, PERIOD).expect("set");
        assert_eq!(set.valid_from_source_height, PERIOD * 8_192);
        assert!(set.is_current());
        let checkpoint = memory.checkpoint(NETWORK, slot(64)).expect("checkpoint");
        assert_eq!(checkpoint.origin, SccpLcCheckpointOriginV1::Parliament);
        assert_eq!(
            stored_committee(&set).expect("decodes").hash_tree_root(),
            chain
                .committee(PERIOD)
                .to_native()
                .expect("committee")
                .hash_tree_root()
        );
        assert!(!is_aged(&ETHEREUM_MAINNET, &client, now));
    }

    #[test]
    fn bootstrap_rejects_stale_future_fork_bound_and_forged_branches() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let bootstrap = chain.bootstrap_wire(slot(64), &chain.synthetic_execution(slot(64)));
        let period_end = ETHEREUM_MAINNET.period_end_ms(PERIOD).expect("time");
        let ws = params().ws_bound_ms;
        assert!(
            verify_bootstrap(
                &ETHEREUM_MAINNET,
                &params(),
                &bootstrap,
                period_end + ws - 1
            )
            .is_ok()
        );
        assert_eq!(
            verify_bootstrap(&ETHEREUM_MAINNET, &params(), &bootstrap, period_end + ws),
            Err(SccpLcError::StaleSigningSet {
                set_id: PERIOD,
                stale_from_ms: period_end + ws,
            })
        );
        let header_ms = chain.slot_unix_ms(slot(64));
        assert!(matches!(
            verify_bootstrap(
                &ETHEREUM_MAINNET,
                &params(),
                &bootstrap,
                header_ms - MAX_SOURCE_FUTURE_MS - 1
            ),
            Err(SccpLcError::SourceTimeInFuture { .. })
        ));
        let bounded = ETHEREUM_MAINNET.with_supported_until_epoch(slot(64) / 32 - 1);
        assert_eq!(
            verify_bootstrap(&bounded, &params(), &bootstrap, header_ms),
            Err(SccpLcError::ForkBeyondSupported {
                epoch: slot(64) / 32,
                supported_until: slot(64) / 32 - 1,
            })
        );
        let mut forged = bootstrap;
        forged.current_sync_committee_branch[0][0] ^= 1;
        assert_eq!(
            verify_bootstrap(&ETHEREUM_MAINNET, &params(), &forged, header_ms),
            Err(consensus(
                EthereumLightClientError::InvalidCurrentCommitteeBranch
            ))
        );
    }

    #[test]
    fn advance_learns_the_next_committee_moves_the_head_and_is_idempotent() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let mut memory = installed(&chain, now);
        let client = light_client(&memory);
        let advance = advance_of(vec![chain.update(&spec(&chain, 200))]);
        let delta = apply_advance(&ETHEREUM_MAINNET, &memory, &client, &advance, now + 1)
            .expect("valid advance");
        assert_eq!(delta.new_sets.len(), 1);
        assert_eq!(delta.new_sets[0].set_id, PERIOD + 1);
        assert_eq!(
            delta.superseded_sets,
            vec![SccpLcSupersessionV1 {
                set_id: PERIOD,
                superseded_at_source_ms: ETHEREUM_MAINNET
                    .period_start_ms(PERIOD + 1)
                    .expect("time"),
            }]
        );
        assert_eq!(delta.checkpoints.len(), 1);
        assert_eq!(
            delta.checkpoints[0].origin,
            SccpLcCheckpointOriginV1::Advance
        );
        let head = delta.head.expect("head moves");
        assert_eq!(head.latest_set_id, PERIOD + 1);
        assert_eq!(head.latest_finalized.source_height, slot(160));
        assert_eq!(head.last_progress_taira_ms, now + 1);
        memory.apply(NETWORK, &delta);
        let again = apply_advance(
            &ETHEREUM_MAINNET,
            &memory,
            &light_client(&memory),
            &advance,
            now + 2,
        )
        .expect("re-proving stored data succeeds");
        assert!(again.is_empty());
        assert_eq!(advance_work(&advance).ethereum_light_client_updates, 1);
    }

    #[test]
    fn advance_rejects_participation_slot_order_and_period_rule_violations() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let client = light_client(&memory);
        let run_at = |spec: SyntheticUpdateSpecV1, at: u64| {
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                &advance_of(vec![chain.update(&spec)]),
                at,
            )
        };
        let run = |spec: SyntheticUpdateSpecV1| run_at(spec, now);
        let threshold = SyntheticUpdateSpecV1 {
            participants: FINALITY_PARTICIPANT_THRESHOLD,
            ..spec(&chain, 200)
        };
        assert!(run(threshold).is_ok());
        assert_eq!(
            run(SyntheticUpdateSpecV1 {
                participants: FINALITY_PARTICIPANT_THRESHOLD - 1,
                ..spec(&chain, 200)
            }),
            Err(consensus(
                EthereumLightClientError::InsufficientParticipation(341)
            ))
        );
        assert_eq!(
            run(SyntheticUpdateSpecV1 {
                attested_slot: slot(200),
                ..spec(&chain, 200)
            }),
            Err(consensus(EthereumLightClientError::InvalidSlotOrder))
        );
        let crossing = SyntheticUpdateSpecV1 {
            attested_slot: (PERIOD + 1) * 8_192 + 3,
            finalized_slot: (PERIOD + 1) * 8_192 - 5,
            finalized_execution: chain.synthetic_execution((PERIOD + 1) * 8_192 - 5),
            signature_slot: (PERIOD + 1) * 8_192 + 4,
            signing_period: Some(PERIOD),
            ..spec(&chain, 200)
        };
        assert_eq!(
            run_at(crossing, chain.slot_unix_ms(crossing.signature_slot)),
            Err(consensus(
                EthereumLightClientError::NextCommitteePeriodMismatch
            ))
        );
        assert_eq!(
            run(SyntheticUpdateSpecV1 {
                signing_period: Some(PERIOD + 3),
                ..spec(&chain, 200)
            }),
            Err(consensus(
                EthereumLightClientError::InvalidSyncCommitteeSignature
            ))
        );
    }

    #[test]
    fn advance_rejects_missing_finality_branch_unknown_sets_and_bounds() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let client = light_client(&memory);
        let mut missing = chain.update(&spec(&chain, 200));
        missing.finality_branch.clear();
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                &advance_of(vec![missing]),
                now
            ),
            Err(execution(EthereumExecutionError::MalformedWire(
                "finality branch"
            )))
        );
        let next_period = SyntheticUpdateSpecV1 {
            attested_slot: slot(8_192 + 10),
            finalized_slot: slot(8_192 + 5),
            finalized_execution: chain.synthetic_execution(slot(8_192 + 5)),
            signature_slot: slot(8_192 + 11),
            ..spec(&chain, 200)
        };
        let later = chain.slot_unix_ms(slot(8_192 + 20));
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                &advance_of(vec![chain.update(&next_period)]),
                later
            ),
            Err(SccpLcError::UnknownSigningSet { set_id: PERIOD + 1 })
        );
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                &advance_of(Vec::new()),
                now
            ),
            Err(SccpLcError::TooFewItems {
                kind: "light-client updates",
                count: 0,
                min: 1,
            })
        );
        let mut small = client;
        small.params.max_updates_per_advance = 1;
        let update = chain.update(&spec(&chain, 200));
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &small,
                &advance_of(vec![update.clone(), update]),
                now
            ),
            Err(SccpLcError::TooManyItems {
                kind: "light-client updates",
                count: 2,
                max: 1,
            })
        );
    }

    #[test]
    fn conflicting_committees_and_checkpoints_point_to_equivocation() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let mut memory = installed(&chain, now);
        let delta = apply_advance(
            &ETHEREUM_MAINNET,
            &memory,
            &light_client(&memory),
            &advance_of(vec![chain.update(&spec(&chain, 200))]),
            now,
        )
        .expect("valid");
        memory.apply(NETWORK, &delta);
        let client = light_client(&memory);
        let other_committee = SyntheticUpdateSpecV1 {
            next_committee_period: Some(PERIOD + 9),
            ..spec(&chain, 220)
        };
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                &advance_of(vec![chain.update(&other_committee)]),
                now
            ),
            Err(SccpLcError::ConflictsWithStoredData(
                SccpLcConflictV1::ConsensusSet { set_id: PERIOD + 1 }
            ))
        );
        let mut forked = chain.synthetic_execution(slot(160));
        forked.block_hash[0] ^= 1;
        let other_block = SyntheticUpdateSpecV1 {
            finalized_execution: forked,
            ..spec(&chain, 200)
        };
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                &advance_of(vec![chain.update(&other_block)]),
                now
            ),
            Err(SccpLcError::ConflictsWithStoredData(
                SccpLcConflictV1::Checkpoint {
                    source_height: slot(160)
                }
            ))
        );
    }

    #[test]
    fn one_advance_catches_up_several_periods() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms((PERIOD + 3) * 8_192 + 500);
        let memory = installed(&chain, now);
        let crate::light_client::proof::SccpLcAdvanceV1::Ethereum(advance) =
            chain.catch_up_advance(PERIOD, PERIOD + 3)
        else {
            unreachable!("synthetic catch-up advances are Ethereum advances")
        };
        let delta = apply_advance(
            &ETHEREUM_MAINNET,
            &memory,
            &light_client(&memory),
            &advance,
            now,
        )
        .expect("catch-up");
        let ids: Vec<u64> = delta.new_sets.iter().map(|set| set.set_id).collect();
        assert_eq!(ids, vec![PERIOD + 1, PERIOD + 2, PERIOD + 3]);
        assert!(delta.new_sets[0].superseded_at_source_ms.is_some());
        assert!(delta.new_sets[1].superseded_at_source_ms.is_some());
        assert!(delta.new_sets[2].superseded_at_source_ms.is_none());
        assert_eq!(delta.superseded_sets.len(), 1);
        assert_eq!(delta.head.expect("moves").latest_set_id, PERIOD + 3);
    }

    #[test]
    fn admitted_advance_and_proof_keep_original_pool_and_borrowed_overlay() {
        use crate::light_client::{
            prepared::PreparedLcFrameV1,
            profile::SccpChainProfilesV1,
            proof::{SccpLcAdvanceV1, SccpSourceProofV1},
            state::admitted::{SccpLcDeltaReadV1, SccpLcOverlayV1},
        };
        use iroha_allocation::AllocationBudget;

        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(8_192 + 300));
        let original = installed(&chain, now);
        let original_head = light_client(&original);
        let original_bytes = original
            .consensus_set(NETWORK, PERIOD)
            .unwrap()
            .set_bytes
            .as_ptr();
        let advance = chain.catch_up_advance(PERIOD, PERIOD + 1);
        let frame = advance.to_bytes().unwrap();
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let prepared =
            PreparedLcFrameV1::advance(frame.as_bytes(), 4 * 1024 * 1024, &budget).unwrap();
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let verify =
            || prepared.verify_advance(SccpChainProfilesV1::latest(), &original, NETWORK, now);
        assert!(
            matches!(verify(), Err(SccpLcAttemptErrorV1::Output(_))),
            "native output admission must refuse the exhausted original pool"
        );
        let foreign = AllocationBudget::new(32 * 1024 * 1024);
        drop(foreign.try_reserve_bytes(foreign.limit_bytes()).unwrap());
        assert!(matches!(verify(), Err(SccpLcAttemptErrorV1::Output(_))));
        drop(occupied);
        let delta = verify().expect("original release permits genuine catch-up");
        let SccpLcAdvanceV1::Ethereum(advance) = &advance else {
            unreachable!()
        };
        let detached =
            apply_advance(&ETHEREUM_MAINNET, &original, &original_head, advance, now).unwrap();
        assert_eq!(delta.head(), detached.head);
        assert_eq!(delta.checkpoints(), detached.checkpoints);
        assert_eq!(
            delta.set(0).unwrap().set_bytes,
            detached.new_sets[0].set_bytes
        );

        let (header, receipt_proof) =
            inbound_block(&chain, vec![transfer_log(EMITTER, &transfer())]);
        let proof = SccpSourceProofV1::Ethereum(EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
                chain.finality_update_for(execution_of(&header), slot(8_192 + 200)),
            )),
            ancestry: EthereumAncestryV1::SameBlock,
            event_header: header,
            transaction_index: 1,
            receipt_proof,
            event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        });
        let proof_frame = proof.to_bytes().unwrap();
        let proof =
            PreparedLcFrameV1::proof(proof_frame.as_bytes(), 4 * 1024 * 1024, &budget).unwrap();
        assert!(
            proof
                .verify_proof(SccpChainProfilesV1::latest(), &original, NETWORK, now)
                .is_err(),
            "the proof requires the signed advance's newly learned committee"
        );
        let overlay = SccpLcOverlayV1::new(&original, NETWORK, std::slice::from_ref(&delta));
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(
            proof.verify_proof(SccpChainProfilesV1::latest(), &overlay, NETWORK, now),
            Err(SccpLcAttemptErrorV1::Output(_))
        ));
        drop(occupied);
        let verified = proof
            .verify_proof(SccpChainProfilesV1::latest(), &overlay, NETWORK, now)
            .expect("genuine receipt verifies through the borrowed advance overlay");
        assert!(
            matches!(verified.event, SccpNativeEventV1::TransferToTaira { message_id, .. } if message_id == [0x3c; 32])
        );
        assert_eq!(
            light_client(&original),
            original_head,
            "verification never commits overlay writes"
        );
        assert_eq!(
            original
                .consensus_set(NETWORK, PERIOD)
                .unwrap()
                .set_bytes
                .as_ptr(),
            original_bytes
        );
        assert!(original.consensus_set(NETWORK, PERIOD + 1).is_none());
        drop(verified);
        drop(proof);
        drop(delta);
        drop(prepared);
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "all original owners release on completion"
        );
    }

    fn inbound_block(
        chain: &SyntheticBeaconChainV1,
        logs: Vec<EthereumLogV1>,
    ) -> (Vec<u8>, EthereumNativeMptProofV1) {
        let receipts = vec![successful_receipt(Vec::new()), successful_receipt(logs)];
        let (receipts_root, receipt_proof) = receipt_root_and_proof(&receipts, 1);
        let header = execution_header_rlp(&SyntheticBlockFieldsV1 {
            parent_hash: [0x11; 32],
            number: 1_000,
            timestamp: chain.slot_unix_ms(slot(150)) / 1_000,
            state_root: [0x22; 32],
            receipts_root,
        });
        (header, receipt_proof)
    }

    fn transfer() -> TransferToTairaLogV1 {
        TransferToTairaLogV1 {
            message_id: [0x3c; 32],
            sender: [0x5e; 20],
            nonce: 7,
            payload: vec![0xab; 70],
        }
    }

    #[test]
    fn same_block_proof_yields_the_transfer_event_and_checkpoints() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let (header, receipt_proof) =
            inbound_block(&chain, vec![transfer_log(EMITTER, &transfer())]);
        let proof = EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
                chain.finality_update_for(execution_of(&header), slot(200)),
            )),
            ancestry: EthereumAncestryV1::SameBlock,
            event_header: header.clone(),
            transaction_index: 1,
            receipt_proof,
            event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        };
        let verified = verify_proof(
            &ETHEREUM_MAINNET,
            &memory,
            &light_client(&memory),
            &proof,
            now,
        )
        .expect("valid proof");
        let block = execution_of(&header);
        assert_eq!(
            verified.event,
            SccpNormalizedEventV1::TransferToTaira {
                emitter: SccpSourceEmitterV1::Evm(EMITTER),
                message_id: [0x3c; 32],
                sender: PayloadAccountV1::new(CODEC_EVM_ADDRESS20, vec![0x5e; 20]),
                nonce: 7,
                payload_hash: payload_hash(&[0xab; 70]),
                locator: SccpSourceLocatorV1 {
                    source_height: 1_000,
                    block_hash: block.block_hash,
                    index_in_block: 1,
                },
            }
        );
        assert_eq!(verified.checkpoints.len(), 1);
        assert_eq!(
            verified.checkpoints[0].origin,
            SccpLcCheckpointOriginV1::Proof
        );
        let work = proof_work(&proof);
        assert_eq!(
            (
                work.proofs,
                work.ethereum_light_client_updates,
                work.native_headers
            ),
            (1, 1, 1)
        );
        let mut wrong_log = proof.clone();
        wrong_log.event =
            EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 1 });
        assert_eq!(
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &wrong_log,
                now
            ),
            Err(EthereumLcError::LogIndexOutOfRange { index: 1, logs: 1 }.into())
        );
        let mut not_transfer = proof;
        not_transfer.event = EthereumEventSelectorV1::Void(EthereumLogRangeV1 {
            first_log_index: 0,
            log_count: 1,
        });
        assert_eq!(
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &not_transfer,
                now
            ),
            Err(EthereumLcError::Event(AbiError::WrongTopic).into())
        );
    }

    #[test]
    fn finalized_proof_binds_receipt_emitter_nonce_and_exact_taira_units() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let finalized = FinalizedLogV1 {
            message_id: [0x74; 32],
            nonce: 9,
            recipient: [0x42; 20],
            token_amount: 1_500_000_000,
        };
        let (topics, data) = finalized.encode();
        let log = crate::ethereum_source::EthereumLogV1 {
            address: EMITTER,
            topics,
            data,
        };
        let (header, receipt_proof) = inbound_block(&chain, vec![log]);
        let proof = EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
                chain.finality_update_for(execution_of(&header), slot(200)),
            )),
            ancestry: EthereumAncestryV1::SameBlock,
            event_header: header.clone(),
            transaction_index: 1,
            receipt_proof,
            event: EthereumEventSelectorV1::Finalized(EthereumLogRefV1 { log_index: 0 }),
        };
        let verified = verify_proof(
            &ETHEREUM_MAINNET,
            &memory,
            &light_client(&memory),
            &proof,
            now,
        )
        .expect("authenticated finalized log");
        assert_eq!(
            verified.event,
            SccpNormalizedEventV1::Finalized {
                emitter: SccpSourceEmitterV1::Evm(EMITTER),
                message_id: finalized.message_id,
                nonce: 9,
                amount: Some(1_500_000_000),
                locator: SccpSourceLocatorV1 {
                    source_height: 1_000,
                    block_hash: execution_of(&header).block_hash,
                    index_in_block: 1,
                },
            }
        );
        let mut wrong_log = proof.clone();
        wrong_log.event = EthereumEventSelectorV1::Finalized(EthereumLogRefV1 { log_index: 1 });
        assert!(
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &wrong_log,
                now
            )
            .is_err()
        );
        let mut wrong_receipt = proof.clone();
        wrong_receipt.transaction_index = 0;
        assert!(
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &wrong_receipt,
                now
            )
            .is_err()
        );
        let mut wrong_kind = proof;
        wrong_kind.event =
            EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 });
        assert!(
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &wrong_kind,
                now
            )
            .is_err()
        );
    }

    #[test]
    fn header_chain_links_and_anchor_are_enforced() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let (header, receipt_proof) =
            inbound_block(&chain, vec![transfer_log(EMITTER, &transfer())]);
        let links = header_chain(&header, 5);
        let anchor = execution_of(links.last().expect("five headers"));
        let proof = EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
                chain.finality_update_for(anchor, slot(200)),
            )),
            ancestry: EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
                headers: links.clone(),
            }),
            event_header: header,
            transaction_index: 1,
            receipt_proof,
            event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        };
        let client = light_client(&memory);
        let verified =
            verify_proof(&ETHEREUM_MAINNET, &memory, &client, &proof, now).expect("valid chain");
        assert_eq!(verified.checkpoints.len(), 2);
        let mut broken = proof.clone();
        if let EthereumAncestryV1::HeaderChain(segment) = &mut broken.ancestry {
            segment.headers.swap(1, 2);
        }
        assert!(matches!(
            verify_proof(&ETHEREUM_MAINNET, &memory, &client, &broken, now),
            Err(SccpLcError::Ethereum(EthereumLcError::AncestryBroken {
                index: 1
            }))
        ));
        let mut short = proof.clone();
        if let EthereumAncestryV1::HeaderChain(segment) = &mut short.ancestry {
            segment.headers.pop();
        }
        assert_eq!(
            verify_proof(&ETHEREUM_MAINNET, &memory, &client, &short, now),
            Err(EthereumLcError::AncestryAnchorMismatch.into())
        );
        let mut bounded = client;
        bounded.params.max_ancestry_headers = 4;
        assert_eq!(
            verify_proof(&ETHEREUM_MAINNET, &memory, &bounded, &proof, now),
            Err(SccpLcError::TooManyItems {
                kind: "ancestry headers",
                count: 5,
                max: 4,
            })
        );
        assert_eq!(proof_work(&proof).native_headers, 6);
    }

    fn history_proof_at(
        chain: &SyntheticBeaconChainV1,
        distance: u64,
    ) -> (EthereumSourceProofV1, SccpLcMemoryStateV1, u64) {
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(chain, now);
        let (header, receipt_proof) =
            inbound_block(chain, vec![transfer_log(EMITTER, &transfer())]);
        let block = execution_of(&header);
        let (state_root, history) =
            history_state(&ETHEREUM_MAINNET, block.number, block.block_hash);
        // The verifier reads no anchor time here beyond the EIP-2935 activation; one slot after
        // the event keeps the anchor before the signature slot at every distance.
        let anchor = SyntheticExecutionHeaderV1 {
            block_hash: [0x77; 32],
            number: block.number + distance,
            state_root,
            receipts_root: [0x78; 32],
            timestamp: block.timestamp + 12,
        };
        let proof = EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::FinalityUpdate(Box::new(
                chain.finality_update_for(anchor, slot(200)),
            )),
            ancestry: EthereumAncestryV1::HistoryContract(history),
            event_header: header,
            transaction_index: 1,
            receipt_proof,
            event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        };
        (proof, memory, now)
    }

    #[test]
    fn history_contract_window_edges() {
        let chain = SyntheticBeaconChainV1::mainnet();
        for distance in [1, 8_191] {
            let (proof, memory, now) = history_proof_at(&chain, distance);
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &proof,
                now,
            )
            .unwrap_or_else(|error| panic!("distance {distance}: {error}"));
        }
        for distance in [0, 8_192] {
            let (proof, memory, now) = history_proof_at(&chain, distance);
            assert_eq!(
                verify_proof(
                    &ETHEREUM_MAINNET,
                    &memory,
                    &light_client(&memory),
                    &proof,
                    now
                ),
                Err(EthereumLcError::HistoryWindow {
                    event_height: 1_000,
                    anchor_height: 1_000 + distance,
                }
                .into()),
                "distance {distance}"
            );
        }
        let (proof, memory, now) = history_proof_at(&chain, 5);
        let mut profile = ETHEREUM_MAINNET;
        profile.history_storage_code_hash = [0; 32];
        assert_eq!(
            verify_proof(&profile, &memory, &light_client(&memory), &proof, now),
            Err(EthereumLcError::HistoryCodeHashMismatch.into())
        );
        let mut other_block = proof;
        other_block.event_header = execution_header_rlp(&SyntheticBlockFieldsV1 {
            parent_hash: [0x12; 32],
            number: 1_000,
            timestamp: 1,
            state_root: [0; 32],
            receipts_root: [0; 32],
        });
        assert_eq!(
            verify_proof(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &other_block,
                now
            ),
            Err(EthereumLcError::HistoryValueMismatch.into())
        );
    }

    const LOCATOR: SccpSourceLocatorV1 = SccpSourceLocatorV1 {
        source_height: 1,
        block_hash: [2; 32],
        index_in_block: 3,
    };

    const fn range(first_log_index: u32, log_count: u32) -> EthereumLogRangeV1 {
        EthereumLogRangeV1 {
            first_log_index,
            log_count,
        }
    }

    fn frozen_receipt() -> EthereumReceiptV1 {
        successful_receipt(
            (10..14)
                .map(|nonce| voided_log(EMITTER, [0; 32], nonce))
                .collect(),
        )
    }

    #[test]
    fn void_runs_normalize_expired_and_frozen_voids() {
        let expired = successful_receipt(vec![voided_log(EMITTER, [9; 32], 44)]);
        assert_eq!(
            select_voids(&expired, range(0, 1), LOCATOR),
            Ok(SccpNormalizedEventV1::Void {
                emitter: SccpSourceEmitterV1::Evm(EMITTER),
                kind: SccpVoidKindV1::Expired,
                first_nonce: 44,
                count: 1,
                message_id_or_zero: [9; 32],
                locator: LOCATOR,
            })
        );
        assert_eq!(
            select_voids(&frozen_receipt(), range(1, 3), LOCATOR),
            Ok(SccpNormalizedEventV1::Void {
                emitter: SccpSourceEmitterV1::Evm(EMITTER),
                kind: SccpVoidKindV1::Frozen,
                first_nonce: 11,
                count: 3,
                message_id_or_zero: [0; 32],
                locator: LOCATOR,
            })
        );
    }

    #[test]
    fn void_runs_reject_gaps_mixes_foreign_emitters_and_bounds() {
        let gap = successful_receipt(vec![
            voided_log(EMITTER, [0; 32], 1),
            voided_log(EMITTER, [0; 32], 3),
        ]);
        let mixed = successful_receipt(vec![
            voided_log(EMITTER, [0; 32], 1),
            voided_log(EMITTER, [5; 32], 2),
        ]);
        let two_emitters = successful_receipt(vec![
            voided_log(EMITTER, [0; 32], 1),
            voided_log([0xe2; 20], [0; 32], 2),
        ]);
        for receipt in [gap, mixed, two_emitters] {
            assert_eq!(
                select_voids(&receipt, range(0, 2), LOCATOR),
                Err(EthereumLcError::VoidRangeInvalid.into())
            );
        }
        let frozen = frozen_receipt();
        for count in [0, 257] {
            assert_eq!(
                select_voids(&frozen, range(0, count), LOCATOR),
                Err(EthereumLcError::VoidRangeInvalid.into())
            );
        }
        assert_eq!(
            select_voids(&frozen, range(3, 2), LOCATOR),
            Err(EthereumLcError::LogIndexOutOfRange { index: 4, logs: 4 }.into())
        );
    }

    #[test]
    fn failed_receipts_are_rejected() {
        let mut receipt = successful_receipt(vec![transfer_log(EMITTER, &transfer())]);
        receipt.success = false;
        let (receipts_root, proof) = receipt_root_and_proof(&[receipt], 0);
        let header = execution_of(&execution_header_rlp(&SyntheticBlockFieldsV1 {
            parent_hash: [0; 32],
            number: 5,
            timestamp: 5,
            state_root: [1; 32],
            receipts_root,
        }));
        assert_eq!(
            open_receipt(header.receipts_root, 0, &proof, &LcMemory::detached())
                .map(|_| ())
                .map_err(|error| detached_error(&error)),
            Err(EthereumLcError::FailedReceipt.into())
        );
    }

    #[test]
    fn backfill_records_the_first_header_and_proofs_anchor_on_it() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let (event_header, receipt_proof) =
            inbound_block(&chain, vec![transfer_log(EMITTER, &transfer())]);
        let links = header_chain(&event_header, 10);
        let tip = links.last().expect("ten headers").clone();
        let initial = verify_bootstrap(
            &ETHEREUM_MAINNET,
            &params(),
            &chain.bootstrap_wire(slot(64), &execution_of(&tip)),
            now,
        )
        .expect("bootstrap on an RLP-backed block");
        let mut memory = SccpLcMemoryStateV1::new();
        memory.install(NETWORK, &initial);
        let client = light_client(&memory);
        let segment = EthereumHeaderSegmentV1 {
            headers: links[4..].to_vec(),
        };
        let delta = apply_backfill(&memory, &client, &segment, now).expect("valid backfill");
        assert!(delta.head.is_none());
        assert_eq!(delta.checkpoints.len(), 1);
        let first = execution_of(&links[4]);
        assert_eq!(delta.checkpoints[0].data.source_height, first.number);
        assert_eq!(
            delta.checkpoints[0].origin,
            SccpLcCheckpointOriginV1::Backfill
        );
        memory.apply(NETWORK, &delta);
        assert!(
            apply_backfill(&memory, &client, &segment, now)
                .expect("idempotent")
                .is_empty()
        );
        let proof = EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
                source_height: first.number,
            }),
            ancestry: EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
                headers: links[..5].to_vec(),
            }),
            event_header,
            transaction_index: 1,
            receipt_proof,
            event: EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 0 }),
        };
        let verified = verify_proof(&ETHEREUM_MAINNET, &memory, &client, &proof, now)
            .expect("anchored on the backfilled checkpoint");
        assert_eq!(proof_work(&proof).ethereum_light_client_updates, 0);
        assert_eq!(verified.checkpoints.len(), 1);
        let unknown = EthereumSegmentCase::Unanchored.segment(&links);
        assert!(matches!(
            apply_backfill(&memory, &client, &unknown, now),
            Err(SccpLcError::UnknownCheckpoint { .. })
        ));
        assert_eq!(
            apply_backfill(
                &memory,
                &client,
                &EthereumHeaderSegmentV1 { headers: vec![tip] },
                now
            ),
            Err(SccpLcError::TooFewItems {
                kind: "backfill headers",
                count: 1,
                min: 2,
            })
        );
        assert_eq!(segment_work(&segment).native_headers, 6);
    }

    enum EthereumSegmentCase {
        Unanchored,
    }

    impl EthereumSegmentCase {
        fn segment(&self, links: &[Vec<u8>]) -> EthereumHeaderSegmentV1 {
            match self {
                Self::Unanchored => EthereumHeaderSegmentV1 {
                    headers: links[1..4].to_vec(),
                },
            }
        }
    }

    fn frame(evidence: &EthereumLcEvidenceV1) -> Vec<u8> {
        crate::light_client::proof::SccpLcEvidenceV1::Ethereum(evidence.clone())
            .to_frame()
            .expect("frame")
    }

    fn report(
        memory: &SccpLcMemoryStateV1,
        a: &EthereumLcEvidenceV1,
        b: &EthereumLcEvidenceV1,
        now: u64,
    ) -> Result<SccpLcFreezeReasonV1, SccpLcError> {
        verify_equivocation(
            &ETHEREUM_MAINNET,
            memory,
            &light_client(memory),
            (a, &frame(a)),
            (b, &frame(b)),
            now,
        )
    }

    #[test]
    fn admitted_bootstrap_and_equivocation_retain_original_decode_and_native_custody() {
        use crate::light_client::{
            prepared::{PreparedLcEvidencePairV1, PreparedLcFrameV1},
            profile::SccpChainProfilesV1,
            state::admitted::SccpLcDeltaReadV1,
        };
        use iroha_allocation::AllocationBudget;
        use iroha_data_model::sccp::light_client::SccpLcInitExpectationV1;

        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let profiles = SccpChainProfilesV1::latest();
        let params = SccpLightClientParamsV1::defaults_for(NETWORK).unwrap();
        let bootstrap =
            chain.bootstrap_with_execution(slot(64), &chain.synthetic_execution(slot(64)));
        let prepared =
            PreparedLcFrameV1::bootstrap(&bootstrap.bytes, 4 * 1024 * 1024, &budget).unwrap();
        let empty = SccpLcMemoryStateV1::default();
        let verify = || {
            prepared.verify_initialization(
                profiles,
                &empty,
                NETWORK,
                SccpLcInitExpectationV1::Absent,
                &params,
                now,
            )
        };
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        assert!(matches!(verify(), Err(SccpLcAttemptErrorV1::Output(_))));
        let foreign = AllocationBudget::new(budget.limit_bytes());
        drop(foreign.try_reserve_bytes(foreign.limit_bytes()).unwrap());
        assert!(matches!(verify(), Err(SccpLcAttemptErrorV1::Output(_))));
        drop(occupied);
        let initial = verify().expect("original release permits bootstrap verification");
        assert_eq!(initial.delta.set_count(), 1);
        let detached = verify_bootstrap(
            &ETHEREUM_MAINNET,
            &params,
            &match crate::light_client::proof::SccpLcBootstrapDataV1::from_frame(&bootstrap.bytes)
                .unwrap()
            {
                crate::light_client::proof::SccpLcBootstrapDataV1::Ethereum(value) => value,
                _ => unreachable!(),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            initial.delta.set(0).unwrap().set_bytes,
            detached.sets[0].set_bytes
        );
        drop(initial);
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), 0);

        let memory = installed(&chain, now);
        let honest = EthereumLcEvidenceV1::Update(Box::new(chain.update(&spec(&chain, 200))));
        let mut forked_execution = chain.synthetic_execution(slot(160));
        forked_execution.block_hash[1] ^= 0xff;
        let forked = EthereumLcEvidenceV1::Update(Box::new(chain.update(&SyntheticUpdateSpecV1 {
            finalized_execution: forked_execution,
            ..spec(&chain, 200)
        })));
        let (first, second) = (frame(&honest), frame(&forked));
        let pair =
            PreparedLcEvidencePairV1::new(&first, &second, 4 * 1024 * 1024, &budget).unwrap();
        let verify = || pair.verify(profiles, &memory, NETWORK, now);
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let local = |error: SccpLcAttemptErrorV1| {
            assert!(
                matches!(
                    error,
                    SccpLcAttemptErrorV1::Admission(_)
                        | SccpLcAttemptErrorV1::Decode(_)
                        | SccpLcAttemptErrorV1::Buffer(_)
                        | SccpLcAttemptErrorV1::Control(_)
                ),
                "original native refusal must remain physical: {error:?}"
            )
        };
        local(verify().unwrap_err());
        drop(foreign.try_reserve_bytes(foreign.limit_bytes()).unwrap());
        local(verify().unwrap_err());
        drop(occupied);
        assert_eq!(
            verify().unwrap(),
            report(&memory, &honest, &forked, now).unwrap()
        );
        drop(pair);
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "all source-bound evidence owners retire"
        );
    }

    #[test]
    fn equivocation_requires_two_conflicting_quorum_valid_records() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let client = light_client(&memory);
        let honest = EthereumLcEvidenceV1::Update(Box::new(chain.update(&spec(&chain, 200))));
        let mut forked_execution = chain.synthetic_execution(slot(160));
        forked_execution.block_hash[1] ^= 0xff;
        let forked = EthereumLcEvidenceV1::Update(Box::new(chain.update(&SyntheticUpdateSpecV1 {
            finalized_execution: forked_execution,
            ..spec(&chain, 200)
        })));
        let unrelated = EthereumLcEvidenceV1::Update(Box::new(chain.update(&spec(&chain, 250))));
        let (honest_frame, forked_frame) = (frame(&honest), frame(&forked));
        let reason = verify_equivocation(
            &ETHEREUM_MAINNET,
            &memory,
            &client,
            (&honest, &honest_frame),
            (&forked, &forked_frame),
            now,
        )
        .expect("conflicting finality");
        let swapped = verify_equivocation(
            &ETHEREUM_MAINNET,
            &memory,
            &client,
            (&forked, &forked_frame),
            (&honest, &honest_frame),
            now,
        )
        .expect("conflicting finality");
        assert_eq!(reason, swapped, "the evidence hash is order independent");
        assert_eq!(
            verify_equivocation(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                (&honest, &honest_frame),
                (&honest, &honest_frame),
                now,
            ),
            Err(SccpLcError::EvidenceNotConflicting)
        );
        assert_eq!(
            verify_equivocation(
                &ETHEREUM_MAINNET,
                &memory,
                &client,
                (&honest, &honest_frame),
                (&unrelated, &frame(&unrelated)),
                now,
            ),
            Err(SccpLcError::EvidenceNotConflicting)
        );
    }

    #[test]
    fn aged_light_clients_are_detected_from_the_newest_set() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let client = light_client(&installed(&chain, now));
        let end = ETHEREUM_MAINNET.period_end_ms(PERIOD).expect("time");
        assert_eq!(
            weak_subjectivity_deadline_ms(&ETHEREUM_MAINNET, &client),
            end + client.params.ws_bound_ms
        );
        assert!(!is_aged(
            &ETHEREUM_MAINNET,
            &client,
            end + client.params.ws_bound_ms - 1
        ));
        assert!(is_aged(
            &ETHEREUM_MAINNET,
            &client,
            end + client.params.ws_bound_ms
        ));
    }

    #[test]
    fn recorded_checkpoints_follow_stride_retention() {
        let recorded = SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: 8_192 * 5 + 1,
                block_hash: [1; 32],
                state_root: None,
                receipts_or_tx_root: [2; 32],
                source_time_ms: 3,
            },
            recorded_at_taira_ms: 4,
            origin: SccpLcCheckpointOriginV1::Advance,
        };
        assert_eq!(
            retention_class(
                NETWORK,
                recorded.data.source_height,
                params().checkpoint_stride,
                recorded.origin
            ),
            SccpLcRetentionClassV1::StrideCandidate { bucket: 5 }
        );
        assert_eq!(count_bound(3, 256), 3);
        assert_eq!(count_bound(u32::MAX, 256), 256);
        assert_eq!(seconds_to_ms(2), Ok(2_000));
        assert_eq!(
            seconds_to_ms(u64::MAX),
            Err(EthereumLcError::TimeOverflow.into())
        );
    }

    /// A canonical execution chain: `count` parent-linked headers above an EDR-shaped block.
    fn canonical_chain(chain: &SyntheticBeaconChainV1, count: usize) -> Vec<Vec<u8>> {
        let (first, _) = inbound_block(chain, Vec::new());
        let mut headers = vec![first.clone()];
        headers.extend(header_chain(&first, count));
        headers
    }

    #[test]
    fn a_forged_block_between_checkpoints_is_reported_with_a_finalized_ancestor() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let canonical = canonical_chain(&chain, 6);
        let tip = execution_of(canonical.last().expect("tip"));
        // Honest: slot(160) is an epoch boundary; its update finalizes the canonical tip.
        let honest_update = chain.update(&SyntheticUpdateSpecV1 {
            finalized_slot: slot(160),
            finalized_execution: tip,
            ..spec(&chain, 200)
        });
        // Forged: a non-checkpoint finalized slot carrying a block at a height the honest
        // updates never finalize (between two canonical checkpoints).
        let middle = execution_of(&canonical[3]);
        let mut forged_block = middle;
        forged_block.block_hash = keccak256(&[b"forged middle block"]);
        let forged = EthereumLcEvidenceV1::Update(Box::new(chain.update(&SyntheticUpdateSpecV1 {
            attested_slot: slot(230),
            finalized_slot: slot(197),
            finalized_execution: forged_block,
            signature_slot: slot(231),
            include_next_committee: false,
            ..spec(&chain, 231)
        })));
        assert_ne!(
            slot(197) % 32,
            0,
            "the forged finalized slot is not a checkpoint"
        );
        let honest = EthereumLcEvidenceV1::Update(Box::new(honest_update.clone()));
        // Plain updates cannot prove it: other slot, other height, consistent order.
        assert_eq!(
            report(&memory, &honest, &forged, now),
            Err(SccpLcError::EvidenceNotConflicting)
        );
        // The honest update plus the canonical header chain from that height to its finalized
        // block proves the canonical block at the forged height.
        let ancestor =
            EthereumLcEvidenceV1::FinalizedAncestor(Box::new(EthereumFinalizedAncestorV1 {
                update: honest_update.clone(),
                ancestry: EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
                    headers: canonical[4..].to_vec(),
                }),
                header: canonical[3].clone(),
            }));
        let reason = report(&memory, &forged, &ancestor, now).expect("same height, other hash");
        assert_eq!(report(&memory, &ancestor, &forged, now), Ok(reason));
        let work = evidence_work(&ancestor);
        assert_eq!(
            (work.ethereum_light_client_updates, work.native_headers),
            (1, 4)
        );
        assert_eq!(evidence_work(&forged).native_headers, 0);
        // Honest records never conflict with each other.
        assert_eq!(
            report(&memory, &honest, &ancestor, now),
            Err(SccpLcError::EvidenceNotConflicting)
        );
        // A forged ancestry is rejected as a record.
        let mut broken = canonical[4..].to_vec();
        broken.swap(0, 1);
        let unlinked =
            EthereumLcEvidenceV1::FinalizedAncestor(Box::new(EthereumFinalizedAncestorV1 {
                update: honest_update,
                ancestry: EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
                    headers: broken,
                }),
                header: canonical[3].clone(),
            }));
        assert_eq!(
            report(&memory, &forged, &unlinked, now),
            Err(EthereumLcError::AncestryBroken { index: 0 }.into())
        );
    }

    #[test]
    fn a_forged_block_ahead_of_the_canonical_chain_is_reported_by_time_order() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let honest = EthereumLcEvidenceV1::Update(Box::new(chain.update(&spec(&chain, 200))));
        let canonical = chain.synthetic_execution(slot(160));
        // A height the canonical chain has not reached, timestamped before the canonical block.
        let ahead = SyntheticExecutionHeaderV1 {
            block_hash: keccak256(&[b"forged future block"]),
            number: canonical.number + 1_000_000,
            state_root: [0x31; 32],
            receipts_root: [0x32; 32],
            timestamp: canonical.timestamp - 12,
        };
        let forged = EthereumLcEvidenceV1::Update(Box::new(chain.update(&SyntheticUpdateSpecV1 {
            finalized_slot: slot(158),
            finalized_execution: ahead,
            ..spec(&chain, 230)
        })));
        assert!(report(&memory, &honest, &forged, now).is_ok());
        // The forger cannot date the block after the canonical one: execution time is bounded
        // by the signature slot, which is bounded by the Taira clock.
        let late = SyntheticExecutionHeaderV1 {
            timestamp: chain.slot_unix_ms(slot(231)) / 1_000,
            ..ahead
        };
        let dated_late = chain.update(&SyntheticUpdateSpecV1 {
            finalized_execution: late,
            ..spec(&chain, 230)
        });
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &advance_of(vec![dated_late]),
                now
            ),
            Err(EthereumLcError::ExecutionAfterSignature {
                execution_ms: chain.slot_unix_ms(slot(231)),
                signature_ms: chain.slot_unix_ms(slot(230)),
            }
            .into())
        );
    }

    #[test]
    fn a_forged_root_under_a_canonical_hash_conflicts() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let mut memory = installed(&chain, now);
        let honest_update = chain.update(&spec(&chain, 200));
        let mut forged_roots = chain.synthetic_execution(slot(160));
        forged_roots.state_root = [0x99; 32];
        let forged_update = chain.update(&SyntheticUpdateSpecV1 {
            finalized_execution: forged_roots,
            ..spec(&chain, 210)
        });
        let honest = EthereumLcEvidenceV1::Update(Box::new(honest_update.clone()));
        let forged = EthereumLcEvidenceV1::Update(Box::new(forged_update.clone()));
        assert!(report(&memory, &honest, &forged, now).is_ok());
        let delta = apply_advance(
            &ETHEREUM_MAINNET,
            &memory,
            &light_client(&memory),
            &advance_of(vec![honest_update]),
            now,
        )
        .expect("honest");
        memory.apply(NETWORK, &delta);
        assert_eq!(
            apply_advance(
                &ETHEREUM_MAINNET,
                &memory,
                &light_client(&memory),
                &advance_of(vec![forged_update]),
                now
            ),
            Err(SccpLcError::ConflictsWithStoredData(
                SccpLcConflictV1::Checkpoint {
                    source_height: slot(160)
                }
            ))
        );
    }

    #[test]
    fn updates_sharing_a_signature_slot_are_not_a_conflict() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        // Two honest aggregates over different attested headers, relabelled to one signature
        // slot: the slot is not signed, so this proves nothing about the committee.
        let first = EthereumLcEvidenceV1::Update(Box::new(chain.update(&SyntheticUpdateSpecV1 {
            signature_slot: slot(260),
            ..spec(&chain, 200)
        })));
        let second = EthereumLcEvidenceV1::Update(Box::new(chain.update(&SyntheticUpdateSpecV1 {
            signature_slot: slot(260),
            ..spec(&chain, 250)
        })));
        assert_eq!(
            report(&memory, &first, &second, now),
            Err(SccpLcError::EvidenceNotConflicting)
        );
    }

    #[test]
    fn blocks_conflict_on_content_and_time_order() {
        let block = |height: u64, time: u64, hash: u8| SccpLcCheckpointDataV1 {
            source_height: height,
            block_hash: [hash; 32],
            state_root: Some([1; 32]),
            receipts_or_tx_root: [2; 32],
            source_time_ms: time,
        };
        assert!(!blocks_conflict(&block(10, 100, 1), &block(10, 100, 1)));
        assert!(blocks_conflict(&block(10, 100, 1), &block(10, 100, 2)));
        assert!(!blocks_conflict(&block(10, 100, 1), &block(11, 112, 2)));
        assert!(!blocks_conflict(&block(11, 112, 2), &block(10, 100, 1)));
        assert!(blocks_conflict(&block(10, 112, 1), &block(11, 112, 2)));
        assert!(blocks_conflict(&block(11, 100, 2), &block(10, 112, 1)));
    }

    #[test]
    fn aged_supersessions_close_the_newest_current_committee() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now = chain.slot_unix_ms(slot(300));
        let memory = installed(&chain, now);
        let client = light_client(&memory);
        assert_eq!(
            aged_supersession(&ETHEREUM_MAINNET, &memory, &client),
            Ok(Some(SccpLcSupersessionV1 {
                set_id: PERIOD,
                superseded_at_source_ms: ETHEREUM_MAINNET
                    .period_start_ms(PERIOD + 1)
                    .expect("time"),
            }))
        );
        let mut unknown = client;
        unknown.head.latest_set_id = PERIOD + 5;
        assert_eq!(
            aged_supersession(&ETHEREUM_MAINNET, &memory, &unknown),
            Ok(None)
        );
    }
}
