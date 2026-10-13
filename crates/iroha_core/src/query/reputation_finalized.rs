//! Durable exact-anchor archive for finalized SoraFS reputation projections.
//!
//! The archive is deliberately a projection store, not finality authority. A commit-owned caller
//! supplies one immutable finalized state view bound to current embedded commit certificates; capture
//! authenticates and constructs the exact record before publication. This module never falls back
//! to a current-head view. Durable records store no credentials, signing material,
//! or process-local authority.
//!
//! Durable growth is linear in new state: each anchor stores only feed suffixes and
//! reserve-provider upserts/removals, while authority policies are stored once by content digest.
//! Exact reads reconstruct the public full projection through the manifest predecessor chain until
//! an explicit, Kura-authenticated retention fence installs a content-addressed virtual base.
//! Compacted feeds then expose a rolling prefix commitment plus retained suffix pagination, while a
//! bounded authenticated journal source-head index and complete inter-checkpoint lifecycle suffix
//! preserve exact source replay; full-history reads fail with a typed `HistoryPruned` condition. A
//! policy-first crash leaves a validated, bounded, immutable cache entry: restart retains and
//! accounts for it, but it cannot qualify an archive without a referenced anchor. Unix publication
//! and staged recovery are descriptor-relative and remain bound to the verified directory inode
//! across hostile ancestor renames. Non-Unix mutation fails closed: Windows needs an audited
//! `NtCreateFile` `RootDirectory` plus handle-relative `FileLinkInformation` wrapper before this
//! archive can be production-qualified there.
use super::archive_index::{
    ArchiveIndexLock, ArchiveIndexLockError, ArchiveIndexReadGuard, ArchiveIndexWriteGuard,
};
use super::finalized_archive_fs::{
    STAGED_FILE_PREFIX, bounded_bytes_len, canonical_bytes_domain_digest,
    is_canonical_digest_file_name,
};
#[cfg(unix)]
use super::finalized_archive_fs::{
    create_unix_staged_file, unix_staged_file_has_canonical_target, unix_stat_matches_metadata,
};
use crate::{
    kura::Kura,
    query::archive_finality::{ArchiveFinalityError, CertifiedArchiveView},
    secure_file_metadata::{self, SecureMetadata},
    smartcontracts::ValidSingularQuery,
    state::StateReadOnly,
};
use iroha_data_model::{
    NetworkId,
    query::sorafs::prelude::{
        FindSorafsOrderbookEvents, FindSorafsProofOutcomeEvents, FindSorafsRepairEvents,
        FindSorafsReputationJournalAuthorityPolicy, FindSorafsReputationJournalEvents,
        FindSorafsReserveEvents, FindSorafsReserveProviders,
    },
    sorafs::{
        capacity::ProviderId,
        moderation_ledger::{
            REPAIR_QUERY_MAX_ITEMS_V1, RepairFinalizedCursorV1, RepairFinalizedEventV1,
        },
        orderbook::{
            ORDERBOOK_QUERY_MAX_ITEMS_V1, OrderbookFinalizedCursorV1, OrderbookFinalizedEventV1,
        },
        proof_ledger::{
            PROOF_OUTCOME_QUERY_MAX_ITEMS_V1, ProofOutcomeFinalizedCursorV1,
            ProofOutcomeFinalizedEventV1,
        },
        reputation::{
            REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1, ReputationJournalAuthorityPolicyRecordV1,
            ReputationJournalFinalizedCursorV1, ReputationJournalFinalizedEventV1,
            ReputationJournalSourceIdV1,
        },
        reserve::{
            RESERVE_MAX_OPEN_APPEALS_V1, RESERVE_MAX_PENDING_MOVEMENTS_V1,
            RESERVE_QUERY_MAX_ITEMS_V1, ReserveFinalizedCursorV1, ReserveFinalizedEventV1,
            ReserveProviderAccountV1,
        },
    },
};
use norito::{
    DecodeLimits, decode_from_bytes_with_limits,
    derive::{NoritoDeserialize, NoritoSerialize},
};
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(any(unix, test))]
use std::io::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Read},
    num::NonZeroUsize,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
const ARCHIVE_VERSION_V1: u16 = 1;
const ANCHORS_DIRECTORY: &str = "anchors";
const CHECKPOINTS_DIRECTORY: &str = "checkpoints";
const POLICIES_DIRECTORY: &str = "policies";
const WRITER_LOCK_FILE: &str = ".writer.lock";
const ANCHOR_FILE_SUFFIX: &str = ".anchor.to";
const CHECKPOINT_FILE_SUFFIX: &str = ".checkpoint.to";
const POLICY_FILE_SUFFIX: &str = ".policy.to";
const CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON: &str =
    "checkpoint publication state could not be reconciled; archive reopen is required";
const KEY_DIGEST_DOMAIN_V1: &[u8] = b"iroha.sorafs.reputation.finalized-archive-key.v1\0";
const MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"iroha.sorafs.reputation.finalized-anchor-manifest.v1\0";
const DELTA_DIGEST_DOMAIN_V1: &[u8] = b"iroha.sorafs.reputation.finalized-anchor-delta.v1\0";
const ANCHOR_DIGEST_DOMAIN_V1: &[u8] = b"iroha.sorafs.reputation.finalized-anchor-record.v1\0";
const CHECKPOINT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-virtual-base-checkpoint.v1\0";
const ANCHOR_PREFIX_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-anchor-prefix.v1\0";
const PROOF_PREFIX_DIGEST_DOMAIN_V1: &[u8] = b"iroha.sorafs.reputation.finalized-proof-prefix.v1\0";
const JOURNAL_PREFIX_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-journal-prefix.v1\0";
const JOURNAL_PREFIX_SOURCE_HEAD_ROOT_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-journal-prefix-source-head-root.v1\0";
const REPAIR_PREFIX_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-repair-prefix.v1\0";
const ORDERBOOK_PREFIX_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-orderbook-prefix.v1\0";
const RESERVE_PREFIX_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-reserve-prefix.v1\0";
const CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-checkpoint-validation.v1\0";
const POLICY_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-policy-record.v1\0";
const POLICY_HISTORY_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-policy-history.v1\0";
const RETENTION_PROPOSAL_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-retention-proposal.v1\0";
const RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-retention-checkpoint-bytes.v1\0";
const RETENTION_APPROVAL_REVISION_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-retention-approval.v1\0";
const RETENTION_APPROVAL_NAMESPACE_V1: [u8; 32] = *b"sorafs.rp.archive.retention.v1.0";
const PROVIDER_STATE_ROOT_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.reputation.finalized-provider-state-root.v1\0";
const MAX_DECODE_NESTING_DEPTH: usize = 128;
const MAX_AUTHORITY_POLICY_REVISIONS_V1: usize = 1_024;
const RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1: usize = 64 * 1024;
const RETENTION_APPROVAL_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    4 * 1024,
    RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1,
    1_024,
    RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
/// Resource ceilings enforced for every archive scan, read, and write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationFinalizedArchiveBounds {
    max_record_bytes: u64,
    max_entries: NonZeroUsize,
    max_total_bytes: u64,
}
impl ReputationFinalizedArchiveBounds {
    /// Construct explicit archive resource ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero or internally inconsistent ceilings and record sizes that
    /// cannot be represented by the bounded Norito decoder on this target.
    pub fn try_new(
        max_record_bytes: u64,
        max_entries: usize,
        max_total_bytes: u64,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let max_entries = NonZeroUsize::new(max_entries).ok_or(
            ReputationFinalizedArchiveError::InvalidBounds {
                reason: "maximum archive entries must be non-zero",
            },
        )?;
        if max_record_bytes == 0 {
            return Err(ReputationFinalizedArchiveError::InvalidBounds {
                reason: "maximum record bytes must be non-zero",
            });
        }
        if max_total_bytes < max_record_bytes {
            return Err(ReputationFinalizedArchiveError::InvalidBounds {
                reason: "maximum total bytes must cover at least one maximum-sized record",
            });
        }
        let max_record_bytes_usize = usize::try_from(max_record_bytes).map_err(|_| {
            ReputationFinalizedArchiveError::InvalidBounds {
                reason: "maximum record bytes exceed this target's address space",
            }
        })?;
        if max_record_bytes_usize.checked_mul(4).is_none() {
            return Err(ReputationFinalizedArchiveError::InvalidBounds {
                reason: "maximum record bytes cannot produce a bounded decode allocation budget",
            });
        }
        Ok(Self {
            max_record_bytes,
            max_entries,
            max_total_bytes,
        })
    }
    /// Maximum canonical bytes accepted for one anchor or policy artifact.
    #[must_use]
    pub const fn max_record_bytes(self) -> u64 {
        self.max_record_bytes
    }
    /// Maximum immutable records accepted in each anchor, checkpoint, or policy namespace.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries.get()
    }
    /// Maximum aggregate bytes accepted across anchors, checkpoints, and policy records.
    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }
    fn decode_limits(self) -> DecodeLimits {
        let max = usize::try_from(self.max_record_bytes)
            .expect("archive construction validates target address-space fit");
        DecodeLimits::new(
            max,
            max,
            max,
            max.checked_mul(4)
                .expect("archive construction validates allocation-budget fit"),
            MAX_DECODE_NESTING_DEPTH,
        )
    }
}
/// Exact immutable finalized-chain identity used as an archive key.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveKeyV1")]
pub struct ReputationFinalizedArchiveKeyV1 {
    /// Exact network from which the projection was captured.
    pub network_id: NetworkId,
    /// Finalized block height.
    pub height: u64,
    /// Exact finalized block hash.
    pub block_hash: [u8; 32],
}
impl ReputationFinalizedArchiveKeyV1 {
    /// Construct and validate one exact finalized archive key.
    ///
    /// # Errors
    ///
    /// Rejects a malformed network identity, zero height, or zero block hash.
    pub fn try_new(
        network_id: NetworkId,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let key = Self {
            network_id,
            height,
            block_hash,
        };
        key.validate()?;
        Ok(key)
    }
    /// Validate the exact finalized identity.
    ///
    /// # Errors
    ///
    /// Rejects a malformed network identity, zero height, or zero block hash.
    pub fn validate(&self) -> Result<(), ReputationFinalizedArchiveError> {
        if self.network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "network id must be an exact marked genesis hash",
            });
        }
        if self.height == 0 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "finalized height must be non-zero",
            });
        }
        if self.block_hash == [0; 32] {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "finalized block hash must be non-zero",
            });
        }
        Ok(())
    }
}
/// Complete typed reputation query projection captured from one finalized view.
///
/// Event feeds contain their full ordered history through `key`; they are not pre-paginated. This
/// insertion/capture form is never returned with a silently truncated prefix: after compaction
/// callers must use the retained pagination APIs and receive a typed `HistoryPruned` boundary.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::reputation_finalized::ReputationFinalizedProjectionV1")]
pub struct ReputationFinalizedProjectionV1 {
    /// Exact chain, height, and block hash shared by every field.
    pub key: ReputationFinalizedArchiveKeyV1,
    /// Timestamp of the exact finalized block in Unix milliseconds.
    pub finalized_at_unix_ms: u64,
    /// Active journal authority policy at the finalized anchor.
    pub authority_policy: ReputationJournalAuthorityPolicyRecordV1,
    /// Complete ordered proof-outcome event feed through the anchor.
    pub proof_outcomes: Vec<ProofOutcomeFinalizedEventV1>,
    /// Complete ordered reputation-journal event feed through the anchor.
    pub journal_events: Vec<ReputationJournalFinalizedEventV1>,
    /// Complete ordered repair event feed through the anchor.
    pub repair_events: Vec<RepairFinalizedEventV1>,
    /// Complete ordered orderbook event feed through the anchor.
    pub orderbook_events: Vec<OrderbookFinalizedEventV1>,
    /// Complete ordered reserve event feed through the anchor.
    pub reserve_events: Vec<ReserveFinalizedEventV1>,
    /// Complete provider-id-ordered authoritative reserve projection.
    pub reserve_providers: Vec<ReserveProviderAccountV1>,
}
/// Source-indexed reputation journal result from one exact finalized archive view.
///
/// The `event` is absent only when the selected finalized view authoritatively contains no event
/// for `source_id`; it is never a capability or history fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ReputationFinalizedArchiveJournalSourceViewV1 {
    /// Exact finalized archive identity used for the lookup.
    pub key: ReputationFinalizedArchiveKeyV1,
    /// Timestamp of the exact finalized block in Unix milliseconds.
    pub finalized_at_unix_ms: u64,
    /// Latest canonical event for the requested source through this view.
    pub event: Option<ReputationJournalFinalizedEventV1>,
}
impl ReputationFinalizedProjectionV1 {
    /// Validate exact-anchor, policy, feed-order, and provider-order invariants.
    ///
    /// # Errors
    ///
    /// Rejects malformed anchors, policy records, non-contiguous or
    /// cross-anchor event feeds, and incomplete provider ordering.
    pub fn validate(&self) -> Result<(), ReputationFinalizedArchiveError> {
        self.key.validate()?;
        if self.finalized_at_unix_ms == 0 || self.finalized_at_unix_ms == u64::MAX {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "finalized block timestamp is invalid",
            });
        }
        self.authority_policy.validate().map_err(|_| {
            ReputationFinalizedArchiveError::InvalidProjection {
                reason: "active reputation journal authority policy is invalid",
            }
        })?;
        if self.authority_policy.activated_at_unix_ms > self.finalized_at_unix_ms {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy activates after the finalized anchor",
            });
        }
        let mut block_hashes = BTreeMap::from([(self.key.height, self.key.block_hash)]);
        validate_event_feed(
            &self.key,
            &self.proof_outcomes,
            &mut block_hashes,
            |event| {
                (
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                )
            },
        )?;
        validate_event_feed(
            &self.key,
            &self.journal_events,
            &mut block_hashes,
            |event| {
                (
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                )
            },
        )?;
        for event in &self.journal_events {
            event.entry.validate().map_err(|_| {
                ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "reputation journal entry is invalid",
                }
            })?;
            if event.recorded_at_unix_ms == 0
                || event.recorded_at_unix_ms > self.finalized_at_unix_ms
                || event.entry.source_time_unix_ms > event.recorded_at_unix_ms
            {
                return Err(ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "reputation journal timestamp is outside the finalized anchor",
                });
            }
        }
        validate_event_feed(&self.key, &self.repair_events, &mut block_hashes, |event| {
            (
                event.sequence,
                event.block_height,
                event.block_hash,
                event.event_index,
            )
        })?;
        validate_event_feed(
            &self.key,
            &self.orderbook_events,
            &mut block_hashes,
            |event| {
                (
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                )
            },
        )?;
        validate_event_feed(
            &self.key,
            &self.reserve_events,
            &mut block_hashes,
            |event| {
                (
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                )
            },
        )?;
        let mut previous_provider_id = None;
        for account in &self.reserve_providers {
            let provider_id = account.terms.provider_id;
            validate_reserve_provider_account(account, self.finalized_at_unix_ms)?;
            if previous_provider_id.is_some_and(|previous| previous >= provider_id) {
                return Err(ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "reserve provider projection is not strictly provider-id ordered",
                });
            }
            previous_provider_id = Some(provider_id);
        }
        Ok(())
    }
}
fn validate_event_feed<T>(
    anchor: &ReputationFinalizedArchiveKeyV1,
    events: &[T],
    block_hashes: &mut BTreeMap<u64, [u8; 32]>,
    identity: impl Fn(&T) -> (u64, u64, [u8; 32], u32),
) -> Result<(), ReputationFinalizedArchiveError> {
    let mut previous: Option<EventIdentity> = None;
    for (index, event) in events.iter().enumerate() {
        let event = EventIdentity::from(identity(event));
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "event feed sequence exceeds the supported range",
            })?;
        if event.sequence != expected_sequence
            || event.block_height == 0
            || event.block_hash == [0; 32]
        {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "event feed identity is invalid or non-contiguous",
            });
        }
        let at_anchor_height = event.block_height == anchor.height;
        if event.block_height > anchor.height
            || (at_anchor_height && event.block_hash != anchor.block_hash)
        {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "event feed crosses its finalized anchor",
            });
        }
        let canonical_index = match previous {
            None => event.event_index == 0,
            Some(previous) if event.block_height == previous.block_height => {
                event.block_hash == previous.block_hash
                    && previous.event_index.checked_add(1) == Some(event.event_index)
            }
            Some(previous) => event.block_height > previous.block_height && event.event_index == 0,
        };
        if !canonical_index {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "event feed block/index order is not canonical",
            });
        }
        match block_hashes.entry(event.block_height) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(event.block_hash);
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get() != &event.block_hash =>
            {
                return Err(ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "finalized feeds disagree on a historical block hash",
                });
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
        previous = Some(event);
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventIdentity {
    sequence: u64,
    block_height: u64,
    block_hash: [u8; 32],
    event_index: u32,
}
impl From<(u64, u64, [u8; 32], u32)> for EventIdentity {
    fn from((sequence, block_height, block_hash, event_index): (u64, u64, [u8; 32], u32)) -> Self {
        Self {
            sequence,
            block_height,
            block_hash,
            event_index,
        }
    }
}
fn proof_event_identity(event: &ProofOutcomeFinalizedEventV1) -> EventIdentity {
    EventIdentity::from((
        event.sequence,
        event.block_height,
        event.block_hash,
        event.event_index,
    ))
}
fn journal_event_identity(event: &ReputationJournalFinalizedEventV1) -> EventIdentity {
    EventIdentity::from((
        event.sequence,
        event.block_height,
        event.block_hash,
        event.event_index,
    ))
}
fn repair_event_identity(event: &RepairFinalizedEventV1) -> EventIdentity {
    EventIdentity::from((
        event.sequence,
        event.block_height,
        event.block_hash,
        event.event_index,
    ))
}
fn orderbook_event_identity(event: &OrderbookFinalizedEventV1) -> EventIdentity {
    EventIdentity::from((
        event.sequence,
        event.block_height,
        event.block_hash,
        event.event_index,
    ))
}
fn reserve_event_identity(event: &ReserveFinalizedEventV1) -> EventIdentity {
    EventIdentity::from((
        event.sequence,
        event.block_height,
        event.block_hash,
        event.event_index,
    ))
}
fn validate_retained_feed<T>(
    prefix: ReputationFeedPrefixSummaryV1,
    retained_suffix: &[T],
    identity: impl Fn(&T) -> EventIdentity,
) -> Result<(), ReputationFinalizedArchiveError> {
    prefix.validate()?;
    let mut previous = prefix.pruned_through.map(position_identity);
    for event in retained_suffix {
        let event = identity(event);
        let expected_sequence = previous.map_or(1, |previous| previous.sequence.saturating_add(1));
        let canonical_index = match previous {
            None => event.event_index == 0,
            Some(previous) if event.block_height == previous.block_height => {
                event.block_hash == previous.block_hash
                    && previous.event_index.checked_add(1) == Some(event.event_index)
            }
            Some(previous) => event.block_height > previous.block_height && event.event_index == 0,
        };
        if event.sequence != expected_sequence
            || event.block_height == 0
            || event.block_hash == [0; 32]
            || !canonical_index
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "retained feed is not the exact canonical suffix of its prefix",
            });
        }
        previous = Some(event);
    }
    Ok(())
}
fn retained_feed_high_water<T>(
    feed: &ReputationRetainedFeedStateV1<T>,
) -> Result<u64, ReputationFinalizedArchiveError> {
    feed.prefix
        .pruned_event_count
        .checked_add(bounded_len(feed.retained_suffix.len())?)
        .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "retained feed high-water mark overflowed",
        })
}
fn compact_retained_feed<T>(
    domain: &[u8],
    feed: &ReputationRetainedFeedStateV1<T>,
    identity: impl Fn(&T) -> EventIdentity,
) -> Result<ReputationFeedPrefixSummaryV1, ReputationFinalizedArchiveError>
where
    T: norito::core::NoritoSerialize,
{
    let mut prefix = feed.prefix;
    for event in &feed.retained_suffix {
        prefix.rolling_prefix_digest =
            rolling_domain_digest(domain, prefix.rolling_prefix_digest, event)?;
        prefix.pruned_event_count = prefix.pruned_event_count.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "feed prefix event count overflowed during compaction",
            },
        )?;
        prefix.pruned_through = Some(event_position(identity(event)));
    }
    prefix.validate()?;
    Ok(prefix)
}
fn merge_journal_source_heads(
    prefix_heads: &[ReputationJournalFinalizedEventV1],
    retained_suffix: &[ReputationJournalFinalizedEventV1],
) -> Result<Vec<ReputationJournalFinalizedEventV1>, ReputationFinalizedArchiveError> {
    let mut heads = BTreeMap::new();
    for event in prefix_heads {
        if heads.insert(event.entry.source_id, event.clone()).is_some() {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal prefix source-head index contains a duplicate source",
            });
        }
    }
    for event in retained_suffix {
        event
            .entry
            .validate()
            .map_err(|_| ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal source-head index contains an invalid entry",
            })?;
        match heads.get(&event.entry.source_id) {
            None if event.entry.source_revision == 1
                && event.entry.predecessor_event_id.is_none() => {}
            Some(previous)
                if previous.sequence < event.sequence
                    && previous.entry.source_kind() == event.entry.source_kind()
                    && previous.entry.source_revision.checked_add(1)
                        == Some(event.entry.source_revision)
                    && event.entry.predecessor_event_id == Some(previous.entry.event_id) => {}
            _ => {
                return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                    reason: "journal source-head index is missing, substituted, or lifecycle-discontinuous",
                });
            }
        }
        heads.insert(event.entry.source_id, event.clone());
    }
    Ok(heads.into_values().collect())
}
fn validate_journal_source_id(
    source_id: ReputationJournalSourceIdV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    if source_id == ReputationJournalSourceIdV1::ZERO {
        return Err(ReputationFinalizedArchiveError::InvalidKey {
            reason: "journal source identifier must be non-zero",
        });
    }
    Ok(())
}
fn validate_journal_prefix_source_heads(
    prefix: ReputationFeedPrefixSummaryV1,
    prefix_heads: &[ReputationJournalFinalizedEventV1],
    retained_suffix: &[ReputationJournalFinalizedEventV1],
    anchor: &ReputationFinalizedArchiveKeyV1,
    finalized_at_unix_ms: u64,
) -> Result<(), ReputationFinalizedArchiveError> {
    prefix.validate()?;
    if (prefix.pruned_event_count == 0) != prefix_heads.is_empty() {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "journal prefix source-head index disagrees with the compacted prefix",
        });
    }
    let finalized_cursor = ReputationJournalFinalizedCursorV1 {
        height: anchor.height,
        block_hash: anchor.block_hash,
        finalized_at_unix_ms,
    };
    let terminal = prefix.pruned_through.map(position_identity);
    let mut previous_source_id = None;
    let mut source_head_sequences = BTreeSet::new();
    let mut contains_terminal = terminal.is_none();
    for event in prefix_heads {
        event.validate(finalized_cursor).map_err(|_| {
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal prefix source-head index contains an invalid finalized event",
            }
        })?;
        let source_id = event.entry.source_id;
        if previous_source_id.is_some_and(|previous| previous >= source_id)
            || !source_head_sequences.insert(event.sequence)
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal prefix source-head index is not strictly source ordered and sequence unique",
            });
        }
        let identity = journal_event_identity(event);
        let Some(terminal) = terminal else {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal prefix source-head index exists without a compacted terminal",
            });
        };
        let position_is_valid = match identity.sequence.cmp(&terminal.sequence) {
            core::cmp::Ordering::Equal => identity == terminal,
            core::cmp::Ordering::Less => {
                identity.block_height < terminal.block_height
                    || (identity.block_height == terminal.block_height
                        && identity.block_hash == terminal.block_hash
                        && identity.event_index < terminal.event_index)
            }
            core::cmp::Ordering::Greater => false,
        };
        if !position_is_valid || identity.sequence > prefix.pruned_event_count {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal prefix source head lies outside its compacted prefix",
            });
        }
        contains_terminal |= identity == terminal;
        previous_source_id = Some(source_id);
    }
    if !contains_terminal {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "journal prefix source-head index omits the compacted terminal event",
        });
    }
    merge_journal_source_heads(prefix_heads, retained_suffix)?;
    Ok(())
}
fn journal_prefix_source_head_root(
    prefix_heads: &[ReputationJournalFinalizedEventV1],
) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOURNAL_PREFIX_SOURCE_HEAD_ROOT_DOMAIN_V1);
    hasher.update(&bounded_len(prefix_heads.len())?.to_le_bytes());
    for event in prefix_heads {
        let bytes = norito::to_bytes(event).map_err(ReputationFinalizedArchiveError::Encode)?;
        hasher.update(&bounded_len(bytes.len())?.to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(*hasher.finalize().as_bytes())
}
fn journal_source_head_commitment(
    prefix_heads: &[ReputationJournalFinalizedEventV1],
    retained_suffix: &[ReputationJournalFinalizedEventV1],
) -> Result<(Vec<ReputationJournalFinalizedEventV1>, u64, [u8; 32]), ReputationFinalizedArchiveError>
{
    let heads = merge_journal_source_heads(prefix_heads, retained_suffix)?;
    let count = bounded_len(heads.len())?;
    let root = journal_prefix_source_head_root(&heads)?;
    Ok((heads, count, root))
}
fn journal_prefix_after_events(
    prefix: ReputationFeedPrefixSummaryV1,
    events: &[ReputationJournalFinalizedEventV1],
) -> Result<ReputationFeedPrefixSummaryV1, ReputationFinalizedArchiveError> {
    validate_retained_feed(prefix, events, journal_event_identity)?;
    let mut next = prefix;
    for event in events {
        next.rolling_prefix_digest = rolling_domain_digest(
            JOURNAL_PREFIX_DIGEST_DOMAIN_V1,
            next.rolling_prefix_digest,
            event,
        )?;
        next.pruned_event_count = next.pruned_event_count.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint journal prefix overflowed while authenticating source lineage",
            },
        )?;
        next.pruned_through = Some(event_position(journal_event_identity(event)));
    }
    next.validate()?;
    Ok(next)
}
fn validate_journal_source_head_delta_standalone(
    checkpoint: &ReputationFinalizedVirtualBaseCheckpointV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    let complete_prefix = journal_prefix_after_events(
        checkpoint.journal_prefix,
        &checkpoint.journal_retained_suffix,
    )?;
    let delta_len = bounded_len(checkpoint.journal_source_head_delta.len())?;
    if delta_len > complete_prefix.pruned_event_count {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "checkpoint source-lineage delta exceeds the journal high-water mark",
        });
    }
    let delta_prefix_count = complete_prefix
        .pruned_event_count
        .checked_sub(delta_len)
        .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "checkpoint source-lineage delta sequence range overflowed",
        })?;
    let first_sequence = if delta_len == 0 {
        0
    } else {
        delta_prefix_count.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint source-lineage delta sequence range overflowed",
            },
        )?
    };
    let finalized_cursor = ReputationJournalFinalizedCursorV1 {
        height: checkpoint.retention_floor.height,
        block_hash: checkpoint.retention_floor.block_hash,
        finalized_at_unix_ms: checkpoint.retention_floor_finalized_at_unix_ms,
    };
    let mut previous = None;
    let mut previous_recorded_at_unix_ms = None;
    let mut event_ids = BTreeSet::new();
    for (offset, event) in checkpoint.journal_source_head_delta.iter().enumerate() {
        event.validate(finalized_cursor).map_err(|_| {
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint source-lineage delta contains an invalid finalized event",
            }
        })?;
        let offset = bounded_len(offset)?;
        let expected_sequence = first_sequence.checked_add(offset).ok_or(
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint source-lineage delta sequence overflowed",
            },
        )?;
        let identity = journal_event_identity(event);
        let canonical_position =
            previous.map_or(event.event_index == 0, |previous: EventIdentity| {
                if identity.block_height == previous.block_height {
                    identity.block_hash == previous.block_hash
                        && previous.event_index.checked_add(1) == Some(identity.event_index)
                } else {
                    identity.block_height > previous.block_height && identity.event_index == 0
                }
            });
        if identity.sequence != expected_sequence
            || !canonical_position
            || previous_recorded_at_unix_ms
                .is_some_and(|timestamp| event.recorded_at_unix_ms < timestamp)
            || !event_ids.insert(event.entry.event_id)
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint source-lineage delta is not a complete canonical journal suffix",
            });
        }
        previous = Some(identity);
        previous_recorded_at_unix_ms = Some(event.recorded_at_unix_ms);
    }
    if previous.is_some() && previous != complete_prefix.pruned_through.map(position_identity) {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "checkpoint source-lineage delta does not reach the journal terminal",
        });
    }
    let (complete_heads, _, _) = journal_source_head_commitment(
        &checkpoint.journal_prefix_source_heads,
        &checkpoint.journal_retained_suffix,
    )?;
    let mut block_hashes = BTreeMap::new();
    if let Some(terminal) = complete_prefix.pruned_through {
        record_retained_feed_block_hash(&mut block_hashes, position_identity(terminal))?;
    }
    for identity in complete_heads.iter().map(journal_event_identity).chain(
        checkpoint
            .journal_source_head_delta
            .iter()
            .map(journal_event_identity),
    ) {
        record_retained_feed_block_hash(&mut block_hashes, identity)?;
    }
    if checkpoint.checkpoint_generation == 1 {
        let expected_prefix = journal_prefix_after_events(
            ReputationFeedPrefixSummaryV1::default(),
            &checkpoint.journal_source_head_delta,
        )?;
        let expected_heads =
            merge_journal_source_heads(&[], &checkpoint.journal_source_head_delta)?;
        if expected_prefix != complete_prefix || expected_heads != complete_heads {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "initial checkpoint source-lineage delta is incomplete or substituted",
            });
        }
    }
    Ok(())
}
fn validate_journal_source_head_lineage(
    previous: &ReputationFinalizedVirtualBaseCheckpointV1,
    current: &ReputationFinalizedVirtualBaseCheckpointV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    validate_journal_source_head_delta_standalone(current)?;
    let (previous_heads, _, _) = journal_source_head_commitment(
        &previous.journal_prefix_source_heads,
        &previous.journal_retained_suffix,
    )?;
    let (current_heads, _, _) = journal_source_head_commitment(
        &current.journal_prefix_source_heads,
        &current.journal_retained_suffix,
    )?;
    let previous_prefix =
        journal_prefix_after_events(previous.journal_prefix, &previous.journal_retained_suffix)?;
    let current_prefix =
        journal_prefix_after_events(current.journal_prefix, &current.journal_retained_suffix)?;
    let expected_prefix =
        journal_prefix_after_events(previous_prefix, &current.journal_source_head_delta)?;
    if expected_prefix != current_prefix {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "checkpoint source-lineage delta does not extend the authenticated journal prefix",
        });
    }
    let expected_heads =
        merge_journal_source_heads(&previous_heads, &current.journal_source_head_delta)?;
    if expected_heads != current_heads {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "checkpoint source-head lineage omitted, rolled back, or substituted a source",
        });
    }
    Ok(())
}
fn validate_reserve_provider_account(
    account: &ReserveProviderAccountV1,
    finalized_at_unix_ms: u64,
) -> Result<(), ReputationFinalizedArchiveError> {
    let updated_at_unix_ms = account.updated_at_unix.checked_mul(1_000).ok_or(
        ReputationFinalizedArchiveError::InvalidProjection {
            reason: "reserve provider update timestamp overflows milliseconds",
        },
    )?;
    if account.terms.provider_id.as_bytes() == &[0; 32]
        || account.terms.capacity_gib == 0
        || account.policy_digest == [0; 32]
        || account.revision == 0
        || account.debt_principal > account.credit_cap
        || (account.debt_principal.is_zero() && !account.accrued_interest.is_zero())
        || account.pending_movements > RESERVE_MAX_PENDING_MOVEMENTS_V1
        || account.open_appeals > RESERVE_MAX_OPEN_APPEALS_V1
        || account.rent_charged_through_unix == 0
        || account.interest_accrued_at_unix == 0
        || account.updated_at_unix == 0
        || account.rent_charged_through_unix > account.updated_at_unix
        || account.interest_accrued_at_unix > account.updated_at_unix
        || updated_at_unix_ms > finalized_at_unix_ms
    {
        return Err(ReputationFinalizedArchiveError::InvalidProjection {
            reason: "reserve provider projection contains a non-canonical account",
        });
    }
    account
        .total_debt()
        .and_then(|_| account.available_credit())
        .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
            reason: "reserve provider debt arithmetic is not canonical",
        })?;
    Ok(())
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::reputation_finalized::ReputationFeedHighWaterMarksV1")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct ReputationFeedHighWaterMarksV1 {
    proof_outcomes: u64,
    journal_events: u64,
    repair_events: u64,
    orderbook_events: u64,
    reserve_events: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedAnchorManifestV1"
)]
struct ReputationFinalizedAnchorManifestV1 {
    key: ReputationFinalizedArchiveKeyV1,
    predecessor: Option<ReputationFinalizedArchiveKeyV1>,
    predecessor_anchor_digest: Option<[u8; 32]>,
    finalized_at_unix_ms: u64,
    policy_record_digest: [u8; 32],
    authority_policy_history_digest: [u8; 32],
    high_water_marks: ReputationFeedHighWaterMarksV1,
    journal_source_head_count: u64,
    journal_source_head_root: [u8; 32],
    reserve_provider_count: u64,
    reserve_provider_state_root: [u8; 32],
}
impl ReputationFinalizedAnchorManifestV1 {
    fn validate_standalone(&self) -> Result<(), ReputationFinalizedArchiveError> {
        self.key.validate()?;
        if self.finalized_at_unix_ms == 0
            || self.finalized_at_unix_ms == u64::MAX
            || self.policy_record_digest == [0; 32]
            || self.authority_policy_history_digest == [0; 32]
            || self.journal_source_head_root == [0; 32]
            || self.reserve_provider_state_root == [0; 32]
        {
            return Err(ReputationFinalizedArchiveError::InvalidManifest {
                reason: "anchor manifest contains a zero or invalid commitment",
            });
        }
        if self.journal_source_head_count > self.high_water_marks.journal_events
            || (self.high_water_marks.journal_events == 0) != (self.journal_source_head_count == 0)
        {
            return Err(ReputationFinalizedArchiveError::InvalidManifest {
                reason: "anchor journal source-head commitment disagrees with its event high-water mark",
            });
        }
        match (&self.predecessor, self.predecessor_anchor_digest) {
            (None, None) => {}
            (Some(predecessor), Some(predecessor_anchor_digest)) => {
                predecessor.validate()?;
                if predecessor.network_id != self.key.network_id
                    || predecessor.height >= self.key.height
                    || predecessor == &self.key
                    || predecessor_anchor_digest == [0; 32]
                {
                    return Err(ReputationFinalizedArchiveError::InvalidManifest {
                        reason: "anchor manifest predecessor link is not an earlier exact content-bound anchor on the same chain",
                    });
                }
            }
            _ => {
                return Err(ReputationFinalizedArchiveError::InvalidManifest {
                    reason: "anchor manifest predecessor key and anchor digest must be present together",
                });
            }
        }
        Ok(())
    }
}
#[derive(
    Debug, Clone, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::query::reputation_finalized::ReputationFinalizedAnchorDeltaV1")]
struct ReputationFinalizedAnchorDeltaV1 {
    proof_outcomes: Vec<ProofOutcomeFinalizedEventV1>,
    journal_events: Vec<ReputationJournalFinalizedEventV1>,
    repair_events: Vec<RepairFinalizedEventV1>,
    orderbook_events: Vec<OrderbookFinalizedEventV1>,
    reserve_events: Vec<ReserveFinalizedEventV1>,
    reserve_provider_upserts: Vec<ReserveProviderAccountV1>,
    reserve_provider_removals: Vec<ProviderId>,
}
impl ReputationFinalizedAnchorDeltaV1 {
    fn validate_provider_operations(
        &self,
        finalized_at_unix_ms: u64,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        let mut previous_upsert = None;
        for account in &self.reserve_provider_upserts {
            validate_reserve_provider_account(account, finalized_at_unix_ms)?;
            let provider_id = account.terms.provider_id;
            if previous_upsert.is_some_and(|previous| previous >= provider_id) {
                return Err(ReputationFinalizedArchiveError::InvalidDelta {
                    reason: "reserve provider upserts are not strictly provider-id ordered",
                });
            }
            previous_upsert = Some(provider_id);
        }
        let mut previous_removal = None;
        for provider_id in &self.reserve_provider_removals {
            if provider_id.as_bytes() == &[0; 32]
                || previous_removal.is_some_and(|previous| previous >= *provider_id)
            {
                return Err(ReputationFinalizedArchiveError::InvalidDelta {
                    reason: "reserve provider removals are not canonical",
                });
            }
            previous_removal = Some(*provider_id);
        }
        let upserts = self
            .reserve_provider_upserts
            .iter()
            .map(|account| account.terms.provider_id)
            .collect::<BTreeSet<_>>();
        if self
            .reserve_provider_removals
            .iter()
            .any(|provider_id| upserts.contains(provider_id))
        {
            return Err(ReputationFinalizedArchiveError::InvalidDelta {
                reason: "reserve provider delta both removes and upserts one provider",
            });
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::PersistedReputationFinalizedAnchorV1"
)]
struct PersistedReputationFinalizedAnchorV1 {
    version: u16,
    manifest_digest: [u8; 32],
    delta_digest: [u8; 32],
    manifest: ReputationFinalizedAnchorManifestV1,
    delta: ReputationFinalizedAnchorDeltaV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedAnchorDigestMaterialV1"
)]
struct ReputationFinalizedAnchorDigestMaterialV1 {
    version: u16,
    manifest_digest: [u8; 32],
    delta_digest: [u8; 32],
}
impl PersistedReputationFinalizedAnchorV1 {
    fn try_new(
        manifest: ReputationFinalizedAnchorManifestV1,
        delta: ReputationFinalizedAnchorDeltaV1,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        manifest.validate_standalone()?;
        delta.validate_provider_operations(manifest.finalized_at_unix_ms)?;
        Ok(Self {
            version: ARCHIVE_VERSION_V1,
            manifest_digest: canonical_domain_digest(MANIFEST_DIGEST_DOMAIN_V1, &manifest)?,
            delta_digest: canonical_domain_digest(DELTA_DIGEST_DOMAIN_V1, &delta)?,
            manifest,
            delta,
        })
    }
    fn validate_standalone(&self) -> Result<(), ReputationFinalizedArchiveError> {
        if self.version != ARCHIVE_VERSION_V1 {
            return Err(ReputationFinalizedArchiveError::UnsupportedArchiveVersion {
                found: self.version,
            });
        }
        self.manifest.validate_standalone()?;
        self.delta
            .validate_provider_operations(self.manifest.finalized_at_unix_ms)?;
        if self.manifest_digest
            != canonical_domain_digest(MANIFEST_DIGEST_DOMAIN_V1, &self.manifest)?
            || self.delta_digest != canonical_domain_digest(DELTA_DIGEST_DOMAIN_V1, &self.delta)?
        {
            return Err(ReputationFinalizedArchiveError::ProjectionDigestMismatch);
        }
        Ok(())
    }
    fn anchor_digest(&self) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
        canonical_domain_digest(
            ANCHOR_DIGEST_DOMAIN_V1,
            &ReputationFinalizedAnchorDigestMaterialV1 {
                version: self.version,
                manifest_digest: self.manifest_digest,
                delta_digest: self.delta_digest,
            },
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::PersistedReputationAuthorityPolicyV1"
)]
struct PersistedReputationAuthorityPolicyV1 {
    version: u16,
    record_digest: [u8; 32],
    record: ReputationJournalAuthorityPolicyRecordV1,
}
impl PersistedReputationAuthorityPolicyV1 {
    fn try_new(
        record: ReputationJournalAuthorityPolicyRecordV1,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        record
            .validate()
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "active reputation journal authority policy is invalid",
            })?;
        Ok(Self {
            version: ARCHIVE_VERSION_V1,
            record_digest: canonical_domain_digest(POLICY_RECORD_DIGEST_DOMAIN_V1, &record)?,
            record,
        })
    }
    fn validate(&self) -> Result<(), ReputationFinalizedArchiveError> {
        if self.version != ARCHIVE_VERSION_V1 {
            return Err(ReputationFinalizedArchiveError::UnsupportedArchiveVersion {
                found: self.version,
            });
        }
        self.record
            .validate()
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "persisted reputation journal authority policy is invalid",
            })?;
        if self.record_digest
            != canonical_domain_digest(POLICY_RECORD_DIGEST_DOMAIN_V1, &self.record)?
        {
            return Err(ReputationFinalizedArchiveError::ProjectionDigestMismatch);
        }
        Ok(())
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::reputation_finalized::ReputationFeedPrefixSummaryV1")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct ReputationFeedPrefixSummaryV1 {
    pruned_through: Option<ReputationFinalizedEventPositionV1>,
    rolling_prefix_digest: [u8; 32],
    pruned_event_count: u64,
}
impl ReputationFeedPrefixSummaryV1 {
    fn validate(self) -> Result<(), ReputationFinalizedArchiveError> {
        match (self.pruned_event_count, self.pruned_through) {
            (0, None) if self.rolling_prefix_digest == [0; 32] => Ok(()),
            (count, Some(position))
                if count != 0
                    && position.sequence == count
                    && position.block_height != 0
                    && position.block_hash != [0; 32]
                    && self.rolling_prefix_digest != [0; 32] =>
            {
                Ok(())
            }
            _ => Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "feed prefix count, terminal cursor, and rolling digest disagree",
            }),
        }
    }
    #[cfg(test)]
    const fn public(self) -> ReputationFinalizedFeedPrefixV1 {
        ReputationFinalizedFeedPrefixV1 {
            pruned_through: self.pruned_through,
            rolling_prefix_digest: self.rolling_prefix_digest,
            pruned_event_count: self.pruned_event_count,
        }
    }
}
fn validate_feed_prefix_terminal(
    prefix: ReputationFeedPrefixSummaryV1,
    anchor: &ReputationFinalizedArchiveKeyV1,
) -> Result<Option<EventIdentity>, ReputationFinalizedArchiveError> {
    prefix.validate()?;
    let Some(position) = prefix.pruned_through else {
        return Ok(None);
    };
    let identity = position_identity(position);
    let at_anchor_height = identity.block_height == anchor.height;
    if identity.block_height > anchor.height
        || (at_anchor_height && identity.block_hash != anchor.block_hash)
    {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "feed prefix terminal cursor crosses or disagrees with its retention-floor anchor",
        });
    }
    Ok(Some(identity))
}
fn record_retained_feed_block_hash(
    block_hashes: &mut BTreeMap<u64, [u8; 32]>,
    identity: EventIdentity,
) -> Result<(), ReputationFinalizedArchiveError> {
    if block_hashes
        .insert(identity.block_height, identity.block_hash)
        .is_some_and(|existing| existing != identity.block_hash)
    {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "retained feeds disagree on a finalized block hash",
        });
    }
    Ok(())
}
fn validate_feed_prefixes_against_anchor(
    anchor: &ReputationFinalizedArchiveKeyV1,
    prefixes: &[ReputationFeedPrefixSummaryV1; 5],
) -> Result<BTreeMap<u64, [u8; 32]>, ReputationFinalizedArchiveError> {
    let mut block_hashes = BTreeMap::new();
    for prefix in prefixes {
        if let Some(identity) = validate_feed_prefix_terminal(*prefix, anchor)? {
            record_retained_feed_block_hash(&mut block_hashes, identity)?;
        }
    }
    Ok(block_hashes)
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationCheckpointValidationSummaryV1"
)]
struct ReputationCheckpointValidationSummaryV1 {
    high_water_marks: ReputationFeedHighWaterMarksV1,
    policy_record_digest: [u8; 32],
    journal_prefix_source_head_count: u64,
    journal_prefix_source_head_root: [u8; 32],
    reserve_provider_count: u64,
    reserve_provider_state_root: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedVirtualBaseCheckpointV1"
)]
struct ReputationFinalizedVirtualBaseCheckpointV1 {
    original_activation_floor: ReputationFinalizedArchiveKeyV1,
    retention_floor: ReputationFinalizedArchiveKeyV1,
    retention_floor_finalized_at_unix_ms: u64,
    retention_floor_anchor_digest: [u8; 32],
    certified_block_id: [u8; 32],
    prior_checkpoint_digest: Option<[u8; 32]>,
    checkpoint_generation: u64,
    cumulative_pruned_anchor_count: u64,
    cumulative_pruned_anchor_bytes: u64,
    cumulative_anchor_prefix_digest: [u8; 32],
    authority_policy: ReputationJournalAuthorityPolicyRecordV1,
    authority_policy_history_digest: [u8; 32],
    proof_prefix: ReputationFeedPrefixSummaryV1,
    journal_prefix: ReputationFeedPrefixSummaryV1,
    // TODO: Replace this bounded inline snapshot with authenticated
    // content-addressed sharded/Merkle source-index artifacts before the
    // unique-source population can grow indefinitely.
    journal_prefix_source_heads: Vec<ReputationJournalFinalizedEventV1>,
    // Complete journal suffix since the predecessor checkpoint. This
    // checkpoint-authenticated history proves source-head lifecycle changes
    // that cannot be reconstructed from latest-head snapshots alone.
    journal_source_head_delta: Vec<ReputationJournalFinalizedEventV1>,
    repair_prefix: ReputationFeedPrefixSummaryV1,
    orderbook_prefix: ReputationFeedPrefixSummaryV1,
    reserve_prefix: ReputationFeedPrefixSummaryV1,
    proof_retained_suffix: Vec<ProofOutcomeFinalizedEventV1>,
    journal_retained_suffix: Vec<ReputationJournalFinalizedEventV1>,
    repair_retained_suffix: Vec<RepairFinalizedEventV1>,
    orderbook_retained_suffix: Vec<OrderbookFinalizedEventV1>,
    reserve_retained_suffix: Vec<ReserveFinalizedEventV1>,
    reserve_providers: Vec<ReserveProviderAccountV1>,
    validation_summary: ReputationCheckpointValidationSummaryV1,
    validation_summary_digest: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::PersistedReputationFinalizedVirtualBaseCheckpointV1"
)]
struct PersistedReputationFinalizedVirtualBaseCheckpointV1 {
    version: u16,
    checkpoint_digest: [u8; 32],
    checkpoint: ReputationFinalizedVirtualBaseCheckpointV1,
}
impl PersistedReputationFinalizedVirtualBaseCheckpointV1 {
    fn try_new(
        checkpoint: ReputationFinalizedVirtualBaseCheckpointV1,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let persisted = Self {
            version: ARCHIVE_VERSION_V1,
            checkpoint_digest: checkpoint_content_digest(ARCHIVE_VERSION_V1, &checkpoint)?,
            checkpoint,
        };
        persisted.validate_standalone()?;
        Ok(persisted)
    }
    fn validate_standalone(&self) -> Result<(), ReputationFinalizedArchiveError> {
        if self.version != ARCHIVE_VERSION_V1 {
            return Err(ReputationFinalizedArchiveError::UnsupportedArchiveVersion {
                found: self.version,
            });
        }
        let checkpoint = &self.checkpoint;
        checkpoint.original_activation_floor.validate()?;
        checkpoint.retention_floor.validate()?;
        let expected_retention_height = checkpoint
            .cumulative_pruned_anchor_count
            .checked_sub(1)
            .and_then(|offset| {
                checkpoint
                    .original_activation_floor
                    .height
                    .checked_add(offset)
            });
        if checkpoint.original_activation_floor.network_id != checkpoint.retention_floor.network_id
            || checkpoint.original_activation_floor.height > checkpoint.retention_floor.height
            || expected_retention_height != Some(checkpoint.retention_floor.height)
            || checkpoint.retention_floor_finalized_at_unix_ms == 0
            || checkpoint.retention_floor_finalized_at_unix_ms == u64::MAX
            || checkpoint.retention_floor_anchor_digest == [0; 32]
            || checkpoint.certified_block_id == [0; 32]
            || checkpoint.checkpoint_generation == 0
            || checkpoint.checkpoint_generation > checkpoint.cumulative_pruned_anchor_count
            || checkpoint.cumulative_pruned_anchor_count == 0
            || checkpoint.cumulative_pruned_anchor_bytes == 0
            || checkpoint.cumulative_anchor_prefix_digest == [0; 32]
            || checkpoint.authority_policy_history_digest == [0; 32]
            || checkpoint
                .prior_checkpoint_digest
                .is_some_and(|digest| digest == [0; 32])
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "virtual-base checkpoint identity or cumulative counters are invalid",
            });
        }
        validate_feed_prefixes_against_anchor(
            &checkpoint.retention_floor,
            &[
                checkpoint.proof_prefix,
                checkpoint.journal_prefix,
                checkpoint.repair_prefix,
                checkpoint.orderbook_prefix,
                checkpoint.reserve_prefix,
            ],
        )?;
        checkpoint.authority_policy.validate().map_err(|_| {
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "virtual-base authority policy is invalid",
            }
        })?;
        if checkpoint.authority_policy.activated_at_unix_ms
            > checkpoint.retention_floor_finalized_at_unix_ms
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "virtual-base authority policy activates after the retention floor",
            });
        }
        validate_retained_feed(
            checkpoint.proof_prefix,
            &checkpoint.proof_retained_suffix,
            |event| {
                EventIdentity::from((
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                ))
            },
        )?;
        validate_retained_feed(
            checkpoint.journal_prefix,
            &checkpoint.journal_retained_suffix,
            |event| {
                EventIdentity::from((
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                ))
            },
        )?;
        validate_retained_feed(
            checkpoint.repair_prefix,
            &checkpoint.repair_retained_suffix,
            |event| {
                EventIdentity::from((
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                ))
            },
        )?;
        validate_retained_feed(
            checkpoint.orderbook_prefix,
            &checkpoint.orderbook_retained_suffix,
            |event| {
                EventIdentity::from((
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                ))
            },
        )?;
        validate_retained_feed(
            checkpoint.reserve_prefix,
            &checkpoint.reserve_retained_suffix,
            |event| {
                EventIdentity::from((
                    event.sequence,
                    event.block_height,
                    event.block_hash,
                    event.event_index,
                ))
            },
        )?;
        validate_event_suffix_anchor(
            &checkpoint.proof_retained_suffix,
            &checkpoint.retention_floor,
            proof_event_identity,
        )?;
        validate_event_suffix_anchor(
            &checkpoint.journal_retained_suffix,
            &checkpoint.retention_floor,
            journal_event_identity,
        )?;
        validate_event_suffix_anchor(
            &checkpoint.repair_retained_suffix,
            &checkpoint.retention_floor,
            repair_event_identity,
        )?;
        validate_event_suffix_anchor(
            &checkpoint.orderbook_retained_suffix,
            &checkpoint.retention_floor,
            orderbook_event_identity,
        )?;
        validate_event_suffix_anchor(
            &checkpoint.reserve_retained_suffix,
            &checkpoint.retention_floor,
            reserve_event_identity,
        )?;
        validate_journal_source_head_delta_standalone(checkpoint)?;
        ReputationReconstructionStateV1::from_checkpoint(checkpoint)?;
        let expected_summary = checkpoint_validation_summary(checkpoint)?;
        if checkpoint.validation_summary != expected_summary
            || checkpoint.validation_summary_digest
                != canonical_domain_digest(
                    CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
                    &checkpoint.validation_summary,
                )?
            || self.checkpoint_digest != checkpoint_content_digest(self.version, checkpoint)?
        {
            return Err(ReputationFinalizedArchiveError::CheckpointDigestMismatch);
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
struct CheckpointIndexEntry {
    persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1,
    path: PathBuf,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReputationRetainedFeedStateV1<T> {
    prefix: ReputationFeedPrefixSummaryV1,
    retained_suffix: Vec<T>,
}
impl<T> Default for ReputationRetainedFeedStateV1<T> {
    fn default() -> Self {
        Self {
            prefix: ReputationFeedPrefixSummaryV1::default(),
            retained_suffix: Vec::new(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReputationReconstructionStateV1 {
    key: ReputationFinalizedArchiveKeyV1,
    finalized_at_unix_ms: u64,
    authority_policy: ReputationJournalAuthorityPolicyRecordV1,
    proof_outcomes: ReputationRetainedFeedStateV1<ProofOutcomeFinalizedEventV1>,
    journal_events: ReputationRetainedFeedStateV1<ReputationJournalFinalizedEventV1>,
    journal_prefix_source_heads: Vec<ReputationJournalFinalizedEventV1>,
    repair_events: ReputationRetainedFeedStateV1<RepairFinalizedEventV1>,
    orderbook_events: ReputationRetainedFeedStateV1<OrderbookFinalizedEventV1>,
    reserve_events: ReputationRetainedFeedStateV1<ReserveFinalizedEventV1>,
    reserve_providers: Vec<ReserveProviderAccountV1>,
}
impl ReputationReconstructionStateV1 {
    fn from_projection(projection: ReputationFinalizedProjectionV1) -> Self {
        Self {
            key: projection.key,
            finalized_at_unix_ms: projection.finalized_at_unix_ms,
            authority_policy: projection.authority_policy,
            proof_outcomes: ReputationRetainedFeedStateV1 {
                prefix: ReputationFeedPrefixSummaryV1::default(),
                retained_suffix: projection.proof_outcomes,
            },
            journal_events: ReputationRetainedFeedStateV1 {
                prefix: ReputationFeedPrefixSummaryV1::default(),
                retained_suffix: projection.journal_events,
            },
            journal_prefix_source_heads: Vec::new(),
            repair_events: ReputationRetainedFeedStateV1 {
                prefix: ReputationFeedPrefixSummaryV1::default(),
                retained_suffix: projection.repair_events,
            },
            orderbook_events: ReputationRetainedFeedStateV1 {
                prefix: ReputationFeedPrefixSummaryV1::default(),
                retained_suffix: projection.orderbook_events,
            },
            reserve_events: ReputationRetainedFeedStateV1 {
                prefix: ReputationFeedPrefixSummaryV1::default(),
                retained_suffix: projection.reserve_events,
            },
            reserve_providers: projection.reserve_providers,
        }
    }
    fn from_checkpoint(
        checkpoint: &ReputationFinalizedVirtualBaseCheckpointV1,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let state = Self {
            key: checkpoint.retention_floor.clone(),
            finalized_at_unix_ms: checkpoint.retention_floor_finalized_at_unix_ms,
            authority_policy: checkpoint.authority_policy.clone(),
            proof_outcomes: ReputationRetainedFeedStateV1 {
                prefix: checkpoint.proof_prefix,
                retained_suffix: checkpoint.proof_retained_suffix.clone(),
            },
            journal_events: ReputationRetainedFeedStateV1 {
                prefix: checkpoint.journal_prefix,
                retained_suffix: checkpoint.journal_retained_suffix.clone(),
            },
            journal_prefix_source_heads: checkpoint.journal_prefix_source_heads.clone(),
            repair_events: ReputationRetainedFeedStateV1 {
                prefix: checkpoint.repair_prefix,
                retained_suffix: checkpoint.repair_retained_suffix.clone(),
            },
            orderbook_events: ReputationRetainedFeedStateV1 {
                prefix: checkpoint.orderbook_prefix,
                retained_suffix: checkpoint.orderbook_retained_suffix.clone(),
            },
            reserve_events: ReputationRetainedFeedStateV1 {
                prefix: checkpoint.reserve_prefix,
                retained_suffix: checkpoint.reserve_retained_suffix.clone(),
            },
            reserve_providers: checkpoint.reserve_providers.clone(),
        };
        state.validate()?;
        Ok(state)
    }
    fn full_projection(
        &self,
    ) -> Result<ReputationFinalizedProjectionV1, ReputationFinalizedArchiveError> {
        if [
            self.proof_outcomes.prefix.pruned_event_count,
            self.journal_events.prefix.pruned_event_count,
            self.repair_events.prefix.pruned_event_count,
            self.orderbook_events.prefix.pruned_event_count,
            self.reserve_events.prefix.pruned_event_count,
        ]
        .into_iter()
        .any(|count| count != 0)
        {
            return Err(ReputationFinalizedArchiveError::HistoryPruned {
                available_after: [
                    self.proof_outcomes.prefix.pruned_through,
                    self.journal_events.prefix.pruned_through,
                    self.repair_events.prefix.pruned_through,
                    self.orderbook_events.prefix.pruned_through,
                    self.reserve_events.prefix.pruned_through,
                ]
                .into_iter()
                .flatten()
                .min(),
            });
        }
        Ok(ReputationFinalizedProjectionV1 {
            key: self.key.clone(),
            finalized_at_unix_ms: self.finalized_at_unix_ms,
            authority_policy: self.authority_policy.clone(),
            proof_outcomes: self.proof_outcomes.retained_suffix.clone(),
            journal_events: self.journal_events.retained_suffix.clone(),
            repair_events: self.repair_events.retained_suffix.clone(),
            orderbook_events: self.orderbook_events.retained_suffix.clone(),
            reserve_events: self.reserve_events.retained_suffix.clone(),
            reserve_providers: self.reserve_providers.clone(),
        })
    }
    fn high_water_marks(
        &self,
    ) -> Result<ReputationFeedHighWaterMarksV1, ReputationFinalizedArchiveError> {
        Ok(ReputationFeedHighWaterMarksV1 {
            proof_outcomes: retained_feed_high_water(&self.proof_outcomes)?,
            journal_events: retained_feed_high_water(&self.journal_events)?,
            repair_events: retained_feed_high_water(&self.repair_events)?,
            orderbook_events: retained_feed_high_water(&self.orderbook_events)?,
            reserve_events: retained_feed_high_water(&self.reserve_events)?,
        })
    }
    fn validate(&self) -> Result<(), ReputationFinalizedArchiveError> {
        self.key.validate()?;
        if self.finalized_at_unix_ms == 0 || self.finalized_at_unix_ms == u64::MAX {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "reconstruction state timestamp is invalid",
            });
        }
        self.authority_policy.validate().map_err(|_| {
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "reconstruction state authority policy is invalid",
            }
        })?;
        validate_retained_feed(
            self.proof_outcomes.prefix,
            &self.proof_outcomes.retained_suffix,
            proof_event_identity,
        )?;
        validate_retained_feed(
            self.journal_events.prefix,
            &self.journal_events.retained_suffix,
            journal_event_identity,
        )?;
        validate_journal_prefix_source_heads(
            self.journal_events.prefix,
            &self.journal_prefix_source_heads,
            &self.journal_events.retained_suffix,
            &self.key,
            self.finalized_at_unix_ms,
        )?;
        validate_retained_feed(
            self.repair_events.prefix,
            &self.repair_events.retained_suffix,
            repair_event_identity,
        )?;
        validate_retained_feed(
            self.orderbook_events.prefix,
            &self.orderbook_events.retained_suffix,
            orderbook_event_identity,
        )?;
        validate_retained_feed(
            self.reserve_events.prefix,
            &self.reserve_events.retained_suffix,
            reserve_event_identity,
        )?;
        validate_event_suffix_anchor(
            &self.proof_outcomes.retained_suffix,
            &self.key,
            proof_event_identity,
        )?;
        validate_event_suffix_anchor(
            &self.journal_events.retained_suffix,
            &self.key,
            journal_event_identity,
        )?;
        validate_event_suffix_anchor(
            &self.repair_events.retained_suffix,
            &self.key,
            repair_event_identity,
        )?;
        validate_event_suffix_anchor(
            &self.orderbook_events.retained_suffix,
            &self.key,
            orderbook_event_identity,
        )?;
        validate_event_suffix_anchor(
            &self.reserve_events.retained_suffix,
            &self.key,
            reserve_event_identity,
        )?;
        let mut retained_block_hashes = validate_feed_prefixes_against_anchor(
            &self.key,
            &[
                self.proof_outcomes.prefix,
                self.journal_events.prefix,
                self.repair_events.prefix,
                self.orderbook_events.prefix,
                self.reserve_events.prefix,
            ],
        )?;
        for identity in self
            .proof_outcomes
            .retained_suffix
            .iter()
            .map(proof_event_identity)
            .chain(
                self.journal_prefix_source_heads
                    .iter()
                    .map(journal_event_identity),
            )
            .chain(
                self.journal_events
                    .retained_suffix
                    .iter()
                    .map(journal_event_identity),
            )
            .chain(
                self.repair_events
                    .retained_suffix
                    .iter()
                    .map(repair_event_identity),
            )
            .chain(
                self.orderbook_events
                    .retained_suffix
                    .iter()
                    .map(orderbook_event_identity),
            )
            .chain(
                self.reserve_events
                    .retained_suffix
                    .iter()
                    .map(reserve_event_identity),
            )
        {
            record_retained_feed_block_hash(&mut retained_block_hashes, identity)?;
        }
        for event in &self.journal_events.retained_suffix {
            event.entry.validate().map_err(|_| {
                ReputationFinalizedArchiveError::InvalidCheckpoint {
                    reason: "retained reputation journal entry is invalid",
                }
            })?;
            if event.recorded_at_unix_ms == 0
                || event.recorded_at_unix_ms > self.finalized_at_unix_ms
                || event.entry.source_time_unix_ms > event.recorded_at_unix_ms
            {
                return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                    reason: "retained reputation journal timestamp is outside the anchor",
                });
            }
        }
        let mut previous_provider_id = None;
        for account in &self.reserve_providers {
            validate_reserve_provider_account(account, self.finalized_at_unix_ms)?;
            let provider_id = account.terms.provider_id;
            if previous_provider_id.is_some_and(|previous| previous >= provider_id) {
                return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                    reason: "virtual-base providers are not strictly provider-id ordered",
                });
            }
            previous_provider_id = Some(provider_id);
        }
        Ok(())
    }
}
fn journal_source_view(
    key: &ReputationFinalizedArchiveKeyV1,
    finalized_at_unix_ms: u64,
    prefix_source_heads: &[ReputationJournalFinalizedEventV1],
    retained_suffix: &[ReputationJournalFinalizedEventV1],
    expected_source_head_count: u64,
    expected_source_head_root: [u8; 32],
    source_id: ReputationJournalSourceIdV1,
) -> Result<ReputationFinalizedArchiveJournalSourceViewV1, ReputationFinalizedArchiveError> {
    let (source_heads, source_head_count, source_head_root) =
        journal_source_head_commitment(prefix_source_heads, retained_suffix)?;
    if source_head_count != expected_source_head_count
        || source_head_root != expected_source_head_root
    {
        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
            reason: "journal source view disagrees with its immutable anchor commitment",
        });
    }
    let event = source_heads
        .binary_search_by_key(&source_id, |event| event.entry.source_id)
        .ok()
        .map(|index| source_heads[index].clone());
    Ok(ReputationFinalizedArchiveJournalSourceViewV1 {
        key: key.clone(),
        finalized_at_unix_ms,
        event,
    })
}
fn journal_source_view_from_state(
    state: &ReputationReconstructionStateV1,
    expected_source_head_count: u64,
    expected_source_head_root: [u8; 32],
    source_id: ReputationJournalSourceIdV1,
) -> Result<ReputationFinalizedArchiveJournalSourceViewV1, ReputationFinalizedArchiveError> {
    journal_source_view(
        &state.key,
        state.finalized_at_unix_ms,
        &state.journal_prefix_source_heads,
        &state.journal_events.retained_suffix,
        expected_source_head_count,
        expected_source_head_root,
        source_id,
    )
}
#[derive(Debug, Clone)]
struct AnchorIndexEntry {
    manifest: ReputationFinalizedAnchorManifestV1,
    anchor_digest: [u8; 32],
    path: PathBuf,
}
#[derive(Debug, Default)]
struct ArchiveIndex {
    by_height: BTreeMap<(NetworkId, u64), AnchorIndexEntry>,
    checkpoints: BTreeMap<NetworkId, CheckpointIndexEntry>,
    policies: BTreeMap<[u8; 32], ReputationJournalAuthorityPolicyRecordV1>,
    latest_projection: BTreeMap<NetworkId, ReputationFinalizedProjectionV1>,
    latest_state: BTreeMap<NetworkId, ReputationReconstructionStateV1>,
    anchor_count: usize,
    checkpoint_count: usize,
    policy_count: usize,
    total_bytes: u64,
    generation: u64,
    requires_reopen: bool,
}
struct PreparedReputationPolicy {
    persisted: PersistedReputationAuthorityPolicyV1,
    bytes: Vec<u8>,
    path: PathBuf,
    /// Exact cumulative accounting, consumed once after this immutable file is authenticated.
    accounting: Option<(usize, u64)>,
}
struct PreparedReputationState {
    policies: Vec<PreparedReputationPolicy>,
    anchor: PersistedReputationFinalizedAnchorV1,
    anchor_digest: [u8; 32],
    anchor_bytes: Vec<u8>,
    anchor_path: PathBuf,
    next_state: ReputationReconstructionStateV1,
    full_projection: Option<ReputationFinalizedProjectionV1>,
    total_bytes: u64,
    anchor_count: usize,
    generation: u64,
}
include!("reputation_finalized/capture_material.rs");
struct PreparedReputationInsertion<'archive> {
    archive: &'archive ReputationFinalizedArchive,
    index: ArchiveIndexWriteGuard<'archive, ArchiveIndex>,
    key: ReputationFinalizedArchiveKeyV1,
    state: Option<PreparedReputationState>,
}
impl PreparedReputationInsertion<'_> {
    fn persist(
        &mut self,
    ) -> Result<ReputationFinalizedArchiveInsertOutcome, ReputationFinalizedArchiveError> {
        persist_admitted_reputation(self.archive, &mut self.index, &self.key, &mut self.state)
    }
}
fn persist_admitted_reputation(
    archive: &ReputationFinalizedArchive,
    index: &mut ArchiveIndex,
    key: &ReputationFinalizedArchiveKeyV1,
    state: &mut Option<PreparedReputationState>,
) -> Result<ReputationFinalizedArchiveInsertOutcome, ReputationFinalizedArchiveError> {
    let Some(prepared) = state.as_mut() else {
        archive.verify_storage_boundaries()?;
        // Existing files still require storage authentication after a delayed replay.
        archive.reconstruct_state_for_key(index, key)?;
        return Ok(ReputationFinalizedArchiveInsertOutcome::ExactReplay);
    };
    archive.verify_storage_boundaries()?;
    for policy in &mut prepared.policies {
        if policy.accounting.is_some() {
            publish_immutable_bytes(
                &archive.policies,
                archive.policies_identity,
                &policy.path,
                &policy.bytes,
            )?;
        }
        let loaded = archive.load_policy_at(&policy.path, Some(policy.persisted.record_digest))?;
        if loaded != policy.persisted {
            return Err(ReputationFinalizedArchiveError::PolicyConflict {
                digest: policy.persisted.record_digest,
            });
        }
        if let Some((policy_count, total_bytes)) = policy.accounting.take() {
            index.policies.insert(
                policy.persisted.record_digest,
                policy.persisted.record.clone(),
            );
            index.policy_count = policy_count;
            index.total_bytes = total_bytes;
        }
    }
    publish_immutable_bytes(
        &archive.anchors,
        archive.anchors_identity,
        &prepared.anchor_path,
        &prepared.anchor_bytes,
    )?;
    let loaded = archive.load_anchor_at(&prepared.anchor_path, Some(key))?;
    if loaded != prepared.anchor {
        return Err(ReputationFinalizedArchiveError::ConflictingProjection {
            network_id: key.network_id,
            height: key.height,
            block_hash: key.block_hash,
        });
    }
    archive.verify_storage_boundaries()?;
    // All fallible work has finished. Taking this private action makes index publication once-only.
    if let Some(prepared) = state.take() {
        index.total_bytes = prepared.total_bytes;
        index.anchor_count = prepared.anchor_count;
        index.by_height.insert(
            (key.network_id, key.height),
            AnchorIndexEntry {
                manifest: prepared.anchor.manifest,
                anchor_digest: prepared.anchor_digest,
                path: prepared.anchor_path,
            },
        );
        if let Some(projection) = prepared.full_projection {
            index.latest_projection.insert(key.network_id, projection);
        } else {
            index.latest_projection.remove(&key.network_id);
        }
        index
            .latest_state
            .insert(key.network_id, prepared.next_state);
        index.generation = prepared.generation;
    }
    Ok(ReputationFinalizedArchiveInsertOutcome::Inserted)
}

#[derive(Debug, Clone)]
struct PreparedReputationFinalizedArchiveCompactionV1 {
    network_id: NetworkId,
    persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1,
    checkpoint_bytes: Vec<u8>,
    anchors: Vec<AnchorIndexEntry>,
    newly_pruned_bytes: u64,
    expected_archive_generation: u64,
}
fn require_contiguous_capture_key_in_index(
    index: &ArchiveIndex,
    key: &ReputationFinalizedArchiveKeyV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    if let Some(existing) = index.by_height.get(&(key.network_id.clone(), key.height)) {
        if existing.manifest.key.block_hash != key.block_hash {
            return Err(ReputationFinalizedArchiveError::FinalizedFork {
                network_id: key.network_id.clone(),
                height: key.height,
            });
        }
        return Ok(());
    }
    let latest = index
        .latest_state
        .get(&key.network_id)
        .map(|state| state.key.height);
    if let Some(latest_height) = latest {
        let expected_height = latest_height.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::ArchiveCoverageGap {
                network_id: key.network_id.clone(),
                missing_height: u64::MAX,
                observed_height: key.height,
            },
        )?;
        if key.height != expected_height {
            return Err(ReputationFinalizedArchiveError::ArchiveCoverageGap {
                network_id: key.network_id.clone(),
                missing_height: expected_height,
                observed_height: key.height,
            });
        }
    }
    Ok(())
}
fn active_checkpoint_digest(index: &ArchiveIndex, network_id: &NetworkId) -> Option<[u8; 32]> {
    index
        .checkpoints
        .get(network_id)
        .map(|checkpoint| checkpoint.persisted.checkpoint_digest)
}
fn validate_qualification_archive_boundary(
    index: &ArchiveIndex,
    network_id: &NetworkId,
    expected_generation: u64,
    expected_checkpoint_digest: Option<[u8; 32]>,
) -> Result<(), ReputationFinalizedArchiveError> {
    if index.generation != expected_generation
        || active_checkpoint_digest(index, network_id) != expected_checkpoint_digest
    {
        return Err(
            ReputationFinalizedArchiveError::QualificationBoundaryChanged {
                boundary: "archive",
            },
        );
    }
    Ok(())
}
fn bounded_len(length: usize) -> Result<u64, ReputationFinalizedArchiveError> {
    u64::try_from(length).map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
        reason: "finalized projection length exceeds the supported range",
    })
}
/// Result of an immutable archive insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationFinalizedArchiveInsertOutcome {
    /// A new exact-anchor record was durably published.
    Inserted,
    /// Byte-equivalent typed content was already durable at the exact key.
    ExactReplay,
}
/// Stable normalized identity of one retained or compacted finalized-feed row.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedEventPositionV1"
)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize,
)]
pub struct ReputationFinalizedEventPositionV1 {
    /// Global one-based feed sequence.
    pub sequence: u64,
    /// Finalized block height containing the row.
    pub block_height: u64,
    /// Exact finalized block hash.
    pub block_hash: [u8; 32],
    /// Canonical feed-event index in the block.
    pub event_index: u32,
}
const fn event_position(identity: EventIdentity) -> ReputationFinalizedEventPositionV1 {
    ReputationFinalizedEventPositionV1 {
        sequence: identity.sequence,
        block_height: identity.block_height,
        block_hash: identity.block_hash,
        event_index: identity.event_index,
    }
}
const fn position_identity(position: ReputationFinalizedEventPositionV1) -> EventIdentity {
    EventIdentity {
        sequence: position.sequence,
        block_height: position.block_height,
        block_hash: position.block_hash,
        event_index: position.event_index,
    }
}
/// Public prefix commitment accompanying one retained finalized feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ReputationFinalizedFeedPrefixV1 {
    /// Last row compacted into the rolling prefix, if any.
    pub pruned_through: Option<ReputationFinalizedEventPositionV1>,
    /// Domain-separated rolling commitment to every compacted row in order.
    pub rolling_prefix_digest: [u8; 32],
    /// Cumulative number of rows compacted into the prefix.
    pub pruned_event_count: u64,
}
#[cfg(test)]
/// Typed result of paginating one retained finalized feed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ReputationFinalizedArchivePageV1<T, C> {
    /// The requested exclusive cursor remains available in the retained suffix.
    Page {
        /// Retained rows after the exclusive cursor.
        events: Vec<T>,
        /// Whether another retained page follows.
        has_more: bool,
        /// Exclusive cursor for the next retained page.
        next_after: Option<C>,
        /// Commitment to history compacted before this retained suffix.
        prefix: ReputationFinalizedFeedPrefixV1,
    },
    /// The request would silently omit compacted history.
    HistoryPruned {
        /// Exact cursor callers must submit to begin at the retained boundary.
        available_after: C,
        /// Commitment to the compacted prefix.
        prefix: ReputationFinalizedFeedPrefixV1,
    },
}
/// Exact caller-supplied fence authorizing one prefix-compaction transaction.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionFenceV1"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[must_use]
pub struct ReputationFinalizedArchiveRetentionFenceV1 {
    compact_through: ReputationFinalizedArchiveKeyV1,
    compact_through_anchor_digest: [u8; 32],
    expected_checkpoint_digest: Option<[u8; 32]>,
    expected_generation: u64,
}
impl ReputationFinalizedArchiveRetentionFenceV1 {
    /// Construct an exact-key, exact-content, checkpoint-head, and generation fence.
    ///
    /// # Errors
    ///
    /// Rejects malformed keys, zero content digests, or generation zero.
    pub fn try_new(
        compact_through: ReputationFinalizedArchiveKeyV1,
        compact_through_anchor_digest: [u8; 32],
        expected_checkpoint_digest: Option<[u8; 32]>,
        expected_generation: u64,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        compact_through.validate()?;
        if compact_through_anchor_digest == [0; 32]
            || expected_checkpoint_digest.is_some_and(|digest| digest == [0; 32])
            || expected_generation == 0
        {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionFence {
                reason: "retention fence digests and generation must be non-zero",
            });
        }
        Ok(Self {
            compact_through,
            compact_through_anchor_digest,
            expected_checkpoint_digest,
            expected_generation,
        })
    }
    /// Exact terminal anchor whose prefix may be compacted.
    #[must_use]
    pub const fn compact_through(&self) -> &ReputationFinalizedArchiveKeyV1 {
        &self.compact_through
    }
    /// Content digest of the exact terminal anchor.
    #[must_use]
    pub const fn compact_through_anchor_digest(&self) -> [u8; 32] {
        self.compact_through_anchor_digest
    }
    /// Active virtual-base checkpoint content address frozen by the caller.
    #[must_use]
    pub const fn expected_checkpoint_digest(&self) -> Option<[u8; 32]> {
        self.expected_checkpoint_digest
    }
    /// Archive generation frozen by the caller.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
}
/// Public qualification of a deployment-owned sealed retention authority.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityQualificationV1"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ReputationFinalizedArchiveRetentionAuthorityQualificationV1 {
    version: u16,
    revision: u64,
    policy_digest: [u8; 32],
}
impl ReputationFinalizedArchiveRetentionAuthorityQualificationV1 {
    /// Construct one exact public adapter and policy qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            version: ARCHIVE_VERSION_V1,
            revision,
            policy_digest,
        }
    }
    /// Return the exact adapter/public-policy revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
    /// Return the exact public-policy digest.
    #[must_use]
    pub const fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }
    fn validate(self) -> Result<(), ReputationFinalizedArchiveError> {
        if self.version != ARCHIVE_VERSION_V1 || self.revision == 0 || self.policy_digest == [0; 32]
        {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionAuthorityBinding);
        }
        Ok(())
    }
}
/// Credential-free expected identity of a sealed retention authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationFinalizedArchiveRetentionAuthorityBindingV1 {
    handle: String,
    qualification: ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
}
impl ReputationFinalizedArchiveRetentionAuthorityBindingV1 {
    /// Construct one exact deployment-owned authority binding.
    ///
    /// # Errors
    ///
    /// Rejects credential-bearing, test-marked, malformed, stale, or zero public identity material.
    pub fn try_new(
        handle: String,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        if !iroha_config::parameters::is_production_runtime_handle(&handle) {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionAuthorityBinding);
        }
        let qualification = ReputationFinalizedArchiveRetentionAuthorityQualificationV1::new(
            revision,
            policy_digest,
        );
        qualification.validate()?;
        Ok(Self {
            handle,
            qualification,
        })
    }
    /// Return the exact credential-free runtime-provider handle.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }
    /// Return the exact public adapter and policy qualification.
    #[must_use]
    pub const fn qualification(
        &self,
    ) -> ReputationFinalizedArchiveRetentionAuthorityQualificationV1 {
        self.qualification
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveCompactionProposalMaterialV1"
)]
struct ReputationFinalizedArchiveCompactionProposalMaterialV1 {
    version: u16,
    fence: ReputationFinalizedArchiveRetentionFenceV1,
    checkpoint_digest: [u8; 32],
    checkpoint_canonical_digest: [u8; 32],
    journal_source_head_count: u64,
    journal_source_head_root: [u8; 32],
}
/// Exact canonical checkpoint, source-head summary, and fence submitted for external approval.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveCompactionProposalV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ReputationFinalizedArchiveCompactionProposalV1 {
    material: ReputationFinalizedArchiveCompactionProposalMaterialV1,
    proposal_digest: [u8; 32],
}
impl ReputationFinalizedArchiveCompactionProposalV1 {
    fn try_new(
        fence: ReputationFinalizedArchiveRetentionFenceV1,
        checkpoint_digest: [u8; 32],
        checkpoint_canonical_digest: [u8; 32],
        journal_source_head_count: u64,
        journal_source_head_root: [u8; 32],
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let material = ReputationFinalizedArchiveCompactionProposalMaterialV1 {
            version: ARCHIVE_VERSION_V1,
            fence,
            checkpoint_digest,
            checkpoint_canonical_digest,
            journal_source_head_count,
            journal_source_head_root,
        };
        let proposal_digest =
            canonical_domain_digest(RETENTION_PROPOSAL_DIGEST_DOMAIN_V1, &material)?;
        let proposal = Self {
            material,
            proposal_digest,
        };
        proposal.validate()?;
        Ok(proposal)
    }
    fn validate(&self) -> Result<(), ReputationFinalizedArchiveError> {
        self.material.fence.compact_through.validate()?;
        if self.material.version != ARCHIVE_VERSION_V1
            || self.material.fence.compact_through_anchor_digest == [0; 32]
            || self
                .material
                .fence
                .expected_checkpoint_digest
                .is_some_and(|digest| digest == [0; 32])
            || self.material.fence.expected_generation == 0
            || self.material.checkpoint_digest == [0; 32]
            || self.material.checkpoint_canonical_digest == [0; 32]
            || self.material.journal_source_head_root == [0; 32]
            || canonical_domain_digest(RETENTION_PROPOSAL_DIGEST_DOMAIN_V1, &self.material)?
                != self.proposal_digest
        {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionApproval {
                reason: "compaction proposal is malformed or noncanonical",
            });
        }
        Ok(())
    }
    /// Return the exact Kura-authenticated archive fence.
    pub const fn fence(&self) -> &ReputationFinalizedArchiveRetentionFenceV1 {
        &self.material.fence
    }
    /// Return the content-addressed archive checkpoint digest.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> [u8; 32] {
        self.material.checkpoint_digest
    }
    /// Return the digest of the complete canonical checkpoint bytes.
    #[must_use]
    pub const fn checkpoint_canonical_digest(&self) -> [u8; 32] {
        self.material.checkpoint_canonical_digest
    }
    /// Return the externally approved complete source-head count.
    #[must_use]
    pub const fn journal_source_head_count(&self) -> u64 {
        self.material.journal_source_head_count
    }
    /// Return the externally approved complete source-head root.
    #[must_use]
    pub const fn journal_source_head_root(&self) -> [u8; 32] {
        self.material.journal_source_head_root
    }
    /// Return the digest naming this exact proposal.
    #[must_use]
    pub const fn proposal_digest(&self) -> [u8; 32] {
        self.proposal_digest
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionApprovalMaterialV1"
)]
struct ReputationFinalizedArchiveRetentionApprovalMaterialV1 {
    namespace: [u8; 32],
    version: u16,
    sequence: u64,
    authority_qualification: ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
    proposal: ReputationFinalizedArchiveCompactionProposalV1,
    predecessor_revision: Option<[u8; 32]>,
    predecessor_checkpoint_digest: Option<[u8; 32]>,
}
/// Canonical monotonic CAS record approving one exact compaction proposal.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionApprovalRecordV1"
)]
pub struct ReputationFinalizedArchiveRetentionApprovalRecordV1 {
    material: ReputationFinalizedArchiveRetentionApprovalMaterialV1,
    revision: [u8; 32],
}
impl ReputationFinalizedArchiveRetentionApprovalRecordV1 {
    fn try_new(
        sequence: u64,
        authority_qualification: ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        proposal: ReputationFinalizedArchiveCompactionProposalV1,
        predecessor_revision: Option<[u8; 32]>,
        predecessor_checkpoint_digest: Option<[u8; 32]>,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let material = ReputationFinalizedArchiveRetentionApprovalMaterialV1 {
            namespace: RETENTION_APPROVAL_NAMESPACE_V1,
            version: ARCHIVE_VERSION_V1,
            sequence,
            authority_qualification,
            proposal,
            predecessor_revision,
            predecessor_checkpoint_digest,
        };
        let revision = canonical_domain_digest(RETENTION_APPROVAL_REVISION_DOMAIN_V1, &material)?;
        let record = Self { material, revision };
        record.validate()?;
        Ok(record)
    }
    fn validate(&self) -> Result<(), ReputationFinalizedArchiveError> {
        self.material.authority_qualification.validate()?;
        self.material.proposal.validate()?;
        let lineage_is_valid = if self.material.sequence == 1 {
            self.material.predecessor_revision.is_none()
                && self.material.predecessor_checkpoint_digest.is_none()
        } else {
            self.material
                .predecessor_revision
                .is_some_and(|revision| revision != [0; 32])
                && self
                    .material
                    .predecessor_checkpoint_digest
                    .is_some_and(|digest| digest != [0; 32])
        };
        if self.material.namespace != RETENTION_APPROVAL_NAMESPACE_V1
            || self.material.version != ARCHIVE_VERSION_V1
            || self.material.sequence == 0
            || !lineage_is_valid
            || canonical_domain_digest(RETENTION_APPROVAL_REVISION_DOMAIN_V1, &self.material)?
                != self.revision
        {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionApproval {
                reason: "approval record is malformed or has noncanonical lineage",
            });
        }
        Ok(())
    }
    /// Decode one strictly bounded canonical Norito approval record.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, malformed, noncanonical, or invalid records.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReputationFinalizedArchiveError> {
        if bytes.is_empty() || bytes.len() > RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1 {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionApproval {
                reason: "approval record exceeds its canonical byte bound",
            });
        }
        let record =
            decode_from_bytes_with_limits::<Self>(bytes, RETENTION_APPROVAL_DECODE_LIMITS_V1)
                .map_err(
                    |_| ReputationFinalizedArchiveError::InvalidRetentionApproval {
                        reason: "approval record failed bounded Norito decoding",
                    },
                )?;
        record.validate()?;
        if norito::to_bytes(&record).map_err(ReputationFinalizedArchiveError::Encode)? != bytes {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionApproval {
                reason: "approval record is not canonical Norito",
            });
        }
        Ok(record)
    }
    /// Encode this approval as strictly bounded canonical Norito.
    ///
    /// # Errors
    ///
    /// Rejects invalid records and encoded values above the fixed V1 bound.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReputationFinalizedArchiveError> {
        self.validate()?;
        let bytes = norito::to_bytes(self).map_err(ReputationFinalizedArchiveError::Encode)?;
        if bytes.is_empty() || bytes.len() > RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1 {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionApproval {
                reason: "approval record exceeds its canonical byte bound",
            });
        }
        Ok(bytes)
    }
    /// Return the monotonic authority sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.material.sequence
    }
    /// Return the exact public authority qualification.
    #[must_use]
    pub const fn authority_qualification(
        &self,
    ) -> ReputationFinalizedArchiveRetentionAuthorityQualificationV1 {
        self.material.authority_qualification
    }
    /// Return the exact approved proposal.
    #[must_use]
    pub const fn proposal(&self) -> &ReputationFinalizedArchiveCompactionProposalV1 {
        &self.material.proposal
    }
    /// Return the exact predecessor approval revision.
    #[must_use]
    pub const fn predecessor_revision(&self) -> Option<[u8; 32]> {
        self.material.predecessor_revision
    }
    /// Return the exact predecessor archive-checkpoint digest.
    #[must_use]
    pub const fn predecessor_checkpoint_digest(&self) -> Option<[u8; 32]> {
        self.material.predecessor_checkpoint_digest
    }
    /// Return this deterministic CAS revision.
    #[must_use]
    pub const fn revision(&self) -> [u8; 32] {
        self.revision
    }
}
/// Fixed payload-free failures returned by an external retention authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1 {
    /// The external authority is unavailable.
    Unavailable,
    /// The external authority rejected the exact operation.
    Rejected,
    /// A compare-and-swap may have committed and requires exact readback.
    Ambiguous,
}
/// Deployment-owned sealed monotonic CAS authority for archive retention.
///
/// Implementations own all credentials and durable state. Each `network_id`
/// identifies an independent linearizable namespace containing only canonical
/// [`ReputationFinalizedArchiveRetentionApprovalRecordV1`] values.
///
/// Calls run while the archive writer is held. Implementations must not acquire State/World
/// writer guards or wait for canonical State publication; candidate publication acquires
/// State ownership before reserving this archive. The production broker adapters perform
/// independent bounded RPCs and retain no State owner.
pub trait ReputationFinalizedArchiveRetentionAuthorityV1: Send + Sync + fmt::Debug {
    /// Return the stable credential-free production handle.
    fn handle(&self) -> &str;
    /// Return the current public adapter and policy qualification.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn qualification(
        &self,
    ) -> Result<
        ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >;
    /// Load the exact latest authoritative record for `network_id`.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn load_latest(
        &self,
        network_id: &NetworkId,
    ) -> Result<
        Option<ReputationFinalizedArchiveRetentionApprovalRecordV1>,
        ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >;
    /// Install `next` only when the authoritative revision is exactly `expected_revision`.
    ///
    /// A write whose commit outcome is unknown must return
    /// [`ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous`].
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn compare_and_swap_latest(
        &self,
        network_id: &NetworkId,
        expected_revision: Option<[u8; 32]>,
        next: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
    ) -> Result<(), ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1>;
}
/// Durable result of one explicit finalized-prefix compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ReputationFinalizedArchiveCompactionOutcomeV1 {
    retention_floor: ReputationFinalizedArchiveKeyV1,
    checkpoint_digest: [u8; 32],
    pruned_anchors: u64,
    pruned_bytes: u64,
    generation: u64,
}
impl ReputationFinalizedArchiveCompactionOutcomeV1 {
    /// Exact virtual-base anchor installed by the checkpoint.
    #[must_use]
    pub const fn retention_floor(&self) -> &ReputationFinalizedArchiveKeyV1 {
        &self.retention_floor
    }
    /// Canonical content address of the installed checkpoint.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> [u8; 32] {
        self.checkpoint_digest
    }
    /// Physical anchor artifacts removed by this transaction.
    #[must_use]
    pub const fn pruned_anchors(&self) -> u64 {
        self.pruned_anchors
    }
    /// Physical anchor bytes removed by this transaction.
    #[must_use]
    pub const fn pruned_bytes(&self) -> u64 {
        self.pruned_bytes
    }
    /// Monotonic anchor/checkpoint-head generation retained across reopen.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Exact durable coverage qualified against one authenticated Kura boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ReputationFinalizedArchiveQualificationV1 {
    activation_floor: ReputationFinalizedArchiveKeyV1,
    archive_tip: ReputationFinalizedArchiveKeyV1,
    checkpoint_digest: Option<[u8; 32]>,
    kura_tip_height: u64,
    lag_blocks: u64,
    generation: u64,
}
impl ReputationFinalizedArchiveQualificationV1 {
    /// Return the first exact height covered by the archive.
    #[must_use]
    pub fn activation_floor(&self) -> &ReputationFinalizedArchiveKeyV1 {
        &self.activation_floor
    }
    /// Return the highest exact height covered by the archive.
    #[must_use]
    pub fn archive_tip(&self) -> &ReputationFinalizedArchiveKeyV1 {
        &self.archive_tip
    }
    /// Return the active virtual-base checkpoint content address, if compacted.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> Option<[u8; 32]> {
        self.checkpoint_digest
    }
    /// Return the authenticated Kura tip used for this qualification.
    #[must_use]
    pub const fn kura_tip_height(&self) -> u64 {
        self.kura_tip_height
    }
    /// Return the explicit Kura suffix not yet represented by the archive.
    #[must_use]
    pub const fn lag_blocks(&self) -> u64 {
        self.lag_blocks
    }
    /// Return the immutable anchor/checkpoint-head generation used for this qualification.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Result of reconciling one frozen state view into the exact archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ReputationFinalizedArchiveReconcileOutcomeV1 {
    insertion: ReputationFinalizedArchiveInsertOutcome,
    qualification: ReputationFinalizedArchiveQualificationV1,
    activation_floor_created: bool,
}
impl ReputationFinalizedArchiveReconcileOutcomeV1 {
    /// Return whether capture inserted a record or proved an exact replay.
    #[must_use]
    pub const fn insertion(&self) -> ReputationFinalizedArchiveInsertOutcome {
        self.insertion
    }
    /// Return the Kura-bound archive qualification after capture.
    pub const fn qualification(&self) -> &ReputationFinalizedArchiveQualificationV1 {
        &self.qualification
    }
    /// Return whether this capture explicitly established a new activation floor.
    #[must_use]
    pub const fn activation_floor_created(&self) -> bool {
        self.activation_floor_created
    }
}
#[derive(Debug)]
struct CapturePage<T, C> {
    rows: Vec<T>,
    has_more: bool,
    next_after: Option<C>,
}
#[derive(Debug)]
struct CapturedReputationSuccessorV1 {
    key: ReputationFinalizedArchiveKeyV1,
    finalized_at_unix_ms: u64,
    authority_policy: ReputationJournalAuthorityPolicyRecordV1,
    proof_outcomes: Vec<ProofOutcomeFinalizedEventV1>,
    journal_events: Vec<ReputationJournalFinalizedEventV1>,
    repair_events: Vec<RepairFinalizedEventV1>,
    orderbook_events: Vec<OrderbookFinalizedEventV1>,
    reserve_events: Vec<ReserveFinalizedEventV1>,
    reserve_providers: Vec<ReserveProviderAccountV1>,
}
#[derive(Debug)]
struct ProjectionCaptureBudget {
    charged_bytes: u64,
    maximum_bytes: u64,
}
impl ProjectionCaptureBudget {
    const fn new(maximum_bytes: u64) -> Self {
        Self {
            charged_bytes: 0,
            maximum_bytes,
        }
    }
    fn charge<T: norito::core::NoritoSerialize>(
        &mut self,
        source: &'static str,
        value: &T,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        let encoded = norito::to_bytes(value).map_err(ReputationFinalizedArchiveError::Encode)?;
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| {
            ReputationFinalizedArchiveError::ProjectionCaptureBudgetExceeded {
                projection: source,
                size: u64::MAX,
                maximum: self.maximum_bytes,
            }
        })?;
        self.charged_bytes = self.charged_bytes.checked_add(encoded_len).ok_or(
            ReputationFinalizedArchiveError::ProjectionCaptureBudgetExceeded {
                projection: source,
                size: u64::MAX,
                maximum: self.maximum_bytes,
            },
        )?;
        if self.charged_bytes > self.maximum_bytes {
            return Err(
                ReputationFinalizedArchiveError::ProjectionCaptureBudgetExceeded {
                    projection: source,
                    size: self.charged_bytes,
                    maximum: self.maximum_bytes,
                },
            );
        }
        Ok(())
    }
}
/// Durable exact-anchor SoraFS reputation projection archive.
#[derive(Debug)]
pub struct ReputationFinalizedArchive {
    root: PathBuf,
    anchors: PathBuf,
    checkpoints: PathBuf,
    policies: PathBuf,
    bounds: ReputationFinalizedArchiveBounds,
    root_identity: ArchiveFileIdentity,
    anchors_identity: ArchiveFileIdentity,
    checkpoints_identity: ArchiveFileIdentity,
    policies_identity: ArchiveFileIdentity,
    writer_lock_identity: ArchiveFileIdentity,
    writer_lock: fs::File,
    index: ArchiveIndexLock<ArchiveIndex>,
}
impl ReputationFinalizedArchive {
    /// Hold the actual archive reader while a component test attempts publication.
    #[cfg(test)]
    pub(crate) fn with_index_reader_for_testing<T>(
        &self,
        inspect: impl FnOnce() -> T,
    ) -> Result<T, ReputationFinalizedArchiveError> {
        let _reader = self.read_index()?;
        Ok(inspect())
    }

    /// Open or create a direct, bounded archive and validate every durable row.
    ///
    /// The supplied root must be a non-empty deployment-owned path. Existing
    /// symlinks, hard-linked records, unknown files, malformed Norito,
    /// conflicting finalized hashes, and exceeded bounds fail startup.
    ///
    /// # Errors
    ///
    /// Returns a typed storage, decode, validation, or resource error rather
    /// than accepting a partially qualified archive.
    pub fn try_open(
        root: impl Into<PathBuf>,
        bounds: ReputationFinalizedArchiveBounds,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let archive = Self::open_unreconciled(root, bounds)?;
        if archive.read_index()?.checkpoint_count != 0 {
            return Err(ReputationFinalizedArchiveError::RetentionAuthorityRequired);
        }
        Ok(archive)
    }
    /// Open an archive whose retention state is sealed by `authority`.
    ///
    /// Startup installs or finishes only the exact checkpoint durably named by the authority's
    /// canonical CAS record. A checkpoint file without that approval is rejected without unlinking
    /// anchors, checkpoints, or policy artifacts. If CAS committed before local checkpoint
    /// publication, recovery deterministically reconstructs and publishes the approved bytes before
    /// cleanup.
    ///
    /// # Errors
    ///
    /// Rejects a missing, substituted, stale, test-marked, drifting,
    /// malformed, rolled-back, or equivocated authority; an unapproved
    /// checkpoint; a Kura/fence mismatch; or any ordinary archive-open failure.
    pub fn try_open_with_retention_authority(
        root: impl Into<PathBuf>,
        bounds: ReputationFinalizedArchiveBounds,
        network_id: &NetworkId,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
        authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        if state_ro.network_id() != network_id || !std::ptr::eq(state_ro.kura(), kura) {
            return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
                reason: "retention open State has a substituted network or Kura binding",
            });
        }
        assert_retention_authority_identity(binding, authority)?;
        let archive = Self::open_unreconciled(root, bounds)?;
        archive.recover_approved_retention(network_id, state_ro, kura, binding, authority)?;
        archive.verify_storage_boundaries()?;
        Ok(archive)
    }
    #[cfg(test)]
    fn try_open_unsealed_for_test(
        root: impl Into<PathBuf>,
        bounds: ReputationFinalizedArchiveBounds,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let archive = Self::open_unreconciled(root, bounds)?;
        let mut index = archive.scan_inventory()?;
        if archive.finish_checkpoint_cleanup(&index)? {
            index = archive.scan_inventory()?;
        }
        *archive.write_index()? = index;
        Ok(archive)
    }
    fn open_unreconciled(
        root: impl Into<PathBuf>,
        bounds: ReputationFinalizedArchiveBounds,
    ) -> Result<Self, ReputationFinalizedArchiveError> {
        let root = root.into();
        validate_archive_root_path(&root)?;
        create_direct_directory(&root)?;
        verify_absolute_directory_ancestry(&root)?;
        let root_identity = direct_archive_directory_identity(&root).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: root.clone(),
                source,
            }
        })?;
        let anchors = root.join(ANCHORS_DIRECTORY);
        create_direct_directory(&anchors)?;
        let anchors_identity = direct_archive_directory_identity(&anchors).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: anchors.clone(),
                source,
            }
        })?;
        let checkpoints = root.join(CHECKPOINTS_DIRECTORY);
        create_direct_directory(&checkpoints)?;
        let checkpoints_identity =
            direct_archive_directory_identity(&checkpoints).map_err(|source| {
                ReputationFinalizedArchiveError::Read {
                    path: checkpoints.clone(),
                    source,
                }
            })?;
        let policies = root.join(POLICIES_DIRECTORY);
        create_direct_directory(&policies)?;
        let policies_identity = direct_archive_directory_identity(&policies).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: policies.clone(),
                source,
            }
        })?;
        verify_archive_directory_identity(&root, root_identity).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: root.clone(),
                source,
            }
        })?;
        let writer_lock_path = root.join(WRITER_LOCK_FILE);
        let writer_lock = open_writer_lock_file(&writer_lock_path)?;
        let writer_lock_identity =
            archive_file_identity(&secure_file_metadata::from_file(&writer_lock).map_err(
                |source| ReputationFinalizedArchiveError::Read {
                    path: writer_lock_path.clone(),
                    source,
                },
            )?);
        acquire_writer_ownership(&writer_lock, &writer_lock_path)?;
        writer_lock
            .sync_all()
            .and_then(|()| sync_archive_directory(&root))
            .map_err(|source| ReputationFinalizedArchiveError::NamespaceSync {
                path: root.clone(),
                source,
            })?;
        let archive = Self {
            root,
            anchors,
            checkpoints,
            policies,
            bounds,
            root_identity,
            anchors_identity,
            checkpoints_identity,
            policies_identity,
            writer_lock_identity,
            writer_lock,
            index: ArchiveIndexLock::new(ArchiveIndex::default()),
        };
        archive.verify_storage_boundaries()?;
        archive.recover_staged_files()?;
        let index = archive.scan_inventory()?;
        *archive.write_index()? = index;
        Ok(archive)
    }
    fn recover_approved_retention(
        &self,
        network_id: &NetworkId,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
        authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        let checkpoint_candidates = self.load_checkpoint_candidates()?;
        if checkpoint_candidates.iter().any(|candidate| {
            &candidate.persisted.checkpoint.retention_floor.network_id != network_id
        }) {
            return Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint);
        }
        let approval = load_retention_approval(binding, authority, network_id)?;
        let Some(approval) = approval else {
            if !checkpoint_candidates.is_empty() {
                return Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint);
            }
            return Ok(());
        };
        validate_retention_approval_record(&approval, binding, network_id)?;
        validate_retention_checkpoint_candidate_inventory(
            &checkpoint_candidates,
            &approval,
            network_id,
        )?;
        let approved_candidate = checkpoint_candidates.iter().find(|candidate| {
            candidate.persisted.checkpoint_digest == approval.proposal().checkpoint_digest()
        });
        let mut index = self.write_index()?;
        self.verify_storage_boundaries()?;
        if let Some(candidate) = approved_candidate {
            validate_approval_checkpoint(&approval, &candidate.persisted, self.bounds)?;
            let expected_generation = approval
                .proposal()
                .fence()
                .expected_generation()
                .checked_add(1)
                .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                    reason: "approved archive generation overflowed",
                })?;
            if active_checkpoint_digest(&index, network_id)
                != Some(approval.proposal().checkpoint_digest())
                || index.generation < expected_generation
            {
                return Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint);
            }
            // Approval freezes the compaction, not subsequent committed captures.
            // Accept later generations only with this exact approved checkpoint
            // and a contiguous, Kura-authenticated retained successor chain.
            let coverage = authenticate_approval_checkpoint_against_certified(
                &candidate.persisted,
                &index,
                state_ro,
                kura,
            )?;
            require_exact_retention_readback(binding, authority, network_id, &approval)?;
            if coverage == ApprovedCheckpointCoverage::AwaitingCapture {
                // A crash after Kura commits but before archive capture and a
                // lost trailing suffix have the same local shape. Preserve
                // recovery evidence until authenticated capture restores full
                // coverage; opening a handle does not qualify a lagging archive.
                return Ok(());
            }
            if let Err(error) = self.finish_checkpoint_cleanup(&index) {
                self.reconcile_checkpoint_index(&mut index)?;
                return Err(error);
            }
            self.reconcile_checkpoint_index(&mut index)?;
            require_exact_retention_readback(binding, authority, network_id, &approval)?;
            return Ok(());
        }
        if active_checkpoint_digest(&index, network_id) != approval.predecessor_checkpoint_digest()
            || index.generation != approval.proposal().fence().expected_generation()
        {
            return Err(ReputationFinalizedArchiveError::RetentionAuthorityRollback);
        }
        let prepared =
            self.prepare_compaction_locked(&index, approval.proposal().fence(), state_ro, kura)?;
        if compaction_proposal(&prepared, approval.proposal().fence())? != *approval.proposal() {
            return Err(ReputationFinalizedArchiveError::RetentionProposalMismatch);
        }
        validate_approval_for_prepared(
            &approval,
            binding,
            &prepared,
            approval.proposal(),
            approval.predecessor_checkpoint_digest(),
        )?;
        require_exact_retention_readback(binding, authority, network_id, &approval)?;
        let _recovered = self.publish_prepared_compaction(&mut index, prepared, || {
            require_exact_retention_readback(binding, authority, network_id, &approval)
        })?;
        Ok(())
    }
    fn load_checkpoint_candidates(
        &self,
    ) -> Result<Vec<CheckpointIndexEntry>, ReputationFinalizedArchiveError> {
        self.verify_storage_boundaries()?;
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&self.checkpoints).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            }
        })? {
            let entry = entry.map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            })?;
            if candidates.len() >= self.bounds.max_entries.get() {
                return Err(ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                    maximum_entries: self.bounds.max_entries.get(),
                });
            }
            let path = entry.path();
            let name = entry.file_name();
            let name =
                name.to_str()
                    .ok_or_else(|| ReputationFinalizedArchiveError::InvalidStorage {
                        path: path.clone(),
                        reason: "archive checkpoint filename is not UTF-8",
                    })?;
            if name.starts_with(STAGED_FILE_PREFIX)
                || !is_canonical_digest_file_name(name, CHECKPOINT_FILE_SUFFIX)
            {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path,
                    reason: "unknown file in finalized reputation checkpoint archive",
                });
            }
            candidates.push(CheckpointIndexEntry {
                persisted: self.load_checkpoint_at(&path, None)?,
                path,
            });
        }
        candidates.sort_by(|left, right| {
            (
                &left.persisted.checkpoint.retention_floor.network_id,
                left.persisted.checkpoint.checkpoint_generation,
                left.persisted.checkpoint.retention_floor.height,
                left.persisted.checkpoint_digest,
            )
                .cmp(&(
                    &right.persisted.checkpoint.retention_floor.network_id,
                    right.persisted.checkpoint.checkpoint_generation,
                    right.persisted.checkpoint.retention_floor.height,
                    right.persisted.checkpoint_digest,
                ))
        });
        self.verify_storage_boundaries()?;
        Ok(candidates)
    }
    /// Return the archive resource policy.
    #[must_use]
    pub const fn bounds(&self) -> ReputationFinalizedArchiveBounds {
        self.bounds
    }
    /// Return the deployment-owned archive root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Return the deterministic path for one exact key.
    ///
    /// # Errors
    ///
    /// Rejects malformed keys or a canonical key encoding failure.
    pub fn record_path(
        &self,
        key: &ReputationFinalizedArchiveKeyV1,
    ) -> Result<PathBuf, ReputationFinalizedArchiveError> {
        key.validate()?;
        Ok(self.anchors.join(anchor_file_name(key)?))
    }
    /// Capture one exact immutable state view authenticated by Kura finality.
    ///
    /// The caller must invoke this while the supplied committed view is frozen and its canonical
    /// Kura block and embedded commit certificate are durable. Every native query page is pinned to the
    /// exact certified height and hash; no current-head or broadcast-event fallback is available.
    ///
    /// If this is the first anchor for a non-genesis height, that height is the archive's explicit
    /// activation floor. The archive does not claim to contain earlier provider-state projections
    /// even though append-only event journals in the first record may begin before the floor.
    ///
    /// # Errors
    ///
    /// Fails closed when Kura, the immutable view, any typed query page, or the deterministic block
    /// timestamp disagrees with the current certified block. Query collection is bounded by the
    /// configured aggregate archive byte ceiling before immutable insertion is attempted.
    pub fn capture_certified_view(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<ReputationFinalizedArchiveInsertOutcome, ReputationFinalizedArchiveError> {
        let (key, finalized_at_unix_ms) = candidate_capture_key(state_ro, kura)?;
        let certified =
            CertifiedArchiveView::new(state_ro, kura).map_err(certified_finality_error)?;
        authenticate_archive_anchor_against_certified(&key, finalized_at_unix_ms, &certified)?;
        let mut insertion = self.prepare_capture_at_key(state_ro, key, finalized_at_unix_ms)?;
        certified
            .verify_unchanged()
            .map_err(certified_finality_error)?;
        insertion.persist()
    }
    fn prepare_capture_at_key(
        &self,
        state_ro: &impl StateReadOnly,
        key: ReputationFinalizedArchiveKeyV1,
        finalized_at_unix_ms: u64,
    ) -> Result<PreparedReputationInsertion<'_>, ReputationFinalizedArchiveError> {
        // Never wait for an archive reader while retaining a committed State view. The executor
        // retains this exact capture boundary and retries after the returned owner-release event.
        let index = self
            .index
            .try_write()
            .map_err(|error| self.index_lock_error(error))?;
        if index.requires_reopen {
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            });
        }
        self.verify_storage_boundaries()?;
        require_contiguous_capture_key_in_index(&index, &key)?;
        let previous = key
            .height
            .checked_sub(1)
            .map(|maximum_height| {
                self.latest_reconstruction_state_at_or_before_in_index(
                    &index,
                    &key.network_id,
                    maximum_height,
                )
            })
            .transpose()?
            .flatten();
        let captured = self.capture_original_successor(
            state_ro,
            key,
            finalized_at_unix_ms,
            previous.as_ref(),
        )?;
        let material = self.prepare_captured_material(
            &index,
            &captured.next_state,
            &captured.authority_policy_history,
        )?;
        Ok(PreparedReputationInsertion {
            archive: self,
            index,
            key: captured.next_state.key.clone(),
            state: material.map(|material| material.finish(captured.next_state)),
        })
    }

    fn capture_original_successor(
        &self,
        state_ro: &impl StateReadOnly,
        key: ReputationFinalizedArchiveKeyV1,
        finalized_at_unix_ms: u64,
        previous: Option<&ReputationReconstructionStateV1>,
    ) -> Result<CapturedReputationCandidate, ReputationFinalizedArchiveError> {
        let mut budget = ProjectionCaptureBudget::new(self.bounds.max_total_bytes);
        let authority_policy = FindSorafsReputationJournalAuthorityPolicy
            .execute(state_ro)
            .map_err(|error| projection_query_error("reputation authority policy", error))?;
        budget.charge("reputation authority policy", &authority_policy)?;
        let authority_policy_history =
            crate::smartcontracts::isi::sorafs_reputation::read_reputation_authority_policy_history(
                state_ro.world(),
                MAX_AUTHORITY_POLICY_REVISIONS_V1,
            )
            .map_err(|error| ReputationFinalizedArchiveError::ProjectionCaptureQuery {
                projection: "reputation authority policy history",
                detail: error.to_string(),
            })?;
        budget.charge(
            "reputation authority policy history",
            &authority_policy_history,
        )?;
        validate_authority_policy_history(
            &authority_policy_history,
            &authority_policy,
            finalized_at_unix_ms,
        )?;
        let proof_cursor = ProofOutcomeFinalizedCursorV1 {
            height: key.height,
            block_hash: key.block_hash,
        };
        let proof_after = previous.and_then(|state| {
            retained_capture_cursor(
                &state.proof_outcomes,
                ProofOutcomeFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::proof_ledger::ProofOutcomeFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            )
        });
        let proof_suffix = collect_capture_pages(
            "proof-outcome events",
            proof_after,
            &mut budget,
            |after| {
                let page = FindSorafsProofOutcomeEvents {
                    expected_finalized_cursor: Some(proof_cursor),
                    after,
                    limit: u32::try_from(PROOF_OUTCOME_QUERY_MAX_ITEMS_V1)
                        .expect("proof-outcome query maximum fits u32"),
                }
                .execute(state_ro)
                .map_err(|error| projection_query_error("proof-outcome events", error))?;
                if page.finalized_cursor != proof_cursor {
                    return Err(projection_anchor_error("proof-outcome events"));
                }
                Ok(CapturePage {
                    rows: page.events,
                    has_more: page.has_more,
                    next_after: page.next_after,
                })
            },
            ProofOutcomeFinalizedEventV1::cursor,
        )?;
        let journal_cursor = ReputationJournalFinalizedCursorV1 {
            height: key.height,
            block_hash: key.block_hash,
            finalized_at_unix_ms,
        };
        let journal_after = previous.and_then(|state| {
            retained_capture_cursor(
                &state.journal_events,
                ReputationJournalFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            )
        });
        let journal_suffix = collect_capture_pages(
            "reputation journal events",
            journal_after,
            &mut budget,
            |after| {
                let page = FindSorafsReputationJournalEvents {
                    expected_finalized_cursor: Some(journal_cursor),
                    after,
                    limit: u32::try_from(REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1)
                        .expect("reputation journal query maximum fits u32"),
                }
                .execute(state_ro)
                .map_err(|error| projection_query_error("reputation journal events", error))?;
                if page.finalized_cursor != journal_cursor {
                    return Err(projection_anchor_error("reputation journal events"));
                }
                Ok(CapturePage {
                    rows: page.events,
                    has_more: page.has_more,
                    next_after: page.next_after,
                })
            },
            ReputationJournalFinalizedEventV1::cursor,
        )?;
        let repair_cursor = RepairFinalizedCursorV1 {
            height: key.height,
            block_hash: key.block_hash,
        };
        let repair_after = previous.and_then(|state| {
            retained_capture_cursor(
                &state.repair_events,
                RepairFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::moderation_ledger::RepairFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            )
        });
        let repair_suffix = collect_capture_pages(
            "repair events",
            repair_after,
            &mut budget,
            |after| {
                let page = FindSorafsRepairEvents {
                    expected_finalized_cursor: Some(repair_cursor),
                    after,
                    limit: REPAIR_QUERY_MAX_ITEMS_V1,
                }
                .execute(state_ro)
                .map_err(|error| projection_query_error("repair events", error))?;
                if page.finalized_cursor != repair_cursor {
                    return Err(projection_anchor_error("repair events"));
                }
                Ok(CapturePage {
                    rows: page.events,
                    has_more: page.has_more,
                    next_after: page.next_after,
                })
            },
            RepairFinalizedEventV1::cursor,
        )?;
        let orderbook_cursor = OrderbookFinalizedCursorV1 {
            height: key.height,
            block_hash: key.block_hash,
        };
        let orderbook_after = previous.and_then(|state| {
            retained_capture_cursor(
                &state.orderbook_events,
                OrderbookFinalizedEventV1::cursor,
                |position| iroha_data_model::sorafs::orderbook::OrderbookFinalizedEventCursorV1 {
                    sequence: position.sequence,
                    block_height: position.block_height,
                    block_hash: position.block_hash,
                    event_index: position.event_index,
                },
            )
        });
        let orderbook_suffix = collect_capture_pages(
            "orderbook events",
            orderbook_after,
            &mut budget,
            |after| {
                let page = FindSorafsOrderbookEvents {
                    expected_finalized_cursor: Some(orderbook_cursor),
                    after,
                    limit: ORDERBOOK_QUERY_MAX_ITEMS_V1,
                }
                .execute(state_ro)
                .map_err(|error| projection_query_error("orderbook events", error))?;
                if page.finalized_cursor != orderbook_cursor {
                    return Err(projection_anchor_error("orderbook events"));
                }
                Ok(CapturePage {
                    rows: page.events,
                    has_more: page.has_more,
                    next_after: page.next_after,
                })
            },
            OrderbookFinalizedEventV1::cursor,
        )?;
        let reserve_cursor = ReserveFinalizedCursorV1 {
            height: key.height,
            block_hash: key.block_hash,
        };
        let reserve_after = previous.and_then(|state| {
            retained_capture_cursor(
                &state.reserve_events,
                ReserveFinalizedEventV1::cursor,
                |position| iroha_data_model::sorafs::reserve::ReserveFinalizedEventCursorV1 {
                    sequence: position.sequence,
                    block_height: position.block_height,
                    block_hash: position.block_hash,
                    event_index: position.event_index,
                },
            )
        });
        let reserve_suffix = collect_capture_pages(
            "reserve events",
            reserve_after,
            &mut budget,
            |after| {
                let page = FindSorafsReserveEvents {
                    expected_finalized_cursor: Some(reserve_cursor),
                    after,
                    limit: RESERVE_QUERY_MAX_ITEMS_V1,
                }
                .execute(state_ro)
                .map_err(|error| projection_query_error("reserve events", error))?;
                if page.finalized_cursor != reserve_cursor {
                    return Err(projection_anchor_error("reserve events"));
                }
                Ok(CapturePage {
                    rows: page.events,
                    has_more: page.has_more,
                    next_after: page.next_after,
                })
            },
            ReserveFinalizedEventV1::cursor,
        )?;
        let reserve_providers = collect_capture_pages(
            "reserve providers",
            None,
            &mut budget,
            |after_provider_id| {
                let page = FindSorafsReserveProviders {
                    expected_finalized_cursor: Some(reserve_cursor),
                    after_provider_id,
                    limit: RESERVE_QUERY_MAX_ITEMS_V1,
                }
                .execute(state_ro)
                .map_err(|error| projection_query_error("reserve providers", error))?;
                if page.finalized_cursor != reserve_cursor {
                    return Err(projection_anchor_error("reserve providers"));
                }
                Ok(CapturePage {
                    rows: page.accounts,
                    has_more: page.has_more,
                    next_after: page.next_after,
                })
            },
            |account: &ReserveProviderAccountV1| account.terms.provider_id,
        )?;
        let next_state = build_captured_successor_state(
            previous,
            CapturedReputationSuccessorV1 {
                key,
                finalized_at_unix_ms,
                authority_policy,
                proof_outcomes: proof_suffix,
                journal_events: journal_suffix,
                repair_events: repair_suffix,
                orderbook_events: orderbook_suffix,
                reserve_events: reserve_suffix,
                reserve_providers,
            },
            &authority_policy_history,
        )?;
        Ok(CapturedReputationCandidate {
            next_state,
            authority_policy_history,
        })
    }
    /// Capture and then qualify one frozen state view against the exact Kura tip.
    ///
    /// An empty archive is allowed to establish an explicit activation floor at this view. A
    /// non-empty archive must already contain every height from its activation floor through the
    /// captured key; no current-tip write can conceal a missed historical capture. The returned
    /// flag makes a new non-genesis floor visible to the launcher, which must not advertise earlier
    /// history.
    ///
    /// # Errors
    ///
    /// Returns the same fail-closed authentication, query, storage, coverage,
    /// or Kura-lag errors as capture and qualification.
    pub fn reconcile_certified_state_tip(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<ReputationFinalizedArchiveReconcileOutcomeV1, ReputationFinalizedArchiveError> {
        let activation_floor_before = self.activation_floor(state_ro.network_id())?;
        let insertion = self.capture_certified_view(state_ro, kura)?;
        // Startup/recovery reconciliation is exact. The configured suffix-lag
        // allowance is solely a live health window and must never qualify an
        // incomplete startup image.
        let qualification = self.qualify_against_certified_tip(state_ro, kura, 0)?;
        Ok(ReputationFinalizedArchiveReconcileOutcomeV1 {
            insertion,
            qualification,
            activation_floor_created: activation_floor_before.is_none(),
        })
    }
    /// Qualify exact contiguous archive coverage against one Kura boundary.
    ///
    /// Every archive anchor from the explicit activation floor through the archive tip must be
    /// present at every height, match Kura's authenticated hash journal and embedded commit certificate,
    /// and retain the exact canonical block timestamp. Only a suffix no larger than
    /// `maximum_kura_tip_lag_blocks` may remain between the archive and Kura tips. Kura, the
    /// archive generation, and the active checkpoint content address are re-read before success so
    /// a changing boundary never receives a mixed qualification.
    ///
    /// # Errors
    ///
    /// Fails closed for an empty archive, a coverage hole, a missing block body
    /// or commit certificate, a timestamp/hash/chain mismatch, excess lag, or a
    /// concurrent Kura/archive boundary change.
    pub fn qualify_against_certified_tip(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        maximum_kura_tip_lag_blocks: u64,
    ) -> Result<ReputationFinalizedArchiveQualificationV1, ReputationFinalizedArchiveError> {
        let network_id = state_ro.network_id();
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        let generation = self.health_generation()?;
        let (anchors, activation_floor, checkpoint_digest, checkpoint_finality_digest) = {
            let index = self.read_index()?;
            self.verify_storage_boundaries()?;
            let mut anchors = index
                .by_height
                .range((
                    std::ops::Bound::Included((network_id.clone(), 0)),
                    std::ops::Bound::Included((network_id.clone(), u64::MAX)),
                ))
                .map(|(_, entry)| {
                    (
                        entry.manifest.key.clone(),
                        entry.manifest.finalized_at_unix_ms,
                    )
                })
                .collect::<Vec<_>>();
            let activation_floor = if let Some(checkpoint) = index.checkpoints.get(network_id) {
                let material = &checkpoint.persisted.checkpoint;
                anchors.insert(
                    0,
                    (
                        material.retention_floor.clone(),
                        material.retention_floor_finalized_at_unix_ms,
                    ),
                );
                material.original_activation_floor.clone()
            } else {
                anchors.first().map(|(key, _)| key.clone()).ok_or(
                    ReputationFinalizedArchiveError::ArchiveUnavailable {
                        reason: "no exact anchor exists for the requested chain",
                    },
                )?
            };
            let checkpoint_finality_digest = index
                .checkpoints
                .get(network_id)
                .map(|checkpoint| checkpoint.persisted.checkpoint.certified_block_id);
            (
                anchors,
                activation_floor,
                active_checkpoint_digest(&index, network_id),
                checkpoint_finality_digest,
            )
        };
        validate_contiguous_archive_coverage(network_id, &anchors)?;
        let archive_tip = anchors
            .last()
            .map(|(key, _)| key.clone())
            .expect("non-empty archive coverage has a tip");
        let certified =
            CertifiedArchiveView::new(state_ro, kura).map_err(certified_finality_error)?;
        if archive_tip.height > certified.tip_height() {
            return Err(ReputationFinalizedArchiveError::ArchiveAheadOfKura {
                archive_height: archive_tip.height,
                kura_height: certified.tip_height(),
            });
        }
        let lag_blocks = certified.tip_height() - archive_tip.height;
        if lag_blocks > maximum_kura_tip_lag_blocks {
            return Err(ReputationFinalizedArchiveError::ArchiveKuraTipLagExceeded {
                archive_height: archive_tip.height,
                kura_height: certified.tip_height(),
                lag: lag_blocks,
                maximum: maximum_kura_tip_lag_blocks,
            });
        }
        for (key, finalized_at_unix_ms) in &anchors {
            authenticate_archive_anchor_against_certified(key, *finalized_at_unix_ms, &certified)?;
        }
        if let Some(expected_digest) = checkpoint_finality_digest {
            let checkpoint_height = anchors
                .first()
                .expect("checkpoint qualification has a virtual-base anchor")
                .0
                .height;
            if *certified
                .block(checkpoint_height)
                .map_err(certified_finality_error)?
                .id()
                .0
                .as_ref()
                != expected_digest
            {
                return Err(ReputationFinalizedArchiveError::ArchiveKuraAnchorMismatch {
                    network_id: network_id.clone(),
                    height: checkpoint_height,
                    reason: "virtual-base certified block identity changed",
                });
            }
        }
        certified
            .verify_unchanged()
            .map_err(certified_finality_error)?;
        let index = self.read_index()?;
        self.verify_synchronized_index(&index)?;
        validate_qualification_archive_boundary(&index, network_id, generation, checkpoint_digest)?;
        let qualification = ReputationFinalizedArchiveQualificationV1 {
            activation_floor,
            archive_tip,
            checkpoint_digest,
            kura_tip_height: certified.tip_height(),
            lag_blocks,
            generation,
        };
        drop(index);
        Ok(qualification)
    }
    /// Return the first immutable anchor captured for `network_id`.
    ///
    /// This key is the explicit historical activation floor. Exact queries
    /// below it must remain unavailable unless a separate authenticated replay
    /// backfills every missing height before production activation.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed archive integrity error.
    pub fn activation_floor(
        &self,
        network_id: &NetworkId,
    ) -> Result<Option<ReputationFinalizedArchiveKeyV1>, ReputationFinalizedArchiveError> {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        if let Some(checkpoint) = index.checkpoints.get(network_id) {
            return Ok(Some(
                checkpoint
                    .persisted
                    .checkpoint
                    .original_activation_floor
                    .clone(),
            ));
        }
        Ok(index
            .by_height
            .range((
                std::ops::Bound::Included((network_id.clone(), 0)),
                std::ops::Bound::Included((network_id.clone(), u64::MAX)),
            ))
            .next()
            .map(|(_, entry)| entry.manifest.key.clone()))
    }
    /// Return the active virtual-base retention floor, if compaction occurred.
    ///
    /// # Errors
    ///
    /// Rejects an empty chain identifier or a substituted archive namespace.
    pub fn retention_floor(
        &self,
        network_id: &NetworkId,
    ) -> Result<Option<ReputationFinalizedArchiveKeyV1>, ReputationFinalizedArchiveError> {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        Ok(index
            .checkpoints
            .get(network_id)
            .map(|checkpoint| checkpoint.persisted.checkpoint.retention_floor.clone()))
    }
    #[cfg(test)]
    fn latest_reconstruction_state_at_or_before(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> Result<Option<ReputationReconstructionStateV1>, ReputationFinalizedArchiveError> {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        let index = self.read_index()?;
        self.latest_reconstruction_state_at_or_before_in_index(&index, network_id, maximum_height)
    }

    fn latest_reconstruction_state_at_or_before_in_index(
        &self,
        index: &ArchiveIndex,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> Result<Option<ReputationReconstructionStateV1>, ReputationFinalizedArchiveError> {
        self.verify_storage_boundaries()?;
        if let Some(entry) = index
            .by_height
            .range((
                std::ops::Bound::Included((network_id.clone(), 0)),
                std::ops::Bound::Included((network_id.clone(), maximum_height)),
            ))
            .next_back()
            .map(|(_, entry)| entry)
        {
            return self.reconstruct_state(index, entry).map(Some);
        }
        if let Some(checkpoint) = index.checkpoints.get(network_id) {
            let checkpoint = &checkpoint.persisted.checkpoint;
            if checkpoint.retention_floor.height <= maximum_height {
                return ReputationReconstructionStateV1::from_checkpoint(checkpoint).map(Some);
            }
            return Err(history_pruned_error(checkpoint));
        }
        Ok(None)
    }
    #[cfg(test)]
    fn require_contiguous_capture_key(
        &self,
        key: &ReputationFinalizedArchiveKeyV1,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        require_contiguous_capture_key_in_index(&index, key)
    }
    /// Durably publish one immutable exact-anchor projection.
    ///
    /// The operation derives an immutable suffix from the latest exact predecessor, publishes any
    /// new content-addressed policy, then publishes the anchor manifest and delta without
    /// clobbering. An identical existing projection is an exact replay.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, capacity, conflict, I/O, or durability
    /// failure. Existing records are never overwritten.
    pub fn insert(
        &self,
        projection: ReputationFinalizedProjectionV1,
    ) -> Result<ReputationFinalizedArchiveInsertOutcome, ReputationFinalizedArchiveError> {
        self.prepare_insert(projection)?.persist()
    }
    fn prepare_insert(
        &self,
        projection: ReputationFinalizedProjectionV1,
    ) -> Result<PreparedReputationInsertion<'_>, ReputationFinalizedArchiveError> {
        projection.validate()?;
        let index = self.write_index()?;
        self.verify_storage_boundaries()?;
        let authority_policy_history = resolve_authority_policy_history(
            &index,
            &projection.authority_policy,
            projection.finalized_at_unix_ms,
        )?;
        let subject = (projection.key.network_id.clone(), projection.key.height);
        if let Some(existing) = index.by_height.get(&subject).cloned() {
            if existing.manifest.key.block_hash != projection.key.block_hash {
                return Err(ReputationFinalizedArchiveError::FinalizedFork {
                    network_id: projection.key.network_id.clone(),
                    height: projection.key.height,
                });
            }
            if self.reconstruct_projection(&index, &existing)? == projection {
                return Ok(PreparedReputationInsertion {
                    archive: self,
                    index,
                    key: projection.key,
                    state: None,
                });
            }
            return Err(ReputationFinalizedArchiveError::ConflictingProjection {
                network_id: projection.key.network_id.clone(),
                height: projection.key.height,
                block_hash: projection.key.block_hash,
            });
        }
        let predecessor = index.latest_state.get(&projection.key.network_id).cloned();
        if let Some(previous) = &predecessor {
            if projection.key.height <= previous.key.height {
                return Err(ReputationFinalizedArchiveError::OutOfOrderAnchor {
                    network_id: projection.key.network_id.clone(),
                    height: projection.key.height,
                    latest_height: previous.key.height,
                });
            }
            validate_projection_transition_from_state(
                previous,
                &projection,
                &authority_policy_history,
            )?;
        }
        validate_projection_against_index(&projection, &index)?;
        let delta = build_anchor_delta_from_state(
            predecessor.as_ref(),
            &projection,
            &authority_policy_history,
        )?;
        let next_state = reconstruction_state_from_full_successor(
            predecessor.as_ref(),
            &projection,
            &authority_policy_history,
        )?;
        self.prepare_new_state(
            index,
            predecessor.as_ref(),
            next_state,
            authority_policy_history,
            delta,
        )
    }
    #[cfg(test)]
    fn insert_captured_state(
        &self,
        next_state: ReputationReconstructionStateV1,
        authority_policy_history: Vec<ReputationJournalAuthorityPolicyRecordV1>,
    ) -> Result<ReputationFinalizedArchiveInsertOutcome, ReputationFinalizedArchiveError> {
        self.prepare_captured_state(next_state, authority_policy_history)?
            .persist()
    }
    #[cfg(test)]
    fn prepare_captured_state(
        &self,
        next_state: ReputationReconstructionStateV1,
        authority_policy_history: Vec<ReputationJournalAuthorityPolicyRecordV1>,
    ) -> Result<PreparedReputationInsertion<'_>, ReputationFinalizedArchiveError> {
        let index = self.write_index()?;
        let material =
            self.prepare_captured_material(&index, &next_state, &authority_policy_history)?;
        Ok(PreparedReputationInsertion {
            archive: self,
            index,
            key: next_state.key.clone(),
            state: material.map(|material| material.finish(next_state)),
        })
    }

    fn prepare_captured_material(
        &self,
        index: &ArchiveIndex,
        next_state: &ReputationReconstructionStateV1,
        authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
    ) -> Result<Option<PreparedReputationMaterial>, ReputationFinalizedArchiveError> {
        next_state.validate()?;
        validate_authority_policy_history(
            authority_policy_history,
            &next_state.authority_policy,
            next_state.finalized_at_unix_ms,
        )?;
        self.verify_storage_boundaries()?;
        require_contiguous_capture_key_in_index(index, &next_state.key)?;
        let subject = (next_state.key.network_id.clone(), next_state.key.height);
        if let Some(existing) = index.by_height.get(&subject).cloned() {
            if existing.manifest.key.block_hash != next_state.key.block_hash {
                return Err(ReputationFinalizedArchiveError::FinalizedFork {
                    network_id: next_state.key.network_id.clone(),
                    height: next_state.key.height,
                });
            }
            if self.reconstruct_state(index, &existing)? == *next_state
                && resolve_authority_policy_history(
                    index,
                    &next_state.authority_policy,
                    next_state.finalized_at_unix_ms,
                )? == authority_policy_history
            {
                return Ok(None);
            }
            return Err(ReputationFinalizedArchiveError::ConflictingProjection {
                network_id: next_state.key.network_id.clone(),
                height: next_state.key.height,
                block_hash: next_state.key.block_hash,
            });
        }
        let predecessor = index.latest_state.get(&next_state.key.network_id).cloned();
        if let Some(previous) = &predecessor {
            if next_state.key.height <= previous.key.height {
                return Err(ReputationFinalizedArchiveError::OutOfOrderAnchor {
                    network_id: next_state.key.network_id.clone(),
                    height: next_state.key.height,
                    latest_height: previous.key.height,
                });
            }
            validate_reconstruction_state_transition(
                previous,
                next_state,
                authority_policy_history,
            )?;
        }
        validate_reconstruction_state_against_index(next_state, index)?;
        let delta = build_anchor_delta_from_reconstruction_state(predecessor.as_ref(), next_state)?;
        self.prepare_new_state_material(
            index,
            predecessor.as_ref(),
            next_state,
            authority_policy_history,
            delta,
        )
        .map(Some)
    }
    fn prepare_new_state<'archive>(
        &'archive self,
        index: ArchiveIndexWriteGuard<'archive, ArchiveIndex>,
        predecessor: Option<&ReputationReconstructionStateV1>,
        next_state: ReputationReconstructionStateV1,
        authority_policy_history: Vec<ReputationJournalAuthorityPolicyRecordV1>,
        delta: ReputationFinalizedAnchorDeltaV1,
    ) -> Result<PreparedReputationInsertion<'archive>, ReputationFinalizedArchiveError> {
        let material = self.prepare_new_state_material(
            &index,
            predecessor,
            &next_state,
            &authority_policy_history,
            delta,
        )?;
        Ok(PreparedReputationInsertion {
            archive: self,
            index,
            key: next_state.key.clone(),
            state: Some(material.finish(next_state)),
        })
    }

    fn prepare_new_state_material(
        &self,
        index: &ArchiveIndex,
        predecessor: Option<&ReputationReconstructionStateV1>,
        next_state: &ReputationReconstructionStateV1,
        authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
        delta: ReputationFinalizedAnchorDeltaV1,
    ) -> Result<PreparedReputationMaterial, ReputationFinalizedArchiveError> {
        validate_authority_policy_history(
            authority_policy_history,
            &next_state.authority_policy,
            next_state.finalized_at_unix_ms,
        )?;
        let authority_policy_history_digest =
            authority_policy_history_digest(authority_policy_history)?;
        let persisted_policies = authority_policy_history
            .iter()
            .cloned()
            .map(PersistedReputationAuthorityPolicyV1::try_new)
            .collect::<Result<Vec<_>, _>>()?;
        let active_policy_record_digest = persisted_policies
            .last()
            .map(|policy| policy.record_digest)
            .ok_or(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy history is empty",
            })?;
        let predecessor_anchor_digest = index
            .by_height
            .range((
                std::ops::Bound::Included((next_state.key.network_id.clone(), 0)),
                std::ops::Bound::Included((next_state.key.network_id.clone(), u64::MAX)),
            ))
            .next_back()
            .map(|(_, entry)| entry.anchor_digest)
            .or_else(|| {
                index
                    .checkpoints
                    .get(&next_state.key.network_id)
                    .map(|checkpoint| {
                        checkpoint
                            .persisted
                            .checkpoint
                            .retention_floor_anchor_digest
                    })
            });
        if predecessor.is_some() != predecessor_anchor_digest.is_some() {
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: "latest projection and exact anchor digest disagree",
            });
        }
        let (_, journal_source_head_count, journal_source_head_root) =
            journal_source_head_commitment(
                &next_state.journal_prefix_source_heads,
                &next_state.journal_events.retained_suffix,
            )?;
        let manifest = ReputationFinalizedAnchorManifestV1 {
            key: next_state.key.clone(),
            predecessor: predecessor.map(|previous| previous.key.clone()),
            predecessor_anchor_digest,
            finalized_at_unix_ms: next_state.finalized_at_unix_ms,
            policy_record_digest: active_policy_record_digest,
            authority_policy_history_digest,
            high_water_marks: next_state.high_water_marks()?,
            journal_source_head_count,
            journal_source_head_root,
            reserve_provider_count: bounded_len(next_state.reserve_providers.len())?,
            reserve_provider_state_root: reserve_provider_state_root(
                &next_state.reserve_providers,
            )?,
        };
        let persisted_anchor = PersistedReputationFinalizedAnchorV1::try_new(manifest, delta)?;
        let anchor_digest = persisted_anchor.anchor_digest()?;
        let anchor_bytes = encode_bounded_artifact(&persisted_anchor, self.bounds)?;
        let anchor_bytes_len = bounded_bytes_len(&anchor_bytes);
        let mut prepared_policies = Vec::with_capacity(persisted_policies.len());
        let mut added_policy_count = 0_usize;
        let mut added_policy_bytes = 0_u64;
        let mut policy_count = index.policy_count;
        let mut policy_total_bytes = index.total_bytes;
        for persisted_policy in persisted_policies {
            if let Some((_, existing)) =
                policy_record_by_policy_digest(index, persisted_policy.record.policy_digest)?
                && existing != &persisted_policy.record
            {
                return Err(ReputationFinalizedArchiveError::PolicyConflict {
                    digest: persisted_policy.record.policy_digest,
                });
            }
            let policy_bytes = encode_bounded_artifact(&persisted_policy, self.bounds)?;
            let policy_is_new = !index.policies.contains_key(&persisted_policy.record_digest);
            if policy_is_new {
                added_policy_count = added_policy_count.checked_add(1).ok_or(
                    ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                        maximum_entries: self.bounds.max_entries.get(),
                    },
                )?;
                added_policy_bytes = added_policy_bytes
                    .checked_add(bounded_bytes_len(&policy_bytes))
                    .ok_or(ReputationFinalizedArchiveError::ArchiveBytesExceeded {
                        size: u64::MAX,
                        maximum: self.bounds.max_total_bytes,
                    })?;
            }
            let accounting = if policy_is_new {
                policy_count = policy_count.checked_add(1).ok_or(
                    ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                        maximum_entries: self.bounds.max_entries.get(),
                    },
                )?;
                policy_total_bytes = policy_total_bytes
                    .checked_add(bounded_bytes_len(&policy_bytes))
                    .ok_or(ReputationFinalizedArchiveError::ArchiveBytesExceeded {
                        size: u64::MAX,
                        maximum: self.bounds.max_total_bytes,
                    })?;
                Some((policy_count, policy_total_bytes))
            } else {
                None
            };
            prepared_policies.push(PreparedReputationPolicy {
                path: self
                    .policies
                    .join(policy_file_name(persisted_policy.record_digest)),
                persisted: persisted_policy,
                bytes: policy_bytes,
                accounting,
            });
        }
        ensure_insert_capacity(
            index,
            self.bounds,
            anchor_bytes_len,
            added_policy_count,
            added_policy_bytes,
        )?;
        let next_generation = index.generation.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::RetentionRequired {
                proposed_entries: usize::MAX,
                maximum_entries: self.bounds.max_entries.get(),
                proposed_policy_entries: index.policy_count,
                maximum_policy_entries: self.bounds.max_entries.get(),
                proposed_bytes: u64::MAX,
                maximum_bytes: self.bounds.max_total_bytes,
            },
        )?;
        let total_bytes = policy_total_bytes.checked_add(anchor_bytes_len).ok_or(
            ReputationFinalizedArchiveError::ArchiveBytesExceeded {
                size: u64::MAX,
                maximum: self.bounds.max_total_bytes,
            },
        )?;
        let anchor_count = index.anchor_count.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                maximum_entries: self.bounds.max_entries.get(),
            },
        )?;
        let anchor_path = self.record_path(&next_state.key)?;
        // A compacted feed has no full projection; that is an admitted representation choice.
        let full_projection = next_state.full_projection().ok();
        Ok(PreparedReputationMaterial {
            policies: prepared_policies,
            anchor: persisted_anchor,
            anchor_digest,
            anchor_bytes,
            anchor_path,
            full_projection,
            total_bytes,
            anchor_count,
            generation: next_generation,
        })
    }
    /// Freeze the exact key, content digest, active checkpoint head, and
    /// generation for a caller-owned retention decision.
    ///
    /// This read does not authorize or perform compaction. The caller must prepare and durably
    /// approve the returned fence through [`Self::prepare_certified_compaction`] and
    /// [`Self::approve_and_install_certified_compaction`].
    ///
    /// # Errors
    ///
    /// Rejects missing, forked, already-compacted, or substituted anchors.
    pub fn retention_fence_for(
        &self,
        key: &ReputationFinalizedArchiveKeyV1,
    ) -> Result<ReputationFinalizedArchiveRetentionFenceV1, ReputationFinalizedArchiveError> {
        key.validate()?;
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let entry = index
            .by_height
            .get(&(key.network_id.clone(), key.height))
            .ok_or(ReputationFinalizedArchiveError::MissingAnchor {
                network_id: key.network_id.clone(),
                height: key.height,
            })?;
        if &entry.manifest.key != key {
            return Err(ReputationFinalizedArchiveError::FinalizedFork {
                network_id: key.network_id.clone(),
                height: key.height,
            });
        }
        ReputationFinalizedArchiveRetentionFenceV1::try_new(
            key.clone(),
            entry.anchor_digest,
            active_checkpoint_digest(&index, &key.network_id),
            index.generation,
        )
    }
    /// Prepare the exact canonical checkpoint proposed for sealed retention.
    ///
    /// Preparation is read-only. Every physical prefix anchor and the fence's certified block are
    /// reauthenticated against one frozen Kura boundary, then the complete canonical checkpoint
    /// bytes are digested into the returned proposal.
    ///
    /// # Errors
    ///
    /// Rejects an absent, stale, forked, unauthenticated, or non-advancing fence, any archive/Kura
    /// boundary change, resource exhaustion, or a damaged archive.
    pub fn prepare_certified_compaction(
        &self,
        fence: &ReputationFinalizedArchiveRetentionFenceV1,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<ReputationFinalizedArchiveCompactionProposalV1, ReputationFinalizedArchiveError>
    {
        let index = self.read_index()?;
        let prepared = self.prepare_compaction_locked(&index, fence, state_ro, kura)?;
        compaction_proposal(&prepared, fence)
    }
    /// Durably approve and install one previously prepared compaction.
    ///
    /// This is the only production compaction entry point. It repeats all archive and Kura
    /// qualification while holding the archive write lock, installs a monotonic canonical record
    /// through the deployment-owned CAS authority, and requires exact authoritative readback both
    /// before checkpoint publication and before any prefix object is unlinked.
    ///
    /// # Errors
    ///
    /// In addition to preparation failures, rejects proposal substitution,
    /// missing or drifting authority identity, rollback, equivocation, an
    /// unchanged or ambiguous CAS, and any durable publication failure.
    pub fn approve_and_install_certified_compaction(
        &self,
        proposal: &ReputationFinalizedArchiveCompactionProposalV1,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
        authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
    ) -> Result<ReputationFinalizedArchiveCompactionOutcomeV1, ReputationFinalizedArchiveError>
    {
        proposal.validate()?;
        let fence = proposal.fence();
        let mut index = self.write_index()?;
        let prepared = self.prepare_compaction_locked(&index, fence, state_ro, kura)?;
        if compaction_proposal(&prepared, fence)? != *proposal {
            return Err(ReputationFinalizedArchiveError::RetentionProposalMismatch);
        }
        assert_retention_authority_identity(binding, authority)?;
        let network_id = fence.compact_through();
        let network_id = &network_id.network_id;
        let current = load_retention_approval(binding, authority, network_id)?;
        let expected_checkpoint = prepared.persisted.checkpoint.prior_checkpoint_digest;
        let next = if let Some(current) = current
            .as_ref()
            .filter(|record| record.proposal() == proposal)
        {
            validate_approval_for_prepared(
                current,
                binding,
                &prepared,
                proposal,
                expected_checkpoint,
            )?;
            current.clone()
        } else {
            if let Some(current) = &current {
                validate_retention_approval_record(current, binding, network_id)?;
            }
            validate_retention_authority_predecessor(current.as_ref(), expected_checkpoint, fence)?;
            let sequence = current.as_ref().map_or(Ok(1), |record| {
                record.sequence().checked_add(1).ok_or(
                    ReputationFinalizedArchiveError::InvalidRetentionApproval {
                        reason: "approval sequence overflowed",
                    },
                )
            })?;
            let next = ReputationFinalizedArchiveRetentionApprovalRecordV1::try_new(
                sequence,
                binding.qualification(),
                proposal.clone(),
                current
                    .as_ref()
                    .map(ReputationFinalizedArchiveRetentionApprovalRecordV1::revision),
                expected_checkpoint,
            )?;
            compare_and_read_back_retention_approval(
                binding,
                authority,
                network_id,
                current.as_ref(),
                &next,
            )?;
            next
        };
        require_exact_retention_readback(binding, authority, network_id, &next)?;
        self.publish_prepared_compaction(&mut index, prepared, || {
            require_exact_retention_readback(binding, authority, network_id, &next)
        })
    }
    #[cfg(test)]
    pub(crate) fn compact_certified_prefix(
        &self,
        fence: &ReputationFinalizedArchiveRetentionFenceV1,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<ReputationFinalizedArchiveCompactionOutcomeV1, ReputationFinalizedArchiveError>
    {
        let mut index = self.write_index()?;
        let prepared = self.prepare_compaction_locked(&index, fence, state_ro, kura)?;
        self.publish_prepared_compaction(&mut index, prepared, || Ok(()))
    }
    fn prepare_compaction_locked(
        &self,
        index: &ArchiveIndex,
        fence: &ReputationFinalizedArchiveRetentionFenceV1,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<PreparedReputationFinalizedArchiveCompactionV1, ReputationFinalizedArchiveError>
    {
        self.verify_storage_boundaries()?;
        if index.generation != fence.expected_generation {
            return Err(ReputationFinalizedArchiveError::RetentionFenceChanged {
                expected_generation: fence.expected_generation,
                observed_generation: index.generation,
            });
        }
        let network_id = &fence.compact_through.network_id;
        if active_checkpoint_digest(index, network_id) != fence.expected_checkpoint_digest {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionFence {
                reason: "retention fence does not bind the active checkpoint head",
            });
        }
        if let Some(active) = index.checkpoints.get(network_id)
            && fence.compact_through.height <= active.persisted.checkpoint.retention_floor.height
        {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionFence {
                reason: "retention fence does not advance the active virtual base",
            });
        }
        let target = index
            .by_height
            .get(&(network_id.clone(), fence.compact_through.height))
            .cloned()
            .ok_or(ReputationFinalizedArchiveError::MissingAnchor {
                network_id: network_id.clone(),
                height: fence.compact_through.height,
            })?;
        if target.manifest.key != fence.compact_through
            || target.anchor_digest != fence.compact_through_anchor_digest
        {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionFence {
                reason: "retention fence exact key or anchor digest was substituted",
            });
        }
        let state = self.reconstruct_state(index, &target)?;
        let anchors = index
            .by_height
            .range((
                std::ops::Bound::Included((network_id.clone(), 0)),
                std::ops::Bound::Included((network_id.clone(), fence.compact_through.height)),
            ))
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        if anchors.is_empty() {
            return Err(ReputationFinalizedArchiveError::InvalidRetentionFence {
                reason: "retention fence selected no physical anchors",
            });
        }
        validate_contiguous_archive_coverage(
            network_id,
            &anchors
                .iter()
                .map(|entry| {
                    (
                        entry.manifest.key.clone(),
                        entry.manifest.finalized_at_unix_ms,
                    )
                })
                .collect::<Vec<_>>(),
        )?;
        let newly_pruned_bytes = anchors.iter().try_fold(0_u64, |total, entry| {
            let bytes = direct_archive_file_metadata(&entry.path, self.bounds.max_record_bytes)
                .map_err(|source| ReputationFinalizedArchiveError::Read {
                    path: entry.path.clone(),
                    source,
                })?
                .len();
            total
                .checked_add(bytes)
                .ok_or(ReputationFinalizedArchiveError::ArchiveBytesExceeded {
                    size: u64::MAX,
                    maximum: self.bounds.max_total_bytes,
                })
        })?;
        let previous_checkpoint = index.checkpoints.get(network_id);
        let (
            original_activation_floor,
            prior_checkpoint_digest,
            checkpoint_generation,
            prior_pruned_count,
            prior_pruned_bytes,
            mut cumulative_anchor_prefix_digest,
        ) = previous_checkpoint.map_or_else(
            || {
                (
                    anchors
                        .first()
                        .expect("non-empty compacted prefix")
                        .manifest
                        .key
                        .clone(),
                    None,
                    1,
                    0,
                    0,
                    [0; 32],
                )
            },
            |checkpoint| {
                let material = &checkpoint.persisted.checkpoint;
                (
                    material.original_activation_floor.clone(),
                    Some(checkpoint.persisted.checkpoint_digest),
                    material.checkpoint_generation.saturating_add(1),
                    material.cumulative_pruned_anchor_count,
                    material.cumulative_pruned_anchor_bytes,
                    material.cumulative_anchor_prefix_digest,
                )
            },
        );
        if checkpoint_generation == u64::MAX {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint generation overflowed",
            });
        }
        for anchor in &anchors {
            cumulative_anchor_prefix_digest = rolling_domain_digest(
                ANCHOR_PREFIX_DIGEST_DOMAIN_V1,
                cumulative_anchor_prefix_digest,
                &anchor.anchor_digest,
            )?;
        }
        let cumulative_pruned_anchor_count = prior_pruned_count
            .checked_add(bounded_len(anchors.len())?)
            .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "cumulative compacted anchor count overflowed",
            })?;
        let cumulative_pruned_anchor_bytes = prior_pruned_bytes
            .checked_add(newly_pruned_bytes)
            .ok_or(ReputationFinalizedArchiveError::ArchiveBytesExceeded {
                size: u64::MAX,
                maximum: self.bounds.max_total_bytes,
            })?;
        let authority_policy_history_digest =
            authority_policy_history_digest(&resolve_authority_policy_history(
                index,
                &state.authority_policy,
                state.finalized_at_unix_ms,
            )?)?;
        let (journal_prefix_source_heads, journal_source_head_count, journal_source_head_root) =
            journal_source_head_commitment(
                &state.journal_prefix_source_heads,
                &state.journal_events.retained_suffix,
            )?;
        if journal_source_head_count != target.manifest.journal_source_head_count
            || journal_source_head_root != target.manifest.journal_source_head_root
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "retention target source-head commitment differs from its reconstructed journal history",
            });
        }
        let mut checkpoint = ReputationFinalizedVirtualBaseCheckpointV1 {
            original_activation_floor,
            retention_floor: state.key.clone(),
            retention_floor_finalized_at_unix_ms: state.finalized_at_unix_ms,
            retention_floor_anchor_digest: fence.compact_through_anchor_digest,
            // The finality digest is fixed-width. A nonzero placeholder lets
            // the exact production checkpoint shape hit local resource gates
            // before any Kura authentication or retention CAS.
            certified_block_id: [1; 32],
            prior_checkpoint_digest,
            checkpoint_generation,
            cumulative_pruned_anchor_count,
            cumulative_pruned_anchor_bytes,
            cumulative_anchor_prefix_digest,
            authority_policy: state.authority_policy.clone(),
            authority_policy_history_digest,
            proof_prefix: compact_retained_feed(
                PROOF_PREFIX_DIGEST_DOMAIN_V1,
                &state.proof_outcomes,
                proof_event_identity,
            )?,
            journal_prefix: compact_retained_feed(
                JOURNAL_PREFIX_DIGEST_DOMAIN_V1,
                &state.journal_events,
                journal_event_identity,
            )?,
            journal_prefix_source_heads,
            journal_source_head_delta: state.journal_events.retained_suffix.clone(),
            repair_prefix: compact_retained_feed(
                REPAIR_PREFIX_DIGEST_DOMAIN_V1,
                &state.repair_events,
                repair_event_identity,
            )?,
            orderbook_prefix: compact_retained_feed(
                ORDERBOOK_PREFIX_DIGEST_DOMAIN_V1,
                &state.orderbook_events,
                orderbook_event_identity,
            )?,
            reserve_prefix: compact_retained_feed(
                RESERVE_PREFIX_DIGEST_DOMAIN_V1,
                &state.reserve_events,
                reserve_event_identity,
            )?,
            proof_retained_suffix: Vec::new(),
            journal_retained_suffix: Vec::new(),
            repair_retained_suffix: Vec::new(),
            orderbook_retained_suffix: Vec::new(),
            reserve_retained_suffix: Vec::new(),
            reserve_providers: state.reserve_providers.clone(),
            validation_summary: ReputationCheckpointValidationSummaryV1 {
                high_water_marks: ReputationFeedHighWaterMarksV1::default(),
                policy_record_digest: [0; 32],
                journal_prefix_source_head_count: 0,
                journal_prefix_source_head_root: [0; 32],
                reserve_provider_count: 0,
                reserve_provider_state_root: [0; 32],
            },
            validation_summary_digest: [0; 32],
        };
        checkpoint.validation_summary = checkpoint_validation_summary(&checkpoint)?;
        checkpoint.validation_summary_digest = canonical_domain_digest(
            CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
            &checkpoint.validation_summary,
        )?;
        if let Some(previous) = previous_checkpoint {
            validate_journal_source_head_lineage(&previous.persisted.checkpoint, &checkpoint)?;
        }
        let preflight =
            PersistedReputationFinalizedVirtualBaseCheckpointV1::try_new(checkpoint.clone())?;
        prepare_checkpoint_publication(index, self.bounds, &preflight)?;
        let certified =
            CertifiedArchiveView::new(state_ro, kura).map_err(certified_finality_error)?;
        if state_ro.network_id() != network_id {
            return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
                reason: "retention State is bound to another network",
            });
        }
        if let Some(active) = index.checkpoints.get(network_id) {
            let material = &active.persisted.checkpoint;
            authenticate_archive_anchor_against_certified(
                &material.retention_floor,
                material.retention_floor_finalized_at_unix_ms,
                &certified,
            )?;
            if *certified
                .block(material.retention_floor.height)
                .map_err(certified_finality_error)?
                .id()
                .0
                .as_ref()
                != material.certified_block_id
            {
                return Err(ReputationFinalizedArchiveError::ArchiveKuraAnchorMismatch {
                    network_id: *network_id,
                    height: material.retention_floor.height,
                    reason: "prior virtual-base certified block identity changed",
                });
            }
        }
        for entry in &anchors {
            authenticate_archive_anchor_against_certified(
                &entry.manifest.key,
                entry.manifest.finalized_at_unix_ms,
                &certified,
            )?;
        }
        checkpoint.certified_block_id = *certified
            .block(fence.compact_through.height)
            .map_err(certified_finality_error)?
            .id()
            .0
            .as_ref();
        certified
            .verify_unchanged()
            .map_err(certified_finality_error)?;
        let persisted = PersistedReputationFinalizedVirtualBaseCheckpointV1::try_new(checkpoint)?;
        let checkpoint_bytes = prepare_checkpoint_publication(index, self.bounds, &persisted)?;
        let expected_archive_generation = index.generation.checked_add(1).ok_or(
            ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "archive generation overflowed during checkpoint publication",
            },
        )?;
        Ok(PreparedReputationFinalizedArchiveCompactionV1 {
            network_id: network_id.clone(),
            persisted,
            checkpoint_bytes,
            anchors,
            newly_pruned_bytes,
            expected_archive_generation,
        })
    }
    fn publish_prepared_compaction<BeforeCleanup>(
        &self,
        index: &mut ArchiveIndex,
        prepared: PreparedReputationFinalizedArchiveCompactionV1,
        before_cleanup: BeforeCleanup,
    ) -> Result<ReputationFinalizedArchiveCompactionOutcomeV1, ReputationFinalizedArchiveError>
    where
        BeforeCleanup: FnOnce() -> Result<(), ReputationFinalizedArchiveError>,
    {
        let retention_floor = prepared.persisted.checkpoint.retention_floor.clone();
        let checkpoint_digest = prepared.persisted.checkpoint_digest;
        let pruned_anchors = bounded_len(prepared.anchors.len())?;
        self.publish_checkpoint_and_reconcile(
            index,
            &prepared.network_id,
            &prepared.persisted,
            &prepared.checkpoint_bytes,
            prepared.expected_archive_generation,
            || Ok(()),
        )?;
        before_cleanup()?;
        if let Err(error) = self.finish_checkpoint_cleanup(index) {
            self.reconcile_checkpoint_index(index)?;
            return Err(error);
        }
        self.reconcile_checkpoint_index(index)?;
        self.verify_storage_boundaries()?;
        Ok(ReputationFinalizedArchiveCompactionOutcomeV1 {
            retention_floor,
            checkpoint_digest,
            pruned_anchors,
            pruned_bytes: prepared.newly_pruned_bytes,
            generation: index.generation,
        })
    }
    /// Publish one checkpoint and adopt the authoritative durable head before cleanup.
    ///
    /// `after_publish` is an in-process phase seam used by deterministic crash tests. Production
    /// supplies a no-op. Every error after the publication attempt still reconciles because a
    /// failed namespace sync may follow a successful canonical link.
    fn publish_checkpoint_and_reconcile<AfterPublish>(
        &self,
        index: &mut ArchiveIndex,
        network_id: &NetworkId,
        persisted: &PersistedReputationFinalizedVirtualBaseCheckpointV1,
        checkpoint_bytes: &[u8],
        expected_generation: u64,
        after_publish: AfterPublish,
    ) -> Result<(), ReputationFinalizedArchiveError>
    where
        AfterPublish: FnOnce() -> Result<(), ReputationFinalizedArchiveError>,
    {
        let checkpoint_path = self
            .checkpoints
            .join(checkpoint_file_name(persisted.checkpoint_digest));
        if let Err(error) = publish_immutable_bytes(
            &self.checkpoints,
            self.checkpoints_identity,
            &checkpoint_path,
            checkpoint_bytes,
        ) {
            self.reconcile_checkpoint_index(index)?;
            return Err(error);
        }
        if let Err(error) = after_publish() {
            self.reconcile_checkpoint_index(index)?;
            return Err(error);
        }
        match self.load_checkpoint_at(&checkpoint_path, Some(persisted.checkpoint_digest)) {
            Ok(loaded) if &loaded == persisted => {}
            Ok(_) => {
                self.reconcile_checkpoint_index(index)?;
                return Err(ReputationFinalizedArchiveError::CheckpointDigestMismatch);
            }
            Err(error) => {
                self.reconcile_checkpoint_index(index)?;
                return Err(error);
            }
        }
        self.reconcile_checkpoint_index(index)?;
        if index.generation != expected_generation
            || active_checkpoint_digest(index, network_id) != Some(persisted.checkpoint_digest)
        {
            return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "published checkpoint did not become the exact next active head",
            });
        }
        Ok(())
    }
    /// Rescan after a checkpoint-namespace mutation or latch the handle closed.
    fn reconcile_checkpoint_index(
        &self,
        index: &mut ArchiveIndex,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        match self.scan_inventory() {
            Ok(refreshed) => {
                *index = refreshed;
                Ok(())
            }
            Err(_) => {
                index.requires_reopen = true;
                Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                    reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
                })
            }
        }
    }
    /// Read one exact `(network_id, height, block_hash)` projection.
    ///
    /// A missing exact key returns `Ok(None)`. This method never substitutes
    /// the current head or another block at the requested height.
    ///
    /// # Errors
    ///
    /// Returns a typed storage, bounds, decode, canonicality, digest, or exact-key binding failure.
    pub fn get_exact(
        &self,
        key: &ReputationFinalizedArchiveKeyV1,
    ) -> Result<Option<ReputationFinalizedProjectionV1>, ReputationFinalizedArchiveError> {
        key.validate()?;
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        if let Some(checkpoint) = index.checkpoints.get(&key.network_id)
            && key.height <= checkpoint.persisted.checkpoint.retention_floor.height
        {
            return Err(history_pruned_error(&checkpoint.persisted.checkpoint));
        }
        let Some(entry) = index.by_height.get(&(key.network_id.clone(), key.height)) else {
            return Ok(None);
        };
        if entry.manifest.key.block_hash != key.block_hash {
            return Ok(None);
        }
        self.reconstruct_projection(&index, entry).map(Some)
    }
    /// Read the latest journal event for one source at an exact finalized key.
    ///
    /// A missing anchor or mismatched hash returns `Ok(None)`. A present view with `event: None` is
    /// an authoritative source absence at that anchor. Unlike full-history projection reads, the
    /// active checkpoint floor remains queryable through its bounded source-head index.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-input, history-pruned, storage, bounds, decode,
    /// canonicality, digest, or reconstruction failure.
    pub fn journal_event_by_source_at_exact(
        &self,
        key: &ReputationFinalizedArchiveKeyV1,
        source_id: ReputationJournalSourceIdV1,
    ) -> Result<
        Option<ReputationFinalizedArchiveJournalSourceViewV1>,
        ReputationFinalizedArchiveError,
    > {
        key.validate()?;
        validate_journal_source_id(source_id)?;
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        if let Some(checkpoint) = index.checkpoints.get(&key.network_id) {
            let checkpoint = &checkpoint.persisted.checkpoint;
            if key.height < checkpoint.retention_floor.height {
                return Err(history_pruned_error(checkpoint));
            }
            if key.height == checkpoint.retention_floor.height {
                if key != &checkpoint.retention_floor {
                    return Ok(None);
                }
                return Ok(Some(journal_source_view(
                    &checkpoint.retention_floor,
                    checkpoint.retention_floor_finalized_at_unix_ms,
                    &checkpoint.journal_prefix_source_heads,
                    &checkpoint.journal_retained_suffix,
                    checkpoint
                        .validation_summary
                        .journal_prefix_source_head_count,
                    checkpoint
                        .validation_summary
                        .journal_prefix_source_head_root,
                    source_id,
                )?));
            }
        }
        let Some(entry) = index.by_height.get(&(key.network_id.clone(), key.height)) else {
            return Ok(None);
        };
        if entry.manifest.key.block_hash != key.block_hash {
            return Ok(None);
        }
        let state = self.reconstruct_state(&index, entry)?;
        Ok(Some(journal_source_view_from_state(
            &state,
            entry.manifest.journal_source_head_count,
            entry.manifest.journal_source_head_root,
            source_id,
        )?))
    }
    /// Read the latest journal event for one source at the highest finalized
    /// archive view at or below `maximum_height`.
    ///
    /// A present view with `event: None` authoritatively proves source absence
    /// at the selected anchor. The active checkpoint floor participates in
    /// selection even after its full feed history has been compacted.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-input, history-pruned, storage, bounds, decode,
    /// canonicality, digest, or reconstruction failure.
    pub fn latest_journal_event_by_source_at_or_before(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
        source_id: ReputationJournalSourceIdV1,
    ) -> Result<
        Option<ReputationFinalizedArchiveJournalSourceViewV1>,
        ReputationFinalizedArchiveError,
    > {
        if network_id.as_bytes()[31] & 1 != 1 || maximum_height == 0 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty and maximum height must be non-zero",
            });
        }
        validate_journal_source_id(source_id)?;
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let checkpoint = index
            .checkpoints
            .get(network_id)
            .map(|entry| &entry.persisted.checkpoint);
        if let Some(checkpoint) = checkpoint
            && maximum_height < checkpoint.retention_floor.height
        {
            return Err(history_pruned_error(checkpoint));
        }
        if let Some(entry) = index
            .by_height
            .range((
                std::ops::Bound::Included((network_id.clone(), 0)),
                std::ops::Bound::Included((network_id.clone(), maximum_height)),
            ))
            .next_back()
            .map(|(_, entry)| entry)
        {
            let state = self.reconstruct_state(&index, entry)?;
            return Ok(Some(journal_source_view_from_state(
                &state,
                entry.manifest.journal_source_head_count,
                entry.manifest.journal_source_head_root,
                source_id,
            )?));
        }
        if let Some(checkpoint) = checkpoint {
            return Ok(Some(journal_source_view(
                &checkpoint.retention_floor,
                checkpoint.retention_floor_finalized_at_unix_ms,
                &checkpoint.journal_prefix_source_heads,
                &checkpoint.journal_retained_suffix,
                checkpoint
                    .validation_summary
                    .journal_prefix_source_head_count,
                checkpoint
                    .validation_summary
                    .journal_prefix_source_head_root,
                source_id,
            )?));
        }
        Ok(None)
    }
    /// Return the highest archived projection at or below `maximum_height`.
    ///
    /// Selection uses the synchronized direct anchor index; only the selected
    /// predecessor chain is reconstructed and revalidated.
    ///
    /// # Errors
    ///
    /// Returns a typed archive integrity or resource failure.
    pub fn latest_at_or_before(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> Result<Option<ReputationFinalizedProjectionV1>, ReputationFinalizedArchiveError> {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        if let Some(checkpoint) = index.checkpoints.get(network_id)
            && maximum_height <= checkpoint.persisted.checkpoint.retention_floor.height
        {
            return Err(history_pruned_error(&checkpoint.persisted.checkpoint));
        }
        let entry = index
            .by_height
            .range((
                std::ops::Bound::Included((network_id.clone(), 0)),
                std::ops::Bound::Included((network_id.clone(), maximum_height)),
            ))
            .next_back()
            .map(|(_, entry)| entry);
        if entry.is_none()
            && let Some(checkpoint) = index.checkpoints.get(network_id)
        {
            return Err(history_pruned_error(&checkpoint.persisted.checkpoint));
        }
        entry
            .map(|entry| self.reconstruct_projection(&index, entry))
            .transpose()
    }
    /// Return the highest archived projection and its complete authenticated
    /// authority-policy predecessor chain at or below `maximum_height`.
    ///
    /// Projection reconstruction and policy-chain resolution share one archive
    /// read guard, so compaction or capture cannot mix anchors, policy records,
    /// or generations inside the response.
    ///
    /// # Errors
    ///
    /// Returns a typed archive integrity, missing-policy, history-pruned, or resource failure.
    pub fn latest_at_or_before_with_policy_history(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> Result<
        Option<(
            ReputationFinalizedProjectionV1,
            Vec<ReputationJournalAuthorityPolicyRecordV1>,
        )>,
        ReputationFinalizedArchiveError,
    > {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "chain id must be non-empty",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        if let Some(checkpoint) = index.checkpoints.get(network_id)
            && maximum_height <= checkpoint.persisted.checkpoint.retention_floor.height
        {
            return Err(history_pruned_error(&checkpoint.persisted.checkpoint));
        }
        let entry = index
            .by_height
            .range((
                std::ops::Bound::Included((network_id.clone(), 0)),
                std::ops::Bound::Included((network_id.clone(), maximum_height)),
            ))
            .next_back()
            .map(|(_, entry)| entry);
        let Some(entry) = entry else {
            if let Some(checkpoint) = index.checkpoints.get(network_id) {
                return Err(history_pruned_error(&checkpoint.persisted.checkpoint));
            }
            return Ok(None);
        };
        let projection = self.reconstruct_projection(&index, entry)?;
        let history = resolve_authority_policy_history(
            &index,
            &projection.authority_policy,
            projection.finalized_at_unix_ms,
        )?;
        if authority_policy_history_digest(&history)?
            != entry.manifest.authority_policy_history_digest
        {
            return Err(ReputationFinalizedArchiveError::InvalidManifest {
                reason: "anchor authority-policy history commitment was substituted",
            });
        }
        Ok(Some((projection, history)))
    }
    #[cfg(test)]
    /// Page retained reputation-journal events at one exact archived anchor.
    fn page_journal_events(
        &self,
        key: &ReputationFinalizedArchiveKeyV1,
        after: Option<
            iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventCursorV1,
        >,
        limit: usize,
    ) -> Result<
        ReputationFinalizedArchivePageV1<
            ReputationJournalFinalizedEventV1,
            iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventCursorV1,
        >,
        ReputationFinalizedArchiveError,
    > {
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let state = self.reconstruct_state_for_key(&index, key)?;
        paginate_retained_feed(
            &state.journal_events,
            after,
            limit,
            REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1,
            ReputationJournalFinalizedEventV1::cursor,
            |cursor| {
                EventIdentity::from((
                    cursor.sequence,
                    cursor.block_height,
                    cursor.block_hash,
                    cursor.event_index,
                ))
            },
            |position| {
                iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventCursorV1 {
                    sequence: position.sequence,
                    block_height: position.block_height,
                    block_hash: position.block_hash,
                    event_index: position.event_index,
                }
            },
        )
    }
    /// Rescan the bound archive namespace and return its live generation.
    ///
    /// An empty archive is deliberately unavailable: production startup must wait for genesis
    /// capture instead of qualifying a current-head fallback. The synchronized read guard prevents
    /// insertion while the durable namespace is reconstructed and compared with the in-memory
    /// direct index. The generation advances for each anchor publication and each active
    /// checkpoint-head mutation, including compaction without a new anchor.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed storage or availability error.
    pub fn health_generation(&self) -> Result<u64, ReputationFinalizedArchiveError> {
        let index = self.read_index()?;
        if (index.anchor_count == 0 && index.checkpoint_count == 0) || index.generation == 0 {
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: "finalized archive has no captured anchor",
            });
        }
        self.verify_synchronized_index(&index)?;
        Ok(index.generation)
    }
    fn verify_synchronized_index(
        &self,
        index: &ArchiveIndex,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        let durable = self.scan_inventory()?;
        let indexes_match = durable.anchor_count == index.anchor_count
            && durable.checkpoint_count == index.checkpoint_count
            && durable.policy_count == index.policy_count
            && durable.total_bytes == index.total_bytes
            && durable.generation == index.generation
            && durable.policies == index.policies
            && durable.latest_projection == index.latest_projection
            && durable.latest_state == index.latest_state
            && durable.checkpoints.len() == index.checkpoints.len()
            && durable.checkpoints.iter().all(|(network_id, checkpoint)| {
                index.checkpoints.get(network_id).is_some_and(|indexed| {
                    indexed.persisted == checkpoint.persisted && indexed.path == checkpoint.path
                })
            })
            && durable.by_height.len() == index.by_height.len()
            && durable.by_height.iter().all(|(key, entry)| {
                index.by_height.get(key).is_some_and(|indexed| {
                    indexed.manifest == entry.manifest
                        && indexed.anchor_digest == entry.anchor_digest
                        && indexed.path == entry.path
                })
            });
        if !indexes_match {
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: "durable archive generation disagrees with its synchronized index",
            });
        }
        Ok(())
    }
    /// Return whether the complete bound archive namespace has no anchors,
    /// checkpoints, or policy records.
    ///
    /// Fresh height-zero startup uses this check before allowing genesis to establish the first
    /// immutable anchor. Checking the whole namespace prevents records belonging to another chain
    /// from being treated as an empty current-chain archive.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed storage, bounds, or archive-integrity error.
    pub fn is_empty(&self) -> Result<bool, ReputationFinalizedArchiveError> {
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let indexed_empty = index.anchor_count == 0
            && index.checkpoint_count == 0
            && index.policy_count == 0
            && index.by_height.is_empty()
            && index.checkpoints.is_empty()
            && index.policies.is_empty()
            && index.latest_projection.is_empty()
            && index.latest_state.is_empty()
            && index.total_bytes == 0
            && index.generation == 0;
        if !indexed_empty {
            return Ok(false);
        }
        let durable = self.scan_inventory()?;
        Ok(durable.anchor_count == 0
            && durable.checkpoint_count == 0
            && durable.policy_count == 0
            && durable.by_height.is_empty()
            && durable.checkpoints.is_empty()
            && durable.policies.is_empty()
            && durable.latest_projection.is_empty()
            && durable.latest_state.is_empty()
            && durable.total_bytes == 0
            && durable.generation == 0)
    }
    fn load_anchor_at(
        &self,
        path: &Path,
        expected_key: Option<&ReputationFinalizedArchiveKeyV1>,
    ) -> Result<PersistedReputationFinalizedAnchorV1, ReputationFinalizedArchiveError> {
        if path.parent() != Some(self.anchors.as_path()) {
            return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
                path: path.to_path_buf(),
            });
        }
        verify_archive_directory_identity(&self.anchors, self.anchors_identity).map_err(
            |source| ReputationFinalizedArchiveError::Read {
                path: self.anchors.clone(),
                source,
            },
        )?;
        let bytes =
            read_bounded_archive_file(path, self.bounds.max_record_bytes).map_err(|source| {
                ReputationFinalizedArchiveError::Read {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        let persisted: PersistedReputationFinalizedAnchorV1 =
            decode_from_bytes_with_limits(&bytes, self.bounds.decode_limits()).map_err(
                |source| ReputationFinalizedArchiveError::Decode {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        let canonical =
            norito::to_bytes(&persisted).map_err(ReputationFinalizedArchiveError::Encode)?;
        if canonical != bytes {
            return Err(ReputationFinalizedArchiveError::NonCanonicalRecord {
                path: path.to_path_buf(),
            });
        }
        persisted.validate_standalone()?;
        if let Some(expected_key) = expected_key {
            if &persisted.manifest.key != expected_key {
                return Err(ReputationFinalizedArchiveError::ExactKeyMismatch {
                    path: path.to_path_buf(),
                });
            }
        }
        let expected_name = anchor_file_name(&persisted.manifest.key)?;
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
                path: path.to_path_buf(),
            });
        }
        verify_archive_directory_identity(&self.anchors, self.anchors_identity).map_err(
            |source| ReputationFinalizedArchiveError::Read {
                path: self.anchors.clone(),
                source,
            },
        )?;
        Ok(persisted)
    }
    fn load_policy_at(
        &self,
        path: &Path,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<PersistedReputationAuthorityPolicyV1, ReputationFinalizedArchiveError> {
        if path.parent() != Some(self.policies.as_path()) {
            return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
                path: path.to_path_buf(),
            });
        }
        verify_archive_directory_identity(&self.policies, self.policies_identity).map_err(
            |source| ReputationFinalizedArchiveError::Read {
                path: self.policies.clone(),
                source,
            },
        )?;
        let bytes =
            read_bounded_archive_file(path, self.bounds.max_record_bytes).map_err(|source| {
                ReputationFinalizedArchiveError::Read {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        let persisted: PersistedReputationAuthorityPolicyV1 =
            decode_from_bytes_with_limits(&bytes, self.bounds.decode_limits()).map_err(
                |source| ReputationFinalizedArchiveError::Decode {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        if norito::to_bytes(&persisted).map_err(ReputationFinalizedArchiveError::Encode)? != bytes {
            return Err(ReputationFinalizedArchiveError::NonCanonicalRecord {
                path: path.to_path_buf(),
            });
        }
        persisted.validate()?;
        let expected_name = policy_file_name(persisted.record_digest);
        if expected_digest.is_some_and(|expected| expected != persisted.record_digest)
            || path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        {
            return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
                path: path.to_path_buf(),
            });
        }
        verify_archive_directory_identity(&self.policies, self.policies_identity).map_err(
            |source| ReputationFinalizedArchiveError::Read {
                path: self.policies.clone(),
                source,
            },
        )?;
        Ok(persisted)
    }
    fn load_checkpoint_at(
        &self,
        path: &Path,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<PersistedReputationFinalizedVirtualBaseCheckpointV1, ReputationFinalizedArchiveError>
    {
        if path.parent() != Some(self.checkpoints.as_path()) {
            return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
                path: path.to_path_buf(),
            });
        }
        verify_archive_directory_identity(&self.checkpoints, self.checkpoints_identity).map_err(
            |source| ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            },
        )?;
        let bytes =
            read_bounded_archive_file(path, self.bounds.max_record_bytes).map_err(|source| {
                ReputationFinalizedArchiveError::Read {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        let persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1 =
            decode_from_bytes_with_limits(&bytes, self.bounds.decode_limits()).map_err(
                |source| ReputationFinalizedArchiveError::Decode {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        if norito::to_bytes(&persisted).map_err(ReputationFinalizedArchiveError::Encode)? != bytes {
            return Err(ReputationFinalizedArchiveError::NonCanonicalRecord {
                path: path.to_path_buf(),
            });
        }
        persisted.validate_standalone()?;
        if expected_digest.is_some_and(|expected| expected != persisted.checkpoint_digest) {
            return Err(ReputationFinalizedArchiveError::CheckpointDigestMismatch);
        }
        let expected_name = checkpoint_file_name(persisted.checkpoint_digest);
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
                path: path.to_path_buf(),
            });
        }
        verify_archive_directory_identity(&self.checkpoints, self.checkpoints_identity).map_err(
            |source| ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            },
        )?;
        Ok(persisted)
    }
    fn remove_unreferenced_policies(
        &self,
        index: &ArchiveIndex,
    ) -> Result<(), ReputationFinalizedArchiveError> {
        let active_record_digests = index
            .by_height
            .values()
            .map(|entry| entry.manifest.policy_record_digest)
            .collect::<BTreeSet<_>>();
        let mut referenced = active_record_digests;
        for checkpoint in index.checkpoints.values() {
            referenced.insert(canonical_domain_digest(
                POLICY_RECORD_DIGEST_DOMAIN_V1,
                &checkpoint.persisted.checkpoint.authority_policy,
            )?);
        }
        for active_record_digest in referenced.clone() {
            let active = index.policies.get(&active_record_digest).ok_or(
                ReputationFinalizedArchiveError::MissingPolicy {
                    digest: active_record_digest,
                },
            )?;
            for record in resolve_authority_policy_history(index, active, u64::MAX)? {
                let (record_digest, retained) =
                    policy_record_by_policy_digest(index, record.policy_digest)?.ok_or(
                        ReputationFinalizedArchiveError::MissingPolicy {
                            digest: record.policy_digest,
                        },
                    )?;
                if retained != &record {
                    return Err(ReputationFinalizedArchiveError::PolicyConflict {
                        digest: record.policy_digest,
                    });
                }
                referenced.insert(record_digest);
            }
        }
        for digest in index
            .policies
            .keys()
            .filter(|digest| !referenced.contains(*digest))
            .copied()
        {
            let path = self.policies.join(policy_file_name(digest));
            self.load_policy_at(&path, Some(digest))?;
            unlink_immutable_archive_file(&self.policies, self.policies_identity, &path)?;
        }
        Ok(())
    }
    fn finish_checkpoint_cleanup(
        &self,
        index: &ArchiveIndex,
    ) -> Result<bool, ReputationFinalizedArchiveError> {
        if index.checkpoints.is_empty() {
            return Ok(false);
        }
        let mut changed = false;
        let mut covered_anchors = Vec::new();
        for entry in
            fs::read_dir(&self.anchors).map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.anchors.clone(),
                source,
            })?
        {
            let path = entry
                .map_err(|source| ReputationFinalizedArchiveError::Read {
                    path: self.anchors.clone(),
                    source,
                })?
                .path();
            let persisted = self.load_anchor_at(&path, None)?;
            if index
                .checkpoints
                .get(&persisted.manifest.key.network_id)
                .is_some_and(|checkpoint| {
                    persisted.manifest.key.height
                        <= checkpoint.persisted.checkpoint.retention_floor.height
                })
            {
                covered_anchors.push((
                    persisted.manifest.key.network_id,
                    persisted.manifest.key.height,
                    path,
                ));
            }
        }
        covered_anchors
            .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for (_, _, path) in covered_anchors {
            unlink_immutable_archive_file(&self.anchors, self.anchors_identity, &path)?;
            changed = true;
        }
        let mut stale_checkpoints = Vec::new();
        for entry in fs::read_dir(&self.checkpoints).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            }
        })? {
            let path = entry
                .map_err(|source| ReputationFinalizedArchiveError::Read {
                    path: self.checkpoints.clone(),
                    source,
                })?
                .path();
            let persisted = self.load_checkpoint_at(&path, None)?;
            let active_digest = index
                .checkpoints
                .get(&persisted.checkpoint.retention_floor.network_id)
                .map(|checkpoint| checkpoint.persisted.checkpoint_digest);
            if active_digest != Some(persisted.checkpoint_digest) {
                stale_checkpoints.push((persisted.checkpoint.checkpoint_generation, path));
            }
        }
        stale_checkpoints.sort_by_key(|(generation, _)| *generation);
        for (_, path) in stale_checkpoints {
            unlink_immutable_archive_file(&self.checkpoints, self.checkpoints_identity, &path)?;
            changed = true;
        }
        let refreshed = self.scan_inventory()?;
        let policies_before = refreshed.policy_count;
        self.remove_unreferenced_policies(&refreshed)?;
        changed |= self.scan_inventory()?.policy_count != policies_before;
        Ok(changed)
    }
    fn reconstruct_projection(
        &self,
        index: &ArchiveIndex,
        target: &AnchorIndexEntry,
    ) -> Result<ReputationFinalizedProjectionV1, ReputationFinalizedArchiveError> {
        self.reconstruct_state(index, target)?.full_projection()
    }
    fn reconstruct_state_for_key(
        &self,
        index: &ArchiveIndex,
        key: &ReputationFinalizedArchiveKeyV1,
    ) -> Result<ReputationReconstructionStateV1, ReputationFinalizedArchiveError> {
        key.validate()?;
        if let Some(checkpoint) = index.checkpoints.get(&key.network_id) {
            let material = &checkpoint.persisted.checkpoint;
            if key.height < material.retention_floor.height {
                return Err(history_pruned_error(material));
            }
            if key.height == material.retention_floor.height {
                if key != &material.retention_floor {
                    return Err(ReputationFinalizedArchiveError::FinalizedFork {
                        network_id: key.network_id.clone(),
                        height: key.height,
                    });
                }
                return ReputationReconstructionStateV1::from_checkpoint(material);
            }
        }
        let entry = index
            .by_height
            .get(&(key.network_id.clone(), key.height))
            .ok_or(ReputationFinalizedArchiveError::MissingAnchor {
                network_id: key.network_id.clone(),
                height: key.height,
            })?;
        if &entry.manifest.key != key {
            return Err(ReputationFinalizedArchiveError::FinalizedFork {
                network_id: key.network_id.clone(),
                height: key.height,
            });
        }
        self.reconstruct_state(index, entry)
    }
    fn reconstruct_state(
        &self,
        index: &ArchiveIndex,
        target: &AnchorIndexEntry,
    ) -> Result<ReputationReconstructionStateV1, ReputationFinalizedArchiveError> {
        let network_id = target.manifest.key.network_id.clone();
        let target_height = target.manifest.key.height;
        let (mut state, mut predecessor_anchor_digest, first_height) =
            if let Some(checkpoint) = index.checkpoints.get(&network_id) {
                let checkpoint = &checkpoint.persisted.checkpoint;
                if target_height <= checkpoint.retention_floor.height {
                    return Err(ReputationFinalizedArchiveError::HistoryPruned {
                        available_after: checkpoint
                            .journal_prefix
                            .pruned_through
                            .or(checkpoint.proof_prefix.pruned_through)
                            .or(checkpoint.repair_prefix.pruned_through)
                            .or(checkpoint.orderbook_prefix.pruned_through)
                            .or(checkpoint.reserve_prefix.pruned_through),
                    });
                }
                (
                    Some(ReputationReconstructionStateV1::from_checkpoint(
                        checkpoint,
                    )?),
                    Some(checkpoint.retention_floor_anchor_digest),
                    checkpoint.retention_floor.height.checked_add(1).ok_or(
                        ReputationFinalizedArchiveError::InvalidCheckpoint {
                            reason: "retention floor cannot have a retained successor",
                        },
                    )?,
                )
            } else {
                (None, None, 0)
            };
        for (_, entry) in index.by_height.range((
            std::ops::Bound::Included((network_id.clone(), first_height)),
            std::ops::Bound::Included((network_id.clone(), target_height)),
        )) {
            let persisted = self.load_anchor_at(&entry.path, Some(&entry.manifest.key))?;
            if persisted.manifest != entry.manifest {
                return Err(ReputationFinalizedArchiveError::ConflictingProjection {
                    network_id: entry.manifest.key.network_id.clone(),
                    height: entry.manifest.key.height,
                    block_hash: entry.manifest.key.block_hash,
                });
            }
            let cached_policy = index
                .policies
                .get(&entry.manifest.policy_record_digest)
                .ok_or(ReputationFinalizedArchiveError::MissingPolicy {
                    digest: entry.manifest.policy_record_digest,
                })?;
            let policy_path = self
                .policies
                .join(policy_file_name(entry.manifest.policy_record_digest));
            let persisted_policy =
                self.load_policy_at(&policy_path, Some(entry.manifest.policy_record_digest))?;
            if &persisted_policy.record != cached_policy {
                return Err(ReputationFinalizedArchiveError::PolicyConflict {
                    digest: entry.manifest.policy_record_digest,
                });
            }
            let authority_policy_history = resolve_authority_policy_history(
                index,
                &persisted_policy.record,
                persisted.manifest.finalized_at_unix_ms,
            )?;
            if authority_policy_history_digest(&authority_policy_history)?
                != persisted.manifest.authority_policy_history_digest
            {
                return Err(ReputationFinalizedArchiveError::InvalidManifest {
                    reason: "anchor authority-policy history commitment was substituted",
                });
            }
            state = Some(apply_anchor_delta_to_state(
                state,
                predecessor_anchor_digest,
                &persisted,
                &persisted_policy.record,
                &authority_policy_history,
            )?);
            predecessor_anchor_digest = Some(persisted.anchor_digest()?);
        }
        let state = state.ok_or(ReputationFinalizedArchiveError::ArchiveUnavailable {
            reason: "indexed anchor has no reconstructable predecessor chain",
        })?;
        if state.key != target.manifest.key {
            return Err(ReputationFinalizedArchiveError::ExactKeyMismatch {
                path: target.path.clone(),
            });
        }
        state.validate()?;
        Ok(state)
    }
    fn verify_storage_boundaries(&self) -> Result<(), ReputationFinalizedArchiveError> {
        verify_absolute_directory_ancestry(&self.root)?;
        verify_archive_directory_identity(&self.root, self.root_identity)
            .and_then(|()| verify_archive_directory_identity(&self.anchors, self.anchors_identity))
            .and_then(|()| {
                verify_archive_directory_identity(&self.checkpoints, self.checkpoints_identity)
            })
            .and_then(|()| {
                verify_archive_directory_identity(&self.policies, self.policies_identity)
            })
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.root.clone(),
                source,
            })?;
        let lock_path = self.root.join(WRITER_LOCK_FILE);
        let lock_metadata = secure_file_metadata::from_path(&lock_path).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: lock_path.clone(),
                source,
            }
        })?;
        let opened_metadata =
            secure_file_metadata::from_file(&self.writer_lock).map_err(|source| {
                ReputationFinalizedArchiveError::Read {
                    path: lock_path.clone(),
                    source,
                }
            })?;
        if lock_metadata.file_type().is_symlink()
            || !lock_metadata.is_file()
            || !secure_file_metadata::is_single_link(&lock_metadata)
            || archive_file_identity(&lock_metadata) != self.writer_lock_identity
            || !archive_file_metadata_unchanged(&lock_metadata, &opened_metadata)
        {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: lock_path,
                reason: "archive writer ownership file was substituted",
            });
        }
        validate_root_namespace(&self.root)?;
        Ok(())
    }
    fn recover_staged_files(&self) -> Result<(), ReputationFinalizedArchiveError> {
        recover_staged_directory(
            &self.anchors,
            self.anchors_identity,
            self.bounds.max_record_bytes,
            ANCHOR_FILE_SUFFIX,
        )?;
        recover_staged_directory(
            &self.checkpoints,
            self.checkpoints_identity,
            self.bounds.max_record_bytes,
            CHECKPOINT_FILE_SUFFIX,
        )?;
        recover_staged_directory(
            &self.policies,
            self.policies_identity,
            self.bounds.max_record_bytes,
            POLICY_FILE_SUFFIX,
        )?;
        self.verify_storage_boundaries()
    }
    fn scan_inventory(&self) -> Result<ArchiveIndex, ReputationFinalizedArchiveError> {
        self.verify_storage_boundaries()?;
        let mut index = ArchiveIndex::default();
        let mut policy_record_digests_by_policy_digest = BTreeMap::new();
        for entry in fs::read_dir(&self.policies).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: self.policies.clone(),
                source,
            }
        })? {
            let entry = entry.map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.policies.clone(),
                source,
            })?;
            index.policy_count = checked_artifact_count(index.policy_count, self.bounds)?;
            let path = entry.path();
            let name = entry.file_name();
            let name =
                name.to_str()
                    .ok_or_else(|| ReputationFinalizedArchiveError::InvalidStorage {
                        path: path.clone(),
                        reason: "archive policy filename is not UTF-8",
                    })?;
            if name.starts_with(STAGED_FILE_PREFIX)
                || !is_canonical_digest_file_name(name, POLICY_FILE_SUFFIX)
            {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path,
                    reason: "unknown file in finalized reputation policy archive",
                });
            }
            let persisted = self.load_policy_at(&path, None)?;
            let size = direct_archive_file_metadata(&path, self.bounds.max_record_bytes)
                .map_err(|source| ReputationFinalizedArchiveError::Read {
                    path: path.clone(),
                    source,
                })?
                .len();
            charge_archive_bytes(&mut index.total_bytes, size, self.bounds)?;
            if policy_record_digests_by_policy_digest
                .insert(persisted.record.policy_digest, persisted.record_digest)
                .is_some_and(|existing| existing != persisted.record_digest)
            {
                return Err(ReputationFinalizedArchiveError::PolicyConflict {
                    digest: persisted.record.policy_digest,
                });
            }
            if index
                .policies
                .insert(persisted.record_digest, persisted.record)
                .is_some()
            {
                return Err(ReputationFinalizedArchiveError::PolicyConflict {
                    digest: persisted.record_digest,
                });
            }
        }
        let mut checkpoint_lineages: BTreeMap<NetworkId, Vec<CheckpointIndexEntry>> =
            BTreeMap::new();
        for entry in fs::read_dir(&self.checkpoints).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            }
        })? {
            let entry = entry.map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.checkpoints.clone(),
                source,
            })?;
            index.checkpoint_count = checked_artifact_count(index.checkpoint_count, self.bounds)?;
            let path = entry.path();
            let name = entry.file_name();
            let name =
                name.to_str()
                    .ok_or_else(|| ReputationFinalizedArchiveError::InvalidStorage {
                        path: path.clone(),
                        reason: "archive checkpoint filename is not UTF-8",
                    })?;
            if name.starts_with(STAGED_FILE_PREFIX)
                || !is_canonical_digest_file_name(name, CHECKPOINT_FILE_SUFFIX)
            {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path,
                    reason: "unknown file in finalized reputation checkpoint archive",
                });
            }
            let persisted = self.load_checkpoint_at(&path, None)?;
            let size = direct_archive_file_metadata(&path, self.bounds.max_record_bytes)
                .map_err(|source| ReputationFinalizedArchiveError::Read {
                    path: path.clone(),
                    source,
                })?
                .len();
            charge_archive_bytes(&mut index.total_bytes, size, self.bounds)?;
            checkpoint_lineages
                .entry(persisted.checkpoint.retention_floor.network_id.clone())
                .or_default()
                .push(CheckpointIndexEntry { persisted, path });
        }
        for (network_id, lineage) in &mut checkpoint_lineages {
            lineage.sort_by(|left, right| {
                (
                    left.persisted.checkpoint.checkpoint_generation,
                    left.persisted.checkpoint.retention_floor.height,
                    left.persisted.checkpoint_digest,
                )
                    .cmp(&(
                        right.persisted.checkpoint.checkpoint_generation,
                        right.persisted.checkpoint.retention_floor.height,
                        right.persisted.checkpoint_digest,
                    ))
            });
            let mut previous: Option<&CheckpointIndexEntry> = None;
            for checkpoint in lineage.iter() {
                let material = &checkpoint.persisted.checkpoint;
                if &material.retention_floor.network_id != network_id {
                    return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                        reason: "checkpoint lineage crosses chain identifiers",
                    });
                }
                match previous {
                    None if (material.checkpoint_generation == 1
                        && material.prior_checkpoint_digest.is_none())
                        || (material.checkpoint_generation > 1
                            && material.prior_checkpoint_digest.is_some()) => {}
                    Some(previous)
                        if material.checkpoint_generation
                            == previous
                                .persisted
                                .checkpoint
                                .checkpoint_generation
                                .checked_add(1)
                                .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                                    reason: "checkpoint generation overflowed",
                                })?
                            && material.prior_checkpoint_digest
                                == Some(previous.persisted.checkpoint_digest)
                            && material.original_activation_floor
                                == previous.persisted.checkpoint.original_activation_floor
                            && material.retention_floor.height
                                > previous.persisted.checkpoint.retention_floor.height
                            && material.cumulative_pruned_anchor_count
                                > previous.persisted.checkpoint.cumulative_pruned_anchor_count
                            && material.cumulative_pruned_anchor_bytes
                                > previous.persisted.checkpoint.cumulative_pruned_anchor_bytes => {}
                    _ => {
                        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                            reason: "checkpoint lineage is forked, stale, or non-monotonic",
                        });
                    }
                }
                if let Some(previous) = previous {
                    validate_journal_source_head_lineage(&previous.persisted.checkpoint, material)?;
                }
                previous = Some(checkpoint);
            }
            let active = lineage
                .last()
                .expect("checkpoint lineage contains at least one entry")
                .clone();
            let expected_policy_digest = canonical_domain_digest(
                POLICY_RECORD_DIGEST_DOMAIN_V1,
                &active.persisted.checkpoint.authority_policy,
            )?;
            if index.policies.get(&expected_policy_digest)
                != Some(&active.persisted.checkpoint.authority_policy)
            {
                return Err(ReputationFinalizedArchiveError::MissingPolicy {
                    digest: expected_policy_digest,
                });
            }
            let policy_history = resolve_authority_policy_history(
                &index,
                &active.persisted.checkpoint.authority_policy,
                active
                    .persisted
                    .checkpoint
                    .retention_floor_finalized_at_unix_ms,
            )?;
            if authority_policy_history_digest(&policy_history)?
                != active.persisted.checkpoint.authority_policy_history_digest
            {
                return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                    reason: "checkpoint authority-policy history commitment was substituted",
                });
            }
            index.checkpoints.insert(network_id.clone(), active);
        }
        let mut persisted_anchors = BTreeMap::new();
        for entry in
            fs::read_dir(&self.anchors).map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.anchors.clone(),
                source,
            })?
        {
            let entry = entry.map_err(|source| ReputationFinalizedArchiveError::Read {
                path: self.anchors.clone(),
                source,
            })?;
            index.anchor_count = checked_artifact_count(index.anchor_count, self.bounds)?;
            let path = entry.path();
            let name = entry.file_name();
            let name =
                name.to_str()
                    .ok_or_else(|| ReputationFinalizedArchiveError::InvalidStorage {
                        path: path.clone(),
                        reason: "archive anchor filename is not UTF-8",
                    })?;
            if name.starts_with(STAGED_FILE_PREFIX)
                || !is_canonical_digest_file_name(name, ANCHOR_FILE_SUFFIX)
            {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path,
                    reason: "unknown file in finalized reputation anchor archive",
                });
            }
            let persisted = self.load_anchor_at(&path, None)?;
            let size = direct_archive_file_metadata(&path, self.bounds.max_record_bytes)
                .map_err(|source| ReputationFinalizedArchiveError::Read {
                    path: path.clone(),
                    source,
                })?
                .len();
            charge_archive_bytes(&mut index.total_bytes, size, self.bounds)?;
            let subject = (
                persisted.manifest.key.network_id.clone(),
                persisted.manifest.key.height,
            );
            if let Some(previous) = persisted_anchors.insert(subject.clone(), persisted.clone()) {
                return Err(
                    if previous.manifest.key.block_hash == persisted.manifest.key.block_hash {
                        ReputationFinalizedArchiveError::ConflictingProjection {
                            network_id: subject.0,
                            height: subject.1,
                            block_hash: previous.manifest.key.block_hash,
                        }
                    } else {
                        ReputationFinalizedArchiveError::FinalizedFork {
                            network_id: subject.0,
                            height: subject.1,
                        }
                    },
                );
            }
            let covered_by_checkpoint =
                index.checkpoints.get(&subject.0).is_some_and(|checkpoint| {
                    subject.1 <= checkpoint.persisted.checkpoint.retention_floor.height
                });
            if !covered_by_checkpoint {
                let anchor_digest = persisted.anchor_digest()?;
                index.by_height.insert(
                    subject,
                    AnchorIndexEntry {
                        manifest: persisted.manifest,
                        anchor_digest,
                        path,
                    },
                );
            }
        }
        let mut states = BTreeMap::new();
        let mut predecessor_anchor_digests = BTreeMap::new();
        let mut retained_anchor_count = 0_u64;
        for (network_id, checkpoint) in &index.checkpoints {
            let material = &checkpoint.persisted.checkpoint;
            states.insert(
                network_id.clone(),
                ReputationReconstructionStateV1::from_checkpoint(material)?,
            );
            predecessor_anchor_digests
                .insert(network_id.clone(), material.retention_floor_anchor_digest);
        }
        for ((network_id, _), persisted) in &persisted_anchors {
            if let Some(checkpoint) = index.checkpoints.get(network_id)
                && persisted.manifest.key.height
                    <= checkpoint.persisted.checkpoint.retention_floor.height
            {
                if persisted.manifest.key == checkpoint.persisted.checkpoint.retention_floor {
                    let checkpoint = &checkpoint.persisted.checkpoint;
                    if persisted.anchor_digest()? != checkpoint.retention_floor_anchor_digest {
                        return Err(ReputationFinalizedArchiveError::CheckpointDigestMismatch);
                    }
                    if persisted.manifest.journal_source_head_count
                        != checkpoint
                            .validation_summary
                            .journal_prefix_source_head_count
                        || persisted.manifest.journal_source_head_root
                            != checkpoint
                                .validation_summary
                                .journal_prefix_source_head_root
                    {
                        return Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                            reason: "retention-floor anchor and checkpoint source-head commitments disagree",
                        });
                    }
                }
                continue;
            }
            retained_anchor_count = retained_anchor_count.checked_add(1).ok_or(
                ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                    maximum_entries: self.bounds.max_entries.get(),
                },
            )?;
            let previous = states.remove(network_id);
            let predecessor_anchor_digest = predecessor_anchor_digests.remove(network_id);
            let policy = index
                .policies
                .get(&persisted.manifest.policy_record_digest)
                .ok_or(ReputationFinalizedArchiveError::MissingPolicy {
                    digest: persisted.manifest.policy_record_digest,
                })?;
            let policy_history = resolve_authority_policy_history(
                &index,
                policy,
                persisted.manifest.finalized_at_unix_ms,
            )?;
            if authority_policy_history_digest(&policy_history)?
                != persisted.manifest.authority_policy_history_digest
            {
                return Err(ReputationFinalizedArchiveError::InvalidManifest {
                    reason: "anchor authority-policy history commitment was substituted",
                });
            }
            let state = apply_anchor_delta_to_state(
                previous,
                predecessor_anchor_digest,
                persisted,
                policy,
                &policy_history,
            )?;
            predecessor_anchor_digests.insert(network_id.clone(), persisted.anchor_digest()?);
            states.insert(network_id.clone(), state);
        }
        for state in states.values() {
            state.validate()?;
        }
        index.latest_projection = states
            .iter()
            .filter_map(|(network_id, state)| {
                state
                    .full_projection()
                    .ok()
                    .map(|projection| (network_id.clone(), projection))
            })
            .collect();
        for projection in index.latest_projection.values() {
            validate_projection_against_index(projection, &index)?;
        }
        index.latest_state = states;
        let compacted_anchor_count =
            index
                .checkpoints
                .values()
                .try_fold(0_u64, |total, checkpoint| {
                    total
                        .checked_add(
                            checkpoint
                                .persisted
                                .checkpoint
                                .cumulative_pruned_anchor_count,
                        )
                        .ok_or(ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                            maximum_entries: self.bounds.max_entries.get(),
                        })
                })?;
        let checkpoint_head_mutation_count =
            index
                .checkpoints
                .values()
                .try_fold(0_u64, |total, checkpoint| {
                    total
                        .checked_add(checkpoint.persisted.checkpoint.checkpoint_generation)
                        .ok_or(ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                            maximum_entries: self.bounds.max_entries.get(),
                        })
                })?;
        index.generation = compacted_anchor_count
            .checked_add(retained_anchor_count)
            .and_then(|generation| generation.checked_add(checkpoint_head_mutation_count))
            .ok_or(ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                maximum_entries: self.bounds.max_entries.get(),
            })?;
        self.verify_storage_boundaries()?;
        Ok(index)
    }
    fn read_index(
        &self,
    ) -> Result<ArchiveIndexReadGuard<'_, ArchiveIndex>, ReputationFinalizedArchiveError> {
        let index = self
            .index
            .read()
            .map_err(|error| self.index_lock_error(error))?;
        if index.requires_reopen {
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            });
        }
        Ok(index)
    }
    fn write_index(
        &self,
    ) -> Result<ArchiveIndexWriteGuard<'_, ArchiveIndex>, ReputationFinalizedArchiveError> {
        let index = self
            .index
            .write()
            .map_err(|error| self.index_lock_error(error))?;
        if index.requires_reopen {
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            });
        }
        Ok(index)
    }
    fn index_lock_error(&self, error: ArchiveIndexLockError) -> ReputationFinalizedArchiveError {
        match error {
            ArchiveIndexLockError::Poisoned => ReputationFinalizedArchiveError::InvalidStorage {
                path: self.root.clone(),
                reason: "archive index lock is poisoned",
            },
            ArchiveIndexLockError::Busy(wait) => {
                ReputationFinalizedArchiveError::IndexBusy { wait }
            }
        }
    }
}
fn compaction_proposal(
    prepared: &PreparedReputationFinalizedArchiveCompactionV1,
    fence: &ReputationFinalizedArchiveRetentionFenceV1,
) -> Result<ReputationFinalizedArchiveCompactionProposalV1, ReputationFinalizedArchiveError> {
    let source_summary = &prepared.persisted.checkpoint.validation_summary;
    ReputationFinalizedArchiveCompactionProposalV1::try_new(
        fence.clone(),
        prepared.persisted.checkpoint_digest,
        canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &prepared.checkpoint_bytes,
        ),
        source_summary.journal_prefix_source_head_count,
        source_summary.journal_prefix_source_head_root,
    )
}
fn validate_approval_checkpoint(
    approval: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
    checkpoint: &PersistedReputationFinalizedVirtualBaseCheckpointV1,
    bounds: ReputationFinalizedArchiveBounds,
) -> Result<(), ReputationFinalizedArchiveError> {
    let fence = approval.proposal().fence();
    let canonical_bytes = encode_bounded_artifact(checkpoint, bounds)?;
    if checkpoint.checkpoint.retention_floor != *fence.compact_through()
        || checkpoint.checkpoint.retention_floor_anchor_digest
            != fence.compact_through_anchor_digest()
        || checkpoint.checkpoint.prior_checkpoint_digest != approval.predecessor_checkpoint_digest()
        || checkpoint.checkpoint_digest != approval.proposal().checkpoint_digest()
        || checkpoint
            .checkpoint
            .validation_summary
            .journal_prefix_source_head_count
            != approval.proposal().journal_source_head_count()
        || checkpoint
            .checkpoint
            .validation_summary
            .journal_prefix_source_head_root
            != approval.proposal().journal_source_head_root()
        || canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &canonical_bytes,
        ) != approval.proposal().checkpoint_canonical_digest()
    {
        return Err(ReputationFinalizedArchiveError::RetentionProposalMismatch);
    }
    Ok(())
}
fn validate_retention_checkpoint_candidate_inventory(
    candidates: &[CheckpointIndexEntry],
    approval: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
    network_id: &NetworkId,
) -> Result<(), ReputationFinalizedArchiveError> {
    let approved = approval.proposal().checkpoint_digest();
    let predecessor = approval.predecessor_checkpoint_digest();
    if predecessor == Some(approved) {
        return Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint);
    }
    let mut observed = BTreeSet::new();
    for candidate in candidates {
        if &candidate.persisted.checkpoint.retention_floor.network_id != network_id
            || !observed.insert(candidate.persisted.checkpoint_digest)
        {
            return Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint);
        }
    }
    let approved_is_present = observed.contains(&approved);
    let exact = match (approved_is_present, predecessor) {
        (true, None) => observed.len() == 1,
        (true, Some(predecessor)) => {
            observed.len() == 1 || (observed.len() == 2 && observed.contains(&predecessor))
        }
        (false, None) => observed.is_empty(),
        (false, Some(predecessor)) => observed.len() == 1 && observed.contains(&predecessor),
    };
    if !exact {
        return Err(
            if !approved_is_present && predecessor.is_some() && observed.is_empty() {
                ReputationFinalizedArchiveError::RetentionAuthorityRollback
            } else {
                ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint
            },
        );
    }
    Ok(())
}
fn validate_approval_for_prepared(
    approval: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
    binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    prepared: &PreparedReputationFinalizedArchiveCompactionV1,
    proposal: &ReputationFinalizedArchiveCompactionProposalV1,
    predecessor_checkpoint_digest: Option<[u8; 32]>,
) -> Result<(), ReputationFinalizedArchiveError> {
    validate_retention_approval_record(
        approval,
        binding,
        &proposal.fence().compact_through().network_id,
    )?;
    if approval.proposal() != proposal
        || approval.predecessor_checkpoint_digest() != predecessor_checkpoint_digest
        || prepared.persisted.checkpoint.prior_checkpoint_digest != predecessor_checkpoint_digest
        || prepared.persisted.checkpoint_digest != proposal.checkpoint_digest()
        || prepared
            .persisted
            .checkpoint
            .validation_summary
            .journal_prefix_source_head_count
            != proposal.journal_source_head_count()
        || prepared
            .persisted
            .checkpoint
            .validation_summary
            .journal_prefix_source_head_root
            != proposal.journal_source_head_root()
        || canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &prepared.checkpoint_bytes,
        ) != proposal.checkpoint_canonical_digest()
    {
        return Err(ReputationFinalizedArchiveError::RetentionProposalMismatch);
    }
    Ok(())
}
fn validate_retention_approval_record(
    approval: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
    binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    network_id: &NetworkId,
) -> Result<(), ReputationFinalizedArchiveError> {
    approval.validate()?;
    if approval.authority_qualification() != binding.qualification()
        || &approval.proposal().fence().compact_through().network_id != network_id
    {
        return Err(ReputationFinalizedArchiveError::RetentionAuthoritySubstitution);
    }
    let canonical = approval.to_canonical_bytes()?;
    if ReputationFinalizedArchiveRetentionApprovalRecordV1::from_canonical_bytes(&canonical)?
        != *approval
    {
        return Err(ReputationFinalizedArchiveError::InvalidRetentionApproval {
            reason: "authority returned a noncanonical approval record",
        });
    }
    Ok(())
}
fn validate_retention_authority_predecessor(
    current: Option<&ReputationFinalizedArchiveRetentionApprovalRecordV1>,
    expected_checkpoint: Option<[u8; 32]>,
    next_fence: &ReputationFinalizedArchiveRetentionFenceV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    if current.map(|record| record.proposal().checkpoint_digest()) != expected_checkpoint
        || current.is_some_and(|record| {
            record.proposal().fence().compact_through().height
                >= next_fence.compact_through().height
        })
    {
        return Err(ReputationFinalizedArchiveError::RetentionAuthorityRollback);
    }
    Ok(())
}
fn retention_authority_external_error(
    error: ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
) -> ReputationFinalizedArchiveError {
    match error {
        ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable => {
            ReputationFinalizedArchiveError::RetentionAuthorityUnavailable
        }
        ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected => {
            ReputationFinalizedArchiveError::RetentionAuthorityRejected
        }
        ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous => {
            ReputationFinalizedArchiveError::RetentionAuthorityCasAmbiguous
        }
    }
}
fn assert_retention_authority_identity(
    binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    binding.qualification.validate()?;
    let handle_before = authority.handle();
    if !iroha_config::parameters::is_production_runtime_handle(handle_before)
        || handle_before != binding.handle()
    {
        return Err(ReputationFinalizedArchiveError::RetentionAuthoritySubstitution);
    }
    let qualification = authority
        .qualification()
        .map_err(retention_authority_external_error)?;
    qualification.validate()?;
    let handle_after = authority.handle();
    if handle_after != handle_before
        || handle_after != binding.handle()
        || qualification != binding.qualification()
    {
        return Err(ReputationFinalizedArchiveError::RetentionAuthoritySubstitution);
    }
    Ok(())
}
fn load_retention_approval(
    binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
    network_id: &NetworkId,
) -> Result<
    Option<ReputationFinalizedArchiveRetentionApprovalRecordV1>,
    ReputationFinalizedArchiveError,
> {
    assert_retention_authority_identity(binding, authority)?;
    let record = authority
        .load_latest(network_id)
        .map_err(retention_authority_external_error)?;
    assert_retention_authority_identity(binding, authority)?;
    if let Some(record) = &record {
        validate_retention_approval_record(record, binding, network_id)?;
    }
    Ok(record)
}
fn require_exact_retention_readback(
    binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
    network_id: &NetworkId,
    expected: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    match load_retention_approval(binding, authority, network_id) {
        Ok(Some(observed)) if observed == *expected => Ok(()),
        Ok(_) => Err(ReputationFinalizedArchiveError::RetentionAuthorityEquivocation),
        Err(_) => Err(ReputationFinalizedArchiveError::RetentionAuthorityCasAmbiguous),
    }
}
fn compare_and_read_back_retention_approval(
    binding: &ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ReputationFinalizedArchiveRetentionAuthorityV1,
    network_id: &NetworkId,
    expected: Option<&ReputationFinalizedArchiveRetentionApprovalRecordV1>,
    next: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    validate_retention_approval_record(next, binding, network_id)?;
    let observed_before_compare = load_retention_approval(binding, authority, network_id)?;
    if observed_before_compare.as_ref() == Some(next) {
        return Ok(());
    }
    if observed_before_compare.as_ref() != expected {
        return Err(ReputationFinalizedArchiveError::RetentionAuthorityEquivocation);
    }
    let compare_result = authority.compare_and_swap_latest(
        network_id,
        expected.map(ReputationFinalizedArchiveRetentionApprovalRecordV1::revision),
        next,
    );
    if assert_retention_authority_identity(binding, authority).is_err() {
        return Err(ReputationFinalizedArchiveError::RetentionAuthorityCasAmbiguous);
    }
    let readback = match load_retention_approval(binding, authority, network_id) {
        Ok(readback) => readback,
        Err(_) => {
            return Err(ReputationFinalizedArchiveError::RetentionAuthorityCasAmbiguous);
        }
    };
    if readback.as_ref() == Some(next) {
        return Ok(());
    }
    if readback.as_ref() == expected {
        return Err(match compare_result {
            Err(ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected) => {
                ReputationFinalizedArchiveError::RetentionAuthorityRejected
            }
            Err(
                ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable
                | ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous,
            ) => ReputationFinalizedArchiveError::RetentionAuthorityCasAmbiguous,
            Ok(()) => ReputationFinalizedArchiveError::RetentionAuthorityCasUnchanged,
        });
    }
    Err(ReputationFinalizedArchiveError::RetentionAuthorityEquivocation)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovedCheckpointCoverage {
    Complete,
    AwaitingCapture,
}

fn authenticate_approval_checkpoint_against_certified(
    checkpoint: &PersistedReputationFinalizedVirtualBaseCheckpointV1,
    index: &ArchiveIndex,
    state_ro: &impl StateReadOnly,
    kura: &Kura,
) -> Result<ApprovedCheckpointCoverage, ReputationFinalizedArchiveError> {
    let material = &checkpoint.checkpoint;
    if state_ro.network_id() != &material.retention_floor.network_id {
        return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
            reason: "retention recovery State is bound to another network",
        });
    }
    let certified = CertifiedArchiveView::new(state_ro, kura).map_err(certified_finality_error)?;
    authenticate_archive_anchor_against_certified(
        &material.retention_floor,
        material.retention_floor_finalized_at_unix_ms,
        &certified,
    )?;
    let mut retained_anchors = vec![(
        material.retention_floor.clone(),
        material.retention_floor_finalized_at_unix_ms,
    )];
    retained_anchors.extend(
        index
            .by_height
            .range((
                std::ops::Bound::Excluded((
                    material.retention_floor.network_id.clone(),
                    material.retention_floor.height,
                )),
                std::ops::Bound::Included((material.retention_floor.network_id.clone(), u64::MAX)),
            ))
            .map(|(_, entry)| {
                (
                    entry.manifest.key.clone(),
                    entry.manifest.finalized_at_unix_ms,
                )
            }),
    );
    validate_contiguous_archive_coverage(&material.retention_floor.network_id, &retained_anchors)?;
    let mut retained_tip_height = material.retention_floor.height;
    for (key, finalized_at_unix_ms) in retained_anchors.iter().skip(1) {
        authenticate_archive_anchor_against_certified(key, *finalized_at_unix_ms, &certified)?;
        retained_tip_height = key.height;
    }
    if *certified
        .block(material.retention_floor.height)
        .map_err(certified_finality_error)?
        .id()
        .0
        .as_ref()
        != material.certified_block_id
    {
        return Err(ReputationFinalizedArchiveError::ArchiveKuraAnchorMismatch {
            network_id: material.retention_floor.network_id,
            height: material.retention_floor.height,
            reason: "approved retention-floor certified block identity changed",
        });
    }
    certified
        .verify_unchanged()
        .map_err(certified_finality_error)?;
    Ok(if retained_tip_height == certified.tip_height() {
        ApprovedCheckpointCoverage::Complete
    } else {
        // Every retained anchor was authenticated against this exact boundary,
        // so the remaining difference is an uncaptured trailing suffix.
        ApprovedCheckpointCoverage::AwaitingCapture
    })
}
fn history_pruned_error(
    checkpoint: &ReputationFinalizedVirtualBaseCheckpointV1,
) -> ReputationFinalizedArchiveError {
    ReputationFinalizedArchiveError::HistoryPruned {
        available_after: checkpoint
            .journal_prefix
            .pruned_through
            .or(checkpoint.proof_prefix.pruned_through)
            .or(checkpoint.repair_prefix.pruned_through)
            .or(checkpoint.orderbook_prefix.pruned_through)
            .or(checkpoint.reserve_prefix.pruned_through),
    }
}
#[cfg(test)]
fn paginate_retained_feed<T, C>(
    feed: &ReputationRetainedFeedStateV1<T>,
    after: Option<C>,
    limit: usize,
    maximum_limit: usize,
    cursor: impl Fn(&T) -> C,
    cursor_identity: impl Fn(C) -> EventIdentity,
    position_cursor: impl Fn(ReputationFinalizedEventPositionV1) -> C,
) -> Result<ReputationFinalizedArchivePageV1<T, C>, ReputationFinalizedArchiveError>
where
    T: Clone,
    C: Copy + PartialEq,
{
    if limit == 0 || limit > maximum_limit {
        return Err(ReputationFinalizedArchiveError::InvalidPageLimit {
            requested: limit,
            maximum: maximum_limit,
        });
    }
    let prefix = feed.prefix.public();
    let start = match (feed.prefix.pruned_through, after) {
        (Some(pruned_through), None) => {
            return Ok(ReputationFinalizedArchivePageV1::HistoryPruned {
                available_after: position_cursor(pruned_through),
                prefix,
            });
        }
        (Some(pruned_through), Some(after)) => {
            let after_identity = cursor_identity(after);
            let pruned_identity = position_identity(pruned_through);
            if after_identity == pruned_identity {
                0
            } else if after_identity.sequence < pruned_identity.sequence {
                return Ok(ReputationFinalizedArchivePageV1::HistoryPruned {
                    available_after: position_cursor(pruned_through),
                    prefix,
                });
            } else if after_identity.sequence == pruned_identity.sequence {
                return Err(ReputationFinalizedArchiveError::InvalidPageCursor);
            } else {
                feed.retained_suffix
                    .iter()
                    .position(|event| cursor(event) == after)
                    .and_then(|position| position.checked_add(1))
                    .ok_or(ReputationFinalizedArchiveError::InvalidPageCursor)?
            }
        }
        (None, Some(after)) => feed
            .retained_suffix
            .iter()
            .position(|event| cursor(event) == after)
            .and_then(|position| position.checked_add(1))
            .ok_or(ReputationFinalizedArchiveError::InvalidPageCursor)?,
        (None, None) => 0,
    };
    let end = start.saturating_add(limit).min(feed.retained_suffix.len());
    let events = feed.retained_suffix[start..end].to_vec();
    let has_more = end < feed.retained_suffix.len();
    let next_after = has_more.then(|| {
        events
            .last()
            .map(cursor)
            .expect("a continuing retained page contains a terminal row")
    });
    Ok(ReputationFinalizedArchivePageV1::Page {
        events,
        has_more,
        next_after,
        prefix,
    })
}
fn validate_contiguous_archive_coverage(
    network_id: &NetworkId,
    anchors: &[(ReputationFinalizedArchiveKeyV1, u64)],
) -> Result<(), ReputationFinalizedArchiveError> {
    let Some((first, _)) = anchors.first() else {
        return Ok(());
    };
    if &first.network_id != network_id {
        return Err(ReputationFinalizedArchiveError::InvalidKey {
            reason: "archive coverage begins on another chain",
        });
    }
    let mut previous_height: Option<u64> = None;
    for (key, _) in anchors {
        if &key.network_id != network_id {
            return Err(ReputationFinalizedArchiveError::InvalidKey {
                reason: "archive coverage crosses chain identifiers",
            });
        }
        if let Some(previous_height) = previous_height {
            let expected_height = previous_height.checked_add(1).ok_or(
                ReputationFinalizedArchiveError::ArchiveCoverageGap {
                    network_id: network_id.clone(),
                    missing_height: u64::MAX,
                    observed_height: key.height,
                },
            )?;
            if key.height != expected_height {
                return Err(ReputationFinalizedArchiveError::ArchiveCoverageGap {
                    network_id: network_id.clone(),
                    missing_height: expected_height,
                    observed_height: key.height,
                });
            }
        }
        previous_height = Some(key.height);
    }
    Ok(())
}
fn authenticate_archive_anchor_against_certified(
    key: &ReputationFinalizedArchiveKeyV1,
    finalized_at_unix_ms: u64,
    certified: &CertifiedArchiveView<'_, impl StateReadOnly>,
) -> Result<(), ReputationFinalizedArchiveError> {
    let block = certified
        .block(key.height)
        .map_err(certified_finality_error)?;
    if block.height() != key.height
        || *block.block_hash().as_ref() != key.block_hash
        || block.block_time_ms() != finalized_at_unix_ms
    {
        return Err(ReputationFinalizedArchiveError::ArchiveKuraAnchorMismatch {
            network_id: key.network_id,
            height: key.height,
            reason: "archive timestamp or identity differs from the certified block",
        });
    }
    Ok(())
}
fn certified_finality_error(error: ArchiveFinalityError) -> ReputationFinalizedArchiveError {
    match error {
        ArchiveFinalityError::Deferred(original) => {
            ReputationFinalizedArchiveError::Deferred(original)
        }
        error => ReputationFinalizedArchiveError::KuraAuthentication {
            operation: "authenticate current certified archive boundary",
            detail: error.to_string(),
        },
    }
}
fn candidate_capture_key(
    state_ro: &impl StateReadOnly,
    kura: &Kura,
) -> Result<(ReputationFinalizedArchiveKeyV1, u64), ReputationFinalizedArchiveError> {
    if !std::ptr::eq(state_ro.kura(), kura) {
        return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
            reason: "immutable state view is bound to another Kura instance",
        });
    }
    let height = u64::try_from(state_ro.height()).map_err(|_| {
        ReputationFinalizedArchiveError::FinalityAuthentication {
            reason: "immutable state height exceeds the supported range",
        }
    })?;
    let block_hash = state_ro.latest_block_hash().ok_or(
        ReputationFinalizedArchiveError::FinalityAuthentication {
            reason: "immutable state has no candidate block hash",
        },
    )?;
    let finalized_at_unix_ms = state_ro.query_ledger_time_ms();
    if finalized_at_unix_ms == 0 || finalized_at_unix_ms == u64::MAX {
        return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
            reason: "candidate header has no valid deterministic timestamp",
        });
    }
    let key = ReputationFinalizedArchiveKeyV1::try_new(
        *state_ro.network_id(),
        height,
        *block_hash.as_ref(),
    )?;
    Ok((key, finalized_at_unix_ms))
}
fn projection_query_error(
    source: &'static str,
    error: iroha_data_model::query::error::QueryExecutionFail,
) -> ReputationFinalizedArchiveError {
    ReputationFinalizedArchiveError::ProjectionCaptureQuery {
        projection: source,
        detail: error.to_string(),
    }
}
const fn projection_anchor_error(source: &'static str) -> ReputationFinalizedArchiveError {
    ReputationFinalizedArchiveError::ProjectionCaptureAnchorMismatch { projection: source }
}
fn collect_capture_pages<T, C>(
    source: &'static str,
    initial_after: Option<C>,
    budget: &mut ProjectionCaptureBudget,
    mut fetch: impl FnMut(Option<C>) -> Result<CapturePage<T, C>, ReputationFinalizedArchiveError>,
    cursor: impl Fn(&T) -> C,
) -> Result<Vec<T>, ReputationFinalizedArchiveError>
where
    T: norito::core::NoritoSerialize,
    C: Copy + Ord,
{
    let mut after = initial_after;
    let mut seen_continuations = BTreeSet::new();
    if let Some(cursor) = after {
        seen_continuations.insert(cursor);
    }
    let mut collected = Vec::new();
    loop {
        let page = fetch(after)?;
        if page.has_more && page.rows.is_empty() {
            return Err(
                ReputationFinalizedArchiveError::ProjectionCapturePagination {
                    projection: source,
                    reason: "non-terminal capture page is empty",
                },
            );
        }
        let mut previous_cursor = after;
        for row in &page.rows {
            let row_cursor = cursor(row);
            if previous_cursor.is_some_and(|previous| row_cursor <= previous) {
                return Err(
                    ReputationFinalizedArchiveError::ProjectionCapturePagination {
                        projection: source,
                        reason: "capture page cursor did not advance strictly",
                    },
                );
            }
            budget.charge(source, row)?;
            previous_cursor = Some(row_cursor);
        }
        collected.try_reserve(page.rows.len()).map_err(|_| {
            ReputationFinalizedArchiveError::ProjectionCaptureAllocation { projection: source }
        })?;
        collected.extend(page.rows);
        if !page.has_more {
            if page.next_after.is_some() {
                return Err(
                    ReputationFinalizedArchiveError::ProjectionCapturePagination {
                        projection: source,
                        reason: "terminal capture page carries a continuation",
                    },
                );
            }
            break;
        }
        let expected_next = previous_cursor.ok_or(
            ReputationFinalizedArchiveError::ProjectionCapturePagination {
                projection: source,
                reason: "non-terminal capture page has no terminal row",
            },
        )?;
        if page.next_after != Some(expected_next) {
            return Err(
                ReputationFinalizedArchiveError::ProjectionCapturePagination {
                    projection: source,
                    reason: "capture continuation differs from the terminal row",
                },
            );
        }
        if !seen_continuations.insert(expected_next) {
            return Err(
                ReputationFinalizedArchiveError::ProjectionCapturePagination {
                    projection: source,
                    reason: "capture continuation was replayed",
                },
            );
        }
        after = Some(expected_next);
    }
    Ok(collected)
}
fn retained_capture_cursor<T, C>(
    feed: &ReputationRetainedFeedStateV1<T>,
    retained_cursor: impl Fn(&T) -> C,
    prefix_cursor: impl Fn(ReputationFinalizedEventPositionV1) -> C,
) -> Option<C> {
    feed.retained_suffix
        .last()
        .map(retained_cursor)
        .or_else(|| feed.prefix.pruned_through.map(prefix_cursor))
}
fn append_capture_suffix<T>(
    source: &'static str,
    rows: &mut Vec<T>,
    suffix: Vec<T>,
) -> Result<(), ReputationFinalizedArchiveError> {
    rows.try_reserve(suffix.len()).map_err(|_| {
        ReputationFinalizedArchiveError::ProjectionCaptureAllocation { projection: source }
    })?;
    rows.extend(suffix);
    Ok(())
}
fn build_captured_successor_state(
    previous: Option<&ReputationReconstructionStateV1>,
    captured: CapturedReputationSuccessorV1,
    authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<ReputationReconstructionStateV1, ReputationFinalizedArchiveError> {
    let mut next = previous
        .cloned()
        .unwrap_or_else(|| ReputationReconstructionStateV1 {
            key: captured.key.clone(),
            finalized_at_unix_ms: captured.finalized_at_unix_ms,
            authority_policy: captured.authority_policy.clone(),
            proof_outcomes: ReputationRetainedFeedStateV1::default(),
            journal_events: ReputationRetainedFeedStateV1::default(),
            journal_prefix_source_heads: Vec::new(),
            repair_events: ReputationRetainedFeedStateV1::default(),
            orderbook_events: ReputationRetainedFeedStateV1::default(),
            reserve_events: ReputationRetainedFeedStateV1::default(),
            reserve_providers: Vec::new(),
        });
    next.key = captured.key;
    next.finalized_at_unix_ms = captured.finalized_at_unix_ms;
    next.authority_policy = captured.authority_policy;
    next.reserve_providers = captured.reserve_providers;
    append_capture_suffix(
        "proof-outcome events",
        &mut next.proof_outcomes.retained_suffix,
        captured.proof_outcomes,
    )?;
    append_capture_suffix(
        "reputation journal events",
        &mut next.journal_events.retained_suffix,
        captured.journal_events,
    )?;
    append_capture_suffix(
        "repair events",
        &mut next.repair_events.retained_suffix,
        captured.repair_events,
    )?;
    append_capture_suffix(
        "orderbook events",
        &mut next.orderbook_events.retained_suffix,
        captured.orderbook_events,
    )?;
    append_capture_suffix(
        "reserve events",
        &mut next.reserve_events.retained_suffix,
        captured.reserve_events,
    )?;
    next.validate()?;
    if let Some(previous) = previous {
        validate_reconstruction_state_transition(previous, &next, authority_policy_history)?;
    }
    Ok(next)
}
fn canonical_domain_digest<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
    let bytes = norito::to_bytes(value).map_err(ReputationFinalizedArchiveError::Encode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn rolling_domain_digest<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    previous: [u8; 32],
    value: &T,
) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
    let bytes = norito::to_bytes(value).map_err(ReputationFinalizedArchiveError::Encode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&previous);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn checkpoint_content_digest(
    version: u16,
    checkpoint: &ReputationFinalizedVirtualBaseCheckpointV1,
) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
    let bytes = norito::to_bytes(checkpoint).map_err(ReputationFinalizedArchiveError::Encode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKPOINT_DIGEST_DOMAIN_V1);
    hasher.update(&version.to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn checkpoint_validation_summary(
    checkpoint: &ReputationFinalizedVirtualBaseCheckpointV1,
) -> Result<ReputationCheckpointValidationSummaryV1, ReputationFinalizedArchiveError> {
    let (_, journal_source_head_count, journal_source_head_root) = journal_source_head_commitment(
        &checkpoint.journal_prefix_source_heads,
        &checkpoint.journal_retained_suffix,
    )?;
    let high_water_marks = ReputationFeedHighWaterMarksV1 {
        proof_outcomes: checkpoint
            .proof_prefix
            .pruned_event_count
            .checked_add(bounded_len(checkpoint.proof_retained_suffix.len())?)
            .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint proof high-water mark overflowed",
            })?,
        journal_events: checkpoint
            .journal_prefix
            .pruned_event_count
            .checked_add(bounded_len(checkpoint.journal_retained_suffix.len())?)
            .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint journal high-water mark overflowed",
            })?,
        repair_events: checkpoint
            .repair_prefix
            .pruned_event_count
            .checked_add(bounded_len(checkpoint.repair_retained_suffix.len())?)
            .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint repair high-water mark overflowed",
            })?,
        orderbook_events: checkpoint
            .orderbook_prefix
            .pruned_event_count
            .checked_add(bounded_len(checkpoint.orderbook_retained_suffix.len())?)
            .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint orderbook high-water mark overflowed",
            })?,
        reserve_events: checkpoint
            .reserve_prefix
            .pruned_event_count
            .checked_add(bounded_len(checkpoint.reserve_retained_suffix.len())?)
            .ok_or(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint reserve high-water mark overflowed",
            })?,
    };
    Ok(ReputationCheckpointValidationSummaryV1 {
        high_water_marks,
        policy_record_digest: canonical_domain_digest(
            POLICY_RECORD_DIGEST_DOMAIN_V1,
            &checkpoint.authority_policy,
        )?,
        journal_prefix_source_head_count: journal_source_head_count,
        journal_prefix_source_head_root: journal_source_head_root,
        reserve_provider_count: bounded_len(checkpoint.reserve_providers.len())?,
        reserve_provider_state_root: reserve_provider_state_root(&checkpoint.reserve_providers)?,
    })
}
fn reserve_provider_state_root(
    accounts: &[ReserveProviderAccountV1],
) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
    canonical_domain_digest(PROVIDER_STATE_ROOT_DOMAIN_V1, &accounts.to_vec())
}
fn encode_bounded_artifact<T: norito::core::NoritoSerialize>(
    artifact: &T,
    bounds: ReputationFinalizedArchiveBounds,
) -> Result<Vec<u8>, ReputationFinalizedArchiveError> {
    let bytes = norito::to_bytes(artifact).map_err(ReputationFinalizedArchiveError::Encode)?;
    let size = bounded_bytes_len(&bytes);
    if size > bounds.max_record_bytes {
        return Err(ReputationFinalizedArchiveError::RecordTooLarge {
            size,
            maximum: bounds.max_record_bytes,
        });
    }
    Ok(bytes)
}
fn prepare_checkpoint_publication(
    index: &ArchiveIndex,
    bounds: ReputationFinalizedArchiveBounds,
    persisted: &PersistedReputationFinalizedVirtualBaseCheckpointV1,
) -> Result<Vec<u8>, ReputationFinalizedArchiveError> {
    let checkpoint_bytes = encode_bounded_artifact(persisted, bounds)?;
    let checkpoint_bytes_len = bounded_bytes_len(&checkpoint_bytes);
    if index.checkpoint_count >= bounds.max_entries.get()
        || index
            .total_bytes
            .checked_add(checkpoint_bytes_len)
            .is_none_or(|bytes| bytes > bounds.max_total_bytes)
    {
        return Err(ReputationFinalizedArchiveError::RetentionRequired {
            proposed_entries: index.anchor_count,
            maximum_entries: bounds.max_entries.get(),
            proposed_policy_entries: index.policy_count,
            maximum_policy_entries: bounds.max_entries.get(),
            proposed_bytes: index.total_bytes.saturating_add(checkpoint_bytes_len),
            maximum_bytes: bounds.max_total_bytes,
        });
    }
    Ok(checkpoint_bytes)
}
fn charge_archive_bytes(
    total: &mut u64,
    bytes: u64,
    bounds: ReputationFinalizedArchiveBounds,
) -> Result<(), ReputationFinalizedArchiveError> {
    *total = (*total).checked_add(bytes).ok_or(
        ReputationFinalizedArchiveError::ArchiveBytesExceeded {
            size: u64::MAX,
            maximum: bounds.max_total_bytes,
        },
    )?;
    if *total > bounds.max_total_bytes {
        return Err(ReputationFinalizedArchiveError::ArchiveBytesExceeded {
            size: *total,
            maximum: bounds.max_total_bytes,
        });
    }
    Ok(())
}
fn checked_artifact_count(
    current: usize,
    bounds: ReputationFinalizedArchiveBounds,
) -> Result<usize, ReputationFinalizedArchiveError> {
    let next =
        current
            .checked_add(1)
            .ok_or(ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
                maximum_entries: bounds.max_entries.get(),
            })?;
    if next > bounds.max_entries.get() {
        return Err(ReputationFinalizedArchiveError::ArchiveCapacityExceeded {
            maximum_entries: bounds.max_entries.get(),
        });
    }
    Ok(next)
}
fn ensure_insert_capacity(
    index: &ArchiveIndex,
    bounds: ReputationFinalizedArchiveBounds,
    anchor_bytes: u64,
    added_policy_count: usize,
    added_policy_bytes: u64,
) -> Result<(), ReputationFinalizedArchiveError> {
    let proposed_entries = index.anchor_count.saturating_add(1);
    let proposed_policy_entries = index.policy_count.saturating_add(added_policy_count);
    let proposed_bytes = index
        .total_bytes
        .checked_add(anchor_bytes)
        .and_then(|total| total.checked_add(added_policy_bytes))
        .unwrap_or(u64::MAX);
    if proposed_entries > bounds.max_entries.get()
        || proposed_policy_entries > bounds.max_entries.get()
        || proposed_bytes > bounds.max_total_bytes
    {
        return Err(ReputationFinalizedArchiveError::RetentionRequired {
            proposed_entries,
            maximum_entries: bounds.max_entries.get(),
            proposed_policy_entries,
            maximum_policy_entries: bounds.max_entries.get(),
            proposed_bytes,
            maximum_bytes: bounds.max_total_bytes,
        });
    }
    Ok(())
}
fn anchor_file_name(
    key: &ReputationFinalizedArchiveKeyV1,
) -> Result<String, ReputationFinalizedArchiveError> {
    let bytes = norito::to_bytes(key).map_err(ReputationFinalizedArchiveError::Encode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_DIGEST_DOMAIN_V1);
    hasher.update(&bytes);
    Ok(format!(
        "{}{ANCHOR_FILE_SUFFIX}",
        hex::encode(hasher.finalize().as_bytes())
    ))
}
fn policy_file_name(digest: [u8; 32]) -> String {
    format!("{}{POLICY_FILE_SUFFIX}", hex::encode(digest))
}
fn checkpoint_file_name(digest: [u8; 32]) -> String {
    format!("{}{CHECKPOINT_FILE_SUFFIX}", hex::encode(digest))
}
fn validate_policy_transition(
    previous: Option<&ReputationJournalAuthorityPolicyRecordV1>,
    current: &ReputationJournalAuthorityPolicyRecordV1,
    current_history: &[ReputationJournalAuthorityPolicyRecordV1],
    predecessor_finalized_at_unix_ms: u64,
    current_finalized_at_unix_ms: u64,
) -> Result<(), ReputationFinalizedArchiveError> {
    validate_authority_policy_history(current_history, current, current_finalized_at_unix_ms)?;
    let Some(previous) = previous else {
        return Ok(());
    };
    let previous_in_current_history = usize::try_from(previous.policy.revision)
        .ok()
        .and_then(|revision| revision.checked_sub(1))
        .and_then(|index| current_history.get(index));
    if previous_in_current_history != Some(previous) {
        return Err(ReputationFinalizedArchiveError::InvalidProjection {
            reason: "authority policy history substitutes the previous active record",
        });
    }
    if current.policy.revision == previous.policy.revision {
        if current != previous {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy activation record changed without a new revision",
            });
        }
        return Ok(());
    }
    if current.policy.revision < previous.policy.revision
        || current.activated_at_unix_ms < predecessor_finalized_at_unix_ms
    {
        return Err(ReputationFinalizedArchiveError::InvalidProjection {
            reason: "authority policy rotation regresses its exact predecessor anchor",
        });
    }
    Ok(())
}
fn validate_authority_policy_history(
    history: &[ReputationJournalAuthorityPolicyRecordV1],
    active: &ReputationJournalAuthorityPolicyRecordV1,
    finalized_at_unix_ms: u64,
) -> Result<(), ReputationFinalizedArchiveError> {
    if history.is_empty()
        || history.len() > MAX_AUTHORITY_POLICY_REVISIONS_V1
        || history.last() != Some(active)
    {
        return Err(ReputationFinalizedArchiveError::InvalidProjection {
            reason: "authority policy history is empty, over-bound, or does not end at the active record",
        });
    }
    let mut previous: Option<&ReputationJournalAuthorityPolicyRecordV1> = None;
    for record in history {
        record
            .validate()
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy history contains an invalid record",
            })?;
        if record.activated_at_unix_ms > finalized_at_unix_ms {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy history activates after the finalized anchor",
            });
        }
        match previous {
            None => {
                if record.policy.revision != 1 || record.policy.predecessor_policy_digest.is_some()
                {
                    return Err(ReputationFinalizedArchiveError::InvalidProjection {
                        reason: "authority policy history does not begin at revision one",
                    });
                }
            }
            Some(predecessor)
                if predecessor.policy.revision.checked_add(1) == Some(record.policy.revision)
                    && record.policy.predecessor_policy_digest
                        == Some(predecessor.policy_digest)
                    && predecessor.activated_at_unix_ms <= record.activated_at_unix_ms => {}
            Some(_) => {
                return Err(ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "authority policy history is skipped, duplicated, substituted, or non-monotonic",
                });
            }
        }
        previous = Some(record);
    }
    Ok(())
}
fn authority_policy_history_digest(
    history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<[u8; 32], ReputationFinalizedArchiveError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_HISTORY_DIGEST_DOMAIN_V1);
    hasher.update(&bounded_len(history.len())?.to_le_bytes());
    for record in history {
        let bytes = norito::to_bytes(record).map_err(ReputationFinalizedArchiveError::Encode)?;
        hasher.update(&bounded_len(bytes.len())?.to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(*hasher.finalize().as_bytes())
}
fn policy_record_by_policy_digest(
    index: &ArchiveIndex,
    policy_digest: [u8; 32],
) -> Result<
    Option<([u8; 32], &ReputationJournalAuthorityPolicyRecordV1)>,
    ReputationFinalizedArchiveError,
> {
    let mut matches = index
        .policies
        .iter()
        .filter(|(_, record)| record.policy_digest == policy_digest);
    let first = matches
        .next()
        .map(|(record_digest, record)| (*record_digest, record));
    if matches.next().is_some() {
        return Err(ReputationFinalizedArchiveError::PolicyConflict {
            digest: policy_digest,
        });
    }
    Ok(first)
}
fn resolve_authority_policy_history(
    index: &ArchiveIndex,
    active: &ReputationJournalAuthorityPolicyRecordV1,
    finalized_at_unix_ms: u64,
) -> Result<Vec<ReputationJournalAuthorityPolicyRecordV1>, ReputationFinalizedArchiveError> {
    active
        .validate()
        .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
            reason: "active reputation journal authority policy is invalid",
        })?;
    let mut descending = Vec::new();
    let mut current = active.clone();
    loop {
        if descending.len() >= MAX_AUTHORITY_POLICY_REVISIONS_V1 {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy history exceeds the archive recovery bound",
            });
        }
        let revision = current.policy.revision;
        let predecessor_digest = current.policy.predecessor_policy_digest;
        descending.push(current);
        match (revision, predecessor_digest) {
            (1, None) => break,
            (1, Some(_)) => {
                return Err(ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "first authority policy record has a predecessor",
                });
            }
            (_, None) => {
                return Err(ReputationFinalizedArchiveError::InvalidProjection {
                    reason: "authority policy history ended before revision one",
                });
            }
            (_, Some(predecessor_digest)) => {
                current = policy_record_by_policy_digest(index, predecessor_digest)?
                    .map(|(_, record)| record.clone())
                    .ok_or(ReputationFinalizedArchiveError::MissingPolicy {
                        digest: predecessor_digest,
                    })?;
            }
        }
    }
    descending.reverse();
    validate_authority_policy_history(&descending, active, finalized_at_unix_ms)?;
    Ok(descending)
}
fn ensure_append_only<T: PartialEq>(
    previous: &[T],
    current: &[T],
) -> Result<(), ReputationFinalizedArchiveError> {
    if current.len() < previous.len() || current.get(..previous.len()) != Some(previous) {
        return Err(ReputationFinalizedArchiveError::InvalidDelta {
            reason: "finalized event history does not extend its exact predecessor",
        });
    }
    Ok(())
}
fn appended_suffix<T: Clone + PartialEq>(
    previous: &[T],
    current: &[T],
) -> Result<Vec<T>, ReputationFinalizedArchiveError> {
    ensure_append_only(previous, current)?;
    Ok(current[previous.len()..].to_vec())
}
fn build_anchor_delta(
    previous: Option<&ReputationFinalizedProjectionV1>,
    current: &ReputationFinalizedProjectionV1,
) -> Result<ReputationFinalizedAnchorDeltaV1, ReputationFinalizedArchiveError> {
    let empty = ReputationFinalizedProjectionV1 {
        key: current.key.clone(),
        finalized_at_unix_ms: current.finalized_at_unix_ms,
        authority_policy: current.authority_policy.clone(),
        proof_outcomes: Vec::new(),
        journal_events: Vec::new(),
        repair_events: Vec::new(),
        orderbook_events: Vec::new(),
        reserve_events: Vec::new(),
        reserve_providers: Vec::new(),
    };
    let previous = previous.unwrap_or(&empty);
    let previous_accounts = previous
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    let current_accounts = current
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    let reserve_provider_removals = previous_accounts
        .keys()
        .filter(|provider_id| !current_accounts.contains_key(*provider_id))
        .copied()
        .collect();
    let reserve_provider_upserts = current_accounts
        .iter()
        .filter(|(provider_id, account)| previous_accounts.get(*provider_id) != Some(account))
        .map(|(_, account)| (**account).clone())
        .collect();
    Ok(ReputationFinalizedAnchorDeltaV1 {
        proof_outcomes: appended_suffix(&previous.proof_outcomes, &current.proof_outcomes)?,
        journal_events: appended_suffix(&previous.journal_events, &current.journal_events)?,
        repair_events: appended_suffix(&previous.repair_events, &current.repair_events)?,
        orderbook_events: appended_suffix(&previous.orderbook_events, &current.orderbook_events)?,
        reserve_events: appended_suffix(&previous.reserve_events, &current.reserve_events)?,
        reserve_provider_upserts,
        reserve_provider_removals,
    })
}
fn validate_full_feed_extends_retained_state<T>(
    domain: &[u8],
    previous: &ReputationRetainedFeedStateV1<T>,
    current: &[T],
    identity: impl Fn(&T) -> EventIdentity,
) -> Result<(), ReputationFinalizedArchiveError>
where
    T: Clone + PartialEq + norito::core::NoritoSerialize,
{
    let prefix_len = usize::try_from(previous.prefix.pruned_event_count).map_err(|_| {
        ReputationFinalizedArchiveError::InvalidProjection {
            reason: "compacted feed prefix does not fit this target",
        }
    })?;
    let retained_end = prefix_len
        .checked_add(previous.retained_suffix.len())
        .ok_or(ReputationFinalizedArchiveError::InvalidProjection {
            reason: "compacted feed retained range overflowed",
        })?;
    if current.len() < retained_end
        || current.get(prefix_len..retained_end) != Some(previous.retained_suffix.as_slice())
    {
        return Err(ReputationFinalizedArchiveError::InvalidDelta {
            reason: "finalized event history does not extend its compacted exact predecessor",
        });
    }
    if prefix_len != 0 {
        let mut digest = [0; 32];
        for event in &current[..prefix_len] {
            digest = rolling_domain_digest(domain, digest, event)?;
        }
        let terminal = current
            .get(prefix_len - 1)
            .map(|event| event_position(identity(event)));
        if digest != previous.prefix.rolling_prefix_digest
            || terminal != previous.prefix.pruned_through
        {
            return Err(ReputationFinalizedArchiveError::InvalidDelta {
                reason: "finalized event history disagrees with its compacted prefix commitment",
            });
        }
    }
    Ok(())
}
fn validate_projection_transition_from_state(
    previous: &ReputationReconstructionStateV1,
    current: &ReputationFinalizedProjectionV1,
    authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<(), ReputationFinalizedArchiveError> {
    if current.key.network_id != previous.key.network_id
        || current.key.height <= previous.key.height
        || current.finalized_at_unix_ms < previous.finalized_at_unix_ms
    {
        return Err(ReputationFinalizedArchiveError::InvalidManifest {
            reason: "anchor does not advance its compacted exact predecessor",
        });
    }
    validate_policy_transition(
        Some(&previous.authority_policy),
        &current.authority_policy,
        authority_policy_history,
        previous.finalized_at_unix_ms,
        current.finalized_at_unix_ms,
    )?;
    validate_full_feed_extends_retained_state(
        PROOF_PREFIX_DIGEST_DOMAIN_V1,
        &previous.proof_outcomes,
        &current.proof_outcomes,
        proof_event_identity,
    )?;
    validate_full_feed_extends_retained_state(
        JOURNAL_PREFIX_DIGEST_DOMAIN_V1,
        &previous.journal_events,
        &current.journal_events,
        journal_event_identity,
    )?;
    let journal_prefix_len = usize::try_from(previous.journal_events.prefix.pruned_event_count)
        .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
            reason: "compacted journal prefix does not fit this target",
        })?;
    let journal_prefix = current.journal_events.get(..journal_prefix_len).ok_or(
        ReputationFinalizedArchiveError::InvalidDelta {
            reason: "finalized journal history omits its compacted source-head prefix",
        },
    )?;
    if merge_journal_source_heads(&[], journal_prefix)? != previous.journal_prefix_source_heads {
        return Err(ReputationFinalizedArchiveError::InvalidDelta {
            reason: "finalized journal history disagrees with its compacted source-head index",
        });
    }
    validate_full_feed_extends_retained_state(
        REPAIR_PREFIX_DIGEST_DOMAIN_V1,
        &previous.repair_events,
        &current.repair_events,
        repair_event_identity,
    )?;
    validate_full_feed_extends_retained_state(
        ORDERBOOK_PREFIX_DIGEST_DOMAIN_V1,
        &previous.orderbook_events,
        &current.orderbook_events,
        orderbook_event_identity,
    )?;
    validate_full_feed_extends_retained_state(
        RESERVE_PREFIX_DIGEST_DOMAIN_V1,
        &previous.reserve_events,
        &current.reserve_events,
        reserve_event_identity,
    )?;
    let previous_accounts = previous
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    for account in &current.reserve_providers {
        if let Some(previous) = previous_accounts.get(&account.terms.provider_id)
            && *previous != account
            && (previous.terms != account.terms
                || account.revision <= previous.revision
                || account.updated_at_unix < previous.updated_at_unix)
        {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "reserve provider update violates immutable terms or monotonic revision",
            });
        }
    }
    Ok(())
}
fn validate_retained_feed_extension<T: PartialEq>(
    previous: &ReputationRetainedFeedStateV1<T>,
    current: &ReputationRetainedFeedStateV1<T>,
) -> Result<(), ReputationFinalizedArchiveError> {
    if current.prefix != previous.prefix {
        return Err(ReputationFinalizedArchiveError::InvalidDelta {
            reason: "captured finalized event suffix substituted its compacted prefix",
        });
    }
    ensure_append_only(&previous.retained_suffix, &current.retained_suffix)
}
fn validate_reconstruction_state_transition(
    previous: &ReputationReconstructionStateV1,
    current: &ReputationReconstructionStateV1,
    authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<(), ReputationFinalizedArchiveError> {
    if current.key.network_id != previous.key.network_id
        || current.key.height <= previous.key.height
        || current.finalized_at_unix_ms < previous.finalized_at_unix_ms
    {
        return Err(ReputationFinalizedArchiveError::InvalidManifest {
            reason: "anchor does not advance its compacted exact predecessor",
        });
    }
    validate_policy_transition(
        Some(&previous.authority_policy),
        &current.authority_policy,
        authority_policy_history,
        previous.finalized_at_unix_ms,
        current.finalized_at_unix_ms,
    )?;
    validate_retained_feed_extension(&previous.proof_outcomes, &current.proof_outcomes)?;
    validate_retained_feed_extension(&previous.journal_events, &current.journal_events)?;
    if current.journal_prefix_source_heads != previous.journal_prefix_source_heads {
        return Err(ReputationFinalizedArchiveError::InvalidDelta {
            reason: "captured finalized journal suffix substituted its compacted source-head index",
        });
    }
    validate_retained_feed_extension(&previous.repair_events, &current.repair_events)?;
    validate_retained_feed_extension(&previous.orderbook_events, &current.orderbook_events)?;
    validate_retained_feed_extension(&previous.reserve_events, &current.reserve_events)?;
    let previous_accounts = previous
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    for account in &current.reserve_providers {
        if let Some(previous) = previous_accounts.get(&account.terms.provider_id)
            && *previous != account
            && (previous.terms != account.terms
                || account.revision <= previous.revision
                || account.updated_at_unix < previous.updated_at_unix)
        {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "reserve provider update violates immutable terms or monotonic revision",
            });
        }
    }
    Ok(())
}
fn retained_feed_delta<T: Clone + PartialEq>(
    previous: Option<&ReputationRetainedFeedStateV1<T>>,
    current: &ReputationRetainedFeedStateV1<T>,
) -> Result<Vec<T>, ReputationFinalizedArchiveError> {
    previous.map_or_else(
        || Ok(current.retained_suffix.clone()),
        |previous| appended_suffix(&previous.retained_suffix, &current.retained_suffix),
    )
}
fn build_anchor_delta_from_reconstruction_state(
    previous: Option<&ReputationReconstructionStateV1>,
    current: &ReputationReconstructionStateV1,
) -> Result<ReputationFinalizedAnchorDeltaV1, ReputationFinalizedArchiveError> {
    let previous_accounts = previous
        .map(|state| state.reserve_providers.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    let current_accounts = current
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    Ok(ReputationFinalizedAnchorDeltaV1 {
        proof_outcomes: retained_feed_delta(
            previous.map(|state| &state.proof_outcomes),
            &current.proof_outcomes,
        )?,
        journal_events: retained_feed_delta(
            previous.map(|state| &state.journal_events),
            &current.journal_events,
        )?,
        repair_events: retained_feed_delta(
            previous.map(|state| &state.repair_events),
            &current.repair_events,
        )?,
        orderbook_events: retained_feed_delta(
            previous.map(|state| &state.orderbook_events),
            &current.orderbook_events,
        )?,
        reserve_events: retained_feed_delta(
            previous.map(|state| &state.reserve_events),
            &current.reserve_events,
        )?,
        reserve_provider_removals: previous_accounts
            .keys()
            .filter(|provider_id| !current_accounts.contains_key(*provider_id))
            .copied()
            .collect(),
        reserve_provider_upserts: current_accounts
            .iter()
            .filter(|(provider_id, account)| previous_accounts.get(*provider_id) != Some(account))
            .map(|(_, account)| (**account).clone())
            .collect(),
    })
}
fn retained_suffix_start<T>(
    feed: &ReputationRetainedFeedStateV1<T>,
) -> Result<usize, ReputationFinalizedArchiveError> {
    usize::try_from(feed.prefix.pruned_event_count)
        .ok()
        .and_then(|prefix| prefix.checked_add(feed.retained_suffix.len()))
        .ok_or(ReputationFinalizedArchiveError::InvalidProjection {
            reason: "compacted feed high-water mark does not fit this target",
        })
}
fn build_anchor_delta_from_state(
    previous: Option<&ReputationReconstructionStateV1>,
    current: &ReputationFinalizedProjectionV1,
    authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<ReputationFinalizedAnchorDeltaV1, ReputationFinalizedArchiveError> {
    let Some(previous) = previous else {
        return build_anchor_delta(None, current);
    };
    validate_projection_transition_from_state(previous, current, authority_policy_history)?;
    let previous_accounts = previous
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    let current_accounts = current
        .reserve_providers
        .iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    Ok(ReputationFinalizedAnchorDeltaV1 {
        proof_outcomes: current.proof_outcomes[retained_suffix_start(&previous.proof_outcomes)?..]
            .to_vec(),
        journal_events: current.journal_events[retained_suffix_start(&previous.journal_events)?..]
            .to_vec(),
        repair_events: current.repair_events[retained_suffix_start(&previous.repair_events)?..]
            .to_vec(),
        orderbook_events: current.orderbook_events
            [retained_suffix_start(&previous.orderbook_events)?..]
            .to_vec(),
        reserve_events: current.reserve_events[retained_suffix_start(&previous.reserve_events)?..]
            .to_vec(),
        reserve_provider_removals: previous_accounts
            .keys()
            .filter(|provider_id| !current_accounts.contains_key(*provider_id))
            .copied()
            .collect(),
        reserve_provider_upserts: current_accounts
            .iter()
            .filter(|(provider_id, account)| previous_accounts.get(*provider_id) != Some(account))
            .map(|(_, account)| (**account).clone())
            .collect(),
    })
}
fn reconstruction_state_from_full_successor(
    previous: Option<&ReputationReconstructionStateV1>,
    current: &ReputationFinalizedProjectionV1,
    authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<ReputationReconstructionStateV1, ReputationFinalizedArchiveError> {
    let Some(previous) = previous else {
        return Ok(ReputationReconstructionStateV1::from_projection(
            current.clone(),
        ));
    };
    validate_projection_transition_from_state(previous, current, authority_policy_history)?;
    let state = ReputationReconstructionStateV1 {
        key: current.key.clone(),
        finalized_at_unix_ms: current.finalized_at_unix_ms,
        authority_policy: current.authority_policy.clone(),
        proof_outcomes: ReputationRetainedFeedStateV1 {
            prefix: previous.proof_outcomes.prefix,
            retained_suffix: current.proof_outcomes[usize::try_from(
                previous.proof_outcomes.prefix.pruned_event_count,
            )
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "proof prefix does not fit this target",
            })?..]
                .to_vec(),
        },
        journal_events: ReputationRetainedFeedStateV1 {
            prefix: previous.journal_events.prefix,
            retained_suffix: current.journal_events[usize::try_from(
                previous.journal_events.prefix.pruned_event_count,
            )
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "journal prefix does not fit this target",
            })?..]
                .to_vec(),
        },
        journal_prefix_source_heads: previous.journal_prefix_source_heads.clone(),
        repair_events: ReputationRetainedFeedStateV1 {
            prefix: previous.repair_events.prefix,
            retained_suffix: current.repair_events[usize::try_from(
                previous.repair_events.prefix.pruned_event_count,
            )
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "repair prefix does not fit this target",
            })?..]
                .to_vec(),
        },
        orderbook_events: ReputationRetainedFeedStateV1 {
            prefix: previous.orderbook_events.prefix,
            retained_suffix: current.orderbook_events[usize::try_from(
                previous.orderbook_events.prefix.pruned_event_count,
            )
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "orderbook prefix does not fit this target",
            })?..]
                .to_vec(),
        },
        reserve_events: ReputationRetainedFeedStateV1 {
            prefix: previous.reserve_events.prefix,
            retained_suffix: current.reserve_events[usize::try_from(
                previous.reserve_events.prefix.pruned_event_count,
            )
            .map_err(|_| ReputationFinalizedArchiveError::InvalidProjection {
                reason: "reserve prefix does not fit this target",
            })?..]
                .to_vec(),
        },
        reserve_providers: current.reserve_providers.clone(),
    };
    state.validate()?;
    Ok(state)
}
fn apply_anchor_delta_to_state(
    previous: Option<ReputationReconstructionStateV1>,
    previous_anchor_digest: Option<[u8; 32]>,
    persisted: &PersistedReputationFinalizedAnchorV1,
    policy: &ReputationJournalAuthorityPolicyRecordV1,
    authority_policy_history: &[ReputationJournalAuthorityPolicyRecordV1],
) -> Result<ReputationReconstructionStateV1, ReputationFinalizedArchiveError> {
    persisted.validate_standalone()?;
    let manifest = &persisted.manifest;
    match (
        &previous,
        &manifest.predecessor,
        previous_anchor_digest,
        manifest.predecessor_anchor_digest,
    ) {
        (None, None, None, None) => {
            validate_policy_transition(
                None,
                policy,
                authority_policy_history,
                0,
                manifest.finalized_at_unix_ms,
            )?;
        }
        (
            Some(previous),
            Some(predecessor),
            Some(previous_anchor_digest),
            Some(manifest_predecessor_anchor_digest),
        ) if predecessor == &previous.key
            && previous_anchor_digest == manifest_predecessor_anchor_digest =>
        {
            if manifest.finalized_at_unix_ms < previous.finalized_at_unix_ms {
                return Err(ReputationFinalizedArchiveError::InvalidManifest {
                    reason: "anchor timestamp regresses from its exact predecessor",
                });
            }
            validate_policy_transition(
                Some(&previous.authority_policy),
                policy,
                authority_policy_history,
                previous.finalized_at_unix_ms,
                manifest.finalized_at_unix_ms,
            )?;
        }
        _ => {
            return Err(ReputationFinalizedArchiveError::InvalidManifest {
                reason: "anchor manifest predecessor key or anchor digest does not match archive order",
            });
        }
    }
    if canonical_domain_digest(POLICY_RECORD_DIGEST_DOMAIN_V1, policy)?
        != manifest.policy_record_digest
    {
        return Err(ReputationFinalizedArchiveError::MissingPolicy {
            digest: manifest.policy_record_digest,
        });
    }
    let previous_marks = previous
        .as_ref()
        .map(ReputationReconstructionStateV1::high_water_marks)
        .transpose()?
        .unwrap_or_default();
    let expected_marks = ReputationFeedHighWaterMarksV1 {
        proof_outcomes: add_suffix_len(
            previous_marks.proof_outcomes,
            persisted.delta.proof_outcomes.len(),
        )?,
        journal_events: add_suffix_len(
            previous_marks.journal_events,
            persisted.delta.journal_events.len(),
        )?,
        repair_events: add_suffix_len(
            previous_marks.repair_events,
            persisted.delta.repair_events.len(),
        )?,
        orderbook_events: add_suffix_len(
            previous_marks.orderbook_events,
            persisted.delta.orderbook_events.len(),
        )?,
        reserve_events: add_suffix_len(
            previous_marks.reserve_events,
            persisted.delta.reserve_events.len(),
        )?,
    };
    if manifest.high_water_marks != expected_marks {
        return Err(ReputationFinalizedArchiveError::InvalidManifest {
            reason: "anchor feed high-water marks do not match its immutable suffixes",
        });
    }
    validate_delta_event_anchors(persisted)?;
    let mut state = previous.unwrap_or_else(|| ReputationReconstructionStateV1 {
        key: manifest.key.clone(),
        finalized_at_unix_ms: manifest.finalized_at_unix_ms,
        authority_policy: policy.clone(),
        proof_outcomes: ReputationRetainedFeedStateV1::default(),
        journal_events: ReputationRetainedFeedStateV1::default(),
        journal_prefix_source_heads: Vec::new(),
        repair_events: ReputationRetainedFeedStateV1::default(),
        orderbook_events: ReputationRetainedFeedStateV1::default(),
        reserve_events: ReputationRetainedFeedStateV1::default(),
        reserve_providers: Vec::new(),
    });
    state.key = manifest.key.clone();
    state.finalized_at_unix_ms = manifest.finalized_at_unix_ms;
    state.authority_policy = policy.clone();
    state
        .proof_outcomes
        .retained_suffix
        .extend(persisted.delta.proof_outcomes.iter().cloned());
    state
        .journal_events
        .retained_suffix
        .extend(persisted.delta.journal_events.iter().cloned());
    state
        .repair_events
        .retained_suffix
        .extend(persisted.delta.repair_events.iter().cloned());
    state
        .orderbook_events
        .retained_suffix
        .extend(persisted.delta.orderbook_events.iter().cloned());
    state
        .reserve_events
        .retained_suffix
        .extend(persisted.delta.reserve_events.iter().cloned());
    let mut providers = state
        .reserve_providers
        .into_iter()
        .map(|account| (account.terms.provider_id, account))
        .collect::<BTreeMap<_, _>>();
    for provider_id in &persisted.delta.reserve_provider_removals {
        if providers.remove(provider_id).is_none() {
            return Err(ReputationFinalizedArchiveError::InvalidDelta {
                reason: "reserve provider delta removes a missing provider",
            });
        }
    }
    for account in &persisted.delta.reserve_provider_upserts {
        if let Some(previous) = providers.get(&account.terms.provider_id) {
            if previous == account
                || previous.terms != account.terms
                || account.revision <= previous.revision
                || account.updated_at_unix < previous.updated_at_unix
            {
                return Err(ReputationFinalizedArchiveError::InvalidDelta {
                    reason: "reserve provider upsert is redundant or non-monotonic",
                });
            }
        }
        providers.insert(account.terms.provider_id, account.clone());
    }
    state.reserve_providers = providers.into_values().collect();
    if bounded_len(state.reserve_providers.len())? != manifest.reserve_provider_count
        || reserve_provider_state_root(&state.reserve_providers)?
            != manifest.reserve_provider_state_root
    {
        return Err(ReputationFinalizedArchiveError::ProviderStateRootMismatch);
    }
    state.validate()?;
    let (_, journal_source_head_count, journal_source_head_root) = journal_source_head_commitment(
        &state.journal_prefix_source_heads,
        &state.journal_events.retained_suffix,
    )?;
    if journal_source_head_count != manifest.journal_source_head_count
        || journal_source_head_root != manifest.journal_source_head_root
    {
        return Err(ReputationFinalizedArchiveError::InvalidManifest {
            reason: "anchor journal source-head commitment does not match its reconstructed event history",
        });
    }
    Ok(state)
}
fn add_suffix_len(
    previous: u64,
    suffix_len: usize,
) -> Result<u64, ReputationFinalizedArchiveError> {
    previous.checked_add(bounded_len(suffix_len)?).ok_or(
        ReputationFinalizedArchiveError::InvalidManifest {
            reason: "anchor feed high-water mark overflow",
        },
    )
}
fn validate_delta_event_anchors(
    persisted: &PersistedReputationFinalizedAnchorV1,
) -> Result<(), ReputationFinalizedArchiveError> {
    let anchor = &persisted.manifest.key;
    validate_event_suffix_anchor(&persisted.delta.proof_outcomes, anchor, |event| {
        EventIdentity::from((
            event.sequence,
            event.block_height,
            event.block_hash,
            event.event_index,
        ))
    })?;
    validate_event_suffix_anchor(&persisted.delta.journal_events, anchor, |event| {
        EventIdentity::from((
            event.sequence,
            event.block_height,
            event.block_hash,
            event.event_index,
        ))
    })?;
    for event in &persisted.delta.journal_events {
        event
            .entry
            .validate()
            .map_err(|_| ReputationFinalizedArchiveError::InvalidDelta {
                reason: "reputation journal suffix contains an invalid entry",
            })?;
        if event.recorded_at_unix_ms == 0
            || event.recorded_at_unix_ms > persisted.manifest.finalized_at_unix_ms
            || event.entry.source_time_unix_ms > event.recorded_at_unix_ms
        {
            return Err(ReputationFinalizedArchiveError::InvalidDelta {
                reason: "reputation journal suffix timestamp exceeds its anchor",
            });
        }
    }
    validate_event_suffix_anchor(&persisted.delta.repair_events, anchor, |event| {
        EventIdentity::from((
            event.sequence,
            event.block_height,
            event.block_hash,
            event.event_index,
        ))
    })?;
    validate_event_suffix_anchor(&persisted.delta.orderbook_events, anchor, |event| {
        EventIdentity::from((
            event.sequence,
            event.block_height,
            event.block_hash,
            event.event_index,
        ))
    })?;
    validate_event_suffix_anchor(&persisted.delta.reserve_events, anchor, |event| {
        EventIdentity::from((
            event.sequence,
            event.block_height,
            event.block_hash,
            event.event_index,
        ))
    })
}
fn validate_event_suffix_anchor<T>(
    events: &[T],
    anchor: &ReputationFinalizedArchiveKeyV1,
    identity: impl Fn(&T) -> EventIdentity,
) -> Result<(), ReputationFinalizedArchiveError> {
    for event in events {
        let event = identity(event);
        let at_anchor_height = event.block_height == anchor.height;
        if event.sequence == 0
            || event.block_height == 0
            || event.block_hash == [0; 32]
            || event.block_height > anchor.height
            || (at_anchor_height && event.block_hash != anchor.block_hash)
        {
            return Err(ReputationFinalizedArchiveError::InvalidDelta {
                reason: "event suffix crosses or disagrees with its finalized anchor",
            });
        }
    }
    Ok(())
}
fn validate_projection_against_index(
    projection: &ReputationFinalizedProjectionV1,
    index: &ArchiveIndex,
) -> Result<(), ReputationFinalizedArchiveError> {
    validate_feed_against_index(projection, index, &projection.proof_outcomes, |event| {
        (event.block_height, event.block_hash)
    })?;
    validate_feed_against_index(projection, index, &projection.journal_events, |event| {
        (event.block_height, event.block_hash)
    })?;
    validate_feed_against_index(projection, index, &projection.repair_events, |event| {
        (event.block_height, event.block_hash)
    })?;
    validate_feed_against_index(projection, index, &projection.orderbook_events, |event| {
        (event.block_height, event.block_hash)
    })?;
    validate_feed_against_index(projection, index, &projection.reserve_events, |event| {
        (event.block_height, event.block_hash)
    })
}
fn validate_reconstruction_state_against_index(
    state: &ReputationReconstructionStateV1,
    index: &ArchiveIndex,
) -> Result<(), ReputationFinalizedArchiveError> {
    validate_state_feed_against_index(
        &state.key,
        index,
        &state.proof_outcomes.retained_suffix,
        |event| (event.block_height, event.block_hash),
    )?;
    validate_state_feed_against_index(
        &state.key,
        index,
        &state.journal_events.retained_suffix,
        |event| (event.block_height, event.block_hash),
    )?;
    validate_state_feed_against_index(
        &state.key,
        index,
        &state.repair_events.retained_suffix,
        |event| (event.block_height, event.block_hash),
    )?;
    validate_state_feed_against_index(
        &state.key,
        index,
        &state.orderbook_events.retained_suffix,
        |event| (event.block_height, event.block_hash),
    )?;
    validate_state_feed_against_index(
        &state.key,
        index,
        &state.reserve_events.retained_suffix,
        |event| (event.block_height, event.block_hash),
    )
}
fn validate_feed_against_index<T>(
    projection: &ReputationFinalizedProjectionV1,
    index: &ArchiveIndex,
    events: &[T],
    identity: impl Fn(&T) -> (u64, [u8; 32]),
) -> Result<(), ReputationFinalizedArchiveError> {
    for event in events {
        let (height, block_hash) = identity(event);
        if let Some(anchor) = index
            .by_height
            .get(&(projection.key.network_id.clone(), height))
            && anchor.manifest.key.block_hash != block_hash
        {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "event block hash disagrees with an archived finalized anchor",
            });
        }
    }
    Ok(())
}
fn validate_state_feed_against_index<T>(
    key: &ReputationFinalizedArchiveKeyV1,
    index: &ArchiveIndex,
    events: &[T],
    identity: impl Fn(&T) -> (u64, [u8; 32]),
) -> Result<(), ReputationFinalizedArchiveError> {
    for event in events {
        let (height, block_hash) = identity(event);
        if let Some(anchor) = index.by_height.get(&(key.network_id.clone(), height))
            && anchor.manifest.key.block_hash != block_hash
        {
            return Err(ReputationFinalizedArchiveError::InvalidProjection {
                reason: "event block hash disagrees with an archived finalized anchor",
            });
        }
    }
    Ok(())
}
fn validate_archive_root_path(path: &Path) -> Result<(), ReputationFinalizedArchiveError> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ReputationFinalizedArchiveError::InvalidStorage {
            path: path.to_path_buf(),
            reason: "archive root must be an absolute normalized non-root path",
        });
    }
    Ok(())
}
fn verify_existing_directory_ancestry(path: &Path) -> Result<(), ReputationFinalizedArchiveError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path: current,
                    reason: "archive ancestry contains a symlink or non-directory component",
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(ReputationFinalizedArchiveError::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}
fn verify_absolute_directory_ancestry(path: &Path) -> Result<(), ReputationFinalizedArchiveError> {
    validate_archive_root_path(path)?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|source| {
            ReputationFinalizedArchiveError::Read {
                path: current.clone(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: current,
                reason: "archive ancestry contains a symlink or non-directory component",
            });
        }
    }
    #[cfg(unix)]
    verify_unix_directory_ancestry(path)?;
    Ok(())
}
#[cfg(unix)]
fn verify_unix_directory_ancestry(path: &Path) -> Result<(), ReputationFinalizedArchiveError> {
    open_unix_directory_ancestry(path).map(drop)
}
#[cfg(unix)]
fn open_unix_directory_ancestry(path: &Path) -> Result<fs::File, ReputationFinalizedArchiveError> {
    use std::os::unix::fs::MetadataExt as _;
    let mut current = fs::File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)
        .map_err(|source| ReputationFinalizedArchiveError::Read {
            path: PathBuf::from("/"),
            source,
        })?,
    );
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let before = rustix::fs::statat(&current, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: path.to_path_buf(),
                reason: "archive ancestry is not a direct directory chain",
            });
        }
        let child = fs::File::from(
            rustix::fs::openat(
                &current,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: path.to_path_buf(),
                source,
            })?,
        );
        let opened = child
            .metadata()
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        let after = rustix::fs::statat(&current, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if !opened.is_dir()
            || crate::kura::unix_device_identity(before.st_dev) != opened.dev()
            || before.st_ino != opened.ino()
            || crate::kura::unix_device_identity(after.st_dev) != opened.dev()
            || after.st_ino != opened.ino()
        {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: path.to_path_buf(),
                reason: "archive ancestry changed during no-follow traversal",
            });
        }
        current = child;
    }
    Ok(current)
}
fn validate_root_namespace(root: &Path) -> Result<(), ReputationFinalizedArchiveError> {
    for entry in fs::read_dir(root).map_err(|source| ReputationFinalizedArchiveError::Read {
        path: root.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| ReputationFinalizedArchiveError::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        if name != ANCHORS_DIRECTORY
            && name != CHECKPOINTS_DIRECTORY
            && name != POLICIES_DIRECTORY
            && name != WRITER_LOCK_FILE
        {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: entry.path(),
                reason: "unknown object in finalized reputation archive root",
            });
        }
    }
    Ok(())
}
fn recover_staged_directory(
    directory: &Path,
    expected_directory_identity: ArchiveFileIdentity,
    max_record_bytes: u64,
    canonical_suffix: &str,
) -> Result<(), ReputationFinalizedArchiveError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let directory_file = open_unix_directory_ancestry(directory)?;
        verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
        let entries = rustix::fs::Dir::read_from(&directory_file)
            .map_err(io::Error::from)
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: directory.to_path_buf(),
                source,
            })?;
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(io::Error::from).map_err(|source| {
                ReputationFinalizedArchiveError::Read {
                    path: directory.to_path_buf(),
                    source,
                }
            })?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            let Some(name_utf8) = name.to_str() else {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path: directory.join(name),
                    reason: "archive staged filename is not UTF-8",
                });
            };
            if !name_utf8.starts_with(STAGED_FILE_PREFIX) {
                continue;
            }
            let metadata =
                rustix::fs::statat(&directory_file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(io::Error::from)
                    .map_err(|source| ReputationFinalizedArchiveError::Read {
                        path: directory.join(name),
                        source,
                    })?;
            if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                != rustix::fs::FileType::RegularFile
                || u64::try_from(metadata.st_size)
                    .ok()
                    .is_none_or(|size| size > max_record_bytes)
                || match metadata.st_nlink as u64 {
                    1 => false,
                    2 => !unix_staged_file_has_canonical_target(
                        &directory_file,
                        name,
                        &metadata,
                        canonical_suffix,
                    )
                    .map_err(io::Error::from)
                    .map_err(|source| {
                        ReputationFinalizedArchiveError::Read {
                            path: directory.join(name),
                            source,
                        }
                    })?,
                    _ => true,
                }
            {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path: directory.join(name),
                    reason: "staged archive artifact is neither private nor linked to one canonical target",
                });
            }
            rustix::fs::unlinkat(&directory_file, name, rustix::fs::AtFlags::empty())
                .map_err(io::Error::from)
                .map_err(|source| ReputationFinalizedArchiveError::Write {
                    path: directory.join(name),
                    source,
                })?;
            removed = true;
        }
        if removed {
            directory_file.sync_all().map_err(|source| {
                ReputationFinalizedArchiveError::NamespaceSync {
                    path: directory.to_path_buf(),
                    source,
                }
            })?;
        }
        return verify_unix_directory_handle(
            &directory_file,
            expected_directory_identity,
            directory,
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (expected_directory_identity, canonical_suffix);
        for entry in
            fs::read_dir(directory).map_err(|source| ReputationFinalizedArchiveError::Read {
                path: directory.to_path_buf(),
                source,
            })?
        {
            let entry = entry.map_err(|source| ReputationFinalizedArchiveError::Read {
                path: directory.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ReputationFinalizedArchiveError::InvalidStorage {
                    path,
                    reason: "archive staged filename is not UTF-8",
                });
            };
            if !name.starts_with(STAGED_FILE_PREFIX) {
                continue;
            }
            let _ = max_record_bytes;
            return Err(ReputationFinalizedArchiveError::UnsupportedPlatform {
                operation: "descriptor-relative staged-artifact recovery",
                platform: std::env::consts::OS,
            });
        }
        Ok(())
    }
}
fn publish_immutable_bytes(
    directory: &Path,
    expected_directory_identity: ArchiveFileIdentity,
    target: &Path,
    bytes: &[u8],
) -> Result<(), ReputationFinalizedArchiveError> {
    if target.parent() != Some(directory) {
        return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
            path: target.to_path_buf(),
        });
    }
    let target_name =
        target
            .file_name()
            .ok_or_else(|| ReputationFinalizedArchiveError::PathBindingMismatch {
                path: target.to_path_buf(),
            })?;
    #[cfg(unix)]
    {
        return publish_immutable_bytes_unix_with_hooks(
            directory,
            expected_directory_identity,
            target,
            target_name,
            bytes,
            || {},
            || {},
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (expected_directory_identity, target_name, bytes);
        Err(ReputationFinalizedArchiveError::UnsupportedPlatform {
            operation: "descriptor-relative no-reparse immutable publication",
            platform: std::env::consts::OS,
        })
    }
}
fn unlink_immutable_archive_file(
    directory: &Path,
    expected_directory_identity: ArchiveFileIdentity,
    target: &Path,
) -> Result<(), ReputationFinalizedArchiveError> {
    if target.parent() != Some(directory) {
        return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
            path: target.to_path_buf(),
        });
    }
    let target_name =
        target
            .file_name()
            .ok_or_else(|| ReputationFinalizedArchiveError::PathBindingMismatch {
                path: target.to_path_buf(),
            })?;
    #[cfg(unix)]
    {
        let directory_file = open_unix_directory_ancestry(directory)?;
        verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
        let before = rustix::fs::statat(
            &directory_file,
            target_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)
        .map_err(|source| ReputationFinalizedArchiveError::Read {
            path: target.to_path_buf(),
            source,
        })?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
            || before.st_nlink as u64 != 1
        {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: target.to_path_buf(),
                reason: "compaction target is not a single-link direct regular file",
            });
        }
        rustix::fs::unlinkat(&directory_file, target_name, rustix::fs::AtFlags::empty())
            .map_err(io::Error::from)
            .map_err(|source| ReputationFinalizedArchiveError::Write {
                path: target.to_path_buf(),
                source,
            })?;
        directory_file.sync_all().map_err(|source| {
            ReputationFinalizedArchiveError::NamespaceSync {
                path: directory.to_path_buf(),
                source,
            }
        })?;
        verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)
    }
    #[cfg(not(unix))]
    {
        let _ = (expected_directory_identity, target_name);
        Err(ReputationFinalizedArchiveError::UnsupportedPlatform {
            operation: "descriptor-relative immutable artifact unlink",
            platform: std::env::consts::OS,
        })
    }
}
#[cfg(unix)]
fn publish_immutable_bytes_unix_with_hooks<BeforeCreate, BeforeLink>(
    directory: &Path,
    expected_directory_identity: ArchiveFileIdentity,
    target: &Path,
    target_name: &OsStr,
    bytes: &[u8],
    before_create: BeforeCreate,
    before_link: BeforeLink,
) -> Result<(), ReputationFinalizedArchiveError>
where
    BeforeCreate: FnOnce(),
    BeforeLink: FnOnce(),
{
    validate_archive_root_path(directory)?;
    if !matches!(
        Path::new(target_name).components().next(),
        Some(Component::Normal(_))
    ) || Path::new(target_name).components().count() != 1
    {
        return Err(ReputationFinalizedArchiveError::PathBindingMismatch {
            path: target.to_path_buf(),
        });
    }
    let directory_file = open_unix_directory_ancestry(directory)?;
    verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
    before_create();
    let (mut staged_file, staged_name) =
        create_unix_staged_file(&directory_file).map_err(|source| {
            ReputationFinalizedArchiveError::Write {
                path: directory.to_path_buf(),
                source,
            }
        })?;
    let staged_path = directory.join(&staged_name);
    let mut staged = UnixStagedArtifact {
        directory: &directory_file,
        name: staged_name,
        armed: true,
    };
    staged_file
        .write_all(bytes)
        .and_then(|()| staged_file.sync_all())
        .map_err(|source| ReputationFinalizedArchiveError::Write {
            path: staged_path.clone(),
            source,
        })?;
    let staged_metadata =
        staged_file
            .metadata()
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: staged_path.clone(),
                source,
            })?;
    verify_unix_named_file(
        &directory_file,
        &staged.name,
        &staged_metadata,
        bounded_bytes_len(bytes),
        1,
    )
    .map_err(|source| ReputationFinalizedArchiveError::InvalidStorage {
        path: staged_path.clone(),
        reason: if source.kind() == io::ErrorKind::InvalidData {
            "staged archive artifact changed before immutable publication"
        } else {
            "staged archive artifact could not be bound before immutable publication"
        },
    })?;
    before_link();
    verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
    let published_new = match rustix::fs::linkat(
        &directory_file,
        &staged.name,
        &directory_file,
        target_name,
        rustix::fs::AtFlags::empty(),
    ) {
        Ok(()) => {
            let linked_metadata =
                staged_file
                    .metadata()
                    .map_err(|source| ReputationFinalizedArchiveError::Read {
                        path: staged_path.clone(),
                        source,
                    })?;
            let linked = rustix::fs::statat(
                &directory_file,
                target_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)
            .and_then(|linked| {
                if unix_stat_matches_metadata(&linked, &linked_metadata, 2) {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "published archive link does not identify the staged artifact",
                    ))
                }
            });
            if let Err(source) = linked {
                let _ = rustix::fs::unlinkat(
                    &directory_file,
                    target_name,
                    rustix::fs::AtFlags::empty(),
                );
                let _ = directory_file.sync_all();
                return Err(ReputationFinalizedArchiveError::Write {
                    path: target.to_path_buf(),
                    source,
                });
            }
            true
        }
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => {
            let _ = staged.unlink();
            let _ = directory_file.sync_all();
            return Err(ReputationFinalizedArchiveError::Write {
                path: target.to_path_buf(),
                source: io::Error::from(error),
            });
        }
    };
    if let Err(unlink_error) = staged.unlink() {
        let rollback = if published_new {
            rustix::fs::unlinkat(&directory_file, target_name, rustix::fs::AtFlags::empty())
        } else {
            Ok(())
        };
        let _ = directory_file.sync_all();
        let source = match rollback {
            Ok(()) => io::Error::from(unlink_error),
            Err(rollback_error) => io::Error::other(format!(
                "failed to remove staged artifact ({unlink_error}) and roll back its published link ({rollback_error})"
            )),
        };
        return Err(ReputationFinalizedArchiveError::Write {
            path: staged_path,
            source,
        });
    }
    directory_file
        .sync_all()
        .map_err(|source| ReputationFinalizedArchiveError::NamespaceSync {
            path: directory.to_path_buf(),
            source,
        })?;
    let published =
        read_bounded_archive_file_at_unix(&directory_file, target_name, bounded_bytes_len(bytes))
            .map_err(|source| ReputationFinalizedArchiveError::Read {
            path: target.to_path_buf(),
            source,
        })?;
    if published != bytes {
        return Err(ReputationFinalizedArchiveError::InvalidStorage {
            path: target.to_path_buf(),
            reason: "immutable archive target already contains different bytes",
        });
    }
    verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)
}
#[cfg(unix)]
struct UnixStagedArtifact<'directory> {
    directory: &'directory fs::File,
    name: OsString,
    armed: bool,
}
#[cfg(unix)]
impl UnixStagedArtifact<'_> {
    fn unlink(&mut self) -> Result<(), rustix::io::Errno> {
        if self.armed {
            rustix::fs::unlinkat(self.directory, &self.name, rustix::fs::AtFlags::empty())?;
            self.armed = false;
        }
        Ok(())
    }
}
#[cfg(unix)]
impl Drop for UnixStagedArtifact<'_> {
    fn drop(&mut self) {
        let _ = self.unlink();
    }
}
#[cfg(unix)]
fn verify_unix_directory_handle(
    directory: &fs::File,
    expected: ArchiveFileIdentity,
    path: &Path,
) -> Result<(), ReputationFinalizedArchiveError> {
    let metadata =
        directory
            .metadata()
            .map_err(|source| ReputationFinalizedArchiveError::Read {
                path: path.to_path_buf(),
                source,
            })?;
    if !metadata.is_dir() || archive_file_identity(&metadata) != expected {
        return Err(ReputationFinalizedArchiveError::InvalidStorage {
            path: path.to_path_buf(),
            reason: "descriptor-relative archive directory identity changed",
        });
    }
    Ok(())
}
#[cfg(unix)]
fn verify_unix_named_file(
    directory: &fs::File,
    name: &OsStr,
    metadata: &fs::Metadata,
    expected_len: u64,
    expected_links: u64,
) -> io::Result<()> {
    let entry = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    if !metadata.is_file()
        || metadata.len() != expected_len
        || !unix_stat_matches_metadata(&entry, metadata, expected_links)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor-relative archive artifact identity mismatch",
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn read_bounded_archive_file_at_unix(
    directory: &fs::File,
    name: &OsStr,
    max_bytes: u64,
) -> io::Result<Vec<u8>> {
    let before = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_nlink as u64 != 1
        || u64::try_from(before.st_size)
            .ok()
            .is_none_or(|size| size > max_bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor-relative archive artifact is not a bounded direct regular file",
        ));
    }
    let mut file = fs::File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened_before = file.metadata()?;
    verify_unix_named_file(directory, name, &opened_before, opened_before.len(), 1)?;
    if crate::kura::unix_device_identity(before.st_dev) != archive_file_identity(&opened_before).0
        || before.st_ino != archive_file_identity(&opened_before).1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor-relative archive artifact changed while opening",
        ));
    }
    let capacity = usize::try_from(opened_before.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let opened_after = file.metadata()?;
    let after = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    if bounded_bytes_len(&bytes) > max_bytes
        || !archive_file_metadata_unchanged(&opened_before, &opened_after)
        || !unix_stat_matches_metadata(&after, &opened_after, 1)
        || opened_after.len() != bounded_bytes_len(&bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor-relative archive artifact changed while reading",
        ));
    }
    Ok(bytes)
}
fn create_direct_directory(path: &Path) -> Result<(), ReputationFinalizedArchiveError> {
    validate_archive_root_path(path)?;
    verify_existing_directory_ancestry(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ReputationFinalizedArchiveError::InvalidStorage {
                path: path.to_path_buf(),
                reason: "archive path must be a direct directory",
            });
        }
        Ok(_) => return verify_absolute_directory_ancestry(path),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ReputationFinalizedArchiveError::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fs::create_dir_all(path).map_err(|source| ReputationFinalizedArchiveError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ReputationFinalizedArchiveError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReputationFinalizedArchiveError::InvalidStorage {
            path: path.to_path_buf(),
            reason: "archive path was substituted during directory creation",
        });
    }
    verify_absolute_directory_ancestry(path)?;
    sync_archive_directory(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(path),
    )
    .map_err(|source| ReputationFinalizedArchiveError::NamespaceSync {
        path: path.to_path_buf(),
        source,
    })
}
fn open_writer_lock_file(path: &Path) -> Result<fs::File, ReputationFinalizedArchiveError> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file =
        options
            .open(path)
            .map_err(|source| ReputationFinalizedArchiveError::WriterBusy {
                path: path.to_path_buf(),
                source,
            })?;
    let path_metadata = secure_file_metadata::from_path(path).map_err(|source| {
        ReputationFinalizedArchiveError::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let opened_metadata = secure_file_metadata::from_file(&file).map_err(|source| {
        ReputationFinalizedArchiveError::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !secure_file_metadata::is_single_link(&path_metadata)
        || !archive_file_metadata_unchanged(&path_metadata, &opened_metadata)
    {
        return Err(ReputationFinalizedArchiveError::InvalidStorage {
            path: path.to_path_buf(),
            reason: "archive writer lock must be a direct single-link regular file",
        });
    }
    Ok(file)
}
fn acquire_writer_ownership(
    file: &fs::File,
    path: &Path,
) -> Result<(), ReputationFinalizedArchiveError> {
    #[cfg(unix)]
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |source| ReputationFinalizedArchiveError::WriterBusy {
            path: path.to_path_buf(),
            source: io::Error::from(source),
        },
    )?;
    #[cfg(not(unix))]
    {
        let _ = (file, path);
    }
    Ok(())
}
#[cfg(unix)]
type ArchiveFileIdentity = (u64, u64);
#[cfg(windows)]
type ArchiveFileIdentity = (Option<u32>, Option<u64>);
#[cfg(not(any(unix, windows)))]
type ArchiveFileIdentity = ();
#[cfg(unix)]
fn archive_file_identity(metadata: &SecureMetadata) -> ArchiveFileIdentity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}
#[cfg(windows)]
fn archive_file_identity(metadata: &SecureMetadata) -> ArchiveFileIdentity {
    (metadata.volume_serial_number(), metadata.file_index())
}
#[cfg(not(any(unix, windows)))]
fn archive_file_identity(_metadata: &SecureMetadata) -> ArchiveFileIdentity {}
#[cfg(unix)]
const fn archive_file_identity_available(_identity: ArchiveFileIdentity) -> bool {
    true
}
#[cfg(windows)]
const fn archive_file_identity_available(identity: ArchiveFileIdentity) -> bool {
    identity.0.is_some() && identity.1.is_some()
}
#[cfg(not(any(unix, windows)))]
const fn archive_file_identity_available(_identity: ArchiveFileIdentity) -> bool {
    false
}
fn direct_archive_directory_identity(path: &Path) -> io::Result<ArchiveFileIdentity> {
    let metadata = secure_file_metadata::from_path(path)?;
    let identity = archive_file_identity(&metadata);
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !archive_file_identity_available(identity)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive directory must be direct and have a stable filesystem identity",
        ));
    }
    Ok(identity)
}
fn verify_archive_directory_identity(path: &Path, expected: ArchiveFileIdentity) -> io::Result<()> {
    if direct_archive_directory_identity(path)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive directory identity changed",
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn archive_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    archive_file_identity(left) == archive_file_identity(right)
        && left.nlink() == 1
        && right.nlink() == 1
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(windows)]
fn archive_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    archive_file_identity_available(archive_file_identity(left))
        && archive_file_identity(left) == archive_file_identity(right)
        && left.number_of_links() == Some(1)
        && right.number_of_links() == Some(1)
        && left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
}
#[cfg(not(any(unix, windows)))]
fn archive_file_metadata_unchanged(_left: &SecureMetadata, _right: &SecureMetadata) -> bool {
    false
}
fn direct_archive_file_metadata(path: &Path, max_bytes: u64) -> io::Result<SecureMetadata> {
    let metadata = secure_file_metadata::from_path(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !secure_file_metadata::is_single_link(&metadata)
        || metadata.len() > max_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive artifact must be a bounded direct single-link regular file",
        ));
    }
    Ok(metadata)
}
fn read_bounded_archive_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let path_before = direct_archive_file_metadata(path, max_bytes)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let opened_before = secure_file_metadata::from_file(&file)?;
    if !archive_file_identity_available(archive_file_identity(&path_before))
        || !archive_file_metadata_unchanged(&path_before, &opened_before)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive artifact identity changed while opening",
        ));
    }
    let capacity = usize::try_from(opened_before.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let opened_after = secure_file_metadata::from_file(&file)?;
    let path_after = secure_file_metadata::from_path(path)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || !secure_file_metadata::is_single_link(&path_after)
        || !archive_file_metadata_unchanged(&opened_before, &opened_after)
        || !archive_file_metadata_unchanged(&opened_before, &path_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive artifact changed while reading",
        ));
    }
    Ok(bytes)
}
fn sync_archive_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let mut options = fs::OpenOptions::new();
        options.read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        options.open(path)?.sync_all()
    }
    #[cfg(not(windows))]
    {
        fs::File::open(path)?.sync_all()
    }
}
/// Fail-closed errors returned by the finalized reputation archive.
#[derive(Debug, Error)]
pub enum ReputationFinalizedArchiveError {
    /// The original authenticated history read has not completed locally.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// A physical index reader or writer currently prevents retained publication.
    #[error("finalized reputation archive index is busy")]
    IndexBusy {
        /// Release Kura and State fences before awaiting this actual index owner.
        wait: iroha_allocation::release::ReleaseWait,
    },
    /// Archive resource ceilings are zero, inconsistent, or unrepresentable.
    #[error("invalid finalized reputation archive bounds: {reason}")]
    InvalidBounds {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// An exact archive key is malformed.
    #[error("invalid finalized reputation archive key: {reason}")]
    InvalidKey {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A typed finalized projection violates an archive invariant.
    #[error("invalid finalized reputation projection: {reason}")]
    InvalidProjection {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A certified Kura block and the immutable state
    /// view do not identify one exact result-bearing block.
    #[error("finalized reputation capture failed Kura authentication: {reason}")]
    FinalityAuthentication {
        /// Stable authentication failure.
        reason: &'static str,
    },
    /// Reading Kura's authenticated canonical inventory failed.
    #[error("finalized reputation capture could not {operation}: {detail}")]
    KuraAuthentication {
        /// Authenticated Kura operation.
        operation: &'static str,
        /// Payload-free storage diagnostic.
        detail: String,
    },
    /// A typed native finalized-view query failed during capture.
    #[error("finalized reputation capture query `{projection}` failed: {detail}")]
    ProjectionCaptureQuery {
        /// Typed projection source.
        projection: &'static str,
        /// Payload-free query diagnostic.
        detail: String,
    },
    /// A typed native query page advertised another finalized anchor.
    #[error("finalized reputation capture query `{projection}` returned another anchor")]
    ProjectionCaptureAnchorMismatch {
        /// Typed projection source.
        projection: &'static str,
    },
    /// Typed query pages did not form one strict exclusive-cursor sequence.
    #[error("invalid finalized reputation capture pagination for `{projection}`: {reason}")]
    ProjectionCapturePagination {
        /// Typed projection source.
        projection: &'static str,
        /// Stable pagination failure.
        reason: &'static str,
    },
    /// Canonical capture material exceeded its configured in-memory ceiling.
    #[error(
        "finalized reputation capture `{projection}` accumulated {size} bytes; maximum is {maximum}"
    )]
    ProjectionCaptureBudgetExceeded {
        /// Typed projection source being collected.
        projection: &'static str,
        /// Canonical bytes accumulated in this capture.
        size: u64,
        /// Configured aggregate archive ceiling.
        maximum: u64,
    },
    /// Bounded capture storage could not reserve another typed page.
    #[error("finalized reputation capture `{projection}` could not reserve bounded memory")]
    ProjectionCaptureAllocation {
        /// Typed projection source being collected.
        projection: &'static str,
    },
    /// Exact archive coverage skipped a height after its activation floor.
    #[error(
        "finalized reputation archive for `{network_id}` is missing height {missing_height} before observed height {observed_height}"
    )]
    ArchiveCoverageGap {
        /// Chain whose exact-height coverage is incomplete.
        network_id: NetworkId,
        /// First missing exact archive height.
        missing_height: u64,
        /// Height observed instead of the required successor.
        observed_height: u64,
    },
    /// The archive advertises a height beyond Kura's exact durable boundary.
    #[error(
        "finalized reputation archive height {archive_height} is ahead of exact Kura height {kura_height}"
    )]
    ArchiveAheadOfKura {
        /// Highest exact archive height.
        archive_height: u64,
        /// Authenticated Kura boundary height.
        kura_height: u64,
    },
    /// The archive suffix lag exceeds the configured production ceiling.
    #[error(
        "finalized reputation archive height {archive_height} lags exact Kura height {kura_height} by {lag} blocks; maximum is {maximum}"
    )]
    ArchiveKuraTipLagExceeded {
        /// Highest exact archive height.
        archive_height: u64,
        /// Authenticated Kura boundary height.
        kura_height: u64,
        /// Exact uncaptured suffix length.
        lag: u64,
        /// Configured maximum suffix length.
        maximum: u64,
    },
    /// An immutable archive anchor differs from authenticated Kura material.
    #[error(
        "finalized reputation archive anchor `{network_id}` height {height} failed Kura qualification: {reason}"
    )]
    ArchiveKuraAnchorMismatch {
        /// Chain identifier in the immutable archive key.
        network_id: NetworkId,
        /// Exact archive height that failed authentication.
        height: u64,
        /// Stable payload-free mismatch category.
        reason: &'static str,
    },
    /// Kura or archive changed while one qualification was in progress.
    #[error("finalized reputation {boundary} qualification boundary changed during validation")]
    QualificationBoundaryChanged {
        /// Boundary that changed.
        boundary: &'static str,
    },
    /// An anchor manifest is not the exact successor it claims to be.
    #[error("invalid finalized reputation anchor manifest: {reason}")]
    InvalidManifest {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// An immutable anchor delta is malformed or non-minimal.
    #[error("invalid finalized reputation anchor delta: {reason}")]
    InvalidDelta {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A caller-supplied compaction fence is malformed or no longer exact.
    #[error("invalid finalized reputation retention fence: {reason}")]
    InvalidRetentionFence {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// Archive generation changed after the caller froze its retention fence.
    #[error(
        "finalized reputation retention fence expected generation {expected_generation}, observed {observed_generation}"
    )]
    RetentionFenceChanged {
        /// Generation bound by the caller.
        expected_generation: u64,
        /// Live generation observed under the writer guard.
        observed_generation: u64,
    },
    /// A configured retention-authority handle, revision, or digest is invalid.
    #[error("invalid finalized reputation retention-authority binding")]
    InvalidRetentionAuthorityBinding,
    /// Existing checkpoint objects require the deployment-owned authority.
    #[error(
        "finalized reputation archive contains retention checkpoints but no authority was supplied"
    )]
    RetentionAuthorityRequired,
    /// The runtime authority does not match its configured public binding.
    #[error("finalized reputation retention authority was substituted or became stale")]
    RetentionAuthoritySubstitution,
    /// The runtime authority could not serve an exact operation.
    #[error("finalized reputation retention authority is unavailable")]
    RetentionAuthorityUnavailable,
    /// The runtime authority rejected the exact operation.
    #[error("finalized reputation retention authority rejected the exact operation")]
    RetentionAuthorityRejected,
    /// The authority's monotonic lineage is behind the local archive.
    #[error("finalized reputation retention authority or archive rolled back")]
    RetentionAuthorityRollback,
    /// The authority returned a competing value for one exact CAS lineage.
    #[error("finalized reputation retention authority equivocated")]
    RetentionAuthorityEquivocation,
    /// A CAS reported success without changing the authoritative value.
    #[error("finalized reputation retention authority CAS left the value unchanged")]
    RetentionAuthorityCasUnchanged,
    /// A CAS outcome or post-write authority identity could not be proven.
    #[error("finalized reputation retention authority CAS outcome is ambiguous")]
    RetentionAuthorityCasAmbiguous,
    /// A canonical checkpoint exists without exact sealed approval.
    #[error("unapproved finalized reputation retention checkpoint")]
    UnapprovedRetentionCheckpoint,
    /// A prepared checkpoint differs from its approved exact proposal.
    #[error("finalized reputation retention proposal does not match canonical checkpoint")]
    RetentionProposalMismatch,
    /// A canonical retention approval violates schema or lineage constraints.
    #[error("invalid finalized reputation retention approval: {reason}")]
    InvalidRetentionApproval {
        /// Stable payload-free rejection reason.
        reason: &'static str,
    },
    /// A virtual-base checkpoint is malformed or its lineage is non-monotonic.
    #[error("invalid finalized reputation virtual-base checkpoint: {reason}")]
    InvalidCheckpoint {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// Canonical checkpoint content or its content-addressed filename disagrees.
    #[error("finalized reputation virtual-base checkpoint digest mismatch")]
    CheckpointDigestMismatch,
    /// Complete history is unavailable because an authenticated prefix was compacted.
    #[error("finalized reputation history was compacted; use retained pagination")]
    HistoryPruned {
        /// Earliest exact exclusive cursor accepted by at least one compacted feed.
        available_after: Option<ReputationFinalizedEventPositionV1>,
    },
    /// One exact retained anchor is absent.
    #[error("finalized reputation anchor for `{network_id}` height {height} is unavailable")]
    MissingAnchor {
        /// Requested chain.
        network_id: NetworkId,
        /// Requested exact height.
        height: u64,
    },
    /// A retained-page limit is zero or above the fixed feed ceiling.
    #[error("invalid finalized reputation retained-page limit {requested}; maximum is {maximum}")]
    InvalidPageLimit {
        /// Caller-requested row count.
        requested: usize,
        /// Fixed feed ceiling.
        maximum: usize,
    },
    /// A retained-page cursor is neither the exact prefix boundary nor a retained row.
    #[error("invalid finalized reputation retained-page cursor")]
    InvalidPageCursor,
    /// The archive exists but has no live qualified anchor.
    #[error("finalized reputation archive is unavailable: {reason}")]
    ArchiveUnavailable {
        /// Stable availability failure.
        reason: &'static str,
    },
    /// The archive namespace contains an unsafe or unexpected object.
    #[error("invalid finalized reputation archive storage at {path}: {reason}")]
    InvalidStorage {
        /// Unsafe storage path.
        path: PathBuf,
        /// Stable validation failure.
        reason: &'static str,
    },
    /// The platform lacks the handle-relative filesystem primitive required by
    /// a production mutation.
    #[error("unsupported finalized reputation archive operation `{operation}` on {platform}")]
    UnsupportedPlatform {
        /// Mutation that cannot be implemented without weakening its boundary.
        operation: &'static str,
        /// Compile-target operating system.
        platform: &'static str,
    },
    /// A durable artifact could not be read safely.
    #[error("failed to read finalized reputation archive artifact {path}: {source}")]
    Read {
        /// Artifact path.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// A durable artifact could not be written safely.
    #[error("failed to write finalized reputation archive artifact {path}: {source}")]
    Write {
        /// Artifact path.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Atomic namespace publication could not be confirmed durably.
    #[error("failed to synchronize finalized reputation archive namespace {path}: {source}")]
    NamespaceSync {
        /// Directory whose namespace sync failed.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Another process currently owns the bounded archive write transaction.
    #[error("finalized reputation archive writer is busy at {path}: {source}")]
    WriterBusy {
        /// Writer-lock path.
        path: PathBuf,
        /// Source lock error.
        #[source]
        source: io::Error,
    },
    /// Canonical Norito encoding failed.
    #[error("failed to encode finalized reputation archive record: {0}")]
    Encode(#[source] norito::core::Error),
    /// Bounded Norito decoding failed.
    #[error("failed to decode finalized reputation archive record {path}: {source}")]
    Decode {
        /// Record path.
        path: PathBuf,
        /// Source Norito decode error.
        #[source]
        source: norito::core::Error,
    },
    /// A decoded record does not re-encode to its exact stored bytes.
    #[error("non-canonical finalized reputation archive record at {path}")]
    NonCanonicalRecord {
        /// Non-canonical record path.
        path: PathBuf,
    },
    /// A record uses an archive schema other than V1.
    #[error("unsupported finalized reputation archive version {found}")]
    UnsupportedArchiveVersion {
        /// Unsupported version.
        found: u16,
    },
    /// A stored manifest, delta, or policy commitment does not match its content.
    #[error("finalized reputation archive canonical digest mismatch")]
    ProjectionDigestMismatch,
    /// An anchor references a missing content-addressed policy.
    #[error("finalized reputation archive policy {digest:?} is missing")]
    MissingPolicy {
        /// Missing full policy-record digest.
        digest: [u8; 32],
    },
    /// One policy digest resolves to conflicting activation content.
    #[error("conflicting finalized reputation archive policy {digest:?}")]
    PolicyConflict {
        /// Conflicted full policy-record digest.
        digest: [u8; 32],
    },
    /// Reconstructed reserve-provider state does not match its manifest root.
    #[error("finalized reputation reserve-provider state root mismatch")]
    ProviderStateRootMismatch,
    /// A record loaded by exact key carries another key.
    #[error("finalized reputation archive exact-key mismatch at {path}")]
    ExactKeyMismatch {
        /// Mismatched record path.
        path: PathBuf,
    },
    /// A valid record is stored under a filename not derived from its exact key.
    #[error("finalized reputation archive path binding mismatch at {path}")]
    PathBindingMismatch {
        /// Misbound record path.
        path: PathBuf,
    },
    /// One canonical record exceeds the configured per-record ceiling.
    #[error("finalized reputation archive record has {size} bytes; maximum is {maximum}")]
    RecordTooLarge {
        /// Encoded record size.
        size: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// The immutable archive already contains the maximum number of records.
    #[error("finalized reputation archive exceeds its {maximum_entries}-entry ceiling")]
    ArchiveCapacityExceeded {
        /// Configured entry ceiling.
        maximum_entries: usize,
    },
    /// Aggregate durable bytes exceed the configured ceiling.
    #[error("finalized reputation archive has {size} bytes; maximum is {maximum}")]
    ArchiveBytesExceeded {
        /// Observed or proposed aggregate bytes.
        size: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// Append-only capacity is exhausted and no implicit pruning is permitted.
    #[error(
        "finalized reputation archive retention is required: proposed {proposed_entries} anchors/{proposed_policy_entries} policies/{proposed_bytes} bytes, maximum {maximum_entries} anchors/{maximum_policy_entries} policies/{maximum_bytes} bytes"
    )]
    RetentionRequired {
        /// Anchor count after the proposed insertion.
        proposed_entries: usize,
        /// Configured anchor ceiling.
        maximum_entries: usize,
        /// Policy-artifact count after the proposed insertion.
        proposed_policy_entries: usize,
        /// Configured policy-artifact ceiling.
        maximum_policy_entries: usize,
        /// Durable bytes after the proposed insertion.
        proposed_bytes: u64,
        /// Configured durable-byte ceiling.
        maximum_bytes: u64,
    },
    /// A new anchor was inserted behind the synchronized chain tip.
    #[error(
        "out-of-order finalized reputation anchor for chain {network_id}: height {height}, latest {latest_height}"
    )]
    OutOfOrderAnchor {
        /// Affected chain.
        network_id: NetworkId,
        /// Proposed height.
        height: u64,
        /// Current archived tip.
        latest_height: u64,
    },
    /// Two hashes claim finality for one chain height.
    #[error("finalized reputation archive fork for chain {network_id} at height {height}")]
    FinalizedFork {
        /// Conflicted chain.
        network_id: NetworkId,
        /// Conflicted finalized height.
        height: u64,
    },
    /// Different projection content claims the same exact finalized key.
    #[error(
        "conflicting finalized reputation projection for chain {network_id} at height {height} and block {block_hash:?}"
    )]
    ConflictingProjection {
        /// Conflicted chain.
        network_id: NetworkId,
        /// Conflicted finalized height.
        height: u64,
        /// Conflicted finalized hash.
        block_hash: [u8; 32],
    },
}
#[cfg(test)]
mod tests {
    mod frame_identity_tests;
    include!("reputation_finalized/preparation_tests.rs");
    include!("reputation_finalized/certified_tests.rs");
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        events::data::sorafs::{
            SorafsOrderbookLedgerEvent, SorafsOrderbookLedgerEventKind, SorafsRepairLedgerEvent,
            SorafsRepairLedgerEventKind, SorafsReserveLedgerEvent, SorafsReserveLedgerEventKind,
        },
        sorafs::{
            capacity::{CapacityDisputeId, CapacityDisputeOutcome},
            orderbook::OrderbookFinalizedEventV1,
            pin_registry::{ManifestDigest, StorageClass},
            proof_ledger::{
                PdpOutcomeProjectionV1, PdpOutcomeStatusV1, ProofOutcomeFinalizedEventV1,
                ProofOutcomeProjectionV1, ProofOutcomeRecordV1,
            },
            reputation::{
                PorTerminalOutcomeV1, PorTerminalStatusV1, ProviderDisputeEventV1,
                ProviderDisputeKindV1, ProviderDisputeResolutionV1, ProviderDisputeStatusV1,
                REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
                REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1, ReputationJournalAuthorityPolicyRecordV1,
                ReputationJournalAuthorityPolicyV1, ReputationJournalEntryV1,
                ReputationJournalPayloadV1,
            },
            reserve::{
                ReserveDuration, ReserveFinalizedEventV1, ReserveLifecycleStage,
                ReserveProviderAccountV1, ReserveProviderTermsV1, ReserveTier,
            },
        },
    };
    use sorafs_manifest::deal::XorQuantity;
    use std::{
        collections::VecDeque,
        io::{Seek, SeekFrom},
        sync::{Arc, Barrier, Mutex},
        thread,
    };
    use tempfile::tempdir;
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(Hash::new(
                vec![seed; 32],
            )),
        )
    }
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed.max(1); 32], Algorithm::Ed25519)
            .expect("construct deterministic test key");
        AccountId::new(keypair.public_key().clone())
    }
    fn empty_test_state(kura: &Arc<Kura>) -> crate::state::State {
        crate::state::State::new_with_chain_and_network_id_for_testing(
            crate::state::World::default(),
            Arc::clone(kura),
            crate::query::store::LiveQueryStore::start_test(),
            iroha_model_base::chain::ChainId::from("reputation-archive-local-test"),
            network_id(0x61),
        )
    }
    fn bounds() -> ReputationFinalizedArchiveBounds {
        ReputationFinalizedArchiveBounds::try_new(1 << 20, 16, 16 << 20)
            .expect("valid test archive bounds")
    }
    fn archive_root(directory: &tempfile::TempDir) -> PathBuf {
        fs::canonicalize(directory.path()).expect("canonicalize temporary archive root")
    }
    fn open_archive(
        directory: &tempfile::TempDir,
        bounds: ReputationFinalizedArchiveBounds,
    ) -> ReputationFinalizedArchive {
        ReputationFinalizedArchive::try_open_unsealed_for_test(archive_root(directory), bounds)
            .expect("open finalized archive")
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestRetentionCasBehavior {
        Apply,
        ApplyAmbiguous,
        LeaveUnchanged,
        Equivocate,
    }
    #[derive(Debug)]
    struct TestRetentionAuthority {
        handle: String,
        qualification: ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        latest: Mutex<Option<ReputationFinalizedArchiveRetentionApprovalRecordV1>>,
        behavior: Mutex<TestRetentionCasBehavior>,
        competing: Mutex<Option<ReputationFinalizedArchiveRetentionApprovalRecordV1>>,
        qualification_count: Mutex<usize>,
        load_count: Mutex<usize>,
        cas_count: Mutex<usize>,
    }
    impl TestRetentionAuthority {
        fn new() -> Self {
            Self {
                handle: "sealed.reputation.archive.primary".to_owned(),
                qualification: ReputationFinalizedArchiveRetentionAuthorityQualificationV1::new(
                    7, [0xA7; 32],
                ),
                latest: Mutex::new(None),
                behavior: Mutex::new(TestRetentionCasBehavior::Apply),
                competing: Mutex::new(None),
                qualification_count: Mutex::new(0),
                load_count: Mutex::new(0),
                cas_count: Mutex::new(0),
            }
        }
        fn binding(&self) -> ReputationFinalizedArchiveRetentionAuthorityBindingV1 {
            ReputationFinalizedArchiveRetentionAuthorityBindingV1::try_new(
                self.handle.clone(),
                self.qualification.revision(),
                self.qualification.policy_digest(),
            )
            .expect("valid test retention authority binding")
        }
        fn set_behavior(&self, behavior: TestRetentionCasBehavior) {
            *self.behavior.lock().expect("lock CAS behavior") = behavior;
        }
        fn set_competing(&self, record: ReputationFinalizedArchiveRetentionApprovalRecordV1) {
            *self.competing.lock().expect("lock competing approval") = Some(record);
        }
        fn load_count(&self) -> usize {
            *self.load_count.lock().expect("lock load count")
        }
        fn qualification_count(&self) -> usize {
            *self
                .qualification_count
                .lock()
                .expect("lock qualification count")
        }
        fn cas_count(&self) -> usize {
            *self.cas_count.lock().expect("lock CAS count")
        }
    }
    impl ReputationFinalizedArchiveRetentionAuthorityV1 for TestRetentionAuthority {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
        > {
            *self
                .qualification_count
                .lock()
                .expect("lock qualification count") += 1;
            Ok(self.qualification)
        }
        fn load_latest(
            &self,
            _network_id: &NetworkId,
        ) -> Result<
            Option<ReputationFinalizedArchiveRetentionApprovalRecordV1>,
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
        > {
            *self.load_count.lock().expect("lock load count") += 1;
            Ok(self.latest.lock().expect("lock latest approval").clone())
        }
        fn compare_and_swap_latest(
            &self,
            _network_id: &NetworkId,
            expected_revision: Option<[u8; 32]>,
            next: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
        ) -> Result<(), ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1> {
            *self.cas_count.lock().expect("lock CAS count") += 1;
            let mut latest = self.latest.lock().expect("lock latest approval");
            if latest
                .as_ref()
                .map(ReputationFinalizedArchiveRetentionApprovalRecordV1::revision)
                != expected_revision
            {
                return Err(ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected);
            }
            match *self.behavior.lock().expect("lock CAS behavior") {
                TestRetentionCasBehavior::Apply => {
                    *latest = Some(next.clone());
                    Ok(())
                }
                TestRetentionCasBehavior::ApplyAmbiguous => {
                    *latest = Some(next.clone());
                    Err(ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous)
                }
                TestRetentionCasBehavior::LeaveUnchanged => Ok(()),
                TestRetentionCasBehavior::Equivocate => {
                    *latest = self
                        .competing
                        .lock()
                        .expect("lock competing approval")
                        .clone();
                    Ok(())
                }
            }
        }
    }
    fn retention_test_proposal(
        height: u64,
        marker: u8,
    ) -> ReputationFinalizedArchiveCompactionProposalV1 {
        let key = ReputationFinalizedArchiveKeyV1::try_new(network_id(0x52), height, [marker; 32])
            .expect("valid retention test key");
        let fence = ReputationFinalizedArchiveRetentionFenceV1::try_new(
            key,
            [marker.wrapping_add(1); 32],
            None,
            height,
        )
        .expect("valid retention test fence");
        ReputationFinalizedArchiveCompactionProposalV1::try_new(
            fence,
            [marker.wrapping_add(2); 32],
            [marker.wrapping_add(3); 32],
            1,
            [marker.wrapping_add(4); 32],
        )
        .expect("valid retention test proposal")
    }
    include!("reputation_finalized/archive_codec_tests.rs");
    fn proposal_network_id(
        approval: &ReputationFinalizedArchiveRetentionApprovalRecordV1,
    ) -> NetworkId {
        approval
            .proposal()
            .fence()
            .compact_through()
            .network_id
            .clone()
    }
    #[test]
    fn complete_namespace_empty_check_rejects_any_record() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        assert!(archive.is_empty().expect("inspect empty archive"));
        archive
            .insert(sample_projection(1, [0x11; 32]))
            .expect("insert projection");
        assert!(!archive.is_empty().expect("inspect populated archive"));
    }
    fn sample_projection(height: u64, block_hash: [u8; 32]) -> ReputationFinalizedProjectionV1 {
        let policy = ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: account(1),
            dispute_recorder_authority: account(2),
            token_recorder_authority: account(3),
            stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
        };
        ReputationFinalizedProjectionV1 {
            key: ReputationFinalizedArchiveKeyV1::try_new(network_id(0x61), height, block_hash)
                .expect("valid exact key"),
            finalized_at_unix_ms: 1_750_000_000_000 + height,
            authority_policy: ReputationJournalAuthorityPolicyRecordV1::try_new(policy,
(account(4)).clone(),
1_700_000_000_000,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: 1_700_000_000_000, authority: (account(4)).clone(),
    }))
            .expect("valid activated authority policy"),
            proof_outcomes: Vec::new(),
            journal_events: Vec::new(),
            repair_events: Vec::new(),
            orderbook_events: Vec::new(),
            reserve_events: Vec::new(),
            reserve_providers: Vec::new(),
        }
    }
    fn rotated_projection(
        predecessor: &ReputationFinalizedProjectionV1,
        height: u64,
        block_hash: [u8; 32],
        recorder_marker: u8,
    ) -> ReputationFinalizedProjectionV1 {
        let mut projection = sample_projection(height, block_hash);
        let mut policy = predecessor.authority_policy.policy.clone();
        policy.revision = policy.revision.checked_add(1).expect("test revision");
        policy.predecessor_policy_digest = Some(predecessor.authority_policy.policy_digest);
        policy.por_recorder_authority = account(recorder_marker);
        projection.authority_policy = ReputationJournalAuthorityPolicyRecordV1::try_new(policy,
(account(4)).clone(),
predecessor.finalized_at_unix_ms.saturating_add(1),
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: predecessor.finalized_at_unix_ms.saturating_add(1), authority: (account(4)).clone(),
    }))
        .expect("rotated authority policy");
        projection
    }
    fn rotated_policy_record(
        predecessor: &ReputationJournalAuthorityPolicyRecordV1,
        recorder_marker: u8,
        activated_at_unix_ms: u64,
    ) -> ReputationJournalAuthorityPolicyRecordV1 {
        let mut policy = predecessor.policy.clone();
        policy.revision = policy.revision.checked_add(1).expect("test revision");
        policy.predecessor_policy_digest = Some(predecessor.policy_digest);
        policy.por_recorder_authority = account(recorder_marker);
        ReputationJournalAuthorityPolicyRecordV1::try_new(policy,
(account(4)).clone(),
activated_at_unix_ms,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: activated_at_unix_ms, authority: (account(4)).clone(),
    }))
            .expect("rotated authority policy record")
    }
    fn journal_event(
        policy: &ReputationJournalAuthorityPolicyV1,
        sequence: u64,
        block_height: u64,
        block_hash: [u8; 32],
        marker: u8,
    ) -> ReputationJournalFinalizedEventV1 {
        let issued_at_unix_ms = 1_710_000_000_000 + sequence * 10;
        let outcome = PorTerminalOutcomeV1 {
            challenge_id: [marker; 32],
            manifest_digest: [0x41; 32],
            epoch_id: 7,
            drand_round: 11,
            forced: false,
            sample_count: 4,
            failed_samples: 0,
            issued_at_unix_ms,
            deadline_at_unix_ms: issued_at_unix_ms + 8,
            responded_at_unix_ms: Some(issued_at_unix_ms + 4),
            decided_at_unix_ms: issued_at_unix_ms + 6,
            proof_digest: Some([marker.wrapping_add(1); 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(17),
            status: PorTerminalStatusV1::Verified,
        };
        let entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([marker; 32]),
            policy.canonical_digest().expect("canonical policy digest"),
            policy.por_recorder_authority.clone(),
            outcome.decided_at_unix_ms,
            None,
            ReputationJournalPayloadV1::PorTerminal(outcome),
        )
        .expect("valid reputation journal entry");
        ReputationJournalFinalizedEventV1 {
            sequence,
            block_height,
            block_hash,
            event_index: 0,
            recorded_at_unix_ms: issued_at_unix_ms + 7,
            entry,
        }
    }
    fn opened_dispute_journal_event(
        policy: &ReputationJournalAuthorityPolicyV1,
        sequence: u64,
        block_height: u64,
        block_hash: [u8; 32],
        event_index: u32,
        marker: u8,
    ) -> ReputationJournalFinalizedEventV1 {
        let submitted_at_unix_ms = 1_710_100_000_000 + u64::from(marker);
        let entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([marker; 32]),
            policy.canonical_digest().expect("canonical policy digest"),
            policy.dispute_recorder_authority.clone(),
            submitted_at_unix_ms,
            None,
            ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                dispute_id: CapacityDisputeId::new([marker.wrapping_add(1); 32]),
                kind: ProviderDisputeKindV1::FeeDispute,
                evidence_digest: [marker.wrapping_add(2); 32],
                submitted_at_unix_ms,
                status: ProviderDisputeStatusV1::Opened,
            }),
        )
        .expect("valid opened dispute journal entry");
        ReputationJournalFinalizedEventV1 {
            sequence,
            block_height,
            block_hash,
            event_index,
            recorded_at_unix_ms: submitted_at_unix_ms + 1,
            entry,
        }
    }
    fn resolved_dispute_journal_event(
        policy: &ReputationJournalAuthorityPolicyV1,
        sequence: u64,
        block_height: u64,
        block_hash: [u8; 32],
        event_index: u32,
        opened: &ReputationJournalFinalizedEventV1,
    ) -> ReputationJournalFinalizedEventV1 {
        let ReputationJournalPayloadV1::ProviderDispute(opened_payload) = &opened.entry.payload
        else {
            panic!("opened fixture must contain a provider dispute");
        };
        let resolved_at_unix_ms = opened_payload.submitted_at_unix_ms + 10;
        let entry = ReputationJournalEntryV1::try_new(
            opened.entry.provider_id,
            policy.canonical_digest().expect("canonical policy digest"),
            policy.dispute_recorder_authority.clone(),
            resolved_at_unix_ms,
            Some(opened.entry.event_id),
            ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                dispute_id: opened_payload.dispute_id,
                kind: opened_payload.kind,
                evidence_digest: opened_payload.evidence_digest,
                submitted_at_unix_ms: opened_payload.submitted_at_unix_ms,
                status: ProviderDisputeStatusV1::Resolved(ProviderDisputeResolutionV1 {
                    outcome: CapacityDisputeOutcome::Upheld,
                    resolved_at_unix_ms,
                    decision_digest: [0xD1; 32],
                    rationale: Some("canonical retained-source resolution".to_owned()),
                }),
            }),
        )
        .expect("valid resolved dispute journal entry");
        ReputationJournalFinalizedEventV1 {
            sequence,
            block_height,
            block_hash,
            event_index,
            recorded_at_unix_ms: resolved_at_unix_ms + 1,
            entry,
        }
    }
    fn orderbook_event(block_height: u64, block_hash: [u8; 32]) -> OrderbookFinalizedEventV1 {
        OrderbookFinalizedEventV1 {
            sequence: 1,
            block_height,
            block_hash,
            event_index: 0,
            event: SorafsOrderbookLedgerEvent {
                kind: SorafsOrderbookLedgerEventKind::TradeMatched,
                order_id: Some([0x11; 32]),
                trade_id: Some([0x22; 32]),
                channel_id: Some([0x33; 32]),
                receipt_id: None,
                provider_id: Some(ProviderId::new([0x44; 32])),
                book_revision: 9,
                authority: account(0x51),
                occurred_at_unix_ms: 1_710_000_000_000,
            },
        }
    }
    fn proof_event(block_height: u64, block_hash: [u8; 32]) -> ProofOutcomeFinalizedEventV1 {
        ProofOutcomeFinalizedEventV1 {
            sequence: 1,
            block_height,
            block_hash,
            event_index: 0,
            outcome: ProofOutcomeRecordV1 {
                version: 1,
                identity_digest: [0x11; 32],
                outcome_digest: [0x12; 32],
                provider_id: ProviderId::new([0x13; 32]),
                manifest_digest: ManifestDigest::new([0x14; 32]),
                admission_envelope_digest: [0x15; 32],
                submitted_by: account(0x16),
                committed_at_unix_ms: 1_710_000_000_000,
                projection: ProofOutcomeProjectionV1::Pdp(PdpOutcomeProjectionV1 {
                    source_sequence: 1,
                    epoch_id: 2,
                    status: PdpOutcomeStatusV1::DeadlineExpired,
                    proof_digest: None,
                    provider_attestation: None,
                    sampled_segments: 1,
                    sampled_hot_leaves: 0,
                    sampled_bytes: 0,
                    issued_at_unix: 1_700_000_000,
                    response_deadline_unix: 1_700_000_010,
                    decided_at_unix: 1_700_000_011,
                }),
            },
        }
    }
    fn repair_event(block_height: u64, block_hash: [u8; 32]) -> RepairFinalizedEventV1 {
        RepairFinalizedEventV1 {
            sequence: 1,
            block_height,
            block_hash,
            event_index: 0,
            event: SorafsRepairLedgerEvent {
                kind: SorafsRepairLedgerEventKind::TaskSubmitted,
                ticket_id: "REP-CAPTURE-1".to_owned(),
                task_id: [0x21; 32],
                provider_id: ProviderId::new([0x22; 32]),
                manifest_digest: ManifestDigest::new([0x23; 32]),
                revision: 1,
                authority: account(0x24),
                occurred_at_unix_ms: 1_710_000_000_000,
            },
        }
    }
    fn reserve_event(block_height: u64, block_hash: [u8; 32]) -> ReserveFinalizedEventV1 {
        ReserveFinalizedEventV1 {
            sequence: 1,
            block_height,
            block_hash,
            event_index: 0,
            event: SorafsReserveLedgerEvent {
                kind: SorafsReserveLedgerEventKind::ProviderRegistered,
                provider_id: Some(ProviderId::new([0x31; 32])),
                operation_id: None,
                policy_digest: [0x32; 32],
                provider_revision: 1,
                resulting_lifecycle_stage: Some(ReserveLifecycleStage::Active),
                authority: account(0x33),
                occurred_at_unix_ms: 1_710_000_000_000,
            },
        }
    }
    fn projection_with_all_feeds(
        height: u64,
        block_hash: [u8; 32],
    ) -> ReputationFinalizedProjectionV1 {
        let mut projection = sample_projection(height, block_hash);
        projection
            .proof_outcomes
            .push(proof_event(height, block_hash));
        projection.journal_events.push(journal_event(
            &projection.authority_policy.policy,
            1,
            height,
            block_hash,
            0x41,
        ));
        projection
            .repair_events
            .push(repair_event(height, block_hash));
        projection
            .orderbook_events
            .push(orderbook_event(height, block_hash));
        projection
            .reserve_events
            .push(reserve_event(height, block_hash));
        projection
    }
    fn captured_all_feed_successor(
        previous: &ReputationReconstructionStateV1,
        height: u64,
        block_hash: [u8; 32],
    ) -> CapturedReputationSuccessorV1 {
        let mut proof = proof_event(height, block_hash);
        proof.sequence = 2;
        let mut journal = journal_event(
            &previous.authority_policy.policy,
            2,
            height,
            block_hash,
            0x42,
        );
        journal.event_index = 0;
        let mut repair = repair_event(height, block_hash);
        repair.sequence = 2;
        let mut orderbook = orderbook_event(height, block_hash);
        orderbook.sequence = 2;
        let mut reserve = reserve_event(height, block_hash);
        reserve.sequence = 2;
        CapturedReputationSuccessorV1 {
            key: ReputationFinalizedArchiveKeyV1::try_new(
                previous.key.network_id.clone(),
                height,
                block_hash,
            )
            .expect("construct captured successor key"),
            finalized_at_unix_ms: previous.finalized_at_unix_ms + 1,
            authority_policy: previous.authority_policy.clone(),
            proof_outcomes: vec![proof],
            journal_events: vec![journal],
            repair_events: vec![repair],
            orderbook_events: vec![orderbook],
            reserve_events: vec![reserve],
            reserve_providers: previous.reserve_providers.clone(),
        }
    }
    fn reserve_account(marker: u8, revision: u64) -> ReserveProviderAccountV1 {
        ReserveProviderAccountV1 {
            terms: ReserveProviderTermsV1 {
                provider_id: ProviderId::new([marker; 32]),
                provider_account: account(marker),
                tier: ReserveTier::TierA,
                storage_class: StorageClass::Hot,
                duration: ReserveDuration::Monthly,
                capacity_gib: 1,
            },
            policy_digest: [0x41; 32],
            revision,
            reserve_balance: XorQuantity::zero(),
            debt_principal: XorQuantity::zero(),
            accrued_interest: XorQuantity::zero(),
            credit_cap: XorQuantity::try_from_micro(1_000_000_000).expect("credit cap fixture"),
            lifecycle_stage: ReserveLifecycleStage::Warning,
            days_past_due: 0,
            pending_movements: 0,
            open_appeals: 0,
            rent_charged_through_unix: 1_700_000_000,
            interest_accrued_at_unix: 1_700_000_000,
            updated_at_unix: 1_700_000_000 + revision,
        }
    }
    fn test_checkpoint_artifact(
        archive: &ReputationFinalizedArchive,
        target_key: &ReputationFinalizedArchiveKeyV1,
    ) -> (
        PersistedReputationFinalizedVirtualBaseCheckpointV1,
        Vec<u8>,
        PathBuf,
    ) {
        let index = archive.read_index().expect("read archive index");
        let target = index
            .by_height
            .get(&(target_key.network_id.clone(), target_key.height))
            .expect("target anchor is indexed")
            .clone();
        assert_eq!(&target.manifest.key, target_key);
        let state = archive
            .reconstruct_state(&index, &target)
            .expect("reconstruct checkpoint state");
        let anchors = index
            .by_height
            .range((
                std::ops::Bound::Included((target_key.network_id.clone(), 0)),
                std::ops::Bound::Included((target_key.network_id.clone(), target_key.height)),
            ))
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        let mut cumulative_anchor_prefix_digest = [0; 32];
        let mut cumulative_pruned_anchor_bytes = 0_u64;
        for anchor in &anchors {
            cumulative_anchor_prefix_digest = rolling_domain_digest(
                ANCHOR_PREFIX_DIGEST_DOMAIN_V1,
                cumulative_anchor_prefix_digest,
                &anchor.anchor_digest,
            )
            .expect("roll test anchor digest");
            cumulative_pruned_anchor_bytes += fs::metadata(&anchor.path)
                .expect("read anchor metadata")
                .len();
        }
        let authority_policy_history_digest = authority_policy_history_digest(
            &resolve_authority_policy_history(
                &index,
                &state.authority_policy,
                state.finalized_at_unix_ms,
            )
            .expect("resolve test policy history"),
        )
        .expect("digest test policy history");
        let mut checkpoint = ReputationFinalizedVirtualBaseCheckpointV1 {
            original_activation_floor: anchors
                .first()
                .expect("checkpoint prefix is non-empty")
                .manifest
                .key
                .clone(),
            retention_floor: state.key.clone(),
            retention_floor_finalized_at_unix_ms: state.finalized_at_unix_ms,
            retention_floor_anchor_digest: target.anchor_digest,
            certified_block_id: [0xA5; 32],
            prior_checkpoint_digest: None,
            checkpoint_generation: 1,
            cumulative_pruned_anchor_count: bounded_len(anchors.len())
                .expect("bounded test prefix"),
            cumulative_pruned_anchor_bytes,
            cumulative_anchor_prefix_digest,
            authority_policy: state.authority_policy.clone(),
            authority_policy_history_digest,
            proof_prefix: compact_retained_feed(
                PROOF_PREFIX_DIGEST_DOMAIN_V1,
                &state.proof_outcomes,
                proof_event_identity,
            )
            .expect("compact proof prefix"),
            journal_prefix: compact_retained_feed(
                JOURNAL_PREFIX_DIGEST_DOMAIN_V1,
                &state.journal_events,
                journal_event_identity,
            )
            .expect("compact journal prefix"),
            journal_prefix_source_heads: merge_journal_source_heads(
                &state.journal_prefix_source_heads,
                &state.journal_events.retained_suffix,
            )
            .expect("compact journal source-head index"),
            journal_source_head_delta: state.journal_events.retained_suffix.clone(),
            repair_prefix: compact_retained_feed(
                REPAIR_PREFIX_DIGEST_DOMAIN_V1,
                &state.repair_events,
                repair_event_identity,
            )
            .expect("compact repair prefix"),
            orderbook_prefix: compact_retained_feed(
                ORDERBOOK_PREFIX_DIGEST_DOMAIN_V1,
                &state.orderbook_events,
                orderbook_event_identity,
            )
            .expect("compact orderbook prefix"),
            reserve_prefix: compact_retained_feed(
                RESERVE_PREFIX_DIGEST_DOMAIN_V1,
                &state.reserve_events,
                reserve_event_identity,
            )
            .expect("compact reserve prefix"),
            proof_retained_suffix: Vec::new(),
            journal_retained_suffix: Vec::new(),
            repair_retained_suffix: Vec::new(),
            orderbook_retained_suffix: Vec::new(),
            reserve_retained_suffix: Vec::new(),
            reserve_providers: state.reserve_providers,
            validation_summary: ReputationCheckpointValidationSummaryV1 {
                high_water_marks: ReputationFeedHighWaterMarksV1::default(),
                policy_record_digest: [0; 32],
                journal_prefix_source_head_count: 0,
                journal_prefix_source_head_root: [0; 32],
                reserve_provider_count: 0,
                reserve_provider_state_root: [0; 32],
            },
            validation_summary_digest: [0; 32],
        };
        checkpoint.validation_summary =
            checkpoint_validation_summary(&checkpoint).expect("summarize test checkpoint");
        checkpoint.validation_summary_digest = canonical_domain_digest(
            CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
            &checkpoint.validation_summary,
        )
        .expect("digest test checkpoint summary");
        let persisted = PersistedReputationFinalizedVirtualBaseCheckpointV1::try_new(checkpoint)
            .expect("construct test checkpoint");
        let bytes = encode_bounded_artifact(&persisted, archive.bounds)
            .expect("encode bounded test checkpoint");
        let path = archive
            .checkpoints
            .join(checkpoint_file_name(persisted.checkpoint_digest));
        drop(index);
        (persisted, bytes, path)
    }
    fn publish_test_checkpoint(
        archive: &ReputationFinalizedArchive,
        target_key: &ReputationFinalizedArchiveKeyV1,
    ) -> PersistedReputationFinalizedVirtualBaseCheckpointV1 {
        let (persisted, bytes, path) = test_checkpoint_artifact(archive, target_key);
        publish_immutable_bytes(
            &archive.checkpoints,
            archive.checkpoints_identity,
            &path,
            &bytes,
        )
        .expect("publish test checkpoint");
        persisted
    }
    #[test]
    fn production_open_rejects_a_checkpoint_without_retention_authority() {
        let directory = tempdir().expect("create archive directory");
        let projection = sample_projection(7, [0x71; 32]);
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert retention-floor projection");
            publish_test_checkpoint(&archive, &projection.key);
        }
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()),
            Err(ReputationFinalizedArchiveError::RetentionAuthorityRequired)
        ));
    }
    fn replace_test_checkpoint_with_recomputed_content_address(
        checkpoints: &Path,
        mut persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1,
    ) -> PathBuf {
        let original_digest = persisted.checkpoint_digest;
        persisted.checkpoint.validation_summary =
            checkpoint_validation_summary(&persisted.checkpoint)
                .expect("recompute test checkpoint validation summary");
        persisted.checkpoint.validation_summary_digest = canonical_domain_digest(
            CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
            &persisted.checkpoint.validation_summary,
        )
        .expect("recompute test checkpoint validation summary digest");
        persisted.checkpoint_digest =
            checkpoint_content_digest(persisted.version, &persisted.checkpoint)
                .expect("recompute test checkpoint content digest");
        assert_ne!(
            persisted.checkpoint_digest, original_digest,
            "semantic checkpoint rewrite must change its content address"
        );
        let original_path = checkpoints.join(checkpoint_file_name(original_digest));
        let replacement_path = checkpoints.join(checkpoint_file_name(persisted.checkpoint_digest));
        fs::remove_file(original_path).expect("remove original test checkpoint");
        fs::write(
            &replacement_path,
            norito::to_bytes(&persisted).expect("encode recommitted test checkpoint"),
        )
        .expect("write recommitted test checkpoint");
        replacement_path
    }
    fn replace_test_checkpoint_with_recomputed_checkpoint_digest(
        checkpoints: &Path,
        mut persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1,
    ) -> PathBuf {
        let original_digest = persisted.checkpoint_digest;
        persisted.checkpoint_digest =
            checkpoint_content_digest(persisted.version, &persisted.checkpoint)
                .expect("recompute test checkpoint content digest");
        assert_ne!(
            persisted.checkpoint_digest, original_digest,
            "checkpoint mutation must change its content address"
        );
        let original_path = checkpoints.join(checkpoint_file_name(original_digest));
        let replacement_path = checkpoints.join(checkpoint_file_name(persisted.checkpoint_digest));
        fs::remove_file(original_path).expect("remove original test checkpoint");
        fs::write(
            &replacement_path,
            norito::to_bytes(&persisted).expect("encode recommitted test checkpoint"),
        )
        .expect("write recommitted test checkpoint");
        replacement_path
    }
    fn archive_with_two_source_checkpoint() -> (
        tempfile::TempDir,
        PersistedReputationFinalizedVirtualBaseCheckpointV1,
    ) {
        let directory = tempdir().expect("create archive directory");
        let mut projection = sample_projection(7, [0x71; 32]);
        let first = journal_event(
            &projection.authority_policy.policy,
            1,
            projection.key.height,
            projection.key.block_hash,
            0x31,
        );
        let mut second = journal_event(
            &projection.authority_policy.policy,
            2,
            projection.key.height,
            projection.key.block_hash,
            0x41,
        );
        second.event_index = 1;
        projection.journal_events = vec![first, second];
        let persisted = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert two-source checkpoint projection");
            publish_test_checkpoint(&archive, &projection.key)
        };
        (directory, persisted)
    }
    #[test]
    fn checkpoint_reopen_rejects_duplicate_and_reordered_source_heads() {
        let (duplicate_directory, mut duplicate) = archive_with_two_source_checkpoint();
        let duplicate_head = duplicate.checkpoint.journal_prefix_source_heads[0].clone();
        duplicate
            .checkpoint
            .journal_prefix_source_heads
            .push(duplicate_head);
        replace_test_checkpoint_with_recomputed_checkpoint_digest(
            &archive_root(&duplicate_directory).join(CHECKPOINTS_DIRECTORY),
            duplicate,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&duplicate_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint { .. })
        ));
        let (reordered_directory, mut reordered) = archive_with_two_source_checkpoint();
        reordered.checkpoint.journal_prefix_source_heads.swap(0, 1);
        replace_test_checkpoint_with_recomputed_checkpoint_digest(
            &archive_root(&reordered_directory).join(CHECKPOINTS_DIRECTORY),
            reordered,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&reordered_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint { .. })
        ));
    }
    #[test]
    fn checkpoint_reopen_rejects_substituted_source_head_and_committed_root() {
        let directory = tempdir().expect("create archive directory");
        let mut projection = sample_projection(7, [0x71; 32]);
        projection.journal_events.push(journal_event(
            &projection.authority_policy.policy,
            1,
            projection.key.height,
            projection.key.block_hash,
            0x51,
        ));
        let mut substituted = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert one-source checkpoint projection");
            publish_test_checkpoint(&archive, &projection.key)
        };
        let substituted_head = journal_event(
            &substituted.checkpoint.authority_policy.policy,
            1,
            substituted.checkpoint.retention_floor.height,
            substituted.checkpoint.retention_floor.block_hash,
            0x52,
        );
        substituted.checkpoint.journal_prefix_source_heads[0] = substituted_head;
        replace_test_checkpoint_with_recomputed_checkpoint_digest(
            &archive_root(&directory).join(CHECKPOINTS_DIRECTORY),
            substituted,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "initial checkpoint source-lineage delta is incomplete or substituted",
            })
        ));
        let (root_directory, mut substituted_root) = archive_with_two_source_checkpoint();
        substituted_root
            .checkpoint
            .validation_summary
            .journal_prefix_source_head_root[0] ^= 0xFF;
        substituted_root.checkpoint.validation_summary_digest = canonical_domain_digest(
            CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
            &substituted_root.checkpoint.validation_summary,
        )
        .expect("recommit substituted source-head root summary");
        replace_test_checkpoint_with_recomputed_checkpoint_digest(
            &archive_root(&root_directory).join(CHECKPOINTS_DIRECTORY),
            substituted_root,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&root_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::CheckpointDigestMismatch)
        ));
    }
    fn archive_with_source_revision_checkpoint() -> (
        tempfile::TempDir,
        PersistedReputationFinalizedVirtualBaseCheckpointV1,
        ReputationJournalFinalizedEventV1,
        ReputationJournalFinalizedEventV1,
        ReputationJournalFinalizedEventV1,
    ) {
        let directory = tempdir().expect("create archive directory");
        let mut projection = sample_projection(7, [0x71; 32]);
        let opened = opened_dispute_journal_event(
            &projection.authority_policy.policy,
            1,
            projection.key.height,
            projection.key.block_hash,
            0,
            0x61,
        );
        let resolved = resolved_dispute_journal_event(
            &projection.authority_policy.policy,
            2,
            projection.key.height,
            projection.key.block_hash,
            1,
            &opened,
        );
        let mut terminal = journal_event(
            &projection.authority_policy.policy,
            3,
            projection.key.height,
            projection.key.block_hash,
            0x71,
        );
        terminal.event_index = 2;
        terminal.recorded_at_unix_ms = resolved.recorded_at_unix_ms + 1;
        projection.journal_events = vec![opened.clone(), resolved.clone(), terminal.clone()];
        let persisted = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert source-revision checkpoint projection");
            publish_test_checkpoint(&archive, &projection.key)
        };
        (directory, persisted, opened, resolved, terminal)
    }
    fn approved_cleaned_source_revision_checkpoint() -> (
        tempfile::TempDir,
        PersistedReputationFinalizedVirtualBaseCheckpointV1,
        ReputationJournalFinalizedEventV1,
        ReputationJournalFinalizedEventV1,
        ReputationJournalFinalizedEventV1,
        TestRetentionAuthority,
    ) {
        let (directory, persisted, opened, resolved, terminal) =
            archive_with_source_revision_checkpoint();
        let fence = ReputationFinalizedArchiveRetentionFenceV1::try_new(
            persisted.checkpoint.retention_floor.clone(),
            persisted.checkpoint.retention_floor_anchor_digest,
            None,
            1,
        )
        .expect("construct approved cleanup fence");
        let checkpoint_bytes =
            norito::to_bytes(&persisted).expect("encode approved cleanup checkpoint");
        let source_summary = &persisted.checkpoint.validation_summary;
        let proposal = ReputationFinalizedArchiveCompactionProposalV1::try_new(
            fence,
            persisted.checkpoint_digest,
            canonical_bytes_domain_digest(
                RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
                &checkpoint_bytes,
            ),
            source_summary.journal_prefix_source_head_count,
            source_summary.journal_prefix_source_head_root,
        )
        .expect("construct approved cleanup proposal");
        let authority = TestRetentionAuthority::new();
        let approval = ReputationFinalizedArchiveRetentionApprovalRecordV1::try_new(
            1,
            authority.binding().qualification(),
            proposal,
            None,
            None,
        )
        .expect("construct approved cleanup record");
        *authority
            .latest
            .lock()
            .expect("lock approved cleanup record") = Some(approval);
        {
            let cleaned = open_archive(&directory, bounds());
            assert_eq!(
                fs::read_dir(&cleaned.anchors)
                    .expect("read cleaned anchor namespace")
                    .count(),
                0,
                "the physical retention-floor anchor must already be absent"
            );
            assert_eq!(
                fs::read_dir(&cleaned.checkpoints)
                    .expect("read cleaned checkpoint namespace")
                    .count(),
                1
            );
        }
        (directory, persisted, opened, resolved, terminal, authority)
    }
    fn recommit_checkpoint_journal_history(
        checkpoints: &Path,
        mut persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1,
        journal_history: Vec<ReputationJournalFinalizedEventV1>,
    ) {
        persisted.checkpoint.journal_prefix =
            journal_prefix_after_events(ReputationFeedPrefixSummaryV1::default(), &journal_history)
                .expect("recommit complete checkpoint journal history");
        persisted.checkpoint.journal_prefix_source_heads =
            merge_journal_source_heads(&[], &journal_history)
                .expect("recommit complete checkpoint source heads");
        persisted.checkpoint.journal_source_head_delta = journal_history;
        persisted.checkpoint.journal_retained_suffix.clear();
        replace_test_checkpoint_with_recomputed_content_address(checkpoints, persisted);
    }
    #[test]
    fn sealed_reopen_rejects_self_consistent_source_omission_and_stale_head_after_cleanup() {
        let (omitted_directory, omitted, _opened, _resolved, mut terminal, omitted_authority) =
            approved_cleaned_source_revision_checkpoint();
        terminal.sequence = 1;
        terminal.event_index = 0;
        recommit_checkpoint_journal_history(
            &archive_root(&omitted_directory).join(CHECKPOINTS_DIRECTORY),
            omitted,
            vec![terminal],
        );
        let omitted_binding = omitted_authority.binding();
        let omitted_kura = Kura::blank_kura_for_testing();
        assert!(matches!(
            ReputationFinalizedArchive::try_open_with_retention_authority(
                archive_root(&omitted_directory),
                bounds(),
                &network_id(0x61),
                &empty_test_state(&omitted_kura).query_view(),
                omitted_kura.as_ref(),
                &omitted_binding,
                &omitted_authority,
            ),
            Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint)
        ));
        assert!(omitted_authority.load_count() > 0);
        assert_eq!(omitted_authority.cas_count(), 0);
        assert_eq!(
            fs::read_dir(archive_root(&omitted_directory).join(ANCHORS_DIRECTORY))
                .expect("read omitted-history anchor namespace")
                .count(),
            0
        );
        let (stale_directory, stale, opened, _resolved, mut terminal, stale_authority) =
            approved_cleaned_source_revision_checkpoint();
        terminal.sequence = 2;
        terminal.event_index = 1;
        recommit_checkpoint_journal_history(
            &archive_root(&stale_directory).join(CHECKPOINTS_DIRECTORY),
            stale,
            vec![opened, terminal],
        );
        let stale_binding = stale_authority.binding();
        let stale_kura = Kura::blank_kura_for_testing();
        assert!(matches!(
            ReputationFinalizedArchive::try_open_with_retention_authority(
                archive_root(&stale_directory),
                bounds(),
                &network_id(0x61),
                &empty_test_state(&stale_kura).query_view(),
                stale_kura.as_ref(),
                &stale_binding,
                &stale_authority,
            ),
            Err(ReputationFinalizedArchiveError::UnapprovedRetentionCheckpoint)
        ));
        assert!(stale_authority.load_count() > 0);
        assert_eq!(stale_authority.cas_count(), 0);
        assert_eq!(
            fs::read_dir(archive_root(&stale_directory).join(ANCHORS_DIRECTORY))
                .expect("read stale-history anchor namespace")
                .count(),
            0
        );
    }
    #[test]
    fn checkpoint_reopen_rejects_recommitted_omitted_and_stale_source_heads() {
        let (omitted_directory, mut omitted, _opened, resolved, _terminal) =
            archive_with_source_revision_checkpoint();
        omitted
            .checkpoint
            .journal_prefix_source_heads
            .retain(|event| event.entry.source_id != resolved.entry.source_id);
        replace_test_checkpoint_with_recomputed_content_address(
            &archive_root(&omitted_directory).join(CHECKPOINTS_DIRECTORY),
            omitted,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&omitted_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "initial checkpoint source-lineage delta is incomplete or substituted",
            })
        ));
        let (stale_directory, mut stale, opened, resolved, _terminal) =
            archive_with_source_revision_checkpoint();
        let stale_head = stale
            .checkpoint
            .journal_prefix_source_heads
            .iter_mut()
            .find(|event| event.entry.source_id == resolved.entry.source_id)
            .expect("resolved source head exists");
        *stale_head = opened;
        replace_test_checkpoint_with_recomputed_content_address(
            &archive_root(&stale_directory).join(CHECKPOINTS_DIRECTORY),
            stale,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&stale_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "initial checkpoint source-lineage delta is incomplete or substituted",
            })
        ));
    }
    fn successor_checkpoint_with_journal_delta(
        previous: &PersistedReputationFinalizedVirtualBaseCheckpointV1,
        retention_floor_block_hash: [u8; 32],
        journal_source_head_delta: Vec<ReputationJournalFinalizedEventV1>,
    ) -> ReputationFinalizedVirtualBaseCheckpointV1 {
        let mut current = previous.checkpoint.clone();
        current.retention_floor = ReputationFinalizedArchiveKeyV1::try_new(
            current.retention_floor.network_id.clone(),
            current.retention_floor.height + 1,
            retention_floor_block_hash,
        )
        .expect("construct source-lineage successor floor");
        current.retention_floor_finalized_at_unix_ms += 1;
        current.retention_floor_anchor_digest = [0xD1; 32];
        current.certified_block_id = [0xD2; 32];
        current.prior_checkpoint_digest = Some(previous.checkpoint_digest);
        current.checkpoint_generation += 1;
        current.cumulative_pruned_anchor_count += 1;
        current.cumulative_pruned_anchor_bytes += 1;
        current.cumulative_anchor_prefix_digest = rolling_domain_digest(
            ANCHOR_PREFIX_DIGEST_DOMAIN_V1,
            current.cumulative_anchor_prefix_digest,
            &current.retention_floor_anchor_digest,
        )
        .expect("extend source-lineage anchor commitment");
        let previous_prefix = journal_prefix_after_events(
            previous.checkpoint.journal_prefix,
            &previous.checkpoint.journal_retained_suffix,
        )
        .expect("summarize predecessor journal");
        let previous_heads = journal_source_head_commitment(
            &previous.checkpoint.journal_prefix_source_heads,
            &previous.checkpoint.journal_retained_suffix,
        )
        .expect("summarize predecessor source heads")
        .0;
        current.journal_prefix =
            journal_prefix_after_events(previous_prefix, &journal_source_head_delta)
                .expect("extend source-lineage journal prefix");
        current.journal_prefix_source_heads =
            merge_journal_source_heads(&previous_heads, &journal_source_head_delta)
                .expect("extend source-lineage source heads");
        current.journal_source_head_delta = journal_source_head_delta;
        current.journal_retained_suffix.clear();
        current.validation_summary =
            checkpoint_validation_summary(&current).expect("summarize source-lineage successor");
        current.validation_summary_digest = canonical_domain_digest(
            CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
            &current.validation_summary,
        )
        .expect("digest source-lineage successor summary");
        current
    }
    #[test]
    fn checkpoint_source_head_lineage_accepts_new_resolved_dispute_with_complete_delta() {
        let directory = tempdir().expect("create archive directory");
        let projection = sample_projection(7, [0x71; 32]);
        let previous = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection)
                .expect("insert empty-journal predecessor");
            publish_test_checkpoint(
                &archive,
                &ReputationFinalizedArchiveKeyV1::try_new(network_id(0x61), 7, [0x71; 32])
                    .expect("construct predecessor key"),
            )
        };
        let opened = opened_dispute_journal_event(
            &previous.checkpoint.authority_policy.policy,
            1,
            8,
            [0x81; 32],
            0,
            0x61,
        );
        let resolved = resolved_dispute_journal_event(
            &previous.checkpoint.authority_policy.policy,
            2,
            8,
            [0x81; 32],
            1,
            &opened,
        );
        let current = successor_checkpoint_with_journal_delta(
            &previous,
            [0x81; 32],
            vec![opened, resolved.clone()],
        );
        PersistedReputationFinalizedVirtualBaseCheckpointV1::try_new(current.clone())
            .expect("complete new dispute lifecycle is standalone canonical");
        validate_journal_source_head_lineage(&previous.checkpoint, &current)
            .expect("complete new dispute lifecycle extends checkpoint lineage");
        assert_eq!(
            current.journal_prefix_source_heads,
            vec![resolved],
            "the resolved revision is the authenticated latest source head"
        );
    }
    #[test]
    fn checkpoint_reopen_accepts_new_resolved_dispute_with_complete_delta() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let (previous, resolved_source_id) = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(first.clone())
                .expect("insert empty-journal predecessor");
            let previous = publish_test_checkpoint(&archive, &first.key);
            let opened = opened_dispute_journal_event(
                &first.authority_policy.policy,
                1,
                8,
                [0x81; 32],
                0,
                0x61,
            );
            let resolved = resolved_dispute_journal_event(
                &first.authority_policy.policy,
                2,
                8,
                [0x81; 32],
                1,
                &opened,
            );
            let resolved_source_id = resolved.entry.source_id;
            let mut second = first;
            second.key = ReputationFinalizedArchiveKeyV1::try_new(
                second.key.network_id.clone(),
                8,
                [0x81; 32],
            )
            .expect("construct source-lineage successor key");
            second.finalized_at_unix_ms += 1;
            second.journal_events = vec![opened.clone(), resolved];
            archive
                .insert(second.clone())
                .expect("insert complete new dispute lifecycle");
            let (anchor_digest, anchor_bytes) = {
                let index = archive.read_index().expect("read successor anchor index");
                let entry = index
                    .by_height
                    .get(&(second.key.network_id.clone(), second.key.height))
                    .expect("source-lineage successor anchor");
                (
                    entry.anchor_digest,
                    fs::metadata(&entry.path)
                        .expect("read successor anchor metadata")
                        .len(),
                )
            };
            let mut current = successor_checkpoint_with_journal_delta(
                &previous,
                second.key.block_hash,
                second.journal_events,
            );
            current.retention_floor_anchor_digest = anchor_digest;
            current.cumulative_anchor_prefix_digest = rolling_domain_digest(
                ANCHOR_PREFIX_DIGEST_DOMAIN_V1,
                previous.checkpoint.cumulative_anchor_prefix_digest,
                &anchor_digest,
            )
            .expect("bind actual successor anchor digest");
            current.cumulative_pruned_anchor_bytes = previous
                .checkpoint
                .cumulative_pruned_anchor_bytes
                .checked_add(anchor_bytes)
                .expect("accumulate successor anchor bytes");
            let persisted = PersistedReputationFinalizedVirtualBaseCheckpointV1::try_new(current)
                .expect("construct successor checkpoint");
            let bytes =
                encode_bounded_artifact(&persisted, bounds()).expect("encode successor checkpoint");
            let path = archive
                .checkpoints
                .join(checkpoint_file_name(persisted.checkpoint_digest));
            publish_immutable_bytes(
                &archive.checkpoints,
                archive.checkpoints_identity,
                &path,
                &bytes,
            )
            .expect("publish successor checkpoint");
            (previous, resolved_source_id)
        };
        let reopened = open_archive(&directory, bounds());
        let floor = reopened
            .retention_floor(&previous.checkpoint.retention_floor.network_id)
            .expect("read successor retention floor")
            .expect("successor checkpoint is active");
        assert_eq!(floor.height, 8);
        let view = reopened
            .journal_event_by_source_at_exact(&floor, resolved_source_id)
            .expect("read resolved source at reopened floor")
            .expect("reopened floor source view");
        assert_eq!(
            view.event
                .expect("resolved source head survives checkpoint reopen")
                .entry
                .source_revision,
            2
        );
        assert_eq!(
            fs::read_dir(&reopened.checkpoints)
                .expect("read reconciled checkpoint namespace")
                .count(),
            1,
            "reopen must retain only the valid successor checkpoint"
        );
        assert_eq!(
            fs::read_dir(&reopened.anchors)
                .expect("read reconciled anchor namespace")
                .count(),
            0,
            "reopen may clean physical anchors only after lineage validation succeeds"
        );
    }
    #[test]
    fn checkpoint_source_head_lineage_rejects_new_resolved_dispute_without_opener() {
        let directory = tempdir().expect("create archive directory");
        let projection = sample_projection(7, [0x71; 32]);
        let previous = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert empty-journal predecessor");
            publish_test_checkpoint(&archive, &projection.key)
        };
        let opened = opened_dispute_journal_event(
            &previous.checkpoint.authority_policy.policy,
            1,
            8,
            [0x81; 32],
            0,
            0x61,
        );
        let mut resolved = resolved_dispute_journal_event(
            &previous.checkpoint.authority_policy.policy,
            2,
            8,
            [0x81; 32],
            1,
            &opened,
        );
        resolved.sequence = 1;
        resolved.event_index = 0;
        let mut forged = previous.checkpoint.clone();
        forged.retention_floor = ReputationFinalizedArchiveKeyV1::try_new(
            forged.retention_floor.network_id.clone(),
            8,
            [0x81; 32],
        )
        .expect("construct forged successor floor");
        forged.retention_floor_finalized_at_unix_ms += 1;
        forged.checkpoint_generation = 2;
        forged.prior_checkpoint_digest = Some(previous.checkpoint_digest);
        forged.journal_prefix = journal_prefix_after_events(
            previous.checkpoint.journal_prefix,
            std::slice::from_ref(&resolved),
        )
        .expect("recommit forged journal prefix");
        forged.journal_prefix_source_heads = vec![resolved.clone()];
        forged.journal_source_head_delta = vec![resolved];
        forged.validation_summary =
            checkpoint_validation_summary(&forged).expect("recommit forged source summary");
        forged.validation_summary_digest = canonical_domain_digest(
            CHECKPOINT_VALIDATION_DIGEST_DOMAIN_V1,
            &forged.validation_summary,
        )
        .expect("digest forged source summary");
        assert!(matches!(
            validate_journal_source_head_lineage(&previous.checkpoint, &forged),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal source-head index is missing, substituted, or lifecycle-discontinuous",
            })
        ));
    }
    #[test]
    fn checkpoint_source_head_lineage_rejects_omission_and_rollback() {
        let (_directory, previous, opened, resolved, _terminal) =
            archive_with_source_revision_checkpoint();
        let unchanged = successor_checkpoint_with_journal_delta(&previous, [0x81; 32], Vec::new());
        validate_journal_source_head_lineage(&previous.checkpoint, &unchanged)
            .expect("unchanged checkpoint source heads extend through an empty delta");
        let mut omitted = unchanged.clone();
        omitted
            .journal_prefix_source_heads
            .retain(|event| event.entry.source_id != resolved.entry.source_id);
        assert!(matches!(
            validate_journal_source_head_lineage(&previous.checkpoint, &omitted),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint source-head lineage omitted, rolled back, or substituted a source",
            })
        ));
        let mut rolled_back = unchanged;
        *rolled_back
            .journal_prefix_source_heads
            .iter_mut()
            .find(|event| event.entry.source_id == resolved.entry.source_id)
            .expect("resolved source head exists") = opened;
        assert!(matches!(
            validate_journal_source_head_lineage(&previous.checkpoint, &rolled_back),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint source-head lineage omitted, rolled back, or substituted a source",
            })
        ));
    }
    fn archive_with_historical_source_checkpoint() -> (
        tempfile::TempDir,
        PersistedReputationFinalizedVirtualBaseCheckpointV1,
        ReputationJournalSourceIdV1,
    ) {
        let directory = tempdir().expect("create archive directory");
        let mut first = sample_projection(7, [0x71; 32]);
        let historical = journal_event(
            &first.authority_policy.policy,
            1,
            first.key.height,
            first.key.block_hash,
            0x51,
        );
        let historical_source_id = historical.entry.source_id;
        first.journal_events.push(historical);
        let mut second = first.clone();
        second.key = ReputationFinalizedArchiveKeyV1::try_new(
            first.key.network_id.clone(),
            first.key.height + 1,
            [0x81; 32],
        )
        .expect("construct historical-source checkpoint floor");
        second.finalized_at_unix_ms += 1;
        let mut terminal = journal_event(
            &second.authority_policy.policy,
            2,
            second.key.height,
            second.key.block_hash,
            0x52,
        );
        terminal.event_index = 0;
        second.journal_events.push(terminal);
        let persisted = {
            let archive = open_archive(&directory, bounds());
            archive.insert(first).expect("insert historical source");
            archive
                .insert(second.clone())
                .expect("insert checkpoint floor");
            publish_test_checkpoint(&archive, &second.key)
        };
        (directory, persisted, historical_source_id)
    }
    #[test]
    fn checkpoint_reopen_rejects_recommitted_source_head_block_hash_and_timestamp_substitution() {
        let (hash_directory, mut substituted_hash, source_id) =
            archive_with_historical_source_checkpoint();
        substituted_hash
            .checkpoint
            .journal_prefix_source_heads
            .iter_mut()
            .find(|event| event.entry.source_id == source_id)
            .expect("historical source head exists")
            .block_hash = [0x72; 32];
        replace_test_checkpoint_with_recomputed_content_address(
            &archive_root(&hash_directory).join(CHECKPOINTS_DIRECTORY),
            substituted_hash,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&hash_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "retained feeds disagree on a finalized block hash",
            })
        ));
        let (timestamp_directory, mut substituted_timestamp, source_id) =
            archive_with_historical_source_checkpoint();
        substituted_timestamp
            .checkpoint
            .journal_prefix_source_heads
            .iter_mut()
            .find(|event| event.entry.source_id == source_id)
            .expect("historical source head exists")
            .recorded_at_unix_ms += 1;
        replace_test_checkpoint_with_recomputed_content_address(
            &archive_root(&timestamp_directory).join(CHECKPOINTS_DIRECTORY),
            substituted_timestamp,
        );
        assert!(matches!(
            ReputationFinalizedArchive::try_open_unsealed_for_test(
                archive_root(&timestamp_directory),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "initial checkpoint source-lineage delta is incomplete or substituted",
            })
        ));
    }
    #[test]
    fn anchor_reopen_rejects_recommitted_source_head_root_substitution() {
        let directory = tempdir().expect("create archive directory");
        let mut projection = sample_projection(7, [0x71; 32]);
        projection.journal_events.push(journal_event(
            &projection.authority_policy.policy,
            1,
            projection.key.height,
            projection.key.block_hash,
            0x51,
        ));
        let anchor_path = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert source-committed anchor");
            archive
                .record_path(&projection.key)
                .expect("derive source-committed anchor path")
        };
        let bytes = fs::read(&anchor_path).expect("read source-committed anchor");
        let mut persisted: PersistedReputationFinalizedAnchorV1 =
            decode_from_bytes_with_limits(&bytes, bounds().decode_limits())
                .expect("decode source-committed anchor");
        persisted.manifest.journal_source_head_root[0] ^= 0xFF;
        persisted.manifest_digest =
            canonical_domain_digest(MANIFEST_DIGEST_DOMAIN_V1, &persisted.manifest)
                .expect("recommit substituted anchor manifest");
        fs::write(
            &anchor_path,
            norito::to_bytes(&persisted).expect("encode recommitted anchor"),
        )
        .expect("write recommitted anchor");
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()),
            Err(ReputationFinalizedArchiveError::InvalidManifest {
                reason: "anchor journal source-head commitment does not match its reconstructed event history",
            })
        ));
    }
    #[test]
    fn public_compaction_paths_reject_oversize_checkpoint_before_approval_or_pruning() {
        let directory = tempdir().expect("create archive directory");
        let mut projection = sample_projection(7, [0x71; 32]);
        projection.journal_events = (0_u8..16)
            .map(|offset| {
                let mut event = journal_event(
                    &projection.authority_policy.policy,
                    u64::from(offset) + 1,
                    projection.key.height,
                    projection.key.block_hash,
                    0x20 + offset,
                );
                event.event_index = u32::from(offset);
                event
            })
            .collect();
        let predecessor = projection.clone();
        projection.key.height += 1;
        projection.key.block_hash = [0x72; 32];
        projection.journal_events.extend((16_u8..32).map(|offset| {
            let mut event = journal_event(
                &projection.authority_policy.policy,
                u64::from(offset) + 1,
                projection.key.height,
                projection.key.block_hash,
                0x20 + offset,
            );
            event.event_index = u32::from(offset - 16);
            event
        }));
        let (persisted, checkpoint_bytes, anchor_bytes, fence) = {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(predecessor.clone())
                .expect("insert many-source predecessor");
            archive
                .insert(projection.clone())
                .expect("insert the bounded successor delta");
            let (persisted, checkpoint_bytes, _) =
                test_checkpoint_artifact(&archive, &projection.key);
            let fence = archive
                .retention_fence_for(&projection.key)
                .expect("freeze oversize checkpoint fence");
            let anchor_bytes = fs::metadata(
                archive
                    .record_path(&projection.key)
                    .expect("derive retained anchor path"),
            )
            .expect("read retained anchor metadata")
            .len();
            (persisted, checkpoint_bytes, anchor_bytes, fence)
        };
        let checkpoint_canonical_digest = canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &checkpoint_bytes,
        );
        let checkpoint_bytes_len =
            u64::try_from(checkpoint_bytes.len()).expect("checkpoint size fits u64");
        assert!(
            checkpoint_bytes_len > anchor_bytes,
            "inline source-head snapshot must contribute to the checkpoint ceiling"
        );
        let tight_bounds = ReputationFinalizedArchiveBounds::try_new(
            checkpoint_bytes_len - 1,
            bounds().max_entries(),
            bounds().max_total_bytes(),
        )
        .expect("construct anchor-fitting checkpoint-rejecting bounds");
        assert!(anchor_bytes <= tight_bounds.max_record_bytes());
        let anchor_path = archive_root(&directory)
            .join(ANCHORS_DIRECTORY)
            .join(anchor_file_name(&projection.key).expect("anchor name"));
        let anchor_wire = fs::read(anchor_path).expect("read retained anchor");
        decode_from_bytes_with_limits::<PersistedReputationFinalizedAnchorV1>(
            &anchor_wire,
            tight_bounds.decode_limits(),
        )
        .expect("the retained anchor fits both the wire and allocation ceilings");
        let archive = open_archive(&directory, tight_bounds);
        let kura = Kura::blank_kura_for_testing();
        assert!(matches!(
            archive.prepare_certified_compaction(&fence, &empty_test_state(&kura).query_view(), kura.as_ref()),
            Err(ReputationFinalizedArchiveError::RecordTooLarge {
                size,
                maximum,
            }) if size == checkpoint_bytes_len && maximum == checkpoint_bytes_len - 1
        ));
        let source_summary = &persisted.checkpoint.validation_summary;
        let proposal = ReputationFinalizedArchiveCompactionProposalV1::try_new(
            fence,
            persisted.checkpoint_digest,
            checkpoint_canonical_digest,
            source_summary.journal_prefix_source_head_count,
            source_summary.journal_prefix_source_head_root,
        )
        .expect("construct valid oversize install proposal");
        let authority = TestRetentionAuthority::new();
        let binding = authority.binding();
        assert!(matches!(
            archive.approve_and_install_certified_compaction(
                &proposal,
                &empty_test_state(&kura).query_view(),
                kura.as_ref(),
                &binding,
                &authority,
            ),
            Err(ReputationFinalizedArchiveError::RecordTooLarge {
                size,
                maximum,
            }) if size == checkpoint_bytes_len && maximum == checkpoint_bytes_len - 1
        ));
        assert_eq!(authority.qualification_count(), 0);
        assert_eq!(authority.load_count(), 0);
        assert_eq!(authority.cas_count(), 0);
        assert!(
            authority
                .latest
                .lock()
                .expect("lock unmodified retention approval")
                .is_none(),
            "oversize install must not publish external retention state"
        );
        assert_eq!(
            archive
                .get_exact(&projection.key)
                .expect("record ceiling failure leaves anchor queryable"),
            Some(projection.clone())
        );
        assert_eq!(
            archive
                .retention_floor(&projection.key.network_id)
                .expect("record ceiling failure publishes no checkpoint"),
            None
        );
        assert_eq!(
            fs::read_dir(&archive.anchors)
                .expect("read retained anchor namespace")
                .count(),
            2,
            "both retained anchors must survive the rejected checkpoint"
        );
        assert_eq!(
            archive
                .get_exact(&predecessor.key)
                .expect("predecessor remains queryable"),
            Some(predecessor)
        );
        assert_eq!(
            fs::read_dir(&archive.checkpoints)
                .expect("read checkpoint namespace after rejected preparation")
                .count(),
            0,
            "public prepare and install must fail before checkpoint publication"
        );
    }
    #[test]
    fn predecessor_link_binds_the_exact_anchor_digest() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let second = sample_projection(8, [0x81; 32]);
        let second_path = {
            let archive = open_archive(&directory, bounds());
            archive.insert(first).expect("insert predecessor");
            archive.insert(second.clone()).expect("insert successor");
            archive
                .record_path(&second.key)
                .expect("derive successor path")
        };
        let bytes = fs::read(&second_path).expect("read successor anchor");
        let mut persisted: PersistedReputationFinalizedAnchorV1 =
            decode_from_bytes_with_limits(&bytes, bounds().decode_limits())
                .expect("decode successor anchor");
        persisted.manifest.predecessor_anchor_digest = Some([0xDD; 32]);
        persisted.manifest_digest =
            canonical_domain_digest(MANIFEST_DIGEST_DOMAIN_V1, &persisted.manifest)
                .expect("recommit tampered manifest");
        fs::write(
            &second_path,
            norito::to_bytes(&persisted).expect("encode tampered successor"),
        )
        .expect("write tampered successor");
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()),
            Err(ReputationFinalizedArchiveError::InvalidManifest { .. })
        ));
    }
    #[test]
    fn retention_fence_rejects_generation_drift_before_kura_work() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let first = sample_projection(7, [0x71; 32]);
        let second = sample_projection(8, [0x81; 32]);
        archive.insert(first.clone()).expect("insert fenced anchor");
        let fence = archive
            .retention_fence_for(&first.key)
            .expect("freeze exact retention fence");
        archive
            .insert(second)
            .expect("advance archive after fence freeze");
        let kura = Kura::blank_kura_for_testing();
        assert!(matches!(
            archive.compact_certified_prefix(&fence, &empty_test_state(&kura).query_view(), &kura),
            Err(ReputationFinalizedArchiveError::RetentionFenceChanged {
                expected_generation: 1,
                observed_generation: 2,
            })
        ));
    }
    #[test]
    fn post_link_checkpoint_error_reconciles_live_index_and_stales_prior_fence() {
        const INJECTED_ERROR: &str = "injected post-link checkpoint publication failure";
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let first = sample_projection(7, [0x71; 32]);
        let mut second = first.clone();
        second.key = ReputationFinalizedArchiveKeyV1::try_new(
            second.key.network_id.clone(),
            first.key.height + 1,
            [0x81; 32],
        )
        .expect("construct retained successor key");
        second.finalized_at_unix_ms += 1;
        archive
            .insert(first.clone())
            .expect("insert retention-floor anchor");
        archive
            .insert(second.clone())
            .expect("insert retained successor");
        let stale_fence = archive
            .retention_fence_for(&second.key)
            .expect("freeze pre-checkpoint fence");
        assert_eq!(stale_fence.expected_generation(), 2);
        assert_eq!(stale_fence.expected_checkpoint_digest(), None);
        let (persisted, checkpoint_bytes, _checkpoint_path) =
            test_checkpoint_artifact(&archive, &first.key);
        let checkpoint_digest = persisted.checkpoint_digest;
        let injected_namespace = archive.checkpoints.clone();
        let error = {
            let mut index = archive.write_index().expect("lock pre-checkpoint index");
            archive
                .publish_checkpoint_and_reconcile(
                    &mut index,
                    &first.key.network_id,
                    &persisted,
                    &checkpoint_bytes,
                    stale_fence.expected_generation() + 1,
                    move || {
                        Err(ReputationFinalizedArchiveError::NamespaceSync {
                            path: injected_namespace,
                            source: io::Error::other(INJECTED_ERROR),
                        })
                    },
                )
                .expect_err("inject failure after the canonical checkpoint link")
        };
        assert!(matches!(
            error,
            ReputationFinalizedArchiveError::NamespaceSync { ref path, .. }
                if path == &archive.checkpoints
        ));
        assert_eq!(
            fs::read_dir(&archive.anchors)
                .expect("read anchors after injected failure")
                .count(),
            2,
            "ambiguous publication must not begin physical cleanup"
        );
        assert_eq!(
            archive
                .retention_floor(&first.key.network_id)
                .expect("read reconciled retention floor"),
            Some(first.key.clone())
        );
        assert!(matches!(
            archive.get_exact(&first.key),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
        assert_eq!(
            archive
                .get_exact(&second.key)
                .expect("read retained successor"),
            Some(second.clone())
        );
        assert_eq!(
            archive
                .health_generation()
                .expect("read reconciled generation"),
            3
        );
        let kura = Kura::blank_kura_for_testing();
        assert!(matches!(
            archive.compact_certified_prefix(
                &stale_fence,
                &empty_test_state(&kura).query_view(),
                &kura
            ),
            Err(ReputationFinalizedArchiveError::RetentionFenceChanged {
                expected_generation: 2,
                observed_generation: 3,
            })
        ));
        let fresh_fence = archive
            .retention_fence_for(&second.key)
            .expect("freeze post-checkpoint fence");
        assert_eq!(fresh_fence.expected_generation(), 3);
        assert_eq!(
            fresh_fence.expected_checkpoint_digest(),
            Some(checkpoint_digest)
        );
        assert!(matches!(
            ReputationFinalizedArchiveRetentionFenceV1::try_new(
                second.key.clone(),
                fresh_fence.compact_through_anchor_digest(),
                Some([0; 32]),
                fresh_fence.expected_generation(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidRetentionFence { .. })
        ));
        {
            let index = archive.read_index().expect("read reconciled index");
            validate_qualification_archive_boundary(
                &index,
                &first.key.network_id,
                3,
                Some(checkpoint_digest),
            )
            .expect("qualification boundary binds the active checkpoint");
            assert!(matches!(
                validate_qualification_archive_boundary(&index, &first.key.network_id, 3, None,),
                Err(
                    ReputationFinalizedArchiveError::QualificationBoundaryChanged {
                        boundary: "archive",
                    }
                )
            ));
        }
        let mut substituted_fence = fresh_fence;
        substituted_fence.expected_checkpoint_digest = None;
        assert!(matches!(
            archive.compact_certified_prefix(
                &substituted_fence,
                &empty_test_state(&kura).query_view(),
                &kura
            ),
            Err(ReputationFinalizedArchiveError::InvalidRetentionFence {
                reason: "retention fence does not bind the active checkpoint head",
            })
        ));
        drop(archive);
        let reopened = open_archive(&directory, bounds());
        assert_eq!(
            fs::read_dir(&reopened.anchors)
                .expect("read anchors after recovery cleanup")
                .count(),
            1
        );
        assert_eq!(
            reopened
                .get_exact(&second.key)
                .expect("read retained successor after reopen"),
            Some(second)
        );
        assert_eq!(
            reopened
                .health_generation()
                .expect("read reopened generation"),
            3
        );
    }
    #[test]
    fn unrecoverable_post_link_checkpoint_error_latches_until_reopen() {
        const INJECTED_ERROR: &str = "injected post-link checkpoint publication failure";
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let first = sample_projection(7, [0x71; 32]);
        archive
            .insert(first.clone())
            .expect("insert retention-floor anchor");
        let (persisted, checkpoint_bytes, _checkpoint_path) =
            test_checkpoint_artifact(&archive, &first.key);
        let obstruction = archive.checkpoints.join("injected-recovery-obstruction");
        let injected_namespace = archive.checkpoints.clone();
        let error = {
            let mut index = archive.write_index().expect("lock pre-checkpoint index");
            archive
                .publish_checkpoint_and_reconcile(
                    &mut index,
                    &first.key.network_id,
                    &persisted,
                    &checkpoint_bytes,
                    2,
                    || {
                        fs::write(&obstruction, b"force deterministic inventory failure")
                            .expect("install inventory obstruction");
                        Err(ReputationFinalizedArchiveError::NamespaceSync {
                            path: injected_namespace,
                            source: io::Error::other(INJECTED_ERROR),
                        })
                    },
                )
                .expect_err("unrecoverable rescan must fail closed")
        };
        assert!(matches!(
            error,
            ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            }
        ));
        assert!(matches!(
            archive.get_exact(&first.key),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            })
        ));
        assert!(matches!(
            archive.retention_floor(&first.key.network_id),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            })
        ));
        assert!(matches!(
            archive.retention_fence_for(&first.key),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            })
        ));
        assert!(matches!(
            archive.health_generation(),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            })
        ));
        let successor = sample_projection(8, [0x81; 32]);
        assert!(matches!(
            archive.insert(successor),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            })
        ));
        fs::remove_file(&obstruction).expect("remove inventory obstruction");
        assert!(matches!(
            archive.retention_floor(&first.key.network_id),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: CHECKPOINT_PUBLICATION_REOPEN_REQUIRED_REASON,
            })
        ));
        drop(archive);
        let reopened = open_archive(&directory, bounds());
        assert!(matches!(
            reopened.get_exact(&first.key),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
        assert_eq!(
            reopened
                .health_generation()
                .expect("reopen clears the in-memory latch"),
            2
        );
    }
    #[test]
    fn checkpoint_reopen_finishes_crash_cleanup_and_pages_retained_suffix() {
        let directory = tempdir().expect("create archive directory");
        let mut first = sample_projection(7, [0x71; 32]);
        first.journal_events.push(journal_event(
            &first.authority_policy.policy,
            1,
            first.key.height,
            first.key.block_hash,
            0x21,
        ));
        let mut second_prefix_event = journal_event(
            &first.authority_policy.policy,
            2,
            first.key.height,
            first.key.block_hash,
            0x22,
        );
        second_prefix_event.event_index = 1;
        first.journal_events.push(second_prefix_event);
        let mut second = first.clone();
        second.key =
            ReputationFinalizedArchiveKeyV1::try_new(second.key.network_id.clone(), 8, [0x81; 32])
                .expect("construct successor key");
        second.finalized_at_unix_ms += 1;
        second.journal_events.push(journal_event(
            &second.authority_policy.policy,
            3,
            second.key.height,
            second.key.block_hash,
            0x23,
        ));
        {
            let archive = open_archive(&directory, bounds());
            archive.insert(first.clone()).expect("insert prefix anchor");
            archive
                .insert(second.clone())
                .expect("insert retained anchor");
            publish_test_checkpoint(&archive, &first.key);
            assert_eq!(
                fs::read_dir(&archive.anchors)
                    .expect("read pre-crash anchors")
                    .count(),
                2,
                "checkpoint publication precedes unlink"
            );
        }
        let reopened = open_archive(&directory, bounds());
        assert_eq!(
            reopened
                .retention_floor(&first.key.network_id)
                .expect("read retention floor"),
            Some(first.key.clone())
        );
        assert_eq!(
            reopened
                .activation_floor(&first.key.network_id)
                .expect("read original floor"),
            Some(first.key.clone())
        );
        assert_eq!(
            fs::read_dir(&reopened.anchors)
                .expect("read recovered anchors")
                .count(),
            1,
            "reopen finishes the checkpoint-first unlink"
        );
        assert!(matches!(
            reopened.get_exact(&first.key),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
        assert!(matches!(
            reopened
                .page_journal_events(&second.key, None, REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1)
                .expect("return typed pruned boundary"),
            ReputationFinalizedArchivePageV1::HistoryPruned { .. }
        ));
        assert!(matches!(
            reopened
                .page_journal_events(
                    &second.key,
                    first.journal_events.first().map(|event| event.cursor()),
                    REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1,
                )
                .expect("return typed boundary for an older retained cursor"),
            ReputationFinalizedArchivePageV1::HistoryPruned { .. }
        ));
        let page = reopened
            .page_journal_events(
                &second.key,
                first.journal_events.last().map(|event| event.cursor()),
                REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1,
            )
            .expect("page retained suffix from exact compacted cursor");
        assert_eq!(
            page,
            ReputationFinalizedArchivePageV1::Page {
                events: vec![second.journal_events[2].clone()],
                has_more: false,
                next_after: None,
                prefix: ReputationFinalizedFeedPrefixV1 {
                    pruned_through: first
                        .journal_events
                        .last()
                        .map(journal_event_identity)
                        .map(event_position),
                    rolling_prefix_digest: first
                        .journal_events
                        .iter()
                        .try_fold([0; 32], |digest, event| {
                            rolling_domain_digest(JOURNAL_PREFIX_DIGEST_DOMAIN_V1, digest, event)
                        })
                        .expect("digest expected journal prefix"),
                    pruned_event_count: 2,
                },
            }
        );
        assert_eq!(reopened.health_generation().expect("stable generation"), 3);
    }
    #[test]
    fn checkpoint_source_head_lookup_survives_reopen_and_preserves_absence_boundaries() {
        let directory = tempdir().expect("create archive directory");
        let mut floor = sample_projection(7, [0x71; 32]);
        let opened = opened_dispute_journal_event(
            &floor.authority_policy.policy,
            1,
            floor.key.height,
            floor.key.block_hash,
            0,
            0x51,
        );
        let resolved = resolved_dispute_journal_event(
            &floor.authority_policy.policy,
            2,
            floor.key.height,
            floor.key.block_hash,
            1,
            &opened,
        );
        let source_id = resolved.entry.source_id;
        floor.journal_events = vec![opened, resolved.clone()];
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(floor.clone())
                .expect("insert source-indexed retention floor");
            publish_test_checkpoint(&archive, &floor.key);
        }
        let reopened = open_archive(&directory, bounds());
        let exact = reopened
            .journal_event_by_source_at_exact(&floor.key, source_id)
            .expect("query exact checkpoint source head")
            .expect("checkpoint floor exists");
        assert_eq!(exact.key, floor.key);
        assert_eq!(exact.finalized_at_unix_ms, floor.finalized_at_unix_ms);
        assert_eq!(exact.event, Some(resolved.clone()));
        let latest = reopened
            .latest_journal_event_by_source_at_or_before(
                &floor.key.network_id,
                floor.key.height,
                source_id,
            )
            .expect("query latest checkpoint source head")
            .expect("checkpoint floor is selectable");
        assert_eq!(latest, exact);
        let absent_source = ReputationJournalSourceIdV1::for_por_challenge([0xFE; 32]);
        let absent = reopened
            .journal_event_by_source_at_exact(&floor.key, absent_source)
            .expect("query authoritative checkpoint absence")
            .expect("checkpoint floor exists");
        assert_eq!(absent.key, floor.key);
        assert_eq!(absent.event, None);
        let wrong_hash = ReputationFinalizedArchiveKeyV1::try_new(
            floor.key.network_id.clone(),
            floor.key.height,
            [0x72; 32],
        )
        .expect("construct wrong-hash exact key");
        assert_eq!(
            reopened
                .journal_event_by_source_at_exact(&wrong_hash, source_id)
                .expect("wrong hash is a missing exact anchor"),
            None
        );
        let missing_successor = ReputationFinalizedArchiveKeyV1::try_new(
            floor.key.network_id.clone(),
            floor.key.height + 1,
            [0x81; 32],
        )
        .expect("construct missing successor key");
        assert_eq!(
            reopened
                .journal_event_by_source_at_exact(&missing_successor, source_id)
                .expect("missing retained successor is not substituted"),
            None
        );
        let below_floor = ReputationFinalizedArchiveKeyV1::try_new(
            floor.key.network_id.clone(),
            floor.key.height - 1,
            [0x61; 32],
        )
        .expect("construct pre-checkpoint key");
        assert!(matches!(
            reopened.journal_event_by_source_at_exact(&below_floor, source_id),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
        assert!(matches!(
            reopened.latest_journal_event_by_source_at_or_before(
                &floor.key.network_id,
                floor.key.height - 1,
                source_id,
            ),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
        assert!(matches!(
            reopened
                .journal_event_by_source_at_exact(&floor.key, ReputationJournalSourceIdV1::ZERO,),
            Err(ReputationFinalizedArchiveError::InvalidKey { .. })
        ));
        assert!(matches!(
            reopened.latest_journal_event_by_source_at_or_before(
                &floor.key.network_id,
                0,
                source_id,
            ),
            Err(ReputationFinalizedArchiveError::InvalidKey { .. })
        ));
        assert!("".parse::<NetworkId>().is_err());
    }
    #[test]
    fn checkpoint_source_index_merges_retained_source_updates_and_new_sources() {
        let directory = tempdir().expect("create archive directory");
        let mut floor = sample_projection(7, [0x71; 32]);
        let opened = opened_dispute_journal_event(
            &floor.authority_policy.policy,
            1,
            floor.key.height,
            floor.key.block_hash,
            0,
            0x61,
        );
        let dispute_source_id = opened.entry.source_id;
        floor.journal_events.push(opened.clone());
        let mut successor = floor.clone();
        successor.key = ReputationFinalizedArchiveKeyV1::try_new(
            floor.key.network_id.clone(),
            floor.key.height + 1,
            [0x81; 32],
        )
        .expect("construct retained successor key");
        successor.finalized_at_unix_ms += 1;
        let resolved = resolved_dispute_journal_event(
            &successor.authority_policy.policy,
            2,
            successor.key.height,
            successor.key.block_hash,
            0,
            &opened,
        );
        let mut new_source = journal_event(
            &successor.authority_policy.policy,
            3,
            successor.key.height,
            successor.key.block_hash,
            0x62,
        );
        new_source.event_index = 1;
        let new_source_id = new_source.entry.source_id;
        successor.journal_events.push(resolved.clone());
        successor.journal_events.push(new_source.clone());
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(floor.clone())
                .expect("insert source-indexed checkpoint floor");
            archive
                .insert(successor.clone())
                .expect("insert retained source successor");
            publish_test_checkpoint(&archive, &floor.key);
        }
        let reopened = open_archive(&directory, bounds());
        assert_eq!(
            reopened
                .journal_event_by_source_at_exact(&floor.key, dispute_source_id)
                .expect("read compacted dispute opening")
                .expect("checkpoint floor exists")
                .event,
            Some(opened)
        );
        assert_eq!(
            reopened
                .journal_event_by_source_at_exact(&successor.key, dispute_source_id)
                .expect("read retained dispute resolution")
                .expect("retained successor exists")
                .event,
            Some(resolved.clone())
        );
        assert_eq!(
            reopened
                .latest_journal_event_by_source_at_or_before(
                    &successor.key.network_id,
                    successor.key.height,
                    dispute_source_id,
                )
                .expect("select retained dispute resolution")
                .expect("retained successor is selectable")
                .event,
            Some(resolved)
        );
        assert_eq!(
            reopened
                .latest_journal_event_by_source_at_or_before(
                    &successor.key.network_id,
                    successor.key.height,
                    new_source_id,
                )
                .expect("select new retained source")
                .expect("retained successor is selectable")
                .event,
            Some(new_source)
        );
    }
    #[test]
    fn compacted_capture_accepts_no_new_feed_events_without_querying_pruned_history() {
        let directory = tempdir().expect("create archive directory");
        let first = projection_with_all_feeds(7, [0x71; 32]);
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(first.clone())
                .expect("insert all-feed retention floor");
            publish_test_checkpoint(&archive, &first.key);
        }
        let archive = open_archive(&directory, bounds());
        let previous = archive
            .latest_reconstruction_state_at_or_before(&first.key.network_id, first.key.height)
            .expect("reconstruct compacted capture predecessor")
            .expect("checkpoint state exists");
        assert_eq!(
            retained_capture_cursor(
                &previous.proof_outcomes,
                ProofOutcomeFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::proof_ledger::ProofOutcomeFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            ),
            first
                .proof_outcomes
                .last()
                .map(ProofOutcomeFinalizedEventV1::cursor)
        );
        assert_eq!(
            retained_capture_cursor(
                &previous.journal_events,
                ReputationJournalFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            ),
            first
                .journal_events
                .last()
                .map(ReputationJournalFinalizedEventV1::cursor)
        );
        assert_eq!(
            retained_capture_cursor(
                &previous.repair_events,
                RepairFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::moderation_ledger::RepairFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            ),
            first
                .repair_events
                .last()
                .map(RepairFinalizedEventV1::cursor)
        );
        assert_eq!(
            retained_capture_cursor(
                &previous.orderbook_events,
                OrderbookFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::orderbook::OrderbookFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            ),
            first
                .orderbook_events
                .last()
                .map(OrderbookFinalizedEventV1::cursor)
        );
        assert_eq!(
            retained_capture_cursor(
                &previous.reserve_events,
                ReserveFinalizedEventV1::cursor,
                |position| {
                    iroha_data_model::sorafs::reserve::ReserveFinalizedEventCursorV1 {
                        sequence: position.sequence,
                        block_height: position.block_height,
                        block_hash: position.block_hash,
                        event_index: position.event_index,
                    }
                },
            ),
            first
                .reserve_events
                .last()
                .map(ReserveFinalizedEventV1::cursor)
        );
        let next = build_captured_successor_state(
            Some(&previous),
            CapturedReputationSuccessorV1 {
                key: ReputationFinalizedArchiveKeyV1::try_new(
                    first.key.network_id.clone(),
                    8,
                    [0x81; 32],
                )
                .expect("construct empty captured successor"),
                finalized_at_unix_ms: previous.finalized_at_unix_ms + 1,
                authority_policy: previous.authority_policy.clone(),
                proof_outcomes: Vec::new(),
                journal_events: Vec::new(),
                repair_events: Vec::new(),
                orderbook_events: Vec::new(),
                reserve_events: Vec::new(),
                reserve_providers: previous.reserve_providers.clone(),
            },
            std::slice::from_ref(&previous.authority_policy),
        )
        .expect("capture empty retained suffixes");
        assert_eq!(next.proof_outcomes, previous.proof_outcomes);
        assert_eq!(next.journal_events, previous.journal_events);
        assert_eq!(next.repair_events, previous.repair_events);
        assert_eq!(next.orderbook_events, previous.orderbook_events);
        assert_eq!(next.reserve_events, previous.reserve_events);
        let next_key = next.key.clone();
        let authority_policy_history = vec![next.authority_policy.clone()];
        assert_eq!(
            archive
                .insert_captured_state(next, authority_policy_history)
                .expect("insert empty captured successor"),
            ReputationFinalizedArchiveInsertOutcome::Inserted
        );
        assert!(matches!(
            archive.get_exact(&next_key),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
    }
    #[test]
    fn compacted_capture_appends_all_feeds_and_replays_after_reopen() {
        let directory = tempdir().expect("create archive directory");
        let first = projection_with_all_feeds(7, [0x71; 32]);
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(first.clone())
                .expect("insert all-feed retention floor");
            publish_test_checkpoint(&archive, &first.key);
        }
        let next = {
            let archive = open_archive(&directory, bounds());
            let previous = archive
                .latest_reconstruction_state_at_or_before(&first.key.network_id, first.key.height)
                .expect("reconstruct compacted predecessor")
                .expect("checkpoint state exists");
            let next = build_captured_successor_state(
                Some(&previous),
                captured_all_feed_successor(&previous, 8, [0x81; 32]),
                std::slice::from_ref(&previous.authority_policy),
            )
            .expect("append every retained feed");
            assert_eq!(next.proof_outcomes.prefix, previous.proof_outcomes.prefix);
            assert_eq!(next.journal_events.prefix, previous.journal_events.prefix);
            assert_eq!(next.repair_events.prefix, previous.repair_events.prefix);
            assert_eq!(
                next.orderbook_events.prefix,
                previous.orderbook_events.prefix
            );
            assert_eq!(next.reserve_events.prefix, previous.reserve_events.prefix);
            assert_eq!(next.proof_outcomes.retained_suffix.len(), 1);
            assert_eq!(next.journal_events.retained_suffix.len(), 1);
            assert_eq!(next.repair_events.retained_suffix.len(), 1);
            assert_eq!(next.orderbook_events.retained_suffix.len(), 1);
            assert_eq!(next.reserve_events.retained_suffix.len(), 1);
            let authority_policy_history = vec![next.authority_policy.clone()];
            archive
                .insert_captured_state(next.clone(), authority_policy_history)
                .expect("insert retained capture");
            let index = archive.read_index().expect("read capture index");
            let checkpoint = index
                .checkpoints
                .get(&first.key.network_id)
                .expect("active checkpoint");
            let anchor = index
                .by_height
                .get(&(next.key.network_id.clone(), next.key.height))
                .expect("captured successor anchor");
            assert_eq!(anchor.manifest.predecessor, Some(first.key.clone()));
            assert_eq!(
                anchor.manifest.predecessor_anchor_digest,
                Some(
                    checkpoint
                        .persisted
                        .checkpoint
                        .retention_floor_anchor_digest
                )
            );
            next
        };
        let reopened = open_archive(&directory, bounds());
        let restored = reopened
            .latest_reconstruction_state_at_or_before(&next.key.network_id, next.key.height)
            .expect("reconstruct retained successor after reopen")
            .expect("retained successor exists");
        assert_eq!(restored, next);
        let previous = reopened
            .latest_reconstruction_state_at_or_before(&first.key.network_id, first.key.height)
            .expect("reconstruct replay predecessor")
            .expect("checkpoint predecessor exists");
        let replay = build_captured_successor_state(
            Some(&previous),
            captured_all_feed_successor(&previous, 8, [0x81; 32]),
            std::slice::from_ref(&previous.authority_policy),
        )
        .expect("rebuild exact retained capture");
        let authority_policy_history = vec![replay.authority_policy.clone()];
        assert_eq!(
            reopened
                .insert_captured_state(replay, authority_policy_history)
                .expect("replay retained capture"),
            ReputationFinalizedArchiveInsertOutcome::ExactReplay
        );
        assert!(matches!(
            reopened.get_exact(&next.key),
            Err(ReputationFinalizedArchiveError::HistoryPruned { .. })
        ));
    }
    #[test]
    fn compacted_capture_rejects_prefix_cursor_substitution_and_feed_gaps() {
        let directory = tempdir().expect("create archive directory");
        let first = projection_with_all_feeds(7, [0x71; 32]);
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(first.clone())
                .expect("insert all-feed retention floor");
            publish_test_checkpoint(&archive, &first.key);
        }
        let archive = open_archive(&directory, bounds());
        let previous = archive
            .latest_reconstruction_state_at_or_before(&first.key.network_id, first.key.height)
            .expect("reconstruct compacted predecessor")
            .expect("checkpoint state exists");
        let mut gapped = captured_all_feed_successor(&previous, 8, [0x81; 32]);
        gapped.journal_events[0].sequence = 3;
        assert!(matches!(
            build_captured_successor_state(
                Some(&previous),
                gapped,
                std::slice::from_ref(&previous.authority_policy),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint { .. })
        ));
        let mut forked = captured_all_feed_successor(&previous, 8, [0x81; 32]);
        forked.proof_outcomes[0].block_height = first.key.height;
        forked.proof_outcomes[0].block_hash = [0x72; 32];
        forked.proof_outcomes[0].event_index = 1;
        assert!(matches!(
            build_captured_successor_state(
                Some(&previous),
                forked,
                std::slice::from_ref(&previous.authority_policy),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint { .. })
        ));
        let mut substituted = previous.clone();
        substituted
            .reserve_events
            .prefix
            .pruned_through
            .as_mut()
            .expect("reserve prefix cursor")
            .sequence = 2;
        let empty = CapturedReputationSuccessorV1 {
            key: ReputationFinalizedArchiveKeyV1::try_new(
                first.key.network_id.clone(),
                8,
                [0x81; 32],
            )
            .expect("construct malformed-cursor successor"),
            finalized_at_unix_ms: substituted.finalized_at_unix_ms + 1,
            authority_policy: substituted.authority_policy.clone(),
            proof_outcomes: Vec::new(),
            journal_events: Vec::new(),
            repair_events: Vec::new(),
            orderbook_events: Vec::new(),
            reserve_events: Vec::new(),
            reserve_providers: substituted.reserve_providers.clone(),
        };
        assert!(matches!(
            build_captured_successor_state(
                Some(&substituted),
                empty,
                std::slice::from_ref(&substituted.authority_policy),
            ),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint { .. })
        ));
        let mut future_prefix = previous;
        let future_cursor = future_prefix
            .journal_events
            .prefix
            .pruned_through
            .as_mut()
            .expect("journal prefix cursor");
        future_cursor.block_height = first.key.height + 1;
        future_cursor.block_hash = [0x81; 32];
        assert!(matches!(
            future_prefix.validate(),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "journal prefix source head lies outside its compacted prefix",
            })
        ));
    }
    #[test]
    fn recommitted_checkpoint_rejects_future_and_cross_feed_prefix_terminals() {
        let future_directory = tempdir().expect("create future-prefix archive directory");
        let first = projection_with_all_feeds(7, [0x71; 32]);
        let mut persisted = {
            let archive = open_archive(&future_directory, bounds());
            archive
                .insert(first.clone())
                .expect("insert future-prefix retention floor");
            publish_test_checkpoint(&archive, &first.key)
        };
        let future_event = journal_event(
            &first.authority_policy.policy,
            2,
            first.key.height + 1,
            [0x81; 32],
            0x42,
        );
        let future_prefix_digest = first
            .journal_events
            .iter()
            .chain(std::iter::once(&future_event))
            .try_fold([0; 32], |digest, event| {
                rolling_domain_digest(JOURNAL_PREFIX_DIGEST_DOMAIN_V1, digest, event)
            })
            .expect("commit canonical journal prefix through H+1");
        persisted.checkpoint.journal_prefix = ReputationFeedPrefixSummaryV1 {
            pruned_through: Some(event_position(journal_event_identity(&future_event))),
            rolling_prefix_digest: future_prefix_digest,
            pruned_event_count: 2,
        };
        let checkpoints = archive_root(&future_directory).join(CHECKPOINTS_DIRECTORY);
        let replacement_path =
            replace_test_checkpoint_with_recomputed_content_address(&checkpoints, persisted);
        assert!(replacement_path.is_file());
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&future_directory), bounds()),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "feed prefix terminal cursor crosses or disagrees with its retention-floor anchor",
            })
        ));
        let cross_feed_directory = tempdir().expect("create cross-feed-prefix archive directory");
        let first = projection_with_all_feeds(7, [0x71; 32]);
        let mut second = first.clone();
        second.key = ReputationFinalizedArchiveKeyV1::try_new(
            second.key.network_id.clone(),
            first.key.height + 1,
            [0x81; 32],
        )
        .expect("construct cross-feed retention floor");
        second.finalized_at_unix_ms += 1;
        let mut persisted = {
            let archive = open_archive(&cross_feed_directory, bounds());
            archive
                .insert(first)
                .expect("insert cross-feed predecessor");
            archive
                .insert(second.clone())
                .expect("insert cross-feed retention floor");
            publish_test_checkpoint(&archive, &second.key)
        };
        persisted
            .checkpoint
            .proof_prefix
            .pruned_through
            .as_mut()
            .expect("proof prefix cursor")
            .block_hash = [0x72; 32];
        let checkpoints = archive_root(&cross_feed_directory).join(CHECKPOINTS_DIRECTORY);
        let replacement_path =
            replace_test_checkpoint_with_recomputed_content_address(&checkpoints, persisted);
        assert!(replacement_path.is_file());
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&cross_feed_directory), bounds()),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "retained feeds disagree on a finalized block hash",
            })
        ));
    }
    #[test]
    fn checkpoint_tamper_rejects_and_policy_gc_preserves_predecessor_closure() {
        let tampered_directory = tempdir().expect("create tamper archive directory");
        let projection = sample_projection(7, [0x71; 32]);
        let checkpoint_path = {
            let archive = open_archive(&tampered_directory, bounds());
            archive
                .insert(projection.clone())
                .expect("insert tamper projection");
            let persisted = publish_test_checkpoint(&archive, &projection.key);
            archive
                .checkpoints
                .join(checkpoint_file_name(persisted.checkpoint_digest))
        };
        let bytes = fs::read(&checkpoint_path).expect("read test checkpoint");
        let mut persisted: PersistedReputationFinalizedVirtualBaseCheckpointV1 =
            decode_from_bytes_with_limits(&bytes, bounds().decode_limits())
                .expect("decode test checkpoint");
        persisted.checkpoint.cumulative_pruned_anchor_bytes += 1;
        fs::write(
            &checkpoint_path,
            norito::to_bytes(&persisted).expect("encode tampered checkpoint"),
        )
        .expect("write tampered checkpoint");
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&tampered_directory), bounds()),
            Err(ReputationFinalizedArchiveError::CheckpointDigestMismatch)
        ));
        let gc_directory = tempdir().expect("create policy-GC archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let mut second = first.clone();
        second.key =
            ReputationFinalizedArchiveKeyV1::try_new(second.key.network_id.clone(), 8, [0x81; 32])
                .expect("construct policy successor key");
        second.finalized_at_unix_ms += 1;
        let mut rotated = second.authority_policy.policy.clone();
        rotated.revision += 1;
        rotated.predecessor_policy_digest = Some(first.authority_policy.policy_digest);
        second.authority_policy = ReputationJournalAuthorityPolicyRecordV1::try_new(rotated,
(account(4)).clone(),
first.finalized_at_unix_ms,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: first.finalized_at_unix_ms, authority: (account(4)).clone(),
    }))
        .expect("construct exact successor policy");
        {
            let archive = open_archive(&gc_directory, bounds());
            archive.insert(first).expect("insert old policy anchor");
            archive
                .insert(second.clone())
                .expect("insert rotated policy anchor");
            assert_eq!(
                fs::read_dir(&archive.policies)
                    .expect("read policies before GC")
                    .count(),
                2
            );
            publish_test_checkpoint(&archive, &second.key);
        }
        let reopened = open_archive(&gc_directory, bounds());
        assert_eq!(
            fs::read_dir(&reopened.policies)
                .expect("read policies after GC")
                .count(),
            2
        );
        assert_eq!(
            reopened.health_generation().expect("stable GC generation"),
            3
        );
    }
    #[test]
    fn exact_hit_miss_and_replay_are_identity_pinned() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let projection = sample_projection(7, [0x71; 32]);
        assert_eq!(
            archive
                .insert(projection.clone())
                .expect("insert projection"),
            ReputationFinalizedArchiveInsertOutcome::Inserted
        );
        assert_eq!(
            archive
                .insert(projection.clone())
                .expect("accept exact replay"),
            ReputationFinalizedArchiveInsertOutcome::ExactReplay
        );
        assert_eq!(
            archive
                .get_exact(&projection.key)
                .expect("read exact projection"),
            Some(projection.clone())
        );
        let missing = ReputationFinalizedArchiveKeyV1::try_new(
            projection.key.network_id.clone(),
            projection.key.height,
            [0x72; 32],
        )
        .expect("valid missing key");
        assert_eq!(archive.get_exact(&missing).expect("read exact miss"), None);
    }
    #[test]
    fn archive_reopens_and_selects_latest_bounded_anchor() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let second = sample_projection(9, [0x91; 32]);
        {
            let archive = open_archive(&directory, bounds());
            archive.insert(first.clone()).expect("insert first");
            archive.insert(second.clone()).expect("insert second");
        }
        let reopened = open_archive(&directory, bounds());
        assert_eq!(reopened.health_generation().expect("indexed generation"), 2);
        assert_eq!(
            reopened
                .latest_at_or_before(&first.key.network_id, 8)
                .expect("select bounded anchor"),
            Some(first)
        );
        assert_eq!(
            reopened
                .latest_at_or_before(&second.key.network_id, 9)
                .expect("select latest anchor"),
            Some(second)
        );
    }
    #[test]
    fn policy_predecessor_closure_survives_compaction_restart() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let second = rotated_projection(&first, 8, [0x81; 32], 0x51);
        let third = rotated_projection(&second, 9, [0x91; 32], 0x52);
        {
            let archive = open_archive(&directory, bounds());
            archive.insert(first.clone()).expect("insert first policy");
            archive
                .insert(second.clone())
                .expect("insert second policy");
            archive.insert(third.clone()).expect("insert third policy");
            let (_, history) = archive
                .latest_at_or_before_with_policy_history(&third.key.network_id, third.key.height)
                .expect("read latest policy history")
                .expect("latest projection exists");
            assert_eq!(
                history,
                vec![
                    first.authority_policy.clone(),
                    second.authority_policy.clone(),
                    third.authority_policy.clone(),
                ]
            );
            publish_test_checkpoint(&archive, &third.key);
        }
        let archive = open_archive(&directory, bounds());
        {
            let index = archive.read_index().expect("read restarted index");
            assert_eq!(
                index.policies.len(),
                3,
                "checkpoint GC must retain the complete active predecessor closure"
            );
        }
        let mut successor = sample_projection(10, [0xA1; 32]);
        successor.authority_policy = third.authority_policy.clone();
        archive
            .insert(successor.clone())
            .expect("insert post-compaction successor");
        let (selected, history) = archive
            .latest_at_or_before_with_policy_history(
                &successor.key.network_id,
                successor.key.height,
            )
            .expect("read restarted policy history")
            .expect("successor exists");
        assert_eq!(selected, successor);
        assert_eq!(
            history,
            vec![
                first.authority_policy,
                second.authority_policy,
                third.authority_policy,
            ]
        );
    }
    #[test]
    fn captured_policy_history_accepts_same_block_revision_jump_and_recovers() {
        let directory = tempdir().expect("create archive directory");
        let first_projection = sample_projection(7, [0x71; 32]);
        let first = ReputationReconstructionStateV1::from_projection(first_projection);
        let rotation_time = first.finalized_at_unix_ms;
        let second = rotated_policy_record(&first.authority_policy, 0x51, rotation_time);
        let third = rotated_policy_record(&second, 0x52, rotation_time);
        let authority_policy_history = vec![
            first.authority_policy.clone(),
            second.clone(),
            third.clone(),
        ];
        let next = build_captured_successor_state(
            Some(&first),
            CapturedReputationSuccessorV1 {
                key: ReputationFinalizedArchiveKeyV1::try_new(
                    first.key.network_id.clone(),
                    8,
                    [0x81; 32],
                )
                .expect("construct captured successor key"),
                finalized_at_unix_ms: first.finalized_at_unix_ms + 1,
                authority_policy: third,
                proof_outcomes: Vec::new(),
                journal_events: Vec::new(),
                repair_events: Vec::new(),
                orderbook_events: Vec::new(),
                reserve_events: Vec::new(),
                reserve_providers: first.reserve_providers.clone(),
            },
            &authority_policy_history,
        )
        .expect("capture two same-block rotations");
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert_captured_state(first.clone(), vec![first.authority_policy.clone()])
                .expect("insert revision-one capture");
            archive
                .insert_captured_state(next.clone(), authority_policy_history.clone())
                .expect("insert revision-three capture");
        }
        let reopened = open_archive(&directory, bounds());
        assert_eq!(
            reopened
                .latest_reconstruction_state_at_or_before(&next.key.network_id, next.key.height)
                .expect("reconstruct revision-jump capture")
                .expect("revision-jump capture exists"),
            next
        );
        let index = reopened.read_index().expect("read recovered policy index");
        assert_eq!(
            resolve_authority_policy_history(
                &index,
                &authority_policy_history[2],
                first.finalized_at_unix_ms + 1,
            )
            .expect("recover complete authority-policy history"),
            authority_policy_history
        );
    }
    #[test]
    fn captured_policy_history_rejects_divergent_previous_revision() {
        let directory = tempdir().expect("create archive directory");
        let revision_one =
            ReputationReconstructionStateV1::from_projection(sample_projection(7, [0x71; 32]));
        let activation_time = revision_one.finalized_at_unix_ms;
        let canonical_second =
            rotated_policy_record(&revision_one.authority_policy, 0x61, activation_time);
        let mut previous = revision_one.clone();
        previous.authority_policy = canonical_second.clone();
        let canonical_history = vec![revision_one.authority_policy.clone(), canonical_second];
        let archive = open_archive(&directory, bounds());
        archive
            .insert_captured_state(previous.clone(), canonical_history)
            .expect("insert canonical revision-two capture");
        let divergent_second =
            rotated_policy_record(&revision_one.authority_policy, 0x71, activation_time);
        let divergent_third = rotated_policy_record(&divergent_second, 0x72, activation_time);
        let divergent_history = vec![
            revision_one.authority_policy,
            divergent_second,
            divergent_third.clone(),
        ];
        let error = build_captured_successor_state(
            Some(&previous),
            CapturedReputationSuccessorV1 {
                key: ReputationFinalizedArchiveKeyV1::try_new(
                    previous.key.network_id.clone(),
                    8,
                    [0x81; 32],
                )
                .expect("construct divergent successor key"),
                finalized_at_unix_ms: previous.finalized_at_unix_ms + 1,
                authority_policy: divergent_third,
                proof_outcomes: Vec::new(),
                journal_events: Vec::new(),
                repair_events: Vec::new(),
                orderbook_events: Vec::new(),
                reserve_events: Vec::new(),
                reserve_providers: previous.reserve_providers.clone(),
            },
            &divergent_history,
        )
        .expect_err("divergent revision-two lineage must fail closed");
        assert!(matches!(
            error,
            ReputationFinalizedArchiveError::InvalidProjection {
                reason: "authority policy history substitutes the previous active record",
            }
        ));
    }
    #[test]
    fn restart_rejects_missing_policy_predecessor_artifact() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let second = rotated_projection(&first, 8, [0x81; 32], 0x61);
        {
            let archive = open_archive(&directory, bounds());
            archive.insert(first.clone()).expect("insert first policy");
            archive.insert(second).expect("insert second policy");
            let first_persisted =
                PersistedReputationAuthorityPolicyV1::try_new(first.authority_policy)
                    .expect("persisted first policy");
            fs::remove_file(
                archive
                    .policies
                    .join(policy_file_name(first_persisted.record_digest)),
            )
            .expect("remove predecessor artifact");
        }
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()),
            Err(ReputationFinalizedArchiveError::MissingPolicy { .. })
        ));
    }
    #[test]
    fn checkpoint_history_commitment_rejects_substituted_predecessor_metadata() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let second = rotated_projection(&first, 8, [0x81; 32], 0x62);
        {
            let archive = open_archive(&directory, bounds());
            archive.insert(first.clone()).expect("insert first policy");
            archive
                .insert(second.clone())
                .expect("insert second policy");
            publish_test_checkpoint(&archive, &second.key);
        }
        {
            let archive = open_archive(&directory, bounds());
            let original =
                PersistedReputationAuthorityPolicyV1::try_new(first.authority_policy.clone())
                    .expect("persist original predecessor");
            fs::remove_file(
                archive
                    .policies
                    .join(policy_file_name(original.record_digest)),
            )
            .expect("remove original predecessor");
            let substituted_policy = first.authority_policy.policy.clone();
            let substituted_activation = first.authority_policy.activated_at_unix_ms;
            let substituted = ReputationJournalAuthorityPolicyRecordV1::try_new(substituted_policy,
(account(0x7F)).clone(),
substituted_activation,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: substituted_activation, authority: (account(0x7F)).clone(),
    }))
            .expect("construct substituted activation metadata");
            let substituted = PersistedReputationAuthorityPolicyV1::try_new(substituted)
                .expect("persist substituted predecessor");
            let bytes = encode_bounded_artifact(&substituted, archive.bounds)
                .expect("encode substituted predecessor");
            let path = archive
                .policies
                .join(policy_file_name(substituted.record_digest));
            publish_immutable_bytes(&archive.policies, archive.policies_identity, &path, &bytes)
                .expect("publish substituted predecessor");
        }
        assert!(matches!(
            ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()),
            Err(ReputationFinalizedArchiveError::InvalidCheckpoint {
                reason: "checkpoint authority-policy history commitment was substituted",
            })
        ));
    }
    #[test]
    fn activation_floor_is_explicit_and_survives_restart() {
        let directory = tempdir().expect("create archive directory");
        let first = sample_projection(7, [0x71; 32]);
        let second = sample_projection(9, [0x91; 32]);
        {
            let archive = open_archive(&directory, bounds());
            assert_eq!(
                archive
                    .activation_floor(&first.key.network_id)
                    .expect("read empty activation floor"),
                None
            );
            archive.insert(first.clone()).expect("insert first");
            archive.insert(second).expect("insert second");
            assert_eq!(
                archive
                    .activation_floor(&first.key.network_id)
                    .expect("read activation floor"),
                Some(first.key.clone())
            );
        }
        let reopened = open_archive(&directory, bounds());
        assert_eq!(
            reopened
                .activation_floor(&first.key.network_id)
                .expect("read restarted activation floor"),
            Some(first.key)
        );
    }
    #[test]
    fn archive_before_view_publication_restarts_as_exact_replay() {
        let directory = tempdir().expect("create archive directory");
        let projection = sample_projection(7, [0x71; 32]);
        {
            let archive = open_archive(&directory, bounds());
            archive
                .insert(projection.clone())
                .expect("simulate archive publication before WSV publication");
        }
        let reopened = open_archive(&directory, bounds());
        reopened
            .require_contiguous_capture_key(&projection.key)
            .expect("same Kura-authenticated key remains admissible on replay");
        assert_eq!(
            reopened
                .insert(projection.clone())
                .expect("reconcile exact archived projection"),
            ReputationFinalizedArchiveInsertOutcome::ExactReplay
        );
        assert_eq!(
            reopened
                .get_exact(&projection.key)
                .expect("read reconciled projection"),
            Some(projection)
        );
    }
    #[test]
    fn qualification_coverage_rejects_every_gap_above_activation_floor() {
        let network_id = network_id(0x61);
        let key = |height, marker| {
            ReputationFinalizedArchiveKeyV1::try_new(network_id.clone(), height, [marker; 32])
                .expect("construct coverage key")
        };
        let contiguous = vec![
            (key(7, 0x71), 1_700_000_000_007),
            (key(8, 0x81), 1_700_000_000_008),
            (key(9, 0x91), 1_700_000_000_009),
        ];
        validate_contiguous_archive_coverage(&network_id, &contiguous)
            .expect("contiguous activation coverage");
        let gapped = vec![contiguous[0].clone(), contiguous[2].clone()];
        assert!(matches!(
            validate_contiguous_archive_coverage(&network_id, &gapped),
            Err(ReputationFinalizedArchiveError::ArchiveCoverageGap {
                missing_height: 8,
                observed_height: 9,
                ..
            })
        ));
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        archive
            .insert(sample_projection(7, [0x71; 32]))
            .expect("insert activation floor");
        assert!(matches!(
            archive.require_contiguous_capture_key(&key(9, 0x91)),
            Err(ReputationFinalizedArchiveError::ArchiveCoverageGap {
                missing_height: 8,
                observed_height: 9,
                ..
            })
        ));
    }
    #[test]
    fn capture_pagination_is_strict_and_memory_bounded() {
        let mut pages = VecDeque::from([
            (
                None,
                CapturePage {
                    rows: vec![1_u64, 2],
                    has_more: true,
                    next_after: Some(2),
                },
            ),
            (
                Some(2),
                CapturePage {
                    rows: vec![3_u64],
                    has_more: false,
                    next_after: None,
                },
            ),
        ]);
        let mut budget = ProjectionCaptureBudget::new(1 << 20);
        let rows = collect_capture_pages(
            "test rows",
            None,
            &mut budget,
            |after| {
                let (expected_after, page) = pages.pop_front().expect("expected capture page");
                assert_eq!(after, expected_after);
                Ok(page)
            },
            |row| *row,
        )
        .expect("collect strict capture pages");
        assert_eq!(rows, vec![1, 2, 3]);
        assert!(pages.is_empty());
        let mut invalid_budget = ProjectionCaptureBudget::new(0);
        assert!(matches!(
            collect_capture_pages(
                "bounded rows",
                None,
                &mut invalid_budget,
                |_| Ok(CapturePage {
                    rows: vec![1_u64],
                    has_more: false,
                    next_after: None,
                }),
                |row| *row,
            ),
            Err(
                ReputationFinalizedArchiveError::ProjectionCaptureBudgetExceeded {
                    projection: "bounded rows",
                    ..
                }
            )
        ));
        let mut continuation_budget = ProjectionCaptureBudget::new(1 << 20);
        assert!(matches!(
            collect_capture_pages(
                "bad continuation",
                None,
                &mut continuation_budget,
                |_| Ok(CapturePage {
                    rows: vec![1_u64],
                    has_more: true,
                    next_after: Some(2),
                }),
                |row| *row,
            ),
            Err(
                ReputationFinalizedArchiveError::ProjectionCapturePagination {
                    projection: "bad continuation",
                    reason: "capture continuation differs from the terminal row",
                }
            )
        ));
    }
    #[cfg(any(unix, windows))]
    #[test]
    fn writer_ownership_rejects_a_live_contender_and_releases_on_drop() {
        let directory = tempdir().expect("create archive directory");
        let root = archive_root(&directory);
        let first =
            ReputationFinalizedArchive::try_open(&root, bounds()).expect("open first archive");
        assert!(matches!(
            ReputationFinalizedArchive::try_open(&root, bounds()),
            Err(ReputationFinalizedArchiveError::WriterBusy { .. })
        ));
        drop(first);
        ReputationFinalizedArchive::try_open(root, bounds())
            .expect("kernel released writer ownership after drop");
    }
    #[test]
    fn tampered_record_fails_bounded_canonical_read_and_restart() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let projection = sample_projection(7, [0x71; 32]);
        archive
            .insert(projection.clone())
            .expect("insert projection");
        let path = archive
            .record_path(&projection.key)
            .expect("derive record path");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open record for corruption");
        let last = file
            .metadata()
            .expect("read record metadata")
            .len()
            .checked_sub(1)
            .expect("record is not empty");
        file.seek(SeekFrom::Start(last))
            .expect("seek to final record byte");
        let mut original = [0_u8; 1];
        file.read_exact(&mut original)
            .expect("read final record byte");
        file.seek(SeekFrom::Start(last))
            .expect("rewind to final record byte");
        file.write_all(&[original[0] ^ 0xFF])
            .expect("corrupt final record byte");
        file.sync_all().expect("sync record corruption");
        assert!(archive.get_exact(&projection.key).is_err());
        drop(archive);
        assert!(ReputationFinalizedArchive::try_open(archive_root(&directory), bounds()).is_err());
    }
    #[test]
    fn exact_path_rejects_a_valid_record_for_another_anchor() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let first = sample_projection(7, [0x71; 32]);
        let second = sample_projection(8, [0x81; 32]);
        archive.insert(first.clone()).expect("insert first");
        archive.insert(second.clone()).expect("insert second");
        let first_path = archive.record_path(&first.key).expect("first path");
        let second_path = archive.record_path(&second.key).expect("second path");
        fs::copy(second_path, first_path).expect("substitute canonical second record");
        assert!(matches!(
            archive.get_exact(&first.key),
            Err(ReputationFinalizedArchiveError::ExactKeyMismatch { .. })
        ));
    }
    #[test]
    fn record_and_aggregate_bounds_fail_closed() {
        let directory = tempdir().expect("create archive directory");
        let tiny = ReputationFinalizedArchiveBounds::try_new(32, 1, 32).expect("valid tiny bounds");
        let archive = open_archive(&directory, tiny);
        assert!(matches!(
            archive.insert(sample_projection(7, [0x71; 32])),
            Err(ReputationFinalizedArchiveError::RecordTooLarge { .. })
        ));
        let directory = tempdir().expect("create second archive directory");
        let one_record = ReputationFinalizedArchiveBounds::try_new(1 << 20, 1, 2 << 20)
            .expect("valid one-record bounds");
        let archive = open_archive(&directory, one_record);
        archive
            .insert(sample_projection(7, [0x71; 32]))
            .expect("insert first projection");
        assert!(matches!(
            archive.insert(sample_projection(8, [0x81; 32])),
            Err(ReputationFinalizedArchiveError::RetentionRequired { .. })
        ));
    }
    #[test]
    fn policy_first_crash_retains_a_bounded_nonqualifying_cache_entry() {
        let directory = tempdir().expect("create archive directory");
        let one_per_namespace = ReputationFinalizedArchiveBounds::try_new(1 << 20, 1, 4 << 20)
            .expect("valid one-per-namespace bounds");
        let projection = sample_projection(7, [0x71; 32]);
        let (orphan_digest, orphan_path, orphan_bytes) = {
            let archive = open_archive(&directory, one_per_namespace);
            let policy =
                PersistedReputationAuthorityPolicyV1::try_new(projection.authority_policy.clone())
                    .expect("construct persisted policy");
            let bytes =
                encode_bounded_artifact(&policy, one_per_namespace).expect("encode orphan policy");
            let path = archive
                .policies
                .join(policy_file_name(policy.record_digest));
            // Simulate process loss after the policy-first durable publication
            // and before the corresponding anchor publication.
            publish_immutable_bytes(&archive.policies, archive.policies_identity, &path, &bytes)
                .expect("publish policy crash artifact");
            (policy.record_digest, path, bounded_bytes_len(&bytes))
        };
        let archive = open_archive(&directory, one_per_namespace);
        assert!(
            orphan_path.is_file(),
            "restart retains immutable policy bytes"
        );
        {
            let index = archive.read_index().expect("read restarted index");
            assert_eq!(index.anchor_count, 0);
            assert_eq!(index.policy_count, 1);
            assert_eq!(index.total_bytes, orphan_bytes);
            assert!(index.policies.contains_key(&orphan_digest));
        }
        assert!(matches!(
            archive.health_generation(),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable { .. })
        ));
        let mut different_policy = projection.clone();
        let mut different_body = different_policy.authority_policy.policy.clone();
        different_body.por_recorder_authority = account(0x61);
        different_policy.authority_policy = ReputationJournalAuthorityPolicyRecordV1::try_new(different_body,
(account(0x62)).clone(),
1_700_000_000_000,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: 1_700_000_000_000, authority: (account(0x62)).clone(),
    }))
        .expect("construct different genesis policy");
        assert!(matches!(
            archive.insert(different_policy),
            Err(ReputationFinalizedArchiveError::RetentionRequired {
                proposed_policy_entries: 2,
                maximum_policy_entries: 1,
                ..
            })
        ));
        archive
            .insert(projection.clone())
            .expect("matching anchor reuses retained policy");
        {
            let index = archive.read_index().expect("read recovered index");
            assert_eq!(index.anchor_count, 1);
            assert_eq!(index.policy_count, 1);
            assert_eq!(index.policies.len(), 1);
            assert!(index.total_bytes > orphan_bytes);
        }
        assert_eq!(
            archive
                .health_generation()
                .expect("referenced anchor qualifies archive"),
            1
        );
        let mut successor = projection;
        successor.key = ReputationFinalizedArchiveKeyV1::try_new(
            successor.key.network_id.clone(),
            8,
            [0x81; 32],
        )
        .expect("construct successor key");
        successor.finalized_at_unix_ms += 1;
        assert!(matches!(
            archive.insert(successor),
            Err(ReputationFinalizedArchiveError::RetentionRequired {
                proposed_entries: 2,
                maximum_entries: 1,
                ..
            })
        ));
    }
    #[test]
    fn conflicting_content_and_finalized_fork_are_rejected() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let original = sample_projection(7, [0x71; 32]);
        archive.insert(original.clone()).expect("insert original");
        let mut conflict = original.clone();
        conflict.finalized_at_unix_ms += 1;
        assert!(matches!(
            archive.insert(conflict),
            Err(ReputationFinalizedArchiveError::ConflictingProjection { .. })
        ));
        assert!(matches!(
            archive.insert(sample_projection(7, [0x72; 32])),
            Err(ReputationFinalizedArchiveError::FinalizedFork { .. })
        ));
    }
    #[test]
    fn append_only_deltas_grow_linearly_and_reconstruct_full_history() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let mut latest = sample_projection(7, [0x70; 32]);
        let mut full_projection_bytes = 0_u64;
        for offset in 0_u8..8 {
            let height = 7 + u64::from(offset);
            let block_hash = [0x70 + offset; 32];
            latest.key = ReputationFinalizedArchiveKeyV1::try_new(
                latest.key.network_id.clone(),
                height,
                block_hash,
            )
            .expect("valid advancing key");
            latest.finalized_at_unix_ms = 1_750_000_000_000 + height;
            latest.journal_events.push(journal_event(
                &latest.authority_policy.policy,
                u64::from(offset) + 1,
                height,
                block_hash,
                0x20 + offset,
            ));
            full_projection_bytes = full_projection_bytes
                .checked_add(bounded_bytes_len(
                    &norito::to_bytes(&latest).expect("encode full projection"),
                ))
                .expect("full projection byte count");
            archive
                .insert(latest.clone())
                .expect("append compact anchor delta");
            let persisted = archive
                .load_anchor_at(
                    &archive
                        .record_path(&latest.key)
                        .expect("derive compact anchor path"),
                    Some(&latest.key),
                )
                .expect("load compact anchor");
            assert_eq!(persisted.delta.journal_events.len(), 1);
        }
        let compact_anchor_bytes = fs::read_dir(&archive.anchors)
            .expect("read anchor directory")
            .try_fold(0_u64, |total, entry| {
                let size = entry?.metadata()?.len();
                Ok::<_, io::Error>(total + size)
            })
            .expect("sum compact anchor bytes");
        assert!(compact_anchor_bytes < full_projection_bytes);
        assert_eq!(
            fs::read_dir(&archive.policies)
                .expect("read policy directory")
                .count(),
            1
        );
        assert_eq!(
            archive
                .get_exact(&latest.key)
                .expect("reconstruct compact tip"),
            Some(latest)
        );
        assert_eq!(archive.health_generation().expect("live generation"), 8);
    }
    #[test]
    fn reserve_provider_deltas_reconstruct_upserts_and_removals() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let mut first = sample_projection(7, [0x71; 32]);
        first.reserve_providers = vec![reserve_account(0x21, 1), reserve_account(0x31, 1)];
        archive.insert(first.clone()).expect("insert provider base");
        let mut second = first.clone();
        second.key =
            ReputationFinalizedArchiveKeyV1::try_new(second.key.network_id.clone(), 8, [0x81; 32])
                .expect("valid second key");
        second.finalized_at_unix_ms += 1;
        second.reserve_providers = vec![reserve_account(0x31, 2), reserve_account(0x41, 1)];
        archive
            .insert(second.clone())
            .expect("insert provider delta");
        let persisted = archive
            .load_anchor_at(
                &archive
                    .record_path(&second.key)
                    .expect("derive provider-delta path"),
                Some(&second.key),
            )
            .expect("load provider delta");
        assert_eq!(
            persisted.delta.reserve_provider_removals,
            vec![ProviderId::new([0x21; 32])]
        );
        assert_eq!(
            persisted
                .delta
                .reserve_provider_upserts
                .iter()
                .map(|account| account.terms.provider_id)
                .collect::<Vec<_>>(),
            vec![ProviderId::new([0x31; 32]), ProviderId::new([0x41; 32])]
        );
        assert_eq!(
            archive.get_exact(&first.key).expect("reconstruct base"),
            Some(first)
        );
        assert_eq!(
            archive.get_exact(&second.key).expect("reconstruct delta"),
            Some(second)
        );
    }
    #[test]
    fn cross_feed_hash_disagreement_and_noncanonical_reserve_accounts_fail() {
        let mut cross_feed = sample_projection(8, [0x81; 32]);
        cross_feed.journal_events.push(journal_event(
            &cross_feed.authority_policy.policy,
            1,
            7,
            [0x71; 32],
            0x21,
        ));
        cross_feed
            .orderbook_events
            .push(orderbook_event(7, [0x72; 32]));
        assert!(matches!(
            cross_feed.validate(),
            Err(ReputationFinalizedArchiveError::InvalidProjection { .. })
        ));
        let mut invalid_debt = sample_projection(8, [0x81; 32]);
        let mut account = reserve_account(0x31, 1);
        account.debt_principal = XorQuantity::try_from_micro(2_000_000_000).expect("debt fixture");
        invalid_debt.reserve_providers.push(account);
        assert!(matches!(
            invalid_debt.validate(),
            Err(ReputationFinalizedArchiveError::InvalidProjection { .. })
        ));
        let mut invalid_interest = sample_projection(8, [0x81; 32]);
        let mut account = reserve_account(0x31, 1);
        account.accrued_interest = XorQuantity::try_from_micro(1).expect("interest fixture");
        invalid_interest.reserve_providers.push(account);
        assert!(matches!(
            invalid_interest.validate(),
            Err(ReputationFinalizedArchiveError::InvalidProjection { .. })
        ));
        let mut invalid_pending = sample_projection(8, [0x81; 32]);
        let mut account = reserve_account(0x31, 1);
        account.pending_movements = RESERVE_MAX_PENDING_MOVEMENTS_V1 + 1;
        invalid_pending.reserve_providers.push(account);
        assert!(matches!(
            invalid_pending.validate(),
            Err(ReputationFinalizedArchiveError::InvalidProjection { .. })
        ));
        let mut invalid_appeals = sample_projection(8, [0x81; 32]);
        let mut account = reserve_account(0x31, 1);
        account.open_appeals = RESERVE_MAX_OPEN_APPEALS_V1 + 1;
        invalid_appeals.reserve_providers.push(account);
        assert!(matches!(
            invalid_appeals.validate(),
            Err(ReputationFinalizedArchiveError::InvalidProjection { .. })
        ));
        let mut invalid_timestamp = sample_projection(8, [0x81; 32]);
        let mut account = reserve_account(0x31, 1);
        account.updated_at_unix = 1_800_000_000;
        invalid_timestamp.reserve_providers.push(account);
        assert!(matches!(
            invalid_timestamp.validate(),
            Err(ReputationFinalizedArchiveError::InvalidProjection { .. })
        ));
    }
    #[test]
    fn synchronized_index_keeps_concurrent_reads_on_complete_generations() {
        let directory = tempdir().expect("create archive directory");
        let bounds = ReputationFinalizedArchiveBounds::try_new(1 << 20, 64, 64 << 20)
            .expect("valid concurrent bounds");
        let archive = Arc::new(open_archive(&directory, bounds));
        archive
            .insert(sample_projection(7, [0x71; 32]))
            .expect("seed archive");
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        {
            let archive = Arc::clone(&archive);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                for height in 8_u8..24 {
                    archive
                        .insert(sample_projection(
                            u64::from(height),
                            [height.wrapping_mul(3); 32],
                        ))
                        .expect("append concurrent generation");
                }
            }));
        }
        for _ in 0..3 {
            let archive = Arc::clone(&archive);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..64 {
                    let projection = archive
                        .latest_at_or_before(&network_id(0x61), u64::MAX)
                        .expect("read synchronized index")
                        .expect("archive remains non-empty");
                    projection.validate().expect("read one complete generation");
                }
            }));
        }
        for worker in workers {
            worker.join().expect("archive worker completed");
        }
        assert_eq!(archive.health_generation().expect("final generation"), 17);
    }
    #[test]
    fn startup_removes_direct_crash_staged_files() {
        let directory = tempdir().expect("create archive directory");
        let staged_path = {
            let archive = open_archive(&directory, bounds());
            let path = archive.anchors.join(".staged-interrupted-anchor");
            drop(archive);
            path
        };
        fs::write(&staged_path, b"partial canonical artifact").expect("write staged crash file");
        let reopened = open_archive(&directory, bounds());
        assert!(!staged_path.exists());
        assert!(matches!(
            reopened.health_generation(),
            Err(ReputationFinalizedArchiveError::ArchiveUnavailable { .. })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn startup_recovers_a_stage_linked_to_one_canonical_policy_target() {
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempdir().expect("create archive directory");
        let projection = sample_projection(7, [0x71; 32]);
        let archive = open_archive(&directory, bounds());
        let policy =
            PersistedReputationAuthorityPolicyV1::try_new(projection.authority_policy.clone())
                .expect("construct persisted policy");
        let bytes = encode_bounded_artifact(&policy, bounds()).expect("encode persisted policy");
        let staged = archive.policies.join(".staged-linked-policy-crash");
        let target = archive
            .policies
            .join(policy_file_name(policy.record_digest));
        drop(archive);
        fs::write(&staged, bytes).expect("write linked staged policy");
        fs::hard_link(&staged, &target).expect("link canonical policy target");
        assert_eq!(
            fs::metadata(&staged).expect("read staged metadata").nlink(),
            2
        );
        let reopened = open_archive(&directory, bounds());
        assert!(!staged.exists());
        assert_eq!(
            fs::metadata(&target)
                .expect("read recovered target metadata")
                .nlink(),
            1
        );
        let index = reopened.read_index().expect("read recovered index");
        assert_eq!(index.anchor_count, 0);
        assert_eq!(index.policy_count, 1);
        assert!(index.policies.contains_key(&policy.record_digest));
    }
    #[cfg(unix)]
    #[test]
    fn descriptor_relative_publication_resists_directory_substitution() {
        use std::os::unix::fs::symlink;
        for substitute_before_create in [true, false] {
            let directory = tempdir().expect("create archive directory");
            let external_guard = tempdir().expect("create replacement directory");
            let external = fs::canonicalize(external_guard.path())
                .expect("canonicalize replacement directory");
            let archive = open_archive(&directory, bounds());
            let phase = if substitute_before_create {
                "before-create"
            } else {
                "before-link"
            };
            let target_name = format!("{phase}.anchor.to");
            let target = archive.anchors.join(&target_name);
            let moved = archive.root.join(format!("anchors-bound-{phase}"));
            let substitute = || {
                fs::rename(&archive.anchors, &moved).expect("move bound archive directory");
                symlink(&external, &archive.anchors).expect("substitute archive directory");
            };
            let result = if substitute_before_create {
                publish_immutable_bytes_unix_with_hooks(
                    &archive.anchors,
                    archive.anchors_identity,
                    &target,
                    target.file_name().expect("target name"),
                    phase.as_bytes(),
                    substitute,
                    || {},
                )
            } else {
                publish_immutable_bytes_unix_with_hooks(
                    &archive.anchors,
                    archive.anchors_identity,
                    &target,
                    target.file_name().expect("target name"),
                    phase.as_bytes(),
                    || {},
                    substitute,
                )
            };
            result.expect("descriptor-relative publication survives path substitution");
            assert_eq!(
                fs::read(moved.join(&target_name)).expect("read bound publication"),
                phase.as_bytes()
            );
            assert!(
                !external.join(&target_name).exists(),
                "replacement namespace must remain untouched"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn descriptor_relative_publication_is_no_clobber_and_cleans_staging() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let target = archive.anchors.join("no-clobber.anchor.to");
        let original = [0x41; 32];
        publish_immutable_bytes(
            &archive.anchors,
            archive.anchors_identity,
            &target,
            &original,
        )
        .expect("publish original artifact");
        publish_immutable_bytes(
            &archive.anchors,
            archive.anchors_identity,
            &target,
            &original,
        )
        .expect("accept byte-identical publication");
        assert!(matches!(
            publish_immutable_bytes(
                &archive.anchors,
                archive.anchors_identity,
                &target,
                &[0x42; 32],
            ),
            Err(ReputationFinalizedArchiveError::InvalidStorage { .. })
        ));
        assert_eq!(fs::read(&target).expect("read immutable target"), original);
        assert_eq!(
            fs::read_dir(&archive.anchors)
                .expect("read archive directory")
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(STAGED_FILE_PREFIX))
                })
                .count(),
            0
        );
    }
    #[cfg(windows)]
    #[test]
    fn unsupported_publication_fails_before_any_path_mutation() {
        let directory = tempdir().expect("create archive directory");
        let archive = open_archive(&directory, bounds());
        let target = archive.anchors.join("unsupported.anchor.to");
        assert!(matches!(
            publish_immutable_bytes(
                &archive.anchors,
                archive.anchors_identity,
                &target,
                b"must not be written",
            ),
            Err(ReputationFinalizedArchiveError::UnsupportedPlatform { .. })
        ));
        assert!(!target.exists());
        assert_eq!(
            fs::read_dir(&archive.anchors)
                .expect("read archive directory")
                .count(),
            0
        );
    }
    #[test]
    fn storage_root_rejects_relative_parent_and_symlink_ancestry() {
        assert!(matches!(
            ReputationFinalizedArchive::try_open("relative/archive", bounds()),
            Err(ReputationFinalizedArchiveError::InvalidStorage { .. })
        ));
        let directory = tempdir().expect("create archive directory");
        let root = archive_root(&directory);
        assert!(matches!(
            ReputationFinalizedArchive::try_open(
                root.join("child").join("..").join("archive"),
                bounds(),
            ),
            Err(ReputationFinalizedArchiveError::InvalidStorage { .. })
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let direct = root.join("direct");
            fs::create_dir(&direct).expect("create direct ancestor");
            let alias = root.join("alias");
            symlink(&direct, &alias).expect("create ancestor symlink");
            assert!(matches!(
                ReputationFinalizedArchive::try_open(alias.join("archive"), bounds()),
                Err(ReputationFinalizedArchiveError::InvalidStorage { .. })
            ));
        }
    }
}
