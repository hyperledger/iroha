//! Durable provider-indexed archive for finalized SoraFS replication orders.
//!
//! The archive is a committed projection, never a source of finality or mutation authority. A
//! commit-owned caller supplies one immutable [`StateReadOnly`] view and the same-State
//! certified-chain reader. Each immutable record stores only changed provider projections, links the exact
//! preceding height, and commits to the complete provider-indexed state.
//!
//! The first record for a network is an explicit activation floor. Authenticated retention may
//! replace a prefix with a content-addressed virtual base while preserving the exact page and
//! cursor bytes at the new floor. Queries below an activation or retention floor fail with distinct
//! typed errors; no current-head fallback or inferred historical coverage exists. Runtime
//! credentials, grants, endpoints, private keys, and payload bytes are absent from every public and
//! durable type.
//!
//! First-release records always encode the optional consensus Musubi archive binding, including an
//! explicit `None` for generic orders. Pre-release archive bytes that lack that field also use a
//! retired state-root domain and cannot pass canonical decode/validation; operators must reset that
//! disposable archive namespace rather than migrate it.
use super::archive_finality::{ArchiveFinalityError, CertifiedArchiveView};
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
    secure_file_metadata::{self, SecureMetadata},
    state::{StateReadOnly, WorldReadOnly as _},
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    musubi::MusubiReplicationOrderArchiveBindingV1,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            PinManifestRecord, PinStatus, ProviderIngestCompletionAuthorityV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId, ReplicationOrderRecord,
            ReplicationOrderStatus,
        },
    },
};
use mv::storage::StorageReadOnly as _;
use norito::{
    DecodeLimits, decode_from_bytes_with_limits,
    derive::{NoritoDeserialize, NoritoSerialize},
};
use sorafs_manifest::capacity::{MAX_CAPACITY_METADATA_VALUE_BYTES, ReplicationOrderV1};
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
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
const RECORDS_DIRECTORY: &str = "records";
const CHECKPOINTS_DIRECTORY: &str = "checkpoints";
const WRITER_LOCK_FILE: &str = ".writer.lock";
const RECORD_FILE_SUFFIX: &str = ".provider-ingest-anchor.to";
const CHECKPOINT_FILE_SUFFIX: &str = ".provider-ingest-base.to";
const KEY_DIGEST_DOMAIN_V1: &[u8] = b"iroha.sorafs.provider-ingest.finalized-archive-key.v1\0";
const RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-archive-record.v1\0";
const CHECKPOINT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-archive-checkpoint.v1\0";
const PREFIX_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-archive-prefix.v1\0";
const RETENTION_PROPOSAL_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-archive-retention-proposal.v1\0";
const RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-archive-retention-checkpoint-bytes.v1\0";
const RETENTION_APPROVAL_REVISION_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-archive-retention-approval.v1\0";
const RETENTION_APPROVAL_NAMESPACE_V1: [u8; 32] = *b"sorafs.pi.archive.retention.v1.0";
const STATE_ROOT_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.finalized-provider-state.first-release.v1\0";
const MILLIS_PER_UNIX_SECOND: u64 = 1_000;
const REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1: usize = 256 * 1024;
const RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1: usize = 64 * 1024;
const MAX_DECODE_NESTING_DEPTH: usize = 128;
const REPLICATION_ORDER_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    MAX_CAPACITY_METADATA_VALUE_BYTES,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1,
    131_072,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
const RETENTION_APPROVAL_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    4 * 1024,
    RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1,
    1_024,
    RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
/// Resource ceilings applied to startup, capture, reconstruction, and paging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestFinalizedArchiveBoundsV1 {
    max_record_bytes: u64,
    max_archive_entries: NonZeroUsize,
    max_total_bytes: u64,
    max_providers_per_anchor: NonZeroUsize,
    max_orders_per_provider: NonZeroUsize,
    max_total_orders_per_anchor: NonZeroUsize,
    max_page_rows: NonZeroUsize,
}
impl ProviderIngestFinalizedArchiveBoundsV1 {
    /// Construct explicit archive and query ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero, internally inconsistent, or target-unrepresentable ceilings.
    pub fn try_new(
        max_record_bytes: u64,
        max_archive_entries: usize,
        max_total_bytes: u64,
        max_providers_per_anchor: usize,
        max_orders_per_provider: usize,
        max_total_orders_per_anchor: usize,
        max_page_rows: usize,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let max_archive_entries = NonZeroUsize::new(max_archive_entries).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum archive entries must be non-zero",
            },
        )?;
        let max_providers_per_anchor = NonZeroUsize::new(max_providers_per_anchor).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum providers per anchor must be non-zero",
            },
        )?;
        let max_orders_per_provider = NonZeroUsize::new(max_orders_per_provider).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum orders per provider must be non-zero",
            },
        )?;
        let max_total_orders_per_anchor = NonZeroUsize::new(max_total_orders_per_anchor).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum total orders per anchor must be non-zero",
            },
        )?;
        let max_page_rows = NonZeroUsize::new(max_page_rows).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum page rows must be non-zero",
            },
        )?;
        let max_record_bytes_usize = usize::try_from(max_record_bytes).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum record bytes exceed this target's address space",
            }
        })?;
        if max_record_bytes == 0 {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum record bytes must be non-zero",
            });
        }
        if max_total_bytes < max_record_bytes {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum total bytes must cover one maximum-sized record",
            });
        }
        if max_record_bytes_usize.checked_mul(4).is_none() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum record bytes cannot produce a decode allocation ceiling",
            });
        }
        if max_page_rows > max_orders_per_provider {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum page rows exceed maximum orders per provider",
            });
        }
        if max_orders_per_provider
            .get()
            .checked_mul(max_providers_per_anchor.get())
            .is_none()
            || max_total_orders_per_anchor
                .get()
                .checked_mul(64)
                .and_then(|orders| {
                    max_providers_per_anchor
                        .get()
                        .checked_mul(16)
                        .and_then(|providers| orders.checked_add(providers))
                })
                .and_then(|elements| elements.checked_add(1_024))
                .is_none()
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "provider/order ceilings overflow aggregate accounting",
            });
        }
        Ok(Self {
            max_record_bytes,
            max_archive_entries,
            max_total_bytes,
            max_providers_per_anchor,
            max_orders_per_provider,
            max_total_orders_per_anchor,
            max_page_rows,
        })
    }
    /// Maximum canonical bytes accepted for one immutable record.
    #[must_use]
    pub const fn max_record_bytes(self) -> u64 {
        self.max_record_bytes
    }
    /// Maximum immutable anchor records retained in the archive.
    #[must_use]
    pub const fn max_archive_entries(self) -> usize {
        self.max_archive_entries.get()
    }
    /// Maximum aggregate canonical bytes retained by the archive.
    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }
    /// Maximum provider projections accepted at one anchor.
    #[must_use]
    pub const fn max_providers_per_anchor(self) -> usize {
        self.max_providers_per_anchor.get()
    }
    /// Maximum replication orders accepted for one provider at one anchor.
    #[must_use]
    pub const fn max_orders_per_provider(self) -> usize {
        self.max_orders_per_provider.get()
    }
    /// Maximum aggregate provider/order rows accepted at one anchor.
    #[must_use]
    pub const fn max_total_orders_per_anchor(self) -> usize {
        self.max_total_orders_per_anchor.get()
    }
    /// Maximum rows returned by one page.
    #[must_use]
    pub const fn max_page_rows(self) -> usize {
        self.max_page_rows.get()
    }
    fn decode_limits(self) -> Result<DecodeLimits, ProviderIngestFinalizedArchiveErrorV1> {
        let max = usize::try_from(self.max_record_bytes).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                reason: "maximum record bytes exceed this target's address space",
            }
        })?;
        let max_total_allocation_bytes =
            max.checked_mul(4)
                .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidBounds {
                    reason: "maximum record bytes cannot produce a decode allocation ceiling",
                })?;
        Ok(DecodeLimits::new(
            max,
            max,
            max,
            max_total_allocation_bytes,
            MAX_DECODE_NESTING_DEPTH,
        ))
    }
}
include!("provider_ingest_finalized/archive_key.rs");
/// One exact provider-scoped replication order at a finalized anchor.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchivedOrderV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ProviderIngestFinalizedArchivedOrderV1 {
    /// Chain-authoritative pin manifest used by the ingest operation.
    pub pin_manifest: PinManifestRecord,
    /// Chain-authoritative replication-order record.
    pub replication_order: ReplicationOrderRecord,
    /// Consensus-authenticated Musubi archive binding, absent for generic non-Musubi replication orders.
    pub musubi_archive: Option<MusubiReplicationOrderArchiveBindingV1>,
}
impl ProviderIngestFinalizedArchivedOrderV1 {
    fn order_id(&self) -> ReplicationOrderId {
        self.replication_order.order_id
    }
}
/// Complete provider-scoped state at one exact finalized anchor.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedProviderProjectionV1"
)]
pub struct ProviderIngestFinalizedProviderProjectionV1 {
    /// Governed provider identity.
    pub provider_id: ProviderId,
    /// Current registered owner expected by completion execution.
    pub expected_owner: Option<AccountId>,
    /// Exact current owner, completion signer, and governed signer-policy binding.
    pub expected_authority: Option<ProviderIngestCompletionAuthorityV1>,
    /// Assigned orders in strict replication-order identity order.
    pub orders: Vec<ProviderIngestFinalizedArchivedOrderV1>,
}
/// Complete provider-indexed projection at one exact finalized anchor.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedProjectionV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ProviderIngestFinalizedProjectionV1 {
    /// Exact finalized identity of this projection.
    pub key: ProviderIngestFinalizedArchiveKeyV1,
    /// Providers in strict provider-identity order, including registered
    /// providers that currently have no assigned orders.
    pub providers: Vec<ProviderIngestFinalizedProviderProjectionV1>,
}
impl ProviderIngestFinalizedProjectionV1 {
    /// Validate provider isolation, order bindings, authority bindings, and
    /// configured resource ceilings.
    ///
    /// # Errors
    ///
    /// Returns a stable typed validation or bounds failure.
    pub fn validate(
        &self,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
    ) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        self.key.validate()?;
        if self.providers.len() > bounds.max_providers_per_anchor() {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                    resource: "providers per anchor",
                    observed: self.providers.len(),
                    maximum: bounds.max_providers_per_anchor(),
                },
            );
        }
        let mut previous_provider = None;
        let mut total_orders = 0_usize;
        let mut orders_by_id: BTreeMap<
            ReplicationOrderId,
            (
                &PinManifestRecord,
                &ReplicationOrderRecord,
                &Option<MusubiReplicationOrderArchiveBindingV1>,
                BTreeSet<ProviderId>,
            ),
        > = BTreeMap::new();
        for provider in &self.providers {
            if provider.provider_id.as_bytes() == &[0; 32] {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "provider identity must be non-zero",
                });
            }
            if previous_provider.is_some_and(|previous| previous >= provider.provider_id) {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "provider projections must be strictly ordered and unique",
                });
            }
            previous_provider = Some(provider.provider_id);
            match (
                provider.expected_owner.as_ref(),
                provider.expected_authority.as_ref(),
            ) {
                (None, Some(_)) => {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "signer policy cannot exist without a registered provider owner",
                    });
                }
                (owner, Some(authority))
                    if !authority.is_valid() || owner != Some(&authority.provider_owner) =>
                {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "provider completion authority is noncanonical or differs from registered owner",
                    });
                }
                _ => {}
            }
            if provider.orders.len() > bounds.max_orders_per_provider() {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                        resource: "orders per provider",
                        observed: provider.orders.len(),
                        maximum: bounds.max_orders_per_provider(),
                    },
                );
            }
            total_orders = total_orders.checked_add(provider.orders.len()).ok_or(
                ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                    resource: "total provider/order rows",
                    observed: usize::MAX,
                    maximum: bounds.max_total_orders_per_anchor(),
                },
            )?;
            if total_orders > bounds.max_total_orders_per_anchor() {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                        resource: "total provider/order rows",
                        observed: total_orders,
                        maximum: bounds.max_total_orders_per_anchor(),
                    },
                );
            }
            let mut previous_order = None;
            for archived in &provider.orders {
                let order_id = archived.order_id();
                if previous_order.is_some_and(|previous| previous >= order_id) {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "provider orders must be strictly ordered and unique",
                    });
                }
                previous_order = Some(order_id);
                validate_archived_order(&self.key, provider.provider_id, archived)?;
                match orders_by_id.entry(order_id) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let mut assigned = BTreeSet::new();
                        assigned.insert(provider.provider_id);
                        entry.insert((
                            &archived.pin_manifest,
                            &archived.replication_order,
                            &archived.musubi_archive,
                            assigned,
                        ));
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        let (pin, order, musubi_archive, assigned) = entry.get_mut();
                        if *pin != &archived.pin_manifest
                            || *order != &archived.replication_order
                            || *musubi_archive != &archived.musubi_archive
                            || !assigned.insert(provider.provider_id)
                        {
                            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                                reason: "one order has conflicting provider projections",
                            });
                        }
                    }
                }
            }
        }
        for (order_id, (_, order, _, projected_providers)) in orders_by_id {
            let decoded = validated_replication_order_from_record(&order_id, order)?;
            let assigned = decoded
                .assignments
                .iter()
                .map(|assignment| ProviderId::new(assignment.provider_id))
                .collect::<BTreeSet<_>>();
            if assigned != projected_providers {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "projected provider set differs from canonical order assignments",
                });
            }
        }
        Ok(())
    }
}
/// One page row carrying every completion execution compare-and-set binding.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveAssignmentV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ProviderIngestFinalizedArchiveAssignmentV1 {
    /// Provider whose index was queried.
    pub provider_id: ProviderId,
    /// Exact expected provider owner, absent only while completion is disabled.
    pub expected_owner: Option<AccountId>,
    /// Exact expected signer-policy identity/revision/digest chain.
    pub expected_authority: Option<ProviderIngestCompletionAuthorityV1>,
    /// Monotonic canonical assignment revision expected at commit.
    pub expected_assignment_revision: u64,
    /// Exact finalized committed-chain prefix expected at commit.
    pub finalized_anchor: ProviderIngestFinalizedAnchorV1,
    /// Exact finalized block creation time.
    pub finalized_at_unix_ms: u64,
    /// Chain-authoritative pin manifest.
    pub pin_manifest: PinManifestRecord,
    /// Chain-authoritative replication order.
    pub replication_order: ReplicationOrderRecord,
    /// Consensus-authenticated Musubi archive binding, absent for generic non-Musubi replication orders.
    pub musubi_archive: Option<MusubiReplicationOrderArchiveBindingV1>,
    /// Exact finalized block Unix time in whole seconds, when completion is admissible.
    pub completion_epoch: Option<u64>,
}
/// Context-bound exclusive cursor for provider-indexed archive pages.
#[rustfmt::skip]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveCursorV1")]
pub struct ProviderIngestFinalizedArchiveCursorV1 {
    /// Exact finalized key whose immutable snapshot is being paged.
    pub key: ProviderIngestFinalizedArchiveKeyV1,
    /// Exact provider index being paged.
    pub provider_id: ProviderId,
    /// Complete-state root that binds the cursor to one archive record.
    pub provider_state_root: [u8; 32],
    /// Last returned order identity, excluded from the next page.
    pub after_order_id: ReplicationOrderId,
}
/// Bounded stable page from one exact provider-indexed committed projection.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchivePageV1"
)]
pub struct ProviderIngestFinalizedArchivePageV1 {
    /// Exact finalized key shared by every returned row.
    pub key: ProviderIngestFinalizedArchiveKeyV1,
    /// Provider index resolved by the page.
    pub provider_id: ProviderId,
    /// Complete-state root committed by the exact anchor record.
    pub provider_state_root: [u8; 32],
    /// Rows in strict replication-order identity order.
    pub rows: Vec<ProviderIngestFinalizedArchiveAssignmentV1>,
    /// Context-bound exclusive continuation, when another row exists.
    pub next_cursor: Option<ProviderIngestFinalizedArchiveCursorV1>,
}
/// One exact provider/order read from an authenticated finalized archive key.
///
/// This is an in-process read result, not a new wire layout. An absent assignment still carries
/// the exact committed provider-state root; source IDs exist only for a present assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestFinalizedArchiveAssignmentLookupV1 {
    /// Exact immutable key selected by the caller.
    pub key: ProviderIngestFinalizedArchiveKeyV1,
    /// Exact provider index read from the committed projection.
    pub provider_id: ProviderId,
    /// Complete provider-state root of this exact archive record.
    pub provider_state_root: [u8; 32],
    /// One exact order assignment, or `None` when it is absent from this provider index.
    pub assignment: Option<ProviderIngestFinalizedArchiveAssignmentV1>,
    /// Other assigned providers in the canonical order's strictly increasing identity order.
    pub source_provider_ids: Vec<[u8; 32]>,
}
/// Outcome of publishing one immutable exact-anchor record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestFinalizedArchiveInsertOutcomeV1 {
    /// A new immutable record was durably published.
    Inserted,
    /// The exact typed projection was already durable at the same key.
    ExactReplay,
}
/// Exact finalized boundary authorized for provider-archive retention.
///
/// The certified block id is supplied by the commit-owned caller and is
/// reauthenticated against Kura before any prefix is removed.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionFenceV1"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ProviderIngestFinalizedArchiveRetentionFenceV1 {
    key: ProviderIngestFinalizedArchiveKeyV1,
    certified_block_id: [u8; 32],
    expected_archive_generation: u64,
}
impl ProviderIngestFinalizedArchiveRetentionFenceV1 {
    /// Construct one exact non-zero retention fence at the caller-observed archive generation.
    ///
    /// # Errors
    ///
    /// Rejects a malformed exact key or a zero certified block id. The
    /// generation is checked atomically by the compaction operation.
    pub fn try_new(
        key: ProviderIngestFinalizedArchiveKeyV1,
        certified_block_id: [u8; 32],
        expected_archive_generation: u64,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        key.validate()?;
        if certified_block_id == [0; 32] {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionFence {
                    reason: "certified block id must be non-zero",
                },
            );
        }
        Ok(Self {
            key,
            certified_block_id,
            expected_archive_generation,
        })
    }
    /// Return the exact greatest height the caller permits pruning through.
    #[must_use]
    pub const fn key(&self) -> &ProviderIngestFinalizedArchiveKeyV1 {
        &self.key
    }
    /// Return the certified block identity authenticating the retention floor.
    #[must_use]
    pub const fn certified_block_id(&self) -> [u8; 32] {
        self.certified_block_id
    }
    /// Return the exact archive generation observed by the retention decider.
    #[must_use]
    pub const fn expected_archive_generation(&self) -> u64 {
        self.expected_archive_generation
    }
}
/// Public qualification of a deployment-owned sealed retention authority.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1 {
    version: u16,
    revision: u64,
    policy_digest: [u8; 32],
}
impl ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1 {
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
    fn validate(self) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        if self.version != ARCHIVE_VERSION_V1 || self.revision == 0 || self.policy_digest == [0; 32]
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionAuthorityBinding);
        }
        Ok(())
    }
}
/// Credential-free expected identity of a sealed retention authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1 {
    handle: String,
    qualification: ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
}
impl ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1 {
    /// Construct one exact deployment-owned authority binding.
    ///
    /// # Errors
    ///
    /// Rejects credential-bearing, test-marked, malformed, stale, or zero public identity material.
    pub fn try_new(
        handle: String,
        revision: u64,
        policy_digest: [u8; 32],
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        if !iroha_config::parameters::is_production_runtime_handle(&handle) {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionAuthorityBinding);
        }
        let qualification = ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1::new(
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
    ) -> ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1 {
        self.qualification
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveCompactionProposalMaterialV1"
)]
struct ProviderIngestFinalizedArchiveCompactionProposalMaterialV1 {
    version: u16,
    fence: ProviderIngestFinalizedArchiveRetentionFenceV1,
    checkpoint_digest: [u8; 32],
    checkpoint_canonical_digest: [u8; 32],
}
/// Exact canonical checkpoint and fence submitted for external approval.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveCompactionProposalV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct ProviderIngestFinalizedArchiveCompactionProposalV1 {
    material: ProviderIngestFinalizedArchiveCompactionProposalMaterialV1,
    proposal_digest: [u8; 32],
}
impl ProviderIngestFinalizedArchiveCompactionProposalV1 {
    fn try_new(
        fence: ProviderIngestFinalizedArchiveRetentionFenceV1,
        checkpoint_digest: [u8; 32],
        checkpoint_canonical_digest: [u8; 32],
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let material = ProviderIngestFinalizedArchiveCompactionProposalMaterialV1 {
            version: ARCHIVE_VERSION_V1,
            fence,
            checkpoint_digest,
            checkpoint_canonical_digest,
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
    fn validate(&self) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        self.material.fence.key.validate()?;
        if self.material.version != ARCHIVE_VERSION_V1
            || self.material.fence.certified_block_id == [0; 32]
            || self.material.checkpoint_digest == [0; 32]
            || self.material.checkpoint_canonical_digest == [0; 32]
            || canonical_domain_digest(RETENTION_PROPOSAL_DIGEST_DOMAIN_V1, &self.material)?
                != self.proposal_digest
        {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                    reason: "compaction proposal is malformed or noncanonical",
                },
            );
        }
        Ok(())
    }
    /// Return the exact Kura-authenticated fence.
    #[must_use]
    pub const fn fence(&self) -> &ProviderIngestFinalizedArchiveRetentionFenceV1 {
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
    /// Return the digest naming this exact proposal.
    #[must_use]
    pub const fn proposal_digest(&self) -> [u8; 32] {
        self.proposal_digest
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionApprovalMaterialV1"
)]
struct ProviderIngestFinalizedArchiveRetentionApprovalMaterialV1 {
    namespace: [u8; 32],
    version: u16,
    sequence: u64,
    authority_qualification: ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
    proposal: ProviderIngestFinalizedArchiveCompactionProposalV1,
    predecessor_revision: Option<[u8; 32]>,
    predecessor_checkpoint_digest: Option<[u8; 32]>,
}
/// Canonical monotonic CAS record approving one exact compaction proposal.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionApprovalRecordV1"
)]
pub struct ProviderIngestFinalizedArchiveRetentionApprovalRecordV1 {
    material: ProviderIngestFinalizedArchiveRetentionApprovalMaterialV1,
    revision: [u8; 32],
}
impl ProviderIngestFinalizedArchiveRetentionApprovalRecordV1 {
    fn try_new(
        sequence: u64,
        authority_qualification: ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
        proposal: ProviderIngestFinalizedArchiveCompactionProposalV1,
        predecessor_revision: Option<[u8; 32]>,
        predecessor_checkpoint_digest: Option<[u8; 32]>,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let material = ProviderIngestFinalizedArchiveRetentionApprovalMaterialV1 {
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
    fn validate(&self) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
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
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                    reason: "approval record is malformed or has noncanonical lineage",
                },
            );
        }
        Ok(())
    }
    /// Decode one strictly bounded canonical Norito approval record.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, malformed, noncanonical, or invalid records.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        if bytes.is_empty() || bytes.len() > RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1 {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                    reason: "approval record exceeds its canonical byte bound",
                },
            );
        }
        let record =
            decode_from_bytes_with_limits::<Self>(bytes, RETENTION_APPROVAL_DECODE_LIMITS_V1)
                .map_err(
                    |_| ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                        reason: "approval record failed bounded Norito decoding",
                    },
                )?;
        record.validate()?;
        if norito::to_bytes(&record).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?
            != bytes
        {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                    reason: "approval record is not canonical Norito",
                },
            );
        }
        Ok(record)
    }
    /// Encode this approval as strictly bounded canonical Norito.
    ///
    /// # Errors
    ///
    /// Rejects invalid records and encoded values above the fixed V1 bound.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProviderIngestFinalizedArchiveErrorV1> {
        self.validate()?;
        let bytes =
            norito::to_bytes(self).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
        if bytes.is_empty() || bytes.len() > RETENTION_APPROVAL_MAX_CANONICAL_BYTES_V1 {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                    reason: "approval record exceeds its canonical byte bound",
                },
            );
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
    ) -> ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1 {
        self.material.authority_qualification
    }
    /// Return the exact approved proposal.
    #[must_use]
    pub const fn proposal(&self) -> &ProviderIngestFinalizedArchiveCompactionProposalV1 {
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
pub enum ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1 {
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
/// [`ProviderIngestFinalizedArchiveRetentionApprovalRecordV1`] values.
///
/// Calls run while the archive writer is held. Implementations must not acquire State/World
/// writer guards or wait for canonical State publication; candidate publication acquires
/// State ownership before reserving this archive. The production broker adapters perform
/// independent bounded RPCs and retain no State owner.
pub trait ProviderIngestFinalizedArchiveRetentionAuthorityV1: Send + Sync + fmt::Debug {
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
        ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
        ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
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
        Option<ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>,
        ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >;
    /// Install `next` only when the authoritative revision is exactly `expected_revision`.
    ///
    /// A write whose commit outcome is unknown must return
    /// [`ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous`].
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn compare_and_swap_latest(
        &self,
        network_id: &NetworkId,
        expected_revision: Option<[u8; 32]>,
        next: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
    ) -> Result<(), ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1>;
}
/// Result of installing one authenticated virtual-base checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ProviderIngestFinalizedArchiveCompactionOutcomeV1 {
    retention_floor: ProviderIngestFinalizedArchiveKeyV1,
    checkpoint_digest: [u8; 32],
    pruned_entries: u64,
    pruned_bytes: u64,
    generation: u64,
}
impl ProviderIngestFinalizedArchiveCompactionOutcomeV1 {
    /// Return the exact oldest queryable key after compaction.
    #[must_use]
    pub const fn retention_floor(&self) -> &ProviderIngestFinalizedArchiveKeyV1 {
        &self.retention_floor
    }
    /// Return the content digest naming the immutable virtual base.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> [u8; 32] {
        self.checkpoint_digest
    }
    /// Return the cumulative number of original anchor records pruned.
    #[must_use]
    pub const fn pruned_entries(&self) -> u64 {
        self.pruned_entries
    }
    /// Return the cumulative canonical record bytes pruned.
    #[must_use]
    pub const fn pruned_bytes(&self) -> u64 {
        self.pruned_bytes
    }
    /// Return the archive generation preserved across compaction.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Exact archive coverage qualified against one authenticated Kura boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ProviderIngestFinalizedArchiveQualificationV1 {
    activation_floor: ProviderIngestFinalizedArchiveKeyV1,
    archive_tip: ProviderIngestFinalizedArchiveKeyV1,
    kura_tip_height: u64,
    lag_blocks: u64,
    generation: u64,
}
impl ProviderIngestFinalizedArchiveQualificationV1 {
    /// Return the first exact finalized height represented by the archive.
    #[must_use]
    pub const fn activation_floor(&self) -> &ProviderIngestFinalizedArchiveKeyV1 {
        &self.activation_floor
    }
    /// Return the highest exact finalized height represented by the archive.
    #[must_use]
    pub const fn archive_tip(&self) -> &ProviderIngestFinalizedArchiveKeyV1 {
        &self.archive_tip
    }
    /// Return the authenticated Kura tip used for qualification.
    #[must_use]
    pub const fn kura_tip_height(&self) -> u64 {
        self.kura_tip_height
    }
    /// Return the explicit Kura suffix not yet captured.
    #[must_use]
    pub const fn lag_blocks(&self) -> u64 {
        self.lag_blocks
    }
    /// Return the immutable archive generation used for qualification.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Outcome of exact startup or recovery reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ProviderIngestFinalizedArchiveReconcileOutcomeV1 {
    insertion: ProviderIngestFinalizedArchiveInsertOutcomeV1,
    qualification: ProviderIngestFinalizedArchiveQualificationV1,
    activation_floor_created: bool,
}
impl ProviderIngestFinalizedArchiveReconcileOutcomeV1 {
    /// Return whether reconciliation inserted or exactly replayed the tip.
    #[must_use]
    pub const fn insertion(&self) -> ProviderIngestFinalizedArchiveInsertOutcomeV1 {
        self.insertion
    }
    /// Return the exact Kura-bound qualification.
    #[must_use]
    pub const fn qualification(&self) -> &ProviderIngestFinalizedArchiveQualificationV1 {
        &self.qualification
    }
    /// Return whether reconciliation established a new explicit floor.
    #[must_use]
    pub const fn activation_floor_created(&self) -> bool {
        self.activation_floor_created
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::query::provider_ingest_finalized::ProviderProjectionDeltaV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct ProviderProjectionDeltaV1 {
    provider_id: ProviderId,
    next: Option<ProviderIngestFinalizedProviderProjectionV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchivePredecessorV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct ProviderIngestFinalizedArchivePredecessorV1 {
    key: ProviderIngestFinalizedArchiveKeyV1,
    record_digest: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRecordMaterialV1"
)]
struct ProviderIngestFinalizedArchiveRecordMaterialV1 {
    version: u16,
    key: ProviderIngestFinalizedArchiveKeyV1,
    predecessor: Option<ProviderIngestFinalizedArchivePredecessorV1>,
    deltas: Vec<ProviderProjectionDeltaV1>,
    provider_state_root: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRecordV1"
)]
struct ProviderIngestFinalizedArchiveRecordV1 {
    material: ProviderIngestFinalizedArchiveRecordMaterialV1,
    record_digest: [u8; 32],
}
impl ProviderIngestFinalizedArchiveRecordV1 {
    fn try_new(
        material: ProviderIngestFinalizedArchiveRecordMaterialV1,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let record_digest = canonical_domain_digest(RECORD_DIGEST_DOMAIN_V1, &material)?;
        let record = Self {
            material,
            record_digest,
        };
        record.validate()?;
        Ok(record)
    }
    fn validate(&self) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        if self.material.version != ARCHIVE_VERSION_V1 {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::UnsupportedArchiveVersion {
                    found: self.material.version,
                },
            );
        }
        self.material.key.validate()?;
        if let Some(predecessor) = &self.material.predecessor {
            predecessor.key.validate()?;
        }
        let valid_predecessor = self
            .material
            .predecessor
            .as_ref()
            .is_none_or(|predecessor| {
                predecessor.key.network_id == self.material.key.network_id
                    && predecessor
                        .key
                        .height
                        .checked_add(1)
                        .is_some_and(|height| height == self.material.key.height)
                    && predecessor.key.finalized_at_unix_ms
                        <= self.material.key.finalized_at_unix_ms
                    && predecessor.record_digest != [0; 32]
            });
        if !valid_predecessor {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
                reason: "predecessor is not the exact prior finalized height",
            });
        }
        if self.material.provider_state_root == [0; 32] {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
                reason: "provider-state root must be non-zero",
            });
        }
        let mut previous_provider = None;
        for delta in &self.material.deltas {
            if delta.provider_id.as_bytes() == &[0; 32]
                || previous_provider.is_some_and(|previous| previous >= delta.provider_id)
                || delta
                    .next
                    .as_ref()
                    .is_some_and(|next| next.provider_id != delta.provider_id)
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
                    reason: "provider deltas are not canonical and strictly ordered",
                });
            }
            previous_provider = Some(delta.provider_id);
        }
        if canonical_domain_digest(RECORD_DIGEST_DOMAIN_V1, &self.material)? != self.record_digest {
            return Err(ProviderIngestFinalizedArchiveErrorV1::RecordDigestMismatch);
        }
        Ok(())
    }
}
impl ProviderIngestFinalizedArchiveCheckpointV1 {
    fn try_new(
        material: ProviderIngestFinalizedArchiveCheckpointMaterialV1,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let checkpoint_digest = canonical_domain_digest(CHECKPOINT_DIGEST_DOMAIN_V1, &material)?;
        let checkpoint = Self {
            material,
            checkpoint_digest,
        };
        checkpoint.validate(bounds)?;
        Ok(checkpoint)
    }
    fn validate(
        &self,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
    ) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        let material = &self.material;
        if material.version != ARCHIVE_VERSION_V1 {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::UnsupportedArchiveVersion {
                    found: material.version,
                },
            );
        }
        material.original_activation_floor.validate()?;
        material.retention_floor.validate()?;
        if material.original_activation_floor.network_id != material.retention_floor.network_id
            || material.original_activation_floor.height > material.retention_floor.height
            || material.projection.key != material.retention_floor
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint floors and projection do not identify one retained prefix",
            });
        }
        let expected_pruned_entries = material
            .retention_floor
            .height
            .checked_sub(material.original_activation_floor.height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint retention distance overflowed",
            })?;
        if material.original_terminal_record_digest == [0; 32]
            || material.cumulative_prefix_digest == [0; 32]
            || material
                .prior_checkpoint_digest
                .is_some_and(|digest| digest == [0; 32])
            || material.certified_block_id == [0; 32]
            || material.pruned_entries != expected_pruned_entries
            || material.pruned_bytes == 0
            || material.total_generation < material.pruned_entries
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint digests and monotonic counters must be canonical and non-zero",
            });
        }
        material.projection.validate(bounds)?;
        if provider_state_root(&material.projection.providers)? != material.provider_state_root {
            return Err(ProviderIngestFinalizedArchiveErrorV1::ProviderStateRootMismatch);
        }
        validate_policy_history_checkpoint(&material.projection, &material.policy_history)?;
        let active_order_ids = provider_order_ids(material.projection.providers.iter());
        if !active_order_ids
            .iter()
            .copied()
            .eq(material.active_order_ids.iter().copied())
            || !strictly_ordered(&material.active_order_ids)
            || !strictly_ordered(&material.seen_order_ids)
            || material
                .active_order_ids
                .iter()
                .any(|order_id| material.seen_order_ids.binary_search(order_id).is_err())
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint order-history summary is noncanonical",
            });
        }
        if canonical_domain_digest(CHECKPOINT_DIGEST_DOMAIN_V1, material)? != self.checkpoint_digest
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::CheckpointDigestMismatch);
        }
        Ok(())
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderPolicyDigestHistoryCheckpointV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct ProviderPolicyDigestHistoryCheckpointV1 {
    policy_id: [u8; 32],
    policy_digests: Vec<[u8; 32]>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderPolicyHistoryCheckpointV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct ProviderPolicyHistoryCheckpointV1 {
    provider_id: ProviderId,
    last: ProviderIngestCompletionAuthorityV1,
    active: bool,
    seen_policy_digests: Vec<ProviderPolicyDigestHistoryCheckpointV1>,
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedPrefixLinkV1"
)]
struct ProviderIngestFinalizedPrefixLinkV1 {
    previous_cumulative_digest: Option<[u8; 32]>,
    key: ProviderIngestFinalizedArchiveKeyV1,
    record_digest: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveCheckpointMaterialV1"
)]
struct ProviderIngestFinalizedArchiveCheckpointMaterialV1 {
    version: u16,
    original_activation_floor: ProviderIngestFinalizedArchiveKeyV1,
    retention_floor: ProviderIngestFinalizedArchiveKeyV1,
    original_terminal_record_digest: [u8; 32],
    cumulative_prefix_digest: [u8; 32],
    prior_checkpoint_digest: Option<[u8; 32]>,
    total_generation: u64,
    pruned_entries: u64,
    pruned_bytes: u64,
    projection: ProviderIngestFinalizedProjectionV1,
    provider_state_root: [u8; 32],
    policy_history: Vec<ProviderPolicyHistoryCheckpointV1>,
    active_order_ids: Vec<ReplicationOrderId>,
    seen_order_ids: Vec<ReplicationOrderId>,
    certified_block_id: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveCheckpointV1"
)]
struct ProviderIngestFinalizedArchiveCheckpointV1 {
    material: ProviderIngestFinalizedArchiveCheckpointMaterialV1,
    checkpoint_digest: [u8; 32],
}
#[derive(Debug, Clone)]
struct ArchiveVirtualBaseV1 {
    checkpoint: ProviderIngestFinalizedArchiveCheckpointV1,
    path: PathBuf,
    canonical_bytes: u64,
}
#[derive(Debug)]
struct PreparedArchiveCompactionV1 {
    checkpoint: ProviderIngestFinalizedArchiveCheckpointV1,
    canonical_bytes: Vec<u8>,
    obsolete: Vec<((NetworkId, u64), ArchiveRecordEntryV1)>,
    previous_base: Option<ArchiveVirtualBaseV1>,
}
#[derive(Debug)]
struct ArchiveCompactionHistoryV1 {
    policy_history: BTreeMap<ProviderId, ProviderPolicyHistoryV1>,
    active_order_ids: BTreeSet<ReplicationOrderId>,
    seen_order_ids: BTreeSet<ReplicationOrderId>,
    cumulative_prefix_digest: [u8; 32],
}
#[derive(Debug, Clone)]
struct ArchiveRecordEntryV1 {
    record: ProviderIngestFinalizedArchiveRecordV1,
    path: PathBuf,
    canonical_bytes: u64,
}
#[derive(Debug, Default)]
struct ArchiveIndexV1 {
    by_height: BTreeMap<(NetworkId, u64), ArchiveRecordEntryV1>,
    virtual_bases: BTreeMap<NetworkId, ArchiveVirtualBaseV1>,
    total_bytes: u64,
    generation: u64,
}
// A short-lived source inventory, not an authenticated archive or cached result.
// Paths are copied fallibly; variable provider/order/retention DTOs are never cloned.
struct QualificationRecordIdentity {
    subject: (NetworkId, u64),
    key: ProviderIngestFinalizedArchiveKeyV1,
    digest: [u8; 32],
    canonical_bytes: u64,
    path: PathBuf,
}
struct QualificationBaseIdentity {
    network_id: NetworkId,
    key: ProviderIngestFinalizedArchiveKeyV1,
    digest: [u8; 32],
    certified_block_id: [u8; 32],
    canonical_bytes: u64,
    path: PathBuf,
}
struct QualificationInventory {
    records: Vec<QualificationRecordIdentity>,
    bases: Vec<QualificationBaseIdentity>,
    generation: u64,
    total_bytes: u64,
}
impl QualificationInventory {
    fn capture(
        index: &ArchiveIndexV1,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let observed = retained_archive_entries(index);
        if observed > bounds.max_archive_entries() {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                    observed,
                    maximum: bounds.max_archive_entries(),
                },
            );
        }
        if index.total_bytes > bounds.max_total_bytes() {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                    observed: index.total_bytes,
                    maximum: bounds.max_total_bytes(),
                },
            );
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(index.by_height.len())
            .map_err(|_| qualification_allocation_error())?;
        let mut bases = Vec::new();
        bases
            .try_reserve_exact(index.virtual_bases.len())
            .map_err(|_| qualification_allocation_error())?;
        for (subject, entry) in &index.by_height {
            records.push(QualificationRecordIdentity {
                subject: *subject,
                key: entry.record.material.key,
                digest: entry.record.record_digest,
                canonical_bytes: entry.canonical_bytes,
                path: qualification_path(&entry.path)?,
            });
        }
        for (network_id, entry) in &index.virtual_bases {
            bases.push(QualificationBaseIdentity {
                network_id: *network_id,
                key: entry.checkpoint.material.retention_floor,
                digest: entry.checkpoint.checkpoint_digest,
                certified_block_id: entry.checkpoint.material.certified_block_id,
                canonical_bytes: entry.canonical_bytes,
                path: qualification_path(&entry.path)?,
            });
        }
        Ok(Self {
            records,
            bases,
            generation: index.generation,
            total_bytes: index.total_bytes,
        })
    }

    fn authenticate<V: StateReadOnly + ?Sized>(
        &self,
        network_id: &NetworkId,
        certified: &CertifiedArchiveView<'_, V>,
    ) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        if let Some(base) = self
            .bases
            .iter()
            .find(|base| &base.network_id == network_id)
        {
            authenticate_qualification_base(
                &base.key,
                base.certified_block_id,
                network_id,
                certified,
            )?;
        }
        for entry in self
            .records
            .iter()
            .filter(|entry| &entry.subject.0 == network_id)
        {
            authenticate_archive_anchor(&entry.key, network_id, certified)?;
        }
        Ok(())
    }

    fn require_same(
        &self,
        current: &ArchiveIndexV1,
    ) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        let records_match = self.records.len() == current.by_height.len()
            && self
                .records
                .iter()
                .zip(&current.by_height)
                .all(|(before, (subject, after))| {
                    &before.subject == subject
                        && before.key == after.record.material.key
                        && before.digest == after.record.record_digest
                        && before.canonical_bytes == after.canonical_bytes
                        && before.path == after.path
                });
        let bases_match = self.bases.len() == current.virtual_bases.len()
            && self.bases.iter().zip(&current.virtual_bases).all(
                |(before, (network_id, after))| {
                    &before.network_id == network_id
                        && before.key == after.checkpoint.material.retention_floor
                        && before.digest == after.checkpoint.checkpoint_digest
                        && before.certified_block_id == after.checkpoint.material.certified_block_id
                        && before.canonical_bytes == after.canonical_bytes
                        && before.path == after.path
                },
            );
        if self.generation != current.generation
            || self.total_bytes != current.total_bytes
            || !records_match
            || !bases_match
        {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                    boundary: "archive",
                },
            );
        }
        Ok(())
    }
}
fn qualification_allocation_error() -> ProviderIngestFinalizedArchiveErrorV1 {
    ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
        resource: "qualification source inventory",
    }
}
fn qualification_path(path: &Path) -> Result<PathBuf, ProviderIngestFinalizedArchiveErrorV1> {
    let mut copy = PathBuf::new();
    copy.try_reserve_exact(path.as_os_str().len())
        .map_err(|_| qualification_allocation_error())?;
    copy.push(path);
    Ok(copy)
}
fn authenticate_qualification_base<V: StateReadOnly + ?Sized>(
    key: &ProviderIngestFinalizedArchiveKeyV1,
    certified_block_id: [u8; 32],
    network_id: &NetworkId,
    certified: &CertifiedArchiveView<'_, V>,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let block = authenticate_archive_anchor(key, network_id, certified)?;
    if *block.id().0.as_ref() != certified_block_id {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveKuraAnchorMismatch {
                network_id: *network_id,
                height: key.height,
                reason: "virtual-base certified block identity differs from Kura",
            },
        );
    }
    Ok(())
}
/// Durable, immutable, provider-indexed finalized replication-order archive.
#[derive(Debug)]
pub struct ProviderIngestFinalizedArchiveV1 {
    root: PathBuf,
    records: PathBuf,
    checkpoints: PathBuf,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
    root_identity: ArchiveFileIdentity,
    records_identity: ArchiveFileIdentity,
    checkpoints_identity: ArchiveFileIdentity,
    writer_lock_identity: ArchiveFileIdentity,
    writer_lock: fs::File,
    index: ArchiveIndexLock<ArchiveIndexV1>,
}
struct PreparedProviderRecord {
    entry: ArchiveRecordEntryV1,
    bytes: Vec<u8>,
    total_bytes: u64,
    generation: u64,
}
/// Shared immutable insertion material, admitted once under the original writer.
struct ProviderInsertionPlan {
    key: ProviderIngestFinalizedArchiveKeyV1,
    record: Option<PreparedProviderRecord>,
}
impl ProviderInsertionPlan {
    fn persist(
        &mut self,
        archive: &ProviderIngestFinalizedArchiveV1,
        index: &mut ArchiveIndexV1,
    ) -> Result<ProviderIngestFinalizedArchiveInsertOutcomeV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        let Some(prepared) = &self.record else {
            archive.verify_storage_boundaries()?;
            // Reauthenticate existing immutable files; this is storage integrity, not admission.
            reconstruct_projection(index, &self.key, archive.bounds)?;
            return Ok(ProviderIngestFinalizedArchiveInsertOutcomeV1::ExactReplay);
        };
        archive.verify_storage_boundaries()?;
        publish_immutable_bytes(
            &archive.records,
            archive.records_identity,
            &prepared.entry.path,
            &prepared.bytes,
        )?;
        let loaded = load_record_at(&prepared.entry.path, archive.bounds, Some(&self.key))?;
        if loaded != prepared.entry.record {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ConflictingProjection {
                    network_id: self.key.network_id,
                    height: self.key.height,
                },
            );
        }
        archive.verify_storage_boundaries()?;
        index.by_height.insert(
            (self.key.network_id, self.key.height),
            prepared.entry.clone(),
        );
        index.total_bytes = prepared.total_bytes;
        index.generation = prepared.generation;
        self.record = None;
        Ok(ProviderIngestFinalizedArchiveInsertOutcomeV1::Inserted)
    }
}
impl ProviderIngestFinalizedArchiveV1 {
    /// Hold the actual archive reader while a component test attempts publication.
    #[cfg(test)]
    pub(crate) fn with_index_reader_for_testing<T>(
        &self,
        inspect: impl FnOnce() -> T,
    ) -> Result<T, ProviderIngestFinalizedArchiveErrorV1> {
        let _reader = self.read_index()?;
        Ok(inspect())
    }

    /// Open or create one direct single-writer archive and validate every
    /// immutable record before making it queryable.
    ///
    /// # Errors
    ///
    /// Rejects unsafe filesystem topology, unknown objects, malformed or noncanonical Norito,
    /// digest mismatch, gaps, forks, rollback, provider substitution, and exceeded bounds.
    pub fn try_open(
        root: impl Into<PathBuf>,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        let (archive, checkpoint_candidates) = Self::open_unreconciled(root, bounds)?;
        if !checkpoint_candidates.is_empty() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRequired);
        }
        {
            let mut index = archive.write_index()?;
            refresh_archive_accounting(&mut index, bounds)?;
            validate_index_coverage(&index, bounds)?;
        }
        archive.verify_storage_boundaries()?;
        Ok(archive)
    }
    /// Open an archive whose retention state is sealed by `authority`.
    ///
    /// Startup installs or finishes only the exact checkpoint durably named by the authority's
    /// canonical CAS record. A checkpoint file without that approval is rejected without unlinking
    /// records or checkpoints. If the CAS committed before local checkpoint publication, recovery
    /// deterministically reconstructs and publishes the approved bytes before cleanup.
    ///
    /// # Errors
    ///
    /// Rejects a missing, substituted, stale, test-marked, drifting, malformed,
    /// rolled-back, or equivocated authority; an unapproved checkpoint; a
    /// Kura/fence mismatch; or any ordinary archive-open failure.
    pub fn try_open_with_retention_authority(
        root: impl Into<PathBuf>,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
        network_id: &NetworkId,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
        authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
    ) -> Result<Self, ProviderIngestFinalizedArchiveErrorV1> {
        if network_id != state_ro.network_id() || !std::ptr::eq(state_ro.kura(), kura) {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "retention State, Kura and configured network do not agree",
                },
            );
        }
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidKey {
                reason: "network id must be an exact genesis-derived identity",
            });
        }
        assert_retention_authority_identity(binding, authority)?;
        let (archive, checkpoint_candidates) = Self::open_unreconciled(root, bounds)?;
        archive.recover_approved_retention(
            network_id,
            state_ro,
            kura,
            binding,
            authority,
            checkpoint_candidates,
        )?;
        archive.verify_storage_boundaries()?;
        Ok(archive)
    }
    fn open_unreconciled(
        root: impl Into<PathBuf>,
        bounds: ProviderIngestFinalizedArchiveBoundsV1,
    ) -> Result<(Self, Vec<ArchiveVirtualBaseV1>), ProviderIngestFinalizedArchiveErrorV1> {
        let root = root.into();
        validate_archive_root_path(&root)?;
        create_direct_directory(&root)?;
        verify_absolute_directory_ancestry(&root)?;
        let root_identity = direct_archive_directory_identity(&root).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: root.clone(),
                source,
            }
        })?;
        let records = root.join(RECORDS_DIRECTORY);
        create_direct_directory(&records)?;
        let records_identity = direct_archive_directory_identity(&records).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: records.clone(),
                source,
            }
        })?;
        let checkpoints = root.join(CHECKPOINTS_DIRECTORY);
        create_direct_directory(&checkpoints)?;
        let checkpoints_identity =
            direct_archive_directory_identity(&checkpoints).map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: checkpoints.clone(),
                    source,
                }
            })?;
        validate_root_namespace(&root)?;
        let writer_lock_path = root.join(WRITER_LOCK_FILE);
        let writer_lock = open_writer_lock_file(&writer_lock_path)?;
        acquire_writer_ownership(&writer_lock, &writer_lock_path)?;
        let writer_lock_identity =
            archive_file_identity(&secure_file_metadata::from_file(&writer_lock).map_err(
                |source| ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: writer_lock_path.clone(),
                    source,
                },
            )?);
        recover_staged_directory(
            &records,
            records_identity,
            bounds.max_record_bytes,
            RECORD_FILE_SUFFIX,
        )?;
        recover_staged_directory(
            &checkpoints,
            checkpoints_identity,
            bounds.max_record_bytes,
            CHECKPOINT_FILE_SUFFIX,
        )?;
        let index = load_archive_index(&records, bounds)?;
        let checkpoint_candidates = load_archive_checkpoints(&checkpoints, bounds)?;
        let archive = Self {
            root,
            records,
            checkpoints,
            bounds,
            root_identity,
            records_identity,
            checkpoints_identity,
            writer_lock_identity,
            writer_lock,
            index: ArchiveIndexLock::new(index),
        };
        archive.verify_storage_boundaries()?;
        Ok((archive, checkpoint_candidates))
    }
    fn recover_approved_retention(
        &self,
        network_id: &NetworkId,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
        authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
        checkpoint_candidates: Vec<ArchiveVirtualBaseV1>,
    ) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        if checkpoint_candidates.iter().any(|candidate| {
            &candidate.checkpoint.material.retention_floor.network_id != network_id
        }) {
            return Err(ProviderIngestFinalizedArchiveErrorV1::UnapprovedRetentionCheckpoint);
        }
        let approval = load_retention_approval(binding, authority, network_id)?;
        let Some(approval) = approval else {
            if !checkpoint_candidates.is_empty() {
                return Err(ProviderIngestFinalizedArchiveErrorV1::UnapprovedRetentionCheckpoint);
            }
            let mut index = self.write_index()?;
            refresh_archive_accounting(&mut index, self.bounds)?;
            validate_index_coverage(&index, self.bounds)?;
            return Ok(());
        };
        validate_retention_approval_record(&approval, binding, network_id)?;
        validate_retention_checkpoint_candidate_inventory(
            &checkpoint_candidates,
            &approval,
            network_id,
        )?;
        authenticate_retention_fence(approval.proposal().fence(), state_ro, kura)?;
        let approved_candidate = checkpoint_candidates.iter().find(|candidate| {
            candidate.checkpoint.checkpoint_digest == approval.proposal().checkpoint_digest()
        });
        let mut index = self.write_index()?;
        self.verify_storage_boundaries()?;
        if let Some(candidate) = approved_candidate {
            validate_approval_checkpoint(&approval, &candidate.checkpoint, self.bounds)?;
            install_virtual_bases(&mut index, &checkpoint_candidates, self.bounds)?;
            if index
                .virtual_bases
                .get(network_id)
                .map(|base| base.checkpoint.checkpoint_digest)
                != Some(approval.proposal().checkpoint_digest())
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::UnapprovedRetentionCheckpoint);
            }
            require_exact_retention_readback(binding, authority, network_id, &approval)?;
            finish_compaction_cleanup(
                &self.records,
                self.records_identity,
                &self.checkpoints,
                self.checkpoints_identity,
                &checkpoint_candidates,
                &mut index,
            )?;
            refresh_archive_accounting(&mut index, self.bounds)?;
            validate_index_coverage(&index, self.bounds)?;
            return Ok(());
        }
        if checkpoint_candidates.is_empty() {
            if approval.predecessor_checkpoint_digest().is_some() {
                return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRollback);
            }
            refresh_archive_accounting(&mut index, self.bounds)?;
            validate_index_coverage(&index, self.bounds)?;
        } else {
            install_virtual_bases(&mut index, &checkpoint_candidates, self.bounds)?;
            if index
                .virtual_bases
                .get(network_id)
                .map(|base| base.checkpoint.checkpoint_digest)
                != approval.predecessor_checkpoint_digest()
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRollback);
            }
            require_exact_retention_readback(binding, authority, network_id, &approval)?;
            finish_compaction_cleanup(
                &self.records,
                self.records_identity,
                &self.checkpoints,
                self.checkpoints_identity,
                &checkpoint_candidates,
                &mut index,
            )?;
            refresh_archive_accounting(&mut index, self.bounds)?;
            validate_index_coverage(&index, self.bounds)?;
        }
        authenticate_retention_prefix(
            &index,
            approval.proposal().fence(),
            state_ro,
            kura,
            self.bounds,
        )?;
        let prepared =
            prepare_archive_compaction(&index, approval.proposal().fence(), self.bounds)?;
        validate_prepared_compaction_capacity(&index, &prepared, self.bounds)?;
        if compaction_proposal(&prepared, approval.proposal().fence())? != *approval.proposal() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionProposalMismatch);
        }
        validate_approval_for_prepared(
            &approval,
            binding,
            &prepared,
            approval.proposal(),
            approval.predecessor_checkpoint_digest(),
        )?;
        require_exact_retention_readback(binding, authority, network_id, &approval)?;
        let _recovered =
            self.publish_prepared_compaction(&mut index, prepared, || {}, &mut |_| {})?;
        Ok(())
    }
    /// Return the explicit first archived key for `network_id`.
    ///
    /// # Errors
    ///
    /// Returns an integrity error if archive boundaries changed.
    pub fn activation_floor(
        &self,
        network_id: &NetworkId,
    ) -> Result<Option<ProviderIngestFinalizedArchiveKeyV1>, ProviderIngestFinalizedArchiveErrorV1>
    {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidKey {
                reason: "network id must be an exact genesis-derived identity",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        if let Some(base) = index.virtual_bases.get(network_id) {
            verify_checkpoint_entry(base, self.bounds)?;
            return Ok(Some(base.checkpoint.material.retention_floor.clone()));
        }
        let floor = first_record_for_network(&index, network_id);
        if let Some(entry) = floor {
            verify_record_entry(entry, self.bounds)?;
        }
        Ok(floor.map(|entry| entry.record.material.key.clone()))
    }
    /// Return the installed compaction floor for `network_id`, when one exists.
    ///
    /// Unlike [`Self::activation_floor`], this returns `None` for an
    /// uncompacted archive even when its original activation record exists.
    ///
    /// # Errors
    ///
    /// Rejects an unmarked network identity or a damaged checkpoint.
    pub fn retention_floor(
        &self,
        network_id: &NetworkId,
    ) -> Result<Option<ProviderIngestFinalizedArchiveKeyV1>, ProviderIngestFinalizedArchiveErrorV1>
    {
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidKey {
                reason: "network id must be an exact genesis-derived identity",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let Some(base) = index.virtual_bases.get(network_id) else {
            return Ok(None);
        };
        verify_checkpoint_entry(base, self.bounds)?;
        Ok(Some(base.checkpoint.material.retention_floor.clone()))
    }
    /// Resolve a height/hash cursor to its complete exact archive key.
    ///
    /// This is the adapter seam for consumers whose finalized cursor carries
    /// height and block hash but not the result-bearing block time. The stored
    /// immutable record supplies the time; callers cannot substitute it.
    ///
    /// # Errors
    ///
    /// Rejects an invalid cursor, a height below the explicit activation
    /// floor, a missing exact height, a hash fork, or damaged immutable bytes.
    pub fn resolve_exact_key(
        &self,
        network_id: &NetworkId,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<ProviderIngestFinalizedArchiveKeyV1, ProviderIngestFinalizedArchiveErrorV1> {
        if network_id.as_bytes()[31] & 1 != 1 || height == 0 || block_hash == [0; 32] {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidKey {
                reason: "finalized cursor must contain an exact network and non-zero height/hash",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let floor = activation_floor_from_index(&index, network_id)?.ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                reason: "no finalized provider-ingest anchor exists for the requested network",
            },
        )?;
        if height < floor.height {
            return Err(below_floor_error(&index, network_id, height, floor.height));
        }
        if height == floor.height
            && let Some(base) = index.virtual_bases.get(network_id)
        {
            verify_checkpoint_entry(base, self.bounds)?;
            if base.checkpoint.material.retention_floor.block_hash != block_hash {
                return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                    network_id: *network_id,
                    height,
                });
            }
            return Ok(base.checkpoint.material.retention_floor.clone());
        }
        let entry = index.by_height.get(&(*network_id, height)).ok_or_else(|| {
            ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor {
                network_id: *network_id,
                height,
            }
        })?;
        verify_record_entry(entry, self.bounds)?;
        if entry.record.material.key.block_hash != block_hash {
            return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                network_id: *network_id,
                height,
            });
        }
        Ok(entry.record.material.key.clone())
    }
    /// Return the monotonic in-process generation of the validated immutable record index.
    ///
    /// # Errors
    ///
    /// Returns an integrity error if the archive lock or filesystem boundary is no longer valid.
    pub fn health_generation(&self) -> Result<u64, ProviderIngestFinalizedArchiveErrorV1> {
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        Ok(index.generation)
    }
    /// Return whether the complete bound archive namespace has no records.
    ///
    /// This is the only state accepted when a fresh height-zero node enables the archive before
    /// genesis capture. The durable namespace is rescanned so an archive for another network cannot
    /// be mistaken for an empty current-network activation floor.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed storage, bounds, or archive-integrity error.
    pub fn is_empty(&self) -> Result<bool, ProviderIngestFinalizedArchiveErrorV1> {
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let durable = load_archive_index(&self.records, self.bounds)?;
        self.verify_storage_boundaries()?;
        Ok(index.generation == 0
            && index.by_height.is_empty()
            && index.virtual_bases.is_empty()
            && index.total_bytes == 0
            && durable.generation == 0
            && durable.by_height.is_empty()
            && durable.virtual_bases.is_empty()
            && durable.total_bytes == 0)
    }
    /// Qualify contiguous immutable coverage against Kura's exact durable tip.
    ///
    /// Every represented anchor is reauthenticated against its result-bearing
    /// block and current commit certificate. The archive and Kura generations are
    /// reread after validation so concurrent boundary changes fail closed. Without an active
    /// Norito budget, only certified ancestry verification releases the physical index reader;
    /// a bounded all-network source inventory also detects same-tip retention changes.
    ///
    /// # Errors
    ///
    /// Rejects empty/incomplete coverage, a forked or timestamp-substituted record, archive state
    /// ahead of Kura, excessive lag, or a changing qualification boundary.
    pub fn qualify_against_certified_tip(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        maximum_kura_tip_lag_blocks: u64,
    ) -> Result<ProviderIngestFinalizedArchiveQualificationV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        self.qualify_against_certified_tip_observed(
            state_ro,
            kura,
            maximum_kura_tip_lag_blocks,
            #[cfg(any(test, feature = "iroha-core-tests"))]
            |_| Ok(()),
        )
    }

    /// Exercise the original qualification with one component-test interleaving.
    ///
    /// The callback receives whether the actual reader was released. Every native
    /// certificate and source fence remains mandatory; no qualification can be injected.
    ///
    /// # Errors
    /// Returns the ordinary qualification or interleaving error, with original
    /// archive/Kura exit refusals taking precedence after an unlocked observation.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn qualify_against_certified_tip_with_interleaving_for_testing(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        maximum_kura_tip_lag_blocks: u64,
        interleave: impl FnOnce(bool) -> Result<(), ProviderIngestFinalizedArchiveErrorV1>,
    ) -> Result<ProviderIngestFinalizedArchiveQualificationV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        self.qualify_against_certified_tip_observed(
            state_ro,
            kura,
            maximum_kura_tip_lag_blocks,
            interleave,
        )
    }

    fn qualify_against_certified_tip_observed(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        maximum_kura_tip_lag_blocks: u64,
        #[cfg(any(test, feature = "iroha-core-tests"))] after_selection: impl FnOnce(
            bool,
        ) -> Result<
            (),
            ProviderIngestFinalizedArchiveErrorV1,
        >,
    ) -> Result<ProviderIngestFinalizedArchiveQualificationV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        let network_id = state_ro.network_id();
        let certified =
            CertifiedArchiveView::new(state_ro, kura).map_err(certified_authentication_error)?;
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidKey {
                reason: "network id must be an exact genesis-derived identity",
            });
        }
        let generation = self.health_generation()?;
        let index = self.read_index()?;
        if norito::core::decode_limits_active() {
            // Preserve the caller's physical read/decode order and early refusals.
            #[cfg(any(test, feature = "iroha-core-tests"))]
            after_selection(false)?;
            let qualification = self.qualify_index(
                &index,
                network_id,
                &certified,
                maximum_kura_tip_lag_blocks,
                generation,
                true,
            )?;
            certified
                .verify_unchanged()
                .map_err(certified_authentication_error)?;
            drop(index);
            if self.health_generation()? != generation {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                        boundary: "archive",
                    },
                );
            }
            return Ok(qualification);
        }

        // This is only a bounded inventory of the exact original source identities. It
        // contains no decoded projections or validation verdict. All canonical physical
        // reads and complete cross-network coverage checks still run under this reader.
        let prepared = QualificationInventory::capture(&index, self.bounds).map(|inventory| {
            let selection = self.qualify_index(
                &index,
                network_id,
                &certified,
                maximum_kura_tip_lag_blocks,
                generation,
                false,
            );
            (inventory, selection)
        });
        drop(index);
        let (inventory, result) = match prepared {
            Ok((inventory, selection)) => {
                #[cfg(any(test, feature = "iroha-core-tests"))]
                let observed = after_selection(true);
                #[cfg(not(any(test, feature = "iroha-core-tests")))]
                let observed: Result<(), ProviderIngestFinalizedArchiveErrorV1> = Ok(());
                let result = observed.and(selection).and_then(|qualification| {
                    inventory.authenticate(network_id, &certified)?;
                    Ok(qualification)
                });
                (Some(inventory), result)
            }
            Err(error) => (None, Err(error)),
        };
        // Close both original sources even on an ordinary validation/observer error.
        // Compaction can preserve generation, so compare the complete retained inventory.
        let archive_exit = (|| {
            let current = self.read_index()?;
            self.verify_storage_boundaries()?;
            if let Some(inventory) = &inventory {
                inventory.require_same(&current)?;
            }
            if current.generation != generation {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                        boundary: "archive",
                    },
                );
            }
            Ok::<(), ProviderIngestFinalizedArchiveErrorV1>(())
        })();
        let certified_exit = certified
            .verify_unchanged()
            .map_err(certified_authentication_error);
        archive_exit?;
        certified_exit?;
        result
    }

    // One canonical physical/coverage recipe. Only certificate placement changes;
    // caller-active Norito scopes retain the original interleaving under the reader.
    fn qualify_index<V: StateReadOnly + ?Sized>(
        &self,
        index: &ArchiveIndexV1,
        network_id: &NetworkId,
        certified: &CertifiedArchiveView<'_, V>,
        maximum_kura_tip_lag_blocks: u64,
        generation: u64,
        authenticate_in_place: bool,
    ) -> Result<ProviderIngestFinalizedArchiveQualificationV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        self.verify_storage_boundaries()?;
        validate_index_coverage(index, self.bounds)?;
        let network_range = (
            std::ops::Bound::Included((*network_id, 0)),
            std::ops::Bound::Included((*network_id, u64::MAX)),
        );
        let activation_floor = activation_floor_from_index(index, network_id)?.ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                reason: "no exact anchor exists for the requested network",
            },
        )?;
        let archive_tip = index
            .by_height
            .range(network_range.clone())
            .next_back()
            .map(|(_, entry)| entry.record.material.key.clone())
            .unwrap_or_else(|| activation_floor.clone());
        if archive_tip.height > certified.tip_height() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveAheadOfKura {
                archive_height: archive_tip.height,
                kura_height: certified.tip_height(),
            });
        }
        let lag_blocks = certified.tip_height() - archive_tip.height;
        if lag_blocks > maximum_kura_tip_lag_blocks {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveKuraTipLagExceeded {
                    archive_height: archive_tip.height,
                    kura_height: certified.tip_height(),
                    lag: lag_blocks,
                    maximum: maximum_kura_tip_lag_blocks,
                },
            );
        }
        if let Some(base) = index.virtual_bases.get(network_id) {
            verify_checkpoint_entry(base, self.bounds)?;
            if authenticate_in_place {
                authenticate_qualification_base(
                    &base.checkpoint.material.retention_floor,
                    base.checkpoint.material.certified_block_id,
                    network_id,
                    certified,
                )?;
            }
        }
        for (_, entry) in index.by_height.range(network_range) {
            verify_record_entry(entry, self.bounds)?;
            if authenticate_in_place {
                authenticate_archive_anchor(&entry.record.material.key, network_id, certified)?;
            }
        }
        Ok(ProviderIngestFinalizedArchiveQualificationV1 {
            activation_floor,
            archive_tip,
            kura_tip_height: certified.tip_height(),
            lag_blocks,
            generation,
        })
    }
    /// Reconcile one replayed startup state tip using the current certified chain, then
    /// require that exact State key to be the zero-lag archive and Kura tip.
    ///
    /// An empty archive establishes an explicit activation floor at the replayed tip. A non-empty
    /// archive accepts only its exact tip replay or one exact successor; a larger gap requires
    /// authenticated per-height replay and fails instead of manufacturing history.
    ///
    /// # Errors
    ///
    /// Rejects an empty state, unavailable certified finality, gap, fork,
    /// projection failure, or non-zero Kura suffix after capture.
    pub fn reconcile_certified_state_tip(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<
        ProviderIngestFinalizedArchiveReconcileOutcomeV1,
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        let height = u64::try_from(state_ro.height()).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                reason: "startup state height exceeds the supported range",
            }
        })?;
        if height == 0 {
            return Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                reason: "startup state has no committed block to reconcile",
            });
        }
        let expected_state_tip = authenticate_capture_view(state_ro, kura)?;
        let activation_floor_before = self.activation_floor(state_ro.network_id())?;
        let insertion = self.capture_certified_view(state_ro, kura)?;
        let qualification = self.qualify_against_certified_tip(state_ro, kura, 0)?;
        if qualification.archive_tip() != &expected_state_tip {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "startup state tip differs from the zero-lag archive and Kura tip",
                },
            );
        }
        Ok(ProviderIngestFinalizedArchiveReconcileOutcomeV1 {
            insertion,
            qualification,
            activation_floor_created: activation_floor_before.is_none(),
        })
    }
    /// Capture one immutable committed view authenticated by its exact durable
    /// current Kura commit certificate.
    ///
    /// # Errors
    ///
    /// Fails closed for any Kura/view mismatch, malformed authoritative state, gap, fork, rollback,
    /// substitution, resource exhaustion, or publication failure.
    pub fn capture_certified_view(
        &self,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<ProviderIngestFinalizedArchiveInsertOutcomeV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        let key = committed_capture_key(state_ro, kura)?;
        let certified =
            CertifiedArchiveView::new(state_ro, kura).map_err(certified_authentication_error)?;
        authenticate_archive_anchor(&key, state_ro.network_id(), &certified)?;
        let projection = capture_projection(state_ro, key, self.bounds)?;
        certified
            .verify_unchanged()
            .map_err(certified_authentication_error)?;
        let mut index = self.index.try_write().map_err(Self::index_lock_error)?;
        self.prepare_insert_locked(&projection, &index)?
            .persist(self, &mut index)
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
        fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
    ) -> Result<
        ProviderIngestFinalizedArchiveCompactionProposalV1,
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        validate_index_coverage(&index, self.bounds)?;
        authenticate_retention_prefix(&index, fence, state_ro, kura, self.bounds)?;
        let prepared = prepare_archive_compaction(&index, fence, self.bounds)?;
        validate_prepared_compaction_capacity(&index, &prepared, self.bounds)?;
        compaction_proposal(&prepared, fence)
    }
    /// Durably approve and install one previously prepared compaction.
    ///
    /// This is the only production compaction entry point. It repeats all archive and Kura
    /// qualification while holding the archive write lock, installs a monotonic canonical record
    /// through the deployment-owned CAS authority, and requires exact authoritative readback before
    /// publishing a checkpoint or unlinking any prefix object.
    ///
    /// # Errors
    ///
    /// In addition to preparation failures, rejects proposal substitution,
    /// missing or drifting authority identity, rollback, equivocation, an
    /// unchanged or ambiguous CAS, and any durable publication failure.
    pub fn approve_and_install_certified_compaction(
        &self,
        proposal: &ProviderIngestFinalizedArchiveCompactionProposalV1,
        state_ro: &impl StateReadOnly,
        kura: &Kura,
        binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
        authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
    ) -> Result<
        ProviderIngestFinalizedArchiveCompactionOutcomeV1,
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        proposal.validate()?;
        assert_retention_authority_identity(binding, authority)?;
        let fence = proposal.fence();
        let mut index = self.write_index()?;
        self.verify_storage_boundaries()?;
        validate_index_coverage(&index, self.bounds)?;
        authenticate_retention_prefix(&index, fence, state_ro, kura, self.bounds)?;
        let prepared = prepare_archive_compaction(&index, fence, self.bounds)?;
        validate_prepared_compaction_capacity(&index, &prepared, self.bounds)?;
        if compaction_proposal(&prepared, fence)? != *proposal {
            return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionProposalMismatch);
        }
        let network_id = &fence.key.network_id;
        let current = load_retention_approval(binding, authority, network_id)?;
        let expected_checkpoint = prepared
            .previous_base
            .as_ref()
            .map(|base| base.checkpoint.checkpoint_digest);
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
                    ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                        reason: "approval sequence overflowed",
                    },
                )
            })?;
            let next = ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::try_new(
                sequence,
                binding.qualification(),
                proposal.clone(),
                current
                    .as_ref()
                    .map(ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::revision),
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
        let readback = load_retention_approval(binding, authority, network_id)?;
        if readback.as_ref() != Some(&next) {
            return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityEquivocation);
        }
        self.publish_prepared_compaction(&mut index, prepared, || {}, &mut |_| {})
    }
    #[cfg(test)]
    fn compact_prefix_locked<AfterPublish, AfterUnlink>(
        &self,
        index: &mut ArchiveIndexV1,
        fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
        after_publish: AfterPublish,
        mut after_unlink: AfterUnlink,
    ) -> Result<
        ProviderIngestFinalizedArchiveCompactionOutcomeV1,
        ProviderIngestFinalizedArchiveErrorV1,
    >
    where
        AfterPublish: FnOnce(),
        AfterUnlink: FnMut(usize),
    {
        if fence.expected_archive_generation != index.generation {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::RetentionFenceGenerationMismatch {
                    expected: fence.expected_archive_generation,
                    observed: index.generation,
                },
            );
        }
        let prepared = prepare_archive_compaction(index, fence, self.bounds)?;
        validate_prepared_compaction_capacity(index, &prepared, self.bounds)?;
        self.publish_prepared_compaction(index, prepared, after_publish, &mut after_unlink)
    }
    fn publish_prepared_compaction<AfterPublish, AfterUnlink>(
        &self,
        index: &mut ArchiveIndexV1,
        prepared: PreparedArchiveCompactionV1,
        after_publish: AfterPublish,
        after_unlink: &mut AfterUnlink,
    ) -> Result<
        ProviderIngestFinalizedArchiveCompactionOutcomeV1,
        ProviderIngestFinalizedArchiveErrorV1,
    >
    where
        AfterPublish: FnOnce(),
        AfterUnlink: FnMut(usize),
    {
        let checkpoint = prepared.checkpoint;
        let checkpoint_bytes = bounded_bytes_len(&prepared.canonical_bytes);
        let checkpoint_path = self
            .checkpoints
            .join(checkpoint_file_name(checkpoint.checkpoint_digest));
        publish_immutable_bytes(
            &self.checkpoints,
            self.checkpoints_identity,
            &checkpoint_path,
            &prepared.canonical_bytes,
        )?;
        let loaded = load_checkpoint_at(&checkpoint_path, self.bounds)?;
        if loaded != checkpoint {
            return Err(ProviderIngestFinalizedArchiveErrorV1::CheckpointDigestMismatch);
        }
        after_publish();
        let virtual_base = ArchiveVirtualBaseV1 {
            checkpoint: checkpoint.clone(),
            path: checkpoint_path,
            canonical_bytes: checkpoint_bytes,
        };
        index
            .virtual_bases
            .insert(checkpoint.material.retention_floor.network_id, virtual_base);
        for (position, (subject, entry)) in prepared.obsolete.iter().enumerate() {
            unlink_verified_archive_file(&self.records, self.records_identity, &entry.path)?;
            after_unlink(position);
            index.by_height.remove(subject);
        }
        if let Some(previous) = prepared.previous_base {
            unlink_verified_archive_file(
                &self.checkpoints,
                self.checkpoints_identity,
                &previous.path,
            )?;
        }
        refresh_archive_accounting(index, self.bounds)?;
        validate_index_coverage(index, self.bounds)?;
        self.verify_storage_boundaries()?;
        Ok(ProviderIngestFinalizedArchiveCompactionOutcomeV1 {
            retention_floor: checkpoint.material.retention_floor.clone(),
            checkpoint_digest: checkpoint.checkpoint_digest,
            pruned_entries: checkpoint.material.pruned_entries,
            pruned_bytes: checkpoint.material.pruned_bytes,
            generation: index.generation,
        })
    }
    /// Durably publish one exact typed projection.
    ///
    /// This lower-level entry point is useful to authenticated replay and deterministic tests.
    /// Production fresh capture should use [`Self::capture_certified_view`].
    ///
    /// # Errors
    ///
    /// Returns a typed validation, coverage, conflict, bounds, or durability
    /// failure.
    /// Existing records are never overwritten.
    pub fn insert(
        &self,
        projection: ProviderIngestFinalizedProjectionV1,
    ) -> Result<ProviderIngestFinalizedArchiveInsertOutcomeV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        let mut index = self.write_index()?;
        self.prepare_insert_locked(&projection, &index)?
            .persist(self, &mut index)
    }
    fn prepare_insert_locked(
        &self,
        projection: &ProviderIngestFinalizedProjectionV1,
        index: &ArchiveIndexV1,
    ) -> Result<ProviderInsertionPlan, ProviderIngestFinalizedArchiveErrorV1> {
        projection.validate(self.bounds)?;
        self.verify_storage_boundaries()?;
        let subject = (projection.key.network_id, projection.key.height);
        if let Some(base) = index.virtual_bases.get(&projection.key.network_id) {
            let floor = &base.checkpoint.material.retention_floor;
            if projection.key.height < floor.height {
                return Err(ProviderIngestFinalizedArchiveErrorV1::BelowRetentionFloor {
                    requested_height: projection.key.height,
                    retention_height: floor.height,
                });
            }
            if projection.key.height == floor.height {
                if projection.key != *floor {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                        network_id: projection.key.network_id,
                        height: projection.key.height,
                    });
                }
                if projection == &base.checkpoint.material.projection {
                    return Ok(ProviderInsertionPlan {
                        key: projection.key,
                        record: None,
                    });
                }
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::ConflictingProjection {
                        network_id: projection.key.network_id,
                        height: projection.key.height,
                    },
                );
            }
        }
        if let Some(existing) = index.by_height.get(&subject) {
            if existing.record.material.key != projection.key {
                return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                    network_id: projection.key.network_id,
                    height: projection.key.height,
                });
            }
            let reconstructed = reconstruct_projection(index, &projection.key, self.bounds)?;
            if &reconstructed == projection {
                return Ok(ProviderInsertionPlan {
                    key: projection.key,
                    record: None,
                });
            }
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ConflictingProjection {
                    network_id: projection.key.network_id,
                    height: projection.key.height,
                },
            );
        }
        let previous_entry = index
            .by_height
            .range((
                std::ops::Bound::Included((projection.key.network_id, 0)),
                std::ops::Bound::Included((projection.key.network_id, u64::MAX)),
            ))
            .next_back()
            .map(|(_, entry)| entry.clone());
        let previous_projection = if let Some(entry) = previous_entry.as_ref() {
            Some(reconstruct_projection(
                index,
                &entry.record.material.key,
                self.bounds,
            )?)
        } else {
            index
                .virtual_bases
                .get(&projection.key.network_id)
                .map(|base| base.checkpoint.material.projection.clone())
        };
        if let Some(previous) = &previous_projection {
            let expected_height = previous.key.height.checked_add(1).ok_or(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveCoverageGap {
                    network_id: projection.key.network_id,
                    missing_height: u64::MAX,
                    observed_height: projection.key.height,
                },
            )?;
            if projection.key.height != expected_height {
                return Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveCoverageGap {
                    network_id: projection.key.network_id,
                    missing_height: expected_height,
                    observed_height: projection.key.height,
                });
            }
            validate_projection_transition(previous, projection)?;
        }
        validate_historical_policy_transition(index, projection, self.bounds)?;
        validate_historical_order_transition(index, projection, self.bounds)?;
        validate_projection_completion_anchors_before_insert(index, projection)?;
        let deltas = build_provider_deltas(previous_projection.as_ref(), projection);
        let provider_state_root = provider_state_root(&projection.providers)?;
        let predecessor = previous_entry.map_or_else(
            || {
                index
                    .virtual_bases
                    .get(&projection.key.network_id)
                    .map(|base| ProviderIngestFinalizedArchivePredecessorV1 {
                        key: base.checkpoint.material.retention_floor.clone(),
                        record_digest: base.checkpoint.material.original_terminal_record_digest,
                    })
            },
            |entry| {
                Some(ProviderIngestFinalizedArchivePredecessorV1 {
                    key: entry.record.material.key,
                    record_digest: entry.record.record_digest,
                })
            },
        );
        let record = ProviderIngestFinalizedArchiveRecordV1::try_new(
            ProviderIngestFinalizedArchiveRecordMaterialV1 {
                version: ARCHIVE_VERSION_V1,
                key: projection.key,
                predecessor,
                deltas,
                provider_state_root,
            },
        )?;
        let bytes = encode_bounded_record(&record, self.bounds)?;
        ensure_insert_capacity(index, self.bounds, bytes.len())?;
        let path = self.record_path(&projection.key)?;
        let canonical_bytes = bounded_bytes_len(&bytes);
        let total_bytes = index.total_bytes.checked_add(canonical_bytes).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: u64::MAX,
                maximum: self.bounds.max_total_bytes(),
            },
        )?;
        let entry = ArchiveRecordEntryV1 {
            record,
            path,
            canonical_bytes,
        };
        let generation = index.generation.checked_add(1).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: usize::MAX,
                maximum: self.bounds.max_archive_entries(),
            },
        )?;
        validate_index_coverage_with_successor(index, self.bounds, Some(&entry), total_bytes)?;
        Ok(ProviderInsertionPlan {
            key: projection.key,
            record: Some(PreparedProviderRecord {
                entry,
                bytes,
                total_bytes,
                generation,
            }),
        })
    }
    /// Read one bounded provider-indexed page at an exact finalized anchor.
    ///
    /// `cursor` is exclusive and must belong to the same network, block, timestamp, provider, and
    /// committed provider-state root. Missing provider state returns an empty terminal page;
    /// another provider is never scanned or returned.
    ///
    /// # Errors
    ///
    /// Rejects a key below the explicit activation floor, a missing/forked
    /// exact anchor, cursor substitution, invalid bounds, or archive damage.
    pub fn read_provider_page(
        &self,
        key: &ProviderIngestFinalizedArchiveKeyV1,
        provider_id: ProviderId,
        cursor: Option<&ProviderIngestFinalizedArchiveCursorV1>,
        limit: usize,
    ) -> Result<ProviderIngestFinalizedArchivePageV1, ProviderIngestFinalizedArchiveErrorV1> {
        key.validate()?;
        if provider_id.as_bytes() == &[0; 32] {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "queried provider identity must be non-zero",
            });
        }
        if limit == 0 || limit > self.bounds.max_page_rows() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidPageLimit {
                observed: limit,
                maximum: self.bounds.max_page_rows(),
            });
        }
        let (root, provider) = self.read_provider_projection_at_key(key, provider_id)?;
        if let Some(cursor) = cursor
            && (&cursor.key != key
                || cursor.provider_id != provider_id
                || cursor.provider_state_root != root)
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::CursorSubstitution);
        }
        let orders = provider
            .as_ref()
            .map_or(&[][..], |provider| provider.orders.as_slice());
        let start = cursor.map_or(0, |cursor| {
            orders
                .binary_search_by_key(&cursor.after_order_id, |order| order.order_id())
                .map_or(usize::MAX, |index| index.saturating_add(1))
        });
        if start == usize::MAX || start > orders.len() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCursorBoundary);
        }
        let end = start.saturating_add(limit).min(orders.len());
        let mut rows = Vec::new();
        rows.try_reserve(end.saturating_sub(start)).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
                resource: "provider page",
            }
        })?;
        if let Some(provider) = provider.as_ref() {
            rows.extend(
                orders[start..end]
                    .iter()
                    .map(|order| project_archive_assignment(key, provider, order)),
            );
        }
        let next_cursor = (end < orders.len()).then(|| ProviderIngestFinalizedArchiveCursorV1 {
            key: key.clone(),
            provider_id,
            provider_state_root: root,
            after_order_id: orders[end - 1].order_id(),
        });
        Ok(ProviderIngestFinalizedArchivePageV1 {
            key: key.clone(),
            provider_id,
            provider_state_root: root,
            rows,
            next_cursor,
        })
    }
    /// Read one provider/order assignment directly from an exact finalized anchor.
    ///
    /// This does not scan bounded pages, change a runtime cursor, or select a current head.
    /// The caller must independently authenticate that `key` is the currently visible committed
    /// State/Kura anchor before using this immutable archive result as current authority.
    ///
    /// # Errors
    ///
    /// Rejects a malformed provider or order, missing/forked/below-floor anchor, invalid
    /// canonical order, archive corruption, or a bounded projection allocation failure.
    pub fn read_provider_assignment(
        &self,
        key: &ProviderIngestFinalizedArchiveKeyV1,
        provider_id: ProviderId,
        order_id: ReplicationOrderId,
    ) -> Result<
        ProviderIngestFinalizedArchiveAssignmentLookupV1,
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        if order_id.as_bytes() == &[0; 32] {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "queried replication-order identity must be non-zero",
            });
        }
        let (provider_state_root, provider) =
            self.read_provider_projection_at_key(key, provider_id)?;
        let archived = provider.as_ref().and_then(|provider| {
            provider
                .orders
                .binary_search_by_key(&order_id, |order| order.order_id())
                .ok()
                .map(|index| &provider.orders[index])
        });
        let (assignment, source_provider_ids) =
            if let (Some(provider), Some(archived)) = (provider.as_ref(), archived) {
                let canonical = validated_replication_order_from_record(
                    &archived.replication_order.order_id,
                    &archived.replication_order,
                )?;
                if !canonical
                    .assignments
                    .iter()
                    .any(|assignment| assignment.provider_id == *provider_id.as_bytes())
                {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "queried provider is absent from the canonical order",
                    });
                }
                let mut sources = Vec::new();
                sources
                    .try_reserve(canonical.assignments.len().saturating_sub(1))
                    .map_err(
                        |_| ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
                            resource: "assignment source providers",
                        },
                    )?;
                sources.extend(canonical.assignments.iter().filter_map(|assignment| {
                    (assignment.provider_id != *provider_id.as_bytes())
                        .then_some(assignment.provider_id)
                }));
                (
                    Some(project_archive_assignment(key, provider, archived)),
                    sources,
                )
            } else {
                (None, Vec::new())
            };
        Ok(ProviderIngestFinalizedArchiveAssignmentLookupV1 {
            key: *key,
            provider_id,
            provider_state_root,
            assignment,
            source_provider_ids,
        })
    }
    fn read_provider_projection_at_key(
        &self,
        key: &ProviderIngestFinalizedArchiveKeyV1,
        provider_id: ProviderId,
    ) -> Result<
        (
            [u8; 32],
            Option<ProviderIngestFinalizedProviderProjectionV1>,
        ),
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        key.validate()?;
        if provider_id.as_bytes() == &[0; 32] {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "queried provider identity must be non-zero",
            });
        }
        let index = self.read_index()?;
        self.verify_storage_boundaries()?;
        let floor = activation_floor_from_index(&index, &key.network_id)?.ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                reason: "no finalized provider-ingest anchor exists for the requested network",
            },
        )?;
        if key.height < floor.height {
            return Err(below_floor_error(
                &index,
                &key.network_id,
                key.height,
                floor.height,
            ));
        }
        let root = if key.height == floor.height
            && let Some(base) = index.virtual_bases.get(&key.network_id)
        {
            verify_checkpoint_entry(base, self.bounds)?;
            if &base.checkpoint.material.retention_floor != key {
                return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                    network_id: key.network_id,
                    height: key.height,
                });
            }
            base.checkpoint.material.provider_state_root
        } else {
            let Some(entry) = index.by_height.get(&(key.network_id, key.height)) else {
                return Err(ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor {
                    network_id: key.network_id,
                    height: key.height,
                });
            };
            if &entry.record.material.key != key {
                return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                    network_id: key.network_id,
                    height: key.height,
                });
            }
            entry.record.material.provider_state_root
        };
        let provider = reconstruct_provider_projection(&index, key, provider_id, self.bounds)?;
        Ok((root, provider))
    }
    /// Return the deterministic immutable path for one exact key.
    ///
    /// # Errors
    ///
    /// Rejects malformed keys or canonical key-encoding failure.
    pub fn record_path(
        &self,
        key: &ProviderIngestFinalizedArchiveKeyV1,
    ) -> Result<PathBuf, ProviderIngestFinalizedArchiveErrorV1> {
        key.validate()?;
        Ok(self.records.join(record_file_name(key)?))
    }
    fn read_index(
        &self,
    ) -> Result<ArchiveIndexReadGuard<'_, ArchiveIndexV1>, ProviderIngestFinalizedArchiveErrorV1>
    {
        self.index.read().map_err(Self::index_lock_error)
    }
    // Retention and ordinary local mutation serialize through the actual index writer.
    // Commit-owned capture probes this same writer without blocking.
    fn write_index(
        &self,
    ) -> Result<ArchiveIndexWriteGuard<'_, ArchiveIndexV1>, ProviderIngestFinalizedArchiveErrorV1>
    {
        let index = self.index.write().map_err(Self::index_lock_error)?;
        Ok(index)
    }
    fn index_lock_error(error: ArchiveIndexLockError) -> ProviderIngestFinalizedArchiveErrorV1 {
        match error {
            ArchiveIndexLockError::Poisoned => {
                ProviderIngestFinalizedArchiveErrorV1::ArchiveLockPoisoned
            }
            ArchiveIndexLockError::Busy(wait) => {
                ProviderIngestFinalizedArchiveErrorV1::IndexBusy { wait }
            }
        }
    }
    fn verify_storage_boundaries(&self) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
        verify_absolute_directory_ancestry(&self.root)?;
        verify_archive_directory_identity(&self.root, self.root_identity).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: self.root.clone(),
                source,
            }
        })?;
        verify_archive_directory_identity(&self.records, self.records_identity).map_err(
            |source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: self.records.clone(),
                source,
            },
        )?;
        verify_archive_directory_identity(&self.checkpoints, self.checkpoints_identity).map_err(
            |source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: self.checkpoints.clone(),
                source,
            },
        )?;
        let lock_path = self.root.join(WRITER_LOCK_FILE);
        let lock_metadata = secure_file_metadata::from_path(&lock_path).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: lock_path.clone(),
                source,
            }
        })?;
        let opened_metadata =
            secure_file_metadata::from_file(&self.writer_lock).map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::Read {
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
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path: lock_path,
                reason: "archive writer ownership file was substituted",
            });
        }
        validate_root_namespace(&self.root)?;
        Ok(())
    }
}
#[derive(Debug)]
struct ProviderProjectionBuilderV1 {
    expected_owner: Option<AccountId>,
    expected_authority: Option<ProviderIngestCompletionAuthorityV1>,
    orders: BTreeMap<ReplicationOrderId, ProviderIngestFinalizedArchivedOrderV1>,
}
fn capture_projection(
    state_ro: &impl StateReadOnly,
    key: ProviderIngestFinalizedArchiveKeyV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<ProviderIngestFinalizedProjectionV1, ProviderIngestFinalizedArchiveErrorV1> {
    let world = state_ro.world();
    let mut providers = BTreeMap::<ProviderId, ProviderProjectionBuilderV1>::new();
    for (provider_id, owner) in world.provider_owners().iter() {
        if providers.len() >= bounds.max_providers_per_anchor() {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                    resource: "providers per anchor",
                    observed: providers.len().saturating_add(1),
                    maximum: bounds.max_providers_per_anchor(),
                },
            );
        }
        providers.insert(
            *provider_id,
            ProviderProjectionBuilderV1 {
                expected_owner: Some(owner.clone()),
                expected_authority: None,
                orders: BTreeMap::new(),
            },
        );
    }
    for (provider_id, authority) in world.provider_ingest_completion_authorities().iter() {
        if !authority.is_valid() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "committed provider completion authority is noncanonical",
            });
        }
        let provider = providers.get_mut(provider_id).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "completion authority has no registered provider owner",
            },
        )?;
        if provider.expected_owner.as_ref() != Some(&authority.provider_owner) {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "completion authority differs from the registered provider owner",
            });
        }
        provider.expected_authority = Some(authority.clone());
    }
    let mut total_orders = 0_usize;
    for (order_id, order_record) in world.replication_orders().iter() {
        let decoded = validated_replication_order_from_record(order_id, order_record)?;
        let pin = world
            .pin_manifests()
            .get(&order_record.manifest_digest)
            .cloned()
            .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "replication order references a missing pin manifest",
            })?;
        if pin.digest != order_record.manifest_digest
            || pin.root_cid != order_record.manifest_root_cid
            || pin.chunker.to_handle() != decoded.chunking_profile
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "replication order and pin manifest bindings differ",
            });
        }
        let musubi_archive = match (
            order_record.musubi_archive,
            world.musubi_locations_by_replication_order().get(order_id),
        ) {
            (None, None) => None,
            (Some(archive_id), Some(reference)) => {
                reference.validate().map_err(|_| {
                    ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "Musubi replication-order/archive binding is noncanonical",
                    }
                })?;
                if reference.binding.replication_order != *order_id
                    || reference.binding.archive_id != archive_id
                {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "Musubi replication-order purpose and projected archive binding disagree",
                    });
                }
                let archive = world
                    .musubi_archives()
                    .get(&reference.binding.archive_id)
                    .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "Musubi archive binding targets a missing archive",
                    })?;
                archive.validate().map_err(|_| {
                    ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "Musubi archive binding targets a noncanonical archive",
                    }
                })?;
                if archive.archive_id != reference.binding.archive_id
                    || archive.commitment != reference.binding.commitment
                {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "Musubi archive binding differs from authoritative registry state",
                    });
                }
                Some(reference.binding.clone())
            }
            (None, Some(_)) | (Some(_), None) => {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "Musubi replication-order purpose and projected archive binding disagree",
                });
            }
        };
        let archived = ProviderIngestFinalizedArchivedOrderV1 {
            pin_manifest: pin,
            replication_order: order_record.clone(),
            musubi_archive,
        };
        for assignment in &decoded.assignments {
            let provider_id = ProviderId::new(assignment.provider_id);
            if !providers.contains_key(&provider_id) {
                if providers.len() >= bounds.max_providers_per_anchor() {
                    return Err(
                        ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                            resource: "providers per anchor",
                            observed: providers.len().saturating_add(1),
                            maximum: bounds.max_providers_per_anchor(),
                        },
                    );
                }
                providers.insert(
                    provider_id,
                    ProviderProjectionBuilderV1 {
                        expected_owner: None,
                        expected_authority: None,
                        orders: BTreeMap::new(),
                    },
                );
            }
            let provider = providers.get_mut(&provider_id).ok_or(
                ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "provider projection insertion failed",
                },
            )?;
            if provider.orders.len() >= bounds.max_orders_per_provider() {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                        resource: "orders per provider",
                        observed: provider.orders.len().saturating_add(1),
                        maximum: bounds.max_orders_per_provider(),
                    },
                );
            }
            total_orders = total_orders.checked_add(1).ok_or(
                ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                    resource: "total provider/order rows",
                    observed: usize::MAX,
                    maximum: bounds.max_total_orders_per_anchor(),
                },
            )?;
            if total_orders > bounds.max_total_orders_per_anchor() {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::ProjectionBoundsExceeded {
                        resource: "total provider/order rows",
                        observed: total_orders,
                        maximum: bounds.max_total_orders_per_anchor(),
                    },
                );
            }
            if provider
                .orders
                .insert(*order_id, archived.clone())
                .is_some()
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "canonical replication order repeats one provider assignment",
                });
            }
        }
    }
    let mut projected = Vec::new();
    projected.try_reserve(providers.len()).map_err(|_| {
        ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
            resource: "provider projection",
        }
    })?;
    projected.extend(providers.into_iter().map(|(provider_id, provider)| {
        ProviderIngestFinalizedProviderProjectionV1 {
            provider_id,
            expected_owner: provider.expected_owner,
            expected_authority: provider.expected_authority,
            orders: provider.orders.into_values().collect(),
        }
    }));
    let projection = ProviderIngestFinalizedProjectionV1 {
        key,
        providers: projected,
    };
    projection.validate(bounds)?;
    Ok(projection)
}
fn project_archive_assignment(
    key: &ProviderIngestFinalizedArchiveKeyV1,
    provider: &ProviderIngestFinalizedProviderProjectionV1,
    order: &ProviderIngestFinalizedArchivedOrderV1,
) -> ProviderIngestFinalizedArchiveAssignmentV1 {
    let finalized_unix_epoch = key.finalized_at_unix_ms / MILLIS_PER_UNIX_SECOND;
    let completion_epoch = matches!(
        order.replication_order.status,
        ReplicationOrderStatus::Pending
    )
    .then_some(finalized_unix_epoch)
    .filter(|epoch| {
        *epoch >= order.replication_order.issued_epoch
            && *epoch <= order.replication_order.deadline_epoch
    });
    ProviderIngestFinalizedArchiveAssignmentV1 {
        provider_id: provider.provider_id,
        expected_owner: provider.expected_owner.clone(),
        expected_authority: provider.expected_authority.clone(),
        expected_assignment_revision: order.replication_order.assignment_revision,
        finalized_anchor: key.finalized_anchor(),
        finalized_at_unix_ms: key.finalized_at_unix_ms,
        pin_manifest: order.pin_manifest.clone(),
        replication_order: order.replication_order.clone(),
        musubi_archive: order.musubi_archive.clone(),
        completion_epoch,
    }
}
fn validated_replication_order_from_record(
    order_id: &ReplicationOrderId,
    order_record: &ReplicationOrderRecord,
) -> Result<ReplicationOrderV1, ProviderIngestFinalizedArchiveErrorV1> {
    if order_record.assignment_revision == 0
        || order_record.canonical_order.is_empty()
        || order_record.canonical_order.len() > REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "replication order revision or canonical payload is invalid",
        });
    }
    let order = decode_from_bytes_with_limits::<ReplicationOrderV1>(
        &order_record.canonical_order,
        REPLICATION_ORDER_DECODE_LIMITS_V1,
    )
    .map_err(
        |_| ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "replication-order payload failed bounded Norito decoding",
        },
    )?;
    order.validate().map_err(
        |_| ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "replication-order payload failed canonical validation",
        },
    )?;
    let canonical =
        norito::to_bytes(&order).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    if canonical != order_record.canonical_order
        || order_id != &order_record.order_id
        || order.order_id != *order_record.order_id.as_bytes()
        || order.manifest_digest != *order_record.manifest_digest.as_bytes()
        || order.manifest_cid.as_slice() != order_record.manifest_root_cid.as_bytes()
        || order.issued_at != order_record.issued_epoch
        || order.deadline_at != order_record.deadline_epoch
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "replication-order record differs from its canonical payload",
        });
    }
    Ok(order)
}
fn validate_archived_order(
    key: &ProviderIngestFinalizedArchiveKeyV1,
    provider_id: ProviderId,
    archived: &ProviderIngestFinalizedArchivedOrderV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let finalized_unix_epoch = key.finalized_at_unix_ms / MILLIS_PER_UNIX_SECOND;
    let order = validated_replication_order_from_record(
        &archived.replication_order.order_id,
        &archived.replication_order,
    )?;
    if archived.pin_manifest.digest != archived.replication_order.manifest_digest
        || archived.pin_manifest.root_cid != archived.replication_order.manifest_root_cid
        || archived.pin_manifest.chunker.to_handle() != order.chunking_profile
        || !order
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == *provider_id.as_bytes())
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "provider, order, and pin-manifest bindings are inconsistent",
        });
    }
    match (
        archived.replication_order.musubi_archive,
        &archived.musubi_archive,
    ) {
        (None, None) => {}
        (Some(archive_id), Some(binding)) => {
            binding.validate().map_err(|_| {
                ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "Musubi replication-order/archive binding is noncanonical",
                }
            })?;
            let commitment = &binding.commitment;
            if binding.replication_order != archived.replication_order.order_id
                || binding.archive_id != archive_id
                || commitment.root_cid != archived.pin_manifest.root_cid
                || commitment.chunker != archived.pin_manifest.chunker
                || commitment.chunk_plan_digest.as_bytes()
                    != &archived.pin_manifest.chunk_digest_sha3_256
                || commitment.por_root.as_bytes() != &archived.pin_manifest.por_root
                || commitment.content_length != archived.pin_manifest.content_length
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                    reason: "Musubi archive binding differs from its replication-order purpose or pin commitment",
                });
            }
        }
        (None, Some(_)) | (Some(_), None) => {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "Musubi replication-order purpose and projected archive binding disagree",
            });
        }
    }
    validate_pin_manifest_lifecycle(&archived.pin_manifest)?;
    if archived.replication_order.order_id.is_auto() {
        crate::smartcontracts::isi::sorafs::validate_stored_automatic_replication_order(
            &archived.pin_manifest,
            &archived.replication_order,
            &hex::encode(archived.replication_order.order_id.as_bytes()),
        )
        .map_err(
            |_| ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "automatic replication order differs from its exact derived pin contract",
            },
        )?;
    }
    let Some(approved_epoch) = archived.pin_manifest.approved_epoch else {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "replication-order lifecycle conflicts with its pin manifest",
        });
    };
    let order_lifecycle_matches_pin = match (
        archived.pin_manifest.status,
        archived.replication_order.status,
    ) {
        (PinStatus::Pending, _)
        | (PinStatus::Approved(_), ReplicationOrderStatus::Cancelled(_)) => false,
        (PinStatus::Approved(_), _) => true,
        (PinStatus::Retired(_), ReplicationOrderStatus::Pending) => false,
        (PinStatus::Retired(retired_epoch), ReplicationOrderStatus::Completed(terminal_epoch)) => {
            terminal_epoch <= retired_epoch
                && (!archived.replication_order.order_id.is_auto()
                    || retired_epoch >= archived.pin_manifest.policy.retention_epoch)
        }
        (PinStatus::Retired(retired_epoch), ReplicationOrderStatus::Expired(terminal_epoch)) => {
            terminal_epoch <= retired_epoch
        }
        (PinStatus::Retired(retired_epoch), ReplicationOrderStatus::Cancelled(cancelled_epoch)) => {
            cancelled_epoch == retired_epoch
        }
    };
    if archived.replication_order.issued_epoch < approved_epoch
        || matches!(archived.pin_manifest.status, PinStatus::Retired(retired_epoch) if archived.replication_order.issued_epoch > retired_epoch)
        || !order_lifecycle_matches_pin
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "replication-order lifecycle conflicts with its pin manifest",
        });
    }
    let assigned = order
        .assignments
        .iter()
        .map(|assignment| ProviderId::new(assignment.provider_id))
        .collect::<BTreeSet<_>>();
    let mut completed = BTreeSet::new();
    let mut previous_completion_epoch = None;
    for completion in &archived.replication_order.provider_completions {
        if !assigned.contains(&completion.provider_id)
            || !completed.insert(completion.provider_id)
            || completion.completion_epoch == 0
            || completion.assignment_revision == 0
            || completion.assignment_revision != archived.replication_order.assignment_revision
            || !completion.completion_authority.is_valid()
            || completion.completion_authority.completion_signer != completion.completed_by
            || !completion.finalized_anchor.is_valid()
            || completion.completion_epoch < archived.replication_order.issued_epoch
            || completion.completion_epoch > archived.replication_order.deadline_epoch
            || previous_completion_epoch
                .is_some_and(|previous| completion.completion_epoch < previous)
            || completion.finalized_anchor.height > key.height
            || completion.completion_epoch > finalized_unix_epoch
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "replication order contains an invalid provider completion",
            });
        }
        previous_completion_epoch = Some(completion.completion_epoch);
    }
    match archived.replication_order.status {
        ReplicationOrderStatus::Pending
            if archived.replication_order.provider_completions.len()
                < usize::from(order.target_replicas) => {}
        ReplicationOrderStatus::Expired(epoch)
            if archived.replication_order.provider_completions.len()
                < usize::from(order.target_replicas)
                && epoch > archived.replication_order.deadline_epoch
                && epoch <= finalized_unix_epoch => {}
        ReplicationOrderStatus::Cancelled(epoch)
            if archived.replication_order.provider_completions.len()
                < usize::from(order.target_replicas)
                && epoch >= archived.replication_order.issued_epoch
                && epoch <= archived.replication_order.deadline_epoch
                && matches!(archived.pin_manifest.status, PinStatus::Retired(retired) if retired == epoch)
                && epoch <= finalized_unix_epoch => {}
        ReplicationOrderStatus::Completed(epoch)
            if archived.replication_order.provider_completions.len()
                == usize::from(order.target_replicas)
                && archived
                    .replication_order
                    .provider_completions
                    .last()
                    .is_some_and(|completion| completion.completion_epoch == epoch) => {}
        _ => {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                reason: "replication-order lifecycle conflicts with provider completions",
            });
        }
    }
    Ok(())
}
fn validate_projection_transition(
    previous: &ProviderIngestFinalizedProjectionV1,
    current: &ProviderIngestFinalizedProjectionV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if current.key.network_id != previous.key.network_id
        || previous
            .key
            .height
            .checked_add(1)
            .is_none_or(|height| height != current.key.height)
        || current.key.finalized_at_unix_ms < previous.key.finalized_at_unix_ms
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidTransition {
            reason: "finalized key is not the exact monotonic successor",
        });
    }
    let previous_providers = previous
        .providers
        .iter()
        .map(|provider| (provider.provider_id, provider))
        .collect::<BTreeMap<_, _>>();
    let current_providers = current
        .providers
        .iter()
        .map(|provider| (provider.provider_id, provider))
        .collect::<BTreeMap<_, _>>();
    for (provider_id, current_provider) in &current_providers {
        if let Some(previous_provider) = previous_providers.get(provider_id) {
            validate_provider_authority_transition(previous_provider, current_provider)?;
        }
    }
    let previous_orders = canonical_order_map(previous)?;
    let current_orders = canonical_order_map(current)?;
    for (order_id, previous_order) in &previous_orders {
        let Some(current_order) = current_orders.get(order_id) else {
            if matches!(
                previous_order.replication_order.status,
                ReplicationOrderStatus::Pending
            ) {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidTransition {
                    reason: "pending replication order disappeared from committed history",
                });
            }
            continue;
        };
        validate_order_transition(previous_order, current_order)?;
    }
    Ok(())
}
#[derive(Debug)]
struct ProviderPolicyHistoryV1 {
    last: ProviderIngestCompletionAuthorityV1,
    active: bool,
    seen_policy_digests: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
}
struct ProviderPolicyHistorySeedV1 {
    providers: BTreeMap<ProviderId, ProviderIngestFinalizedProviderProjectionV1>,
    history: BTreeMap<ProviderId, ProviderPolicyHistoryV1>,
    seeded: bool,
}
struct ProviderOrderHistorySeedV1 {
    providers: BTreeMap<ProviderId, ProviderIngestFinalizedProviderProjectionV1>,
    active: BTreeSet<ReplicationOrderId>,
    seen: BTreeSet<ReplicationOrderId>,
    seeded: bool,
}
fn validate_historical_policy_transition(
    index: &ArchiveIndexV1,
    projection: &ProviderIngestFinalizedProjectionV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let ProviderPolicyHistorySeedV1 {
        mut providers,
        mut history,
        seeded: mut history_seeded,
    } = policy_history_seed_from_virtual_base(index, &projection.key.network_id)?;
    for (_, entry) in index.by_height.range((
        std::ops::Bound::Included((projection.key.network_id, 0)),
        std::ops::Bound::Included((projection.key.network_id, u64::MAX)),
    )) {
        verify_record_entry(entry, bounds)?;
        apply_provider_deltas(&mut providers, &entry.record.material.deltas);
        if history_seeded {
            observe_policy_history(&providers, &mut history)?;
        } else {
            seed_policy_history(&providers, &mut history);
            history_seeded = true;
        }
    }
    let projected = projection
        .providers
        .iter()
        .map(|provider| (provider.provider_id, provider.clone()))
        .collect::<BTreeMap<_, _>>();
    if history_seeded {
        observe_policy_history(&projected, &mut history)
    } else {
        seed_policy_history(&projected, &mut history);
        Ok(())
    }
}
fn validate_historical_order_transition(
    index: &ArchiveIndexV1,
    projection: &ProviderIngestFinalizedProjectionV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let ProviderOrderHistorySeedV1 {
        mut providers,
        mut active,
        mut seen,
        seeded: mut history_seeded,
    } = order_history_seed_from_virtual_base(index, &projection.key.network_id);
    for (_, entry) in index.by_height.range((
        std::ops::Bound::Included((projection.key.network_id, 0)),
        std::ops::Bound::Included((projection.key.network_id, u64::MAX)),
    )) {
        verify_record_entry(entry, bounds)?;
        apply_provider_deltas(&mut providers, &entry.record.material.deltas);
        let current = provider_order_ids(providers.values());
        if history_seeded {
            observe_order_history(current, &mut active, &mut seen)?;
        } else {
            active = current.clone();
            seen = current;
            history_seeded = true;
        }
    }
    let current = provider_order_ids(projection.providers.iter());
    if history_seeded {
        observe_order_history(current, &mut active, &mut seen)
    } else {
        Ok(())
    }
}
fn provider_order_ids<I>(providers: I) -> BTreeSet<ReplicationOrderId>
where
    I: IntoIterator,
    I::Item: std::ops::Deref<Target = ProviderIngestFinalizedProviderProjectionV1>,
{
    providers
        .into_iter()
        .fold(BTreeSet::new(), |mut order_ids, provider| {
            order_ids.extend(provider.orders.iter().map(|order| order.order_id()));
            order_ids
        })
}
fn observe_order_history(
    current: BTreeSet<ReplicationOrderId>,
    active: &mut BTreeSet<ReplicationOrderId>,
    seen: &mut BTreeSet<ReplicationOrderId>,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if let Some(order_id) = current
        .difference(active)
        .find(|order_id| seen.contains(*order_id))
        .copied()
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution { order_id });
    }
    seen.extend(current.iter().copied());
    *active = current;
    Ok(())
}
fn seed_policy_history(
    providers: &BTreeMap<ProviderId, ProviderIngestFinalizedProviderProjectionV1>,
    history: &mut BTreeMap<ProviderId, ProviderPolicyHistoryV1>,
) {
    history.extend(providers.iter().filter_map(|(provider_id, provider)| {
        provider.expected_authority.as_ref().map(|authority| {
            let policy = authority.signer_policy;
            let mut seen_policy_digests = BTreeMap::new();
            seen_policy_digests.insert(policy.policy_id, BTreeSet::from([policy.policy_digest]));
            (
                *provider_id,
                ProviderPolicyHistoryV1 {
                    last: authority.clone(),
                    active: true,
                    seen_policy_digests,
                },
            )
        })
    }));
}
fn observe_policy_history(
    providers: &BTreeMap<ProviderId, ProviderIngestFinalizedProviderProjectionV1>,
    history: &mut BTreeMap<ProviderId, ProviderPolicyHistoryV1>,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    for (provider_id, observed) in history.iter_mut() {
        if providers
            .get(provider_id)
            .and_then(|provider| provider.expected_authority.as_ref())
            .is_none()
        {
            observed.active = false;
        }
    }
    for (provider_id, provider) in providers {
        let Some(next_authority) = provider.expected_authority.as_ref() else {
            continue;
        };
        let next = next_authority.signer_policy;
        let Some(observed) = history.get_mut(provider_id) else {
            if next.revision != 1 || next.predecessor_digest.is_some() {
                return Err(ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                    provider_id: *provider_id,
                });
            }
            let mut seen_policy_digests = BTreeMap::new();
            seen_policy_digests.insert(next.policy_id, BTreeSet::from([next.policy_digest]));
            history.insert(
                *provider_id,
                ProviderPolicyHistoryV1 {
                    last: next_authority.clone(),
                    active: true,
                    seen_policy_digests,
                },
            );
            continue;
        };
        // Equal policy bytes alone must never conceal a changed owner or signer.
        if &observed.last == next_authority {
            if !observed.active {
                return Err(ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                    provider_id: *provider_id,
                });
            }
            continue;
        }
        let previous = observed.last.signer_policy;
        let valid = if previous.policy_id == next.policy_id {
            previous
                .revision
                .checked_add(1)
                .is_some_and(|revision| revision == next.revision)
                && next.predecessor_digest == Some(previous.policy_digest)
                && next.policy_digest != previous.policy_digest
                && !observed
                    .seen_policy_digests
                    .get(&next.policy_id)
                    .is_some_and(|digests| digests.contains(&next.policy_digest))
        } else {
            next.revision == 1
                && next.predecessor_digest.is_none()
                && !observed.seen_policy_digests.contains_key(&next.policy_id)
        };
        if !valid {
            return Err(if previous.policy_id == next.policy_id {
                ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                    provider_id: *provider_id,
                }
            } else {
                ProviderIngestFinalizedArchiveErrorV1::AuthoritySubstitution {
                    provider_id: *provider_id,
                }
            });
        }
        observed.last = next_authority.clone();
        observed.active = true;
        observed
            .seen_policy_digests
            .entry(next.policy_id)
            .or_default()
            .insert(next.policy_digest);
    }
    Ok(())
}
fn validate_projection_completion_anchors_before_insert(
    index: &ArchiveIndexV1,
    projection: &ProviderIngestFinalizedProjectionV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let floor_height = activation_floor_from_index(index, &projection.key.network_id)?
        .map_or(projection.key.height, |floor| floor.height);
    for provider in &projection.providers {
        for order in &provider.orders {
            for completion in &order.replication_order.provider_completions {
                let anchor = completion.finalized_anchor;
                if anchor.height > projection.key.height {
                    return Err(
                        ProviderIngestFinalizedArchiveErrorV1::CompletionAnchorMismatch {
                            order_id: order.order_id(),
                        },
                    );
                }
                if anchor.height < floor_height {
                    continue;
                }
                let matches = if anchor.height == projection.key.height {
                    anchor.block_hash == projection.key.block_hash
                } else if index
                    .virtual_bases
                    .get(&projection.key.network_id)
                    .is_some_and(|base| {
                        base.checkpoint.material.retention_floor.height == anchor.height
                            && base.checkpoint.material.retention_floor.block_hash
                                == anchor.block_hash
                    })
                {
                    true
                } else {
                    index
                        .by_height
                        .get(&(projection.key.network_id, anchor.height))
                        .is_some_and(|entry| {
                            entry.record.material.key.block_hash == anchor.block_hash
                        })
                };
                if !matches {
                    return Err(
                        ProviderIngestFinalizedArchiveErrorV1::CompletionAnchorMismatch {
                            order_id: order.order_id(),
                        },
                    );
                }
            }
        }
    }
    Ok(())
}
fn validate_provider_authority_transition(
    previous: &ProviderIngestFinalizedProviderProjectionV1,
    current: &ProviderIngestFinalizedProviderProjectionV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if previous.expected_owner != current.expected_owner
        && previous.expected_authority == current.expected_authority
        && current.expected_authority.is_some()
    {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::AuthoritySubstitution {
                provider_id: current.provider_id,
            },
        );
    }
    match (
        previous.expected_authority.as_ref(),
        current.expected_authority.as_ref(),
    ) {
        (_, None) => Ok(()),
        // Full-chain history distinguishes first activation from reactivation.
        (None, Some(_)) => Ok(()),
        (Some(previous), Some(next)) if previous == next => Ok(()),
        (Some(previous), Some(next)) => {
            let previous = previous.signer_policy;
            let next = next.signer_policy;
            if previous.policy_id == next.policy_id {
                if previous
                    .revision
                    .checked_add(1)
                    .is_some_and(|revision| revision == next.revision)
                    && next.predecessor_digest == Some(previous.policy_digest)
                    && next.policy_digest != previous.policy_digest
                {
                    Ok(())
                } else {
                    Err(ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                        provider_id: current.provider_id,
                    })
                }
            } else if next.revision == 1 && next.predecessor_digest.is_none() {
                Ok(())
            } else {
                Err(
                    ProviderIngestFinalizedArchiveErrorV1::AuthoritySubstitution {
                        provider_id: current.provider_id,
                    },
                )
            }
        }
    }
}
fn canonical_order_map(
    projection: &ProviderIngestFinalizedProjectionV1,
) -> Result<
    BTreeMap<ReplicationOrderId, ProviderIngestFinalizedArchivedOrderV1>,
    ProviderIngestFinalizedArchiveErrorV1,
> {
    let mut orders = BTreeMap::new();
    for provider in &projection.providers {
        for order in &provider.orders {
            match orders.entry(order.order_id()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(order.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() != order => {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
                        reason: "provider projections disagree about one replication order",
                    });
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
    }
    Ok(orders)
}
fn validate_order_transition(
    previous: &ProviderIngestFinalizedArchivedOrderV1,
    current: &ProviderIngestFinalizedArchivedOrderV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let previous_record = &previous.replication_order;
    let current_record = &current.replication_order;
    if previous_record.order_id != current_record.order_id
        || previous_record.manifest_digest != current_record.manifest_digest
        || previous_record.manifest_root_cid != current_record.manifest_root_cid
        || previous_record.issued_by != current_record.issued_by
        || previous_record.issued_epoch != current_record.issued_epoch
        || previous_record.deadline_epoch != current_record.deadline_epoch
        || previous_record.musubi_archive != current_record.musubi_archive
        || previous.musubi_archive != current.musubi_archive
        || !pin_manifest_immutable_fields_match(&previous.pin_manifest, &current.pin_manifest)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution {
            order_id: current_record.order_id,
        });
    }
    validate_pin_manifest_transition(
        &previous.pin_manifest,
        &current.pin_manifest,
        current_record.order_id,
    )?;
    if current_record.assignment_revision < previous_record.assignment_revision {
        return Err(ProviderIngestFinalizedArchiveErrorV1::AssignmentRollback {
            order_id: current_record.order_id,
        });
    }
    if current_record.assignment_revision == previous_record.assignment_revision {
        if current_record.canonical_order != previous_record.canonical_order {
            return Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution {
                order_id: current_record.order_id,
            });
        }
    } else {
        if previous_record
            .assignment_revision
            .checked_add(1)
            .is_none_or(|revision| revision != current_record.assignment_revision)
            || !previous_record.provider_completions.is_empty()
            || !matches!(previous_record.status, ReplicationOrderStatus::Pending)
            || current_record.canonical_order == previous_record.canonical_order
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::AssignmentRollback {
                order_id: current_record.order_id,
            });
        }
        let previous_order =
            validated_replication_order_from_record(&previous_record.order_id, previous_record)?;
        let mut current_order =
            validated_replication_order_from_record(&current_record.order_id, current_record)?;
        current_order.assignments = previous_order.assignments.clone();
        if current_order != previous_order {
            return Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution {
                order_id: current_record.order_id,
            });
        }
    }
    if !current_record
        .provider_completions
        .starts_with(&previous_record.provider_completions)
        || (!matches!(previous_record.status, ReplicationOrderStatus::Pending)
            && current_record.provider_completions != previous_record.provider_completions)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::CompletionRollback {
            order_id: current_record.order_id,
        });
    }
    let valid_status = match (previous_record.status, current_record.status) {
        (ReplicationOrderStatus::Pending, _) => true,
        (
            ReplicationOrderStatus::Completed(previous),
            ReplicationOrderStatus::Completed(current),
        ) => previous == current,
        (ReplicationOrderStatus::Expired(previous), ReplicationOrderStatus::Expired(current)) => {
            previous == current
        }
        (
            ReplicationOrderStatus::Cancelled(previous),
            ReplicationOrderStatus::Cancelled(current),
        ) => previous == current,
        _ => false,
    };
    if !valid_status {
        return Err(ProviderIngestFinalizedArchiveErrorV1::CompletionRollback {
            order_id: current_record.order_id,
        });
    }
    Ok(())
}
fn pin_manifest_immutable_fields_match(
    previous: &PinManifestRecord,
    current: &PinManifestRecord,
) -> bool {
    previous.digest == current.digest
        && previous.root_cid == current.root_cid
        && previous.chunker == current.chunker
        && previous.chunk_digest_sha3_256 == current.chunk_digest_sha3_256
        && previous.por_root == current.por_root
        && previous.content_length == current.content_length
        && previous.policy == current.policy
        && previous.submitted_by == current.submitted_by
        && previous.submitted_epoch == current.submitted_epoch
        && previous.alias == current.alias
        && previous.successor_of == current.successor_of
        && previous.metadata == current.metadata
}
fn validate_pin_manifest_lifecycle(
    manifest: &PinManifestRecord,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let status_is_valid = match manifest.status {
        iroha_data_model::sorafs::pin_registry::PinStatus::Pending => {
            manifest.approved_epoch.is_none()
                && manifest.retirement_reason.is_none()
                && manifest.council_envelope_digest.is_none()
        }
        iroha_data_model::sorafs::pin_registry::PinStatus::Approved(epoch) => {
            manifest.approved_epoch == Some(epoch)
                && epoch >= manifest.submitted_epoch
                && epoch < manifest.policy.retention_epoch
                && manifest.retirement_reason.is_none()
        }
        iroha_data_model::sorafs::pin_registry::PinStatus::Retired(epoch) => {
            epoch >= manifest.submitted_epoch
                && manifest.approved_epoch.is_none_or(|approved_epoch| {
                    approved_epoch >= manifest.submitted_epoch
                        && approved_epoch <= epoch
                        && approved_epoch < manifest.policy.retention_epoch
                })
                && (manifest.approved_epoch.is_some() || manifest.council_envelope_digest.is_none())
        }
    };
    if !status_is_valid
        || manifest
            .council_envelope_digest
            .is_some_and(|digest| digest == [0; 32])
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection {
            reason: "pin-manifest lifecycle state is noncanonical",
        });
    }
    Ok(())
}
fn validate_pin_manifest_transition(
    previous: &PinManifestRecord,
    current: &PinManifestRecord,
    order_id: ReplicationOrderId,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    use iroha_data_model::sorafs::pin_registry::PinStatus;
    let status_is_monotonic = match (previous.status, current.status) {
        (
            PinStatus::Pending,
            PinStatus::Pending | PinStatus::Approved(_) | PinStatus::Retired(_),
        ) => true,
        (PinStatus::Approved(previous), PinStatus::Approved(current)) => previous == current,
        (PinStatus::Approved(approved), PinStatus::Retired(retired)) => retired >= approved,
        (PinStatus::Retired(previous), PinStatus::Retired(current)) => previous == current,
        (PinStatus::Approved(_) | PinStatus::Retired(_), PinStatus::Pending)
        | (PinStatus::Retired(_), PinStatus::Approved(_)) => false,
    };
    let envelope_is_monotonic = match (
        previous.council_envelope_digest,
        current.council_envelope_digest,
    ) {
        (Some(previous), Some(current)) => previous == current,
        (Some(_), None) => false,
        (None, Some(_)) => !matches!(current.status, PinStatus::Pending),
        (None, None) => true,
    };
    let approval_is_monotonic = match (previous.approved_epoch, current.approved_epoch) {
        (Some(previous), Some(current)) => previous == current,
        (Some(_), None) => false,
        (None, Some(next_approval)) => {
            matches!(previous.status, PinStatus::Pending)
                && (matches!(
                    current.status,
                    PinStatus::Approved(status_epoch) if status_epoch == next_approval
                ) || matches!(
                    current.status,
                    PinStatus::Retired(retired_epoch) if next_approval <= retired_epoch
                ))
        }
        (None, None) => true,
    };
    let retirement_is_monotonic = match (previous.status, current.status) {
        (PinStatus::Retired(_), PinStatus::Retired(_)) => {
            previous.retirement_reason == current.retirement_reason
        }
        (_, PinStatus::Retired(_)) => true,
        (_, PinStatus::Pending | PinStatus::Approved(_)) => current.retirement_reason.is_none(),
    };
    if !status_is_monotonic
        || !approval_is_monotonic
        || !envelope_is_monotonic
        || !retirement_is_monotonic
        || previous.pin_fee_payment != current.pin_fee_payment
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution { order_id });
    }
    Ok(())
}
fn build_provider_deltas(
    previous: Option<&ProviderIngestFinalizedProjectionV1>,
    current: &ProviderIngestFinalizedProjectionV1,
) -> Vec<ProviderProjectionDeltaV1> {
    let previous = previous
        .map(|projection| {
            projection
                .providers
                .iter()
                .map(|provider| (provider.provider_id, provider))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let current_by_provider = current
        .providers
        .iter()
        .map(|provider| (provider.provider_id, provider))
        .collect::<BTreeMap<_, _>>();
    let provider_ids = previous
        .keys()
        .chain(current_by_provider.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    provider_ids
        .into_iter()
        .filter_map(|provider_id| {
            let before = previous.get(&provider_id).copied();
            let after = current_by_provider.get(&provider_id).copied();
            (before != after).then(|| ProviderProjectionDeltaV1 {
                provider_id,
                next: after.cloned(),
            })
        })
        .collect()
}
fn apply_provider_deltas(
    providers: &mut BTreeMap<ProviderId, ProviderIngestFinalizedProviderProjectionV1>,
    deltas: &[ProviderProjectionDeltaV1],
) {
    for delta in deltas {
        if let Some(next) = &delta.next {
            providers.insert(delta.provider_id, next.clone());
        } else {
            providers.remove(&delta.provider_id);
        }
    }
}
fn first_record_for_network<'index>(
    index: &'index ArchiveIndexV1,
    network_id: &NetworkId,
) -> Option<&'index ArchiveRecordEntryV1> {
    index
        .by_height
        .range((
            std::ops::Bound::Included((*network_id, 0)),
            std::ops::Bound::Included((*network_id, u64::MAX)),
        ))
        .next()
        .map(|(_, entry)| entry)
}
fn below_floor_error(
    index: &ArchiveIndexV1,
    network_id: &NetworkId,
    requested_height: u64,
    floor_height: u64,
) -> ProviderIngestFinalizedArchiveErrorV1 {
    if index.virtual_bases.contains_key(network_id) {
        ProviderIngestFinalizedArchiveErrorV1::BelowRetentionFloor {
            requested_height,
            retention_height: floor_height,
        }
    } else {
        ProviderIngestFinalizedArchiveErrorV1::BelowActivationFloor {
            requested_height,
            activation_height: floor_height,
        }
    }
}
fn retained_archive_entries(index: &ArchiveIndexV1) -> usize {
    index
        .by_height
        .len()
        .saturating_add(index.virtual_bases.len())
}
fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}
fn policy_history_to_checkpoint(
    history: &BTreeMap<ProviderId, ProviderPolicyHistoryV1>,
) -> Vec<ProviderPolicyHistoryCheckpointV1> {
    history
        .iter()
        .map(
            |(provider_id, observed)| ProviderPolicyHistoryCheckpointV1 {
                provider_id: *provider_id,
                last: observed.last.clone(),
                active: observed.active,
                seen_policy_digests: observed
                    .seen_policy_digests
                    .iter()
                    .map(
                        |(policy_id, policy_digests)| ProviderPolicyDigestHistoryCheckpointV1 {
                            policy_id: *policy_id,
                            policy_digests: policy_digests.iter().copied().collect(),
                        },
                    )
                    .collect(),
            },
        )
        .collect()
}
fn policy_history_from_checkpoint(
    checkpoint: &[ProviderPolicyHistoryCheckpointV1],
) -> Result<BTreeMap<ProviderId, ProviderPolicyHistoryV1>, ProviderIngestFinalizedArchiveErrorV1> {
    let mut history = BTreeMap::new();
    for provider in checkpoint {
        let mut seen_policy_digests: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>> = BTreeMap::new();
        let mut previous_policy_id = None;
        for policy in &provider.seen_policy_digests {
            if policy.policy_id == [0; 32]
                || previous_policy_id.is_some_and(|previous| previous >= policy.policy_id)
                || policy.policy_digests.is_empty()
                || !strictly_ordered(&policy.policy_digests)
                || policy
                    .policy_digests
                    .iter()
                    .any(|digest| *digest == [0; 32])
                || seen_policy_digests
                    .insert(
                        policy.policy_id,
                        policy.policy_digests.iter().copied().collect(),
                    )
                    .is_some()
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                    reason: "checkpoint policy-digest history is noncanonical",
                });
            }
            previous_policy_id = Some(policy.policy_id);
        }
        if provider.provider_id.as_bytes() == &[0; 32]
            || !provider.last.is_valid()
            || !seen_policy_digests
                .get(&provider.last.signer_policy.policy_id)
                .is_some_and(|digests| digests.contains(&provider.last.signer_policy.policy_digest))
            || history
                .insert(
                    provider.provider_id,
                    ProviderPolicyHistoryV1 {
                        last: provider.last.clone(),
                        active: provider.active,
                        seen_policy_digests,
                    },
                )
                .is_some()
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint provider-policy history is noncanonical",
            });
        }
    }
    Ok(history)
}
fn validate_policy_history_checkpoint(
    projection: &ProviderIngestFinalizedProjectionV1,
    checkpoint: &[ProviderPolicyHistoryCheckpointV1],
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if checkpoint
        .windows(2)
        .any(|window| window[0].provider_id >= window[1].provider_id)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "checkpoint provider-policy history is not strictly ordered",
        });
    }
    let history = policy_history_from_checkpoint(checkpoint)?;
    let projected = projection
        .providers
        .iter()
        .map(|provider| (provider.provider_id, provider.expected_authority.as_ref()))
        .collect::<BTreeMap<_, _>>();
    for (provider_id, observed) in &history {
        if projected.get(provider_id).copied().flatten()
            != observed.active.then_some(&observed.last)
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint active policy differs from retained provider projection",
            });
        }
    }
    if projected
        .iter()
        .any(|(provider_id, policy)| policy.is_some_and(|_| !history.contains_key(provider_id)))
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "retained provider policy is absent from checkpoint history",
        });
    }
    Ok(())
}
fn policy_history_seed_from_virtual_base(
    index: &ArchiveIndexV1,
    network_id: &NetworkId,
) -> Result<ProviderPolicyHistorySeedV1, ProviderIngestFinalizedArchiveErrorV1> {
    let Some(base) = index.virtual_bases.get(network_id) else {
        return Ok(ProviderPolicyHistorySeedV1 {
            providers: BTreeMap::new(),
            history: BTreeMap::new(),
            seeded: false,
        });
    };
    Ok(ProviderPolicyHistorySeedV1 {
        providers: base
            .checkpoint
            .material
            .projection
            .providers
            .iter()
            .map(|provider| (provider.provider_id, provider.clone()))
            .collect(),
        history: policy_history_from_checkpoint(&base.checkpoint.material.policy_history)?,
        seeded: true,
    })
}
fn order_history_seed_from_virtual_base(
    index: &ArchiveIndexV1,
    network_id: &NetworkId,
) -> ProviderOrderHistorySeedV1 {
    let Some(base) = index.virtual_bases.get(network_id) else {
        return ProviderOrderHistorySeedV1 {
            providers: BTreeMap::new(),
            active: BTreeSet::new(),
            seen: BTreeSet::new(),
            seeded: false,
        };
    };
    ProviderOrderHistorySeedV1 {
        providers: base
            .checkpoint
            .material
            .projection
            .providers
            .iter()
            .map(|provider| (provider.provider_id, provider.clone()))
            .collect(),
        active: base
            .checkpoint
            .material
            .active_order_ids
            .iter()
            .copied()
            .collect(),
        seen: base
            .checkpoint
            .material
            .seen_order_ids
            .iter()
            .copied()
            .collect(),
        seeded: true,
    }
}
fn compaction_proposal(
    prepared: &PreparedArchiveCompactionV1,
    fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
) -> Result<ProviderIngestFinalizedArchiveCompactionProposalV1, ProviderIngestFinalizedArchiveErrorV1>
{
    ProviderIngestFinalizedArchiveCompactionProposalV1::try_new(
        fence.clone(),
        prepared.checkpoint.checkpoint_digest,
        canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &prepared.canonical_bytes,
        ),
    )
}
fn validate_approval_checkpoint(
    approval: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
    checkpoint: &ProviderIngestFinalizedArchiveCheckpointV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let fence = approval.proposal().fence();
    let canonical_bytes = encode_bounded_checkpoint(checkpoint, bounds)?;
    if checkpoint.material.retention_floor != fence.key
        || checkpoint.material.certified_block_id != fence.certified_block_id
        || checkpoint.material.total_generation != fence.expected_archive_generation
        || checkpoint.material.prior_checkpoint_digest != approval.predecessor_checkpoint_digest()
        || checkpoint.checkpoint_digest != approval.proposal().checkpoint_digest()
        || canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &canonical_bytes,
        ) != approval.proposal().checkpoint_canonical_digest()
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionProposalMismatch);
    }
    Ok(())
}
fn validate_retention_checkpoint_candidate_inventory(
    candidates: &[ArchiveVirtualBaseV1],
    approval: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
    network_id: &NetworkId,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let approved = approval.proposal().checkpoint_digest();
    let predecessor = approval.predecessor_checkpoint_digest();
    if predecessor == Some(approved) {
        return Err(ProviderIngestFinalizedArchiveErrorV1::UnapprovedRetentionCheckpoint);
    }
    let mut observed = BTreeSet::new();
    for candidate in candidates {
        if &candidate.checkpoint.material.retention_floor.network_id != network_id
            || !observed.insert(candidate.checkpoint.checkpoint_digest)
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::UnapprovedRetentionCheckpoint);
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
                ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRollback
            } else {
                ProviderIngestFinalizedArchiveErrorV1::UnapprovedRetentionCheckpoint
            },
        );
    }
    Ok(())
}
fn validate_approval_for_prepared(
    approval: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
    binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    prepared: &PreparedArchiveCompactionV1,
    proposal: &ProviderIngestFinalizedArchiveCompactionProposalV1,
    predecessor_checkpoint_digest: Option<[u8; 32]>,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    validate_retention_approval_record(approval, binding, &proposal.fence().key.network_id)?;
    if approval.proposal() != proposal
        || approval.predecessor_checkpoint_digest() != predecessor_checkpoint_digest
        || prepared.checkpoint.material.prior_checkpoint_digest != predecessor_checkpoint_digest
        || prepared.checkpoint.checkpoint_digest != proposal.checkpoint_digest()
        || canonical_bytes_domain_digest(
            RETENTION_CHECKPOINT_BYTES_DIGEST_DOMAIN_V1,
            &prepared.canonical_bytes,
        ) != proposal.checkpoint_canonical_digest()
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionProposalMismatch);
    }
    Ok(())
}
fn validate_retention_approval_record(
    approval: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
    binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    network_id: &NetworkId,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    approval.validate()?;
    if approval.authority_qualification() != binding.qualification()
        || &approval.proposal().fence().key.network_id != network_id
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthoritySubstitution);
    }
    let canonical = approval.to_canonical_bytes()?;
    if ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::from_canonical_bytes(&canonical)?
        != *approval
    {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionApproval {
                reason: "authority returned a noncanonical approval record",
            },
        );
    }
    Ok(())
}
fn validate_retention_authority_predecessor(
    current: Option<&ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>,
    expected_checkpoint: Option<[u8; 32]>,
    next_fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if current.map(|record| record.proposal().checkpoint_digest()) != expected_checkpoint
        || current
            .is_some_and(|record| record.proposal().fence().key.height >= next_fence.key.height)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRollback);
    }
    Ok(())
}
fn retention_authority_external_error(
    error: ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
) -> ProviderIngestFinalizedArchiveErrorV1 {
    match error {
        ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable => {
            ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityUnavailable
        }
        ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected => {
            ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRejected
        }
        ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous => {
            ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityCasAmbiguous
        }
    }
}
fn assert_retention_authority_identity(
    binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    binding.qualification.validate()?;
    let handle_before = authority.handle();
    if !iroha_config::parameters::is_production_runtime_handle(handle_before)
        || handle_before != binding.handle()
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthoritySubstitution);
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
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthoritySubstitution);
    }
    Ok(())
}
fn load_retention_approval(
    binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
    network_id: &NetworkId,
) -> Result<
    Option<ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>,
    ProviderIngestFinalizedArchiveErrorV1,
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
    binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
    network_id: &NetworkId,
    expected: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    match load_retention_approval(binding, authority, network_id) {
        Ok(Some(observed)) if observed == *expected => Ok(()),
        Ok(_) => Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityEquivocation),
        Err(_) => Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityCasAmbiguous),
    }
}
fn compare_and_read_back_retention_approval(
    binding: &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    authority: &dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1,
    network_id: &NetworkId,
    expected: Option<&ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>,
    next: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    validate_retention_approval_record(next, binding, network_id)?;
    if load_retention_approval(binding, authority, network_id)?.as_ref() != expected {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityEquivocation);
    }
    let compare_result = authority.compare_and_swap_latest(
        network_id,
        expected.map(ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::revision),
        next,
    );
    if assert_retention_authority_identity(binding, authority).is_err() {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityCasAmbiguous);
    }
    let readback = match load_retention_approval(binding, authority, network_id) {
        Ok(readback) => readback,
        Err(_) => {
            return Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityCasAmbiguous);
        }
    };
    if readback.as_ref() == Some(next) {
        return Ok(());
    }
    if readback.as_ref() == expected {
        return Err(match compare_result {
            Err(ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected) => {
                ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRejected
            }
            Err(
                ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Unavailable
                | ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous,
            ) => ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityCasAmbiguous,
            Ok(()) => ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityCasUnchanged,
        });
    }
    Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityEquivocation)
}
fn authenticate_retention_fence(
    fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
    state_ro: &impl StateReadOnly,
    kura: &Kura,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let certified =
        CertifiedArchiveView::new(state_ro, kura).map_err(certified_authentication_error)?;
    authenticate_retention_identity(fence, state_ro.network_id(), &certified)?;
    certified
        .verify_unchanged()
        .map_err(certified_authentication_error)
}
fn authenticate_retention_identity<V: StateReadOnly + ?Sized>(
    fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
    network_id: &NetworkId,
    certified: &CertifiedArchiveView<'_, V>,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    fence.key.validate()?;
    let block = authenticate_archive_anchor(&fence.key, network_id, certified)?;
    if fence.certified_block_id == [0; 32] || *block.id().0.as_ref() != fence.certified_block_id {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionFence {
                reason: "retention fence substituted the certified block identity",
            },
        );
    }
    Ok(())
}
fn authenticate_retention_prefix(
    index: &ArchiveIndexV1,
    fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
    state_ro: &impl StateReadOnly,
    kura: &Kura,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if fence.expected_archive_generation != index.generation {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::RetentionFenceGenerationMismatch {
                expected: fence.expected_archive_generation,
                observed: index.generation,
            },
        );
    }
    let certified =
        CertifiedArchiveView::new(state_ro, kura).map_err(certified_authentication_error)?;
    if let Some(base) = index.virtual_bases.get(&fence.key.network_id) {
        let block = authenticate_archive_anchor(
            &base.checkpoint.material.retention_floor,
            state_ro.network_id(),
            &certified,
        )?;
        if *block.id().0.as_ref() != base.checkpoint.material.certified_block_id {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionFence {
                    reason: "existing retention base substituted the certified block identity",
                },
            );
        }
    }
    for (_, entry) in index.by_height.range((
        std::ops::Bound::Included((fence.key.network_id, 0)),
        std::ops::Bound::Included((fence.key.network_id, fence.key.height)),
    )) {
        verify_record_entry(entry, bounds)?;
        authenticate_archive_anchor(
            &entry.record.material.key,
            state_ro.network_id(),
            &certified,
        )?;
    }
    authenticate_retention_identity(fence, state_ro.network_id(), &certified)?;
    certified
        .verify_unchanged()
        .map_err(certified_authentication_error)
}
fn prepare_archive_compaction(
    index: &ArchiveIndexV1,
    fence: &ProviderIngestFinalizedArchiveRetentionFenceV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<PreparedArchiveCompactionV1, ProviderIngestFinalizedArchiveErrorV1> {
    let network_id = &fence.key.network_id;
    let previous_base = index.virtual_bases.get(network_id).cloned();
    if previous_base
        .as_ref()
        .is_some_and(|base| fence.key.height <= base.checkpoint.material.retention_floor.height)
    {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::InvalidRetentionFence {
                reason: "retention fence must advance the installed virtual base",
            },
        );
    }
    let terminal = index
        .by_height
        .get(&(*network_id, fence.key.height))
        .ok_or_else(
            || ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor {
                network_id: *network_id,
                height: fence.key.height,
            },
        )?;
    if terminal.record.material.key != fence.key {
        return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
            network_id: *network_id,
            height: fence.key.height,
        });
    }
    let projection = reconstruct_projection(index, &fence.key, bounds)?;
    let provider_state_root = provider_state_root(&projection.providers)?;
    if provider_state_root != terminal.record.material.provider_state_root {
        return Err(ProviderIngestFinalizedArchiveErrorV1::ProviderStateRootMismatch);
    }
    let history = checkpoint_history_through(index, network_id, fence.key.height, bounds)?;
    let mut obsolete = Vec::new();
    for (subject, entry) in index.by_height.range((
        std::ops::Bound::Included((*network_id, 0)),
        std::ops::Bound::Included((*network_id, fence.key.height)),
    )) {
        obsolete.try_reserve(1).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
                resource: "retention prefix inventory",
            }
        })?;
        obsolete.push((subject.to_owned(), entry.clone()));
    }
    let (pruned_entries, pruned_bytes) =
        cumulative_pruned_accounting(previous_base.as_ref(), &obsolete)?;
    let original_activation_floor = previous_base.as_ref().map_or_else(
        || {
            first_record_for_network(index, network_id)
                .map(|entry| entry.record.material.key.clone())
                .ok_or(ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                    reason: "retention network has no activation floor",
                })
        },
        |base| Ok(base.checkpoint.material.original_activation_floor.clone()),
    )?;
    let checkpoint = ProviderIngestFinalizedArchiveCheckpointV1::try_new(
        ProviderIngestFinalizedArchiveCheckpointMaterialV1 {
            version: ARCHIVE_VERSION_V1,
            original_activation_floor,
            retention_floor: fence.key.clone(),
            original_terminal_record_digest: terminal.record.record_digest,
            cumulative_prefix_digest: history.cumulative_prefix_digest,
            prior_checkpoint_digest: previous_base
                .as_ref()
                .map(|base| base.checkpoint.checkpoint_digest),
            total_generation: index.generation,
            pruned_entries,
            pruned_bytes,
            projection,
            provider_state_root,
            policy_history: policy_history_to_checkpoint(&history.policy_history),
            active_order_ids: history.active_order_ids.iter().copied().collect(),
            seen_order_ids: history.seen_order_ids.iter().copied().collect(),
            certified_block_id: fence.certified_block_id,
        },
        bounds,
    )?;
    let canonical_bytes = encode_bounded_checkpoint(&checkpoint, bounds)?;
    Ok(PreparedArchiveCompactionV1 {
        checkpoint,
        canonical_bytes,
        obsolete,
        previous_base,
    })
}
fn cumulative_pruned_accounting(
    previous_base: Option<&ArchiveVirtualBaseV1>,
    obsolete: &[((NetworkId, u64), ArchiveRecordEntryV1)],
) -> Result<(u64, u64), ProviderIngestFinalizedArchiveErrorV1> {
    let newly_pruned_entries = u64::try_from(obsolete.len()).map_err(|_| {
        ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "retention prefix entry count is unrepresentable",
        }
    })?;
    let newly_pruned_bytes = obsolete
        .iter()
        .map(|(_, entry)| entry.canonical_bytes)
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes))
        .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "retention prefix byte count overflowed",
        })?;
    let prior_entries = previous_base.map_or(0, |base| base.checkpoint.material.pruned_entries);
    let prior_bytes = previous_base.map_or(0, |base| base.checkpoint.material.pruned_bytes);
    let pruned_entries = prior_entries.checked_add(newly_pruned_entries).ok_or(
        ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "cumulative retention entry count overflowed",
        },
    )?;
    let pruned_bytes = prior_bytes.checked_add(newly_pruned_bytes).ok_or(
        ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "cumulative retention byte count overflowed",
        },
    )?;
    Ok((pruned_entries, pruned_bytes))
}
fn validate_prepared_compaction_capacity(
    index: &ArchiveIndexV1,
    prepared: &PreparedArchiveCompactionV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let retained_after = retained_archive_entries(index)
        .saturating_sub(prepared.obsolete.len())
        .saturating_add(usize::from(prepared.previous_base.is_none()));
    if retained_after > bounds.max_archive_entries() {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: retained_after,
                maximum: bounds.max_archive_entries(),
            },
        );
    }
    let newly_pruned_bytes = prepared
        .obsolete
        .iter()
        .map(|(_, entry)| entry.canonical_bytes)
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes))
        .ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: u64::MAX,
                maximum: bounds.max_total_bytes(),
            },
        )?;
    let old_checkpoint_bytes = prepared
        .previous_base
        .as_ref()
        .map_or(0, |base| base.canonical_bytes);
    let retained_bytes = index
        .total_bytes
        .checked_sub(newly_pruned_bytes)
        .and_then(|bytes| bytes.checked_sub(old_checkpoint_bytes))
        .and_then(|bytes| bytes.checked_add(bounded_bytes_len(&prepared.canonical_bytes)))
        .ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: u64::MAX,
                maximum: bounds.max_total_bytes(),
            },
        )?;
    if retained_bytes > bounds.max_total_bytes() {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: retained_bytes,
                maximum: bounds.max_total_bytes(),
            },
        );
    }
    Ok(())
}
fn checkpoint_history_through(
    index: &ArchiveIndexV1,
    network_id: &NetworkId,
    retention_height: u64,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<ArchiveCompactionHistoryV1, ProviderIngestFinalizedArchiveErrorV1> {
    let base = index.virtual_bases.get(network_id);
    let mut providers = base.map_or_else(BTreeMap::new, |base| {
        base.checkpoint
            .material
            .projection
            .providers
            .iter()
            .map(|provider| (provider.provider_id, provider.clone()))
            .collect()
    });
    let mut policy_history = base
        .map(|base| policy_history_from_checkpoint(&base.checkpoint.material.policy_history))
        .transpose()?
        .unwrap_or_default();
    let mut active_orders = base.map_or_else(BTreeSet::new, |base| {
        base.checkpoint
            .material
            .active_order_ids
            .iter()
            .copied()
            .collect()
    });
    let mut seen_orders = base.map_or_else(BTreeSet::new, |base| {
        base.checkpoint
            .material
            .seen_order_ids
            .iter()
            .copied()
            .collect()
    });
    let mut history_seeded = base.is_some();
    let mut cumulative = base.map(|base| base.checkpoint.material.cumulative_prefix_digest);
    let start_height = base.map_or(0, |base| {
        base.checkpoint
            .material
            .retention_floor
            .height
            .saturating_add(1)
    });
    let mut observed_retention = base
        .is_some_and(|base| base.checkpoint.material.retention_floor.height == retention_height);
    for (_, entry) in index.by_height.range((
        std::ops::Bound::Included((*network_id, start_height)),
        std::ops::Bound::Included((*network_id, retention_height)),
    )) {
        verify_record_entry(entry, bounds)?;
        apply_provider_deltas(&mut providers, &entry.record.material.deltas);
        if history_seeded {
            observe_policy_history(&providers, &mut policy_history)?;
            observe_order_history(
                provider_order_ids(providers.values()),
                &mut active_orders,
                &mut seen_orders,
            )?;
        } else {
            seed_policy_history(&providers, &mut policy_history);
            active_orders = provider_order_ids(providers.values());
            seen_orders = active_orders.clone();
            history_seeded = true;
        }
        cumulative = Some(canonical_domain_digest(
            PREFIX_DIGEST_DOMAIN_V1,
            &ProviderIngestFinalizedPrefixLinkV1 {
                previous_cumulative_digest: cumulative,
                key: entry.record.material.key.clone(),
                record_digest: entry.record.record_digest,
            },
        )?);
        observed_retention = entry.record.material.key.height == retention_height;
    }
    if !observed_retention {
        return Err(ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor {
            network_id: *network_id,
            height: retention_height,
        });
    }
    let cumulative =
        cumulative.ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "retention prefix has no cumulative digest",
        })?;
    Ok(ArchiveCompactionHistoryV1 {
        policy_history,
        active_order_ids: active_orders,
        seen_order_ids: seen_orders,
        cumulative_prefix_digest: cumulative,
    })
}
fn reconstruct_provider_projection(
    index: &ArchiveIndexV1,
    key: &ProviderIngestFinalizedArchiveKeyV1,
    provider_id: ProviderId,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<
    Option<ProviderIngestFinalizedProviderProjectionV1>,
    ProviderIngestFinalizedArchiveErrorV1,
> {
    let floor = activation_floor_from_index(index, &key.network_id)?.ok_or(
        ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
            reason: "requested network has no archived anchors",
        },
    )?;
    if key.height < floor.height {
        return Err(below_floor_error(
            index,
            &key.network_id,
            key.height,
            floor.height,
        ));
    }
    let base = index.virtual_bases.get(&key.network_id);
    let mut provider = base.and_then(|base| {
        base.checkpoint
            .material
            .projection
            .providers
            .binary_search_by_key(&provider_id, |provider| provider.provider_id)
            .ok()
            .map(|position| base.checkpoint.material.projection.providers[position].clone())
    });
    let mut found = base.is_some_and(|base| base.checkpoint.material.retention_floor == *key);
    for (_, entry) in index.by_height.range((
        std::ops::Bound::Included((key.network_id, floor.height)),
        std::ops::Bound::Included((key.network_id, key.height)),
    )) {
        verify_record_entry(entry, bounds)?;
        if let Ok(delta_index) = entry
            .record
            .material
            .deltas
            .binary_search_by_key(&provider_id, |delta| delta.provider_id)
        {
            provider = entry.record.material.deltas[delta_index].next.clone();
        }
        if entry.record.material.key.height == key.height {
            if &entry.record.material.key != key {
                return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                    network_id: key.network_id,
                    height: key.height,
                });
            }
            found = true;
        }
    }
    if !found {
        return Err(ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor {
            network_id: key.network_id,
            height: key.height,
        });
    }
    if provider
        .as_ref()
        .is_some_and(|projection| projection.provider_id != provider_id)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
            reason: "provider-indexed delta resolved to another provider",
        });
    }
    Ok(provider)
}
fn reconstruct_projection(
    index: &ArchiveIndexV1,
    key: &ProviderIngestFinalizedArchiveKeyV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<ProviderIngestFinalizedProjectionV1, ProviderIngestFinalizedArchiveErrorV1> {
    let floor = activation_floor_from_index(index, &key.network_id)?.ok_or(
        ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
            reason: "requested network has no archived anchors",
        },
    )?;
    if key.height < floor.height {
        return Err(below_floor_error(
            index,
            &key.network_id,
            key.height,
            floor.height,
        ));
    }
    let base = index.virtual_bases.get(&key.network_id);
    let mut providers = base.map_or_else(BTreeMap::new, |base| {
        base.checkpoint
            .material
            .projection
            .providers
            .iter()
            .map(|provider| (provider.provider_id, provider.clone()))
            .collect()
    });
    let mut found = base.is_some_and(|base| base.checkpoint.material.retention_floor == *key);
    for (_, entry) in index.by_height.range((
        std::ops::Bound::Included((key.network_id, floor.height)),
        std::ops::Bound::Included((key.network_id, key.height)),
    )) {
        verify_record_entry(entry, bounds)?;
        apply_provider_deltas(&mut providers, &entry.record.material.deltas);
        let projected = providers.values().cloned().collect::<Vec<_>>();
        if provider_state_root(&projected)? != entry.record.material.provider_state_root {
            return Err(ProviderIngestFinalizedArchiveErrorV1::ProviderStateRootMismatch);
        }
        if entry.record.material.key.height == key.height {
            if &entry.record.material.key != key {
                return Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                    network_id: key.network_id,
                    height: key.height,
                });
            }
            found = true;
        }
    }
    if !found {
        return Err(ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor {
            network_id: key.network_id,
            height: key.height,
        });
    }
    let projection = ProviderIngestFinalizedProjectionV1 {
        key: key.clone(),
        providers: providers.into_values().collect(),
    };
    projection.validate(bounds)?;
    Ok(projection)
}
fn verify_record_entry(
    entry: &ArchiveRecordEntryV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let metadata =
        direct_archive_file_metadata(&entry.path, bounds.max_record_bytes()).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: entry.path.clone(),
                source,
            }
        })?;
    if metadata.len() != entry.canonical_bytes {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: entry.path.clone(),
            reason: "immutable record length changed after archive qualification",
        });
    }
    let loaded = load_record_at(&entry.path, bounds, Some(&entry.record.material.key))?;
    if loaded != entry.record {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: entry.path.clone(),
            reason: "immutable record content changed after archive qualification",
        });
    }
    Ok(())
}
fn validate_index_coverage(
    index: &ArchiveIndexV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    validate_index_coverage_with_successor(index, bounds, None, index.total_bytes)
}
fn validate_index_coverage_with_successor(
    index: &ArchiveIndexV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
    successor: Option<&ArchiveRecordEntryV1>,
    total_bytes: u64,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let retained_entries =
        retained_archive_entries(index).saturating_add(usize::from(successor.is_some()));
    if retained_entries > bounds.max_archive_entries() {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: retained_entries,
                maximum: bounds.max_archive_entries(),
            },
        );
    }
    if total_bytes > bounds.max_total_bytes() {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: total_bytes,
                maximum: bounds.max_total_bytes(),
            },
        );
    }
    let network_ids = index
        .by_height
        .keys()
        .map(|(network_id, _)| *network_id)
        .chain(index.virtual_bases.keys().cloned())
        .chain(successor.map(|entry| entry.record.material.key.network_id))
        .collect::<BTreeSet<_>>();
    for network_id in network_ids {
        let virtual_base = index.virtual_bases.get(&network_id);
        if let Some(base) = virtual_base {
            verify_checkpoint_entry(base, bounds)?;
        }
        let mut previous_key =
            virtual_base.map(|base| base.checkpoint.material.retention_floor.clone());
        let mut previous_digest =
            virtual_base.map(|base| base.checkpoint.material.original_terminal_record_digest);
        let mut providers = virtual_base.map_or_else(BTreeMap::new, |base| {
            base.checkpoint
                .material
                .projection
                .providers
                .iter()
                .map(|provider| (provider.provider_id, provider.clone()))
                .collect()
        });
        let mut policy_history = virtual_base
            .map(|base| policy_history_from_checkpoint(&base.checkpoint.material.policy_history))
            .transpose()?
            .unwrap_or_default();
        let mut active_orders = virtual_base.map_or_else(BTreeSet::new, |base| {
            base.checkpoint
                .material
                .active_order_ids
                .iter()
                .copied()
                .collect()
        });
        let mut seen_orders = virtual_base.map_or_else(BTreeSet::new, |base| {
            base.checkpoint
                .material
                .seen_order_ids
                .iter()
                .copied()
                .collect()
        });
        let entries = index.by_height.range((
            std::ops::Bound::Included((network_id, 0)),
            std::ops::Bound::Included((network_id, u64::MAX)),
        ));
        let entries = entries
            .map(|(_, entry)| entry)
            .chain(successor.filter(|entry| entry.record.material.key.network_id == network_id));
        for entry in entries {
            entry.record.validate()?;
            match previous_key.as_ref() {
                None if entry.record.material.predecessor.is_some() => {
                    return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
                        reason: "activation-floor record has a predecessor",
                    });
                }
                Some(previous) => {
                    let expected_height = previous.height.checked_add(1).ok_or(
                        ProviderIngestFinalizedArchiveErrorV1::ArchiveCoverageGap {
                            network_id,
                            missing_height: u64::MAX,
                            observed_height: entry.record.material.key.height,
                        },
                    )?;
                    if entry.record.material.key.height != expected_height {
                        return Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveCoverageGap {
                            network_id,
                            missing_height: expected_height,
                            observed_height: entry.record.material.key.height,
                        });
                    }
                    let expected = ProviderIngestFinalizedArchivePredecessorV1 {
                        key: previous.clone(),
                        record_digest: previous_digest.ok_or(
                            ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                                reason: "virtual predecessor digest is absent",
                            },
                        )?,
                    };
                    if entry.record.material.predecessor.as_ref() != Some(&expected) {
                        return Err(
                            ProviderIngestFinalizedArchiveErrorV1::PredecessorSubstitution {
                                network_id,
                                height: entry.record.material.key.height,
                            },
                        );
                    }
                }
                None => {}
            }
            let before = ProviderIngestFinalizedProjectionV1 {
                key: previous_key
                    .clone()
                    .unwrap_or_else(|| entry.record.material.key.clone()),
                providers: providers.values().cloned().collect(),
            };
            validate_delta_minimality(&providers, &entry.record.material.deltas)?;
            apply_provider_deltas(&mut providers, &entry.record.material.deltas);
            let current = ProviderIngestFinalizedProjectionV1 {
                key: entry.record.material.key.clone(),
                providers: providers.values().cloned().collect(),
            };
            current.validate(bounds)?;
            if provider_state_root(&current.providers)? != entry.record.material.provider_state_root
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::ProviderStateRootMismatch);
            }
            if previous_key.is_some() {
                validate_projection_transition(&before, &current)?;
                observe_policy_history(&providers, &mut policy_history)?;
                observe_order_history(
                    provider_order_ids(providers.values()),
                    &mut active_orders,
                    &mut seen_orders,
                )?;
            } else {
                seed_policy_history(&providers, &mut policy_history);
                active_orders = provider_order_ids(providers.values());
                seen_orders = active_orders.clone();
            }
            if successor.is_some_and(|candidate| std::ptr::eq(candidate, entry)) {
                validate_projection_completion_anchors_before_insert(index, &current)?;
            } else {
                validate_completion_anchors(index, &current)?;
            }
            previous_key = Some(entry.record.material.key.clone());
            previous_digest = Some(entry.record.record_digest);
        }
    }
    Ok(())
}
fn validate_delta_minimality(
    providers: &BTreeMap<ProviderId, ProviderIngestFinalizedProviderProjectionV1>,
    deltas: &[ProviderProjectionDeltaV1],
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    for delta in deltas {
        match (providers.get(&delta.provider_id), delta.next.as_ref()) {
            (Some(before), Some(after)) if before == after => {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
                    reason: "provider delta repeats unchanged state",
                });
            }
            (None, None) => {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidRecord {
                    reason: "provider delta removes absent state",
                });
            }
            _ => {}
        }
    }
    Ok(())
}
fn validate_completion_anchors(
    index: &ArchiveIndexV1,
    projection: &ProviderIngestFinalizedProjectionV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let floor = activation_floor_from_index(index, &projection.key.network_id)?.ok_or(
        ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
            reason: "no exact activation floor exists for the projection network",
        },
    )?;
    for provider in &projection.providers {
        for order in &provider.orders {
            for completion in &order.replication_order.provider_completions {
                if completion.finalized_anchor.height < floor.height {
                    continue;
                }
                if completion.finalized_anchor.height == floor.height
                    && index
                        .virtual_bases
                        .get(&projection.key.network_id)
                        .is_some_and(|base| {
                            base.checkpoint.material.retention_floor.block_hash
                                == completion.finalized_anchor.block_hash
                        })
                {
                    continue;
                }
                let Some(anchor) = index.by_height.get(&(
                    projection.key.network_id,
                    completion.finalized_anchor.height,
                )) else {
                    return Err(
                        ProviderIngestFinalizedArchiveErrorV1::CompletionAnchorMismatch {
                            order_id: order.order_id(),
                        },
                    );
                };
                if anchor.record.material.key.block_hash != completion.finalized_anchor.block_hash {
                    return Err(
                        ProviderIngestFinalizedArchiveErrorV1::CompletionAnchorMismatch {
                            order_id: order.order_id(),
                        },
                    );
                }
            }
        }
    }
    Ok(())
}
fn activation_floor_from_index(
    index: &ArchiveIndexV1,
    network_id: &NetworkId,
) -> Result<Option<ProviderIngestFinalizedArchiveKeyV1>, ProviderIngestFinalizedArchiveErrorV1> {
    if network_id.as_bytes()[31] & 1 != 1 {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidKey {
            reason: "network id must be an exact genesis-derived identity",
        });
    }
    if let Some(base) = index.virtual_bases.get(network_id) {
        return Ok(Some(base.checkpoint.material.retention_floor.clone()));
    }
    Ok(first_record_for_network(index, network_id).map(|entry| entry.record.material.key.clone()))
}
fn provider_state_root(
    providers: &[ProviderIngestFinalizedProviderProjectionV1],
) -> Result<[u8; 32], ProviderIngestFinalizedArchiveErrorV1> {
    canonical_domain_digest(STATE_ROOT_DOMAIN_V1, &providers.to_vec())
}
fn canonical_domain_digest<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], ProviderIngestFinalizedArchiveErrorV1> {
    let bytes = norito::to_bytes(value).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn authenticate_archive_anchor<V: StateReadOnly + ?Sized>(
    key: &ProviderIngestFinalizedArchiveKeyV1,
    network_id: &NetworkId,
    certified: &CertifiedArchiveView<'_, V>,
) -> Result<crate::sumeragi::certified_chain::CertifiedBlock, ProviderIngestFinalizedArchiveErrorV1>
{
    if &key.network_id != network_id {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                reason: "archive anchor belongs to another State network",
            },
        );
    }
    let block = certified
        .block(key.height)
        .map_err(certified_authentication_error)?;
    if *block.block_hash().as_ref() != key.block_hash
        || block.block_time_ms() != key.finalized_at_unix_ms
    {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveKuraAnchorMismatch {
                network_id: key.network_id,
                height: key.height,
                reason: "archive identity or timestamp differs from the certified block",
            },
        );
    }
    Ok(block)
}
fn authenticate_capture_view(
    state_ro: &impl StateReadOnly,
    kura: &Kura,
) -> Result<ProviderIngestFinalizedArchiveKeyV1, ProviderIngestFinalizedArchiveErrorV1> {
    let key = committed_capture_key(state_ro, kura)?;
    let certified =
        CertifiedArchiveView::new(state_ro, kura).map_err(certified_authentication_error)?;
    authenticate_archive_anchor(&key, state_ro.network_id(), &certified)?;
    certified
        .verify_unchanged()
        .map_err(certified_authentication_error)?;
    Ok(key)
}
fn certified_authentication_error(
    error: ArchiveFinalityError,
) -> ProviderIngestFinalizedArchiveErrorV1 {
    match error {
        ArchiveFinalityError::Deferred(original) => {
            ProviderIngestFinalizedArchiveErrorV1::Deferred(original)
        }
        ArchiveFinalityError::BoundaryChanged => {
            ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                boundary: "certified Kura",
            }
        }
        error => ProviderIngestFinalizedArchiveErrorV1::KuraAuthentication {
            operation: "authenticate same-State certified archive boundary",
            detail: error.to_string(),
        },
    }
}
fn committed_capture_key(
    state_ro: &impl StateReadOnly,
    kura: &Kura,
) -> Result<ProviderIngestFinalizedArchiveKeyV1, ProviderIngestFinalizedArchiveErrorV1> {
    if !std::ptr::eq(state_ro.kura(), kura) {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                reason: "immutable state view is bound to another Kura instance",
            },
        );
    }
    let height = u64::try_from(state_ro.height()).map_err(|_| {
        ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
            reason: "immutable state height exceeds the supported range",
        }
    })?;
    let block_hash = state_ro.latest_block_hash().ok_or(
        ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
            reason: "immutable state has no committed block hash",
        },
    )?;
    ProviderIngestFinalizedArchiveKeyV1::try_new(
        *state_ro.network_id(),
        height,
        *block_hash.as_ref(),
        state_ro.query_ledger_time_ms(),
    )
}
fn encode_bounded_record(
    record: &ProviderIngestFinalizedArchiveRecordV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<Vec<u8>, ProviderIngestFinalizedArchiveErrorV1> {
    let bytes = norito::to_bytes(record).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    let observed = bounded_bytes_len(&bytes);
    if observed == 0 || observed > bounds.max_record_bytes() {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RecordTooLarge {
            observed,
            maximum: bounds.max_record_bytes(),
        });
    }
    Ok(bytes)
}
fn encode_bounded_checkpoint(
    checkpoint: &ProviderIngestFinalizedArchiveCheckpointV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<Vec<u8>, ProviderIngestFinalizedArchiveErrorV1> {
    let bytes =
        norito::to_bytes(checkpoint).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    let observed = bounded_bytes_len(&bytes);
    if observed == 0 || observed > bounds.max_record_bytes() {
        return Err(ProviderIngestFinalizedArchiveErrorV1::RecordTooLarge {
            observed,
            maximum: bounds.max_record_bytes(),
        });
    }
    Ok(bytes)
}
fn load_archive_index(
    records: &Path,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<ArchiveIndexV1, ProviderIngestFinalizedArchiveErrorV1> {
    let mut index = ArchiveIndexV1::default();
    for entry in
        fs::read_dir(records).map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: records.to_path_buf(),
            source,
        })?
    {
        let entry = entry.map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: records.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path,
                reason: "archive record filename is not UTF-8",
            });
        };
        if !is_canonical_digest_file_name(name, RECORD_FILE_SUFFIX) {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path,
                reason: "unknown object in provider-ingest record namespace",
            });
        }
        let observed_entries = index.by_height.len().checked_add(1).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: usize::MAX,
                maximum: bounds.max_archive_entries(),
            },
        )?;
        if observed_entries > bounds.max_archive_entries() {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                    observed: observed_entries,
                    maximum: bounds.max_archive_entries(),
                },
            );
        }
        let record = load_record_at(&path, bounds, None)?;
        if record_file_name(&record.material.key)? != name {
            return Err(ProviderIngestFinalizedArchiveErrorV1::ExactKeyMismatch { path });
        }
        let metadata =
            direct_archive_file_metadata(&path, bounds.max_record_bytes()).map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: path.clone(),
                    source,
                }
            })?;
        let canonical_bytes = metadata.len();
        index.total_bytes = index.total_bytes.checked_add(canonical_bytes).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: u64::MAX,
                maximum: bounds.max_total_bytes(),
            },
        )?;
        if index.total_bytes > bounds.max_total_bytes() {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                    observed: index.total_bytes,
                    maximum: bounds.max_total_bytes(),
                },
            );
        }
        let subject = (record.material.key.network_id, record.material.key.height);
        if let Some(existing) = index.by_height.get(&subject) {
            return Err(
                if existing.record.material.key.block_hash == record.material.key.block_hash {
                    ProviderIngestFinalizedArchiveErrorV1::ConflictingProjection {
                        network_id: subject.0,
                        height: subject.1,
                    }
                } else {
                    ProviderIngestFinalizedArchiveErrorV1::FinalizedFork {
                        network_id: subject.0,
                        height: subject.1,
                    }
                },
            );
        }
        index.by_height.insert(
            subject,
            ArchiveRecordEntryV1 {
                record,
                path,
                canonical_bytes,
            },
        );
    }
    index.generation = u64::try_from(index.by_height.len()).map_err(|_| {
        ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
            observed: index.by_height.len(),
            maximum: bounds.max_archive_entries(),
        }
    })?;
    Ok(index)
}
fn load_record_at(
    path: &Path,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
    expected_key: Option<&ProviderIngestFinalizedArchiveKeyV1>,
) -> Result<ProviderIngestFinalizedArchiveRecordV1, ProviderIngestFinalizedArchiveErrorV1> {
    let bytes = read_bounded_archive_file(path, bounds.max_record_bytes()).map_err(|source| {
        ProviderIngestFinalizedArchiveErrorV1::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if bytes.is_empty() {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: path.to_path_buf(),
            reason: "archive record is empty",
        });
    }
    let record = decode_from_bytes_with_limits::<ProviderIngestFinalizedArchiveRecordV1>(
        &bytes,
        bounds.decode_limits()?,
    )
    .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    record.validate()?;
    let canonical =
        norito::to_bytes(&record).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    if canonical != bytes {
        return Err(ProviderIngestFinalizedArchiveErrorV1::NonCanonicalRecord {
            path: path.to_path_buf(),
        });
    }
    if expected_key.is_some_and(|expected| expected != &record.material.key) {
        return Err(ProviderIngestFinalizedArchiveErrorV1::ExactKeyMismatch {
            path: path.to_path_buf(),
        });
    }
    Ok(record)
}
fn load_checkpoint_at(
    path: &Path,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<ProviderIngestFinalizedArchiveCheckpointV1, ProviderIngestFinalizedArchiveErrorV1> {
    let bytes = read_bounded_archive_file(path, bounds.max_record_bytes()).map_err(|source| {
        ProviderIngestFinalizedArchiveErrorV1::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if bytes.is_empty() {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: path.to_path_buf(),
            reason: "archive checkpoint is empty",
        });
    }
    let checkpoint = decode_from_bytes_with_limits::<ProviderIngestFinalizedArchiveCheckpointV1>(
        &bytes,
        bounds.decode_limits()?,
    )
    .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    checkpoint.validate(bounds)?;
    let canonical =
        norito::to_bytes(&checkpoint).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    if canonical != bytes {
        return Err(ProviderIngestFinalizedArchiveErrorV1::NonCanonicalRecord {
            path: path.to_path_buf(),
        });
    }
    let expected_name = checkpoint_file_name(checkpoint.checkpoint_digest);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(ProviderIngestFinalizedArchiveErrorV1::ExactKeyMismatch {
            path: path.to_path_buf(),
        });
    }
    Ok(checkpoint)
}
fn load_archive_checkpoints(
    checkpoints: &Path,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<Vec<ArchiveVirtualBaseV1>, ProviderIngestFinalizedArchiveErrorV1> {
    let mut loaded = Vec::new();
    for entry in
        fs::read_dir(checkpoints).map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: checkpoints.to_path_buf(),
            source,
        })?
    {
        let entry = entry.map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: checkpoints.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path,
                reason: "archive checkpoint filename is not UTF-8",
            });
        };
        if !is_canonical_digest_file_name(&name, CHECKPOINT_FILE_SUFFIX) {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path,
                reason: "unknown object in provider-ingest checkpoint namespace",
            });
        }
        let maximum_candidates = bounds.max_archive_entries().checked_mul(2).ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: usize::MAX,
                maximum: bounds.max_archive_entries(),
            },
        )?;
        if loaded.len() >= maximum_candidates {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                    observed: loaded.len().saturating_add(1),
                    maximum: maximum_candidates,
                },
            );
        }
        loaded.try_reserve(1).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
                resource: "checkpoint inventory",
            }
        })?;
        let checkpoint = load_checkpoint_at(&path, bounds)?;
        let metadata =
            direct_archive_file_metadata(&path, bounds.max_record_bytes()).map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: path.clone(),
                    source,
                }
            })?;
        loaded.push(ArchiveVirtualBaseV1 {
            checkpoint,
            path,
            canonical_bytes: metadata.len(),
        });
    }
    Ok(loaded)
}
fn install_virtual_bases(
    index: &mut ArchiveIndexV1,
    candidates: &[ArchiveVirtualBaseV1],
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let mut by_network: BTreeMap<NetworkId, Vec<&ArchiveVirtualBaseV1>> = BTreeMap::new();
    for candidate in candidates {
        candidate.checkpoint.validate(bounds)?;
        let network = by_network
            .entry(candidate.checkpoint.material.retention_floor.network_id)
            .or_default();
        network.try_reserve(1).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::ProjectionAllocation {
                resource: "checkpoint network inventory",
            }
        })?;
        network.push(candidate);
    }
    for (network_id, mut network_candidates) in by_network {
        network_candidates.sort_by_key(|candidate| {
            (
                candidate.checkpoint.material.retention_floor.height,
                candidate.checkpoint.checkpoint_digest,
            )
        });
        for pair in network_candidates.windows(2) {
            let previous = pair[0];
            let next = pair[1];
            if previous.checkpoint.material.retention_floor.height
                == next.checkpoint.material.retention_floor.height
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::AmbiguousCheckpoint {
                    network_id,
                    retention_height: next.checkpoint.material.retention_floor.height,
                });
            }
        }
        let active = network_candidates.last().copied().ok_or(
            ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                reason: "checkpoint candidate set is empty",
            },
        )?;
        if network_candidates.len() > 1 {
            let prior = network_candidates[network_candidates.len() - 2];
            if active.checkpoint.material.prior_checkpoint_digest
                != Some(prior.checkpoint.checkpoint_digest)
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                    reason: "newest checkpoint does not authenticate its durable predecessor",
                });
            }
            if active.checkpoint.material.original_activation_floor
                != prior.checkpoint.material.original_activation_floor
                || active.checkpoint.material.pruned_entries
                    <= prior.checkpoint.material.pruned_entries
                || active.checkpoint.material.pruned_bytes <= prior.checkpoint.material.pruned_bytes
                || active.checkpoint.material.total_generation
                    < prior.checkpoint.material.total_generation
                || active.checkpoint.material.cumulative_prefix_digest
                    == prior.checkpoint.material.cumulative_prefix_digest
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                    reason: "newest checkpoint rolled back its authenticated prefix counters",
                });
            }
        }
        let floor = &active.checkpoint.material.retention_floor;
        if let Some(original) = index.by_height.get(&(network_id, floor.height)) {
            if original.record.material.key != *floor
                || original.record.record_digest
                    != active.checkpoint.material.original_terminal_record_digest
                || original.record.material.provider_state_root
                    != active.checkpoint.material.provider_state_root
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
                    reason: "virtual base differs from its still-retained original anchor",
                });
            }
        }
        index.virtual_bases.insert(network_id, (*active).clone());
    }
    Ok(())
}
fn finish_compaction_cleanup(
    records: &Path,
    records_identity: ArchiveFileIdentity,
    checkpoints: &Path,
    checkpoints_identity: ArchiveFileIdentity,
    checkpoint_candidates: &[ArchiveVirtualBaseV1],
    index: &mut ArchiveIndexV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let obsolete_records = index
        .by_height
        .iter()
        .filter(|((network_id, height), _)| {
            index
                .virtual_bases
                .get(network_id)
                .is_some_and(|base| *height <= base.checkpoint.material.retention_floor.height)
        })
        .map(|(subject, entry)| (subject.to_owned(), entry.path.clone()))
        .collect::<Vec<_>>();
    for (_, path) in &obsolete_records {
        unlink_verified_archive_file(records, records_identity, path)?;
    }
    for (subject, _) in obsolete_records {
        index.by_height.remove(&subject);
    }
    let active_paths = index
        .virtual_bases
        .values()
        .map(|base| base.path.clone())
        .collect::<BTreeSet<_>>();
    let stale_checkpoints = checkpoint_candidates
        .iter()
        .filter(|candidate| !active_paths.contains(&candidate.path))
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    for path in &stale_checkpoints {
        unlink_verified_archive_file(checkpoints, checkpoints_identity, path)?;
    }
    Ok(())
}
fn refresh_archive_accounting(
    index: &mut ArchiveIndexV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    index.total_bytes = index
        .by_height
        .values()
        .map(|entry| entry.canonical_bytes)
        .chain(
            index
                .virtual_bases
                .values()
                .map(|base| base.canonical_bytes),
        )
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes))
        .ok_or(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: u64::MAX,
                maximum: bounds.max_total_bytes(),
            },
        )?;
    let pruned_entries = index
        .virtual_bases
        .values()
        .map(|base| base.checkpoint.material.pruned_entries)
        .try_fold(0_u64, |total, count| total.checked_add(count))
        .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "checkpoint pruned-entry accounting overflowed",
        })?;
    index.generation = pruned_entries
        .checked_add(u64::try_from(index.by_height.len()).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: index.by_height.len(),
                maximum: bounds.max_archive_entries(),
            }
        })?)
        .ok_or(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "archive generation accounting overflowed",
        })?;
    if index
        .virtual_bases
        .values()
        .any(|base| base.checkpoint.material.total_generation > index.generation)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidCheckpoint {
            reason: "checkpoint generation exceeds pruned plus retained archive history",
        });
    }
    Ok(())
}
fn verify_checkpoint_entry(
    entry: &ArchiveVirtualBaseV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let metadata =
        direct_archive_file_metadata(&entry.path, bounds.max_record_bytes()).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: entry.path.clone(),
                source,
            }
        })?;
    if metadata.len() != entry.canonical_bytes {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: entry.path.clone(),
            reason: "immutable checkpoint length changed after archive qualification",
        });
    }
    if load_checkpoint_at(&entry.path, bounds)? != entry.checkpoint {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: entry.path.clone(),
            reason: "immutable checkpoint changed after archive qualification",
        });
    }
    Ok(())
}
fn unlink_verified_archive_file(
    directory: &Path,
    expected_directory_identity: ArchiveFileIdentity,
    path: &Path,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if path.parent() != Some(directory) {
        return Err(ProviderIngestFinalizedArchiveErrorV1::PathBindingMismatch {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let name = path.file_name().ok_or_else(|| {
            ProviderIngestFinalizedArchiveErrorV1::PathBindingMismatch {
                path: path.to_path_buf(),
            }
        })?;
        let directory_file = open_unix_directory_ancestry(directory)?;
        verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
        let opened = fs::File::from(
            rustix::fs::openat(
                &directory_file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: path.to_path_buf(),
                source,
            })?,
        );
        let metadata =
            opened
                .metadata()
                .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
        let named =
            rustix::fs::statat(&directory_file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)
                .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || !unix_stat_matches_metadata(&named, &metadata, 1)
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path: path.to_path_buf(),
                reason: "immutable archive artifact changed before retention unlink",
            });
        }
        rustix::fs::unlinkat(&directory_file, name, rustix::fs::AtFlags::empty())
            .map_err(io::Error::from)
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Write {
                path: path.to_path_buf(),
                source,
            })?;
        directory_file.sync_all().map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::NamespaceSync {
                path: directory.to_path_buf(),
                source,
            }
        })?;
        verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let _ = expected_directory_identity;
        Err(ProviderIngestFinalizedArchiveErrorV1::UnsupportedPlatform {
            operation: "descriptor-relative immutable prefix cleanup",
            platform: std::env::consts::OS,
        })
    }
}
fn ensure_insert_capacity(
    index: &ArchiveIndexV1,
    bounds: ProviderIngestFinalizedArchiveBoundsV1,
    record_bytes: usize,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let observed_entries = retained_archive_entries(index)
        .checked_add(1)
        .unwrap_or(usize::MAX);
    if observed_entries > bounds.max_archive_entries() {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded {
                observed: observed_entries,
                maximum: bounds.max_archive_entries(),
            },
        );
    }
    let record_bytes = u64::try_from(record_bytes).unwrap_or(u64::MAX);
    let observed_bytes = index
        .total_bytes
        .checked_add(record_bytes)
        .unwrap_or(u64::MAX);
    if observed_bytes > bounds.max_total_bytes() {
        return Err(
            ProviderIngestFinalizedArchiveErrorV1::ArchiveBytesExceeded {
                observed: observed_bytes,
                maximum: bounds.max_total_bytes(),
            },
        );
    }
    Ok(())
}
fn record_file_name(
    key: &ProviderIngestFinalizedArchiveKeyV1,
) -> Result<String, ProviderIngestFinalizedArchiveErrorV1> {
    let bytes = norito::to_bytes(key).map_err(ProviderIngestFinalizedArchiveErrorV1::Encode)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_DIGEST_DOMAIN_V1);
    hasher.update(&bytes);
    Ok(format!(
        "{}{RECORD_FILE_SUFFIX}",
        hex::encode(hasher.finalize().as_bytes())
    ))
}
fn checkpoint_file_name(checkpoint_digest: [u8; 32]) -> String {
    format!("{}{CHECKPOINT_FILE_SUFFIX}", hex::encode(checkpoint_digest))
}
fn validate_archive_root_path(path: &Path) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: path.to_path_buf(),
            reason: "archive root must be an absolute normalized non-root path",
        });
    }
    Ok(())
}
fn verify_existing_directory_ancestry(
    path: &Path,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                    path: current,
                    reason: "archive ancestry contains a symlink or non-directory component",
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}
fn verify_absolute_directory_ancestry(
    path: &Path,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    validate_archive_root_path(path)?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: current.clone(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path: current,
                reason: "archive ancestry contains a symlink or non-directory component",
            });
        }
    }
    #[cfg(unix)]
    open_unix_directory_ancestry(path).map(drop)?;
    Ok(())
}
#[cfg(unix)]
fn open_unix_directory_ancestry(
    path: &Path,
) -> Result<fs::File, ProviderIngestFinalizedArchiveErrorV1> {
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
        .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
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
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
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
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: path.to_path_buf(),
                source,
            })?,
        );
        let opened =
            child
                .metadata()
                .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
        let after = rustix::fs::statat(&current, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if !opened.is_dir()
            || before.st_dev as u64 != opened.dev()
            || before.st_ino as u64 != opened.ino()
            || after.st_dev as u64 != opened.dev()
            || after.st_ino as u64 != opened.ino()
        {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path: path.to_path_buf(),
                reason: "archive ancestry changed during no-follow traversal",
            });
        }
        current = child;
    }
    Ok(current)
}
fn validate_root_namespace(root: &Path) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    for entry in
        fs::read_dir(root).map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: root.to_path_buf(),
            source,
        })?
    {
        let entry = entry.map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        if name != RECORDS_DIRECTORY && name != CHECKPOINTS_DIRECTORY && name != WRITER_LOCK_FILE {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path: entry.path(),
                reason: "unknown object in finalized provider-ingest archive root",
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
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let directory_file = open_unix_directory_ancestry(directory)?;
        verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
        let entries = rustix::fs::Dir::read_from(&directory_file)
            .map_err(io::Error::from)
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: directory.to_path_buf(),
                source,
            })?;
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(io::Error::from).map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: directory.to_path_buf(),
                    source,
                }
            })?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            let Some(name_utf8) = name.to_str() else {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
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
                    .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                        path: directory.join(name),
                        source,
                    })?;
            let unsafe_stage = rustix::fs::FileType::from_raw_mode(metadata.st_mode)
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
                        ProviderIngestFinalizedArchiveErrorV1::Read {
                            path: directory.join(name),
                            source,
                        }
                    })?,
                    _ => true,
                };
            if unsafe_stage {
                return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                    path: directory.join(name),
                    reason: "staged artifact is neither private nor linked to one canonical target",
                });
            }
            rustix::fs::unlinkat(&directory_file, name, rustix::fs::AtFlags::empty())
                .map_err(io::Error::from)
                .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Write {
                    path: directory.join(name),
                    source,
                })?;
            removed = true;
        }
        if removed {
            directory_file.sync_all().map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::NamespaceSync {
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
        let _ = (
            expected_directory_identity,
            canonical_suffix,
            max_record_bytes,
        );
        for entry in fs::read_dir(directory).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Read {
                path: directory.to_path_buf(),
                source,
            }
        })? {
            let entry = entry.map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: directory.to_path_buf(),
                source,
            })?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(STAGED_FILE_PREFIX))
            {
                return Err(ProviderIngestFinalizedArchiveErrorV1::UnsupportedPlatform {
                    operation: "descriptor-relative staged-artifact recovery",
                    platform: std::env::consts::OS,
                });
            }
        }
        Ok(())
    }
}
fn publish_immutable_bytes(
    directory: &Path,
    expected_directory_identity: ArchiveFileIdentity,
    target: &Path,
    bytes: &[u8],
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    if target.parent() != Some(directory) {
        return Err(ProviderIngestFinalizedArchiveErrorV1::PathBindingMismatch {
            path: target.to_path_buf(),
        });
    }
    let target_name = target.file_name().ok_or_else(|| {
        ProviderIngestFinalizedArchiveErrorV1::PathBindingMismatch {
            path: target.to_path_buf(),
        }
    })?;
    #[cfg(unix)]
    {
        publish_immutable_bytes_unix_with_hooks(
            directory,
            expected_directory_identity,
            target,
            target_name,
            bytes,
            || {},
            || {},
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (expected_directory_identity, target_name, bytes);
        Err(ProviderIngestFinalizedArchiveErrorV1::UnsupportedPlatform {
            operation: "descriptor-relative no-reparse immutable publication",
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
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1>
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
        return Err(ProviderIngestFinalizedArchiveErrorV1::PathBindingMismatch {
            path: target.to_path_buf(),
        });
    }
    let directory_file = open_unix_directory_ancestry(directory)?;
    verify_unix_directory_handle(&directory_file, expected_directory_identity, directory)?;
    before_create();
    let (mut staged_file, staged_name) =
        create_unix_staged_file(&directory_file).map_err(|source| {
            ProviderIngestFinalizedArchiveErrorV1::Write {
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
        .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Write {
            path: staged_path.clone(),
            source,
        })?;
    let staged_metadata =
        staged_file
            .metadata()
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
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
    .map_err(|_| ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
        path: staged_path.clone(),
        reason: "staged artifact changed before immutable publication",
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
            let linked_metadata = staged_file.metadata().map_err(|source| {
                ProviderIngestFinalizedArchiveErrorV1::Read {
                    path: staged_path.clone(),
                    source,
                }
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
                        "published link differs from staged artifact",
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
                return Err(ProviderIngestFinalizedArchiveErrorV1::Write {
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
            return Err(ProviderIngestFinalizedArchiveErrorV1::Write {
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
                "failed to remove staged artifact ({unlink_error}) and roll back published link ({rollback_error})"
            )),
        };
        return Err(ProviderIngestFinalizedArchiveErrorV1::Write {
            path: staged_path,
            source,
        });
    }
    directory_file.sync_all().map_err(|source| {
        ProviderIngestFinalizedArchiveErrorV1::NamespaceSync {
            path: directory.to_path_buf(),
            source,
        }
    })?;
    let published =
        read_bounded_archive_file_at_unix(&directory_file, target_name, bounded_bytes_len(bytes))
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
            path: target.to_path_buf(),
            source,
        })?;
    if published != bytes {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: target.to_path_buf(),
            reason: "immutable target already contains different bytes",
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
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    let metadata =
        directory
            .metadata()
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Read {
                path: path.to_path_buf(),
                source,
            })?;
    if !metadata.is_dir() || archive_file_identity(&metadata) != expected {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
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
            "descriptor-relative artifact identity mismatch",
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
            "artifact is not a bounded direct single-link regular file",
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
    if before.st_dev as u64 != archive_file_identity(&opened_before).0
        || before.st_ino as u64 != archive_file_identity(&opened_before).1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact changed while opening",
        ));
    }
    let capacity = usize::try_from(opened_before.len()).unwrap_or(0);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| io::Error::other("could not reserve bounded archive read buffer"))?;
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
            "artifact changed while reading",
        ));
    }
    Ok(bytes)
}
fn create_direct_directory(path: &Path) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    validate_archive_root_path(path)?;
    verify_existing_directory_ancestry(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
                path: path.to_path_buf(),
                reason: "archive path must be a direct directory",
            });
        }
        Ok(_) => return verify_absolute_directory_ancestry(path),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ProviderIngestFinalizedArchiveErrorV1::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fs::create_dir_all(path).map_err(|source| ProviderIngestFinalizedArchiveErrorV1::Write {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        ProviderIngestFinalizedArchiveErrorV1::Write {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
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
    .map_err(
        |source| ProviderIngestFinalizedArchiveErrorV1::NamespaceSync {
            path: path.to_path_buf(),
            source,
        },
    )
}
fn open_writer_lock_file(path: &Path) -> Result<fs::File, ProviderIngestFinalizedArchiveErrorV1> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file =
        options
            .open(path)
            .map_err(|source| ProviderIngestFinalizedArchiveErrorV1::WriterBusy {
                path: path.to_path_buf(),
                source,
            })?;
    let path_metadata = secure_file_metadata::from_path(path).map_err(|source| {
        ProviderIngestFinalizedArchiveErrorV1::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let opened_metadata = secure_file_metadata::from_file(&file).map_err(|source| {
        ProviderIngestFinalizedArchiveErrorV1::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !secure_file_metadata::is_single_link(&path_metadata)
        || !archive_file_metadata_unchanged(&path_metadata, &opened_metadata)
    {
        return Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage {
            path: path.to_path_buf(),
            reason: "writer lock must be a direct single-link regular file",
        });
    }
    Ok(file)
}
fn acquire_writer_ownership(
    file: &fs::File,
    path: &Path,
) -> Result<(), ProviderIngestFinalizedArchiveErrorV1> {
    #[cfg(unix)]
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |source| ProviderIngestFinalizedArchiveErrorV1::WriterBusy {
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
    use std::os::unix::fs::MetadataExt as _;
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
            "archive directory must be direct and have a stable identity",
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
    use std::os::unix::fs::MetadataExt as _;
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
            "artifact must be a bounded direct single-link regular file",
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
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
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
            "artifact identity changed while opening",
        ));
    }
    let capacity = usize::try_from(opened_before.len()).unwrap_or(0);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| io::Error::other("could not reserve bounded archive read buffer"))?;
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let opened_after = secure_file_metadata::from_file(&file)?;
    let path_after = secure_file_metadata::from_path(path)?;
    if bounded_bytes_len(&bytes) > max_bytes
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || !secure_file_metadata::is_single_link(&path_after)
        || !archive_file_metadata_unchanged(&opened_before, &opened_after)
        || !archive_file_metadata_unchanged(&opened_before, &path_after)
        || opened_after.len() != bounded_bytes_len(&bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "artifact changed while reading",
        ));
    }
    Ok(bytes)
}
fn sync_archive_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
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
/// Fail-closed errors returned by the finalized provider-ingest archive.
#[derive(Debug, Error)]
pub enum ProviderIngestFinalizedArchiveErrorV1 {
    /// The original authenticated history read has not completed locally.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// A physical index reader or writer currently prevents retained publication.
    #[error("finalized provider-ingest archive index is busy")]
    IndexBusy {
        /// Release Kura and State fences before awaiting this actual index owner.
        wait: iroha_allocation::release::ReleaseWait,
    },
    /// Archive ceilings are zero, inconsistent, or unrepresentable.
    #[error("invalid finalized provider-ingest archive bounds: {reason}")]
    InvalidBounds {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// An exact archive key is malformed.
    #[error("invalid finalized provider-ingest archive key: {reason}")]
    InvalidKey {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A caller-supplied retention boundary is malformed or unauthenticated.
    #[error("invalid finalized provider-ingest archive retention fence: {reason}")]
    InvalidRetentionFence {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// The archive advanced after the retention decision was made.
    #[error(
        "finalized provider-ingest retention fence expected archive generation {expected}, observed {observed}"
    )]
    RetentionFenceGenerationMismatch {
        /// Generation captured by the retention decision.
        expected: u64,
        /// Generation held under the archive write lock.
        observed: u64,
    },
    /// A configured retention-authority handle, revision, or digest is invalid.
    #[error("invalid finalized provider-ingest retention-authority binding")]
    InvalidRetentionAuthorityBinding,
    /// Existing checkpoint objects require the deployment-owned authority.
    #[error(
        "finalized provider-ingest archive contains retention checkpoints but no authority was supplied"
    )]
    RetentionAuthorityRequired,
    /// The runtime authority does not match its configured public binding.
    #[error("finalized provider-ingest retention authority was substituted or became stale")]
    RetentionAuthoritySubstitution,
    /// The runtime authority could not serve an exact operation.
    #[error("finalized provider-ingest retention authority is unavailable")]
    RetentionAuthorityUnavailable,
    /// The runtime authority rejected the exact operation.
    #[error("finalized provider-ingest retention authority rejected the exact operation")]
    RetentionAuthorityRejected,
    /// The authority's monotonic lineage is behind the local archive.
    #[error("finalized provider-ingest retention authority or archive rolled back")]
    RetentionAuthorityRollback,
    /// The authority returned a competing value for one exact CAS lineage.
    #[error("finalized provider-ingest retention authority equivocated")]
    RetentionAuthorityEquivocation,
    /// A CAS reported success without changing the authoritative value.
    #[error("finalized provider-ingest retention authority CAS left the value unchanged")]
    RetentionAuthorityCasUnchanged,
    /// A CAS outcome or post-write authority identity could not be proven.
    #[error("finalized provider-ingest retention authority CAS outcome is ambiguous")]
    RetentionAuthorityCasAmbiguous,
    /// A canonical checkpoint exists without exact sealed approval.
    #[error("unapproved finalized provider-ingest retention checkpoint")]
    UnapprovedRetentionCheckpoint,
    /// A prepared checkpoint differs from its approved exact proposal.
    #[error("finalized provider-ingest retention proposal does not match canonical checkpoint")]
    RetentionProposalMismatch,
    /// A canonical retention approval violates schema or lineage constraints.
    #[error("invalid finalized provider-ingest retention approval: {reason}")]
    InvalidRetentionApproval {
        /// Stable payload-free rejection reason.
        reason: &'static str,
    },
    /// A typed provider projection violates an invariant.
    #[error("invalid finalized provider-ingest projection: {reason}")]
    InvalidProjection {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A projection exceeded one configured row-count ceiling.
    #[error("finalized provider-ingest projection {resource} count {observed} exceeds {maximum}")]
    ProjectionBoundsExceeded {
        /// Bounded projection resource.
        resource: &'static str,
        /// Observed count.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A bounded in-memory projection reservation failed.
    #[error("finalized provider-ingest projection could not allocate bounded {resource}")]
    ProjectionAllocation {
        /// Bounded allocation category.
        resource: &'static str,
    },
    /// A persisted record violates its canonical schema.
    #[error("invalid finalized provider-ingest archive record: {reason}")]
    InvalidRecord {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A record uses an archive version other than V1.
    #[error("unsupported finalized provider-ingest archive version {found}")]
    UnsupportedArchiveVersion {
        /// Unsupported version.
        found: u16,
    },
    /// A stored record digest differs from its canonical material.
    #[error("finalized provider-ingest archive record digest mismatch")]
    RecordDigestMismatch,
    /// A virtual-base checkpoint violates its canonical schema or history.
    #[error("invalid finalized provider-ingest archive checkpoint: {reason}")]
    InvalidCheckpoint {
        /// Stable validation failure.
        reason: &'static str,
    },
    /// A checkpoint digest differs from its canonical material.
    #[error("finalized provider-ingest archive checkpoint digest mismatch")]
    CheckpointDigestMismatch,
    /// More than one checkpoint claims the same newest retention floor.
    #[error(
        "ambiguous finalized provider-ingest checkpoint for `{network_id}` at retention height {retention_height}"
    )]
    AmbiguousCheckpoint {
        /// Network with competing virtual bases.
        network_id: NetworkId,
        /// Conflicted retention height.
        retention_height: u64,
    },
    /// Two block hashes or timestamps claim one network height.
    #[error("finalized provider-ingest archive fork for `{network_id}` at height {height}")]
    FinalizedFork {
        /// Conflicted network.
        network_id: NetworkId,
        /// Conflicted height.
        height: u64,
    },
    /// One exact key resolves to different typed provider state.
    #[error(
        "conflicting finalized provider-ingest projection for `{network_id}` at height {height}"
    )]
    ConflictingProjection {
        /// Conflicted network.
        network_id: NetworkId,
        /// Conflicted height.
        height: u64,
    },
    /// Exact archive coverage skipped a height after activation.
    #[error(
        "finalized provider-ingest archive for `{network_id}` is missing height {missing_height} before {observed_height}"
    )]
    ArchiveCoverageGap {
        /// Network with incomplete coverage.
        network_id: NetworkId,
        /// First required missing height.
        missing_height: u64,
        /// Observed non-successor height.
        observed_height: u64,
    },
    /// The immutable archive tip is beyond Kura's authenticated boundary.
    #[error(
        "finalized provider-ingest archive height {archive_height} is ahead of exact Kura height {kura_height}"
    )]
    ArchiveAheadOfKura {
        /// Highest exact archive height.
        archive_height: u64,
        /// Authenticated Kura boundary height.
        kura_height: u64,
    },
    /// The uncaptured Kura suffix exceeds the configured readiness ceiling.
    #[error(
        "finalized provider-ingest archive height {archive_height} lags exact Kura height {kura_height} by {lag}; maximum is {maximum}"
    )]
    ArchiveKuraTipLagExceeded {
        /// Highest exact archive height.
        archive_height: u64,
        /// Authenticated Kura boundary height.
        kura_height: u64,
        /// Uncaptured suffix length.
        lag: u64,
        /// Configured maximum suffix length.
        maximum: u64,
    },
    /// One immutable anchor differs from authenticated Kura material.
    #[error(
        "finalized provider-ingest archive anchor `{network_id}` height {height} failed Kura qualification: {reason}"
    )]
    ArchiveKuraAnchorMismatch {
        /// Archived network.
        network_id: NetworkId,
        /// Archived height.
        height: u64,
        /// Stable payload-free mismatch category.
        reason: &'static str,
    },
    /// Kura or the archive changed during one qualification.
    #[error(
        "finalized provider-ingest {boundary} qualification boundary changed during validation"
    )]
    QualificationBoundaryChanged {
        /// Changed boundary.
        boundary: &'static str,
    },
    /// Aggregate durable bytes exceed the configured ceiling.
    #[error(
        "finalized provider-ingest archive bytes {observed} exceed configured maximum {maximum}"
    )]
    ArchiveBytesExceeded {
        /// Observed aggregate bytes.
        observed: u64,
        /// Configured aggregate maximum.
        maximum: u64,
    },
    /// Immutable record count exceeds the configured ceiling.
    #[error(
        "finalized provider-ingest archive entries {observed} exceed configured maximum {maximum}"
    )]
    ArchiveCapacityExceeded {
        /// Observed entry count.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The requested network has no qualified exact anchor.
    #[error("finalized provider-ingest archive is unavailable: {reason}")]
    ArchiveUnavailable {
        /// Stable availability failure.
        reason: &'static str,
    },
    /// An exact query predates the explicit activation floor.
    #[error(
        "requested finalized provider-ingest height {requested_height} is below activation floor {activation_height}"
    )]
    BelowActivationFloor {
        /// Requested exact height.
        requested_height: u64,
        /// First represented exact height.
        activation_height: u64,
    },
    /// An exact query predates a deliberately compacted retention floor.
    #[error(
        "requested finalized provider-ingest height {requested_height} is below retention floor {retention_height}"
    )]
    BelowRetentionFloor {
        /// Requested exact height.
        requested_height: u64,
        /// Oldest exact height retained by the virtual base.
        retention_height: u64,
    },
    /// No immutable record exists at the requested exact height.
    #[error("unknown finalized provider-ingest anchor for `{network_id}` at height {height}")]
    UnknownExactAnchor {
        /// Requested network.
        network_id: NetworkId,
        /// Requested height.
        height: u64,
    },
    /// A cursor belongs to another network, block, provider, or state root.
    #[error("finalized provider-ingest page cursor context was substituted")]
    CursorSubstitution,
    /// A cursor's exclusive order identity is absent from the exact page state.
    #[error("finalized provider-ingest page cursor boundary is invalid")]
    InvalidCursorBoundary,
    /// A page limit is zero or exceeds the configured maximum.
    #[error("finalized provider-ingest page limit {observed} is outside 1..={maximum}")]
    InvalidPageLimit {
        /// Requested page size.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Reconstructed complete provider state differs from the committed root.
    #[error("finalized provider-ingest provider-state root mismatch")]
    ProviderStateRootMismatch,
    /// A provider signer policy rolled back its governed identity chain.
    #[error("finalized provider-ingest authority rollback for provider {provider_id:?}")]
    AuthorityRollback {
        /// Provider with a rolled-back policy.
        provider_id: ProviderId,
    },
    /// A provider owner or signer policy was substituted noncanonically.
    #[error("finalized provider-ingest authority substitution for provider {provider_id:?}")]
    AuthoritySubstitution {
        /// Provider with substituted authority.
        provider_id: ProviderId,
    },
    /// Immutable replication-order or manifest identity changed.
    #[error("finalized provider-ingest order substitution for {order_id:?}")]
    OrderSubstitution {
        /// Substituted order.
        order_id: ReplicationOrderId,
    },
    /// A replication assignment revision rolled back or skipped its successor.
    #[error("finalized provider-ingest assignment rollback for {order_id:?}")]
    AssignmentRollback {
        /// Rolled-back order.
        order_id: ReplicationOrderId,
    },
    /// Completion history or terminal status rolled back.
    #[error("finalized provider-ingest completion rollback for {order_id:?}")]
    CompletionRollback {
        /// Rolled-back order.
        order_id: ReplicationOrderId,
    },
    /// Two adjacent exact projections violate a monotonic transition.
    #[error("invalid finalized provider-ingest projection transition: {reason}")]
    InvalidTransition {
        /// Stable transition failure.
        reason: &'static str,
    },
    /// A retained completion points to another archived finalized hash.
    #[error("finalized provider-ingest completion anchor mismatch for {order_id:?}")]
    CompletionAnchorMismatch {
        /// Order containing the mismatched completion.
        order_id: ReplicationOrderId,
    },
    /// A Kura receipt and immutable view do not identify one committed block.
    #[error("finalized provider-ingest capture failed Kura authentication: {reason}")]
    FinalityAuthentication {
        /// Stable authentication failure.
        reason: &'static str,
    },
    /// Reading Kura's authenticated inventory failed.
    #[error("finalized provider-ingest capture could not {operation}: {detail}")]
    KuraAuthentication {
        /// Authenticated Kura operation.
        operation: &'static str,
        /// Payload-free storage diagnostic.
        detail: String,
    },
    /// One canonical record exceeds its configured byte ceiling.
    #[error(
        "finalized provider-ingest record bytes {observed} exceed configured maximum {maximum}"
    )]
    RecordTooLarge {
        /// Observed canonical bytes.
        observed: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// The archive namespace contains an unsafe or unexpected object.
    #[error("invalid finalized provider-ingest archive storage at {path}: {reason}")]
    InvalidStorage {
        /// Unsafe storage path.
        path: PathBuf,
        /// Stable validation failure.
        reason: &'static str,
    },
    /// The platform lacks a required handle-relative filesystem primitive.
    #[error("unsupported finalized provider-ingest archive operation `{operation}` on {platform}")]
    UnsupportedPlatform {
        /// Mutation that cannot be performed safely.
        operation: &'static str,
        /// Compile-target operating system.
        platform: &'static str,
    },
    /// A durable artifact could not be read safely.
    #[error("failed to read finalized provider-ingest archive artifact {path}: {source}")]
    Read {
        /// Artifact path.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// A durable artifact could not be written safely.
    #[error("failed to write finalized provider-ingest archive artifact {path}: {source}")]
    Write {
        /// Artifact path.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Atomic namespace publication could not be confirmed durably.
    #[error("failed to synchronize finalized provider-ingest archive namespace {path}: {source}")]
    NamespaceSync {
        /// Directory whose namespace sync failed.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Another process owns the archive write transaction.
    #[error("finalized provider-ingest archive writer is busy at {path}: {source}")]
    WriterBusy {
        /// Writer-lock path.
        path: PathBuf,
        /// Source lock error.
        #[source]
        source: io::Error,
    },
    /// Canonical Norito encoding failed.
    #[error("failed to encode finalized provider-ingest archive record: {0}")]
    Encode(#[source] norito::core::Error),
    /// Bounded Norito decoding failed.
    #[error("failed to decode finalized provider-ingest archive record {path}: {source}")]
    Decode {
        /// Record path.
        path: PathBuf,
        /// Source Norito error.
        #[source]
        source: norito::core::Error,
    },
    /// Decoded content does not re-encode to exact stored bytes.
    #[error("noncanonical finalized provider-ingest archive record at {path}")]
    NonCanonicalRecord {
        /// Noncanonical record path.
        path: PathBuf,
    },
    /// A record path or exact lookup resolves to another key.
    #[error("finalized provider-ingest archive exact-key mismatch at {path}")]
    ExactKeyMismatch {
        /// Mismatched path.
        path: PathBuf,
    },
    /// An immutable target escaped its verified record directory.
    #[error("finalized provider-ingest archive path binding mismatch at {path}")]
    PathBindingMismatch {
        /// Rejected path.
        path: PathBuf,
    },
    /// A record does not name the exact prior record and digest.
    #[error(
        "finalized provider-ingest predecessor substitution for `{network_id}` at height {height}"
    )]
    PredecessorSubstitution {
        /// Affected network.
        network_id: NetworkId,
        /// Affected height.
        height: u64,
    },
    /// The in-process archive lock was poisoned.
    #[error("finalized provider-ingest archive lock is poisoned")]
    ArchiveLockPoisoned,
}
#[cfg(test)]
mod tests {
    #[path = "../certified_capture_tests.rs"]
    mod certified_capture_tests;
    mod frame_identity_tests;
    include!("provider_ingest_finalized/preparation_tests.rs");
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        block::BlockHeader,
        sorafs::pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ManifestRootCid, PinPolicy,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ReplicationOrderCompletionRecord,
        },
    };
    use iroha_model_base::metadata::Metadata;
    use sorafs_manifest::capacity::{
        CapacityMetadataEntry, REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1,
        ReplicationOrderSlaV1,
    };
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;
    use std::{
        panic::AssertUnwindSafe,
        sync::{Arc, Mutex},
    };
    const PROVIDER_A: ProviderId = ProviderId::new([0x11; 32]);
    const PROVIDER_B: ProviderId = ProviderId::new([0x22; 32]);
    const PROVIDER_EMPTY: ProviderId = ProviderId::new([0x33; 32]);
    fn physical_tempdir() -> std::io::Result<tempfile::TempDir> {
        let temp_root = std::env::temp_dir().canonicalize()?;
        tempfile::Builder::new()
            .prefix("provider-ingest-finalized-")
            .tempdir_in(temp_root)
    }
    fn bounds() -> ProviderIngestFinalizedArchiveBoundsV1 {
        ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            32,
            32 * 1024 * 1024,
            16,
            16,
            64,
            1,
        )
        .expect("valid archive bounds")
    }
    fn account(seed: u8) -> AccountId {
        let key =
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic key");
        AccountId::new(key.public_key().clone())
    }
    fn policy(identity: u8, revision: u64) -> ProviderIngestCompletionSignerPolicyV1 {
        let digest = u8::try_from(revision).unwrap_or(0xFE);
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [identity; 32],
            revision,
            predecessor_digest: (revision > 1).then(|| [digest.saturating_sub(1); 32]),
            policy_digest: [digest; 32],
        }
    }
    fn test_network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            [seed; 32],
        )))
    }
    fn key(height: u64) -> ProviderIngestFinalizedArchiveKeyV1 {
        ProviderIngestFinalizedArchiveKeyV1::try_new(
            test_network_id(0x31),
            height,
            [u8::try_from(height).unwrap_or(0xFE); 32],
            height.saturating_mul(1_000),
        )
        .expect("valid finalized key")
    }
    fn archived_order(
        order_seed: u8,
        assigned: &[ProviderId],
    ) -> ProviderIngestFinalizedArchivedOrderV1 {
        let digest = ManifestDigest::new([order_seed.wrapping_add(0x40); 32]);
        let root = ManifestRootCid::from_blake3_digest([order_seed.wrapping_add(0x50); 32])
            .expect("manifest root");
        let chunker = ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        };
        let mut pin = PinManifestRecord::new(
            digest,
            root.clone(),
            chunker,
            [order_seed.wrapping_add(0x60); 32],
            [order_seed.wrapping_add(0x70); 32],
            4_096,
            archived_pin_policy(),
            account(1),
            1,
            None,
            None,
            Metadata::default(),
        );
        pin.approve(1, None);
        let order_id = [order_seed; 32];
        let canonical = ReplicationOrderV1 {
            version: REPLICATION_ORDER_VERSION_V1,
            order_id,
            manifest_cid: root.as_bytes().to_vec(),
            manifest_digest: *digest.as_bytes(),
            chunking_profile: "sorafs.sf1@1.0.0".to_owned(),
            target_replicas: u16::try_from(assigned.len()).expect("bounded assignments"),
            assignments: assigned
                .iter()
                .map(|provider_id| ReplicationAssignmentV1 {
                    provider_id: *provider_id.as_bytes(),
                    slice_gib: 1,
                    lane: None,
                })
                .collect(),
            issued_at: 1,
            deadline_at: 1_000,
            sla: ReplicationOrderSlaV1 {
                ingest_deadline_secs: 10,
                min_availability_percent_milli: 99_000,
                min_por_success_percent_milli: 99_000,
            },
            metadata: Vec::new(),
        };
        canonical.validate().expect("valid canonical order");
        ProviderIngestFinalizedArchivedOrderV1 {
            pin_manifest: pin,
            replication_order: ReplicationOrderRecord {
                order_id: ReplicationOrderId::new(order_id),
                manifest_digest: digest,
                manifest_root_cid: root,
                musubi_archive: None,
                issued_by: account(1),
                issued_epoch: 1,
                deadline_epoch: 1_000,
                canonical_order: norito::to_bytes(&canonical).expect("canonical order bytes"),
                assignment_revision: 1,
                provider_completions: Vec::new(),
                status: ReplicationOrderStatus::Pending,
            },
            musubi_archive: None,
        }
    }
    fn set_order_window(
        archived: &mut ProviderIngestFinalizedArchivedOrderV1,
        issued_epoch: u64,
        deadline_epoch: u64,
        ingest_deadline_secs: u32,
    ) {
        let record = &mut archived.replication_order;
        let mut canonical = validated_replication_order_from_record(&record.order_id, record)
            .expect("valid source order before changing the fixture window");
        canonical.issued_at = issued_epoch;
        canonical.deadline_at = deadline_epoch;
        canonical.sla.ingest_deadline_secs = ingest_deadline_secs;
        canonical
            .validate()
            .expect("valid replacement order window");
        record.canonical_order = norito::to_bytes(&canonical).expect("canonical order bytes");
        record.issued_epoch = issued_epoch;
        record.deadline_epoch = deadline_epoch;
    }
    fn completion_authority(
        owner_seed: u8,
        policy: ProviderIngestCompletionSignerPolicyV1,
    ) -> ProviderIngestCompletionAuthorityV1 {
        let owner = account(owner_seed);
        ProviderIngestCompletionAuthorityV1::new(owner.clone(), owner, policy)
    }
    fn projection(height: u64) -> ProviderIngestFinalizedProjectionV1 {
        let key = key(height);
        let shared = archived_order(0x21, &[PROVIDER_A, PROVIDER_B]);
        let only_a = archived_order(0x22, &[PROVIDER_A]);
        ProviderIngestFinalizedProjectionV1 {
            key,
            providers: vec![
                ProviderIngestFinalizedProviderProjectionV1 {
                    provider_id: PROVIDER_A,
                    expected_owner: Some(account(0x11)),
                    expected_authority: Some(completion_authority(0x11, policy(0xA1, 1))),
                    orders: vec![shared.clone(), only_a],
                },
                ProviderIngestFinalizedProviderProjectionV1 {
                    provider_id: PROVIDER_B,
                    expected_owner: Some(account(0x22)),
                    expected_authority: Some(completion_authority(0x22, policy(0xB1, 1))),
                    orders: vec![shared],
                },
                ProviderIngestFinalizedProviderProjectionV1 {
                    provider_id: PROVIDER_EMPTY,
                    expected_owner: Some(account(0x33)),
                    expected_authority: None,
                    orders: Vec::new(),
                },
            ],
        }
    }
    #[test]
    fn full_completion_authority_survives_checkpoint_and_rejects_same_policy_key_substitution() {
        let mut first = projection(7);
        first.providers[0]
            .expected_authority
            .as_mut()
            .unwrap()
            .completion_signer = account(0x71);
        first.validate(bounds()).unwrap();
        let providers = first
            .providers
            .iter()
            .cloned()
            .map(|p| (p.provider_id, p))
            .collect::<BTreeMap<_, _>>();
        let mut history = BTreeMap::new();
        seed_policy_history(&providers, &mut history);
        let checkpoint = policy_history_to_checkpoint(&history);
        let bytes = norito::to_bytes(&checkpoint).unwrap();
        let decoded: Vec<ProviderPolicyHistoryCheckpointV1> =
            norito::decode_from_bytes(&bytes).unwrap();
        validate_policy_history_checkpoint(&first, &decoded).unwrap();
        let mut recovered = policy_history_from_checkpoint(&decoded).unwrap();
        assert_eq!(
            recovered[&PROVIDER_A].last,
            first.providers[0].expected_authority.clone().unwrap()
        );
        observe_policy_history(&providers, &mut recovered).expect("exact full-authority replay");
        let mut changed = first.clone();
        changed.providers[0]
            .expected_authority
            .as_mut()
            .unwrap()
            .completion_signer = account(0x72);
        let changed_map = changed
            .providers
            .iter()
            .cloned()
            .map(|p| (p.provider_id, p))
            .collect::<BTreeMap<_, _>>();
        assert!(matches!(
            observe_policy_history(&changed_map, &mut recovered),
            Err(ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                provider_id: PROVIDER_A
            })
        ));
        assert!(
            validate_provider_authority_transition(&first.providers[0], &changed.providers[0])
                .is_err()
        );
        assert!(validate_policy_history_checkpoint(&changed, &decoded).is_err());
        changed.providers[0]
            .expected_authority
            .as_mut()
            .unwrap()
            .signer_policy = policy(0xA1, 2);
        validate_provider_authority_transition(&first.providers[0], &changed.providers[0]).unwrap();
        let changed_map = changed
            .providers
            .iter()
            .cloned()
            .map(|p| (p.provider_id, p))
            .collect::<BTreeMap<_, _>>();
        observe_policy_history(&changed_map, &mut recovered)
            .expect("explicit successor may change key");
        validate_policy_history_checkpoint(&changed, &policy_history_to_checkpoint(&recovered))
            .unwrap();
        let mut owner_mismatch = changed;
        owner_mismatch.providers[0].expected_owner = Some(account(0x73));
        assert!(owner_mismatch.validate(bounds()).is_err());
    }
    #[test]
    fn exact_assignment_lookup_matches_committed_page_root_and_excludes_other_providers() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert projection");
        let order_id = ReplicationOrderId::new([0x21; 32]);
        let exact = archive
            .read_provider_assignment(&first.key, PROVIDER_A, order_id)
            .expect("read exact assignment");
        let page = archive
            .read_provider_page(&first.key, PROVIDER_A, None, 1)
            .expect("read first bounded page");
        assert_eq!(exact.key, page.key);
        assert_eq!(exact.provider_id, page.provider_id);
        assert_eq!(exact.provider_state_root, page.provider_state_root);
        assert_eq!(exact.assignment.as_ref(), page.rows.first());
        assert_eq!(exact.source_provider_ids, vec![*PROVIDER_B.as_bytes()]);
        let after_first_page = archive
            .read_provider_assignment(&first.key, PROVIDER_A, ReplicationOrderId::new([0x22; 32]))
            .expect("direct lookup crosses one-row page boundary");
        assert_eq!(after_first_page.source_provider_ids, Vec::<[u8; 32]>::new());
        assert_eq!(
            after_first_page
                .assignment
                .as_ref()
                .map(|row| row.replication_order.order_id),
            Some(ReplicationOrderId::new([0x22; 32]))
        );
        for (provider_id, missing_order_id) in [
            (PROVIDER_A, ReplicationOrderId::new([0x23; 32])),
            (PROVIDER_EMPTY, order_id),
            (ProviderId::new([0x44; 32]), order_id),
        ] {
            let absent = archive
                .read_provider_assignment(&first.key, provider_id, missing_order_id)
                .expect("authenticated absent assignment");
            assert_eq!(absent.provider_state_root, page.provider_state_root);
            assert!(absent.assignment.is_none());
            assert!(absent.source_provider_ids.is_empty());
        }
        let mut fork = first.key;
        fork.block_hash = [0xF7; 32];
        assert!(matches!(
            archive.read_provider_assignment(&fork, PROVIDER_A, order_id),
            Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork { .. })
        ));
        assert!(matches!(
            archive.read_provider_assignment(&key(6), PROVIDER_A, order_id),
            Err(ProviderIngestFinalizedArchiveErrorV1::BelowActivationFloor { .. })
        ));
        assert!(matches!(
            archive.read_provider_assignment(
                &first.key,
                PROVIDER_A,
                ReplicationOrderId::new([0; 32])
            ),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
    }
    #[test]
    fn exact_assignment_lookup_uses_new_revision_and_canonical_source_rotation() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive
            .insert(first.clone())
            .expect("insert first projection");
        let order_id = ReplicationOrderId::new([0x21; 32]);
        let old = archive
            .read_provider_assignment(&first.key, PROVIDER_A, order_id)
            .expect("old assignment");
        assert_eq!(old.source_provider_ids, vec![*PROVIDER_B.as_bytes()]);
        let mut next = advance_projection(&first, 8);
        let provider_a = next
            .providers
            .iter_mut()
            .find(|provider| provider.provider_id == PROVIDER_A)
            .expect("provider A");
        let shared = provider_a.orders.first_mut().expect("shared order");
        let mut canonical = validated_replication_order_from_record(
            &shared.replication_order.order_id,
            &shared.replication_order,
        )
        .expect("canonical old order");
        canonical.assignments[1].provider_id = *PROVIDER_EMPTY.as_bytes();
        canonical.validate().expect("canonical rotated order");
        shared.replication_order.canonical_order =
            norito::to_bytes(&canonical).expect("encode rotated order");
        shared.replication_order.assignment_revision = 2;
        let revised = shared.clone();
        next.providers
            .iter_mut()
            .find(|provider| provider.provider_id == PROVIDER_B)
            .expect("provider B")
            .orders
            .clear();
        next.providers
            .iter_mut()
            .find(|provider| provider.provider_id == PROVIDER_EMPTY)
            .expect("replacement provider")
            .orders
            .push(revised);
        archive
            .insert(next.clone())
            .expect("insert rotated assignment");
        let current = archive
            .read_provider_assignment(&next.key, PROVIDER_A, order_id)
            .expect("current assignment");
        assert_eq!(
            current.source_provider_ids,
            vec![*PROVIDER_EMPTY.as_bytes()]
        );
        assert_eq!(
            current
                .assignment
                .as_ref()
                .map(|row| row.expected_assignment_revision),
            Some(2)
        );
        assert_eq!(
            archive
                .read_provider_assignment(&next.key, PROVIDER_B, order_id)
                .expect("removed provider")
                .assignment,
            None
        );
        assert_eq!(
            archive
                .read_provider_assignment(&first.key, PROVIDER_A, order_id)
                .expect("historical assignment"),
            old
        );
    }
    #[test]
    fn exact_assignment_lookup_reaches_beyond_thousand_row_page_limit() {
        let directory = physical_tempdir().expect("archive tempdir");
        let large_bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            8 * 1024 * 1024,
            2,
            16 * 1024 * 1024,
            1,
            1_001,
            1_001,
            1_000,
        )
        .expect("large provider/order bounds");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), large_bounds)
                .expect("open archive");
        let base = archived_order(0x21, &[PROVIDER_A]);
        let canonical = validated_replication_order_from_record(
            &base.replication_order.order_id,
            &base.replication_order,
        )
        .expect("base canonical order");
        let mut orders = Vec::new();
        orders.try_reserve(1_001).expect("reserve bounded fixture");
        for index in 0..1_001u16 {
            let mut order = base.clone();
            let mut id = [0; 32];
            id[..2].copy_from_slice(&index.to_be_bytes());
            id[2] = 1;
            let mut encoded_order = canonical.clone();
            encoded_order.order_id = id;
            encoded_order.validate().expect("ordered fixture order");
            order.replication_order.order_id = ReplicationOrderId::new(id);
            order.replication_order.canonical_order =
                norito::to_bytes(&encoded_order).expect("encode fixture order");
            orders.push(order);
        }
        let key = key(7);
        archive
            .insert(ProviderIngestFinalizedProjectionV1 {
                key,
                providers: vec![ProviderIngestFinalizedProviderProjectionV1 {
                    provider_id: PROVIDER_A,
                    expected_owner: Some(account(0x11)),
                    expected_authority: Some(completion_authority(0x11, policy(0xA1, 1))),
                    orders,
                }],
            })
            .expect("insert 1,001 canonical orders");
        let first_page = archive
            .read_provider_page(&key, PROVIDER_A, None, 1_000)
            .expect("read maximum page");
        assert_eq!(first_page.rows.len(), 1_000);
        assert!(first_page.next_cursor.is_some());
        let mut final_id = [0; 32];
        final_id[..2].copy_from_slice(&1_000u16.to_be_bytes());
        final_id[2] = 1;
        let direct = archive
            .read_provider_assignment(&key, PROVIDER_A, ReplicationOrderId::new(final_id))
            .expect("read beyond maximum page directly");
        assert_eq!(direct.provider_state_root, first_page.provider_state_root);
        assert_eq!(
            direct
                .assignment
                .as_ref()
                .map(|row| row.replication_order.order_id),
            Some(ReplicationOrderId::new(final_id))
        );
        assert!(direct.source_provider_ids.is_empty());
    }
    include!("provider_ingest_finalized/musubi_archive_binding_tests.rs");
    #[test]
    fn complete_namespace_empty_check_rejects_any_record() {
        let directory = physical_tempdir().expect("create archive directory");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(directory.path().join("archive"), bounds())
                .expect("open archive");
        assert!(archive.is_empty().expect("inspect empty archive"));
        archive.insert(projection(1)).expect("insert projection");
        assert!(!archive.is_empty().expect("inspect populated archive"));
    }
    #[test]
    fn pre_release_archive_state_root_is_not_accepted_by_first_release_layout() {
        let projection = projection(7);
        let pre_release_root = canonical_domain_digest(
            b"iroha.sorafs.provider-ingest.finalized-provider-state.v1\0",
            &projection.providers,
        )
        .expect("pre-release root fixture");
        let first_release_root =
            provider_state_root(&projection.providers).expect("first-release root");
        assert_ne!(pre_release_root, first_release_root);
        let directory = physical_tempdir().expect("archive record directory");
        let path = directory.path().join("pre-release-root-record.norito");
        let record = ProviderIngestFinalizedArchiveRecordV1::try_new(
            ProviderIngestFinalizedArchiveRecordMaterialV1 {
                version: ARCHIVE_VERSION_V1,
                key: projection.key.clone(),
                predecessor: None,
                deltas: build_provider_deltas(None, &projection),
                provider_state_root: pre_release_root,
            },
        )
        .expect("pre-release state root still forms a self-consistent outer record");
        let bytes = encode_bounded_record(&record, bounds()).expect("encode record fixture");
        fs::write(&path, &bytes).expect("write record fixture");
        let mut index = ArchiveIndexV1::default();
        index.by_height.insert(
            (projection.key.network_id, projection.key.height),
            ArchiveRecordEntryV1 {
                record,
                path,
                canonical_bytes: bounded_bytes_len(&bytes),
            },
        );
        assert!(matches!(
            reconstruct_projection(&index, &projection.key, bounds()),
            Err(ProviderIngestFinalizedArchiveErrorV1::ProviderStateRootMismatch)
        ));
    }
    fn advance_projection(
        previous: &ProviderIngestFinalizedProjectionV1,
        height: u64,
    ) -> ProviderIngestFinalizedProjectionV1 {
        let mut next = previous.clone();
        next.key = key(height);
        next
    }
    fn archive_root(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().join("provider-ingest-finalized")
    }
    fn retention_fence(
        key: ProviderIngestFinalizedArchiveKeyV1,
        expected_archive_generation: u64,
    ) -> ProviderIngestFinalizedArchiveRetentionFenceV1 {
        ProviderIngestFinalizedArchiveRetentionFenceV1::try_new(
            key,
            [0xD7; 32],
            expected_archive_generation,
        )
        .expect("valid test retention fence")
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
        qualification: ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
        latest: Mutex<Option<ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>>,
        behavior: Mutex<TestRetentionCasBehavior>,
        competing: Mutex<Option<ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>>,
    }
    impl TestRetentionAuthority {
        fn new() -> Self {
            Self {
                handle: "sealed://sorafs/provider-ingest/archive-retention-primary".to_owned(),
                qualification: ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1::new(
                    7, [0xA7; 32],
                ),
                latest: Mutex::new(None),
                behavior: Mutex::new(TestRetentionCasBehavior::Apply),
                competing: Mutex::new(None),
            }
        }
        fn binding(&self) -> ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1 {
            ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1::try_new(
                self.handle.clone(),
                self.qualification.revision(),
                self.qualification.policy_digest(),
            )
            .expect("valid test retention authority binding")
        }
        fn set_behavior(&self, behavior: TestRetentionCasBehavior) {
            *self.behavior.lock().expect("lock CAS behavior") = behavior;
        }
        fn set_competing(&self, record: ProviderIngestFinalizedArchiveRetentionApprovalRecordV1) {
            *self.competing.lock().expect("lock competing approval") = Some(record);
        }
    }
    impl ProviderIngestFinalizedArchiveRetentionAuthorityV1 for TestRetentionAuthority {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
            ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
        > {
            Ok(self.qualification)
        }
        fn load_latest(
            &self,
            _network_id: &NetworkId,
        ) -> Result<
            Option<ProviderIngestFinalizedArchiveRetentionApprovalRecordV1>,
            ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
        > {
            Ok(self.latest.lock().expect("lock latest approval").clone())
        }
        fn compare_and_swap_latest(
            &self,
            _network_id: &NetworkId,
            expected_revision: Option<[u8; 32]>,
            next: &ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
        ) -> Result<(), ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1> {
            let mut latest = self.latest.lock().expect("lock latest approval");
            if latest
                .as_ref()
                .map(ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::revision)
                != expected_revision
            {
                return Err(
                    ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected,
                );
            }
            match *self.behavior.lock().expect("lock CAS behavior") {
                TestRetentionCasBehavior::Apply => {
                    *latest = Some(next.clone());
                    Ok(())
                }
                TestRetentionCasBehavior::ApplyAmbiguous => {
                    *latest = Some(next.clone());
                    Err(ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1::Ambiguous)
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
    fn prepared_compaction_for_test(
        archive: &ProviderIngestFinalizedArchiveV1,
        target: ProviderIngestFinalizedArchiveKeyV1,
    ) -> (
        ProviderIngestFinalizedArchiveRetentionFenceV1,
        PreparedArchiveCompactionV1,
        ProviderIngestFinalizedArchiveCompactionProposalV1,
    ) {
        let index = archive.read_index().expect("lock archive for preparation");
        let fence = retention_fence(target, index.generation);
        let prepared =
            prepare_archive_compaction(&index, &fence, archive.bounds).expect("prepare compaction");
        let proposal = compaction_proposal(&prepared, &fence).expect("digest proposal");
        (fence, prepared, proposal)
    }
    #[cfg(unix)]
    fn compact_for_test(
        archive: &ProviderIngestFinalizedArchiveV1,
        key: ProviderIngestFinalizedArchiveKeyV1,
    ) -> ProviderIngestFinalizedArchiveCompactionOutcomeV1 {
        let mut index = archive.write_index().expect("lock archive for compaction");
        let fence = retention_fence(key, index.generation);
        archive
            .compact_prefix_locked(&mut index, &fence, || {}, |_| {})
            .expect("compact authenticated test prefix")
    }
    #[cfg(unix)]
    fn candidate_for_prepared_compaction(
        archive: &ProviderIngestFinalizedArchiveV1,
        prepared: &PreparedArchiveCompactionV1,
    ) -> ArchiveVirtualBaseV1 {
        ArchiveVirtualBaseV1 {
            checkpoint: prepared.checkpoint.clone(),
            path: archive
                .checkpoints
                .join(checkpoint_file_name(prepared.checkpoint.checkpoint_digest)),
            canonical_bytes: bounded_bytes_len(&prepared.canonical_bytes),
        }
    }
    #[cfg(unix)]
    fn publish_prepared_checkpoint_for_test(
        archive: &ProviderIngestFinalizedArchiveV1,
        prepared: &PreparedArchiveCompactionV1,
    ) -> PathBuf {
        let candidate = candidate_for_prepared_compaction(archive, prepared);
        publish_immutable_bytes(
            &archive.checkpoints,
            archive.checkpoints_identity,
            &candidate.path,
            &prepared.canonical_bytes,
        )
        .expect("publish test checkpoint");
        candidate.path
    }
    #[cfg(unix)]
    fn archive_namespace_snapshot(directory: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(directory)
            .expect("read archive namespace")
            .map(|entry| {
                let entry = entry.expect("read archive namespace entry");
                (
                    entry
                        .file_name()
                        .into_string()
                        .expect("archive filename must be UTF-8"),
                    fs::read(entry.path()).expect("read archive namespace bytes"),
                )
            })
            .collect()
    }
    #[cfg(unix)]
    include!("provider_ingest_finalized/retention_inventory_tests.rs");
    include!("provider_ingest_finalized/archive_codec_tests.rs");
    #[cfg(unix)]
    #[test]
    fn virtual_base_preserves_floor_pages_cursors_and_successor_bytes() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
        let first = projection(7);
        let second = advance_projection(&first, 8);
        let third = advance_projection(&second, 9);
        archive.insert(first.clone()).expect("insert first");
        archive.insert(second.clone()).expect("insert second");
        archive.insert(third.clone()).expect("insert third");
        let page_before = archive
            .read_provider_page(&second.key, PROVIDER_A, None, 1)
            .expect("page before compaction");
        let page_before_bytes = norito::to_bytes(&page_before).expect("encode exact page");
        let cursor_before = page_before.next_cursor.as_ref().expect("page cursor");
        let cursor_before_bytes = norito::to_bytes(cursor_before).expect("encode exact cursor");
        let continuation_before = archive
            .read_provider_page(&second.key, PROVIDER_A, Some(cursor_before), 1)
            .expect("continuation before compaction");
        let continuation_before_bytes =
            norito::to_bytes(&continuation_before).expect("encode exact continuation");
        let successor_path = archive.record_path(&third.key).expect("successor path");
        let successor_before = fs::read(&successor_path).expect("read successor");
        let outcome = compact_for_test(&archive, second.key.clone());
        assert_eq!(outcome.pruned_entries(), 2);
        assert_eq!(outcome.generation(), 3);
        assert!(
            !archive
                .record_path(&first.key)
                .expect("first path")
                .exists()
        );
        assert!(
            !archive
                .record_path(&second.key)
                .expect("second path")
                .exists()
        );
        assert_eq!(
            fs::read(&successor_path).expect("read retained successor"),
            successor_before,
            "the successor predecessor commitment must never be rewritten"
        );
        let page_after = archive
            .read_provider_page(&second.key, PROVIDER_A, None, 1)
            .expect("page from virtual base");
        assert_eq!(
            norito::to_bytes(&page_after).expect("encode compacted page"),
            page_before_bytes
        );
        assert_eq!(
            norito::to_bytes(page_after.next_cursor.as_ref().expect("compacted cursor"))
                .expect("encode compacted cursor"),
            cursor_before_bytes
        );
        assert_eq!(
            norito::to_bytes(
                &archive
                    .read_provider_page(&second.key, PROVIDER_A, Some(cursor_before), 1)
                    .expect("pre-compaction cursor remains valid")
            )
            .expect("encode compacted continuation"),
            continuation_before_bytes
        );
        assert_eq!(
            archive
                .insert(second.clone())
                .expect("exact virtual-base replay"),
            ProviderIngestFinalizedArchiveInsertOutcomeV1::ExactReplay
        );
        assert!(matches!(
            archive.resolve_exact_key(
                &first.key.network_id,
                first.key.height,
                first.key.block_hash
            ),
            Err(ProviderIngestFinalizedArchiveErrorV1::BelowRetentionFloor {
                requested_height: 7,
                retention_height: 8
            })
        ));
        drop(archive);
        assert!(matches!(
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()),
            Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRequired)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn compaction_reclaims_entry_capacity_without_crossing_the_fence() {
        let directory = physical_tempdir().expect("archive tempdir");
        let tight_bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            3,
            32 * 1024 * 1024,
            16,
            16,
            64,
            1,
        )
        .expect("tight bounds");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), tight_bounds)
                .expect("open archive");
        let first = projection(7);
        let second = advance_projection(&first, 8);
        let third = advance_projection(&second, 9);
        let fourth = advance_projection(&third, 10);
        archive.insert(first.clone()).expect("insert first");
        archive.insert(second.clone()).expect("insert second");
        archive.insert(third.clone()).expect("insert third");
        assert!(matches!(
            archive.insert(fourth.clone()),
            Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveCapacityExceeded { .. })
        ));
        let stale_fence = retention_fence(second.key.clone(), 2);
        {
            let mut index = archive.write_index().expect("lock archive");
            assert!(matches!(
                archive.compact_prefix_locked(&mut index, &stale_fence, || {}, |_| {}),
                Err(
                    ProviderIngestFinalizedArchiveErrorV1::RetentionFenceGenerationMismatch {
                        expected: 2,
                        observed: 3
                    }
                )
            ));
        }
        let missing_fence = retention_fence(
            fourth.key.clone(),
            archive.health_generation().expect("archive generation"),
        );
        {
            let mut index = archive.write_index().expect("lock archive");
            assert!(matches!(
                archive.compact_prefix_locked(&mut index, &missing_fence, || {}, |_| {}),
                Err(ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor { height: 10, .. })
            ));
        }
        assert!(
            archive
                .record_path(&first.key)
                .expect("first path")
                .exists()
        );
        let outcome = compact_for_test(&archive, second.key.clone());
        assert_eq!(outcome.pruned_entries(), 2);
        assert!(outcome.pruned_bytes() > 0);
        archive
            .insert(fourth.clone())
            .expect("reclaimed capacity accepts exact successor");
        assert_eq!(
            archive
                .resolve_exact_key(
                    &third.key.network_id,
                    third.key.height,
                    third.key.block_hash
                )
                .expect("retained suffix"),
            third.key
        );
    }
    #[cfg(unix)]
    #[test]
    fn repeated_compaction_preserves_generation_and_checkpoint_lineage() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        let second = advance_projection(&first, 8);
        let third = advance_projection(&second, 9);
        let fourth = advance_projection(&third, 10);
        archive.insert(first).expect("insert first");
        archive.insert(second.clone()).expect("insert second");
        archive.insert(third.clone()).expect("insert third");
        let outcome = compact_for_test(&archive, second.key.clone());
        archive.insert(fourth).expect("insert exact successor");
        let first_checkpoint_digest = outcome.checkpoint_digest();
        let advanced = compact_for_test(&archive, third.key.clone());
        assert_eq!(advanced.pruned_entries(), 3);
        assert_eq!(advanced.generation(), 4);
        let index = archive.read_index().expect("read repeated compaction");
        let base = index
            .virtual_bases
            .get(&third.key.network_id)
            .expect("advanced virtual base");
        assert_eq!(
            base.checkpoint.material.prior_checkpoint_digest,
            Some(first_checkpoint_digest)
        );
        drop(index);
        assert_eq!(
            fs::read_dir(archive_root(&directory).join(CHECKPOINTS_DIRECTORY))
                .expect("read checkpoint namespace")
                .count(),
            1,
            "successful compaction must remove the superseded checkpoint"
        );
        assert!(matches!(
            archive.resolve_exact_key(
                &second.key.network_id,
                second.key.height,
                second.key.block_hash
            ),
            Err(ProviderIngestFinalizedArchiveErrorV1::BelowRetentionFloor {
                requested_height: 8,
                retention_height: 9
            })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn manual_reopen_never_installs_or_finishes_checkpoint_crash_cleanup() {
        for crash_after_first_unlink in [false, true] {
            let directory = physical_tempdir().expect("archive tempdir");
            let root = archive_root(&directory);
            let archive =
                ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
            let first = projection(7);
            let second = advance_projection(&first, 8);
            let third = advance_projection(&second, 9);
            archive.insert(first.clone()).expect("insert first");
            archive.insert(second.clone()).expect("insert second");
            archive.insert(third.clone()).expect("insert third");
            let fence = retention_fence(
                second.key.clone(),
                archive.health_generation().expect("archive generation"),
            );
            let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut index = archive.write_index().expect("lock archive");
                if crash_after_first_unlink {
                    let _ = archive
                        .compact_prefix_locked(
                            &mut index,
                            &fence,
                            || {},
                            |position| {
                                if position == 0 {
                                    panic!("simulated crash during prefix cleanup");
                                }
                            },
                        )
                        .expect("crash hook must interrupt compaction");
                } else {
                    let _ = archive
                        .compact_prefix_locked(
                            &mut index,
                            &fence,
                            || panic!("simulated crash after checkpoint publication"),
                            |_| {},
                        )
                        .expect("crash hook must interrupt compaction");
                }
            }));
            assert!(crashed.is_err());
            drop(archive);
            let remaining_before = fs::read_dir(root.join(RECORDS_DIRECTORY))
                .expect("read interrupted records")
                .count();
            assert!(matches!(
                ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()),
                Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRequired)
            ));
            assert_eq!(
                fs::read_dir(root.join(RECORDS_DIRECTORY))
                    .expect("re-read interrupted records")
                    .count(),
                remaining_before,
                "manual startup must not continue prefix cleanup"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn tampered_virtual_predecessor_digest_is_rejected_on_reopen() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
        let first = projection(7);
        let second = advance_projection(&first, 8);
        let third = advance_projection(&second, 9);
        archive.insert(first).expect("insert first");
        archive.insert(second.clone()).expect("insert second");
        archive.insert(third).expect("insert third");
        let _ = compact_for_test(&archive, second.key);
        let checkpoint_path = archive
            .read_index()
            .expect("read archive index")
            .virtual_bases
            .values()
            .next()
            .expect("virtual base")
            .path
            .clone();
        let mut checkpoint =
            load_checkpoint_at(&checkpoint_path, bounds()).expect("load checkpoint");
        drop(archive);
        checkpoint.material.original_terminal_record_digest = [0xE1; 32];
        checkpoint.checkpoint_digest =
            canonical_domain_digest(CHECKPOINT_DIGEST_DOMAIN_V1, &checkpoint.material)
                .expect("recompute content digest");
        checkpoint
            .validate(bounds())
            .expect("self-consistent tamper");
        let substituted_path = root
            .join(CHECKPOINTS_DIRECTORY)
            .join(checkpoint_file_name(checkpoint.checkpoint_digest));
        fs::remove_file(&checkpoint_path).expect("remove original checkpoint");
        fs::write(
            &substituted_path,
            norito::to_bytes(&checkpoint).expect("encode substituted checkpoint"),
        )
        .expect("write substituted checkpoint");
        assert!(matches!(
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()),
            Err(ProviderIngestFinalizedArchiveErrorV1::RetentionAuthorityRequired)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn compacted_policy_and_order_history_remain_monotonic() {
        let policy_directory = physical_tempdir().expect("policy archive tempdir");
        let policy_archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&policy_directory), bounds())
                .expect("open policy archive");
        let first = projection(7);
        policy_archive
            .insert(first.clone())
            .expect("insert policy floor");
        let mut replacement = advance_projection(&first, 8);
        replacement.providers[0].expected_authority =
            Some(completion_authority(0x11, policy(0xC1, 1)));
        policy_archive
            .insert(replacement.clone())
            .expect("insert policy replacement");
        let _ = compact_for_test(&policy_archive, replacement.key.clone());
        let mut cycled = advance_projection(&replacement, 9);
        cycled.providers[0].expected_authority = Some(completion_authority(0x11, policy(0xA1, 1)));
        assert!(matches!(
            policy_archive.insert(cycled),
            Err(
                ProviderIngestFinalizedArchiveErrorV1::AuthoritySubstitution {
                    provider_id: PROVIDER_A
                }
            )
        ));
        let order_directory = physical_tempdir().expect("order archive tempdir");
        let order_archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&order_directory), bounds())
                .expect("open order archive");
        let target = ReplicationOrderId::new([0x22; 32]);
        let mut order_floor = projection(7);
        for provider in &mut order_floor.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    set_order_window(archived, 1, 7, 6);
                }
            }
        }
        order_archive
            .insert(order_floor.clone())
            .expect("insert order floor");
        let mut terminal = advance_projection(&order_floor, 8);
        for provider in &mut terminal.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    archived.replication_order.status = ReplicationOrderStatus::Expired(8);
                }
            }
        }
        order_archive
            .insert(terminal.clone())
            .expect("terminalize order");
        let mut removed = advance_projection(&terminal, 9);
        let removed_order = removed.providers[0]
            .orders
            .iter()
            .find(|order| order.order_id() == target)
            .expect("terminal order")
            .clone();
        removed.providers[0]
            .orders
            .retain(|order| order.order_id() != target);
        order_archive
            .insert(removed.clone())
            .expect("remove terminal order");
        let _ = compact_for_test(&order_archive, removed.key.clone());
        let mut reappeared = advance_projection(&removed, 10);
        reappeared.providers[0].orders.push(removed_order);
        assert!(matches!(
            order_archive.insert(reappeared),
            Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution {
                order_id
            }) if order_id == target
        ));
    }
    #[test]
    fn outer_record_decoder_accepts_domain_valid_large_canonical_order_fields() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        let mut first = projection(7);
        let target = ReplicationOrderId::new([0x22; 32]);
        for provider in &mut first.providers {
            for archived in &mut provider.orders {
                if archived.order_id() != target {
                    continue;
                }
                let mut canonical = validated_replication_order_from_record(
                    &archived.replication_order.order_id,
                    &archived.replication_order,
                )
                .expect("decode canonical order");
                canonical.metadata = vec![CapacityMetadataEntry {
                    key: "large".to_owned(),
                    value: "x".repeat(2_048),
                }];
                canonical.validate().expect("large metadata remains valid");
                archived.replication_order.canonical_order =
                    norito::to_bytes(&canonical).expect("encode large canonical order");
            }
        }
        {
            let archive =
                ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
            archive
                .insert(first.clone())
                .expect("insert large canonical field");
        }
        let reopened =
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("reopen archive");
        assert_eq!(
            reopened
                .resolve_exact_key(
                    &first.key.network_id,
                    first.key.height,
                    first.key.block_hash
                )
                .expect("resolve reopened key"),
            first.key
        );
    }
    #[test]
    fn provider_reassignment_preserves_old_exact_index_and_removes_new_index() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert first");
        let shared_id = ReplicationOrderId::new([0x21; 32]);
        let mut reassigned = advance_projection(&first, 8);
        reassigned
            .providers
            .retain(|provider| provider.provider_id != PROVIDER_B);
        let provider_a = reassigned
            .providers
            .iter_mut()
            .find(|provider| provider.provider_id == PROVIDER_A)
            .expect("provider A");
        let shared = provider_a
            .orders
            .iter_mut()
            .find(|order| order.order_id() == shared_id)
            .expect("shared order");
        let mut canonical = validated_replication_order_from_record(
            &shared.replication_order.order_id,
            &shared.replication_order,
        )
        .expect("decode shared order");
        canonical.assignments[1].provider_id = *PROVIDER_EMPTY.as_bytes();
        shared.replication_order.canonical_order =
            norito::to_bytes(&canonical).expect("re-encode reassigned order");
        shared.replication_order.assignment_revision = 2;
        let revised_shared = shared.clone();
        let provider_empty = reassigned
            .providers
            .iter_mut()
            .find(|provider| provider.provider_id == PROVIDER_EMPTY)
            .expect("replacement provider");
        provider_empty.orders.push(revised_shared);
        archive
            .insert(reassigned.clone())
            .expect("insert provider reassignment");
        assert_eq!(
            archive
                .read_provider_page(&first.key, PROVIDER_B, None, 1)
                .expect("old provider index")
                .rows
                .len(),
            1
        );
        assert!(
            archive
                .read_provider_page(&reassigned.key, PROVIDER_B, None, 1)
                .expect("removed provider index")
                .rows
                .is_empty()
        );
        assert_eq!(
            archive
                .read_provider_page(&reassigned.key, PROVIDER_EMPTY, None, 1)
                .expect("replacement provider index")
                .rows[0]
                .replication_order
                .order_id,
            shared_id
        );
    }
    #[test]
    fn below_floor_fork_gap_cursor_substitution_and_replay_conflict_fail_closed() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert first");
        assert!(matches!(
            archive.resolve_exact_key(&first.key.network_id, 6, key(6).block_hash),
            Err(
                ProviderIngestFinalizedArchiveErrorV1::BelowActivationFloor {
                    requested_height: 6,
                    activation_height: 7
                }
            )
        ));
        assert!(matches!(
            archive.resolve_exact_key(&first.key.network_id, 7, [0xF7; 32]),
            Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork { .. })
        ));
        assert!(matches!(
            archive.resolve_exact_key(&first.key.network_id, 8, key(8).block_hash),
            Err(ProviderIngestFinalizedArchiveErrorV1::UnknownExactAnchor { .. })
        ));
        assert!(matches!(
            archive.read_provider_page(&key(6), PROVIDER_A, None, 1),
            Err(
                ProviderIngestFinalizedArchiveErrorV1::BelowActivationFloor {
                    requested_height: 6,
                    activation_height: 7
                }
            )
        ));
        let gap = advance_projection(&first, 9);
        assert!(matches!(
            archive.insert(gap.clone()),
            Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveCoverageGap {
                missing_height: 8,
                observed_height: 9,
                ..
            })
        ));
        let second = advance_projection(&first, 8);
        archive.insert(second.clone()).expect("insert successor");
        let mut second_gap = advance_projection(&second, 10);
        second_gap.key.block_hash = [0xEE; 32];
        assert!(matches!(
            archive.insert(second_gap),
            Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveCoverageGap {
                missing_height: 9,
                observed_height: 10,
                ..
            })
        ));
        let mut fork = second.clone();
        fork.key.block_hash = [0xF8; 32];
        assert!(matches!(
            archive.insert(fork),
            Err(ProviderIngestFinalizedArchiveErrorV1::FinalizedFork { .. })
        ));
        let first_page = archive
            .read_provider_page(&second.key, PROVIDER_A, None, 1)
            .expect("first page");
        let mut substituted = first_page.next_cursor.expect("cursor");
        substituted.provider_id = PROVIDER_B;
        assert!(matches!(
            archive.read_provider_page(&second.key, PROVIDER_A, Some(&substituted), 1),
            Err(ProviderIngestFinalizedArchiveErrorV1::CursorSubstitution)
        ));
        let mut conflict = second.clone();
        conflict.providers[0].expected_owner = Some(account(0x77));
        let authority = conflict.providers[0].expected_authority.as_mut().unwrap();
        authority.provider_owner = account(0x77);
        authority.completion_signer = account(0x77);
        assert!(matches!(
            archive.insert(conflict),
            Err(ProviderIngestFinalizedArchiveErrorV1::ConflictingProjection { .. })
        ));
    }
    #[test]
    fn authority_assignment_and_owner_substitution_transitions_are_rejected() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert first");
        let mut rollback = advance_projection(&first, 8);
        rollback.providers[0].expected_authority = Some(completion_authority(
            0x11,
            ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [0xA1; 32],
                revision: 2,
                predecessor_digest: Some([0xFE; 32]),
                policy_digest: [2; 32],
            },
        ));
        assert!(matches!(
            archive.insert(rollback),
            Err(ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                provider_id: PROVIDER_A
            })
        ));
        let mut owner_substitution = advance_projection(&first, 8);
        owner_substitution.providers[0].expected_owner = Some(account(0x66));
        assert!(matches!(
            archive.insert(owner_substitution),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
        let mut assignment_rollback = advance_projection(&first, 8);
        for provider in &mut assignment_rollback.providers {
            for order in &mut provider.orders {
                order.replication_order.assignment_revision = 2;
            }
        }
        assert!(matches!(
            archive.insert(assignment_rollback),
            Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution { .. })
                | Err(ProviderIngestFinalizedArchiveErrorV1::AssignmentRollback { .. })
                | Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
        let mut valid_rotation = advance_projection(&first, 8);
        valid_rotation.providers[0].expected_authority =
            Some(completion_authority(0x11, policy(0xA1, 2)));
        archive
            .insert(valid_rotation)
            .expect("exact predecessor-bound signer rotation");
    }
    #[test]
    fn activation_floor_accepts_current_policy_revision_without_claiming_prior_history() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let mut floor = projection(7);
        floor.providers[0].expected_authority = Some(completion_authority(0x11, policy(0xA1, 5)));
        archive
            .insert(floor.clone())
            .expect("insert explicit mid-history activation floor");
        let mut successor = advance_projection(&floor, 8);
        successor.providers[0].expected_authority =
            Some(completion_authority(0x11, policy(0xA1, 6)));
        archive
            .insert(successor)
            .expect("insert exact successor to floor policy");
    }
    #[test]
    fn assignment_revision_cannot_substitute_non_assignment_order_fields() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert first");
        let target = ReplicationOrderId::new([0x22; 32]);
        let mut revised = advance_projection(&first, 8);
        for provider in &mut revised.providers {
            for archived in &mut provider.orders {
                if archived.order_id() != target {
                    continue;
                }
                let mut canonical = validated_replication_order_from_record(
                    &archived.replication_order.order_id,
                    &archived.replication_order,
                )
                .expect("decode canonical order");
                canonical.assignments[0].slice_gib = 2;
                archived.replication_order.canonical_order =
                    norito::to_bytes(&canonical).expect("re-encode revised order");
                archived.replication_order.assignment_revision = 2;
            }
        }
        archive
            .insert(revised.clone())
            .expect("assignment-only revision");
        let mut substituted = advance_projection(&revised, 9);
        for provider in &mut substituted.providers {
            for archived in &mut provider.orders {
                if archived.order_id() != target {
                    continue;
                }
                let mut canonical = validated_replication_order_from_record(
                    &archived.replication_order.order_id,
                    &archived.replication_order,
                )
                .expect("decode canonical order");
                canonical.assignments[0].slice_gib = 3;
                canonical.sla.ingest_deadline_secs = 11;
                archived.replication_order.canonical_order =
                    norito::to_bytes(&canonical).expect("re-encode revised order");
                archived.replication_order.assignment_revision = 3;
            }
        }
        assert!(matches!(
            archive.insert(substituted),
            Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution {
                order_id
            }) if order_id == target
        ));
    }
    #[test]
    fn terminal_order_identity_cannot_reappear_after_removal() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let target = ReplicationOrderId::new([0x22; 32]);
        let mut first = projection(7);
        for provider in &mut first.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    set_order_window(archived, 1, 7, 6);
                }
            }
        }
        archive.insert(first.clone()).expect("insert first");
        let mut terminal = advance_projection(&first, 8);
        for provider in &mut terminal.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    archived.replication_order.status = ReplicationOrderStatus::Expired(8);
                }
            }
        }
        archive.insert(terminal.clone()).expect("terminalize order");
        let mut removed = advance_projection(&terminal, 9);
        let removed_order = removed.providers[0]
            .orders
            .iter()
            .find(|order| order.order_id() == target)
            .expect("terminal order")
            .clone();
        removed.providers[0]
            .orders
            .retain(|order| order.order_id() != target);
        archive
            .insert(removed.clone())
            .expect("remove terminal order");
        let mut reappeared = advance_projection(&removed, 10);
        reappeared.providers[0].orders.push(removed_order);
        assert!(matches!(
            archive.insert(reappeared),
            Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution {
                order_id
            }) if order_id == target
        ));
    }
    #[test]
    fn expired_order_cannot_append_provider_completion() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let target = ReplicationOrderId::new([0x21; 32]);
        let mut first = projection(7);
        for provider in &mut first.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    set_order_window(archived, 1, 7, 6);
                }
            }
        }
        archive.insert(first.clone()).expect("insert first");
        let mut expired = advance_projection(&first, 8);
        for provider in &mut expired.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    archived.replication_order.status = ReplicationOrderStatus::Expired(8);
                }
            }
        }
        archive
            .insert(expired.clone())
            .expect("insert valid expiration");
        let retained_completion = ReplicationOrderCompletionRecord {
            provider_id: PROVIDER_A,
            completed_by: account(0x11),
            completion_epoch: 7,
            assignment_revision: 1,
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                account(0x11).clone(),
                account(0x11),
                policy(0xA1, 1),
            ),
            finalized_anchor: key(7).finalized_anchor(),
        };
        let mut appended = advance_projection(&expired, 9);
        for provider in &mut appended.providers {
            for archived in &mut provider.orders {
                if archived.order_id() == target {
                    archived
                        .replication_order
                        .provider_completions
                        .push(retained_completion.clone());
                }
            }
        }
        assert!(matches!(
            archive.insert(appended),
            Err(ProviderIngestFinalizedArchiveErrorV1::CompletionRollback {
                order_id
            }) if order_id == target
        ));
    }
    #[test]
    fn invalid_expiration_epoch_is_rejected_at_activation_floor() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let mut malformed = projection(7);
        for provider in &mut malformed.providers {
            for archived in &mut provider.orders {
                archived.replication_order.status = ReplicationOrderStatus::Expired(7);
            }
        }
        assert!(matches!(
            archive.insert(malformed),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
    }
    #[test]
    fn canonical_order_timestamps_must_match_archived_record_epochs() {
        let mut shortened = archived_order(0x23, &[PROVIDER_A]);
        set_order_window(&mut shortened, 1, 7, 6);
        let canonical = validated_replication_order_from_record(
            &shortened.replication_order.order_id,
            &shortened.replication_order,
        )
        .expect("fixture deadline and canonical payload agree");
        assert_eq!(canonical.deadline_at, 7);
        assert_eq!(shortened.replication_order.deadline_epoch, 7);
        assert_eq!(canonical.issued_at, 1);
        assert_eq!(canonical.sla.ingest_deadline_secs, 6);
        assert_eq!(
            u64::from(canonical.sla.ingest_deadline_secs),
            canonical.deadline_at - canonical.issued_at
        );
        let mut excessive_sla = canonical.clone();
        excessive_sla.sla.ingest_deadline_secs = 7;
        assert!(matches!(
            excessive_sla.validate(),
            Err(sorafs_manifest::capacity::ReplicationOrderValidationError::SlaExceedsOrderWindow)
        ));
        validate_archived_order(&key(7), PROVIDER_A, &shortened)
            .expect("the shortened pending fixture remains valid at its deadline");

        let mut issued_mismatch = archived_order(0x23, &[PROVIDER_A]).replication_order;
        issued_mismatch.issued_epoch = issued_mismatch.issued_epoch.saturating_add(1);
        assert!(matches!(
            validated_replication_order_from_record(&issued_mismatch.order_id, &issued_mismatch),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));

        let mut deadline_mismatch = archived_order(0x23, &[PROVIDER_A]).replication_order;
        deadline_mismatch.deadline_epoch = deadline_mismatch.deadline_epoch.saturating_sub(1);
        assert!(matches!(
            validated_replication_order_from_record(
                &deadline_mismatch.order_id,
                &deadline_mismatch
            ),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
    }
    #[test]
    fn lifecycle_validation_uses_finalized_unix_seconds_instead_of_height() {
        let completion_key = ProviderIngestFinalizedArchiveKeyV1::try_new(
            test_network_id(0x31),
            7,
            [7; 32],
            900_999,
        )
        .expect("valid completion key");
        let completed_by = account(0x11);
        let mut completed = archived_order(0x23, &[PROVIDER_A]);
        completed.replication_order.provider_completions = vec![ReplicationOrderCompletionRecord {
            provider_id: PROVIDER_A,
            completed_by: completed_by.clone(),
            completion_epoch: 900,
            assignment_revision: 1,
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                completed_by.clone(),
                completed_by,
                policy(0xA1, 1),
            ),
            finalized_anchor: completion_key.finalized_anchor(),
        }];
        completed.replication_order.status = ReplicationOrderStatus::Completed(900);
        validate_archived_order(&completion_key, PROVIDER_A, &completed)
            .expect("completion time may exceed the unrelated block height");

        let mut future_completion = completed.clone();
        future_completion.replication_order.provider_completions[0].completion_epoch = 901;
        future_completion.replication_order.status = ReplicationOrderStatus::Completed(901);
        assert!(matches!(
            validate_archived_order(&completion_key, PROVIDER_A, &future_completion),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));

        let expiration_key = ProviderIngestFinalizedArchiveKeyV1::try_new(
            test_network_id(0x31),
            7,
            [7; 32],
            1_001_999,
        )
        .expect("valid expiration key");
        let mut expired = archived_order(0x24, &[PROVIDER_A]);
        expired.replication_order.status = ReplicationOrderStatus::Expired(1_001);
        validate_archived_order(&expiration_key, PROVIDER_A, &expired)
            .expect("expiration time may exceed the unrelated block height");

        expired.replication_order.status = ReplicationOrderStatus::Expired(1_002);
        assert!(matches!(
            validate_archived_order(&expiration_key, PROVIDER_A, &expired),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
    }
    #[test]
    fn archived_completion_evidence_must_be_nondecreasing() {
        let completion_key = ProviderIngestFinalizedArchiveKeyV1::try_new(
            test_network_id(0x31),
            7,
            [7; 32],
            900_999,
        )
        .expect("valid completion key");
        let owner_a = account(0x11);
        let owner_b = account(0x22);
        let mut archived = archived_order(0x23, &[PROVIDER_A, PROVIDER_B]);
        archived.replication_order.provider_completions = vec![
            ReplicationOrderCompletionRecord {
                provider_id: PROVIDER_A,
                completed_by: owner_a.clone(),
                completion_epoch: 900,
                assignment_revision: 1,
                completion_authority: ProviderIngestCompletionAuthorityV1::new(
                    owner_a.clone(),
                    owner_a,
                    policy(0xA1, 1),
                ),
                finalized_anchor: completion_key.finalized_anchor(),
            },
            ReplicationOrderCompletionRecord {
                provider_id: PROVIDER_B,
                completed_by: owner_b.clone(),
                completion_epoch: 899,
                assignment_revision: 1,
                completion_authority: ProviderIngestCompletionAuthorityV1::new(
                    owner_b.clone(),
                    owner_b,
                    policy(0xB1, 1),
                ),
                finalized_anchor: completion_key.finalized_anchor(),
            },
        ];
        archived.replication_order.status = ReplicationOrderStatus::Completed(899);

        assert!(matches!(
            validate_archived_order(&completion_key, PROVIDER_A, &archived),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidProjection { .. })
        ));
    }
    #[test]
    fn pin_lifecycle_cannot_rollback_after_retirement() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let mut first = projection(7);
        for provider in &mut first.providers {
            for archived in &mut provider.orders {
                set_order_window(archived, 2, 7, 5);
            }
        }
        archive.insert(first.clone()).expect("insert first");
        let mut retired = advance_projection(&first, 8);
        for provider in &mut retired.providers {
            for archived in &mut provider.orders {
                archived.pin_manifest.retire(8, Some("retired".to_owned()));
                archived.replication_order.status = ReplicationOrderStatus::Expired(8);
            }
        }
        archive
            .insert(retired.clone())
            .expect("insert monotonic retirement");
        let mut substituted_approval = advance_projection(&retired, 9);
        for provider in &mut substituted_approval.providers {
            for archived in &mut provider.orders {
                archived.pin_manifest.approved_epoch = Some(2);
            }
        }
        substituted_approval
            .validate(bounds())
            .expect("substituted approval is locally valid before checking history");
        assert!(matches!(
            archive.insert(substituted_approval),
            Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution { .. })
        ));
        let mut rollback = advance_projection(&retired, 9);
        for provider in &mut rollback.providers {
            for archived in &mut provider.orders {
                archived.pin_manifest.approve(1, None);
            }
        }
        rollback
            .validate(bounds())
            .expect("approval rollback is locally valid before checking history");
        assert!(matches!(
            archive.insert(rollback),
            Err(ProviderIngestFinalizedArchiveErrorV1::OrderSubstitution { .. })
        ));
    }
    #[test]
    fn revoked_policy_identity_cannot_be_reused_at_an_old_revision() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert first");
        let mut revoked = advance_projection(&first, 8);
        revoked.providers[0].expected_authority = None;
        archive
            .insert(revoked.clone())
            .expect("record signer revocation");
        let mut reused = advance_projection(&revoked, 9);
        reused.providers[0].expected_authority = Some(completion_authority(0x11, policy(0xA1, 1)));
        assert!(matches!(
            archive.insert(reused),
            Err(ProviderIngestFinalizedArchiveErrorV1::AuthorityRollback {
                provider_id: PROVIDER_A
            })
        ));
        let mut successor = advance_projection(&revoked, 9);
        successor.providers[0].expected_authority =
            Some(completion_authority(0x11, policy(0xA1, 2)));
        archive
            .insert(successor)
            .expect("strict successor may reactivate a revoked policy identity");
    }
    #[test]
    fn replaced_policy_identity_cannot_cycle_back_to_an_old_identity() {
        let directory = physical_tempdir().expect("archive tempdir");
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(archive_root(&directory), bounds())
                .expect("open archive");
        let first = projection(7);
        archive.insert(first.clone()).expect("insert first");
        let mut replacement = advance_projection(&first, 8);
        replacement.providers[0].expected_authority =
            Some(completion_authority(0x11, policy(0xC1, 1)));
        archive
            .insert(replacement.clone())
            .expect("insert replacement policy identity");
        let mut cycled = advance_projection(&replacement, 9);
        cycled.providers[0].expected_authority = Some(completion_authority(0x11, policy(0xA1, 1)));
        assert!(matches!(
            archive.insert(cycled),
            Err(
                ProviderIngestFinalizedArchiveErrorV1::AuthoritySubstitution {
                    provider_id: PROVIDER_A
                }
            )
        ));
    }
    #[test]
    fn bounded_decode_rejects_allocation_bomb_without_panicking() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        {
            let archive = ProviderIngestFinalizedArchiveV1::try_open(&root, bounds())
                .expect("open empty archive");
            drop(archive);
        }
        let malicious = root
            .join(RECORDS_DIRECTORY)
            .join(format!("{}{RECORD_FILE_SUFFIX}", "a".repeat(64)));
        fs::write(&malicious, vec![0xFF; 1024]).expect("write bounded malicious record");
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds())
        }));
        assert!(outcome.is_ok(), "bounded decoder must not panic");
        assert!(outcome.expect("no panic").is_err());
    }
    #[test]
    fn corruption_is_rejected_before_archive_qualification() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        let first = projection(7);
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
        archive.insert(first.clone()).expect("insert projection");
        let path = archive.record_path(&first.key).expect("record path");
        let mut bytes = fs::read(&path).expect("read record");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x80;
        fs::write(&path, bytes).expect("corrupt record");
        let page_error = archive
            .read_provider_page(&first.key, PROVIDER_A, None, 1)
            .expect_err("corrupt page record");
        let direct_error = archive
            .read_provider_assignment(&first.key, PROVIDER_A, ReplicationOrderId::new([0x21; 32]))
            .expect_err("corrupt direct-lookup record");
        assert_eq!(
            std::mem::discriminant(&page_error),
            std::mem::discriminant(&direct_error),
            "direct lookup must retain the page reader's typed corruption error"
        );
        assert!(archive.activation_floor(&first.key.network_id).is_err());
        drop(archive);
        assert!(ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn crash_stage_recovery_accepts_only_one_canonical_link_peer() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        let first = projection(7);
        let canonical = {
            let archive =
                ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
            archive.insert(first.clone()).expect("insert projection");
            archive.record_path(&first.key).expect("record path")
        };
        let staged = root
            .join(RECORDS_DIRECTORY)
            .join(".staged-crash-after-link");
        fs::hard_link(&canonical, &staged).expect("simulate crash after immutable link");
        assert_eq!(
            fs::metadata(&canonical)
                .expect("canonical metadata")
                .nlink(),
            2
        );
        let reopened = ProviderIngestFinalizedArchiveV1::try_open(&root, bounds())
            .expect("recover linked stage");
        assert!(!staged.exists());
        assert_eq!(
            fs::metadata(&canonical)
                .expect("canonical metadata")
                .nlink(),
            1
        );
        assert_eq!(
            reopened
                .read_provider_page(&first.key, PROVIDER_A, None, 1)
                .expect("recovered page")
                .rows
                .len(),
            1
        );
    }
    #[cfg(unix)]
    #[test]
    fn hostile_staged_hardlink_is_rejected() {
        let directory = physical_tempdir().expect("archive tempdir");
        let external = physical_tempdir().expect("external tempdir");
        let root = archive_root(&directory);
        {
            let archive = ProviderIngestFinalizedArchiveV1::try_open(&root, bounds())
                .expect("open empty archive");
            drop(archive);
        }
        let external_file = external.path().join("outside");
        fs::write(&external_file, b"not an archive record").expect("write outside file");
        let staged = root.join(RECORDS_DIRECTORY).join(".staged-hostile-link");
        fs::hard_link(&external_file, &staged).expect("create hostile staged hardlink");
        assert!(ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).is_err());
    }
    #[test]
    fn archive_is_single_writer() {
        let directory = physical_tempdir().expect("archive tempdir");
        let root = archive_root(&directory);
        let first = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open first writer"),
        );
        assert!(matches!(
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()),
            Err(ProviderIngestFinalizedArchiveErrorV1::WriterBusy { .. })
        ));
        drop(first);
        ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("writer lock released");
    }
    #[cfg(unix)]
    #[test]
    fn writer_lock_path_substitution_fails_closed() {
        let directory = physical_tempdir().expect("archive tempdir");
        let displaced = physical_tempdir().expect("displaced lock tempdir");
        let root = archive_root(&directory);
        let archive =
            ProviderIngestFinalizedArchiveV1::try_open(&root, bounds()).expect("open archive");
        let lock_path = root.join(WRITER_LOCK_FILE);
        fs::rename(&lock_path, displaced.path().join("writer.lock"))
            .expect("displace owned writer lock");
        fs::write(&lock_path, b"").expect("substitute writer lock");
        assert!(matches!(
            archive.health_generation(),
            Err(ProviderIngestFinalizedArchiveErrorV1::InvalidStorage { .. })
        ));
    }
}
