//! Proof registry query helpers shared with Torii.
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    time::{Duration, Instant},
};

use crate::state::{State, WorldReadOnly};
use iroha_data_model::proof::{ProofId, ProofRecord, ProofStatus};
use mv::storage::StorageReadOnly;

/// Maximum ordered prefix a proof-list query may retain while paginating.
///
/// Proof listing uses offset pagination over a height-ordered registry. Keeping
/// this invariant in the query helper bounds memory independently of the total
/// number or encoded size of stored proof records.
pub const MAX_PROOF_QUERY_WINDOW: usize = 100_000;

/// Resource budget for one proof registry list or count query.
#[derive(Debug, Clone, Copy)]
pub struct ProofQueryBudget {
    deadline: Instant,
    max_window: usize,
}

impl ProofQueryBudget {
    /// Construct a budget whose deadline is relative to the current instant.
    #[must_use]
    pub fn for_timeout(timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            deadline: now.checked_add(timeout).unwrap_or(now),
            max_window: MAX_PROOF_QUERY_WINDOW,
        }
    }

    #[cfg(test)]
    fn with_max_window(timeout: Duration, max_window: usize) -> Self {
        let mut budget = Self::for_timeout(timeout);
        budget.max_window = max_window;
        budget
    }

    fn check_deadline(self) -> Result<(), ProofQueryError> {
        if Instant::now() >= self.deadline {
            Err(ProofQueryError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

/// Failure returned when a proof registry query exceeds its admitted work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofQueryError {
    /// The configured request deadline elapsed during registry traversal.
    #[error("proof registry query deadline exceeded")]
    DeadlineExceeded,
    /// The requested offset and page size require an excessive ordered prefix.
    #[error("proof registry query window {requested} exceeds maximum {maximum}")]
    WindowTooLarge {
        /// Requested ordered prefix size.
        requested: usize,
        /// Maximum admitted ordered prefix size.
        maximum: usize,
    },
}

/// Filters applied when querying proof records.
#[derive(Debug, Clone)]
pub struct ProofFilters<'a> {
    /// Restrict results to a specific backend (e.g., `halo2/ipa`).
    pub backend: Option<&'a str>,
    /// Restrict results to a specific verification status.
    pub status: Option<ProofStatus>,
    /// When true, only bridge proof records are returned.
    pub bridge_only: bool,
    /// Minimum bridge range start height (inclusive) when `bridge_only` is set.
    pub bridge_min_range_start: Option<u64>,
    /// Maximum bridge range end height (inclusive) when `bridge_only` is set.
    pub bridge_max_range_end: Option<u64>,
    /// Require the proof to carry a specific ZK1 TLV tag.
    pub has_tag: Option<[u8; 4]>,
    /// Minimum `verified_at_height` (inclusive).
    pub min_height: Option<u64>,
    /// Maximum `verified_at_height` (inclusive).
    pub max_height: Option<u64>,
}
/// Pagination controls for proof listings.
#[derive(Debug, Clone)]
pub struct ProofListParams<'a> {
    /// Filter set applied before ordering/pagination.
    pub filters: ProofFilters<'a>,
    /// When true, results are returned in descending order of verification height.
    pub descending: bool,
    /// Optional offset applied after ordering.
    pub offset: Option<u32>,
    /// Optional limit applied after offset (server-side cap enforced at 1000).
    pub limit: Option<u32>,
}
/// Materialised proof entry returned by the listing helper.
#[derive(Debug, Clone)]
pub struct ProofListItem {
    /// Stable proof identifier (backend + proof hash).
    pub id: ProofId,
    /// Stored proof metadata (status, VK references, height).
    pub record: ProofRecord,
}

#[derive(Clone, Copy)]
struct OrderedProof<'a> {
    id: &'a ProofId,
    record: &'a ProofRecord,
    descending: bool,
}

impl OrderedProof<'_> {
    fn base_cmp(&self, other: &Self) -> Ordering {
        self.record
            .verified_at_height
            .unwrap_or(0)
            .cmp(&other.record.verified_at_height.unwrap_or(0))
            .then_with(|| self.id.cmp(other.id))
    }
}

impl PartialEq for OrderedProof<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.descending == other.descending && self.base_cmp(other) == Ordering::Equal
    }
}

impl Eq for OrderedProof<'_> {}

impl PartialOrd for OrderedProof<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedProof<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.descending.cmp(&other.descending).then_with(|| {
            let ordering = self.base_cmp(other);
            if self.descending {
                ordering.reverse()
            } else {
                ordering
            }
        })
    }
}

/// List proof records using the supplied filters and pagination controls.
///
/// # Errors
///
/// Returns an error when the deadline expires or the requested ordered prefix
/// exceeds [`MAX_PROOF_QUERY_WINDOW`].
pub fn list_proofs(
    state: &State,
    params: &ProofListParams<'_>,
    budget: ProofQueryBudget,
) -> Result<Vec<ProofListItem>, ProofQueryError> {
    budget.check_deadline()?;
    let start = params.offset.unwrap_or(0) as usize;
    let cap = params.limit.unwrap_or(1000).clamp(1, 1000) as usize;
    let window = start
        .checked_add(cap)
        .filter(|window| *window <= budget.max_window)
        .ok_or_else(|| ProofQueryError::WindowTooLarge {
            requested: start.saturating_add(cap),
            maximum: budget.max_window,
        })?;
    let world = state.world_view();
    let mut selected = BinaryHeap::with_capacity(window.min(1024));
    for (id, record) in candidate_proofs(&world, &params.filters) {
        budget.check_deadline()?;
        if !proof_matches_filters(id, record, &params.filters) {
            continue;
        }
        let entry = OrderedProof {
            id,
            record,
            descending: params.descending,
        };
        if selected.len() < window {
            selected.push(entry);
        } else if selected.peek().is_some_and(|worst| entry < *worst) {
            selected.pop();
            selected.push(entry);
        }
    }
    budget.check_deadline()?;
    let mut entries = selected.into_vec();
    entries.sort_unstable();
    Ok(entries
        .into_iter()
        .skip(start)
        .take(cap)
        .map(|entry| ProofListItem {
            id: entry.id.clone(),
            record: entry.record.clone(),
        })
        .collect())
}
/// Count proof records matching the supplied filters (ignores pagination controls).
///
/// # Errors
///
/// Returns an error when the query deadline expires.
pub fn count_proofs(
    state: &State,
    filters: &ProofFilters<'_>,
    budget: ProofQueryBudget,
) -> Result<u64, ProofQueryError> {
    budget.check_deadline()?;
    let world = state.world_view();
    let mut count = 0_u64;
    for (id, record) in candidate_proofs(&world, filters) {
        budget.check_deadline()?;
        if proof_matches_filters(id, record, filters) {
            count = count.saturating_add(1);
        }
    }
    budget.check_deadline()?;
    Ok(count)
}
fn candidate_proofs<'a, W>(
    world: &'a W,
    filters: &'a ProofFilters<'a>,
) -> Box<dyn Iterator<Item = (&'a ProofId, &'a ProofRecord)> + 'a>
where
    W: WorldReadOnly,
{
    if let Some(tag) = filters.has_tag {
        return Box::new(
            crate::state::range_bounds::index_members(world.proofs_by_tag(), &tag)
                .filter_map(|proof_id| world.proofs().get_key_value(proof_id)),
        );
    }
    if let Some(backend) = filters.backend {
        Box::new(world.proofs_by_backend_iter(backend))
    } else if let Some(status) = filters.status.as_ref() {
        Box::new(world.proofs_by_status_iter(status))
    } else {
        Box::new(world.proofs().iter())
    }
}
fn proof_matches_filters(id: &ProofId, record: &ProofRecord, filters: &ProofFilters<'_>) -> bool {
    if let Some(backend) = filters.backend
        && id.backend != backend
    {
        return false;
    }
    if let Some(status) = filters.status
        && record.status != status
    {
        return false;
    }
    if let Some(min_height) = filters.min_height {
        match record.verified_at_height {
            Some(h) if h >= min_height => {}
            _ => return false,
        }
    }
    if let Some(max_height) = filters.max_height {
        match record.verified_at_height {
            Some(h) if h <= max_height => {}
            _ => return false,
        }
    }
    if filters.bridge_only {
        match record.bridge.as_ref() {
            Some(bridge) => {
                if let Some(min_range_start) = filters.bridge_min_range_start
                    && bridge.proof.range.start_height < min_range_start
                {
                    return false;
                }
                if let Some(max_range_end) = filters.bridge_max_range_end
                    && bridge.proof.range.end_height > max_range_end
                {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::{
        bridge::{
            BridgeProof, BridgeProofPayload, BridgeProofRange, BridgeProofRecord,
            BridgeTransparentProof,
        },
        proof::{ProofId, ProofRecord, ProofStatus},
    };
    use nonzero_ext::nonzero;
    fn blank_state() -> State {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        State::new(World::new(), kura, query)
    }
    fn query_budget() -> ProofQueryBudget {
        ProofQueryBudget::for_timeout(Duration::from_secs(30))
    }
    fn list_for_filters(state: &State, filters: ProofFilters<'_>) -> Vec<ProofListItem> {
        list_proofs(
            state,
            &ProofListParams {
                filters,
                descending: false,
                offset: None,
                limit: None,
            },
            query_budget(),
        )
        .expect("proof query should stay within the test budget")
    }
    fn bridge_proof_record(
        range: BridgeProofRange,
        payload: BridgeProofPayload,
        commitment: [u8; 32],
        size_bytes: u32,
    ) -> BridgeProofRecord {
        BridgeProofRecord {
            proof: BridgeProof { range, payload },
            commitment,
            size_bytes,
        }
    }
    fn bridge_record(
        backend: &str,
        proof_hash: [u8; 32],
        proof: BridgeProofRecord,
        verified_at_height: u64,
    ) -> (ProofId, ProofRecord) {
        let id = ProofId {
            backend: backend.into(),
            proof_hash,
        };
        let record = ProofRecord {
            id: id.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: Some(verified_at_height),
            bridge: Some(proof),
        };
        (id, record)
    }
    fn plain_record(
        backend: &str,
        proof_hash: [u8; 32],
        status: ProofStatus,
        verified_at_height: Option<u64>,
    ) -> (ProofId, ProofRecord) {
        let id = ProofId {
            backend: backend.into(),
            proof_hash,
        };
        let record = ProofRecord {
            id: id.clone(),
            vk_ref: None,
            vk_commitment: None,
            status,
            verified_at_height,
            bridge: None,
        };
        (id, record)
    }
    #[tokio::test]
    async fn list_and_count_filter_by_tag_and_status() {
        let state = blank_state();
        let backend = "halo2/ipa";
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let id_verified = ProofId {
            backend: backend.into(),
            proof_hash: [0x11; 32],
        };
        let rec_verified = ProofRecord {
            id: id_verified.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: Some(42),
            bridge: None,
        };
        stx.world.insert_proof_record(rec_verified);
        stx.world
            .proof_tags
            .insert(id_verified.clone(), vec![*b"PROF"]);
        stx.world
            .proofs_by_tag
            .insert((*b"PROF", id_verified.clone()), ());
        let id_rejected = ProofId {
            backend: backend.into(),
            proof_hash: [0x22; 32],
        };
        let rec_rejected = ProofRecord {
            id: id_rejected.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Rejected,
            verified_at_height: Some(43),
            bridge: None,
        };
        stx.world.insert_proof_record(rec_rejected);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit proof registry snapshot");
        let filters = ProofFilters {
            backend: Some(backend),
            status: Some(ProofStatus::Verified),
            bridge_only: false,
            bridge_min_range_start: None,
            bridge_max_range_end: None,
            has_tag: Some(*b"PROF"),
            min_height: None,
            max_height: None,
        };
        let params = ProofListParams {
            filters,
            descending: false,
            offset: None,
            limit: None,
        };
        let rows = list_proofs(&state, &params, query_budget())
            .expect("proof list should stay within the test budget");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id_verified);
        assert_eq!(rows[0].record.status, ProofStatus::Verified);
        let total = count_proofs(&state, &params.filters, query_budget())
            .expect("proof count should stay within the test budget");
        assert_eq!(total, 1);
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn list_filters_respect_height_ranges() {
        let state = blank_state();
        let backend = "halo2/ipa";
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        // Proof with verified height 10
        let id_early = ProofId {
            backend: backend.into(),
            proof_hash: [0xAA; 32],
        };
        let rec_early = ProofRecord {
            id: id_early.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: Some(10),
            bridge: None,
        };
        stx.world.insert_proof_record(rec_early);
        // Proof with verified height 25
        let id_late = ProofId {
            backend: backend.into(),
            proof_hash: [0xBB; 32],
        };
        let rec_late = ProofRecord {
            id: id_late.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: Some(25),
            bridge: None,
        };
        stx.world.insert_proof_record(rec_late);
        // Submitted proof (no height) should only appear when no bounds are requested.
        let id_submitted = ProofId {
            backend: backend.into(),
            proof_hash: [0xCC; 32],
        };
        let rec_submitted = ProofRecord {
            id: id_submitted.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Submitted,
            verified_at_height: None,
            bridge: None,
        };
        stx.world.insert_proof_record(rec_submitted);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit proof registry snapshot");
        // Filter proofs verified at or above height 20 -> should only include id_late
        let filters_min_only = ProofFilters {
            backend: Some(backend),
            status: Some(ProofStatus::Verified),
            bridge_only: false,
            bridge_min_range_start: None,
            bridge_max_range_end: None,
            has_tag: None,
            min_height: Some(20),
            max_height: None,
        };
        let params_min = ProofListParams {
            filters: filters_min_only,
            descending: false,
            offset: None,
            limit: None,
        };
        let rows_min = list_proofs(&state, &params_min, query_budget())
            .expect("minimum-height query should stay within budget");
        assert_eq!(rows_min.len(), 1);
        assert_eq!(rows_min[0].id, id_late);
        // Filter proofs verified at or below height 12 -> should only include id_early
        let filters_max_only = ProofFilters {
            backend: Some(backend),
            status: Some(ProofStatus::Verified),
            bridge_only: false,
            bridge_min_range_start: None,
            bridge_max_range_end: None,
            has_tag: None,
            min_height: None,
            max_height: Some(12),
        };
        let params_max = ProofListParams {
            filters: filters_max_only,
            descending: false,
            offset: None,
            limit: None,
        };
        let rows_max = list_proofs(&state, &params_max, query_budget())
            .expect("maximum-height query should stay within budget");
        assert_eq!(rows_max.len(), 1);
        assert_eq!(rows_max[0].id, id_early);
        // Narrow window should exclude submitted proof with no height.
        let filters_window = ProofFilters {
            backend: Some(backend),
            status: None,
            bridge_only: false,
            bridge_min_range_start: None,
            bridge_max_range_end: None,
            has_tag: None,
            min_height: Some(5),
            max_height: Some(15),
        };
        let params_window = ProofListParams {
            filters: filters_window,
            descending: false,
            offset: None,
            limit: None,
        };
        let rows_window = list_proofs(&state, &params_window, query_budget())
            .expect("height-window query should stay within budget");
        assert_eq!(rows_window.len(), 1);
        assert_eq!(rows_window[0].id, id_early);
        // Count helper should reflect the same filtering.
        let count = count_proofs(
            &state,
            &ProofFilters {
                backend: Some(backend),
                status: Some(ProofStatus::Verified),
                bridge_only: false,
                bridge_min_range_start: None,
                bridge_max_range_end: None,
                has_tag: None,
                min_height: Some(0),
                max_height: Some(30),
            },
            query_budget(),
        )
        .expect("filtered count should stay within budget");
        assert_eq!(count, 2);
    }
    #[tokio::test]
    async fn bridge_filters_only_bridge_records() {
        use iroha_data_model::proof::{ProofBox, ProofStatus};
        let state = blank_state();
        let backend = "bridge/test";
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let payload = BridgeProofPayload::TransparentZk(BridgeTransparentProof {
            verifier_manifest_hash: [0x11; 32],
            proof: ProofBox::new(backend.into(), vec![0xAA, 0xBB]),
            recursion_depth: Some(1),
        });
        // Early bridge proof.
        let bridge_proof = bridge_proof_record(
            BridgeProofRange {
                start_height: 1,
                end_height: 3,
            },
            payload.clone(),
            [0x10; 32],
            2,
        );
        let (_, rec_bridge) = bridge_record(backend, [0x01; 32], bridge_proof, 5);
        stx.world.insert_proof_record(rec_bridge);
        // Bridge proof with a later range.
        let later_proof = bridge_proof_record(
            BridgeProofRange {
                start_height: 20,
                end_height: 25,
            },
            payload,
            [0x11; 32],
            3,
        );
        let (id_later, rec_later) = bridge_record(backend, [0x02; 32], later_proof, 6);
        stx.world.insert_proof_record(rec_later);
        // Non-bridge proof should be filtered out.
        let (_, plain) = plain_record("halo2/ipa", [0x03; 32], ProofStatus::Verified, Some(7));
        stx.world.insert_proof_record(plain);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit bridge filter snapshot");
        let rows = list_for_filters(
            &state,
            ProofFilters {
                backend: None,
                status: Some(ProofStatus::Verified),
                bridge_only: true,
                bridge_min_range_start: None,
                bridge_max_range_end: None,
                has_tag: None,
                min_height: None,
                max_height: None,
            },
        );
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.record.bridge.is_some()));
        let range_filtered = list_for_filters(
            &state,
            ProofFilters {
                backend: None,
                status: None,
                bridge_only: true,
                bridge_min_range_start: Some(10),
                bridge_max_range_end: Some(30),
                has_tag: None,
                min_height: None,
                max_height: None,
            },
        );
        assert_eq!(range_filtered.len(), 1);
        assert_eq!(range_filtered[0].id, id_later);
    }

    #[tokio::test]
    async fn list_pagination_keeps_the_requested_ordered_prefix() {
        let state = blank_state();
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        for height in 1_u8..=4 {
            let (_, record) = plain_record(
                "halo2/ipa",
                [height; 32],
                ProofStatus::Verified,
                Some(u64::from(height)),
            );
            stx.world.insert_proof_record(record);
        }
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit pagination snapshot");

        let filters = ProofFilters {
            backend: None,
            status: None,
            bridge_only: false,
            bridge_min_range_start: None,
            bridge_max_range_end: None,
            has_tag: None,
            min_height: None,
            max_height: None,
        };
        let mut params = ProofListParams {
            filters,
            descending: false,
            offset: Some(1),
            limit: Some(2),
        };
        let ascending = list_proofs(&state, &params, query_budget())
            .expect("ascending page should stay within budget");
        assert_eq!(
            ascending
                .iter()
                .map(|item| item.record.verified_at_height)
                .collect::<Vec<_>>(),
            vec![Some(2), Some(3)]
        );

        params.descending = true;
        let descending = list_proofs(&state, &params, query_budget())
            .expect("descending page should stay within budget");
        assert_eq!(
            descending
                .iter()
                .map(|item| item.record.verified_at_height)
                .collect::<Vec<_>>(),
            vec![Some(3), Some(2)]
        );
    }

    #[tokio::test]
    async fn proof_query_budget_fails_closed() {
        let state = blank_state();
        let filters = ProofFilters {
            backend: None,
            status: None,
            bridge_only: false,
            bridge_min_range_start: None,
            bridge_max_range_end: None,
            has_tag: None,
            min_height: None,
            max_height: None,
        };
        let params = ProofListParams {
            filters,
            descending: false,
            offset: Some(1),
            limit: Some(1),
        };
        let error = list_proofs(
            &state,
            &params,
            ProofQueryBudget::with_max_window(Duration::from_secs(30), 1),
        )
        .expect_err("oversized ordered prefix must be rejected");
        assert_eq!(
            error,
            ProofQueryError::WindowTooLarge {
                requested: 2,
                maximum: 1,
            }
        );
        assert_eq!(
            count_proofs(
                &state,
                &params.filters,
                ProofQueryBudget::for_timeout(Duration::ZERO),
            ),
            Err(ProofQueryError::DeadlineExceeded)
        );
    }
}
