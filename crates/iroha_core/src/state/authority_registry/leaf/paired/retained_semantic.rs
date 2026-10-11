//! Retained canonical semantic rows and completed paired-tree stages.
//!
//! Actual key buffers, pending digests, ordered nodes and successful lookup paths
//! survive local refusal in the same owner. All backing uses a clone of the same
//! original allocation pool. Retained calls clone the caller's already admitted
//! refund scope; its last clone retires after every physical child of this owner.
//! The immutable source iterator borrows an existing validated native cut and is
//! never replaced or restarted. No source, map, row or pool is cloned to retry.
//! TODO: connect the reference-free fourteen-map publication source and its
//! retained semantic verifier plan to these materializers. These scoped nodes
//! do not authenticate complete State, certified history or restoration.
//! TODO: retain constructor planning-prefix refusals at the publication owner and
//! account generic schema/codec scratch; only completed ordered stages survive
//! here, not an unfinished ordered constructor or a consumed once-call failure.

use super::*;
use iroha_allocation::{AllocationBudget, OwnedAllocationScope};

/// Exact table/codec cause or local finite materializer-work refusal.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum RetainedSemanticError {
    /// Preserve the existing original table/codec/allocation cause.
    #[error(transparent)]
    Table(#[from] LeafError),
    /// No work starts beyond the caller's cumulative bound.
    #[error("semantic capture work exceeds its original local bound: {used} -> {required}/{limit}")]
    Work {
        used: usize,
        required: usize,
        limit: usize,
    },
    /// Checked finite kernel demand is not representable.
    #[error("semantic capture work demand overflow")]
    Overflow,
    /// Retained caller scope must identify the exact original pool.
    #[error("semantic capture scope does not belong to its original pool")]
    ScopeIdentity,
    /// A row/phase/source-size contract was violated before any result delivery.
    #[error("semantic capture original row or phase changed")]
    Phase,
}
impl RetainedSemanticError {
    // The consuming convenience is derived from the same finite LeafLimits.
    // A limit/overflow cannot grant a partial result or protocol verdict.
    pub(in crate::state) fn into_leaf(self) -> LeafError {
        match self {
            Self::Table(error) => error,
            Self::Work { .. } | Self::Overflow => LeafError::StreamedTableLimit,
            Self::ScopeIdentity | Self::Phase => LeafError::RowLimit,
        }
    }
}

/// Completed materializer stages and monotonic successful/attempted work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct RetainedSemanticProgress {
    pub rows: usize,
    pub pending_key: bool,
    pub pending_digest: bool,
    pub rows_sealed: bool,
    pub sorted: bool,
    pub ordered: bool,
    pub lookup_rows: usize,
    pub work: usize,
    pub complete: bool,
}

// Concread's unbounded whole-table iterator retains two fixed LeafPaths. Each
// next can ascend and descend each path at most once; setup has two such walks.
// This admits node/control steps, with no key comparisons for unbounded bounds.
const ITERATOR_STEP: usize = 4 * (usize::BITS as usize + 1) + 8;
// MerkleMap has 256 key bits. get, replacement_nodes and replace_node each visit
// at most 257 nodes; full common-prefix/key-bit and branch/leaf hash frames have
// fixed Hash-width geometry. Include all three walks before each actual retry.
const SORT_BOUND_STEP: usize = 2 * usize::BITS as usize + 2;
const LOOKUP_STEP: usize = 3 * 257 * (4 * Hash::LENGTH + 32);

fn add(left: usize, right: usize) -> Result<usize, RetainedSemanticError> {
    left.checked_add(right)
        .ok_or(RetainedSemanticError::Overflow)
}
fn mul(left: usize, right: usize) -> Result<usize, RetainedSemanticError> {
    left.checked_mul(right)
        .ok_or(RetainedSemanticError::Overflow)
}

// This is compile-time geometry of the actual canonical registry. find_field
// visits at most every field once; each of the two catalog binary searches is
// bounded by that same field count. The inline selection walk is no larger.
const fn registry_geometry(fields: &[Field]) -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < fields.len() {
        total += fields[index].id.len() + 8;
        if let Role::Canonical(Canonical::Owner(children)) = fields[index].role {
            total += registry_geometry(children);
        }
        index += 1;
    }
    total
}
const REGISTRY_GEOMETRY: usize = registry_geometry(STATE_FIELDS);

// The retained native entry points are closed to the actual three source
// producers. Their generated nominal identities are literal fast paths, not
// arbitrary dynamic NoritoSchema callbacks or caller-provided funding tokens.
fn closed_setup_literal(
    table: &str,
) -> Result<(&'static str, &'static str), RetainedSemanticError> {
    let pair = match table {
        "world.musubi_archive_availability" => (
            <iroha_data_model::musubi::ArchiveId as NoritoSchema>::static_nominal_name(),
            "iroha:state:musubi-availability-authority:v1",
        ),
        "world.musubi_resolver_index" => (
            <iroha_data_model::musubi::MusubiReleaseIdV1 as NoritoSchema>::static_nominal_name(),
            "iroha:state:musubi-resolver-authority:v1",
        ),
        "world.musubi_public_directory" => (
            <iroha_data_model::musubi::MusubiPackageSelectorV1 as NoritoSchema>::static_nominal_name(),
            "iroha:state:musubi-directory-authority:v1",
        ),
        #[cfg(test)]
        "triggers.data" => (
            <iroha_data_model::trigger::TriggerId as NoritoSchema>::static_nominal_name(),
            "iroha:state:trigger-data-action:v1",
        ),
        _ => return Err(RetainedSemanticError::Phase),
    };
    Ok((pair.0.ok_or(RetainedSemanticError::Phase)?, pair.1))
}
fn setup_selector_work(table: &str) -> Result<usize, RetainedSemanticError> {
    // Four literal matches and their scalar generated static-name callbacks.
    // The input length is O(1); its bytes are not inspected until admission.
    add(mul(8, table.len())?, 128)
}
fn setup_registry_work(key: &str, value: &str) -> Result<usize, RetainedSemanticError> {
    // All registry walk/search comparisons, bitset visits, two literal-name
    // callbacks, schema/start framing and the final key-name geometry lookup.
    add(
        add(
            mul(8, REGISTRY_GEOMETRY)?,
            mul(4, add(key.len(), value.len())?)?,
        )?,
        512,
    )
}
fn admit_work(work: &mut usize, demand: usize, limit: usize) -> Result<(), RetainedSemanticError> {
    let required = add(*work, demand)?;
    if required > limit {
        return Err(RetainedSemanticError::Work {
            used: *work,
            required,
            limit,
        });
    }
    *work = required;
    Ok(())
}

/// Finite row/finalizer cold-build ceiling derived from the existing leaf policy.
/// Generic consuming leaf helpers retain their separate metadata setup obligation;
/// retained native source operations additionally pre-admit their literal setup prefix.
/// It grants no additional allocation, row, payload or semantic-validation bound.
pub(super) fn finite_work_bound(limits: LeafLimits, framing: usize) -> Result<usize, LeafError> {
    let rows = usize::try_from(limits.max_rows.min(MAX_NORITO_TREE_ENTRIES as u64))
        .map_err(|_| LeafError::RowLimit)?;
    let key = limits.max_payload_bytes.min(MAX_NORITO_KEY_BYTES);
    let value = limits
        .max_payload_bytes
        .min(u32::MAX as usize)
        .min(usize::try_from(limits.max_streamed_value_bytes / 2).unwrap_or(usize::MAX));
    let per_row = ITERATOR_STEP
        .checked_add(LOOKUP_STEP)
        .and_then(|n| key.checked_mul(9).and_then(|k| n.checked_add(k)))
        .and_then(|n| value.checked_mul(6).and_then(|v| n.checked_add(v)))
        .and_then(|n| {
            n.checked_add(896)
                .and_then(|n| framing.checked_mul(2).and_then(|f| n.checked_add(f)))
        })
        .ok_or(LeafError::StreamedTableLimit)?;
    let comparisons = sort_bound(rows).ok_or(LeafError::StreamedTableLimit)?;
    rows.checked_mul(per_row)
        .and_then(|n| {
            comparisons
                .checked_mul(2 * key + 8)
                .and_then(|s| n.checked_add(s))
        })
        .and_then(|n| n.checked_add(2 * ITERATOR_STEP + SORT_BOUND_STEP + 1024))
        .ok_or(LeafError::StreamedTableLimit)
}

pub(super) struct RetainedSemanticTable {
    // Every actual physical child precedes the scope's last-owner retirement.
    encoded: StagedRows,
    pending_key: Option<iroha_allocation::ChargedBuffer<u8>>,
    pending_row: Option<PairedDigestRow>,
    ordered: Option<NoritoKeyDigestRangeTreeV1>,
    selection: Option<CanonicalTableLeafSet>,
    completed: Option<CanonicalTablePairedSnapshot>,
    table: &'static str,
    identity: &'static str,
    key_schema: Schema,
    value_schema: Schema,
    limits: LeafLimits,
    budget: AllocationBudget,
    retained_bytes: usize,
    streamed_bytes: u64,
    maximum_key: usize,
    framing: usize,
    lookup_next: usize,
    pending_lookup: Option<(Hash, Hash)>,
    work: usize,
    rows_sealed: bool,
    sorted: bool,
    scope: Option<OwnedAllocationScope>,
}
impl RetainedSemanticTable {
    fn new(
        table: &str,
        identity: &'static str,
        limits: LeafLimits,
        budget: &AllocationBudget,
        scope: Option<&OwnedAllocationScope>,
    ) -> Result<Self, RetainedSemanticError> {
        if scope.is_some_and(|scope| !scope.belongs_to(budget)) {
            return Err(RetainedSemanticError::ScopeIdentity);
        }
        let selection = CanonicalTableLeafSet::new(&[table], limits, budget)?;
        let (table, (key_schema, value_schema)) = selection
            .selection
            .table(table)
            .ok_or(LeafError::UnknownField)?;
        if !matches!(value_schema, Schema::Semantic { identity: declared, .. } if identity == declared)
        {
            return Err(LeafError::TypeMismatch(table).into());
        }
        let key_name = match key_schema {
            Schema::Norito { nominal_name, .. } => nominal_name().len(),
            _ => return Err(LeafError::UnresolvedSchema(table).into()),
        };
        // Scalar geometry only. Existing schema-name/codec metadata scratch is
        // still an explicit separate funding obligation, never a State token.
        let framing = add(add(key_name, identity.len())?, add(table.len(), 256)?)?;
        let maximum = usize::try_from(limits.max_rows.min(MAX_NORITO_TREE_ENTRIES as u64))
            .map_err(|_| LeafError::RowLimit)?;
        Ok(Self {
            encoded: StagedRows::new(maximum, budget)?,
            pending_key: None,
            pending_row: None,
            ordered: None,
            selection: Some(selection),
            completed: None,
            table,
            identity,
            key_schema,
            value_schema,
            limits,
            budget: budget.clone(),
            retained_bytes: 0,
            streamed_bytes: 0,
            maximum_key: 0,
            framing,
            lookup_next: 0,
            pending_lookup: None,
            work: 0,
            rows_sealed: false,
            sorted: false,
            scope: scope.cloned(),
        })
    }
    pub(super) fn once(
        table: &str,
        identity: &'static str,
        limits: LeafLimits,
        budget: &AllocationBudget,
    ) -> Result<Self, LeafError> {
        Self::new(table, identity, limits, budget, None).map_err(RetainedSemanticError::into_leaf)
    }
    fn admit(&mut self, demand: usize, limit: usize) -> Result<(), RetainedSemanticError> {
        admit_work(&mut self.work, demand, limit)
    }
    pub(super) fn work_bound(&self) -> Result<usize, LeafError> {
        finite_work_bound(self.limits, self.framing)
    }
    fn observe(&self) -> RetainedSemanticProgress {
        RetainedSemanticProgress {
            rows: self
                .completed
                .as_ref()
                .map_or(self.encoded.len(), CanonicalTablePairedSnapshot::row_count),
            pending_key: self.pending_key.is_some(),
            pending_digest: self.pending_row.is_some(),
            rows_sealed: self.rows_sealed,
            sorted: self.sorted,
            ordered: self.ordered.is_some() || self.completed.is_some(),
            lookup_rows: self.lookup_next,
            work: self.work,
            complete: self.completed.is_some(),
        }
    }
    pub(super) fn push<K: Encode + NoritoSchema, S: Encode>(
        &mut self,
        key: &K,
        project: impl FnOnce() -> S,
        limit: usize,
    ) -> Result<(), RetainedSemanticError> {
        if self.rows_sealed {
            return Err(RetainedSemanticError::Phase);
        }
        if u64::try_from(self.encoded.len()).map_err(|_| RetainedSemanticError::Overflow)?
            >= self.limits.max_rows.min(MAX_NORITO_TREE_ENTRIES as u64)
        {
            return Err(LeafError::RowLimit.into());
        }
        if self.pending_key.is_none() && self.pending_row.is_none() {
            // Both bounded key passes plus the final raw verification hash. This
            // explicit ceiling is spent before a refused allocation/encoder, too.
            self.admit(
                mul(4, self.limits.max_payload_bytes.min(MAX_NORITO_KEY_BYTES))?,
                limit,
            )?;
            self.pending_key = Some(staging::encode_key(
                self.table,
                self.key_schema,
                key,
                self.limits.max_payload_bytes,
                &self.budget,
            )?);
        }
        if self.pending_row.is_none() {
            let key = self
                .pending_key
                .as_ref()
                .ok_or(RetainedSemanticError::Phase)?;
            let mut retained = self.retained_bytes;
            charge_digest_row(&mut retained, key.as_slice().len(), self.limits)?;
            let bound = value_stream_bound(self.limits, self.streamed_bytes)?;
            // Preserve attempted-prefix work on every real encoder refusal; only
            // successful canonical byte usage belongs to the table's LeafLimits.
            // The existing canonical stream kernel caps each pass at u32::MAX.
            // Preserve its original bound/error mapping; admit only actual work.
            self.admit(
                add(mul(6, bound.min(u32::MAX as usize))?, self.framing)?,
                limit,
            )?;
            let (ordered_value_digest, lookup_value_digest, length) =
                semantic_bare_payload_digests(
                    self.table,
                    self.value_schema,
                    self.identity,
                    &project(),
                    bound,
                )
                .map_err(|error| value_stream_error(error, bound, self.limits))?;
            let mut streamed = self.streamed_bytes;
            charge_streamed_value(&mut streamed, length, self.limits)?;
            self.retained_bytes = retained;
            self.streamed_bytes = streamed;
            let key = self
                .pending_key
                .take()
                .ok_or(RetainedSemanticError::Phase)?;
            self.maximum_key = self.maximum_key.max(key.as_slice().len());
            self.pending_row = Some(PairedDigestRow {
                key,
                ordered_value_digest,
                lookup_value_digest,
            });
        }
        // Growth must be admitted while the exact pending canonical row and every
        // prior key remain owned. A refusal never consumes that pending row.
        let required = self
            .encoded
            .len()
            .checked_add(1)
            .ok_or(RetainedSemanticError::Overflow)?;
        self.admit(mul(4, self.encoded.growth_rows())?, limit)?;
        self.encoded.reserve_for(required)?;
        self.encoded.push_reserved(
            self.pending_row
                .take()
                .ok_or(RetainedSemanticError::Phase)?,
        );
        Ok(())
    }
    pub(super) fn seal_rows(&mut self) {
        self.rows_sealed = true;
    }
    pub(super) fn advance_finalizer(&mut self, limit: usize) -> Result<(), RetainedSemanticError> {
        if self.completed.is_some() {
            return Ok(());
        }
        if !self.rows_sealed || self.pending_key.is_some() || self.pending_row.is_some() {
            return Err(RetainedSemanticError::Phase);
        }
        // Preserve the original intrinsic ordered-capacity check before sorting.
        let count = self.encoded.len();
        let maximum = self
            .limits
            .max_ordered_table_bytes
            .min(MAX_NORITO_TREE_PAYLOAD_BYTES);
        if self.ordered.is_none()
            && count != 0
            && ordered_retained_bytes(count, self.retained_bytes)? > maximum
        {
            return Err(LeafError::OrderedRange(NoritoKeyRangeError::Capacity).into());
        }
        if !self.sorted {
            self.admit(SORT_BOUND_STEP, limit)?;
            let bound = sort_bound(self.encoded.len()).ok_or(RetainedSemanticError::Overflow)?;
            self.admit(mul(bound, add(mul(2, self.maximum_key)?, 8)?)?, limit)?;
            heap_sort(self.encoded.as_mut_slice());
            self.sorted = true;
        }
        if self.ordered.is_none() {
            let count = self.encoded.len();
            let nodes = if count == 0 {
                0
            } else {
                count
                    .checked_next_power_of_two()
                    .and_then(|n| n.checked_mul(2))
                    .and_then(|n| n.checked_sub(1))
                    .ok_or(RetainedSemanticError::Overflow)?
            };
            // Exact retained framing bounds key copies, duplicate comparisons
            // and every leaf/branch hash of this fixed ordered-tree kernel.
            self.admit(
                add(
                    mul(count, add(mul(4, self.maximum_key)?, 160)?)?,
                    mul(nodes, 128)?,
                )?,
                limit,
            )?;
            let schema = self
                .selection
                .as_ref()
                .ok_or(RetainedSemanticError::Phase)?
                .selection
                .schema;
            self.ordered = Some(
                NoritoKeyDigestRangeTreeV1::from_sorted_digests(
                    schema,
                    self.table.as_bytes(),
                    self.encoded
                        .as_slice()
                        .iter()
                        .map(|row| (row.key.as_slice(), row.ordered_value_digest)),
                    self.limits.max_ordered_table_bytes,
                    &self.budget,
                )
                .map_err(LeafError::OrderedRange)?,
            );
        }
        while self.lookup_next < self.encoded.len() {
            if self.pending_lookup.is_none() {
                let index = self.lookup_next;
                let length = self.encoded.as_slice()[index].key.as_slice().len();
                self.admit(add(length, self.framing)?, limit)?;
                let row = &self.encoded.as_slice()[index];
                let key_hash = bare_payload_hash(
                    self.table,
                    self.key_schema,
                    row.key.as_slice(),
                    KEY_PAYLOAD,
                )?;
                let table_len =
                    u64::try_from(self.table.len()).map_err(|_| RetainedSemanticError::Overflow)?;
                let path = Hash::new_from_chunks(&[
                    PATH,
                    &table_len.to_le_bytes(),
                    self.table.as_bytes(),
                    key_hash.as_ref(),
                ]);
                self.pending_lookup = Some((path, row.lookup_value_digest));
            }
            self.admit(LOOKUP_STEP, limit)?;
            let (path, digest) = self.pending_lookup.ok_or(RetainedSemanticError::Phase)?;
            self.selection
                .as_mut()
                .ok_or(RetainedSemanticError::Phase)?
                .leaves
                .replace(path, None, Some(digest))
                .map_err(|error| lookup_error(error, self.table))?;
            self.lookup_next += 1;
            self.pending_lookup = None;
        }
        self.admit(add(512, self.table.len())?, limit)?;
        let lookup = self.selection.take().ok_or(RetainedSemanticError::Phase)?;
        let ordered = self.ordered.take().ok_or(RetainedSemanticError::Phase)?;
        let rows = u64::try_from(ordered.len()).map_err(|_| RetainedSemanticError::Overflow)?;
        let root = paired_root(self.table, rows, lookup.root(), ordered.root());
        self.completed = Some(CanonicalTablePairedSnapshot {
            lookup,
            ordered,
            root,
        });
        self.encoded.retire()?;
        Ok(())
    }
    pub(super) fn take_once(&mut self) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        if self.scope.is_some() {
            return Err(LeafError::RowLimit);
        }
        self.completed.take().ok_or(LeafError::RowLimit)
    }
}

/// Source-borrowed operation on one exact already validated native table iterator.
/// It keeps that iterator and pending original row across refusal without rescans.
/// Completed nodes are borrowed together with this owner; delivery cannot detach
/// them from their original refund scope or promise finalized State authority.
pub(in crate::state) struct RetainedSemanticRows<'row, K, V, S, I>
where
    I: Iterator<Item = (&'row K, &'row V)>,
{
    // Any iterator-owned physical reader retires before the builder's last scope.
    rows: I,
    pending: Option<(&'row K, &'row V)>,
    project: fn(&V) -> S,
    original_count: usize,
    fetched: usize,
    exhausted: bool,
    builder: RetainedSemanticTable,
}
impl<'row, K: Encode + NoritoSchema + 'row, V: 'row, S: Encode, I>
    RetainedSemanticRows<'row, K, V, S, I>
where
    I: Iterator<Item = (&'row K, &'row V)> + ExactSizeIterator,
{
    /// Only the three reviewed semantic producers pass their actual immutable source iterator.
    /// Static registry/name planning is admitted before constructing metadata.
    pub(in crate::state) fn new(
        table: &str,
        identity: &'static str,
        limits: LeafLimits,
        budget: &AllocationBudget,
        retention: (&OwnedAllocationScope, usize),
        source: impl FnOnce() -> I,
        project: fn(&V) -> S,
    ) -> Result<Self, RetainedSemanticError> {
        Self::from_source(
            table,
            identity,
            limits,
            budget,
            (Some(retention.0), retention.1),
            source,
            project,
        )
    }
    fn from_source(
        table: &str,
        identity: &'static str,
        limits: LeafLimits,
        budget: &AllocationBudget,
        retention: (Option<&OwnedAllocationScope>, usize),
        source: impl FnOnce() -> I,
        project: fn(&V) -> S,
    ) -> Result<Self, RetainedSemanticError> {
        if retention.0.is_some_and(|scope| !scope.belongs_to(budget)) {
            return Err(RetainedSemanticError::ScopeIdentity);
        }
        let mut work = 0;
        admit_work(&mut work, setup_selector_work(table)?, retention.1)?;
        let (key_literal, value_literal) = closed_setup_literal(table)?;
        admit_work(
            &mut work,
            setup_registry_work(key_literal, value_literal)?,
            retention.1,
        )?;
        let mut builder = RetainedSemanticTable::new(table, identity, limits, budget, retention.0)?;
        builder.work = work;
        builder.admit(ITERATOR_STEP, retention.1)?;
        let rows = source();
        let original_count = rows.len();
        Ok(Self {
            builder,
            rows,
            pending: None,
            project,
            original_count,
            fetched: 0,
            exhausted: false,
        })
    }
    /// Consuming convenience uses the same finite kernel without manufacturing a scope.
    /// Its initial literal metadata derivation retains the consuming helper's
    /// separate setup obligation; only `new` accepts a caller setup-work limit.
    pub(in crate::state) fn once(
        table: &str,
        identity: &'static str,
        limits: LeafLimits,
        budget: &AllocationBudget,
        source: impl FnOnce() -> I,
        project: fn(&V) -> S,
    ) -> Result<Self, LeafError> {
        let selector = setup_selector_work(table).map_err(RetainedSemanticError::into_leaf)?;
        // This convenience has no caller-supplied work limit. Its closed literal
        // selector is included in the finite derived cold-build ceiling.
        // TODO: publication must retain and pre-admit this planning prefix; this
        // consuming entry does not claim the retained constructor's setup rule.
        let (key_literal, value_literal) =
            closed_setup_literal(table).map_err(RetainedSemanticError::into_leaf)?;
        let setup = selector
            .checked_add(
                setup_registry_work(key_literal, value_literal)
                    .map_err(RetainedSemanticError::into_leaf)?,
            )
            .ok_or(LeafError::StreamedTableLimit)?;
        let framing = table
            .len()
            .checked_add(key_literal.len())
            .and_then(|n| n.checked_add(identity.len()))
            .and_then(|n| n.checked_add(256))
            .ok_or(LeafError::StreamedTableLimit)?;
        let limit = finite_work_bound(limits, framing)?
            .checked_add(setup)
            .ok_or(LeafError::StreamedTableLimit)?;
        Self::from_source(
            table,
            identity,
            limits,
            budget,
            (None, limit),
            source,
            project,
        )
        .map_err(RetainedSemanticError::into_leaf)
    }
    /// An existing once-call producer explicitly consumes its original on refusal.
    pub(in crate::state) fn finish_once(
        mut self,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        if self.builder.scope.is_some() {
            return Err(LeafError::RowLimit);
        }
        let mut limits = self.builder.limits;
        limits.max_rows = limits
            .max_rows
            .min(u64::try_from(self.original_count).map_err(|_| LeafError::RowLimit)?);
        let limit = finite_work_bound(limits, self.builder.framing)?
            .checked_add(self.builder.work)
            .ok_or(LeafError::StreamedTableLimit)?;
        self.advance(limit)
            .map_err(RetainedSemanticError::into_leaf)?;
        self.builder.take_once()
    }
    /// Retry with the same source, pool, scope, pending row and monotonic work.
    pub(in crate::state) fn advance(
        &mut self,
        limit: usize,
    ) -> Result<RetainedSemanticProgress, RetainedSemanticError> {
        let result = self.advance_inner(limit);
        #[cfg(all(test, sumeragi_core_mutation = "HC176"))]
        if result.is_err() {
            // Mutation: later refusal evicts successful canonical rows while its
            // source cursor still remembers that they were already consumed.
            self.builder.encoded.discard_for_mutation();
        }
        result
    }
    fn advance_inner(
        &mut self,
        limit: usize,
    ) -> Result<RetainedSemanticProgress, RetainedSemanticError> {
        while !self.exhausted {
            if self.pending.is_none() {
                self.builder.admit(ITERATOR_STEP, limit)?;
                self.pending = self.rows.next();
                if self.pending.is_none() {
                    if self.fetched != self.original_count {
                        return Err(RetainedSemanticError::Phase);
                    }
                    self.exhausted = true;
                    self.builder.seal_rows();
                    break;
                }
                self.fetched = add(self.fetched, 1)?;
                if self.fetched > self.original_count {
                    return Err(RetainedSemanticError::Phase);
                }
            }
            let (key, value) = self.pending.ok_or(RetainedSemanticError::Phase)?;
            self.builder.push(key, || (self.project)(value), limit)?;
            self.pending = None;
        }
        self.builder.advance_finalizer(limit)?;
        Ok(self.builder.observe())
    }
    /// Observe original retained progress even after a local refusal.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: the retained publication consumer must inspect scoped materializer progress"
        )
    )]
    pub(in crate::state) fn progress(&self) -> RetainedSemanticProgress {
        self.builder.observe()
    }
    /// Borrow a completed scoped result without separating its original owner.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: the retained publication consumer must borrow the completed semantic pair"
        )
    )]
    pub(in crate::state) fn snapshot(&self) -> Option<&CanonicalTablePairedSnapshot> {
        self.builder.completed.as_ref()
    }
}

// A max-heap compares at most twice per downward level. The closed ceiling is
// build=sum floor(n/2^d), shrink=sum(n-2^d), both positive terms, times two.
fn sort_bound(length: usize) -> Option<usize> {
    let mut levels = 0_usize;
    let mut build = length / 2;
    while build != 0 {
        levels = levels.checked_add(build)?;
        build /= 2;
    }
    let mut threshold = 2_usize;
    while threshold < length {
        levels = levels.checked_add(length - threshold)?;
        let Some(next) = threshold.checked_mul(2) else {
            break;
        };
        threshold = next;
    }
    levels.checked_mul(2)
}
fn heap_sort(rows: &mut [PairedDigestRow]) {
    heap_sort_by(rows, |left, right| {
        left.key.as_slice().cmp(right.key.as_slice())
    });
}
fn heap_sort_by<T>(rows: &mut [T], mut compare: impl FnMut(&T, &T) -> std::cmp::Ordering) {
    fn sift<T>(
        rows: &mut [T],
        mut root: usize,
        end: usize,
        compare: &mut impl FnMut(&T, &T) -> std::cmp::Ordering,
    ) {
        while root < end / 2 {
            let mut child = root * 2 + 1;
            if child + 1 < end && compare(&rows[child], &rows[child + 1]).is_lt() {
                child += 1;
            }
            if !compare(&rows[root], &rows[child]).is_lt() {
                break;
            }
            rows.swap(root, child);
            root = child;
        }
    }
    for root in (0..rows.len() / 2).rev() {
        sift(rows, root, rows.len(), &mut compare);
    }
    for end in (1..rows.len()).rev() {
        rows.swap(0, end);
        sift(rows, 0, end, &mut compare);
    }
}

#[cfg(test)]
#[path = "retained_semantic_tests.rs"]
mod tests;
