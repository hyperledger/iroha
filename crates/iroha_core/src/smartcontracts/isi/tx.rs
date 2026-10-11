//! Implementations for transaction queries.
use crate::smartcontracts::isi::query::json_predicate::predicate_value_at_path;
use crate::{
    kura::{KaigiSignalCandidateIndexError, KaigiSignalCandidatePosition},
    state::StateReadOnly,
};
use eyre::Result;
use iroha_crypto::{HashOf, MerkleTree};
use iroha_data_model::{
    AccountId,
    block::BlockHeader,
    kaigi::KaigiId,
    query::{
        CommittedTransaction, CommittedTxFilters, dsl::CompoundPredicate,
        error::QueryExecutionFail, json::PredicateJson,
    },
    transaction::{TransactionResult, signed::TransactionEntrypoint},
};
use norito::json::Value;
use norito::{Decode, Encode};
use std::{collections::BTreeSet, num::NonZeroUsize, ops::ControlFlow};
fn block_hash_from_value(value: &Value) -> Option<HashOf<BlockHeader>> {
    norito::json::from_value(value.clone()).ok()
}
fn entrypoint_hash_from_value(value: &Value) -> Option<HashOf<TransactionEntrypoint>> {
    norito::json::from_value(value.clone()).ok()
}
fn account_id_from_value(value: &Value) -> Option<AccountId> {
    norito::json::from_value(value.clone())
        .ok()
        .or_else(|| AccountId::parse_encoded(value.as_str()?).ok())
}
fn timestamp_ms_from_value(value: &Value) -> Option<u64> {
    norito::json::from_value(value.clone()).ok()
}
fn result_status_from_value(value: &Value) -> Option<bool> {
    norito::json::from_value(value.clone()).ok()
}
fn transaction_block_hash_field(field: &str) -> bool {
    matches!(field, "block_hash" | "block" | "block.hash")
}
fn transaction_entrypoint_hash_field(field: &str) -> bool {
    matches!(field, "entrypoint_hash" | "entrypoint.hash")
}
fn transaction_authority_field(field: &str) -> bool {
    matches!(field, "authority" | "authority_id")
}
fn transaction_timestamp_field(field: &str) -> bool {
    matches!(field, "timestamp_ms" | "creation_time_ms")
}
fn transaction_result_status_field(field: &str) -> bool {
    matches!(field, "result_ok" | "result.is_ok")
}
fn intersect_block_candidate_heights(
    selected: &mut Option<BTreeSet<NonZeroUsize>>,
    candidates: BTreeSet<NonZeroUsize>,
) {
    if let Some(selected) = selected {
        selected.retain(|height| candidates.contains(height));
    } else {
        *selected = Some(candidates);
    }
}
fn entrypoint_hash_candidate_heights(
    hash: Option<HashOf<TransactionEntrypoint>>,
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let Some(hash) = hash else {
        return Some(BTreeSet::new());
    };
    state_ro.kura().get_block_heights_by_entrypoint_hash(hash)
}
fn entrypoint_hash_candidate_heights_from_values(
    values: &[Value],
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let mut candidates = BTreeSet::new();
    for hash in values.iter().filter_map(entrypoint_hash_from_value) {
        let indexed = state_ro.kura().get_block_heights_by_entrypoint_hash(hash)?;
        candidates.extend(indexed);
    }
    Some(candidates)
}
fn authority_candidate_heights(
    authority: Option<AccountId>,
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let Some(authority) = authority else {
        return Some(BTreeSet::new());
    };
    state_ro
        .kura()
        .get_block_heights_by_transaction_authority(&authority)
}
fn authority_candidate_heights_from_values(
    values: &[Value],
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let mut candidates = BTreeSet::new();
    for authority in values.iter().filter_map(account_id_from_value) {
        let indexed = state_ro
            .kura()
            .get_block_heights_by_transaction_authority(&authority)?;
        candidates.extend(indexed);
    }
    Some(candidates)
}
fn timestamp_candidate_heights(
    timestamp_ms: Option<u64>,
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let Some(timestamp_ms) = timestamp_ms else {
        return Some(BTreeSet::new());
    };
    state_ro
        .kura()
        .get_block_heights_by_transaction_timestamp_ms(timestamp_ms)
}
fn timestamp_candidate_heights_from_values(
    values: &[Value],
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let mut candidates = BTreeSet::new();
    for timestamp_ms in values.iter().filter_map(timestamp_ms_from_value) {
        let indexed = state_ro
            .kura()
            .get_block_heights_by_transaction_timestamp_ms(timestamp_ms)?;
        candidates.extend(indexed);
    }
    Some(candidates)
}
fn result_status_candidate_heights(
    result_status: Option<bool>,
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let Some(result_status) = result_status else {
        return Some(BTreeSet::new());
    };
    state_ro
        .kura()
        .get_block_heights_by_transaction_result_status(result_status)
}
fn result_status_candidate_heights_from_values(
    values: &[Value],
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let mut candidates = BTreeSet::new();
    for result_status in values.iter().filter_map(result_status_from_value) {
        let indexed = state_ro
            .kura()
            .get_block_heights_by_transaction_result_status(result_status)?;
        candidates.extend(indexed);
    }
    Some(candidates)
}
fn transaction_candidate_block_heights(
    predicate: &PredicateJson,
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let mut best = None;
    for cond in &predicate.equals {
        if transaction_block_hash_field(&cond.field) {
            intersect_block_candidate_heights(
                &mut best,
                block_hash_from_value(&cond.value)
                    .and_then(|hash| state_ro.block_height_by_hash(hash))
                    .into_iter()
                    .collect(),
            );
        }
        if transaction_entrypoint_hash_field(&cond.field)
            && let Some(candidates) =
                entrypoint_hash_candidate_heights(entrypoint_hash_from_value(&cond.value), state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
        if transaction_authority_field(&cond.field)
            && let Some(candidates) =
                authority_candidate_heights(account_id_from_value(&cond.value), state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
        if transaction_timestamp_field(&cond.field)
            && let Some(candidates) =
                timestamp_candidate_heights(timestamp_ms_from_value(&cond.value), state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
        if transaction_result_status_field(&cond.field)
            && let Some(candidates) =
                result_status_candidate_heights(result_status_from_value(&cond.value), state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
    }
    for cond in &predicate.r#in {
        if transaction_block_hash_field(&cond.field) {
            intersect_block_candidate_heights(
                &mut best,
                cond.values
                    .iter()
                    .filter_map(block_hash_from_value)
                    .filter_map(|hash| state_ro.block_height_by_hash(hash))
                    .collect(),
            );
        }
        if transaction_entrypoint_hash_field(&cond.field)
            && let Some(candidates) =
                entrypoint_hash_candidate_heights_from_values(&cond.values, state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
        if transaction_authority_field(&cond.field)
            && let Some(candidates) =
                authority_candidate_heights_from_values(&cond.values, state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
        if transaction_timestamp_field(&cond.field)
            && let Some(candidates) =
                timestamp_candidate_heights_from_values(&cond.values, state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
        if transaction_result_status_field(&cond.field)
            && let Some(candidates) =
                result_status_candidate_heights_from_values(&cond.values, state_ro)
        {
            intersect_block_candidate_heights(&mut best, candidates);
        }
    }
    best
}
fn transaction_filter_candidate_block_heights(
    filters: &CommittedTxFilters,
    state_ro: &impl StateReadOnly,
) -> Option<BTreeSet<NonZeroUsize>> {
    let mut best = None;
    if let Some(block_hash) = filters.block_eq.as_ref() {
        intersect_block_candidate_heights(
            &mut best,
            state_ro
                .block_height_by_hash(*block_hash)
                .into_iter()
                .collect(),
        );
    }
    if !filters.block_in.is_empty() {
        intersect_block_candidate_heights(
            &mut best,
            filters
                .block_in
                .iter()
                .filter_map(|hash| state_ro.block_height_by_hash(*hash))
                .collect(),
        );
    }
    if let Some(entrypoint_hash) = filters.entry_eq.as_ref()
        && let Some(candidates) = state_ro
            .kura()
            .get_block_heights_by_entrypoint_hash(*entrypoint_hash)
    {
        intersect_block_candidate_heights(&mut best, candidates);
    }
    if !filters.entry_in.is_empty() {
        let mut candidates = BTreeSet::new();
        for entrypoint_hash in &filters.entry_in {
            let indexed = state_ro
                .kura()
                .get_block_heights_by_entrypoint_hash(*entrypoint_hash)?;
            candidates.extend(indexed);
        }
        intersect_block_candidate_heights(&mut best, candidates);
    }
    if let Some(authority) = filters.authority_eq.as_ref()
        && let Some(candidates) = state_ro
            .kura()
            .get_block_heights_by_transaction_authority(authority)
    {
        intersect_block_candidate_heights(&mut best, candidates);
    }
    if !filters.authority_in.is_empty() {
        let mut candidates = BTreeSet::new();
        for authority in &filters.authority_in {
            let indexed = state_ro
                .kura()
                .get_block_heights_by_transaction_authority(authority)?;
            candidates.extend(indexed);
        }
        intersect_block_candidate_heights(&mut best, candidates);
    }
    if filters.ts_ge.is_some() || filters.ts_le.is_some() {
        let candidates = state_ro
            .kura()
            .get_block_heights_by_transaction_timestamp_range(filters.ts_ge, filters.ts_le)?;
        intersect_block_candidate_heights(&mut best, candidates);
    }
    if let Some(result_ok) = filters.result_ok
        && let Some(candidates) = state_ro
            .kura()
            .get_block_heights_by_transaction_result_status(result_ok)
    {
        intersect_block_candidate_heights(&mut best, candidates);
    }
    if !filters.result_ok_in.is_empty() {
        let mut candidates = BTreeSet::new();
        for result_ok in filters.result_ok_in.iter().copied() {
            let indexed = state_ro
                .kura()
                .get_block_heights_by_transaction_result_status(result_ok)?;
            candidates.extend(indexed);
        }
        intersect_block_candidate_heights(&mut best, candidates);
    }
    best
}
fn transaction_query_plan(
    filter: &CompoundPredicate<CommittedTransaction>,
    state_ro: &impl StateReadOnly,
) -> (Option<PredicateJson>, Option<BTreeSet<NonZeroUsize>>) {
    let predicate_json = filter
        .json_payload()
        .and_then(|raw| norito::json::from_str::<PredicateJson>(raw).ok());
    let mut candidate_heights = None;
    if let Some(filters) = filter.committed_tx_filters()
        && let Some(candidates) = transaction_filter_candidate_block_heights(&filters, state_ro)
    {
        intersect_block_candidate_heights(&mut candidate_heights, candidates);
    }
    if let Some(candidates) = predicate_json
        .as_ref()
        .and_then(|predicate| transaction_candidate_block_heights(predicate, state_ro))
    {
        intersect_block_candidate_heights(&mut candidate_heights, candidates);
    }
    (predicate_json, candidate_heights)
}
fn reject_unbounded_emergency_fast_transaction_history(
    state_ro: &impl StateReadOnly,
    candidate_heights: Option<&BTreeSet<NonZeroUsize>>,
) -> Result<(), QueryExecutionFail> {
    if state_ro.kura().emergency_fast_startup_enabled() && candidate_heights.is_none() {
        return Err(QueryExecutionFail::Conversion(
            "transaction history is unavailable without a complete positive index during emergency Fast mode; restart in Strict mode"
                .to_owned(),
        ));
    }
    Ok(())
}
fn transaction_field_equals(
    tx: &CommittedTransaction,
    field: &str,
    expected: &Value,
    tx_value: Option<&Value>,
) -> bool {
    if transaction_block_hash_field(field) {
        return block_hash_from_value(expected).is_some_and(|hash| tx.block_hash == hash);
    }
    if transaction_entrypoint_hash_field(field) {
        return entrypoint_hash_from_value(expected).is_some_and(|hash| tx.entrypoint_hash == hash);
    }
    if transaction_authority_field(field) {
        return account_id_from_value(expected)
            .is_some_and(|authority| tx.entrypoint.authority_opt() == Some(&authority));
    }
    if transaction_timestamp_field(field) {
        return timestamp_ms_from_value(expected)
            .is_some_and(|timestamp_ms| tx.entrypoint.creation_time_ms() == Some(timestamp_ms));
    }
    if transaction_result_status_field(field) {
        return result_status_from_value(expected)
            .is_some_and(|result_status| tx.result().is_ok() == result_status);
    }
    tx_value.and_then(|value| predicate_value_at_path(value, field)) == Some(expected)
}
fn transaction_field_in(
    tx: &CommittedTransaction,
    field: &str,
    expected_values: &[Value],
    tx_value: Option<&Value>,
) -> bool {
    expected_values
        .iter()
        .any(|expected| transaction_field_equals(tx, field, expected, tx_value))
}
fn transaction_field_exists(
    tx: &CommittedTransaction,
    field: &str,
    tx_value: Option<&Value>,
) -> bool {
    if transaction_block_hash_field(field)
        || transaction_entrypoint_hash_field(field)
        || transaction_result_status_field(field)
    {
        return true;
    }
    if transaction_authority_field(field) {
        return tx.entrypoint.authority_opt().is_some();
    }
    if transaction_timestamp_field(field) {
        return tx.entrypoint.creation_time_ms().is_some();
    }
    tx_value
        .and_then(|value| predicate_value_at_path(value, field))
        .is_some_and(|actual| !actual.is_null())
}
fn transaction_predicate_json_applies(
    predicate: &PredicateJson,
    tx: &CommittedTransaction,
) -> bool {
    let tx_value = norito::json::to_value(tx).ok();
    let tx_value = tx_value.as_ref();
    for cond in &predicate.equals {
        if !transaction_field_equals(tx, &cond.field, &cond.value, tx_value) {
            return false;
        }
    }
    for cond in &predicate.r#in {
        if !transaction_field_in(tx, &cond.field, &cond.values, tx_value) {
            return false;
        }
    }
    for field in &predicate.exists {
        if !transaction_field_exists(tx, field, tx_value) {
            return false;
        }
    }
    true
}
fn transaction_filter_applies(
    filter: &CompoundPredicate<CommittedTransaction>,
    predicate_json: Option<&PredicateJson>,
    tx: &CommittedTransaction,
) -> bool {
    predicate_json.map_or_else(
        || filter.applies(tx),
        |predicate| transaction_predicate_json_applies(predicate, tx),
    )
}
fn canonical_transaction_history_error(message: impl std::fmt::Display) -> QueryExecutionFail {
    QueryExecutionFail::Conversion(format!(
        "canonical Network transaction history is inconsistent: {message}"
    ))
}

#[cfg(test)]
thread_local! { static CANONICAL_NETWORK_PROJECTION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn reset_canonical_network_projection_calls_for_test() {
    CANONICAL_NETWORK_PROJECTION_CALLS.set(0);
}
#[cfg(test)]
pub(crate) fn canonical_network_projection_calls_for_test() -> usize {
    CANONICAL_NETWORK_PROJECTION_CALLS.get()
}

/// Validated source/output structure and one input proof tree for a single carrier.
/// Finality and physical byte admission belong to the caller's canonical reader.
struct NetworkCarrierProjection {
    block: iroha_data_model::block::SharedSignedBlock,
    inputs: MerkleTree<TransactionEntrypoint>,
    count: u32,
}
impl NetworkCarrierProjection {
    fn new(block: iroha_data_model::block::SharedSignedBlock) -> Result<Self, QueryExecutionFail> {
        #[cfg(test)]
        CANONICAL_NETWORK_PROJECTION_CALLS.set(CANONICAL_NETWORK_PROJECTION_CALLS.get() + 1);
        if block
            .execution_context()
            .is_some_and(|context| !context.has_current_version())
        {
            return Err(canonical_transaction_history_error(
                "retired merge carrier is not a Network source",
            ));
        }
        block
            .validate_output_merkle_cache()
            .map_err(canonical_transaction_history_error)?;
        let count = u32::try_from(block.network_entrypoint_count()).map_err(|_| {
            canonical_transaction_history_error("Network count exceeds proof index space")
        })?;
        Ok(Self {
            inputs: block.network_input_merkle_tree(),
            block,
            count,
        })
    }

    fn transaction_at(
        &self,
        input_index: u32,
        max_row_bytes: u64,
        before_clone: impl FnOnce(u64) -> Result<(), QueryExecutionFail>,
    ) -> Result<CommittedTransaction, QueryExecutionFail> {
        if max_row_bytes == 0 {
            return Err(QueryExecutionFail::GasBudgetExceeded);
        }
        let block = self.block.as_ref();
        let entrypoint = block
            .network_entrypoint_at(input_index as usize)
            .ok_or_else(|| canonical_transaction_history_error("Network source is missing"))?;
        let (output_index, _) = block.network_output_at(input_index).ok_or_else(|| {
            canonical_transaction_history_error("Network input has no exact output")
        })?;
        let output = block
            .execution_outputs()
            .get(output_index as usize)
            .ok_or_else(|| canonical_transaction_history_error("joined output is missing"))?;
        let entrypoint_proof = self
            .inputs
            .get_proof(input_index)
            .ok_or_else(|| canonical_transaction_history_error("input proof is missing"))?;
        let output_proof = block
            .output_proof(output_index)
            .ok_or_else(|| canonical_transaction_history_error("output proof is missing"))?;
        let block_hash = block.hash();
        let entrypoint_hash = entrypoint.hash();
        let output_hash = HashOf::new(output);
        // Measure the same seven fields without first cloning either large value.
        // Canonical flags and the shared borrowed-struct encoder fix the layout.
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let fields: [&dyn norito::core::SerializePayload; 7] = [
            &block_hash,
            &entrypoint_hash,
            &entrypoint_proof,
            entrypoint,
            &output_hash,
            &output_proof,
            output,
        ];
        let borrowed = super::query::BorrowedSingularStruct::new(fields);
        // Exact-length hints are optional, including for valid rejection reasons.
        // Count the actual borrowed wire under the caller's finite row ceiling;
        // then admit its exact bytes before cloning the entrypoint or output.
        let measured = super::query::bounded_bare_encoded_len(&borrowed, max_row_bytes)?;
        before_clone(measured)?;
        Ok(CommittedTransaction {
            block_hash,
            entrypoint_hash,
            entrypoint_proof,
            entrypoint: entrypoint.clone(),
            output_hash,
            output_proof,
            output: output.clone(),
        })
    }
}

/// One exact finalized carrier and the work/bytes admitted by its reader.
///
/// This immutable read result carries no authority to mutate or publish State.
/// Limits bound wire I/O and source/output validation, not the complete decoder heap.
#[derive(Debug)]
pub struct FinalizedExecutionCarrier {
    block: iroha_data_model::block::SharedSignedBlock,
    wire_bytes: u64,
    work_items: u64,
}
impl FinalizedExecutionCarrier {
    /// Borrow the exact authenticated complete carrier.
    pub fn block(&self) -> &iroha_data_model::block::SharedSignedBlock {
        &self.block
    }
    /// Aggregate native source bytes charged before I/O, including every read ancestor.
    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
    /// Native source frames plus complete target validation work, including empty carriers.
    pub fn work_items(&self) -> u64 {
        self.work_items
    }
    /// Project one exact Network input and its joined output from this authenticated carrier.
    ///
    /// No auxiliary transaction index or additional storage read is consulted. The complete row
    /// is measured before its source and output are cloned.
    ///
    /// # Errors
    /// Rejects a missing input, invalid source/output proofs, or a zero/exceeded row byte limit.
    pub fn transaction_at(
        &self,
        input_index: u32,
        max_row_bytes: u64,
    ) -> Result<CommittedTransaction, QueryExecutionFail> {
        if max_row_bytes == 0 {
            return Err(QueryExecutionFail::GasBudgetExceeded);
        }
        let projection = NetworkCarrierProjection::new(self.block.clone())?;
        projection.transaction_at(input_index, max_row_bytes, |bytes| {
            if bytes > max_row_bytes {
                return Err(QueryExecutionFail::GasBudgetExceeded);
            }
            Ok(())
        })
    }
    /// Visit the exact borrowed Network results of this already authenticated carrier.
    ///
    /// The independently selected header must match before any result reaches the visitor.
    /// Both full-prefix and off-chain checkpoint readers use this same projection; no
    /// additional source read, DTO clone or output-authentication path is introduced.
    /// # Errors
    /// Rejects a foreign carrier or a missing input/output in the complete validated join.
    pub fn visit_network_transactions(
        &self,
        expected_hash: HashOf<BlockHeader>,
        mut visitor: impl FnMut(&TransactionEntrypoint, &TransactionResult),
    ) -> Result<BlockHeader, QueryExecutionFail> {
        if self.block().hash() != expected_hash {
            return Err(canonical_transaction_history_error(
                "native carrier differs from the caller's exact committed binding",
            ));
        }
        let block = self.block();
        for index in 0..block.network_entrypoint_count() {
            let entrypoint = block.network_entrypoint_at(index).ok_or_else(|| {
                canonical_transaction_history_error("validated source disappeared")
            })?;
            let index = u32::try_from(index).map_err(|_| {
                canonical_transaction_history_error("Network count exceeds index space")
            })?;
            let (_, output) = block.network_output_at(index).ok_or_else(|| {
                canonical_transaction_history_error("validated output disappeared")
            })?;
            visitor(entrypoint, &output.result);
        }
        Ok(block.header())
    }

    /// Consume the read result and retain its immutable authenticated body.
    pub fn into_block(self) -> iroha_data_model::block::SharedSignedBlock {
        self.block
    }
}

/// Read a complete native execution from an independently configured, immutable State cut.
///
/// This is an offchain boundary: every native prefix frame is admitted before reading and
/// verified from signed genesis. Source frames/bytes count against the same finite caller
/// budget as output validation; a genesis result requires its actual H2 successor.
/// Deterministic instructions use their original State history owner, not this local QC path.
/// # Errors
/// Rejects zero/exceeded bounds, unavailable or changed source frames, invalid native
/// authority and inconsistent complete outputs. No partial carrier escapes on refusal.
pub(crate) fn read_finalized_execution_carrier(
    kura: &crate::kura::Kura,
    chain_id: &iroha_model_base::chain::ChainId,
    network: iroha_data_model::NetworkId,
    hashes: &dyn crate::state::BlockHashRead,
    height: NonZeroUsize,
    expected_hash: HashOf<BlockHeader>,
    max_work: u64,
    max_bytes: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    FinalizedExecutionCarrier,
    crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>,
> {
    use crate::sumeragi::certified_chain::{
        NativeExecutionReadError, NativeExecutionReadLimits, read_authenticated_execution,
    };
    if max_work == 0 || max_bytes == 0 {
        return Err(QueryExecutionFail::GasBudgetExceeded.into());
    }
    let height_u64 =
        u64::try_from(height.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    if hashes.hash_at(height.get() - 1).copied() != Some(expected_hash) {
        return Err(canonical_transaction_history_error(
            "requested execution is outside its original State hash cut",
        )
        .into());
    }
    // Admit the exact target before the prefix's first body read. Occupied metadata is
    // untrusted until the actual native certificates authenticate all these same frames.
    let target = kura
        .native_frame_read(height_u64, expected_hash)
        .map_err(|error| {
            crate::execution_attempt::kura_read_attempt_error(
                error,
                canonical_transaction_history_error,
            )
        })?
        .ok_or_else(|| canonical_transaction_history_error("native carrier is unavailable"))?;
    let target_wire_bytes = target.wire_len();
    if target_wire_bytes > max_bytes {
        return Err(QueryExecutionFail::GasBudgetExceeded.into());
    }
    let verified = read_authenticated_execution(
        kura,
        chain_id,
        network,
        hashes,
        height_u64,
        NativeExecutionReadLimits {
            admitted_target_wire_bytes: target_wire_bytes,
            max_source_blocks: max_work,
            max_source_wire_bytes: max_bytes,
            max_frame_wire_bytes: max_bytes,
        },
        budget,
    )
    .map_err(|error| match error {
        NativeExecutionReadError::Capacity { .. } => {
            crate::execution_attempt::ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded,
            )
        }
        NativeExecutionReadError::Deferred(reason) => {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
        }
        error => crate::execution_attempt::ExecutionAttemptError::Rejected(
            canonical_transaction_history_error(error),
        ),
    })?;
    let block = verified.authority.block().clone();
    let work = u64::try_from(
        block
            .network_entrypoint_count()
            .max(block.execution_outputs().len())
            .max(1),
    )
    .map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    let work = work
        .checked_add(verified.source_blocks)
        .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
    if work > max_work {
        return Err(QueryExecutionFail::GasBudgetExceeded.into());
    }
    if block
        .execution_context()
        .is_some_and(|context| !context.has_current_version())
    {
        return Err(canonical_transaction_history_error(
            "retired merge carrier is not a Network source",
        )
        .into());
    }
    block
        .validate_output_merkle_cache()
        .map_err(canonical_transaction_history_error)?;
    Ok(FinalizedExecutionCarrier {
        block,
        wire_bytes: verified.source_wire_bytes,
        work_items: work,
    })
}

/// Read one event-only carrier from the actual immutable State source.
///
/// Exact target metadata precedes every body read. The descriptor remains owned through
/// the same bounded ancestry/QC verifier and output join; this does not alter the
/// original full-prefix or deterministic history reader.
/// # Errors
/// Preserves original source/decode/refusal causes, unavailable or substituted source,
/// invalid finality and unchanged finite source/output limits.
pub(crate) fn read_finalized_event_carrier(
    source: crate::state::CanonicalHistorySource<'_>,
    kura: &crate::kura::Kura,
    chain_id: &iroha_model_base::chain::ChainId,
    network: iroha_data_model::NetworkId,
    height: NonZeroUsize,
    expected_hash: HashOf<BlockHeader>,
    max_work: u64,
    max_bytes: u64,
) -> Result<
    FinalizedExecutionCarrier,
    crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>,
> {
    if max_work == 0 || max_bytes == 0 {
        return Err(QueryExecutionFail::GasBudgetExceeded.into());
    }
    let target = kura
        .native_frame_read(
            u64::try_from(height.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?,
            expected_hash,
        )
        .map_err(|error| {
            crate::execution_attempt::kura_read_attempt_error(
                error,
                canonical_transaction_history_error,
            )
        })?
        .ok_or_else(|| canonical_transaction_history_error("native carrier is unavailable"))?;
    let target_wire_bytes = target.wire_len();
    if target_wire_bytes > max_bytes {
        return Err(QueryExecutionFail::GasBudgetExceeded.into());
    }
    let (verified, source_blocks, wire_bytes) =
        crate::sumeragi::certified_chain::read_event_execution(
            source, chain_id, network, height, &target, max_work, max_bytes,
        )?;
    let block = verified.block().clone();
    if block.hash() != expected_hash {
        return Err(canonical_transaction_history_error(
            "requested execution is outside its original State hash cut",
        )
        .into());
    }
    let work = u64::try_from(
        block
            .network_entrypoint_count()
            .max(block.execution_outputs().len())
            .max(1),
    )
    .map_err(|_| QueryExecutionFail::GasBudgetExceeded)?
    .checked_add(source_blocks)
    .filter(|work| *work <= max_work)
    .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
    if block
        .execution_context()
        .is_some_and(|context| !context.has_current_version())
    {
        return Err(canonical_transaction_history_error(
            "retired merge carrier is not a Network source",
        )
        .into());
    }
    block
        .validate_output_merkle_cache()
        .map_err(canonical_transaction_history_error)?;
    Ok(FinalizedExecutionCarrier {
        block,
        wire_bytes,
        work_items: work,
    })
}

/// Read one complete native execution for an off-chain reader.
///
/// The carrier is authenticated by a descending walk that starts at the
/// nearest verified history checkpoint at or above `height` (or the tip), so
/// any height costs at most
/// [`HISTORY_CHECKPOINT_INTERVAL`](crate::kura::history_checkpoints::HISTORY_CHECKPOINT_INTERVAL)
/// `+ 1` source blocks, unlike [`read_finalized_execution_carrier`], which
/// verifies the whole prefix from signed genesis. Its source work depends on
/// node-local checkpoints, so on-chain readers must use the prefix reader.
/// # Errors
/// Rejects zero/exceeded bounds, unavailable or contradicted history, retired
/// carriers and inconsistent outputs.
pub(crate) fn read_executed_carrier_from_checkpoints(
    source: crate::state::CanonicalHistorySource<'_>,
    height: NonZeroUsize,
    max_work: u64,
    max_bytes: u64,
    read_budget: &crate::state::CanonicalHistoryReadBudget,
) -> Result<
    FinalizedExecutionCarrier,
    crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>,
> {
    use crate::execution_attempt::ExecutionAttemptError;
    if max_work == 0 || max_bytes == 0 {
        return Err(QueryExecutionFail::GasBudgetExceeded.into());
    }
    let exceeded = || ExecutionAttemptError::Rejected(QueryExecutionFail::GasBudgetExceeded);
    let mut source_blocks = 0_u64;
    let mut wire_bytes = 0_u64;
    let mut carrier = None;
    read_budget.with(|| {
        source
            .with_read_budget(read_budget)
            .visit_executed_backwards_from_checkpoints(
                height,
                height,
                |blocks, bytes| {
                    source_blocks = source_blocks
                        .checked_add(blocks)
                        .filter(|work| *work <= max_work)
                        .ok_or_else(exceeded)?;
                    wire_bytes = wire_bytes
                        .checked_add(bytes)
                        .filter(|size| *size <= max_bytes)
                        .ok_or_else(exceeded)?;
                    Ok(())
                },
                |receipt| {
                    carrier = Some(receipt.block().clone());
                    Ok(ControlFlow::Break(()))
                },
            )
    })?;
    let block = carrier.ok_or_else(|| {
        ExecutionAttemptError::Rejected(canonical_transaction_history_error(
            "requested execution was absent from its authenticated interval",
        ))
    })?;
    let work = u64::try_from(
        block
            .network_entrypoint_count()
            .max(block.execution_outputs().len())
            .max(1),
    )
    .map_err(|_| exceeded())?
    .checked_add(source_blocks)
    .filter(|work| *work <= max_work)
    .ok_or_else(exceeded)?;
    if block
        .execution_context()
        .is_some_and(|context| !context.has_current_version())
    {
        return Err(canonical_transaction_history_error(
            "retired merge carrier is not a Network source",
        )
        .into());
    }
    block
        .validate_output_merkle_cache()
        .map_err(canonical_transaction_history_error)?;
    Ok(FinalizedExecutionCarrier {
        block,
        wire_bytes,
        work_items: work,
    })
}

/// Visit borrowed Network results from one exact finalized carrier.
///
/// Internal outputs never become transactions. No State read guard is needed
/// while Kura authenticates durable finality.
/// # Errors
/// Propagates complete finalized-carrier admission and validation failures.
pub fn visit_finalized_network_transactions(
    state: &crate::state::State,
    height: NonZeroUsize,
    expected_hash: HashOf<BlockHeader>,
    max_work: u64,
    max_bytes: u64,
    mut visitor: impl FnMut(&TransactionEntrypoint, &TransactionResult),
) -> Result<BlockHeader, crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>> {
    let carrier = state.read_finalized_execution_carrier(height, max_work, max_bytes)?;
    carrier
        .visit_network_transactions(expected_hash, &mut visitor)
        .map_err(Into::into)
}

#[cfg(test)]
fn block_committed_transactions(
    block: &iroha_data_model::block::SignedBlock,
) -> Result<Vec<CommittedTransaction>, QueryExecutionFail> {
    let projection = NetworkCarrierProjection::new(
        crate::block::reserve_block_for_tests().initialize(block.clone()),
    )?;
    (0..projection.count)
        .rev()
        .map(|index| projection.transaction_at(index, TRANSACTION_HISTORY_MAX_BYTES, |_| Ok(())))
        .collect()
}
/// Immutable canonical prefix bound to a Kaigi signal-history cursor.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::tx::KaigiSignalHistoryAnchor")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct KaigiSignalHistoryAnchor {
    height: u64,
    tip_hash: Option<HashOf<BlockHeader>>,
}

impl KaigiSignalHistoryAnchor {
    /// Construct a structurally valid canonical-prefix anchor.
    #[must_use]
    pub fn new(height: u64, tip_hash: Option<HashOf<BlockHeader>>) -> Option<Self> {
        ((height == 0) == tip_hash.is_none()).then_some(Self { height, tip_hash })
    }

    fn capture(state_ro: &impl StateReadOnly) -> Result<Self, QueryExecutionFail> {
        Ok(Self {
            height: u64::try_from(state_ro.height()).map_err(|_| {
                QueryExecutionFail::Conversion("Kaigi signal history height exceeds u64".to_owned())
            })?,
            tip_hash: state_ro.latest_block_hash(),
        })
    }

    fn validate(self, state_ro: &impl StateReadOnly) -> Result<(), QueryExecutionFail> {
        let height = usize::try_from(self.height).map_err(|_| QueryExecutionFail::Expired)?;
        let observed_tip = height
            .checked_sub(1)
            .and_then(|index| state_ro.block_hashes().get(index))
            .copied();
        if observed_tip != self.tip_hash {
            return Err(QueryExecutionFail::Expired);
        }
        Ok(())
    }

    /// Return the anchored canonical height.
    #[must_use]
    pub const fn height(self) -> u64 {
        self.height
    }

    /// Return the canonical hash at the anchored height, if non-empty.
    #[must_use]
    pub const fn tip_hash(self) -> Option<HashOf<BlockHeader>> {
        self.tip_hash
    }
}

/// Revalidated committed transaction selected by the Kaigi signal index.
#[derive(Debug, Clone)]
pub struct IndexedKaigiSignalCandidate {
    position: KaigiSignalCandidatePosition,
    authority: AccountId,
    carrier_timestamp_ms: u64,
    transaction: CommittedTransaction,
}

impl IndexedKaigiSignalCandidate {
    /// Return the stable structural position used by exclusive cursors.
    #[must_use]
    pub const fn position(&self) -> KaigiSignalCandidatePosition {
        self.position
    }

    /// Return the transaction authority bound into the index locator.
    #[must_use]
    pub fn authority(&self) -> &AccountId {
        &self.authority
    }

    /// Return the canonical carrier-block timestamp.
    #[must_use]
    pub const fn carrier_timestamp_ms(&self) -> u64 {
        self.carrier_timestamp_ms
    }

    /// Borrow the revalidated committed transaction.
    #[must_use]
    pub const fn transaction(&self) -> &CommittedTransaction {
        &self.transaction
    }
}

/// Bounded chronological page returned by the Kaigi signal index.
#[derive(Debug, Clone)]
pub struct IndexedKaigiSignalCandidatePage {
    anchor: KaigiSignalHistoryAnchor,
    candidates: Vec<IndexedKaigiSignalCandidate>,
    has_more: bool,
}

const TRANSACTION_HISTORY_BYTES_PER_WORK_UNIT: u64 = 64 * 1024;
const TRANSACTION_HISTORY_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Derive the bounded history-byte allowance from configured query work.
///
/// This includes physical carrier reads and projected row copies. The hard
/// ceiling also applies to callers whose weighted policy does not price bytes.
#[must_use]
pub const fn transaction_history_byte_limit(work_cap: u64) -> u64 {
    let scaled = work_cap.saturating_mul(TRANSACTION_HISTORY_BYTES_PER_WORK_UNIT);
    if scaled < TRANSACTION_HISTORY_MAX_BYTES {
        scaled
    } else {
        TRANSACTION_HISTORY_MAX_BYTES
    }
}

/// Explicit scan work limits, independent of retained response rows and bytes.
/// Every carrier reserves an item and its exact finalized wire before reading;
/// remaining complete output rows and selected DTO bytes are charged before projection.
#[derive(Clone, Copy, Debug)]
pub struct TransactionHistoryWorkLimits {
    /// Maximum complete source/output work in one carrier.
    pub max_carrier_work: u64,
    /// Maximum cumulative work across all scanned carriers, including empty ones.
    pub max_total_work: u64,
    /// Maximum cumulative exact carrier and projected DTO bytes.
    pub max_bytes: u64,
}

/// Independent hard limits for one indexed Kaigi signal-history page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KaigiSignalCandidateWorkLimits {
    max_candidates: u64,
    max_carrier_bytes: u64,
    max_projected_transactions: u64,
    max_output_work: u64,
}

impl KaigiSignalCandidateWorkLimits {
    /// Derive balanced limits from the configured query work cap.
    #[must_use]
    pub fn from_work_cap(work_cap: u64) -> Option<Self> {
        if work_cap == 0 || work_cap > iroha_data_model::query::parameters::MAX_FETCH_SIZE.get() {
            return None;
        }
        Some(Self {
            max_candidates: work_cap,
            max_carrier_bytes: work_cap
                .saturating_mul(TRANSACTION_HISTORY_BYTES_PER_WORK_UNIT)
                .min(TRANSACTION_HISTORY_MAX_BYTES),
            max_projected_transactions: work_cap,
            max_output_work: work_cap,
        })
    }

    #[cfg(test)]
    const fn new_for_test(
        max_candidates: u64,
        max_carrier_bytes: u64,
        max_projected_transactions: u64,
        max_output_work: u64,
    ) -> Self {
        Self {
            max_candidates,
            max_carrier_bytes,
            max_projected_transactions,
            max_output_work,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct KaigiSignalCandidateWork {
    carrier_bytes: u64,
    projected_transactions: u64,
    output_work: u64,
}

impl KaigiSignalCandidateWork {
    fn try_charge(
        &mut self,
        limits: KaigiSignalCandidateWorkLimits,
        carrier_bytes: u64,
        projected_transactions: u64,
        output_work: u64,
    ) -> bool {
        let Some(next_carrier_bytes) = self.carrier_bytes.checked_add(carrier_bytes) else {
            return false;
        };
        let Some(next_projected_transactions) = self
            .projected_transactions
            .checked_add(projected_transactions)
        else {
            return false;
        };
        let Some(next_output_work) = self.output_work.checked_add(output_work) else {
            return false;
        };
        if next_carrier_bytes > limits.max_carrier_bytes
            || next_projected_transactions > limits.max_projected_transactions
            || next_output_work > limits.max_output_work
        {
            return false;
        }
        self.carrier_bytes = next_carrier_bytes;
        self.projected_transactions = next_projected_transactions;
        self.output_work = next_output_work;
        true
    }
}

impl IndexedKaigiSignalCandidatePage {
    /// Return the immutable canonical prefix shared by every continuation.
    #[must_use]
    pub const fn anchor(&self) -> KaigiSignalHistoryAnchor {
        self.anchor
    }

    /// Borrow the revalidated candidates in chronological structural order.
    #[must_use]
    pub fn candidates(&self) -> &[IndexedKaigiSignalCandidate] {
        &self.candidates
    }

    /// Return whether another anchored raw candidate follows this page.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

fn kaigi_signal_index_error(error: KaigiSignalCandidateIndexError) -> QueryExecutionFail {
    match error {
        KaigiSignalCandidateIndexError::Unavailable => QueryExecutionFail::Conversion(
            "Kaigi signal history index is unavailable or incomplete".to_owned(),
        ),
        KaigiSignalCandidateIndexError::CursorMismatch => QueryExecutionFail::CursorMismatch,
    }
}

/// Read a bounded, anchored page of exact-schema Kaigi signal candidates.
///
/// This path never falls back to a full transaction-history walk. Every
/// locator is rehydrated from the immutable canonical snapshot and checked
/// against its block hash, entrypoint hash, successful result, call id, and
/// transaction authority before it is returned.
///
/// # Errors
///
/// Returns `Expired` when the anchored canonical prefix changed,
/// `CursorMismatch` when the exclusive position is not an exact candidate for
/// this call, or a fail-closed conversion/history error when the index or
/// authenticated carrier evidence is unavailable.
pub fn indexed_kaigi_signal_candidates_page(
    state_ro: &impl StateReadOnly,
    call_id: &KaigiId,
    anchor: Option<KaigiSignalHistoryAnchor>,
    after: Option<KaigiSignalCandidatePosition>,
    limits: KaigiSignalCandidateWorkLimits,
) -> Result<IndexedKaigiSignalCandidatePage, QueryExecutionFail> {
    if limits.max_candidates == 0
        || limits.max_candidates > iroha_data_model::query::parameters::MAX_FETCH_SIZE.get()
        || limits.max_carrier_bytes == 0
        || limits.max_projected_transactions == 0
        || limits.max_output_work == 0
    {
        return Err(QueryExecutionFail::FetchSizeTooBig);
    }
    if anchor.is_none() && after.is_some() {
        return Err(QueryExecutionFail::CursorMismatch);
    }
    let anchor = match anchor {
        Some(anchor) => {
            anchor.validate(state_ro)?;
            anchor
        }
        None => KaigiSignalHistoryAnchor::capture(state_ro)?,
    };
    let anchor_height = usize::try_from(anchor.height).map_err(|_| QueryExecutionFail::Expired)?;
    let limit = usize::try_from(limits.max_candidates)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or(QueryExecutionFail::FetchSizeTooBig)?;
    let locator_page = state_ro
        .kura()
        .get_kaigi_signal_candidate_locators(call_id, anchor_height, after, limit)
        .map_err(kaigi_signal_index_error)?;
    let mut candidates = Vec::new();
    candidates
        .try_reserve(locator_page.candidates.len())
        .map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    let locator_has_more = locator_page.has_more;
    let locator_count = locator_page.candidates.len();
    let mut processed_locators = 0_usize;
    let mut work = KaigiSignalCandidateWork::default();
    let mut cached_carrier: Option<(u64, u64, NetworkCarrierProjection)> = None;
    for locator in locator_page.candidates {
        let position = locator.position;
        if cached_carrier.as_ref().map(|cached| cached.0) != Some(position.block_height()) {
            let height = usize::try_from(position.block_height())
                .ok()
                .and_then(NonZeroUsize::new)
                .ok_or(QueryExecutionFail::CursorMismatch)?;
            let loaded = (|| {
                let block = state_ro
                    .canonical_history()
                    .executed_block(height, |source_blocks, wire_bytes| {
                        if work.try_charge(limits, wire_bytes, 0, source_blocks) {
                            Ok(())
                        } else {
                            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                            ))
                        }
                    })
                    .map_err(crate::smartcontracts::isi::query::query_transport_error)?;
                if block.hash() != position.block_hash() {
                    return Err(QueryExecutionFail::Expired);
                }
                let rows = u64::try_from(
                    block
                        .execution_outputs()
                        .len()
                        .max(block.network_entrypoint_count())
                        .max(1),
                )
                .map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
                if !work.try_charge(limits, 0, 0, rows - 1) {
                    return Err(QueryExecutionFail::GasBudgetExceeded);
                }
                let projection = NetworkCarrierProjection::new(block)?;
                let timestamp =
                    u64::try_from(projection.block.header().creation_time().as_millis()).map_err(
                        |_| canonical_transaction_history_error("carrier timestamp exceeds u64"),
                    )?;
                Ok((position.block_height(), timestamp, projection))
            })();
            match loaded {
                Ok(carrier) => cached_carrier = Some(carrier),
                Err(QueryExecutionFail::GasBudgetExceeded) if !candidates.is_empty() => break,
                Err(error) => return Err(error),
            }
        }
        let (_, carrier_timestamp_ms, projection) = cached_carrier
            .as_ref()
            .ok_or_else(|| canonical_transaction_history_error("admitted carrier is missing"))?;
        let projected = projection.transaction_at(
            position.network_input_index(),
            limits.max_carrier_bytes.saturating_sub(work.carrier_bytes),
            |bytes| {
                if work.try_charge(limits, bytes, 1, 0) {
                    Ok(())
                } else {
                    Err(QueryExecutionFail::GasBudgetExceeded)
                }
            },
        );
        let transaction = match projected {
            Ok(transaction) => transaction,
            Err(QueryExecutionFail::GasBudgetExceeded) if !candidates.is_empty() => break,
            Err(error) => return Err(error),
        };
        if transaction.block_hash() != &position.block_hash()
            || transaction.entrypoint_hash() != &position.entrypoint_hash()
            || crate::kura::Kura::kaigi_signal_candidate_identity(
                transaction.entrypoint(),
                transaction.result(),
            ) != Some((call_id.clone(), locator.authority.clone()))
        {
            return Err(QueryExecutionFail::Conversion(
                "Kaigi signal index locator does not match canonical transaction evidence"
                    .to_owned(),
            ));
        }
        candidates.push(IndexedKaigiSignalCandidate {
            position,
            authority: locator.authority,
            carrier_timestamp_ms: *carrier_timestamp_ms,
            transaction,
        });
        processed_locators = processed_locators.saturating_add(1);
    }
    anchor.validate(state_ro)?;
    Ok(IndexedKaigiSignalCandidatePage {
        anchor,
        candidates,
        has_more: locator_has_more || processed_locators < locator_count,
    })
}
/// Immutable upper bound for a replayed transaction-history scan.
///
/// Exact stored queries retain this compact chain anchor instead of retaining
/// every projected transaction. A continuation accepts later appended blocks,
/// but it must continue to observe the same canonical prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransactionHistoryAnchor {
    height: usize,
    tip_hash: Option<HashOf<BlockHeader>>,
}
impl TransactionHistoryAnchor {
    /// Capture the canonical prefix visible to a query view.
    pub(crate) fn capture(state_ro: &impl StateReadOnly) -> Self {
        Self {
            height: state_ro.height(),
            tip_hash: state_ro.latest_block_hash(),
        }
    }
    fn validate(self, state_ro: &impl StateReadOnly) -> Result<(), QueryExecutionFail> {
        let observed_tip = self
            .height
            .checked_sub(1)
            .and_then(|index| state_ro.block_hashes().get(index))
            .copied();
        if observed_tip != self.tip_hash {
            return Err(QueryExecutionFail::Expired);
        }
        Ok(())
    }
}
/// Compact resume position within an anchored transaction-history scan.
///
/// The cursor points just after a projected transaction in one carrier block.
/// Replaying it may re-read that one carrier, but never rescans newer carriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransactionHistoryCursor {
    height: usize,
    transaction_offset: usize,
}
/// Visit exact finalized Network history with admission before reading and cloning.
///
/// `before_project` admits item work and canonical bytes cumulatively. Every
/// carrier costs one item before I/O, remaining source/output rows are charged
/// before complete validation, and each selected row is measured before cloning.
/// Only the current carrier and one projected row are owned by this walker.
pub(crate) fn visit_committed_transactions(
    state_ro: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    anchor: TransactionHistoryAnchor,
    resume: Option<TransactionHistoryCursor>,
    max_row_bytes: u64,
    before_project: impl FnMut(u64, u64) -> Result<(), QueryExecutionFail>,
    mut visitor: impl FnMut(
        CommittedTransaction,
        bool,
        TransactionHistoryCursor,
    ) -> Result<ControlFlow<()>, QueryExecutionFail>,
) -> Result<bool, QueryExecutionFail> {
    walk_committed_transactions(
        state_ro,
        filter,
        anchor,
        HistoryStart::Tip,
        resume.map(HistoryResume::After),
        max_row_bytes,
        before_project,
        |transaction, matches, visit| visitor(transaction, matches, visit.next),
    )
}
/// Where a history walk authenticates its first block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryStart {
    /// The original tip: source work is deterministic, as on-chain readers require.
    Tip,
    /// The nearest node-local checkpoint above the interval; off-chain readers only.
    Checkpoint,
}
/// Where a history walk resumes.
#[derive(Debug, Clone, Copy)]
enum HistoryResume {
    /// Just after a projected transaction (an iterable-query continuation).
    After(TransactionHistoryCursor),
    /// Strictly before the transaction at these block coordinates.
    Before(TransactionHistoryPosition),
}
impl HistoryResume {
    /// Highest carrier height the walk may still visit.
    fn height(self) -> usize {
        match self {
            Self::After(cursor) => cursor.height,
            // Nothing in the block precedes its first transaction.
            Self::Before(position) if position.block_index == 0 => {
                position.height.saturating_sub(1)
            }
            Self::Before(position) => position.height,
        }
    }
    /// Newest-first offset at which the walk re-enters the carrier at `height`.
    fn offset_in(
        self,
        height: usize,
        transaction_count: usize,
    ) -> Result<usize, QueryExecutionFail> {
        match self {
            Self::After(cursor) if cursor.height == height => Ok(cursor.transaction_offset),
            Self::Before(position) if position.height == height => transaction_count
                .checked_sub(position.block_index)
                .ok_or(QueryExecutionFail::CursorMismatch),
            _ => Ok(0),
        }
    }
}
/// One visited transaction's coordinates.
#[derive(Debug, Clone, Copy)]
struct HistoryVisit {
    /// Continuation just after the transaction.
    next: TransactionHistoryCursor,
    /// Block coordinates of the transaction.
    position: TransactionHistoryPosition,
}
fn walk_committed_transactions(
    state_ro: &impl StateReadOnly,
    filter: &CompoundPredicate<CommittedTransaction>,
    anchor: TransactionHistoryAnchor,
    start: HistoryStart,
    resume: Option<HistoryResume>,
    max_row_bytes: u64,
    before_project: impl FnMut(u64, u64) -> Result<(), QueryExecutionFail>,
    mut visitor: impl FnMut(
        CommittedTransaction,
        bool,
        HistoryVisit,
    ) -> Result<ControlFlow<()>, QueryExecutionFail>,
) -> Result<bool, QueryExecutionFail> {
    anchor.validate(state_ro)?;
    let (predicate_json, candidate_heights) = transaction_query_plan(filter, state_ro);
    reject_unbounded_emergency_fast_transaction_history(state_ro, candidate_heights.as_ref())?;
    let maximum_height = resume.map_or(anchor.height, |resume| resume.height().min(anchor.height));
    let candidates = candidate_heights.map(|mut heights| {
        heights.retain(|height| height.get() <= maximum_height);
        heights
    });
    let (first, last) = if let Some(heights) = &candidates {
        let (Some(first), Some(last)) = (heights.first(), heights.last()) else {
            return Ok(true);
        };
        (*first, *last)
    } else {
        let Some(last) = NonZeroUsize::new(maximum_height) else {
            return Ok(true);
        };
        (NonZeroUsize::MIN, last)
    };
    // This query-owned callback returns semantic query outcomes, including its query
    // work limit. Declare that at the source bridge rather than inferring locality from
    // a wire-shaped budget error. Original source/decoder refusals stay typed below.
    // Both callbacks use the same admission owner sequentially; no charge borrow
    // survives either callback or the walker's subsequent source operation.
    let before_project = std::cell::RefCell::new(before_project);
    let before_read = |source_blocks, wire_len| {
        before_project.borrow_mut()(source_blocks, wire_len)
            .map_err(crate::execution_attempt::ExecutionAttemptError::Rejected)
    };
    let visit_receipt = |receipt: crate::sumeragi::certified_chain::CommittedBlock| {
        let height = NonZeroUsize::new(
            usize::try_from(receipt.height()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?,
        )
        .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        if candidates
            .as_ref()
            .is_some_and(|heights| !heights.contains(&height))
        {
            return Ok(ControlFlow::Continue(()));
        }
        let block = receipt.block().clone();
        let work = block
            .network_entrypoint_count()
            .max(block.execution_outputs().len())
            .max(1);
        before_project.borrow_mut()(
            u64::try_from(work - 1).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?,
            0,
        )?;
        let projection = NetworkCarrierProjection::new(block)?;
        let transaction_count = projection.count as usize;
        let transaction_offset = resume.map_or(Ok(0), |resume| {
            resume.offset_in(height.get(), transaction_count)
        })?;
        if transaction_offset > transaction_count {
            return Err(QueryExecutionFail::CursorMismatch.into());
        }
        for index in transaction_offset..transaction_count {
            let input_index = projection.count - 1 - index as u32;
            let transaction = projection.transaction_at(input_index, max_row_bytes, |bytes| {
                before_project.borrow_mut()(0, bytes)
            })?;
            let matches = transaction_filter_applies(filter, predicate_json.as_ref(), &transaction);
            let next_cursor = if index + 1 < transaction_count {
                TransactionHistoryCursor {
                    height: height.get(),
                    transaction_offset: index + 1,
                }
            } else {
                TransactionHistoryCursor {
                    height: height.get() - 1,
                    transaction_offset: 0,
                }
            };
            let visit = HistoryVisit {
                next: next_cursor,
                position: TransactionHistoryPosition {
                    height: height.get(),
                    block_index: input_index as usize,
                },
            };
            if visitor(transaction, matches, visit)?.is_break() {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    };
    let history = state_ro.canonical_history();
    match start {
        HistoryStart::Tip => {
            history.visit_executed_backwards_until(first, last, before_read, visit_receipt)
        }
        HistoryStart::Checkpoint => history.visit_executed_backwards_from_checkpoints(
            first,
            last,
            before_read,
            visit_receipt,
        ),
    }
    .map_err(crate::smartcontracts::isi::query::query_transport_error)
}
/// Visit history within cumulative source/output work and byte limits.
///
/// Bytes include each exact finalized carrier and every projected row, charged
/// before reading or cloning. Empty and nonmatching carriers consume work too.
/// The visitor can stop early without cloning subsequent rows.
///
/// # Errors
/// Rejects zero limits, exceeded work or bytes, unavailable history and corrupt bodies.
pub fn visit_committed_transactions_bounded(
    state_ro: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    max_projection_work: u64,
    max_history_bytes: u64,
    visitor: impl FnMut(CommittedTransaction, bool) -> Result<ControlFlow<()>, QueryExecutionFail>,
) -> Result<bool, QueryExecutionFail> {
    visit_committed_transactions_with_work_budget(
        state_ro,
        filter,
        max_projection_work,
        max_projection_work,
        max_history_bytes,
        visitor,
    )
}

/// Visit history with explicit per-carrier, cumulative work and cumulative byte limits.
///
/// # Errors
/// Rejects invalid limits before scanning and exceeded limits before dependent work.
pub fn visit_committed_transactions_with_work_budget(
    state_ro: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    max_carrier_projection_work: u64,
    max_total_projection_work: u64,
    max_history_bytes: u64,
    mut visitor: impl FnMut(CommittedTransaction, bool) -> Result<ControlFlow<()>, QueryExecutionFail>,
) -> Result<bool, QueryExecutionFail> {
    let canonical_max = iroha_data_model::query::parameters::MAX_FETCH_SIZE.get();
    if max_carrier_projection_work == 0
        || max_carrier_projection_work > canonical_max
        || max_total_projection_work == 0
        || max_total_projection_work > canonical_max
        || max_history_bytes == 0
    {
        return Err(QueryExecutionFail::FetchSizeTooBig);
    }
    let mut total_work = 0_u64;
    let mut total_bytes = 0_u64;
    visit_committed_transactions(
        state_ro,
        &filter,
        TransactionHistoryAnchor::capture(state_ro),
        None,
        max_history_bytes,
        |items, bytes| {
            // A carrier's first item is reserved before its row count is known.
            // The second charge contains exactly the remaining rows.
            if items > max_carrier_projection_work.saturating_sub(1) && bytes == 0 {
                return Err(QueryExecutionFail::GasBudgetExceeded);
            }
            total_work = total_work
                .checked_add(items)
                .filter(|n| *n <= max_total_projection_work)
                .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .filter(|n| *n <= max_history_bytes)
                .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
            Ok(())
        },
        |transaction, matches, _| visitor(transaction, matches),
    )
}
/// Block coordinates of a committed transaction: its block height and its
/// index among that block's transactions.
///
/// Coordinates are global: every peer holds the same blocks, so a position
/// issued by one peer resumes a walk on any other. Walks run newest first and
/// resume strictly before a position; transactions committed after a position
/// was issued sit at greater heights and are never revisited, so paging
/// through history is stable while the chain grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionHistoryPosition {
    height: usize,
    block_index: usize,
}

impl TransactionHistoryPosition {
    /// Coordinates of the transaction at `block_index` in the block at `height`.
    pub fn new(height: u64, block_index: u64) -> Option<Self> {
        Some(Self {
            height: usize::try_from(height).ok()?,
            block_index: usize::try_from(block_index).ok()?,
        })
    }

    /// Height of the block holding the transaction.
    pub fn height(self) -> u64 {
        self.height as u64
    }

    /// Index of the transaction within its block, in commit order.
    pub fn block_index(self) -> u64 {
        self.block_index as u64
    }
}

/// How one page of a resumable history walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionHistoryPageEnd {
    /// The visitor stopped at the transaction at this position.
    Stopped(TransactionHistoryPosition),
    /// The page's work or byte budget ran out after visiting the transaction
    /// at this position; resume strictly before it.
    BudgetSpent(TransactionHistoryPosition),
    /// The budget ran out before the walk reached a transaction: the blocks
    /// above the starting position alone exceed it, so no page with this
    /// budget can start this deep.
    OutOfReach,
    /// No older history remains.
    Exhausted,
}

/// Visit one page of committed transactions newest first, strictly before `resume`.
///
/// Every off-chain walk authenticates history downward from the nearest verified
/// checkpoint at or above the requested position. Its work and byte budgets
/// include checkpoint-to-position authentication as well as visited transactions.
/// Consensus execution retains its cache-independent accounting. Running out of budget after visiting a
/// transaction ends the page with the position to resume from
/// ([`TransactionHistoryPageEnd::BudgetSpent`]); running out before reaching
/// one ends it with [`TransactionHistoryPageEnd::OutOfReach`].
///
/// # Errors
/// Rejects zero or oversized limits, unavailable history and an anchor that
/// moved underneath the walk.
pub fn visit_committed_transaction_page(
    state_ro: &impl StateReadOnly,
    resume: Option<TransactionHistoryPosition>,
    max_projection_work: u64,
    max_history_bytes: u64,
    mut visitor: impl FnMut(CommittedTransaction, TransactionHistoryPosition) -> ControlFlow<()>,
) -> Result<TransactionHistoryPageEnd, QueryExecutionFail> {
    let canonical_max = iroha_data_model::query::parameters::MAX_FETCH_SIZE.get();
    if max_projection_work == 0 || max_projection_work > canonical_max || max_history_bytes == 0 {
        return Err(QueryExecutionFail::FetchSizeTooBig);
    }
    let mut total_work = 0_u64;
    let mut total_bytes = 0_u64;
    let mut budget_spent = false;
    let mut last = None;
    let mut stopped = false;
    let walk = walk_committed_transactions(
        state_ro,
        &CompoundPredicate::PASS,
        TransactionHistoryAnchor::capture(state_ro),
        HistoryStart::Checkpoint,
        resume.map(HistoryResume::Before),
        max_history_bytes,
        |items, bytes| {
            let work = total_work
                .checked_add(items)
                .filter(|work| *work <= max_projection_work);
            let size = total_bytes
                .checked_add(bytes)
                .filter(|size| *size <= max_history_bytes);
            if let (Some(work), Some(size)) = (work, size) {
                total_work = work;
                total_bytes = size;
                Ok(())
            } else {
                budget_spent = true;
                Err(QueryExecutionFail::GasBudgetExceeded)
            }
        },
        |transaction, _matches, visit| {
            last = Some(visit.position);
            let flow = visitor(transaction, visit.position);
            stopped = flow.is_break();
            Ok(flow)
        },
    );
    match (walk, last) {
        (Ok(_), Some(position)) if stopped => Ok(TransactionHistoryPageEnd::Stopped(position)),
        (Ok(_), _) => Ok(TransactionHistoryPageEnd::Exhausted),
        (Err(QueryExecutionFail::GasBudgetExceeded), Some(position)) if budget_spent => {
            Ok(TransactionHistoryPageEnd::BudgetSpent(position))
        }
        (Err(QueryExecutionFail::GasBudgetExceeded), None) if budget_spent => {
            Ok(TransactionHistoryPageEnd::OutOfReach)
        }
        (Err(error), _) => Err(error),
    }
}

/// Collect a small committed-transaction snapshot within explicit retention bounds.
///
/// Carrier work is bounded independently before source/output validation and proof construction. Transactions are visited
/// newest first and only predicate matches are retained. The function rejects a result set that
/// exceeds `max_projected_transactions` instead of returning a silently truncated snapshot, and
/// charges canonical retained bytes before every push.
///
/// # Errors
///
/// Returns [`QueryExecutionFail::GasBudgetExceeded`] before resolving an oversized carrier or
/// retaining bytes beyond `max_retained_bytes`, [`QueryExecutionFail::FetchSizeTooBig`] when the
/// matched result set exceeds the canonical fetch ceiling, or propagates durable validation
/// failures.
pub fn committed_transactions_bounded_snapshot(
    state_ro: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    work_limits: TransactionHistoryWorkLimits,
    max_projected_transactions: u64,
    max_retained_bytes: u64,
) -> Result<Vec<CommittedTransaction>, QueryExecutionFail> {
    if max_projected_transactions == 0 || max_retained_bytes == 0 {
        return Err(QueryExecutionFail::GasBudgetExceeded);
    }
    if max_projected_transactions > iroha_data_model::query::parameters::MAX_FETCH_SIZE.get() {
        return Err(QueryExecutionFail::FetchSizeTooBig);
    }
    let capacity = usize::try_from(max_projected_transactions).unwrap_or(usize::MAX);
    let mut retained_bytes = 0_u64;
    let mut transactions = Vec::new();
    transactions
        .try_reserve_exact(capacity)
        .map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    visit_committed_transactions_with_work_budget(
        state_ro,
        filter,
        work_limits.max_carrier_work,
        work_limits.max_total_work,
        work_limits.max_bytes,
        |transaction, matches| {
            if matches {
                if transactions.len() == capacity {
                    return Err(QueryExecutionFail::FetchSizeTooBig);
                }
                let transaction_bytes =
                    u64::try_from(norito::codec::Encode::encoded_len(&transaction))
                        .unwrap_or(u64::MAX);
                retained_bytes = retained_bytes
                    .checked_add(transaction_bytes)
                    .filter(|bytes| *bytes <= max_retained_bytes)
                    .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
                transactions.push(transaction);
            }
            Ok(ControlFlow::Continue(()))
        },
    )?;
    Ok(transactions)
}
/// Collect a finite snapshot selected by a complete positive index.
///
/// # Errors
/// Rejects unavailable indexes, corrupt or missing bodies and exceeded explicit
/// work or retention limits. Partial history is never returned as a snapshot.
pub fn committed_transactions_indexed_snapshot(
    state_ro: &impl StateReadOnly,
    filter: CompoundPredicate<CommittedTransaction>,
    work_limits: TransactionHistoryWorkLimits,
    max_projected_transactions: u64,
    max_retained_bytes: u64,
) -> Result<Vec<CommittedTransaction>, QueryExecutionFail> {
    if transaction_query_plan(&filter, state_ro).1.is_none() {
        return Err(QueryExecutionFail::Conversion(
            "transaction aggregate/select queries require a positive indexed filter".into(),
        ));
    }
    committed_transactions_bounded_snapshot(
        state_ro,
        filter,
        work_limits,
        max_projected_transactions,
        max_retained_bytes,
    )
}

/// Bounded fixture-only baseline; production uses the fallible page owner.
#[cfg(test)]
pub(crate) fn execute_transactions_fixture(
    filter: CompoundPredicate<CommittedTransaction>,
    state: &impl StateReadOnly,
) -> Result<std::vec::IntoIter<CommittedTransaction>, QueryExecutionFail> {
    committed_transactions_bounded_snapshot(
        state,
        filter,
        TransactionHistoryWorkLimits {
            max_carrier_work: iroha_data_model::query::parameters::MAX_FETCH_SIZE.get(),
            max_total_work: iroha_data_model::query::parameters::MAX_FETCH_SIZE.get(),
            max_bytes: transaction_history_byte_limit(
                iroha_data_model::query::parameters::MAX_FETCH_SIZE.get(),
            ),
        },
        iroha_data_model::query::parameters::MAX_FETCH_SIZE.get(),
        TRANSACTION_HISTORY_MAX_BYTES,
    )
    .map(Vec::into_iter)
}

/// Bounded fixture snapshot used to compare paginated output and corruption handling.
#[cfg(test)]
pub(crate) fn committed_transactions_snapshot(
    state: &impl StateReadOnly,
) -> Result<Vec<CommittedTransaction>, QueryExecutionFail> {
    execute_transactions_fixture(CompoundPredicate::PASS, state).map(Iterator::collect)
}

#[cfg(test)]
/// Transaction-history regression fixtures and tests.
pub(crate) mod tests {
    use super::*;
    use crate::tx::tests::*;
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::IntoKeyValue;
    use iroha_data_model::{
        ValidationFail,
        block::{
            BlockHeader, SignedBlock,
            execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        },
        prelude::{
            AccountId, DataTriggerSequence, InstructionBox, NetworkId, Registrable,
            TransactionBuilder, TransactionEntrypoint, TransactionResult,
        },
        transaction::error::TransactionRejectionReason,
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::json::Json;

    #[test]
    fn kaigi_signal_history_anchor_constructor_rejects_inconsistent_empty_prefixes() {
        let tip =
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x71; Hash::LENGTH]));
        assert!(KaigiSignalHistoryAnchor::new(0, None).is_some());
        assert!(KaigiSignalHistoryAnchor::new(1, Some(tip)).is_some());
        assert!(KaigiSignalHistoryAnchor::new(0, Some(tip)).is_none());
        assert!(KaigiSignalHistoryAnchor::new(1, None).is_none());
    }

    #[test]
    fn kaigi_signal_candidate_identity_requires_exact_call_and_success() {
        let key_pair = KeyPair::random();
        let authority = AccountId::new(key_pair.public_key().clone());
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"kaigi-index-test")),
        );
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert(
            "kaigi_signal".parse().expect("metadata key"),
            Json::new(norito::json!({
                "schema": "iroha-demo-kaigi-chain-signal/v1",
                "callId": "kaigi.universal:indexed",
                "call_id": "kaigi.universal:indexed",
            })),
        );
        let entrypoint = TransactionEntrypoint::External(
            TransactionBuilder::new(
                network_id,
                authority.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_metadata(metadata)
            .with_instructions::<InstructionBox>([])
            .sign(key_pair.private_key()),
        );
        let success = TransactionResult::from(Ok(DataTriggerSequence::default()));
        let (call_id, indexed_authority) =
            crate::kura::Kura::kaigi_signal_candidate_identity(&entrypoint, &success)
                .expect("exact successful signal");
        assert_eq!(call_id.to_string(), "kaigi.universal:indexed");
        assert_eq!(indexed_authority, authority);
        let failed = TransactionResult::from(Err(TransactionRejectionReason::Validation(
            ValidationFail::InternalError("rejected".to_owned()),
        )));
        assert!(crate::kura::Kura::kaigi_signal_candidate_identity(&entrypoint, &failed).is_none());
    }
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };
    #[derive(norito::NoritoSchema, norito::codec::Encode, norito::codec::Decode)]
    #[norito_schema(name = "iroha_core::smartcontracts::isi::tx::tests::MutableQueryBlock")]
    struct MutableQueryBlock {
        signatures: iroha_data_model::block::BlockSignatures,
        payload: iroha_data_model::block::BlockPayload,
        result: Option<iroha_data_model::block::BlockResult>,
        commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
    }
    // Structural codec corruption only: the actual query reader must still
    // authenticate the original exact wire from its independent CommitQC.
    fn mutable_query_block(
        block: &SignedBlock,
        mutate: impl FnOnce(&mut iroha_data_model::block::BlockResult),
    ) -> SignedBlock {
        use norito::codec::{DecodeAll, Encode as _};
        let mut mutable = MutableQueryBlock::decode_all(&mut block.encode().as_slice()).unwrap();
        mutate(mutable.result.as_mut().unwrap());
        SignedBlock::decode_all(&mut mutable.encode().as_slice()).unwrap()
    }
    #[test]
    fn canonical_network_projection_is_reverse_ordered_and_rejects_tampering() {
        let parent = empty_query_block(None);
        let block = canonical_query_carrier(&parent, 1, true, 0);
        let committed = block_committed_transactions(&block).unwrap();
        assert_eq!(committed.len(), 2);
        assert_eq!(committed[0].entrypoint_proof.leaf_index(), 1);
        assert_eq!(committed[1].entrypoint_proof.leaf_index(), 0);
        let inputs = block.network_input_merkle_commitment().unwrap();
        let outputs = block.output_merkle_commitment().unwrap();
        assert!(committed.iter().all(|tx| tx.block_hash == block.hash()
            && tx.entrypoint_proof.verify(&tx.entrypoint_hash, &inputs)
            && tx.output_proof.verify(&tx.output_hash, &outputs)));
        let mut changed = block.as_ref().clone();
        let mut rows = changed.execution_outputs().to_vec();
        let ExecutionOutputV1::Network(row) = &mut rows[0] else {
            unreachable!()
        };
        row.result = TransactionResult::new(Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("changed".into()),
        )));
        install_query_outputs(&mut changed, rows);
        assert_eq!(changed.hash(), block.hash());
        assert_ne!(
            changed.output_merkle_commitment(),
            block.output_merkle_commitment()
        );
        assert!(committed.iter().any(|tx| !tx.output_proof.verify(
            &tx.output_hash,
            &changed.output_merkle_commitment().unwrap()
        )));
        let bad = mutable_query_block(&block, |result| {
            result.outputs[0] = changed.execution_outputs()[0].clone();
        });
        assert!(block_committed_transactions(&bad).is_err());
    }
    #[test]
    fn canonical_network_exact_projection_returns_only_requested_source() {
        let block = canonical_query_carrier(&empty_query_block(None), 2, true, 0);
        let full = block_committed_transactions(&block).unwrap();
        let projection = NetworkCarrierProjection::new(block.clone()).unwrap();
        let exact = projection
            .transaction_at(0, TRANSACTION_HISTORY_MAX_BYTES, |_| Ok(()))
            .unwrap();
        assert_eq!(exact, full[1]);
        assert_eq!(exact.entrypoint_proof.leaf_index(), 0);
        assert_eq!(exact.output_proof.leaf_index(), 0);
        assert!(exact.entrypoint_proof.verify(
            &exact.entrypoint_hash,
            &block.network_input_merkle_commitment().unwrap()
        ));
        assert!(exact.output_proof.verify(
            &exact.output_hash,
            &block.output_merkle_commitment().unwrap()
        ));
        assert!(
            projection
                .transaction_at(2, TRANSACTION_HISTORY_MAX_BYTES, |_| Ok(()))
                .is_err()
        );
    }
    #[test]
    fn kaigi_signal_candidate_work_charges_all_dimensions_cumulatively() {
        let limits = KaigiSignalCandidateWorkLimits::new_for_test(4, 100, 6, 3);
        let mut work = KaigiSignalCandidateWork::default();
        assert!(work.try_charge(limits, 40, 2, 1));
        assert!(work.try_charge(limits, 60, 4, 2));
        assert!(!work.try_charge(limits, 1, 0, 0));
        assert!(!work.try_charge(limits, 0, 1, 0));
        assert!(!work.try_charge(limits, 0, 0, 1));
        assert_eq!(work.carrier_bytes, 100);
        assert_eq!(work.projected_transactions, 6);
        assert_eq!(work.output_work, 3);
    }
    /// Empty typed parent used only to bind the physical query history.
    pub(crate) fn empty_query_block(previous: Option<&SignedBlock>) -> SignedBlock {
        let height = previous.map_or(1, |block| block.header().height().get() + 1);
        let time = previous.map_or(0, |block| {
            u64::try_from(block.header().creation_time().as_millis()).unwrap() + 10
        });
        let mut block = iroha_data_model::block::builder::BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(height).unwrap(),
            previous.map(SignedBlock::hash),
            None,
            time,
            0,
        ))
        .build_with_signature(0, &GENESIS_ACCOUNT.key);
        install_query_outputs(&mut block, Vec::new());
        block
    }
    fn install_query_outputs(block: &mut SignedBlock, outputs: Vec<ExecutionOutputV1>) {
        let fragments =
            u64::try_from(outputs.iter().filter(|row| row.result().is_ok()).count()).unwrap();
        let proposal = block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection");
        block
            .set_execution_outputs(
                outputs,
                fragments,
                Default::default(),
                Vec::new(),
                Default::default(),
                Default::default(),
                &crate::execution_output_test_support::structural_output_limits(),
            )
            .unwrap();
        assert_eq!(
            block
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection"),
            proposal
        );
    }
    /// Two signed Network inputs with explicit full typed output rows; no merge sidecar.
    pub(crate) fn canonical_query_carrier(
        previous: &SignedBlock,
        epoch: u64,
        result_ok: bool,
        metadata_bytes: usize,
    ) -> iroha_data_model::block::SharedSignedBlock {
        let network = crate::kura::tests::canonical_query_network_id();
        let height = previous.header().height().get() + 1;
        let mut builder = iroha_data_model::block::builder::BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(height).unwrap(),
            Some(previous.hash()),
            None,
            epoch * 10 + 2,
            0,
        ));
        for index in 0..2 {
            let key = KeyPair::random();
            let mut tx = TransactionBuilder::new(
                network,
                AccountId::new(key.public_key().clone()),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            );
            tx.set_creation_time(Duration::from_millis(epoch * 10 + index));
            if metadata_bytes != 0 {
                let mut metadata = Metadata::default();
                metadata.insert(
                    "query_padding".parse().unwrap(),
                    Json::new("p".repeat(metadata_bytes)),
                );
                tx = tx.with_metadata(metadata);
            }
            builder.push_transaction(
                tx.with_instructions::<InstructionBox>([])
                    .sign(key.private_key()),
            );
        }
        let mut block = builder.build_with_signature(0, &GENESIS_ACCOUNT.key);
        let outputs = (0..2)
            .map(|index| {
                ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index: index,
                    result: TransactionResult::new(if result_ok {
                        Ok(DataTriggerSequence::default())
                    } else {
                        Err(TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted(format!(
                                "query rejection {epoch}:{index}"
                            )),
                        ))
                    }),
                    completions: Vec::new(),
                })
            })
            .collect();
        install_query_outputs(&mut block, outputs);
        crate::block::reserve_block_for_tests().initialize(block)
    }
    /// Physical finality-backed Network history shared by pagination/index regressions.
    pub(crate) struct CanonicalQueryFixture {
        /// Query authority and canonical State history.
        pub(crate) state: Arc<crate::state::State>,
        /// Retain original execution and physical custody for every query continuation.
        pub(crate) store: crate::kura::tests::CanonicalQueryStore,
        /// Carrier selected by index tests.
        pub(crate) target_block_hash: HashOf<BlockHeader>,
        /// Exact requested outer input identity.
        pub(crate) target_entrypoint_hash: HashOf<TransactionEntrypoint>,
        /// Authority appearing in precisely one input.
        pub(crate) target_authority: AccountId,
        /// Timestamp appearing in precisely one input.
        pub(crate) target_timestamp_ms: u64,
        /// Selected physical body position.
        pub(crate) target_height: NonZeroUsize,
        /// Older unselected physical body position.
        pub(crate) unrelated_height: NonZeroUsize,
    }
    fn native_query_chain(
        carriers: u64,
        metadata_bytes: usize,
    ) -> crate::sumeragi::test_chain::CertifiedTestChain {
        native_query_chain_with_query_gas(carriers, metadata_bytes, None)
    }
    fn native_query_chain_with_query_gas(
        carriers: u64,
        metadata_bytes: usize,
        query_stored_min_gas_units: Option<u64>,
    ) -> crate::sumeragi::test_chain::CertifiedTestChain {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_data_model::{
            account::Account,
            isi::{Log, Unregister},
        };
        let mut world = crate::state::World::with(
            [],
            [Account::new(iroha_test_samples::ALICE_ID.clone())
                .build(&iroha_test_samples::ALICE_ID)],
            [],
        );
        world.account_permissions.insert(
            iroha_test_samples::ALICE_ID.clone(),
            BTreeSet::from([
                iroha_executor_data_model::permission::query::CanReadAllLedgerData.into(),
            ]),
        );
        let keys = (0..carriers * 2)
            .map(|index| {
                KeyPair::from_seed(
                    index.to_le_bytes().to_vec(),
                    iroha_crypto::Algorithm::Ed25519,
                )
            })
            .collect::<Vec<_>>();
        for key in &keys {
            let account = AccountId::new(key.public_key().clone());
            let (id, value) = Account::new(account.clone())
                .build(&account)
                .into_key_value();
            world.accounts.insert(id, value);
        }
        let mut config = TestChainConfig::new(world, 1000);
        if let Some(units) = query_stored_min_gas_units {
            config.pipeline.query_stored_min_gas_units = units;
        }
        let mut chain = CertifiedTestChain::start(config).unwrap();
        for epoch in 1..=carriers {
            let transactions = (0..2)
                .map(|index| {
                    let key = &keys[((epoch - 1) * 2 + index) as usize];
                    let mut tx = TransactionBuilder::new(
                        chain.network_id(),
                        AccountId::new(key.public_key().clone()),
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    );
                    tx.set_creation_time(Duration::from_millis((epoch + 1) * 1000 + index));
                    if metadata_bytes != 0 {
                        let mut metadata = Metadata::default();
                        metadata.insert(
                            "query_padding".parse().unwrap(),
                            Json::new("p".repeat(metadata_bytes)),
                        );
                        tx = tx.with_metadata(metadata);
                    }
                    let instruction: InstructionBox = if epoch == 9 {
                        Unregister::domain(
                            iroha_model_base::domain::DomainId::try_new(
                                "missing-query-domain",
                                "universal",
                            )
                            .unwrap(),
                        )
                        .into()
                    } else {
                        Log::new(
                            iroha_data_model::Level::INFO,
                            format!("query {epoch}:{index}"),
                        )
                        .into()
                    };
                    tx.with_instructions([instruction]).sign(key.private_key())
                })
                .collect();
            chain.commit(transactions);
        }
        chain
    }

    /// Sixteen actual two-input native carriers above their authentic genesis.
    pub(crate) fn canonical_query_fixture() -> CanonicalQueryFixture {
        canonical_query_fixture_with_optional_query_gas(None)
    }
    /// The same original history with a finite query configuration fixed before execution.
    pub(crate) fn canonical_query_fixture_with_query_gas(units: u64) -> CanonicalQueryFixture {
        canonical_query_fixture_with_optional_query_gas(Some(units))
    }
    fn canonical_query_fixture_with_optional_query_gas(
        units: Option<u64>,
    ) -> CanonicalQueryFixture {
        let store = crate::kura::tests::CanonicalQueryStore::from_chain(
            native_query_chain_with_query_gas(16, 0, units),
        );
        let target = store.blocks[9].clone();
        let input = target.network_entrypoint_at(0).unwrap();
        let target_entrypoint_hash = input.hash();
        let target_authority = input.authority_opt().unwrap().clone();
        let target_timestamp_ms = input.creation_time_ms().unwrap();
        let state = Arc::clone(&store.state);
        let view = state.view();
        let tip = view
            .native_execution_tip()
            .expect("original executed native tip");
        assert_eq!(tip.height(), 17);
        assert_eq!(tip.iroha_hash(), store.blocks[16].hash());
        assert_eq!(view.height(), 17);
        drop(view);
        CanonicalQueryFixture {
            state,
            store,
            target_block_hash: target.hash(),
            target_entrypoint_hash,
            target_authority,
            target_timestamp_ms,
            target_height: NonZeroUsize::new(10).unwrap(),
            unrelated_height: NonZeroUsize::new(2).unwrap(),
        }
    }
    fn query_work_limits() -> TransactionHistoryWorkLimits {
        TransactionHistoryWorkLimits {
            max_carrier_work: 64,
            max_total_work: 512,
            max_bytes: TRANSACTION_HISTORY_MAX_BYTES,
        }
    }
    fn execute_indexed_carrier_query(
        state_ro: &impl StateReadOnly,
        filter: CompoundPredicate<CommittedTransaction>,
    ) -> Vec<CommittedTransaction> {
        state_ro.kura().reset_canonical_query_reads_for_test();
        let transactions =
            crate::smartcontracts::isi::tx::execute_transactions_fixture(filter, state_ro)
                .expect("indexed canonical Network transaction query succeeds")
                .collect::<Vec<_>>();
        assert_eq!(
            state_ro.kura().canonical_query_reads_for_test().0,
            8,
            "one selected carrier requires its exact height-17 through height-10 ancestry"
        );
        transactions
    }
    #[test]
    fn indexed_network_queries_read_only_selected_canonical_carriers() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        let by_block = execute_indexed_carrier_query(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| {
                p.equals("block_hash", fixture.target_block_hash.to_string())
            }),
        );
        assert_eq!(by_block.len(), 2);
        assert!(
            by_block
                .iter()
                .all(|transaction| transaction.block_hash == fixture.target_block_hash)
        );
        let by_hash = execute_indexed_carrier_query(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| {
                p.equals(
                    "entrypoint_hash",
                    fixture.target_entrypoint_hash.to_string(),
                )
            }),
        );
        assert_eq!(by_hash.len(), 1);
        assert_eq!(by_hash[0].entrypoint_hash, fixture.target_entrypoint_hash);
        let by_authority = execute_indexed_carrier_query(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| {
                p.equals("authority", fixture.target_authority.to_string())
            }),
        );
        assert_eq!(by_authority.len(), 1);
        assert_eq!(
            by_authority[0].entrypoint.authority_opt(),
            Some(&fixture.target_authority)
        );
        let by_timestamp = execute_indexed_carrier_query(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| {
                p.equals("timestamp_ms", fixture.target_timestamp_ms)
            }),
        );
        assert_eq!(by_timestamp.len(), 1);
        assert_eq!(
            by_timestamp[0].entrypoint.creation_time_ms(),
            Some(fixture.target_timestamp_ms)
        );
        let by_timestamp_range = execute_indexed_carrier_query(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::from_filters(CommittedTxFilters {
                ts_ge: Some(fixture.target_timestamp_ms),
                ts_le: Some(fixture.target_timestamp_ms),
                ..CommittedTxFilters::default()
            }),
        );
        assert_eq!(by_timestamp_range.len(), 1);
        let by_result = execute_indexed_carrier_query(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| p.equals("result_ok", false)),
        );
        assert_eq!(by_result.len(), 2);
        assert!(
            by_result
                .iter()
                .all(|transaction| transaction.result().as_ref().is_err())
        );
    }
    #[test]
    fn finalized_carrier_reader_and_state_wrapper_admit_exact_wire_and_work() {
        let chain = super::native_carrier_reader_tests::chain();
        let height = NonZeroUsize::new(2).unwrap();
        let expected_receipt = chain.committed(2);
        let expected = expected_receipt.block();
        let (work, bytes) = super::native_carrier_reader_tests::bounds(&chain, 2);
        let kura = chain.kura();
        kura.reset_canonical_query_reads_for_test();
        let read = chain
            .state()
            .read_finalized_execution_carrier(height, work, bytes)
            .unwrap();
        assert_eq!(read.wire_bytes(), bytes);
        assert_eq!(read.work_items(), work);
        assert_eq!(
            read.block().canonical_wire().unwrap().as_framed(),
            expected.canonical_wire().unwrap().as_framed()
        );
        assert_eq!(kura.canonical_query_reads_for_test(), (2, bytes));
        let mut actual = Vec::new();
        visit_finalized_network_transactions(
            chain.state(),
            height,
            expected.hash(),
            work,
            bytes,
            |source, result| {
                actual.push((source.hash(), result.is_ok()));
            },
        )
        .unwrap();
        let expected_rows = (0..expected.network_entrypoint_count())
            .map(|index| {
                (
                    expected.network_entrypoint_at(index).unwrap().hash(),
                    expected
                        .network_output_at(u32::try_from(index).unwrap())
                        .unwrap()
                        .1
                        .result
                        .is_ok(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected_rows);
        assert_eq!(read.into_block().hash(), expected.hash());
    }

    #[test]
    fn finalized_carrier_projects_exact_transaction_without_a_complete_auxiliary_index() {
        use crate::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use norito::codec::Encode as _;
        let config = TestChainConfig::new(World::new(), 1_000);
        let key = config.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(config).unwrap();
        let signed = chain.sign(
            &key,
            [iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                "exact cold carrier".into(),
            )
            .into()],
            1_001,
        );
        let hash = signed.hash_as_entrypoint();
        let saved_wire = signed.encode_wire_v1().unwrap();
        chain.commit(vec![signed]);
        let (work, bytes) = super::native_carrier_reader_tests::bounds(&chain, 2);
        let fixture = crate::kura::tests::CommittedNetworkProofFixture::from_chain(chain);
        fixture.make_target_cold();
        assert!(
            fixture
                .kura
                .get_block_heights_by_entrypoint_hash(hash)
                .is_none()
        );
        let index_before = fixture.index_image();
        let height = NonZeroUsize::new(2).unwrap();
        let view = fixture.state.view();
        assert!(matches!(
            committed_transactions_indexed_snapshot(
                &view,
                CompoundPredicate::from_filters(CommittedTxFilters {
                    entry_eq: Some(hash),
                    ..CommittedTxFilters::default()
                }),
                query_work_limits(),
                1,
                TRANSACTION_HISTORY_MAX_BYTES,
            ),
            Err(QueryExecutionFail::Conversion(_))
        ));
        drop(view);
        fixture.kura.reset_canonical_query_reads_for_test();
        let carrier = fixture
            .state
            .read_finalized_execution_carrier(height, work, bytes)
            .unwrap();
        let input_index = carrier
            .block()
            .network_entrypoints()
            .position(|entrypoint| entrypoint.hash() == hash)
            .unwrap() as u32;
        let details = carrier.transaction_at(input_index, bytes).unwrap();
        assert_eq!(details.entrypoint_hash, hash);
        assert!(details.result().is_ok());
        let TransactionEntrypoint::External(committed) = details.entrypoint() else {
            panic!("exact external transaction");
        };
        assert_eq!(committed.encode_wire_v1().unwrap(), saved_wire);
        let row_bytes = details.encode().len() as u64;
        assert_eq!(
            carrier.transaction_at(input_index, row_bytes).unwrap(),
            details
        );
        for limit in [0, row_bytes - 1] {
            assert!(matches!(
                carrier.transaction_at(input_index, limit),
                Err(QueryExecutionFail::GasBudgetExceeded)
            ));
        }
        assert!(carrier.transaction_at(u32::MAX, bytes).is_err());
        assert_eq!(fixture.kura.canonical_query_reads_for_test(), (2, bytes));
        assert_eq!(fixture.index_image(), index_before);
        assert!(!fixture.target_cached());
    }

    #[test]
    fn finalized_carrier_projects_rejected_registration_without_an_exact_length_hint() {
        use crate::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use iroha_data_model::{account::Account, isi::Register};
        use norito::{codec::Encode as _, core::SerializePayload as _};
        let config = TestChainConfig::new(World::new(), 1_000);
        let key = config.genesis_key.clone();
        let existing = AccountId::new(key.public_key().clone());
        let mut chain = CertifiedTestChain::start(config).unwrap();
        let signed = chain.sign(
            &key,
            [Register::account(Account::new(existing)).into()],
            1_001,
        );
        let hash = signed.hash_as_entrypoint();
        assert_eq!(chain.commit(vec![signed]), [false]);
        let (work, bytes) = super::native_carrier_reader_tests::bounds(&chain, 2);
        let carrier = chain
            .state()
            .read_finalized_execution_carrier(NonZeroUsize::new(2).unwrap(), work, bytes)
            .unwrap();
        let index = carrier
            .block()
            .network_entrypoints()
            .position(|entry| entry.hash() == hash)
            .unwrap() as u32;
        let (_, original) = carrier.block().network_output_at(index).unwrap();
        assert!(original.result.is_err());
        assert_eq!(
            original.encoded_len_exact(),
            None,
            "this real rejected output has no exact hint"
        );
        let projected = carrier
            .transaction_at(index, bytes)
            .expect("a missing optional hint does not exhaust the admitted row budget");
        assert_eq!(projected.entrypoint_hash, hash);
        assert!(projected.result().is_err());
        let exact = projected.encode().len() as u64;
        assert_eq!(carrier.transaction_at(index, exact).unwrap(), projected);
        for cap in [0, exact - 1] {
            assert!(matches!(
                carrier.transaction_at(index, cap),
                Err(QueryExecutionFail::GasBudgetExceeded)
            ));
        }
        assert!(projected.entrypoint_proof.verify(
            &projected.entrypoint_hash,
            &carrier.block().network_input_merkle_commitment().unwrap(),
        ));
        assert!(projected.output_proof.verify(
            &projected.output_hash,
            &carrier.block().output_merkle_commitment().unwrap(),
        ));
    }
    #[test]
    fn finalized_carrier_reader_denies_before_body_io_and_returns_no_partial_rows() {
        let chain = super::native_carrier_reader_tests::chain();
        let height = NonZeroUsize::new(2).unwrap();
        let expected = chain.committed(2);
        let (work, bytes) = super::native_carrier_reader_tests::bounds(&chain, 2);
        let target_bytes = expected.block().encode_wire().unwrap().len() as u64;
        let kura = chain.kura();
        for (work, limit) in [(0, bytes), (work, 0), (work, target_bytes - 1)] {
            kura.reset_canonical_query_reads_for_test();
            assert!(matches!(
                chain
                    .state()
                    .read_finalized_execution_carrier(height, work, limit),
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    QueryExecutionFail::GasBudgetExceeded
                ))
            ));
            assert_eq!(kura.canonical_query_reads_for_test(), (0, 0));
        }
        let mut visits = 0;
        assert!(matches!(
            visit_finalized_network_transactions(
                chain.state(),
                height,
                expected.block_hash(),
                1,
                bytes,
                |_, _| visits += 1
            ),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ));
        assert_eq!(visits, 0);
        kura.reset_canonical_query_reads_for_test();
        assert!(
            chain
                .state()
                .read_finalized_execution_carrier(NonZeroUsize::new(999).unwrap(), work, bytes)
                .is_err()
        );
        assert_eq!(kura.canonical_query_reads_for_test(), (0, 0));
    }

    #[test]
    fn finalized_carrier_reader_refuses_corrupt_exact_wire_even_with_warm_body() {
        let chain = super::native_carrier_reader_tests::chain();
        let height = NonZeroUsize::new(2).unwrap();
        let expected = chain.committed(2);
        let (work, bytes) = super::native_carrier_reader_tests::bounds(&chain, 2);
        chain
            .state()
            .read_finalized_execution_carrier(height, work, bytes)
            .unwrap();
        chain.kura().corrupt_native_frame_for_test(height);
        let mut visits = 0;
        assert!(
            visit_finalized_network_transactions(
                chain.state(),
                height,
                expected.block_hash(),
                work,
                bytes,
                |_, _| visits += 1
            )
            .is_err()
        );
        assert_eq!(visits, 0);
        assert!(
            chain
                .state()
                .read_finalized_execution_carrier(height, work, bytes)
                .is_err()
        );
        assert_eq!(
            expected.block().encode_wire().unwrap().len() as u64,
            chain
                .kura()
                .native_frame_read(2, expected.block_hash())
                .unwrap()
                .unwrap()
                .wire_len()
        );
    }

    #[test]
    fn indexed_snapshot_uses_entrypoint_index_and_rejects_unbounded_filters() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        state_view.kura().reset_canonical_query_reads_for_test();
        let selected = committed_transactions_indexed_snapshot(
            &state_view,
            CompoundPredicate::from_filters(CommittedTxFilters {
                entry_eq: Some(fixture.target_entrypoint_hash),
                ..CommittedTxFilters::default()
            }),
            query_work_limits(),
            64,
            TRANSACTION_HISTORY_MAX_BYTES,
        )
        .expect("indexed transaction snapshot");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].entrypoint_hash, fixture.target_entrypoint_hash);
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            8,
            "indexed materialization authenticates the selected carrier through its original tip"
        );
        state_view.kura().reset_canonical_query_reads_for_test();
        let missing_hash = HashOf::from_untyped_unchecked(Hash::new(b"missing-query-entrypoint"));
        let missing = committed_transactions_indexed_snapshot(
            &state_view,
            CompoundPredicate::from_filters(CommittedTxFilters {
                entry_eq: Some(missing_hash),
                ..CommittedTxFilters::default()
            }),
            query_work_limits(),
            64,
            TRANSACTION_HISTORY_MAX_BYTES,
        )
        .expect("missing indexed transaction snapshot");
        assert!(missing.is_empty());
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            0,
            "a complete sparse-index miss must not read a canonical carrier"
        );
        let error = committed_transactions_indexed_snapshot(
            &state_view,
            CompoundPredicate::PASS,
            query_work_limits(),
            64,
            TRANSACTION_HISTORY_MAX_BYTES,
        )
        .expect_err("unbounded transaction history must be rejected");
        assert!(
            error
                .to_string()
                .contains("require a positive indexed filter")
        );
    }
    #[test]
    fn indexed_and_unindexed_transaction_history_report_the_same_hash_only_gap() {
        let fixture = canonical_query_fixture();
        let target_height = fixture
            .state
            .view()
            .block_height_by_hash(fixture.target_block_hash)
            .expect("target transaction carrier must be indexed");
        fixture
            .state
            .kura()
            .corrupt_canonical_body_for_testing(target_height)
            .expect("convert target transaction carrier to hash-only form");
        let state_view = fixture.state.view();
        for height in 1..target_height.get() {
            state_view
                .canonical_block_by_height(NonZeroUsize::new(height).expect("positive height"))
                .expect("evicting the selected body must preserve earlier canonical bodies");
        }
        let indexed_error = committed_transactions_indexed_snapshot(
            &state_view,
            CompoundPredicate::from_filters(CommittedTxFilters {
                entry_eq: Some(fixture.target_entrypoint_hash),
                ..CommittedTxFilters::default()
            }),
            query_work_limits(),
            64,
            TRANSACTION_HISTORY_MAX_BYTES,
        )
        .expect_err("indexed history must reject a hash-only selected carrier");
        let unindexed_error = crate::smartcontracts::isi::tx::execute_transactions_fixture(
            CompoundPredicate::PASS,
            &state_view,
        )
        .err()
        .expect("unindexed history must reject the same hash-only carrier");
        let paginated_error = visit_committed_transactions(
            &state_view,
            &CompoundPredicate::PASS,
            TransactionHistoryAnchor::capture(&state_view),
            None,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, _| Ok(()),
            |_, _, _| Ok(ControlFlow::Continue(())),
        )
        .expect_err("paginated history must surface the same hash-only carrier gap");
        assert!(matches!(
            &indexed_error,
            QueryExecutionFail::CanonicalHistory(
                iroha_data_model::query::error::CanonicalHistoryError::BodyUnavailable {
                    height,
                    ..
                }
            ) if *height == u64::try_from(target_height.get()).unwrap()
        ));
        assert_eq!(unindexed_error, indexed_error);
        assert_eq!(paginated_error, indexed_error);
    }
    #[test]
    fn indexed_network_query_ignores_unselected_corruption_and_fails_on_selected_corruption() {
        let unrelated = canonical_query_fixture();
        unrelated.store.corrupt_body(unrelated.unrelated_height);
        let unrelated_view = unrelated.state.view();
        let selected = execute_indexed_carrier_query(
            &unrelated_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| {
                p.equals(
                    "entrypoint_hash",
                    unrelated.target_entrypoint_hash.to_string(),
                )
            }),
        );
        assert_eq!(selected.len(), 1);
        unrelated_view.kura().reset_canonical_query_reads_for_test();
        assert!(
            crate::smartcontracts::isi::tx::execute_transactions_fixture(
                CompoundPredicate::<CommittedTransaction>::PASS,
                &unrelated_view,
            )
            .is_err(),
            "unindexed complete history must fail closed on any corrupt canonical body"
        );
        assert_eq!(
            unrelated_view.kura().canonical_query_reads_for_test().0,
            16,
            "descending complete scan reaches the corrupted height-two body"
        );
        let selected = canonical_query_fixture();
        selected.store.corrupt_body(selected.target_height);
        let selected_view = selected.state.view();
        selected_view.kura().reset_canonical_query_reads_for_test();
        assert!(
            crate::smartcontracts::isi::tx::execute_transactions_fixture(
                CompoundPredicate::<CommittedTransaction>::build(|p| {
                    p.equals(
                        "entrypoint_hash",
                        selected.target_entrypoint_hash.to_string(),
                    )
                }),
                &selected_view,
            )
            .is_err(),
            "selected corrupt canonical body must fail closed before returning an iterator"
        );
        assert_eq!(selected_view.kura().canonical_query_reads_for_test().0, 8);
    }
    #[test]
    fn canonical_query_reader_rejects_changed_outputs_under_original_finality() {
        let fixture = canonical_query_fixture();
        let original = &fixture.store.blocks[fixture.target_height.get() - 1];
        let mut changed = original.as_ref().clone();
        let mut rows = changed.execution_outputs().to_vec();
        let ExecutionOutputV1::Network(row) = &mut rows[0] else {
            unreachable!()
        };
        let Err(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            iroha_data_model::isi::error::InstructionExecutionError::Find(
                iroha_data_model::query::error::FindError::Domain(domain),
            ),
        ))) = &mut row.result.0
        else {
            panic!(
                "original native rejection must name the missing domain: {:?}",
                row.result
            );
        };
        assert_eq!(domain.to_string(), "missing-query-domain.universal");
        // Alter the actual typed rejection without discarding its original receipt fields.
        // The replacement label has the same canonical length, so the durable index stays exact.
        *domain = iroha_model_base::domain::DomainId::try_new(
            "changed-query-domain",
            domain.dataspace().as_ref(),
        )
        .expect("same-length canonical domain label");
        install_query_outputs(&mut changed, rows);
        changed.validate_output_merkle_cache().unwrap();
        assert_eq!(changed.hash(), original.hash());
        assert_eq!(
            changed
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection"),
            original
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection")
        );
        assert_ne!(
            changed.output_merkle_commitment(),
            original.output_merkle_commitment()
        );
        let wire = changed.encode_wire().unwrap();
        assert_eq!(wire.len(), original.encode_wire().unwrap().len());
        assert_ne!(Hash::new(&wire), Hash::new(original.encode_wire().unwrap()));
        let decoded = iroha_data_model::block::decode_framed_signed_block(&wire)
            .expect("changed output is internally canonical, unlike a checksum corruption");
        let expected_height = fixture.target_height.get() as u64;
        let frame_error = crate::sumeragi::certified_chain::read_frame(
            crate::block::reserve_block_for_tests().initialize(decoded),
            expected_height,
        )
        .expect_err("original execution certificate cannot commit the changed output");
        assert!(matches!(&frame_error,
            crate::execution_attempt::ExecutionAttemptError::Rejected(
                crate::sumeragi::certified_chain::ChainReadError::ExecutionMismatch { height })
                if *height == expected_height));
        let expected_error = QueryExecutionFail::Conversion(frame_error.to_string());
        fixture.store.overwrite_body(fixture.target_height, &wire);
        let error = execute_transactions_fixture(
            CompoundPredicate::from_filters(CommittedTxFilters {
                entry_eq: Some(fixture.target_entrypoint_hash),
                ..Default::default()
            }),
            &fixture.state.view(),
        )
        .err()
        .expect("original QC must reject self-consistent changed output");
        assert_eq!(
            error, expected_error,
            "query must reject the exact original execution commitment mismatch"
        );
    }
    #[test]
    fn transaction_history_pages_resume_strictly_before_their_position() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        let walk = |resume, work, stop_after: usize| {
            let mut page = Vec::new();
            let end = visit_committed_transaction_page(
                &state_view,
                resume,
                work,
                TRANSACTION_HISTORY_MAX_BYTES,
                |transaction, position| {
                    page.push((transaction.entrypoint_hash, position));
                    if page.len() == stop_after {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                },
            )
            .expect("history page");
            (page, end)
        };
        // A cold node authenticates history from the tip, so a one-block budget
        // cannot reach a position below the newest block.
        state_view.kura().history_checkpoints().clear();
        let deep = TransactionHistoryPosition::new(3, 0).expect("position");
        let (rest, end) = walk(Some(deep), 1, usize::MAX);
        assert!(rest.is_empty());
        assert_eq!(end, TransactionHistoryPageEnd::OutOfReach);
        let (all, end) = walk(None, 1_000, usize::MAX);
        assert_eq!(end, TransactionHistoryPageEnd::Exhausted);
        assert!(all.len() >= 4, "fixture spans several carriers");
        assert!(
            all.windows(2).all(|pair| pair[0].1 > pair[1].1),
            "newest first with strictly decreasing coordinates"
        );
        let mut paged = Vec::new();
        let mut resume = None;
        loop {
            let (page, end) = walk(resume, 1_000, 3);
            paged.extend(page);
            match end {
                TransactionHistoryPageEnd::Stopped(position) => resume = Some(position),
                TransactionHistoryPageEnd::Exhausted => break,
                TransactionHistoryPageEnd::BudgetSpent(_)
                | TransactionHistoryPageEnd::OutOfReach => {
                    panic!("the budget is ample")
                }
            }
        }
        assert_eq!(
            paged, all,
            "stopped pages resume strictly before their position"
        );
        // The smallest budget that reaches the newest transaction.
        let work = (1..1_000)
            .find(|work| !walk(None, *work, usize::MAX).0.is_empty())
            .expect("an ample budget reaches the newest transaction");
        let mut budgeted = Vec::new();
        let mut resume = None;
        let mut pages = 0;
        let out_of_reach = loop {
            let (page, end) = walk(resume, work, usize::MAX);
            budgeted.extend(page);
            pages += 1;
            match end {
                TransactionHistoryPageEnd::BudgetSpent(position) => resume = Some(position),
                TransactionHistoryPageEnd::OutOfReach => break true,
                TransactionHistoryPageEnd::Exhausted => break false,
                TransactionHistoryPageEnd::Stopped(_) => unreachable!("the visitor never stops"),
            }
        };
        assert!(pages > 1, "a minimal budget spreads history over pages");
        assert!(!budgeted.is_empty());
        assert_eq!(
            budgeted[..],
            all[..budgeted.len()],
            "spent budgets end pages without skipping or repeating rows"
        );
        assert!(
            out_of_reach || budgeted == all,
            "a walk ends only when history is exhausted or out of reach"
        );
        let oldest = all[all.len() - 1].1;
        let (rest, end) = walk(Some(oldest), 1_000, usize::MAX);
        assert!(rest.is_empty(), "nothing precedes the oldest transaction");
        assert_eq!(end, TransactionHistoryPageEnd::Exhausted);
        // Walks remember the identities they verify, so once warm the same deep
        // position is reached within a budget far below a walk from the tip.
        let warm = (1..16)
            .find(|work| !walk(Some(deep), *work, usize::MAX).0.is_empty())
            .expect("a warm walk reaches the deep position cheaply");
        let (rest, _) = walk(Some(deep), warm, usize::MAX);
        let first_older = all
            .iter()
            .position(|(_, position)| *position < deep)
            .expect("history precedes the deep position");
        assert_eq!(
            rest[..],
            all[first_older..first_older + rest.len()],
            "a warm deep page continues exactly where history stands"
        );
    }
    #[test]
    fn fallible_transaction_visitor_reads_only_carriers_needed_by_bounded_page() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        state_view.kura().reset_canonical_query_reads_for_test();
        let mut visited = Vec::new();
        let exhausted = visit_committed_transactions(
            &state_view,
            &CompoundPredicate::PASS,
            TransactionHistoryAnchor::capture(&state_view),
            None,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, _| Ok(()),
            |transaction, matches, _| {
                assert!(matches);
                visited.push(transaction);
                Ok(if visited.len() == 3 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                })
            },
        )
        .expect("bounded fallible transaction scan");
        assert!(!exhausted);
        assert_eq!(visited.len(), 3);
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            2,
            "three newest transactions span exactly two two-entry carriers"
        );
        assert!(visited.iter().all(|transaction| {
            let block = fixture
                .store
                .blocks
                .iter()
                .find(|block| block.hash() == transaction.block_hash)
                .unwrap();
            transaction.verify_inclusion_in_block(block)
        }));
    }
    #[test]
    fn bounded_transaction_snapshot_rejects_count_and_byte_amplification() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        assert_eq!(
            committed_transactions_bounded_snapshot(
                &state_view,
                CompoundPredicate::PASS,
                query_work_limits(),
                1,
                TRANSACTION_HISTORY_MAX_BYTES,
            )
            .expect_err("retained row count is independently bounded"),
            QueryExecutionFail::FetchSizeTooBig
        );
        assert_eq!(
            committed_transactions_bounded_snapshot(
                &state_view,
                CompoundPredicate::PASS,
                query_work_limits(),
                iroha_data_model::query::parameters::MAX_FETCH_SIZE.get(),
                1,
            )
            .expect_err("retained canonical bytes must be bounded"),
            QueryExecutionFail::GasBudgetExceeded
        );
    }
    #[test]
    fn bounded_transaction_visitor_does_not_charge_chain_age_as_retained_memory() {
        let fixture = canonical_query_fixture();
        // The authentic genesis now contains three signed inputs; each successor has two.
        // These finite fixture bounds follow the original source, not a larger production cap.
        let geometry: Vec<_> = fixture
            .store
            .blocks
            .iter()
            .map(|block| {
                (
                    block.network_entrypoint_count(),
                    block.execution_outputs().len(),
                )
            })
            .collect();
        assert_eq!(geometry[0], (3, 3));
        assert_eq!(geometry[1..], [(2, 2); 16]);
        assert_eq!(
            geometry
                .iter()
                .map(|(inputs, outputs)| inputs.max(outputs))
                .sum::<usize>(),
            35
        );
        let carrier_bound = u64::try_from(
            geometry
                .iter()
                .map(|(inputs, outputs)| (*inputs).max(*outputs))
                .max()
                .unwrap(),
        )
        .unwrap();
        let total_bound = u64::try_from(
            geometry
                .iter()
                .map(|(inputs, outputs)| inputs.max(outputs))
                .sum::<usize>(),
        )
        .unwrap();
        let state_view = fixture.state.view();
        let false_filter = CompoundPredicate::<CommittedTransaction>::build(|prototype| {
            prototype.equals("field_that_does_not_exist", true)
        });
        // Preserve the former 2/33 bound as a refusal, then isolate each insufficient bound.
        // All 32 successor rows may be projected; the three-row genesis must be prepaid whole.
        for (carrier_work, total_work) in [(2, 33), (2, 35), (3, 34)] {
            let mut visited = 0;
            let error = visit_committed_transactions_with_work_budget(
                &state_view,
                false_filter.clone(),
                carrier_work,
                total_work,
                TRANSACTION_HISTORY_MAX_BYTES,
                |_, matches| {
                    assert!(!matches);
                    visited += 1;
                    Ok(ControlFlow::Continue(()))
                },
            )
            .expect_err("unpaid whole genesis must not reach row projection");
            assert_eq!(error, QueryExecutionFail::GasBudgetExceeded);
            assert_eq!(visited, 32);
        }
        let mut visited = 0_usize;
        let exhausted = visit_committed_transactions_with_work_budget(
            &state_view,
            false_filter,
            carrier_bound,
            total_bound,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, matches| {
                assert!(!matches);
                visited = visited.saturating_add(1);
                Ok(ControlFlow::Continue(()))
            },
        )
        .expect("each carrier fits independently within the projection bound");
        assert!(exhausted);
        assert_eq!(
            visited,
            usize::try_from(total_bound).expect("retained row census")
        );
        assert!(visited > 2, "the scan crossed multiple bounded carriers");
    }
    #[test]
    fn cumulative_transaction_visitor_bounds_chain_age_and_projection_work() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        state_view.kura().reset_canonical_query_reads_for_test();
        let false_filter = CompoundPredicate::<CommittedTransaction>::build(|prototype| {
            prototype.equals("field_that_does_not_exist", true)
        });
        let mut visited = 0_usize;
        let error = visit_committed_transactions_with_work_budget(
            &state_view,
            false_filter,
            2,
            3,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, matches| {
                assert!(!matches);
                visited = visited.saturating_add(1);
                Ok(ControlFlow::Continue(()))
            },
        )
        .expect_err("a second two-entry carrier must exceed cumulative work three");
        assert_eq!(error, QueryExecutionFail::GasBudgetExceeded);
        assert_eq!(visited, 2, "only the first carrier may be projected");
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            2,
            "the complete row work is charged after its admitted body read, before proof projection",
        );
    }
    #[test]
    fn authenticated_history_walk_stops_before_unreached_corruption_and_prepays_io() {
        let store = crate::kura::tests::CanonicalQueryStore::from_chain(native_query_chain(3, 0));
        store.corrupt_body(NonZeroUsize::new(2).unwrap());
        let view = store.state.view();
        let source = view.canonical_history();
        let first = NonZeroUsize::MIN;
        let last = NonZeroUsize::new(4).unwrap();
        store.kura.reset_canonical_query_reads_for_test();
        let mut source_charges = Vec::new();
        let mut visited = Vec::new();
        let exhausted = source
            .visit_executed_backwards_until(
                first,
                last,
                |frames, bytes| {
                    source_charges.push((frames, bytes));
                    Ok(())
                },
                |receipt| {
                    visited.push(receipt.height());
                    Ok(if receipt.height() == 3 {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    })
                },
            )
            .expect("exact original ancestry above the corruption remains readable");
        assert!(!exhausted);
        assert_eq!(visited, [4, 3]);
        assert_eq!(
            source_charges,
            [(1, store.wire_bytes([4])), (1, store.wire_bytes([3])),]
        );
        assert_eq!(
            store.kura.canonical_query_reads_for_test(),
            (2, store.wire_bytes([4, 3]))
        );
        let err = source
            .visit_executed_backwards_until(
                first,
                last,
                |_, _| Ok(()),
                |_| Ok(ControlFlow::Continue(())),
            )
            .expect_err("a complete walk must authenticate the corrupt older source");
        assert!(matches!(
            err,
            crate::execution_attempt::ExecutionAttemptError::Rejected(
                QueryExecutionFail::Conversion(_)
            )
        ));
        store.kura.reset_canonical_query_reads_for_test();
        let err = source
            .visit_executed_backwards_until(
                first,
                last,
                |_, _| {
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ))
                },
                |_| panic!("unpaid source cannot reach a receipt visitor"),
            )
            .expect_err("source work and bytes are admitted before physical I/O");
        assert_eq!(
            err,
            crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into()
            )
        );
        assert_eq!(store.kura.canonical_query_reads_for_test(), (0, 0));
    }

    #[test]
    fn cumulative_transaction_visitor_charges_nonmatching_native_carriers() {
        let store = crate::kura::tests::CanonicalQueryStore::from_chain(native_query_chain(3, 0));
        let state_view = store.state.view();
        store.kura.reset_canonical_query_reads_for_test();
        let error = visit_committed_transactions_with_work_budget(
            &state_view,
            CompoundPredicate::<CommittedTransaction>::build(|p| {
                p.equals("field_that_does_not_exist", true)
            }),
            64,
            2,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, matches| {
                assert!(!matches);
                Ok(ControlFlow::Continue(()))
            },
        )
        .expect_err("original native source prefix exceeds finite cumulative work");
        assert_eq!(error, QueryExecutionFail::GasBudgetExceeded);
    }
    #[test]
    fn transaction_budget_rejects_large_body_before_read_or_decode() {
        const TRANSACTION_METADATA_BYTES: usize = 256 * 1024;
        let store = crate::kura::tests::CanonicalQueryStore::from_chain(native_query_chain(
            1,
            TRANSACTION_METADATA_BYTES,
        ));
        let expected_bytes = store.wire_bytes([2]);
        assert!(expected_bytes > u64::try_from(2 * TRANSACTION_METADATA_BYTES).unwrap());
        let state = &store.state;
        let state_view = state.view();
        store.kura.reset_canonical_query_reads_for_test();
        reset_canonical_network_projection_calls_for_test();
        let mut charges = Vec::new();
        let err = visit_committed_transactions(
            &state_view,
            &CompoundPredicate::PASS,
            TransactionHistoryAnchor::capture(&state_view),
            None,
            TRANSACTION_HISTORY_MAX_BYTES,
            |work, bytes| {
                charges.push((work, bytes));
                Err(QueryExecutionFail::GasBudgetExceeded)
            },
            |_, _, _| panic!("underfunded query must not project a transaction"),
        )
        .expect_err("authenticated physical bytes are charged before allocation or decode");
        assert_eq!(err, QueryExecutionFail::GasBudgetExceeded);
        assert_eq!(charges, vec![(1, expected_bytes)]);
        assert_eq!(store.kura.canonical_query_reads_for_test(), (0, 0));
        assert_eq!(canonical_network_projection_calls_for_test(), 0);
    }
    #[test]
    fn fallible_transaction_visitor_exact_scan_is_point_indexed_and_ordered() {
        let fixture = canonical_query_fixture();
        let state_view = fixture.state.view();
        let expected = committed_transactions_snapshot(&state_view).expect("eager exact baseline");
        state_view.kura().reset_canonical_query_reads_for_test();
        let mut visited = Vec::new();
        let exhausted = visit_committed_transactions(
            &state_view,
            &CompoundPredicate::PASS,
            TransactionHistoryAnchor::capture(&state_view),
            None,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, _| Ok(()),
            |transaction, matches, _| {
                assert!(matches);
                visited.push(transaction);
                Ok(ControlFlow::Continue(()))
            },
        )
        .expect("fallible exact transaction scan");
        assert!(exhausted);
        assert_eq!(visited, expected);
        assert_eq!(
            state_view.kura().canonical_query_reads_for_test().0,
            17,
            "exact scan reads every complete body, including the empty genesis"
        );
    }
    #[test]
    fn fallible_transaction_visitor_defers_unreached_corruption_but_exact_fails() {
        let fixture = canonical_query_fixture();
        let mut corrupted_wire = fixture.store.blocks[fixture.unrelated_height.get() - 1]
            .encode_wire()
            .expect("original canonical historical wire");
        *corrupted_wire
            .last_mut()
            .expect("original wire is nonempty") ^= 1;
        let codec_error = iroha_data_model::block::decode_framed_signed_block(&corrupted_wire)
            .expect_err("altered source must fail its canonical frame checksum");
        assert_eq!(
            codec_error.kind(),
            norito::core::DecodeAttemptErrorKind::Invalid
        );
        let codec_error = codec_error.into_error();
        assert!(matches!(codec_error, norito::Error::ChecksumMismatch));
        let expected_error = QueryExecutionFail::Conversion(codec_error.to_string());
        fixture.store.corrupt_body(fixture.unrelated_height);
        let state_view = fixture.state.view();
        let mut visited = 0_usize;
        let exhausted = visit_committed_transactions(
            &state_view,
            &CompoundPredicate::PASS,
            TransactionHistoryAnchor::capture(&state_view),
            None,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, _| Ok(()),
            |_, matches, _| {
                assert!(matches);
                visited += 1;
                Ok(if visited == 2 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                })
            },
        )
        .expect("newest bounded page should not touch the corrupt oldest carrier");
        assert!(!exhausted);
        assert_eq!(visited, 2);
        let err = visit_committed_transactions(
            &state_view,
            &CompoundPredicate::PASS,
            TransactionHistoryAnchor::capture(&state_view),
            None,
            TRANSACTION_HISTORY_MAX_BYTES,
            |_, _| Ok(()),
            |_, _, _| Ok(ControlFlow::Continue(())),
        )
        .expect_err("exact scan must fail on selected historical corruption");
        assert_eq!(
            err, expected_error,
            "exact visitor must propagate the complete canonical source refusal"
        );
    }
    /// Verifies that all per-field iterators over a committed block are consistent.
    #[tokio::test]
    async fn block_iterators_are_consistent() {
        let mut sandbox = Sandbox::default()
            .with_data_trigger_transfer("bob", 40, "carol")
            .with_time_trigger_transfer_labeled("alice", 1, "alice", 0)
            .with_time_trigger_transfer_labeled("alice", 1, "alice", 1)
            .with_time_trigger_transfer_labeled("alice", 1, "alice", 2)
            .with_time_trigger_transfer("carol", 30, "dave")
            .with_data_trigger_transfer("dave", 20, "eve");
        sandbox.request_transfer("alice", 50, "bob");
        sandbox.request_transfer("eve", 1, "eve");
        sandbox.request_transfer("eve", 2, "eve");
        sandbox.request_transfer("eve", 3, "eve");
        sandbox.request_transfer("eve", 4, "eve");
        sandbox.request_transfer("eve", 5, "eve");
        let mut block = sandbox.block();
        block.assert_balances([
            ("alice", 60),
            ("bob", 10),
            ("carol", 10),
            ("dave", 10),
            ("eve", 10),
        ]);
        let (_events, committed_block) = block.apply();
        block.assert_balances([
            ("alice", 10),
            ("bob", 20),
            ("carol", 20),
            ("dave", 20),
            ("eve", 30),
        ]);
        let block = committed_block.as_ref();
        let ordinary = block_committed_transactions(block).unwrap();
        assert_eq!(ordinary.len(), 6);
        assert!(
            ordinary
                .iter()
                .all(|tx| tx.verify_inclusion_in_block(block))
        );
        assert_eq!(6, block.network_input_hashes().len());
        assert_eq!(6, block.external_entrypoints_cloned().len());
        assert_eq!(6, block.external_transactions().len());
        assert_eq!(10, block.output_hashes().len());
        assert_eq!(10, block.output_results().len());
        assert_eq!(
            4,
            block
                .execution_outputs()
                .iter()
                .filter(|row| matches!(row, ExecutionOutputV1::Time(_)))
                .count()
        );
        let inputs = block.network_input_merkle_tree();
        assert!((0..6).all(|index| inputs.get_proof(index).is_some()));
        assert!(inputs.get_proof(6).is_none());
        assert!((0..10).all(|index| block.output_proof(index).is_some()));
        assert!(block.output_proof(10).is_none());
        assert_eq!(
            block.network_input_hashes().collect::<Vec<_>>(),
            block
                .external_entrypoints_cloned()
                .map(|entry| entry.hash())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            block.output_hashes().collect::<Vec<_>>(),
            block
                .execution_outputs()
                .iter()
                .map(HashOf::new)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            block.external_entrypoints_cloned().collect::<Vec<_>>(),
            block
                .external_transactions()
                .cloned()
                .map(TransactionEntrypoint::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            block.external_entrypoints_cloned().next(),
            block
                .external_transactions()
                .cloned()
                .map(TransactionEntrypoint::from)
                .next()
        );
        assert_eq!(
            block.external_entrypoints_cloned().next_back(),
            block
                .external_transactions()
                .cloned()
                .map(TransactionEntrypoint::from)
                .next_back()
        );
        assert_eq!(
            block.output_hashes().next(),
            block.execution_outputs().first().map(HashOf::new)
        );
        assert_eq!(
            block.output_hashes().last(),
            block.execution_outputs().last().map(HashOf::new)
        );
        for (index, entry) in block.network_entrypoints().enumerate() {
            let (position, row) = block
                .network_output_at(u32::try_from(index).unwrap())
                .unwrap();
            assert_eq!(position, row.input_index);
            assert_eq!(ordinary[5 - index].entrypoint_hash, entry.hash());
            assert_eq!(ordinary[5 - index].result(), &row.result);
        }
    }
}

#[cfg(test)]
#[path = "tx_canonical_network_query_tests.rs"]
mod canonical_network_query_tests;

#[cfg(test)]
mod native_carrier_reader_tests;
