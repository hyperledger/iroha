//! Native history production under the request's original complete memory owner.
//!
//! A byte counter is not an allocation permit. This module joins the existing query-pool
//! reservation to one cumulative native codec context and one original cold-frame pool.
//! Finality prepays that entire grant once, then Core reuses a bounded live-graph working set.
//! Every clone shares those same owners. Synchronous scopes restore thread state before returning;
//! no native allocation scope survives an await or moves to an unrelated request.

use std::cell::RefCell;
#[cfg(test)]
use std::sync::Arc;

use iroha_allocation::{AllocationBudget, ChargedShared};
use norito::{DecodeLimits, core::DecodeBudgetContext};

use crate::{Error, QueryAdmissionPermit, QueryFanoutMemoryEnvelope, QueryFanoutMemoryReservation};

fn capacity() -> Error {
    crate::native_projection_response::capacity()
}

/// The producer phases are created only by the original query-pool acquisition.
pub struct ProducerBudget {
    envelope: QueryFanoutMemoryEnvelope,
    pool_generation: u64,
    cold_frames: AllocationBudget,
    /// Finality's bounded live graphs use the portion of the original producer
    /// grant outside the cold-frame corridor, prepaid through `allocations`.
    finality_graphs: AllocationBudget,
    /// Physical response-wrapper layouts occupy the remaining encoder corridor. They grant
    /// neither decoder credit nor source admission, and all clones keep this original pool.
    response_metadata: AllocationBudget,
    allocations: DecodeBudgetContext,
    allocation_limits: DecodeLimits,
    /// Set when a limit derived from this owner refused the read, so the admission
    /// that granted it may serve the same read again with a larger owner.
    owner_limit_refused: std::sync::atomic::AtomicBool,
}

impl ProducerBudget {
    pub(crate) fn response_metadata(&self) -> &AllocationBudget {
        &self.response_metadata
    }
    pub(crate) fn note_owner_limit_refused(&self) {
        self.owner_limit_refused
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub(crate) fn owner_limit_refused(&self) -> bool {
        self.owner_limit_refused
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Derive corridors from an already admitted envelope, never a configured or response cap.
    pub(crate) fn from_admitted(
        envelope: QueryFanoutMemoryEnvelope,
        pool_generation: u64,
    ) -> Result<ChargedShared<Self>, Error> {
        // Generic history retains one raw source, cumulative native block/result graphs, compact selected
        // rows and cursor scratch, then the exact response. Request representations and their
        // decode phase stay outside this corridor. Counting allocations cumulatively is stricter
        // than live-byte accounting: freeing a traversed ancestor does not reset this allowance.
        // Both inline and evicted cold frames charge this same cumulative counter before
        // their physical frame-pool allocation. Do not count that sub-pool a second time.
        // Keep the independently retained request bytes and input decode phase, native
        // wrapper/control corridor, and existing fixed allowance outside this grant.
        // Their sum plus this cumulative grant is exactly the actual admitted W, even
        // for signed fanout envelopes whose phase is larger than prebody admission.
        // A prebody owner has not measured Q/E yet: request_bytes == 0 reserves
        // the original seven signed plus one verified representation, rather than
        // asserting no request retention. The shared prebody denominator already
        // admits precisely this floor. Measured envelopes retain their exact bytes.
        // Original bodyless-finality admission explicitly sets request decode to zero,
        // so it has no request-retention floor. Existing envelopes are never reinterpreted.
        let retained_request = if envelope.request_bytes == 0 {
            envelope
                .request_decode_allocated_bytes
                .checked_mul(
                    crate::QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS
                        + crate::QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS,
                )
                .ok_or_else(capacity)?
        } else {
            envelope.request_bytes
        };
        let allocated = envelope
            .working_set_bytes
            .checked_sub(retained_request)
            .and_then(|bytes| bytes.checked_sub(envelope.request_decode_allocated_bytes))
            .and_then(|bytes| bytes.checked_sub(envelope.candidate_encoded_bytes))
            .and_then(|bytes| bytes.checked_sub(crate::query_fanout_fixed_overhead_bytes()?))
            .filter(|bytes| *bytes >= envelope.final_body_bytes)
            .ok_or_else(capacity)?;
        let response_metadata = AllocationBudget::new(envelope.candidate_encoded_bytes);
        let allocation_limits = DecodeLimits::new(
            envelope.decode_allocated_bytes,
            envelope.route_body_bytes,
            allocated,
            allocated,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        let allocations = DecodeBudgetContext::try_new_owned(allocation_limits, &response_metadata)
            .map_err(|_| capacity())?;
        let finality_graphs = AllocationBudget::new(
            allocated
                .checked_sub(envelope.route_body_bytes)
                .ok_or_else(capacity)?,
        );
        let mut reservation = response_metadata
            .try_reserve(ChargedShared::<Self>::allocation_layout())
            .map_err(|_| capacity())?;
        let budget = Self {
            envelope,
            pool_generation,
            cold_frames: AllocationBudget::new(envelope.route_body_bytes),
            finality_graphs,
            response_metadata,
            allocations,
            allocation_limits,
            owner_limit_refused: std::sync::atomic::AtomicBool::new(false),
        };
        ChargedShared::from_reservation(budget, &mut reservation).map_err(|_| capacity())
    }
}

/// Closed capability retaining both actual admission and its unchanged producer corridors.
#[derive(Clone)]
pub struct HistoryProducerOwner {
    // Reclaim all native producer controls before the last query lease releases credit.
    budget: ChargedShared<ProducerBudget>,
    _reservation: QueryFanoutMemoryReservation,
}

thread_local! {
    static PHYSICAL_HISTORY_OWNER: RefCell<Option<HistoryProducerOwner>> = const {
        RefCell::new(None)
    };
}

impl HistoryProducerOwner {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let working = 48 * 1024 * 1024;
        let pool = crate::ByteWeightedMemoryPool::new(working).unwrap();
        let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([working as u64]).unwrap(),
            QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap(),
            pool.generation(),
        )
        .unwrap();
        Self::from_reservation(&reservation).unwrap()
    }
    /// Capture the admitted producer before moving the request into a physical worker.
    pub(crate) fn from_admission(admission: &QueryAdmissionPermit) -> Result<Self, Error> {
        Self::from_reservation(admission._fanout_memory.as_ref().ok_or_else(capacity)?)
    }

    /// A present outer capability may never disappear into a fresh, wider finality
    /// admission. The generic asynchronous lookup filters foreign generations;
    /// compare actual pool custody as well before selecting the bodyless path.
    pub(crate) fn validate_finality_inheritance(
        admission: &QueryAdmissionPermit,
    ) -> Result<(), Error> {
        if let Some(inherited) = Self::current_if_admitted()? {
            let admitted = Self::from_admission(admission)?;
            if !inherited.cold_frames().same_pool(admitted.cold_frames()) {
                return Err(capacity());
            }
        }
        Ok(())
    }

    /// Response-only tokens and a different admission generation cannot grant production.
    pub(crate) fn from_reservation(
        reservation: &QueryFanoutMemoryReservation,
    ) -> Result<Self, Error> {
        let admitted = reservation.admission.ok_or_else(capacity)?;
        let budget = reservation.producer.as_ref().ok_or_else(capacity)?;
        if budget.envelope != admitted.envelope
            || budget.pool_generation != admitted.pool_generation
        {
            return Err(capacity());
        }
        Ok(Self {
            _reservation: reservation.clone(),
            budget: budget.clone(),
        })
    }

    /// Borrow only the retained physical or asynchronous request capability.
    /// Asynchronous lookup supplies data; it never installs a native thread scope.
    pub(crate) fn current() -> Result<Self, Error> {
        Self::current_if_admitted()?.ok_or_else(capacity)
    }

    /// Distinguish an explicitly standalone engine from a present but invalid admission.
    /// A failed query owner must never select a standalone serialization path.
    pub(crate) fn current_if_admitted() -> Result<Option<Self>, Error> {
        if let Some(owner) = PHYSICAL_HISTORY_OWNER.with(|current| current.borrow().clone()) {
            return Ok(Some(owner));
        }
        #[cfg(feature = "app_api")]
        if let Ok(owner) =
            crate::COLLECTION_READ_MEMORY_RESERVATION.try_with(Self::from_reservation)
        {
            return owner.map(Some);
        }
        if let Ok(owner) = crate::APP_ROUTED_READ_HTTP_ADMISSION
            .try_with(|admission| Self::from_reservation(&admission.reservation))
        {
            return owner.map(Some);
        }
        Ok(None)
    }

    /// Retain one cumulative context across all synchronous source and projection phases.
    pub(crate) fn scope<R>(&self, work: impl FnOnce() -> R) -> R {
        self.physical_scope(|| self.budget.allocations.with(work))
    }

    /// Install only original admission custody for a separately prepaid producer.
    /// Any enclosing decoder scopes remain active; none is cleared or replaced.
    /// Finality uses this while Core owns its finite live-graph working set.
    pub(crate) fn physical_scope<R>(&self, work: impl FnOnce() -> R) -> R {
        struct Restore(Option<HistoryProducerOwner>);
        impl Drop for Restore {
            fn drop(&mut self) {
                PHYSICAL_HISTORY_OWNER.with(|current| {
                    *current.borrow_mut() = self.0.take();
                });
            }
        }
        let _restore = Restore(
            PHYSICAL_HISTORY_OWNER.with(|current| current.borrow_mut().replace(self.clone())),
        );
        work()
    }

    /// Exact native backing pool used by cold canonical frame and shared shell allocation.
    pub(crate) fn cold_frames(&self) -> &AllocationBudget {
        &self.budget.cold_frames
    }

    /// Share the same physical and cumulative owners with Core's canonical cold reader.
    pub(crate) fn canonical_history_budget(&self) -> iroha_core::state::CanonicalHistoryReadBudget {
        iroha_core::state::CanonicalHistoryReadBudget::new(
            self.budget.cold_frames.clone(),
            self.budget.allocations.clone(),
        )
    }

    /// Prepay finality's complete source/output and graph corridors from this
    /// request's original cumulative grant. Generic decoded graphs must not spend
    /// the cold-frame portion while exact finality destinations retain it.
    pub(crate) fn finality_budget(
        &self,
    ) -> Result<iroha_core::sumeragi::finality::NativeFinalityProofBudget, Error> {
        self.budget
            .allocations
            .with(|| {
                norito::core::reserve_decode_allocation(
                    self.budget.allocation_limits.max_total_allocated_bytes(),
                )
            })
            .map_err(|_| capacity())?;
        Ok(
            iroha_core::sumeragi::finality::NativeFinalityProofBudget::new(
                self.budget.cold_frames.clone(),
                self.budget.finality_graphs.clone(),
                self.budget.allocation_limits,
            ),
        )
    }

    pub(crate) fn response_metadata(&self) -> &AllocationBudget {
        &self.budget.response_metadata
    }

    /// Borrow the original cumulative codec owner for synchronous authorization reads.
    pub(crate) fn allocation_context(&self) -> &DecodeBudgetContext {
        &self.budget.allocations
    }

    /// Reuse matching physical admission or acquire one actual transient authorization owner.
    /// A present invalid or foreign-generation token is a refusal, never a standalone grant.
    pub(crate) fn authentication_read(app: &crate::SharedAppState) -> Result<Self, Error> {
        if let Some(owner) = Self::current_if_admitted()? {
            // A routed read's owner is sized for that read, at most the configured one.
            if owner.budget.pool_generation != app.query_fanout_inflight.generation()
                || owner.budget.envelope.working_set_bytes > app.query_fanout_working_set_bytes
            {
                return Err(capacity());
            }
            return Ok(owner);
        }
        let reservation =
            crate::try_acquire_new_query_fanout_memory(app).map_err(|_| capacity())?;
        Self::from_reservation(&reservation)
    }

    /// Reuse the request's admitted owner (`borrowed == true`), or wait in the query
    /// admission queue for the smallest owner whose phase covers `unit_bytes`, the
    /// request's largest representation; an unknown size takes the configured owner.
    pub(crate) async fn authentication_read_waiting(
        app: &crate::SharedAppState,
        unit_bytes: Option<usize>,
    ) -> Result<(Self, bool), axum::response::Response> {
        use axum::response::IntoResponse as _;
        if let Some(owner) = Self::current_if_admitted().map_err(Error::into_response)? {
            if owner.budget.pool_generation != app.query_fanout_inflight.generation()
                || owner.budget.envelope.working_set_bytes > app.query_fanout_working_set_bytes
            {
                return Err(capacity().into_response());
            }
            return Ok((owner, true));
        }
        let working_set = crate::authentication_owner_working_set(app, unit_bytes);
        let reservation = crate::acquire_app_routed_read_http_memory(app, working_set).await?;
        Ok((
            Self::from_reservation(&reservation).map_err(Error::into_response)?,
            false,
        ))
    }

    /// The complete working set this owner was admitted with.
    pub(crate) fn working_set_bytes(&self) -> usize {
        self.budget.envelope.working_set_bytes
    }

    /// Record that a limit derived from this owner refused its request.
    pub(crate) fn note_owner_limit_refused(&self) {
        self.budget.note_owner_limit_refused();
    }

    /// Acquire one fresh fail-fast owner for a background worker's off-chain history read.
    /// A worker has no request: a present request owner is refused, never borrowed, and the
    /// worker's own owner is installed only inside its synchronous scopes. Each read takes a
    /// separate reservation from the same query-fanout pool as HTTP readers, never State
    /// execution memory; a busy pool refuses with `CapacityLimit` and the caller retries.
    pub(crate) fn background_read(app: &crate::SharedAppState) -> Result<Self, Error> {
        if Self::current_if_admitted()?.is_some() {
            return Err(capacity());
        }
        let reservation =
            crate::try_acquire_new_query_fanout_memory(app).map_err(|_| capacity())?;
        Self::from_reservation(&reservation)
    }

    /// Compact row and cursor backing may not borrow the decoded-graph corridor.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.budget.envelope.accumulator_retained_bytes
    }

    /// The final body remains inside the existing response corridor.
    pub(crate) fn response_bytes(&self) -> usize {
        self.budget.envelope.final_body_bytes
    }

    /// Refuse a read that outgrew this owner's own limits, and record that the owner refused it.
    fn owner_capacity(&self) -> Error {
        self.budget.note_owner_limit_refused();
        capacity()
    }

    /// Admit exact native collection backing before allocation, without geometric overgrowth.
    pub(crate) fn selected<T>(&self, count: usize) -> Result<Vec<T>, Error> {
        let bytes = std::alloc::Layout::array::<T>(count)
            .map_err(|_| self.owner_capacity())?
            .size();
        if bytes > self.retained_bytes() {
            return Err(self.owner_capacity());
        }
        self.scope(|| norito::core::reserve_decode_allocation(bytes))
            .map_err(|_| self.owner_capacity())?;
        crate::torii_routed_read_exact_vec(count, "history selected records", bytes)
            .map_err(|_| self.owner_capacity())
    }

    /// Encode a borrowed projection under the unchanged cumulative owner.
    pub(crate) fn json<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        payload: &T,
    ) -> Result<axum::response::Response, Error> {
        self.json_with_limit(payload, self.response_bytes())
    }

    /// Keep a stricter selected-source phase without replacing the actual query owner.
    pub(crate) fn json_with_limit<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        payload: &T,
        limit: usize,
    ) -> Result<axum::response::Response, Error> {
        let encoded = self
            .scope(|| {
                norito::json::to_json_bounded_boxed(payload, limit.min(self.response_bytes()))
            })
            .map_err(|_| self.owner_capacity())?;
        let bytes = crate::response_memory_custody::owned(encoded, self)
            .map_err(|_| self.owner_capacity())?;
        crate::response_memory_custody::json(bytes, self).map_err(|_| self.owner_capacity())
    }

    /// Stream one single-line canonical JSON event into exact native response backing.
    /// The returned data owns this same complete query reservation through its last slice.
    pub(crate) fn sse_data<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        payload: &T,
    ) -> Result<axum::body::Bytes, Error> {
        struct Event<'a, T: ?Sized>(&'a T);
        impl<T: norito::json::JsonSerialize + ?Sized> norito::json::FastJsonWrite for Event<'_, T> {
            fn write_json(&self, out: &mut String) {
                norito::json::write_json_unbounded(self, out);
            }
            fn write_json_to(
                &self,
                out: &mut dyn norito::json::JsonWriteSink,
            ) -> Result<(), norito::json::BoundedJsonError> {
                out.push_str("data: ")?;
                self.0.json_serialize_to(out)?;
                out.push_str("\n\n")
            }
        }
        let encoded = self
            .scope(|| norito::json::to_json_bounded_boxed(&Event(payload), self.response_bytes()))
            .map_err(|_| self.owner_capacity())?;
        crate::response_memory_custody::owned(encoded, self).map_err(|_| self.owner_capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(bytes: usize) -> HistoryProducerOwner {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let envelope = QueryFanoutMemoryEnvelope::for_body_admission(bytes).unwrap();
        let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
            semaphore.try_acquire_owned().unwrap(),
            envelope,
            7,
        )
        .unwrap();
        HistoryProducerOwner::from_reservation(&reservation).unwrap()
    }

    #[test]
    fn native_history_counters_are_cumulative_across_physical_scopes() {
        let owner = owner(48 * 1024 * 1024);
        let amount = owner.response_bytes();
        owner
            .scope(|| norito::core::reserve_decode_allocation(amount))
            .unwrap();
        let first = owner.budget.allocations.consumed_allocated_bytes();
        owner
            .clone()
            .scope(|| norito::core::reserve_decode_allocation(amount))
            .unwrap();
        assert_eq!(
            owner.budget.allocations.consumed_allocated_bytes(),
            first + amount as u64
        );
        let mut refused = false;
        for _ in 0..16 {
            if owner
                .scope(|| norito::core::reserve_decode_allocation(amount))
                .is_err()
            {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "separate cold reads must not reset allocation credit"
        );
        assert!(
            HistoryProducerOwner::current().is_err(),
            "physical scope must be restored"
        );
    }

    #[test]
    fn finality_physical_scope_preserves_inherited_limits_and_restores_after_unwind() {
        let owner = owner(48_000_000);
        let inherited = DecodeBudgetContext::new(DecodeLimits::new(1024, 1024, 1024, 64, 16));
        inherited.with(|| {
            owner.physical_scope(|| {
                assert!(
                    HistoryProducerOwner::current()
                        .unwrap()
                        .cold_frames()
                        .same_pool(owner.cold_frames())
                );
                norito::core::reserve_decode_allocation(64).unwrap();
                assert!(norito::core::reserve_decode_allocation(1).is_err());
            });
        });
        assert_eq!(inherited.consumed_allocated_bytes(), 64);
        assert_eq!(owner.allocation_context().consumed_allocated_bytes(), 0);
        assert!(HistoryProducerOwner::current().is_err());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.physical_scope(|| panic!("physical finality worker interrupted"));
        }));
        assert!(HistoryProducerOwner::current().is_err());
        assert!(!norito::core::decode_limits_active());
    }

    #[test]
    fn finality_graph_prepayment_cannot_duplicate_the_original_history_grant() {
        let owner = owner(48_000_000);
        let graph_bytes = owner.budget.finality_graphs.limit_bytes();
        let frames = owner.cold_frames().limit_bytes();
        assert_eq!(
            graph_bytes + frames,
            owner.budget.allocation_limits.max_total_allocated_bytes()
        );
        let finality = owner.finality_budget().unwrap();
        assert_eq!(
            owner.allocation_context().consumed_allocated_bytes(),
            (graph_bytes + frames) as u64
        );
        assert!(owner.clone().finality_budget().is_err());
        assert!(
            owner
                .scope(|| norito::core::reserve_decode_allocation(1))
                .is_err()
        );
        drop(finality);
        assert!(
            owner.finality_budget().is_err(),
            "drop cannot reset the original prepaid grant"
        );
        let used = self::owner(48_000_000);
        used.scope(|| norito::core::reserve_decode_allocation(1))
            .unwrap();
        assert!(
            used.finality_budget().is_err(),
            "finality cannot overwrite prior generic consumption"
        );
    }

    #[test]
    fn bodyless_finality_releases_only_absent_request_phases_inside_the_same_working_set() {
        let working = 48_000_000;
        let prebody = QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap();
        let bodyless = QueryFanoutMemoryEnvelope::for_bodyless_finality(working).unwrap();
        assert!(bodyless.phases_fit());
        assert_eq!(bodyless.working_set_bytes, prebody.working_set_bytes);
        assert_eq!(bodyless.route_body_bytes, prebody.route_body_bytes);
        assert_eq!(bodyless.final_body_bytes, prebody.final_body_bytes);
        assert_eq!(
            bodyless.candidate_encoded_bytes,
            prebody.candidate_encoded_bytes
        );
        assert_eq!(bodyless.request_bytes, 0);
        assert_eq!(bodyless.request_decode_allocated_bytes, 0);
        let original = owner(working);
        let bodyless_budget = ProducerBudget::from_admitted(bodyless, 7).unwrap();
        let absent_request = prebody.request_decode_allocated_bytes
            * (1 + crate::QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS
                + crate::QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS);
        assert_eq!(
            bodyless_budget.finality_graphs.limit_bytes(),
            original.budget.finality_graphs.limit_bytes() + absent_request
        );
        assert_eq!(
            original.budget.envelope, prebody,
            "existing owners retain their original geometry"
        );
    }

    #[test]
    fn larger_initial_finality_working_set_reduces_slots_inside_the_same_aggregate_pool() {
        let aggregate = 512_000_000;
        let geometry = crate::query_memory_geometry(aggregate, 192_000_000, 64_000_000, 64)
            .expect("explicit initial query capacity");
        assert_eq!(geometry.fanout_working_set_bytes, 192_000_000);
        assert_eq!(geometry.fanout_pool_bytes, 384_000_000);
        assert_eq!(geometry.fanout_slots.get(), 2);
        assert_eq!(geometry.ingress_slots.get(), 4);
        assert_eq!(
            geometry.fanout_working_set_bytes * geometry.fanout_slots.get(),
            geometry.fanout_pool_bytes
        );
        let envelope =
            QueryFanoutMemoryEnvelope::for_bodyless_finality(geometry.fanout_working_set_bytes)
                .unwrap();
        let budget = ProducerBudget::from_admitted(envelope, 7).unwrap();
        // Fifteen prebody units partition the working set after the 9,561,666-byte fixed
        // allowance. Bodyless finality keeps one unit each for response metadata and cold frames.
        assert_eq!(budget.cold_frames.limit_bytes(), 12_162_555);
        assert_eq!(budget.finality_graphs.limit_bytes(), 158_113_224);
        assert_eq!(
            budget.allocation_limits.max_total_allocated_bytes(),
            170_275_779
        );
        assert_eq!(budget.allocation_limits.max_field_bytes(), 12_162_555);
        assert_eq!(budget.allocation_limits.max_sequence_elements(), 12_162_555);
        // This is a new initial reservation. A smaller inherited request keeps
        // its exact original owner and cannot acquire these larger corridors.
        let smaller = owner(48_000_000);
        assert_eq!(smaller.budget.envelope.working_set_bytes, 48_000_000);
    }

    #[test]
    fn finality_rejects_missing_or_replaced_present_outer_admission() {
        let inherited = owner(48_000_000);
        let foreign = owner(48_000_000);
        let query = Arc::new(tokio::sync::Semaphore::new(1));
        let mut admission = QueryAdmissionPermit {
            _query: Arc::clone(&query).try_acquire_owned().unwrap(),
            _heavy: None,
            _body: None,
            _fanout_memory: None,
        };
        inherited.physical_scope(|| {
            assert!(HistoryProducerOwner::validate_finality_inheritance(&admission).is_err());
            admission._fanout_memory = Some(foreign._reservation.clone());
            assert!(HistoryProducerOwner::validate_finality_inheritance(&admission).is_err());
            admission._fanout_memory = Some(inherited._reservation.clone());
            HistoryProducerOwner::validate_finality_inheritance(&admission).unwrap();
            assert_eq!(
                admission
                    ._fanout_memory
                    .as_ref()
                    .unwrap()
                    .admission
                    .unwrap()
                    .envelope,
                inherited.budget.envelope
            );
        });
    }

    #[test]
    fn native_history_refuses_response_only_and_foreign_generation_tokens() {
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        assert!(
            HistoryProducerOwner::from_reservation(&QueryFanoutMemoryReservation::new(permit))
                .is_err()
        );
        let mut original = owner(48 * 1024 * 1024)._reservation;
        original.admission.as_mut().unwrap().pool_generation += 1;
        assert!(HistoryProducerOwner::from_reservation(&original).is_err());
    }

    #[test]
    fn native_history_scope_restores_after_panic_and_isolates_requests() {
        let first = owner(48 * 1024 * 1024);
        let second = owner(48 * 1024 * 1024);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            first.scope(|| {
                norito::core::reserve_decode_allocation(1024).unwrap();
                panic!("physical worker interrupted");
            })
        }));
        assert!(HistoryProducerOwner::current().is_err());
        assert_eq!(second.budget.allocations.consumed_allocated_bytes(), 0);
        assert_eq!(first.budget.allocations.consumed_allocated_bytes(), 1024);
    }

    #[test]
    fn native_history_unknown_prebody_request_retains_all_original_request_phases() {
        let owner = owner(48_000_000);
        let envelope = owner.budget.envelope;
        let retained_request = envelope.request_decode_allocated_bytes
            * (crate::QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS
                + crate::QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS);
        let grant = envelope.working_set_bytes
            - crate::query_fanout_fixed_overhead_bytes().unwrap()
            - retained_request
            - envelope.request_decode_allocated_bytes
            - envelope.candidate_encoded_bytes;
        owner
            .scope(|| norito::core::reserve_decode_allocation(grant))
            .unwrap();
        assert!(
            owner
                .scope(|| norito::core::reserve_decode_allocation(1))
                .is_err()
        );
        assert_eq!(
            owner.budget.allocations.consumed_allocated_bytes(),
            grant as u64
        );
        assert_eq!(
            retained_request
                + envelope.request_decode_allocated_bytes
                + envelope.candidate_encoded_bytes
                + grant
                + crate::query_fanout_fixed_overhead_bytes().unwrap(),
            envelope.working_set_bytes
        );
    }

    #[tokio::test]
    async fn detached_history_worker_installs_the_real_owner_and_retains_returned_sse_bytes() {
        let working = 48_000_000;
        let pool = crate::ByteWeightedMemoryPool::new(working).unwrap();
        let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([working as u64]).unwrap(),
            QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap(),
            pool.generation(),
        )
        .unwrap();
        let query = Arc::new(tokio::sync::Semaphore::new(1));
        let admission = QueryAdmissionPermit {
            _query: query.try_acquire_owned().unwrap(),
            _heavy: None,
            _body: None,
            _fanout_memory: Some(reservation),
        };
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let (finished, output) = tokio::sync::oneshot::channel();
        let request = tokio::spawn(crate::routing::run_admitted_blocking(
            admission,
            "owned history test worker failed",
            move || {
                let owner = HistoryProducerOwner::current()?;
                started.send(()).unwrap();
                held.recv().unwrap();
                let bytes = owner.sse_data(&17_u64)?;
                finished.send(bytes).unwrap();
                Ok(())
            },
        ));
        entered.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(pool.try_acquire_parts([working as u64]).is_none());
        release.send(()).unwrap();
        let bytes = output.await.unwrap();
        assert_eq!(bytes.as_ref(), b"data: 17\n\n");
        let clone = bytes.clone();
        drop(bytes);
        assert!(pool.try_acquire_parts([working as u64]).is_none());
        drop(clone);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if pool.try_acquire_parts([working as u64]).is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("physical worker must release the original complete owner");
        assert!(HistoryProducerOwner::current().is_err());
    }
}
