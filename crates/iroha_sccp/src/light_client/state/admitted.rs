//! Original-pool delta custody and allocation-free ordered light-client overlays.
//!
//! This owner covers its exact row arrays and encoded set bytes. Native verifier input and
//! scratch are separate owners: constructing a delta owner does not fund those allocations.

use std::{alloc::Layout, fmt, io::Cursor};

use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferError};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::light_client::{SccpLcCheckpointV1, SccpLcHeadV1, SccpLightClientV1},
};

use super::{
    SccpLcConsensusSetRefV1, SccpLcDeltaV1, SccpLcStateView, SccpLcSupersessionV1,
    same_checkpoint_block, state_hash,
};

/// Finite output capacities derived by the caller from the admitted verifier work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SccpLcDeltaCapacityV1 {
    /// Maximum learned consensus records in this call.
    pub new_sets: usize,
    /// Maximum superseded records in this call.
    pub superseded_sets: usize,
    /// Maximum new finalized checkpoints in this call.
    pub checkpoints: usize,
    /// Maximum bytes of one canonical encoded validator record.
    pub set_bytes: usize,
}

/// A local physical refusal or an output exceeding its original admission plan.
#[derive(Debug)]
pub enum SccpLcDeltaAdmissionErrorV1 {
    /// Original finite pool refused an exact native layout.
    Admission(AllocationRefusal),
    /// An admitted buffer could not be constructed.
    Buffer(ChargedBufferError),
    /// The output exceeds the source-derived finite plan.
    Capacity(&'static str),
    /// A second row conflicts with a row already produced by this same call.
    Conflict(&'static str),
    /// Canonical serialization failed; its partial destination is discarded.
    Codec(norito::Error),
}
impl fmt::Display for SccpLcDeltaAdmissionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::Buffer(error) => error.fmt(f),
            Self::Capacity(kind) => write!(f, "light-client delta exceeds admitted {kind}"),
            Self::Conflict(kind) => write!(f, "light-client delta conflicts at {kind}"),
            Self::Codec(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SccpLcDeltaAdmissionErrorV1 {}
impl From<AllocationRefusal> for SccpLcDeltaAdmissionErrorV1 {
    fn from(error: AllocationRefusal) -> Self {
        Self::Admission(error)
    }
}
impl From<ChargedBufferError> for SccpLcDeltaAdmissionErrorV1 {
    fn from(error: ChargedBufferError) -> Self {
        Self::Buffer(error)
    }
}

struct Set {
    id: u64,
    first_height: u64,
    superseded_ms: Option<u64>,
    bytes: ChargedBuffer<u8>,
}
impl Set {
    fn as_ref(&self) -> SccpLcConsensusSetRefV1<'_> {
        SccpLcConsensusSetRefV1 {
            set_id: self.id,
            valid_from_source_height: self.first_height,
            superseded_at_source_ms: self.superseded_ms,
            set_bytes: self.bytes.as_slice(),
        }
    }
}

/// An immutable verifier delta whose actual allocations retain original pool custody.
///
/// It exposes borrowed records only. Moving it preserves the same allocations; there is no
/// clone or extraction operation that could separate encoded bytes from their charges.
pub struct SccpLcAdmittedDeltaV1 {
    sets: ChargedBuffer<Set>,
    superseded: ChargedBuffer<SccpLcSupersessionV1>,
    checkpoints: ChargedBuffer<SccpLcCheckpointV1>,
    head: Option<SccpLcHeadV1>,
}
impl fmt::Debug for SccpLcAdmittedDeltaV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SccpLcAdmittedDeltaV1")
            .field("new_sets", &self.sets.as_slice().len())
            .field("superseded_sets", &self.superseded.as_slice().len())
            .field("checkpoints", &self.checkpoints.as_slice().len())
            .field("head", &self.head)
            .finish()
    }
}

/// Mutable construction phase, with all row backing admitted before construction.
#[derive(Debug)]
pub struct SccpLcDeltaBuilderV1 {
    delta: SccpLcAdmittedDeltaV1,
    budget: AllocationBudget,
    max_set_bytes: usize,
}
impl SccpLcDeltaBuilderV1 {
    pub(super) const fn delta(&self) -> &SccpLcAdmittedDeltaV1 {
        &self.delta
    }

    /// Admit all fixed row arrays from the actual original pool before allocating them.
    /// Encoded validator bytes are separately admitted at their exact frame length before
    /// the encoder constructs even one output byte.
    ///
    /// # Errors
    /// Refuses impossible layouts, original capacity exhaustion or allocator failure.
    pub fn new(
        capacity: SccpLcDeltaCapacityV1,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcDeltaAdmissionErrorV1> {
        let layouts = [
            Layout::array::<Set>(capacity.new_sets),
            Layout::array::<SccpLcSupersessionV1>(capacity.superseded_sets),
            Layout::array::<SccpLcCheckpointV1>(capacity.checkpoints),
        ];
        let mut exact = [Layout::new::<()>(); 3];
        for (to, from) in exact.iter_mut().zip(layouts) {
            *to = from.map_err(|_| AllocationRefusal::DemandOverflow)?;
        }
        let mut prepaid = budget.try_reserve_layouts(exact)?;
        let buffer_error = |error| match error {
            iroha_allocation::PrepaidBufferError::Allocation(error) => {
                SccpLcDeltaAdmissionErrorV1::Buffer(error)
            }
            _ => SccpLcDeltaAdmissionErrorV1::Capacity("original row reservation"),
        };
        let sets = ChargedBuffer::from_reservation(capacity.new_sets, &mut prepaid)
            .map_err(buffer_error)?;
        let superseded = ChargedBuffer::from_reservation(capacity.superseded_sets, &mut prepaid)
            .map_err(buffer_error)?;
        let checkpoints = ChargedBuffer::from_reservation(capacity.checkpoints, &mut prepaid)
            .map_err(buffer_error)?;
        Ok(Self {
            delta: SccpLcAdmittedDeltaV1 {
                sets,
                superseded,
                checkpoints,
                head: None,
            },
            budget: budget.clone(),
            max_set_bytes: capacity.set_bytes,
        })
    }

    /// Borrow an already constructed set without copying its encoded validator graph.
    #[must_use]
    pub fn consensus_set(&self, id: u64) -> Option<SccpLcConsensusSetRefV1<'_>> {
        self.delta
            .sets
            .as_slice()
            .iter()
            .find(|set| set.id == id)
            .map(Set::as_ref)
    }

    /// Write a canonical set frame directly into its exact original-pool allocation.
    /// The input graph is borrowed and remains the caller's physical-custody responsibility.
    ///
    /// # Errors
    /// Refuses a repeated id, exhausted row capacity, oversize frame, or original allocation
    /// failure before constructing output; an encoding failure drops the partial buffer.
    pub fn encode_set<T: norito::NoritoSerialize>(
        &mut self,
        id: u64,
        first_height: u64,
        superseded_ms: Option<u64>,
        value: &T,
    ) -> Result<(), SccpLcDeltaAdmissionErrorV1> {
        if self.consensus_set(id).is_some() {
            return Err(SccpLcDeltaAdmissionErrorV1::Conflict("set id"));
        }
        if self.delta.sets.as_slice().len() == self.delta.sets.capacity() {
            return Err(SccpLcDeltaAdmissionErrorV1::Capacity("set rows"));
        }
        let bytes =
            norito::canonical_frame_len(value).map_err(SccpLcDeltaAdmissionErrorV1::Codec)?;
        if bytes > self.max_set_bytes {
            return Err(SccpLcDeltaAdmissionErrorV1::Capacity("set bytes"));
        }
        let mut encoded = ChargedBuffer::new(bytes, &self.budget)?;
        for _ in 0..bytes {
            encoded.push_reserved(0);
        }
        let mut cursor = Cursor::new(encoded.as_mut_slice());
        norito::core::write_canonical_to_writer(value, &mut cursor)
            .map_err(SccpLcDeltaAdmissionErrorV1::Codec)?;
        if cursor.position() != bytes as u64 {
            return Err(SccpLcDeltaAdmissionErrorV1::Capacity("set encoding length"));
        }
        self.delta
            .sets
            .try_push(Set {
                id,
                first_height,
                superseded_ms,
                bytes: encoded,
            })
            .map_err(|_| SccpLcDeltaAdmissionErrorV1::Capacity("set rows changed"))?;
        self.delta
            .sets
            .as_mut_slice()
            .sort_unstable_by_key(|set| set.id);
        Ok(())
    }

    /// Record a supersession in an existing new record or in its admitted scalar row array.
    ///
    /// # Errors
    /// Refuses a contradictory supersession or exhausted row capacity without mutation.
    pub fn supersede(&mut self, id: u64, at: u64) -> Result<(), SccpLcDeltaAdmissionErrorV1> {
        if let Some(set) = self
            .delta
            .sets
            .as_mut_slice()
            .iter_mut()
            .find(|set| set.id == id)
        {
            if set.superseded_ms.is_some_and(|old| old != at) {
                return Err(SccpLcDeltaAdmissionErrorV1::Conflict(
                    "new-set supersession",
                ));
            }
            set.superseded_ms = Some(at);
            return Ok(());
        }
        if let Some(old) = self
            .delta
            .superseded
            .as_slice()
            .iter()
            .find(|set| set.set_id == id)
        {
            return if old.superseded_at_source_ms == at {
                Ok(())
            } else {
                Err(SccpLcDeltaAdmissionErrorV1::Conflict("supersession"))
            };
        }
        self.delta
            .superseded
            .try_push(SccpLcSupersessionV1 {
                set_id: id,
                superseded_at_source_ms: at,
            })
            .map_err(|_| SccpLcDeltaAdmissionErrorV1::Capacity("supersession rows"))?;
        self.delta
            .superseded
            .as_mut_slice()
            .sort_unstable_by_key(|set| set.set_id);
        Ok(())
    }

    /// Record one finalized checkpoint idempotently in its admitted scalar row array.
    ///
    /// # Errors
    /// Refuses a conflicting same-height block or exhausted capacity without mutation.
    pub fn checkpoint(
        &mut self,
        checkpoint: SccpLcCheckpointV1,
    ) -> Result<(), SccpLcDeltaAdmissionErrorV1> {
        if let Some(old) = self
            .delta
            .checkpoints
            .as_slice()
            .iter()
            .find(|old| old.data.source_height == checkpoint.data.source_height)
        {
            return if same_checkpoint_block(&old.data, &checkpoint.data) {
                Ok(())
            } else {
                Err(SccpLcDeltaAdmissionErrorV1::Conflict("checkpoint"))
            };
        }
        self.delta
            .checkpoints
            .try_push(checkpoint)
            .map_err(|_| SccpLcDeltaAdmissionErrorV1::Capacity("checkpoint rows"))?;
        self.delta
            .checkpoints
            .as_mut_slice()
            .sort_unstable_by_key(|row| row.data.source_height);
        Ok(())
    }

    /// Seal this exact set of original allocations with the verifier's final optional head.
    #[must_use]
    pub fn finish(mut self, head: Option<SccpLcHeadV1>) -> SccpLcAdmittedDeltaV1 {
        self.delta.head = head;
        self.delta
    }
}

/// Shared read interface for a detached tool delta and an admitted native delta.
/// The verifier/state overlay only borrows either representation.
pub trait SccpLcDeltaReadV1 {
    /// Number of learned records.
    fn set_count(&self) -> usize;
    /// Borrow the indexed learned record.
    fn set(&self, index: usize) -> Option<SccpLcConsensusSetRefV1<'_>>;
    /// Scalar supersessions.
    fn superseded(&self) -> &[SccpLcSupersessionV1];
    /// Scalar finalized checkpoints.
    fn checkpoints(&self) -> &[SccpLcCheckpointV1];
    /// Optional new light-client head.
    fn head(&self) -> Option<SccpLcHeadV1>;
}
impl SccpLcDeltaReadV1 for SccpLcAdmittedDeltaV1 {
    fn set_count(&self) -> usize {
        self.sets.as_slice().len()
    }
    fn set(&self, index: usize) -> Option<SccpLcConsensusSetRefV1<'_>> {
        self.sets.as_slice().get(index).map(Set::as_ref)
    }
    fn superseded(&self) -> &[SccpLcSupersessionV1] {
        self.superseded.as_slice()
    }
    fn checkpoints(&self) -> &[SccpLcCheckpointV1] {
        self.checkpoints.as_slice()
    }
    fn head(&self) -> Option<SccpLcHeadV1> {
        self.head
    }
}
impl SccpLcDeltaReadV1 for SccpLcDeltaV1 {
    fn set_count(&self) -> usize {
        self.new_sets.len()
    }
    fn set(&self, index: usize) -> Option<SccpLcConsensusSetRefV1<'_>> {
        self.new_sets.get(index).map(Into::into)
    }
    fn superseded(&self) -> &[SccpLcSupersessionV1] {
        &self.superseded_sets
    }
    fn checkpoints(&self) -> &[SccpLcCheckpointV1] {
        &self.checkpoints
    }
    fn head(&self) -> Option<SccpLcHeadV1> {
        self.head
    }
}

/// Ordered immutable advances over one borrowed original source, without committed writes.
/// Later layers override only the network explicitly assigned to this overlay.
pub struct SccpLcOverlayV1<'a, V: SccpLcStateView + ?Sized, D: SccpLcDeltaReadV1> {
    original: &'a V,
    network: SccpNetworkV1,
    deltas: &'a [D],
}
impl<'a, V: SccpLcStateView + ?Sized, D: SccpLcDeltaReadV1> SccpLcOverlayV1<'a, V, D> {
    /// Borrow the same original source and already verified delta owners in signed order.
    #[must_use]
    pub const fn new(original: &'a V, network: SccpNetworkV1, deltas: &'a [D]) -> Self {
        Self {
            original,
            network,
            deltas,
        }
    }
}
impl<V: SccpLcStateView + ?Sized, D: SccpLcDeltaReadV1> SccpLcStateView
    for SccpLcOverlayV1<'_, V, D>
{
    fn light_client(&self, network: SccpNetworkV1) -> Option<SccpLightClientV1> {
        let mut current = self.original.light_client(network)?;
        if network == self.network {
            for delta in self.deltas {
                if let Some(head) = delta.head() {
                    current.head = head;
                    current.state_hash =
                        state_hash(&current.params, &head, current.frozen.as_ref());
                }
            }
        }
        Some(current)
    }
    fn consensus_set(
        &self,
        network: SccpNetworkV1,
        id: u64,
    ) -> Option<SccpLcConsensusSetRefV1<'_>> {
        if network != self.network {
            return self.original.consensus_set(network, id);
        }
        let mut result = self.original.consensus_set(network, id);
        for delta in self.deltas {
            for index in 0..delta.set_count() {
                if let Some(set) = delta.set(index).filter(|set| set.set_id == id) {
                    result = Some(set);
                }
            }
            if let Some(set) = result.as_mut() {
                for supersession in delta.superseded().iter().filter(|set| set.set_id == id) {
                    set.superseded_at_source_ms = Some(supersession.superseded_at_source_ms);
                }
            }
        }
        result
    }
    fn checkpoint(&self, network: SccpNetworkV1, height: u64) -> Option<SccpLcCheckpointV1> {
        if network == self.network {
            for delta in self.deltas.iter().rev() {
                if let Some(checkpoint) = delta
                    .checkpoints()
                    .iter()
                    .find(|record| record.data.source_height == height)
                {
                    return Some(*checkpoint);
                }
            }
        }
        self.original.checkpoint(network, height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sccp::light_client::{
        SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcConsensusSetV1, SccpLcPointV1,
        SccpLightClientParamsV1,
    };

    const NETWORK: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
    fn capacity() -> SccpLcDeltaCapacityV1 {
        SccpLcDeltaCapacityV1 {
            new_sets: 1,
            superseded_sets: 1,
            checkpoints: 1,
            set_bytes: 4096,
        }
    }
    fn checkpoint(height: u64) -> SccpLcCheckpointV1 {
        SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: height,
                block_hash: [7; 32],
                state_root: None,
                receipts_or_tx_root: [8; 32],
                source_time_ms: height,
            },
            recorded_at_taira_ms: 77,
            origin: SccpLcCheckpointOriginV1::Advance,
        }
    }
    fn head(height: u64) -> SccpLcHeadV1 {
        SccpLcHeadV1 {
            latest_set_id: height,
            latest_finalized: SccpLcPointV1 {
                source_height: height,
                block_hash: [9; 32],
                source_time_ms: height,
            },
            last_progress_taira_ms: 77,
        }
    }

    #[test]
    fn delta_admission_precedes_rows_and_encoded_graph_and_retry_uses_original_pool() {
        let empty = AllocationBudget::new(0);
        assert!(SccpLcDeltaBuilderV1::new(capacity(), &empty).is_err());
        assert_eq!(empty.reserved_bytes(), 0);
        let measure = AllocationBudget::new(65536);
        let planned = SccpLcDeltaBuilderV1::new(capacity(), &measure).expect("row backing");
        let rows = measure.reserved_bytes();
        drop(planned);
        assert_eq!(measure.reserved_bytes(), 0);
        let value = [42_u64, 43];
        let frame = norito::encode_canonical(&value).expect("fixture frame");
        let original = AllocationBudget::new(rows + frame.len());
        let mut builder = SccpLcDeltaBuilderV1::new(capacity(), &original).expect("exact rows");
        let held = original.try_reserve_bytes(1).expect("one competing byte");
        assert!(builder.encode_set(7, 70, None, &value).is_err());
        assert!(builder.consensus_set(7).is_none());
        assert_eq!(original.reserved_bytes(), rows + 1);
        // A same-sized foreign pool cannot release the exact original refusal.
        let unrelated = AllocationBudget::new(rows + frame.len());
        drop(
            unrelated
                .try_reserve_bytes(frame.len())
                .expect("foreign reservation"),
        );
        assert!(builder.encode_set(7, 70, None, &value).is_err());
        drop(held);
        builder
            .encode_set(7, 70, None, &value)
            .expect("physical release permits retry");
        assert_eq!(builder.consensus_set(7).expect("set").set_bytes, frame);
        assert_eq!(original.reserved_bytes(), rows + frame.len());
        let delta = builder.finish(Some(head(7)));
        assert_eq!(delta.set_count(), 1);
        assert_eq!(delta.head(), Some(head(7)));
        assert_eq!(delta.set(0).expect("borrow").valid_from_source_height, 70);
        drop(delta);
        assert_eq!(
            original.reserved_bytes(),
            0,
            "original rows and nested bytes are freed before refund"
        );
    }

    #[test]
    fn delta_row_bounds_and_conflicts_leave_existing_records_unchanged() {
        let pool = AllocationBudget::new(65536);
        let mut builder = SccpLcDeltaBuilderV1::new(capacity(), &pool).expect("rows");
        let before = pool.reserved_bytes();
        builder.max_set_bytes = 1;
        assert!(matches!(
            builder.encode_set(1, 1, None, &1_u64),
            Err(SccpLcDeltaAdmissionErrorV1::Capacity("set bytes"))
        ));
        assert_eq!(pool.reserved_bytes(), before);
        builder.max_set_bytes = 4096;
        builder.encode_set(1, 1, None, &1_u64).expect("set");
        assert!(builder.encode_set(1, 1, None, &1_u64).is_err());
        assert!(builder.encode_set(2, 2, None, &2_u64).is_err());
        builder.supersede(1, 10).expect("new record metadata");
        builder.supersede(1, 10).expect("idempotent metadata");
        assert!(builder.supersede(1, 11).is_err());
        builder.supersede(0, 5).expect("stored predecessor");
        builder.supersede(0, 5).expect("idempotent predecessor");
        assert!(builder.supersede(0, 6).is_err());
        assert!(builder.supersede(9, 6).is_err());
        builder.checkpoint(checkpoint(1)).expect("checkpoint");
        builder
            .checkpoint(checkpoint(1))
            .expect("idempotent checkpoint");
        let mut conflicting = checkpoint(1);
        conflicting.data.block_hash = [0; 32];
        assert!(builder.checkpoint(conflicting).is_err());
        assert!(builder.checkpoint(checkpoint(2)).is_err());
        let delta = builder.finish(None);
        assert_eq!(delta.set(0).expect("set").superseded_at_source_ms, Some(10));
        assert_eq!(
            delta.superseded(),
            &[SccpLcSupersessionV1 {
                set_id: 0,
                superseded_at_source_ms: 5
            }]
        );
        assert_eq!(delta.checkpoints(), &[checkpoint(1)]);
        drop(delta);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    struct Source {
        record: SccpLcConsensusSetV1,
        client: SccpLightClientV1,
    }
    impl SccpLcStateView for Source {
        fn light_client(&self, network: SccpNetworkV1) -> Option<SccpLightClientV1> {
            (network == NETWORK).then_some(self.client)
        }
        fn consensus_set(
            &self,
            network: SccpNetworkV1,
            id: u64,
        ) -> Option<SccpLcConsensusSetRefV1<'_>> {
            (network == NETWORK && id == self.record.set_id).then(|| (&self.record).into())
        }
        fn checkpoint(&self, network: SccpNetworkV1, height: u64) -> Option<SccpLcCheckpointV1> {
            (network == NETWORK && height == 1).then(|| checkpoint(1))
        }
    }

    #[test]
    fn ordered_overlay_borrows_original_and_admitted_graphs_without_mutating_either() {
        let params = SccpLightClientParamsV1::defaults_for(NETWORK).expect("external");
        let source = Source {
            record: SccpLcConsensusSetV1 {
                set_id: 1,
                valid_from_source_height: 1,
                superseded_at_source_ms: None,
                set_bytes: vec![11; 64],
            },
            client: SccpLightClientV1 {
                params,
                head: head(1),
                frozen: None,
                state_hash: state_hash(&params, &head(1), None),
            },
        };
        let pool = AllocationBudget::new(65536);
        let mut first = SccpLcDeltaBuilderV1::new(capacity(), &pool).expect("first");
        first.encode_set(2, 2, None, &2_u64).expect("new set");
        first.supersede(1, 20).expect("first successor");
        first.checkpoint(checkpoint(2)).expect("first checkpoint");
        let mut second = SccpLcDeltaBuilderV1::new(capacity(), &pool).expect("second");
        second.encode_set(3, 3, None, &3_u64).expect("next set");
        second.supersede(2, 30).expect("second successor");
        second.checkpoint(checkpoint(3)).expect("second checkpoint");
        let deltas = [first.finish(Some(head(2))), second.finish(Some(head(3)))];
        let original_used = pool.reserved_bytes();
        let overlay = SccpLcOverlayV1::new(&source, NETWORK, &deltas);
        assert_eq!(overlay.light_client(NETWORK).expect("client").head, head(3));
        assert_eq!(
            overlay.light_client(NETWORK).expect("client").state_hash,
            state_hash(&params, &head(3), None)
        );
        let parent = overlay.consensus_set(NETWORK, 1).expect("parent record");
        assert_eq!(parent.set_bytes.as_ptr(), source.record.set_bytes.as_ptr());
        assert_eq!(parent.superseded_at_source_ms, Some(20));
        let intermediate = overlay
            .consensus_set(NETWORK, 2)
            .expect("first delta record");
        assert_eq!(
            intermediate.set_bytes.as_ptr(),
            deltas[0].set(0).expect("first").set_bytes.as_ptr()
        );
        assert_eq!(intermediate.superseded_at_source_ms, Some(30));
        assert!(deltas[0].set(0).expect("first").is_current());
        assert!(
            overlay
                .consensus_set(NETWORK, 3)
                .expect("newest")
                .is_current()
        );
        for height in 1..=3 {
            assert_eq!(
                overlay.checkpoint(NETWORK, height),
                Some(checkpoint(height))
            );
        }
        assert!(overlay.light_client(SccpNetworkV1::TonMainnet).is_none());
        assert!(
            overlay
                .consensus_set(SccpNetworkV1::TonMainnet, 2)
                .is_none()
        );
        assert!(overlay.checkpoint(SccpNetworkV1::TonMainnet, 2).is_none());
        assert_eq!(source.client.head, head(1));
        assert!(source.record.superseded_at_source_ms.is_none());
        assert_eq!(
            pool.reserved_bytes(),
            original_used,
            "overlay construction/read allocates no graph"
        );
        drop(deltas);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn partially_constructed_delta_unwind_frees_rows_and_nested_bytes_in_original_pool() {
        let pool = AllocationBudget::new(65536);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut builder = SccpLcDeltaBuilderV1::new(capacity(), &pool).expect("rows");
            builder
                .encode_set(7, 70, None, &77_u64)
                .expect("nested bytes");
            assert!(pool.reserved_bytes() > 0);
            panic!("injected after exact delta allocation");
        }));
        assert!(result.is_err());
        assert_eq!(pool.reserved_bytes(), 0);
        let retry = SccpLcDeltaBuilderV1::new(capacity(), &pool).expect("retry original pool");
        drop(retry);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
