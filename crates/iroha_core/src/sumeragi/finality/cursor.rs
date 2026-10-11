//! Bounded in-memory native history progress for local portable discovery.
//!
//! Only real State-pinned signed genesis starts this cursor. Neither callers nor disk DTOs
//! can import a checkpoint. Partial progress is historical and never returned as current.

use std::{
    alloc::Layout,
    num::{NonZeroU16, NonZeroU64},
    time::Instant,
};

use super::ProofError;
use crate::{
    state::StateReadOnly,
    sumeragi::certified_chain::{
        CertifiedBlock, CertifiedPrefix, CommittedBlock, bounded_native_carrier,
        bounded_native_carrier_extent, read_frame,
    },
};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer};
use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, SharedSignedBlock, consensus::SumeragiRootScope},
    sumeragi_finality::{
        MAX_FINALITY_BLOCK_BYTES, MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint,
        SumeragiFinalityVerifier, VerifiedSumeragiBlock,
    },
};

/// Closed local failure of bounded native-to-portable observation.
#[derive(Debug, thiserror::Error)]
pub enum NativeFinalityCursorErrorV1 {
    /// The selected finite monotonic call budget expired.
    #[error("native finality observation deadline expired")]
    Deadline,
    /// Source identity, coherent cut or an explicit local extent differs.
    #[error("native finality observation source or bound differs")]
    Source,
    /// An original native or portable verifier refused its exact input.
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// Original finite pool or allocator refused an actual retained backing.
    #[error("native finality observation allocation unavailable")]
    Allocation,
}
type Error = NativeFinalityCursorErrorV1;
type Result<T> = std::result::Result<T, Error>;

/// An opaque, non-cloneable native prefix and canonical compact checkpoint.
///
/// It has no decoded-checkpoint constructor and never persists trust. Every returned block
/// comes from the sole portable verifier after full native certificate checks. Retained
/// physical buffers keep their original allocation charges across calls and refusals.
#[derive(Default)]
pub struct NativeFinalityCursorV1 {
    original: Option<Original>,
}

/// One historical portable verification result retaining its original allocation envelope.
/// It authenticates the selected height, without claiming that height is the current tip.
/// No constructor, clone or unaccounted move-out is exposed.
pub struct NativeFinalityAtHeightV1 {
    block: ChargedBuffer<VerifiedSumeragiBlock>,
    native: ChargedBuffer<CommittedBlock>,
    _decode: DecodeCustody,
}
impl NativeFinalityAtHeightV1 {
    /// Borrow the sole verifier output while its original allocation custody remains held.
    #[must_use]
    pub fn block(&self) -> &VerifiedSumeragiBlock {
        &self.block.as_slice()[0]
    }
    /// Borrow the same bounded durable receipt authenticated by this portable decision.
    /// This enables native snapshot joins without another frame read or imported trust.
    #[must_use]
    pub fn native_block(&self) -> &CommittedBlock {
        &self.native.as_slice()[0]
    }
}

/// One verified result additionally bound to the exact current State and durable cut.
/// No constructor, clone or unaccounted move-out is exposed.
pub struct NativeCurrentFinalityV1 {
    at: NativeFinalityAtHeightV1,
}
impl NativeCurrentFinalityV1 {
    /// Borrow the sole verifier output under its original allocation custody.
    #[must_use]
    pub fn block(&self) -> &VerifiedSumeragiBlock {
        self.at.block()
    }
    /// Borrow the same durable receipt authenticated by this current decision.
    #[must_use]
    pub fn native_block(&self) -> &CommittedBlock {
        self.at.native_block()
    }
}

struct Original {
    network: NetworkId,
    chain_id: String,
    prefix: ChargedBuffer<CertifiedPrefix>,
    native_height: u64,
    native_hash: HashOf<BlockHeader>,
    pending: Option<Pending>,
    checkpoint: Option<ChargedBuffer<u8>>,
    // Declared last: decoded prefix/pending/checkpoint owners reclaim before these charges.
    native_decode: NativeDecodeEnvelope,
}
enum Pending {
    Genesis(SharedSignedBlock),
    Successor(ChargedBuffer<CertifiedBlock>),
}

impl NativeFinalityCursorV1 {
    /// Create empty local progress; this acquires no source, memory backing or authority.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance at most 64 caller-selected native heights toward this exact current State cut.
    ///
    /// `None` means a genuine height-one source or incomplete bounded catch-up, never current
    /// authority. Later calls continue the same in-memory authenticated prefix. A failed
    /// portable step retains its native receipt and retries that exact step before acquisition.
    /// # Errors
    /// Refuses foreign/regressed history, changed native receipts, incoherent State/Kura,
    /// expired deadlines, invalid certificates and original memory/codec refusals.
    pub fn advance_current(
        &mut self,
        view: &impl StateReadOnly,
        budget: &AllocationBudget,
        deadline: Instant,
        maximum_steps: NonZeroU16,
    ) -> Result<Option<NativeCurrentFinalityV1>> {
        Ok(self
            .advance_at(view, budget, deadline, maximum_steps, None)?
            .map(|at| NativeCurrentFinalityV1 { at }))
    }

    /// Advance the same original prefix toward one historical committed height.
    ///
    /// At most 64 steps execute per call; `None` retains incomplete local progress.
    /// Targets must be non-genesis and within the current durable State cut. A
    /// caller cannot rewind an existing prefix, import trust or bypass a pending
    /// native step. The returned owner authenticates only this selected height.
    /// # Errors
    /// The same source, certificate, deadline and allocation failures as
    /// [`Self::advance_current`], plus a genesis, future or regressed target.
    pub fn advance_to_height(
        &mut self,
        view: &impl StateReadOnly,
        height: NonZeroU64,
        budget: &AllocationBudget,
        deadline: Instant,
        maximum_steps: NonZeroU16,
    ) -> Result<Option<NativeFinalityAtHeightV1>> {
        if height.get() < 2 {
            return Err(Error::Source);
        }
        self.advance_at(view, budget, deadline, maximum_steps, Some(height.get()))
    }

    fn advance_at(
        &mut self,
        view: &impl StateReadOnly,
        budget: &AllocationBudget,
        deadline: Instant,
        maximum_steps: NonZeroU16,
        requested: Option<u64>,
    ) -> Result<Option<NativeFinalityAtHeightV1>> {
        check(deadline)?;
        if maximum_steps.get() > 64 {
            return Err(Error::Source);
        }
        let current = coherent_height(view)?;
        let target = requested.unwrap_or(current);
        if target > current {
            return Err(Error::Source);
        }
        if target == 0 {
            return Ok(None);
        }
        if self.original.is_none() {
            check(deadline)?;
            let extent = bounded_native_carrier_extent(view, 1, MAX_FINALITY_BLOCK_BYTES)
                .map_err(ProofError::from)?;
            check(deadline)?;
            let mut native_decode = NativeDecodeEnvelope::new(budget)?;
            native_decode.ensure(extent, budget)?;
            let (genesis, prefix) = native_decode.run(extent, || {
                check(deadline)?;
                let genesis =
                    bounded_native_carrier(view, 1, extent, budget).map_err(ProofError::from)?;
                check(deadline)?;
                let prefix = CertifiedPrefix::new_admitted(
                    view.chain_id(),
                    *view.network_id(),
                    genesis.clone(),
                    budget,
                )
                .map_err(ProofError::from)?;
                Ok((genesis, prefix))
            })?;
            let metadata =
                iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
                    .map_err(|error| {
                        Error::Proof(ProofError::from(
                            iroha_data_model::sumeragi_finality::FinalityReadError::Genesis(error),
                        ))
                    })?;
            if metadata.sumeragi_context.root_scope != SumeragiRootScope::Global
                || view.chain_id().as_str().len() > 1024
            {
                return Err(Error::Source);
            }
            self.original = Some(Original {
                network: *view.network_id(),
                chain_id: view.chain_id().to_string(),
                prefix,
                native_height: 1,
                native_hash: genesis.hash(),
                pending: Some(Pending::Genesis(genesis)),
                checkpoint: None,
                native_decode,
            });
        }
        let original = self.original.as_mut().ok_or(Error::Source)?;
        if original.network != *view.network_id()
            || original.chain_id != view.chain_id().as_str()
            || !original.prefix.belongs_to(budget)
            || original.native_height > target
            || view.block_hashes().get(original.native_height as usize - 1)
                != Some(&original.native_hash)
        {
            return Err(Error::Source);
        }
        for _ in 0..maximum_steps.get() {
            check(deadline)?;
            if original.pending.is_none() {
                if original.native_height == target {
                    break;
                }
                let next = original.native_height.checked_add(1).ok_or(Error::Source)?;
                // Prepay the returned complete receipt before the native prefix advances.
                let mut retained = ChargedBuffer::new(1, budget).map_err(|_| Error::Allocation)?;
                check(deadline)?;
                let extent = bounded_native_carrier_extent(view, next, MAX_FINALITY_BLOCK_BYTES)
                    .map_err(ProofError::from)?;
                check(deadline)?;
                original.native_decode.ensure(extent, budget)?;
                let hash = original.native_decode.run(extent, || {
                    check(deadline)?;
                    let block = bounded_native_carrier(view, next, extent, budget)
                        .map_err(ProofError::from)?;
                    let hash = block.hash();
                    check(deadline)?;
                    original.prefix.as_mut_slice()[0]
                        .push_admitted_with_finish(block, budget, |step| {
                            let (current, _) = step.into_parts();
                            retained.push_reserved(current);
                        })
                        .map_err(ProofError::from)?;
                    Ok(hash)
                })?;
                original.native_height = next;
                original.native_hash = hash;
                original.pending = Some(Pending::Successor(retained));
            }
            // A failure below keeps the exact native receipt and preceding compact checkpoint.
            original.finish_pending(budget, deadline)?;
        }
        check(deadline)?;
        if original.pending.is_some() || original.native_height != target || target < 2 {
            return Ok(None);
        }
        let bytes = original.checkpoint.as_ref().ok_or(Error::Source)?;
        let custody = DecodeCustody::new(bytes.as_slice().len(), budget)?;
        let mut output = ChargedBuffer::new(1, budget).map_err(|_| Error::Allocation)?;
        let mut native = ChargedBuffer::new(1, budget).map_err(|_| Error::Allocation)?;
        custody.run(|| {
            let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(bytes.as_slice())
                .map_err(ProofError::from)?;
            // A retained proof is not a substitute for continued actual durable carrier custody.
            check(deadline)?;
            let durable = bounded_native_carrier(view, target, MAX_FINALITY_BLOCK_BYTES, budget)
                .map_err(ProofError::from)?;
            check(deadline)?;
            let identity = durable
                .canonical_wire_identity()
                .map_err(|_| Error::Source)?;
            if identity
                != (
                    checkpoint.tip().block_wire.len() as u64,
                    iroha_crypto::Hash::new(&checkpoint.tip().block_wire),
                )
            {
                return Err(Error::Source);
            }
            check(deadline)?;
            let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
                &checkpoint,
                &original.network,
                &original.chain_id,
            )
            .map_err(ProofError::from)?;
            check(deadline)?;
            let verified = verifier
                .verify_retained_decision(checkpoint.tip())
                .map_err(ProofError::from)?;
            check(deadline)?;
            let receipt = read_frame(durable, target).map_err(ProofError::from)?;
            if coherent_height(view)? != current
                || verified.height() != target
                || verified.block().hash() != original.native_hash
                || receipt.block_hash() != verified.block().hash()
                || receipt.core_hash() != verified.core_hash()
                || receipt.result() != verified.result()
                || receipt.id().0.as_ref() != verified.context_id().as_ref()
            {
                return Err(Error::Source);
            }
            native.push_reserved(receipt);
            output.push_reserved(verified);
            Ok(())
        })?;
        Ok(Some(NativeFinalityAtHeightV1 {
            block: output,
            native,
            _decode: custody,
        }))
    }
}

impl Original {
    fn finish_pending(&mut self, budget: &AllocationBudget, deadline: Instant) -> Result<()> {
        let pending = self.pending.as_ref().ok_or(Error::Source)?;
        let (block, members) = match pending {
            Pending::Genesis(block) => (
                block,
                &self.prefix.as_slice()[0].current_epoch_context().committee,
            ),
            Pending::Successor(retained) => {
                let receipt = &retained.as_slice()[0];
                (
                    receipt.block(),
                    &receipt.commitment().schedule.current.committee,
                )
            }
        };
        let owned = super::proof_destination::OwnedProof::new(block, members, budget, deadline)
            .map_err(|error| match error {
                super::ProofDestinationError::Deadline => Error::Deadline,
                super::ProofDestinationError::Source => Error::Source,
                super::ProofDestinationError::Admission(_)
                | super::ProofDestinationError::Buffer(_)
                | super::ProofDestinationError::Key(_) => Error::Allocation,
            })?;
        let checkpoint_bytes = self
            .checkpoint
            .as_ref()
            .map_or(0, |bytes| bytes.as_slice().len());
        let envelope_bytes = checkpoint_bytes
            .checked_add(owned.proof.block_wire.len())
            .ok_or(Error::Source)?;
        let custody = DecodeCustody::new(envelope_bytes, budget)?;
        let retained = custody.run(|| {
            check(deadline)?;
            let mut verifier = if let Some(bytes) = &self.checkpoint {
                let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(bytes.as_slice())
                    .map_err(ProofError::from)?;
                check(deadline)?;
                SumeragiFinalityVerifier::from_trusted_checkpoint(
                    &checkpoint,
                    &self.network,
                    &self.chain_id,
                )
                .map_err(ProofError::from)?
            } else {
                SumeragiFinalityVerifier::new(block, &self.chain_id, owned.proof.committee.clone())
                    .map_err(ProofError::from)?
            };
            check(deadline)?;
            verifier.verify(&owned.proof).map_err(ProofError::from)?;
            check(deadline)?;
            let checkpoint = verifier
                .export_checkpoint(&owned.proof)
                .map_err(ProofError::from)?;
            check(deadline)?;
            encode_checkpoint(&checkpoint, budget, deadline)
        })?;
        check(deadline)?;
        // Only the authenticated compact checkpoint becomes the next portable trust root.
        self.checkpoint = Some(retained);
        self.pending = None;
        Ok(())
    }
}

struct BufferWriter<'a>(&'a mut ChargedBuffer<u8>);
impl std::io::Write for BufferWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0.capacity().saturating_sub(self.0.as_slice().len()) {
            return Err(std::io::Error::other(
                "native checkpoint exceeds counted extent",
            ));
        }
        for byte in bytes {
            self.0.push_reserved(*byte);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode_checkpoint(
    value: &SumeragiFinalityCheckpoint,
    budget: &AllocationBudget,
    deadline: Instant,
) -> Result<ChargedBuffer<u8>> {
    check(deadline)?;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::canonical_frame_len(value).map_err(|_| Error::Source)?;
    if length > MAX_FINALITY_CHECKPOINT_BYTES {
        return Err(Error::Source);
    }
    check(deadline)?;
    let mut buffer = ChargedBuffer::new(length, budget).map_err(|_| Error::Allocation)?;
    norito::core::write_canonical_to_writer(value, &mut BufferWriter(&mut buffer))
        .map_err(|_| Error::Source)?;
    if buffer.as_slice().len() != length {
        return Err(Error::Source);
    }
    Ok(buffer)
}
fn coherent_height(view: &impl StateReadOnly) -> Result<u64> {
    let count = view.block_hashes().len();
    if view
        .kura()
        .exact_durable_blocks_count()
        .map_err(|_| Error::Source)?
        != count
    {
        return Err(Error::Source);
    }
    u64::try_from(count).map_err(|_| Error::Source)
}
fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}

// A real original-pool charge accompanies the canonical decoder allowance and bounded clone
// workspace. Values constructed in run are destroyed before this custody, except the single
// verified output which is physically coupled to it in NativeFinalityAtHeightV1 above.
struct DecodeCustody {
    limits: norito::DecodeLimits,
    _charge: AllocationCharge,
}
impl DecodeCustody {
    fn new(encoded: usize, budget: &AllocationBudget) -> Result<Self> {
        if encoded
            > MAX_FINALITY_CHECKPOINT_BYTES
                .checked_add(MAX_FINALITY_BLOCK_BYTES)
                .ok_or(Error::Source)?
        {
            return Err(Error::Source);
        }
        let derived = norito::canonical_decode_limits(encoded);
        // The same finite total covers sequential proof/checkpoint reads. A separate equal
        // envelope prepays their bounded retained model clones; RS16 scratch is also prepaid.
        let decoded = derived
            .max_total_allocated_bytes()
            .checked_add(
                iroha_data_model::sumeragi_finality::MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES,
            )
            .ok_or(Error::Source)?;
        let charged = decoded.checked_mul(2).ok_or(Error::Source)?;
        let layout = Layout::array::<u8>(charged).map_err(|_| Error::Allocation)?;
        let charge = budget
            .try_reserve(layout)
            .map_err(|_| Error::Allocation)?
            .try_split(layout)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            limits: norito::DecodeLimits::new(
                derived.max_sequence_elements(),
                MAX_FINALITY_CHECKPOINT_BYTES,
                derived.max_total_elements(),
                decoded,
                derived.max_nesting_depth(),
            ),
            _charge: charge,
        })
    }
    fn run<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        norito::with_decode_limits_scope(self.limits, action)
    }
}

// Exact inline slots are distinct from this conservative prepaid lifetime coverage of the
// native owner's nested decoder/authority graphs. Existing native reader TODOs remain: this
// is not individual nested-allocation provenance. The envelope only grows in powers of two,
// retaining every original increment until the entire prefix/pending owner is destroyed.
struct NativeDecodeEnvelope {
    reserved: usize,
    charges: ChargedBuffer<AllocationCharge>,
}
impl NativeDecodeEnvelope {
    fn new(budget: &AllocationBudget) -> Result<Self> {
        Ok(Self {
            reserved: 0,
            charges: ChargedBuffer::new(usize::BITS as usize, budget)
                .map_err(|_| Error::Allocation)?,
        })
    }
    fn ensure(&mut self, wire: usize, budget: &AllocationBudget) -> Result<()> {
        if wire == 0 || wire > MAX_FINALITY_BLOCK_BYTES || !self.charges.belongs_to(budget) {
            return Err(Error::Source);
        }
        let demand = norito::canonical_decode_limits(wire)
            .max_total_allocated_bytes()
            .checked_mul(4)
            .and_then(|n| {
                n.checked_add(
                    iroha_data_model::sumeragi_finality::MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES,
                )
            })
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::Allocation)?;
        if demand > self.reserved {
            let layout =
                Layout::array::<u8>(demand - self.reserved).map_err(|_| Error::Allocation)?;
            let charge = budget
                .try_reserve(layout)
                .map_err(|_| Error::Allocation)?
                .try_split(layout)
                .map_err(|_| Error::Allocation)?;
            self.charges.push_reserved(charge);
            self.reserved = demand;
        }
        Ok(())
    }
    fn run<T>(&self, wire: usize, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let derived = norito::canonical_decode_limits(wire);
        let total = derived
            .max_total_allocated_bytes()
            .checked_add(
                iroha_data_model::sumeragi_finality::MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES,
            )
            .ok_or(Error::Allocation)?;
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(
                derived.max_sequence_elements(),
                MAX_FINALITY_BLOCK_BYTES,
                derived.max_total_elements(),
                total,
                derived.max_nesting_depth(),
            ),
            action,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    };
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn one() -> NonZeroU16 {
        NonZeroU16::new(1).unwrap()
    }

    #[test]
    fn native_cursor_advances_real_prefix_in_bounded_steps_and_never_exports_genesis_authority() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        assert_eq!(cursor.original.as_ref().unwrap().native_height, 2);
        let current = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(current.block().height(), 3);
        assert_eq!(
            current.native_block().block_hash(),
            current.block().block().hash()
        );
        assert_eq!(
            current.native_block().core_hash(),
            current.block().core_hash()
        );
        assert_eq!(current.native_block().result(), current.block().result());
        assert_eq!(
            current.block().block().hash(),
            *chain.state().view().block_hashes().last().unwrap()
        );
        assert!(budget.reserved_bytes() > 0);
        drop(current);
        let again = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(again.block().height(), 3);
        drop(again);
        drop(cursor);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn historical_cursor_authenticates_exact_target_without_rewinding_or_claiming_current() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        for height in [1, 4] {
            assert!(matches!(
                cursor.advance_to_height(
                    &chain.state().view(),
                    NonZeroU64::new(height).unwrap(),
                    &budget,
                    deadline(),
                    one(),
                ),
                Err(Error::Source)
            ));
            assert!(cursor.original.is_none());
        }
        assert!(
            cursor
                .advance_to_height(
                    &chain.state().view(),
                    NonZeroU64::new(2).unwrap(),
                    &budget,
                    deadline(),
                    one(),
                )
                .unwrap()
                .is_none()
        );
        let old = cursor
            .advance_to_height(
                &chain.state().view(),
                NonZeroU64::new(2).unwrap(),
                &budget,
                deadline(),
                one(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(old.block().height(), 2);
        assert_eq!(
            old.block().block().hash(),
            *chain.state().view().block_hashes().get(1).unwrap()
        );
        assert_eq!(old.native_block().result(), old.block().result());
        assert_ne!(
            old.block().block().hash(),
            *chain.state().view().block_hashes().last().unwrap()
        );
        drop(old);
        let current = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(current.block().height(), 3);
        drop(current);
        assert!(matches!(
            cursor.advance_to_height(
                &chain.state().view(),
                NonZeroU64::new(2).unwrap(),
                &budget,
                deadline(),
                one(),
            ),
            Err(Error::Source)
        ));
        assert_eq!(cursor.original.as_ref().unwrap().native_height, 3);
        drop(cursor);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn portable_allocation_refusal_retains_native_pending_and_retries_same_pool() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        chain.commit(Vec::new());
        let extent =
            bounded_native_carrier_extent(&chain.state().view(), 2, MAX_FINALITY_BLOCK_BYTES)
                .unwrap();
        cursor
            .original
            .as_mut()
            .unwrap()
            .native_decode
            .ensure(extent, &budget)
            .unwrap();
        let preceding = cursor
            .original
            .as_ref()
            .unwrap()
            .checkpoint
            .as_ref()
            .unwrap()
            .as_slice()
            .to_vec();
        // Native receipt acquisition for this small actual fixture remains admitted; the
        // canonical portable decoder's mandatory 64 MiB scratch envelope cannot be admitted.
        let held = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes() - 4 * 1024 * 1024)
            .unwrap();
        assert!(matches!(
            cursor.advance_current(&chain.state().view(), &budget, deadline(), one()),
            Err(Error::Allocation)
        ));
        let original = cursor.original.as_ref().unwrap();
        assert_eq!(original.native_height, 2);
        assert!(matches!(original.pending, Some(Pending::Successor(_))));
        assert_eq!(original.checkpoint.as_ref().unwrap().as_slice(), preceding);
        drop(held);
        let current = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(current.block().height(), 2);
        assert!(cursor.original.as_ref().unwrap().pending.is_none());
        drop(current);
        drop(cursor);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn native_cursor_refuses_invalid_successor_and_keeps_the_original_genesis_progress() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        chain.commit(Vec::new());
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .is_err()
        );
        assert_eq!(cursor.original.as_ref().unwrap().native_height, 1);
        assert!(cursor.original.as_ref().unwrap().pending.is_none());
    }

    #[test]
    fn native_cursor_refuses_expired_foreign_pool_and_unbounded_call_without_authority() {
        let chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        assert!(matches!(
            cursor.advance_current(&chain.state().view(), &budget, Instant::now(), one()),
            Err(Error::Deadline)
        ));
        assert!(cursor.original.is_none());
        assert!(
            cursor
                .advance_current(
                    &chain.state().view(),
                    &budget,
                    deadline(),
                    NonZeroU16::new(65).unwrap()
                )
                .is_err()
        );
        assert!(cursor.original.is_none());
        assert!(
            cursor
                .advance_current(
                    &chain.state().view(),
                    &AllocationBudget::new(0),
                    deadline(),
                    one()
                )
                .is_err()
        );
        assert!(cursor.original.is_none());
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        let foreign = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        assert!(
            cursor
                .advance_current(&chain.state().view(), &foreign, deadline(), one())
                .is_err()
        );
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}
