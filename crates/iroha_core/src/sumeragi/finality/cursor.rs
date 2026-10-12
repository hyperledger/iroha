//! Bounded in-memory native history progress for local portable discovery.
//!
//! Only real State-pinned signed genesis starts this cursor. Neither callers nor disk DTOs
//! can import a checkpoint. Partial progress is historical and never returned as current.

use std::{
    alloc::Layout,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Instant,
};

use super::ProofError;
use crate::{
    state::StateReadOnly,
    sumeragi::certified_chain::{
        AdmittedPrefixInitialization, AdmittedPrefixPush, CertifiedBlock, CertifiedPrefix,
        CommittedBlock, NativeCarrierAcquisition, admit_verification_slot,
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
    /// A bounded decoder envelope extent or layout is not representable.
    #[error("native finality observation allocation extent unavailable")]
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
    initializing: Option<Initializing>,
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
    chain_id: ChainIdentity,
    prefix: ChargedBuffer<CertifiedPrefix>,
    native_height: u64,
    native_hash: HashOf<BlockHeader>,
    pending: Option<Pending>,
    preparing: Option<PendingPreparation>,
    checkpoint: Option<ChargedBuffer<u8>>,
    acquiring: Option<Successor>,
    projecting: Option<OutputRead>,
    kura: Arc<crate::kura::Kura>,
    // Declared last: decoded prefix/pending/checkpoint owners reclaim before these charges.
    native_decode: NativeDecodeEnvelope,
}
enum Pending {
    Genesis(SharedSignedBlock),
    Successor(ChargedBuffer<CertifiedBlock>),
}

// Canonical ChainId is at most 128 ASCII bytes. Retain its exact identity inline, so a
// retry binding needs neither a second uncharged String nor a hash-based substitute.
struct ChainIdentity {
    bytes: [u8; iroha_model_base::chain::MAX_CHAIN_ID_BYTES],
    length: usize,
}
impl ChainIdentity {
    fn new(chain: &iroha_model_base::chain::ChainId) -> Self {
        let mut bytes = [0; iroha_model_base::chain::MAX_CHAIN_ID_BYTES];
        bytes[..chain.as_str().len()].copy_from_slice(chain.as_str().as_bytes());
        Self {
            bytes,
            length: chain.as_str().len(),
        }
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.length])
            .expect("original canonical ASCII chain identity")
    }
}

// Bodies and verification slots retire before the last original decoder envelope.
struct Initializing {
    prefix: AdmittedPrefixInitialization,
    carrier: Carrier,
    network: NetworkId,
    chain_id: ChainIdentity,
    native_decode: NativeDecodeEnvelope,
}
struct Successor {
    output: ChargedBuffer<CertifiedBlock>,
    read: AdmittedPrefixPush,
    carrier: Option<Carrier>,
}
struct Carrier {
    body: Option<SharedSignedBlock>,
    acquisition: NativeCarrierAcquisition<'static>,
    extent: usize,
    height: u64,
    hash: HashOf<BlockHeader>,
}
impl Carrier {
    fn new(
        view: &impl StateReadOnly,
        height: u64,
        extent: usize,
        budget: &AllocationBudget,
    ) -> Result<Self> {
        let index = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(Error::Source)?;
        let hash = *view
            .block_hashes()
            .get(index.get() - 1)
            .ok_or(Error::Source)?;
        Ok(Self {
            body: None,
            acquisition: NativeCarrierAcquisition::new_owned(
                view.kura_handle(),
                index,
                hash,
                budget.clone(),
                extent,
            ),
            extent,
            height,
            hash,
        })
    }
    fn recheck(&self, view: &impl StateReadOnly, budget: &AllocationBudget) -> Result<()> {
        if !self
            .acquisition
            .matches_owner(view.kura(), self.height, self.hash, budget)
            || view.block_hashes().get(self.height as usize - 1) != Some(&self.hash)
        {
            return Err(Error::Source);
        }
        Ok(())
    }
    fn complete(
        &mut self,
        view: &impl StateReadOnly,
        budget: &AllocationBudget,
    ) -> Result<&SharedSignedBlock> {
        self.recheck(view, budget)?;
        if self.body.is_none() {
            self.body = Some(self.acquisition.complete().map_err(ProofError::from)?);
        } else {
            self.acquisition
                .recheck_original_source()
                .map_err(ProofError::from)?;
        }
        Ok(self.body.as_ref().expect("original acquired native body"))
    }
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
            let initialized = self.initialize(view, budget, deadline);
            #[cfg(all(test, sumeragi_core_mutation = "HC233"))]
            if matches!(&initialized, Err(Error::Proof(ProofError::Deferred(_)))) {
                self.initializing = None;
            }
            initialized?;
        }
        let original = self.original.as_mut().ok_or(Error::Source)?;
        if original.network != *view.network_id()
            || original.chain_id.as_str() != view.chain_id().as_str()
            || !core::ptr::eq(original.kura.as_ref(), view.kura())
            || !original.prefix.belongs_to(budget)
            || original.native_height > target
            || view.block_hashes().get(original.native_height as usize - 1)
                != Some(&original.native_hash)
        {
            return Err(Error::Source);
        }
        if original.projecting.is_some() {
            // A newer captured cut may arrive while an older final projection is deferred.
            // Complete that same original operation before advancing its native prefix.
            // Its historical result can never be returned as authority for the newer tip.
            let completed = original.finish_output(view, budget, deadline, current)?;
            if original.native_height == target {
                return Ok(Some(completed));
            }
            drop(completed);
        }
        for _ in 0..maximum_steps.get() {
            check(deadline)?;
            if original.pending.is_none() {
                if original.native_height == target {
                    break;
                }
                let next = original.native_height.checked_add(1).ok_or(Error::Source)?;
                if original.acquiring.is_none() {
                    // Preserve the original output admission before source extent checks.
                    original.acquiring = Some(Successor {
                        output: admit_verification_slot(budget).map_err(ProofError::from)?,
                        read: AdmittedPrefixPush::default(),
                        carrier: None,
                    });
                }
                let acquired = original.acquire_successor(view, next, budget, deadline);
                #[cfg(all(test, sumeragi_core_mutation = "HC234"))]
                if matches!(&acquired, Err(Error::Proof(ProofError::Deferred(_)))) {
                    original.acquiring = None;
                }
                acquired?;
            }
            // A failure below keeps the exact native receipt and preceding compact checkpoint.
            original.finish_pending(budget, deadline)?;
        }
        check(deadline)?;
        if original.pending.is_some() || original.native_height != target || target < 2 {
            return Ok(None);
        }
        original
            .finish_output(view, budget, deadline, current)
            .map(Some)
    }

    fn initialize(
        &mut self,
        view: &impl StateReadOnly,
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<()> {
        if self.initializing.is_none() {
            check(deadline)?;
            let extent = bounded_native_carrier_extent(view, 1, MAX_FINALITY_BLOCK_BYTES)
                .map_err(ProofError::from)?;
            check(deadline)?;
            let native_decode = NativeDecodeEnvelope::new(budget)?;
            self.initializing = Some(Initializing {
                prefix: AdmittedPrefixInitialization::default(),
                carrier: Carrier::new(view, 1, extent, budget)?,
                network: *view.network_id(),
                chain_id: ChainIdentity::new(view.chain_id()),
                native_decode,
            });
        }
        let original = self
            .initializing
            .as_mut()
            .expect("original initialization attempt");
        if original.network != *view.network_id()
            || original.chain_id.as_str() != view.chain_id().as_str()
        {
            return Err(Error::Source);
        }
        original.carrier.recheck(view, budget)?;
        let extent = original.carrier.extent;
        original.native_decode.ensure(extent, budget)?;
        let prefix = original.native_decode.run(extent, || {
            check(deadline)?;
            let genesis = original.carrier.complete(view, budget)?;
            check(deadline)?;
            #[cfg(test)]
            tests::probe_original_carrier(genesis);
            original
                .prefix
                .complete(view.chain_id(), *view.network_id(), genesis.clone(), budget)
                .map_err(|error| Error::Proof(ProofError::from(error)))
        })?;
        let genesis = original
            .carrier
            .body
            .as_ref()
            .expect("original initialized genesis");
        let metadata =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(genesis)
                .map_err(|error| {
                    Error::Proof(ProofError::from(
                        iroha_data_model::sumeragi_finality::FinalityReadError::Genesis(error),
                    ))
                })?;
        if metadata.sumeragi_context.root_scope != SumeragiRootScope::Global {
            return Err(Error::Source);
        }
        let Initializing {
            mut carrier,
            network,
            chain_id,
            native_decode,
            ..
        } = self
            .initializing
            .take()
            .expect("complete original initialization");
        self.original = Some(Original {
            network,
            chain_id,
            kura: view.kura_handle(),
            prefix,
            native_height: 1,
            native_hash: carrier.hash,
            pending: Some(Pending::Genesis(
                carrier.body.take().expect("original genesis body"),
            )),
            preparing: None,
            checkpoint: None,
            acquiring: None,
            projecting: None,
            native_decode,
        });
        Ok(())
    }
}

impl Original {
    fn acquire_successor(
        &mut self,
        view: &impl StateReadOnly,
        next: u64,
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<()> {
        let original = self.acquiring.as_mut().expect("original successor output");
        if original.carrier.is_none() {
            check(deadline)?;
            let extent = bounded_native_carrier_extent(view, next, MAX_FINALITY_BLOCK_BYTES)
                .map_err(ProofError::from)?;
            check(deadline)?;
            original.carrier = Some(Carrier::new(view, next, extent, budget)?);
        }
        let carrier = original
            .carrier
            .as_mut()
            .expect("original successor carrier");
        carrier.recheck(view, budget)?;
        let extent = carrier.extent;
        self.native_decode.ensure(extent, budget)?;
        self.native_decode.run(extent, || {
            check(deadline)?;
            let block = carrier.complete(view, budget)?;
            check(deadline)?;
            #[cfg(test)]
            tests::probe_original_carrier(block);
            original
                .read
                .complete_with_finish(
                    &mut self.prefix.as_mut_slice()[0],
                    block.clone(),
                    budget,
                    |step| {
                        let (current, _) = step.into_parts();
                        original.output.push_reserved(current);
                    },
                )
                .map_err(ProofError::from)?;
            Ok(())
        })?;
        self.native_height = next;
        self.native_hash = carrier.hash;
        let completed = self.acquiring.take().expect("complete original successor");
        self.pending = Some(Pending::Successor(completed.output));
        Ok(())
    }

    fn finish_output(
        &mut self,
        view: &impl StateReadOnly,
        budget: &AllocationBudget,
        deadline: Instant,
        current: u64,
    ) -> Result<NativeFinalityAtHeightV1> {
        let bytes = self.checkpoint.as_ref().ok_or(Error::Source)?;
        if self.projecting.is_none() {
            let custody = DecodeCustody::new(bytes.as_slice().len(), budget)?;
            self.projecting = Some(OutputRead {
                output: None,
                native: None,
                checkpoint: None,
                carrier: None,
                height: self.native_height,
                hash: self.native_hash,
                custody,
            });
        }
        let original = self
            .projecting
            .as_mut()
            .expect("original output projection");
        if original.height != self.native_height || original.hash != self.native_hash {
            return Err(Error::Source);
        }
        let completed = original.complete(
            bytes.as_slice(),
            self.network,
            self.chain_id.as_str(),
            view,
            budget,
            deadline,
            current,
        );
        #[cfg(all(test, sumeragi_core_mutation = "HC235"))]
        if matches!(&completed, Err(Error::Proof(ProofError::Deferred(_)))) {
            self.projecting = None;
        }
        completed?;
        Ok(self
            .projecting
            .take()
            .expect("complete original output projection")
            .into_output())
    }

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
        let original = self
            .preparing
            .get_or_insert_with(PendingPreparation::default);
        let completed = original.complete(
            block,
            members,
            self.checkpoint.as_ref().map(ChargedBuffer::as_slice),
            self.network,
            self.chain_id.as_str(),
            budget,
            deadline,
        );
        #[cfg(all(test, sumeragi_core_mutation = "HC236"))]
        if matches!(&completed, Err(Error::Proof(ProofError::Deferred(_)))) {
            self.preparing = None;
        }
        completed?;
        check(deadline)?;
        let original = self
            .preparing
            .take()
            .expect("complete original pending preparation");
        // Only the authenticated compact checkpoint becomes the next portable trust root.
        self.checkpoint = Some(
            original
                .encoded
                .expect("complete original checkpoint bytes"),
        );
        self.pending = None;
        Ok(())
    }
}

// This attempt retains each completed real allocation in its original admission order.
// In particular a partial PoP/key destination cannot refund earlier wire/committee charges,
// nor can checkpoint output pressure retire the decoder envelope and exported graph.
#[derive(Default)]
struct PendingPreparation {
    destination: super::proof_destination::ProofPreparation,
    checkpoint: Option<SumeragiFinalityCheckpoint>,
    encoded: Option<ChargedBuffer<u8>>,
    // Last: every decoded verifier/checkpoint graph retires before this original envelope.
    custody: Option<DecodeCustody>,
}
impl PendingPreparation {
    #[expect(
        clippy::too_many_arguments,
        reason = "original native source, checkpoint and caller custody stay explicit"
    )]
    fn complete(
        &mut self,
        block: &SharedSignedBlock,
        members: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
        previous: Option<&[u8]>,
        network: NetworkId,
        chain: &str,
        budget: &AllocationBudget,
        deadline: Instant,
    ) -> Result<()> {
        let owned = self
            .destination
            .complete(block, members, budget, deadline)
            .map_err(proof_destination_error)?;
        let envelope_bytes = previous
            .map_or(0, <[u8]>::len)
            .checked_add(owned.proof.block_wire.len())
            .ok_or(Error::Source)?;
        #[cfg(test)]
        tests::probe_pending_envelope(block.header().height().get(), envelope_bytes, &owned.proof);
        if self.custody.is_none() {
            self.custody = Some(DecodeCustody::new(envelope_bytes, budget)?);
        }
        let custody = self
            .custody
            .as_ref()
            .expect("original pending decoder envelope");
        custody.run(|| {
            if self.checkpoint.is_none() {
                check(deadline)?;
                let mut verifier = if let Some(bytes) = previous {
                    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(bytes)
                        .map_err(ProofError::from)?;
                    check(deadline)?;
                    SumeragiFinalityVerifier::from_trusted_checkpoint(&checkpoint, &network, chain)
                        .map_err(ProofError::from)?
                } else {
                    SumeragiFinalityVerifier::new(block, chain, owned.proof.committee.clone())
                        .map_err(ProofError::from)?
                };
                check(deadline)?;
                verifier.verify(&owned.proof).map_err(ProofError::from)?;
                check(deadline)?;
                let checkpoint = verifier
                    .export_checkpoint(&owned.proof)
                    .map_err(ProofError::from)?;
                check(deadline)?;
                self.checkpoint = Some(checkpoint);
            }
            let checkpoint = self
                .checkpoint
                .as_ref()
                .expect("original verified checkpoint");
            #[cfg(test)]
            tests::probe_pending_checkpoint(checkpoint);
            if self.encoded.is_none() {
                self.encoded = Some(encode_checkpoint(checkpoint, budget, deadline)?);
            }
            Ok(())
        })
    }
}

fn allocation_error(cause: iroha_allocation::AllocationRefusal) -> Error {
    #[cfg(test)]
    tests::observe_pending_refusal(&cause);
    Error::Proof(ProofError::Deferred(cause.into()))
}
fn buffer_error(error: iroha_allocation::ChargedBufferError) -> Error {
    match error {
        iroha_allocation::ChargedBufferError::Admission(cause) => allocation_error(cause),
        iroha_allocation::ChargedBufferError::Allocator { .. } => Error::Proof(
            ProofError::Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into()),
        ),
    }
}
fn proof_destination_error(error: super::ProofDestinationError) -> Error {
    #[cfg(test)]
    tests::observe_pending_destination(&error);
    use iroha_allocation::ChargedBufferFromChargeError;
    use iroha_crypto::PublicKeyAllocationError;
    match error {
        super::ProofDestinationError::Deadline => Error::Deadline,
        super::ProofDestinationError::Source => Error::Source,
        super::ProofDestinationError::Admission(cause) => allocation_error(cause),
        super::ProofDestinationError::Buffer(error) => buffer_error(error),
        super::ProofDestinationError::Key(
            PublicKeyAllocationError::ForeignPool
            | PublicKeyAllocationError::Allocation(ChargedBufferFromChargeError::LayoutMismatch {
                ..
            }),
        ) => Error::Source,
        super::ProofDestinationError::Key(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::DemandOverflow,
        )) => allocation_error(iroha_allocation::AllocationRefusal::DemandOverflow),
        super::ProofDestinationError::Key(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::Allocator { .. },
        )) => Error::Proof(ProofError::Deferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        )),
    }
}

// All retained decoded/source graphs and exact output slots retire before this attempt's
// original portable decoder envelope. This stage owns no authority independently of the
// native prefix and the locally produced checkpoint it borrows for initialization.
struct OutputRead {
    output: Option<ChargedBuffer<VerifiedSumeragiBlock>>,
    native: Option<ChargedBuffer<CommittedBlock>>,
    checkpoint: Option<SumeragiFinalityCheckpoint>,
    carrier: Option<Carrier>,
    height: u64,
    hash: HashOf<BlockHeader>,
    custody: DecodeCustody,
}
impl OutputRead {
    #[expect(
        clippy::too_many_arguments,
        reason = "the exact original identity, caller pool and captured cut remain explicit"
    )]
    fn complete(
        &mut self,
        bytes: &[u8],
        network: NetworkId,
        chain: &str,
        view: &impl StateReadOnly,
        budget: &AllocationBudget,
        deadline: Instant,
        current: u64,
    ) -> Result<()> {
        let Self {
            output,
            native,
            checkpoint,
            carrier,
            height,
            hash,
            custody,
        } = self;
        #[cfg(test)]
        tests::probe_output_slots(*height);
        if output.is_none() {
            *output = Some(admit_verification_slot(budget).map_err(ProofError::from)?);
        }
        if native.is_none() {
            *native = Some(admit_verification_slot(budget).map_err(ProofError::from)?);
        }
        custody.run(|| {
            if checkpoint.is_none() {
                *checkpoint = Some(
                    SumeragiFinalityCheckpoint::decode_canonical(bytes)
                        .map_err(ProofError::from)?,
                );
            }
            let checkpoint = checkpoint
                .as_ref()
                .expect("original decoded local checkpoint");
            check(deadline)?;
            if carrier.is_none() {
                *carrier = Some(Carrier::new(
                    view,
                    *height,
                    MAX_FINALITY_BLOCK_BYTES,
                    budget,
                )?);
            }
            #[cfg(test)]
            tests::probe_output_carrier(*height);
            let durable = carrier
                .as_mut()
                .expect("original durable projection source")
                .complete(view, budget)?;
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
            let output = output.as_mut().expect("original verified output slot");
            let native = native.as_mut().expect("original native output slot");
            if output.as_slice().is_empty() {
                check(deadline)?;
                let verifier =
                    SumeragiFinalityVerifier::from_trusted_checkpoint(checkpoint, &network, chain)
                        .map_err(ProofError::from)?;
                check(deadline)?;
                let verified = verifier
                    .verify_retained_decision(checkpoint.tip())
                    .map_err(ProofError::from)?;
                check(deadline)?;
                output.push_reserved(verified);
            }
            let verified = &output.as_slice()[0];
            if native.as_slice().is_empty() {
                check(deadline)?;
                let receipt = read_frame(durable.clone(), *height, verified.root_scope())
                    .map_err(ProofError::from)?;
                native.push_reserved(receipt);
            }
            let receipt = &native.as_slice()[0];
            if coherent_height(view)? != current
                || verified.height() != *height
                || verified.block().hash() != *hash
                || receipt.block_hash() != verified.block().hash()
                || receipt.core_hash() != verified.core_hash()
                || receipt.result() != verified.result()
                || receipt.id().0.as_ref() != verified.context_id().as_ref()
            {
                return Err(Error::Source);
            }
            Ok(())
        })
    }
    fn into_output(self) -> NativeFinalityAtHeightV1 {
        NativeFinalityAtHeightV1 {
            block: self.output.expect("complete original verified output"),
            native: self.native.expect("complete original native output"),
            _decode: self.custody,
        }
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
    let mut buffer = ChargedBuffer::new(length, budget).map_err(buffer_error)?;
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
            .map_err(allocation_error)?
            .try_split(layout)
            .expect("exact admitted decoder envelope");
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
            charges: ChargedBuffer::new(usize::BITS as usize, budget).map_err(buffer_error)?,
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
                .map_err(allocation_error)?
                .try_split(layout)
                .expect("exact admitted native envelope increment");
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
pub(super) fn probe_pending_key(
    height: u64,
    index: usize,
    count: usize,
    demand: usize,
    wire: usize,
    pop: usize,
) {
    tests::pending_key_probe(height, index, count, demand, wire, pop);
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
            Err(Error::Proof(ProofError::Deferred(_)))
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
    thread_local! {
        static CARRIER_PROBE: std::cell::RefCell<Option<Box<dyn FnMut(&SharedSignedBlock)>>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn probe_original_carrier(block: &SharedSignedBlock) {
        CARRIER_PROBE.with_borrow_mut(|probe| {
            if let Some(probe) = probe {
                probe(block);
            }
        });
    }
    struct ProbeGuard;
    impl Drop for ProbeGuard {
        fn drop(&mut self) {
            CARRIER_PROBE.with_borrow_mut(|probe| *probe = None);
        }
    }

    // Pressure begins only after the real durable carrier was acquired by this cursor.
    // No receipt, authority or QC is supplied by the test: the next production admission
    // succeeds for CommittedBlock and fails for the complete CertifiedResultV1 slot.
    fn native_cursor_late_result_slot(genesis: bool, cancel: bool) {
        use crate::sumeragi::commitment::CertifiedResultV1;
        use iroha_allocation::{
            AllocationRefusal, AllocationReservation, release::ReleaseRegistration,
        };
        use std::{
            cell::RefCell,
            future::Future,
            rc::Rc,
            sync::Arc,
            task::{Context, Poll},
        };

        let _retirement_pin = crossbeam_epoch::pin();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit_at(20_000, Vec::new());
        let expected = chain.committed(2);
        let hash = expected.block_hash();
        let result = expected.result();
        drop(expected);
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        if !genesis {
            assert!(
                cursor
                    .advance_current(&chain.state().view(), &budget, deadline(), one())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(cursor.original.as_ref().unwrap().native_height, 1);
        }
        let mut prepaid = budget
            .try_reserve_bytes(ReleaseRegistration::allocation_layout().size())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let registration_bytes = ReleaseRegistration::allocation_layout().size();
        let pressure = Rc::new(RefCell::new(None::<AllocationReservation>));
        let pointers = Rc::new(RefCell::new(Vec::<usize>::new()));
        let original_pressure = Rc::clone(&pressure);
        let original_pointers = Rc::clone(&pointers);
        let original_budget = budget.clone();
        let mut first = true;
        CARRIER_PROBE.with_borrow_mut(|probe| {
            assert!(probe.is_none());
            *probe = Some(Box::new(move |block| {
                if block.header().height().get() != if genesis { 1 } else { 2 } {
                    return;
                }
                original_pointers
                    .borrow_mut()
                    .push(std::ptr::from_ref(&**block) as usize);
                if first {
                    first = false;
                    let preceding = size_of::<CommittedBlock>()
                        + if genesis {
                            size_of::<CertifiedPrefix>()
                        } else {
                            0
                        };
                    *original_pressure.borrow_mut() = Some(
                        original_budget
                            .try_reserve_bytes(
                                original_budget.limit_bytes()
                                    - original_budget.reserved_bytes()
                                    - preceding,
                            )
                            .unwrap(),
                    );
                }
            }));
        });
        let _probe = ProbeGuard;
        let Err(Error::Proof(ProofError::Deferred(cause))) =
            cursor.advance_current(&chain.state().view(), &budget, deadline(), one())
        else {
            panic!("the real native result slot must refuse");
        };
        let Some(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = cause.allocation_refusal()
        else {
            panic!("preserve original result-slot physical refusal");
        };
        assert_eq!(*requested_bytes, size_of::<CertifiedResultV1>());
        assert_eq!(*reserved_bytes, budget.limit_bytes());
        assert_eq!(*limit_bytes, budget.limit_bytes());
        let mut wait = Box::pin(release.clone().wait_for_release(&mut registration));
        let mut poll = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            wait.as_mut().poll(&mut poll),
            Poll::Pending,
            "late result refusal must retain earlier source, output and verification owners instead of self-waking"
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        if genesis {
            assert!(cursor.original.is_none());
        } else {
            assert_eq!(cursor.original.as_ref().unwrap().native_height, 1);
        }
        let Err(Error::Proof(ProofError::Deferred(repeated))) =
            cursor.advance_current(&chain.state().view(), &budget, deadline(), one())
        else {
            panic!("retry must remain on the same native result slot");
        };
        assert_eq!(repeated.allocation_refusal(), cause.allocation_refusal());
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
        assert_eq!(pointers.borrow().len(), 2);
        assert_eq!(
            pointers.borrow()[0],
            pointers.borrow()[1],
            "retry must lend the original shared native body"
        );
        {
            // A second genuine State has the same signed genesis and independently opened
            // durable storage. Matching labels and hashes cannot rebind the pending owner.
            let foreign =
                CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
            assert_eq!(
                chain.state().view().network_id(),
                foreign.state().view().network_id()
            );
            assert_eq!(
                chain.state().view().block_hashes().get(0),
                foreign.state().view().block_hashes().get(0)
            );
            assert!(!Arc::ptr_eq(chain.kura(), foreign.kura()));
            assert!(matches!(
                cursor.advance_current(&foreign.state().view(), &budget, deadline(), one()),
                Err(Error::Source)
            ));
            assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        }
        let foreign_pool = AllocationBudget::new(budget.limit_bytes());
        assert!(matches!(
            cursor.advance_current(&chain.state().view(), &foreign_pool, deadline(), one()),
            Err(Error::Source)
        ));
        assert_eq!(foreign_pool.reserved_bytes(), 0);
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        if cancel {
            drop(cursor);
            assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
            drop(wait);
            drop(pressure.borrow_mut().take());
            assert_eq!(budget.reserved_bytes(), registration_bytes);
            drop(registration);
            assert_eq!(budget.reserved_bytes(), 0);
            return;
        }
        drop(pressure.borrow_mut().take());
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
        drop(wait);
        let mut current = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap();
        if genesis {
            assert!(current.is_none());
            current = cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap();
        }
        let current = current
            .expect("genuine native QC releases exact finality after original capacity returns");
        assert_eq!(current.block().height(), 2);
        assert_eq!(current.native_block().block_hash(), hash);
        assert_eq!(current.native_block().result(), result);
        assert_eq!(current.block().block().hash(), hash);
        assert_eq!(current.block().result(), result);
        assert!(cursor.original.as_ref().unwrap().pending.is_none());
        assert_eq!(pointers.borrow().len(), 3);
        assert!(
            pointers
                .borrow()
                .iter()
                .all(|pointer| *pointer == pointers.borrow()[0])
        );
        drop(current);
        drop(cursor);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn native_cursor_genesis_result_slot_refusal_retains_original_source_until_release() {
        for cancel in [false, true] {
            native_cursor_late_result_slot(true, cancel);
        }
    }
    #[test]
    fn native_cursor_successor_result_slot_refusal_retains_original_source_until_release() {
        for cancel in [false, true] {
            native_cursor_late_result_slot(false, cancel);
        }
    }

    #[test]
    fn cursor_chain_identity_preserves_canonical_maximum_and_exact_rebinding() {
        use iroha_model_base::chain::{ChainId, MAX_CHAIN_ID_BYTES};
        let name = "A".repeat(MAX_CHAIN_ID_BYTES);
        let chain: ChainId = name.parse().unwrap();
        let retained = ChainIdentity::new(&chain);
        assert_eq!(retained.as_str(), chain.as_str());
        assert_eq!(retained.as_str().len(), MAX_CHAIN_ID_BYTES);
        let changed: ChainId = ("A".repeat(MAX_CHAIN_ID_BYTES - 1) + "B").parse().unwrap();
        assert_ne!(retained.as_str(), changed.as_str());
        assert_eq!(ChainIdentity::new(&changed).as_str(), changed.as_str());
        assert_ne!(retained.as_str(), "A");
    }
    thread_local! {
        static OUTPUT_PROBE: std::cell::RefCell<Option<Box<dyn FnMut(u64, bool)>>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn probe_output_slots(height: u64) {
        OUTPUT_PROBE.with_borrow_mut(|probe| {
            if let Some(probe) = probe {
                probe(height, false);
            }
        });
    }
    pub(super) fn probe_output_carrier(height: u64) {
        OUTPUT_PROBE.with_borrow_mut(|probe| {
            if let Some(probe) = probe {
                probe(height, true);
            }
        });
    }
    struct OutputProbeGuard;
    impl Drop for OutputProbeGuard {
        fn drop(&mut self) {
            OUTPUT_PROBE.with_borrow_mut(|probe| *probe = None);
        }
    }

    // Final projection must keep its actual raw frame, decoded checkpoint, output slots
    // and original decoder envelope when a later physical admission refuses. The hook
    // only adds pressure: all source bytes, native receipts and signatures remain genuine.
    fn native_cursor_output_refusal(shell: bool, cancel: bool, append: bool) {
        use iroha_allocation::{
            AllocationRefusal, AllocationReservation, release::ReleaseRegistration,
        };
        use std::{
            cell::RefCell,
            future::Future,
            rc::Rc,
            task::{Context, Poll},
        };

        let _retirement_pin = crossbeam_epoch::pin();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit_at(20_000, Vec::new());
        let receipt = chain.committed(2);
        let mut expected_hash = receipt.block_hash();
        let mut expected_result = receipt.result();
        drop(receipt);
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        let initial = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(initial.block().height(), 2);
        drop(initial);
        let wire =
            bounded_native_carrier_extent(&chain.state().view(), 2, MAX_FINALITY_BLOCK_BYTES)
                .unwrap();
        let preceding_checkpoint = cursor
            .original
            .as_ref()
            .unwrap()
            .checkpoint
            .as_ref()
            .unwrap()
            .as_slice()
            .to_vec();
        let mut prepaid = budget
            .try_reserve_bytes(ReleaseRegistration::allocation_layout().size())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let pressure = Rc::new(RefCell::new(None::<AllocationReservation>));
        let original_pressure = Rc::clone(&pressure);
        let original_budget = budget.clone();
        let mut first = true;
        OUTPUT_PROBE.with_borrow_mut(|probe| {
            assert!(probe.is_none());
            *probe = Some(Box::new(move |height, at_carrier| {
                if !first || height != 2 || at_carrier != shell {
                    return;
                }
                first = false;
                let preceding = if shell {
                    wire
                } else {
                    size_of::<VerifiedSumeragiBlock>()
                };
                *original_pressure.borrow_mut() = Some(
                    original_budget
                        .try_reserve_bytes(
                            original_budget.limit_bytes()
                                - original_budget.reserved_bytes()
                                - preceding,
                        )
                        .unwrap(),
                );
            }));
        });
        let _probe = OutputProbeGuard;
        chain.kura().reset_canonical_query_reads_for_test();
        let Err(Error::Proof(ProofError::Deferred(cause))) =
            cursor.advance_current(&chain.state().view(), &budget, deadline(), one())
        else {
            panic!("the actual final output admission must preserve its original physical refusal");
        };
        let Some(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = cause.allocation_refusal()
        else {
            panic!("preserve exact final projection capacity cause");
        };
        assert_eq!(
            *requested_bytes,
            if shell {
                SharedSignedBlock::allocation_layout().size()
            } else {
                size_of::<CommittedBlock>()
            }
        );
        assert_eq!(*reserved_bytes, budget.limit_bytes());
        assert_eq!(*limit_bytes, budget.limit_bytes());
        let mut wait = Box::pin(release.clone().wait_for_release(&mut registration));
        let mut poll = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            wait.as_mut().poll(&mut poll),
            Poll::Pending,
            "a refused final projection must retain its earlier original allocations instead of self-waking"
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert_eq!(
            chain.kura().canonical_query_reads_for_test(),
            if shell { (1, wire as u64) } else { (0, 0) }
        );
        assert_eq!(cursor.original.as_ref().unwrap().native_height, 2);
        assert_eq!(
            cursor
                .original
                .as_ref()
                .unwrap()
                .checkpoint
                .as_ref()
                .unwrap()
                .as_slice(),
            preceding_checkpoint
        );
        if append {
            // A genuinely committed successor can arrive while the old projection is parked.
            // It changes the requested current cut, never the retained height-two source.
            chain.commit_at(30_000, Vec::new());
            let receipt = chain.committed(3);
            expected_hash = receipt.block_hash();
            expected_result = receipt.result();
            drop(receipt);
            chain.kura().reset_canonical_query_reads_for_test();
        }
        let reads = chain.kura().canonical_query_reads_for_test();
        let Err(Error::Proof(ProofError::Deferred(repeated))) =
            cursor.advance_current(&chain.state().view(), &budget, deadline(), one())
        else {
            panic!("retry must retain the exact refused projection even after a new tip");
        };
        assert_eq!(repeated.allocation_refusal(), cause.allocation_refusal());
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
        assert_eq!(
            chain.kura().canonical_query_reads_for_test(),
            reads,
            "retry must not reread the retained original frame"
        );
        assert_eq!(cursor.original.as_ref().unwrap().native_height, 2);
        if cancel {
            drop(cursor);
            assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
            drop(wait);
            drop(pressure.borrow_mut().take());
            assert_eq!(
                budget.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
            drop(registration);
            assert_eq!(budget.reserved_bytes(), 0);
            return;
        }
        drop(pressure.borrow_mut().take());
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
        drop(wait);
        let current = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(current.block().height(), if append { 3 } else { 2 });
        assert_eq!(current.block().block().hash(), expected_hash);
        assert_eq!(current.native_block().block_hash(), expected_hash);
        assert_eq!(current.block().result(), expected_result);
        assert_eq!(current.native_block().result(), expected_result);
        assert_eq!(
            cursor.original.as_ref().unwrap().native_height,
            if append { 3 } else { 2 }
        );
        drop(cursor);
        assert!(budget.reserved_bytes() > ReleaseRegistration::allocation_layout().size());
        assert_eq!(
            current.native_block().result(),
            expected_result,
            "final reader owns its original envelope after cursor cancellation"
        );
        drop(current);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn native_cursor_output_shell_refusal_retains_projection_and_observes_new_tip() {
        native_cursor_output_refusal(true, false, false);
        native_cursor_output_refusal(true, false, true);
        native_cursor_output_refusal(true, true, false);
    }

    #[test]
    fn native_cursor_output_receipt_slot_preserves_exact_capacity_and_refunds() {
        native_cursor_output_refusal(false, false, false);
        native_cursor_output_refusal(false, true, false);
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PendingStage {
        Key,
        Envelope,
        Checkpoint,
    }
    thread_local! {
        static PENDING_PROBE: std::cell::RefCell<Option<Box<dyn FnMut(PendingStage, u64, usize, usize, usize)>>> = const { std::cell::RefCell::new(None) };
        static PENDING_REFUSAL: std::cell::RefCell<Option<iroha_allocation::AllocationRefusal>> = const { std::cell::RefCell::new(None) };
    }
    fn probe_pending_stage(
        stage: PendingStage,
        height: u64,
        demand: usize,
        first: usize,
        second: usize,
    ) {
        PENDING_PROBE.with_borrow_mut(|probe| {
            if let Some(probe) = probe {
                probe(stage, height, demand, first, second);
            }
        });
    }
    pub(super) fn pending_key_probe(
        height: u64,
        index: usize,
        count: usize,
        demand: usize,
        wire: usize,
        pop: usize,
    ) {
        if index + 1 == count {
            probe_pending_stage(PendingStage::Key, height, demand, wire, pop);
        }
    }
    pub(super) fn probe_pending_envelope(
        height: u64,
        encoded: usize,
        proof: &iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
    ) {
        let demand = (norito::canonical_decode_limits(encoded).max_total_allocated_bytes()
            + iroha_data_model::sumeragi_finality::MAX_FINALITY_AVAILABILITY_SCRATCH_BYTES)
            * 2;
        probe_pending_stage(
            PendingStage::Envelope,
            height,
            demand,
            proof.block_wire.as_ptr() as usize,
            proof.committee.as_ptr() as usize,
        );
    }
    pub(super) fn probe_pending_checkpoint(checkpoint: &SumeragiFinalityCheckpoint) {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let demand = norito::canonical_frame_len(checkpoint).unwrap();
        probe_pending_stage(
            PendingStage::Checkpoint,
            checkpoint.tip().block_header.height().get(),
            demand,
            checkpoint.tip().block_wire.as_ptr() as usize,
            checkpoint.tip().committee.as_ptr() as usize,
        );
    }
    pub(super) fn observe_pending_refusal(cause: &iroha_allocation::AllocationRefusal) {
        if PENDING_PROBE.with_borrow(Option::is_some) {
            PENDING_REFUSAL.with_borrow_mut(|original| *original = Some(cause.clone()));
        }
    }
    pub(super) fn observe_pending_destination(error: &super::super::ProofDestinationError) {
        use super::super::ProofDestinationError;
        match error {
            ProofDestinationError::Admission(cause)
            | ProofDestinationError::Buffer(iroha_allocation::ChargedBufferError::Admission(
                cause,
            )) => observe_pending_refusal(cause),
            _ => {}
        }
    }
    struct PendingProbeGuard;
    impl Drop for PendingProbeGuard {
        fn drop(&mut self) {
            PENDING_PROBE.with_borrow_mut(|probe| *probe = None);
            PENDING_REFUSAL.with_borrow_mut(|cause| *cause = None);
        }
    }

    // The observer copies the original production refusal before its diagnostic mapping;
    // it neither probes capacity a second time nor manufactures a new release generation.
    // This exposes the pre-repair self-wake even when the old cursor erases Capacity.
    fn native_cursor_pending_refusal(stage: PendingStage, cancel: bool) {
        use iroha_allocation::{
            AllocationRefusal, AllocationReservation, release::ReleaseRegistration,
        };
        use std::{
            cell::{Cell, RefCell},
            future::Future,
            rc::Rc,
            task::{Context, Poll},
        };
        let _retirement_pin = crossbeam_epoch::pin();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit_at(20_000, Vec::new());
        let receipt = chain.committed(2);
        let hash = receipt.block_hash();
        let result = receipt.result();
        drop(receipt);
        let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
        let mut cursor = NativeFinalityCursorV1::new();
        assert!(
            cursor
                .advance_current(&chain.state().view(), &budget, deadline(), one())
                .unwrap()
                .is_none()
        );
        let preceding = cursor
            .original
            .as_ref()
            .unwrap()
            .checkpoint
            .as_ref()
            .unwrap()
            .as_slice()
            .to_vec();
        let mut prepaid = budget
            .try_reserve_bytes(ReleaseRegistration::allocation_layout().size())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let pressure = Rc::new(RefCell::new(None::<AllocationReservation>));
        let pointers = Rc::new(RefCell::new(Vec::<(usize, usize)>::new()));
        let demand = Rc::new(Cell::new(0));
        let original_pressure = Rc::clone(&pressure);
        let original_pointers = Rc::clone(&pointers);
        let original_demand = Rc::clone(&demand);
        let original_budget = budget.clone();
        let mut first = true;
        PENDING_PROBE.with_borrow_mut(|probe| {
            assert!(probe.is_none());
            *probe = Some(Box::new(
                move |at, height, bytes, first_pointer, second_pointer| {
                    if at != stage || height != 2 {
                        return;
                    }
                    original_pointers
                        .borrow_mut()
                        .push((first_pointer, second_pointer));
                    if first {
                        first = false;
                        original_demand.set(bytes);
                        *original_pressure.borrow_mut() = Some(
                            original_budget
                                .try_reserve_bytes(
                                    original_budget.limit_bytes()
                                        - original_budget.reserved_bytes(),
                                )
                                .unwrap(),
                        );
                    }
                },
            ));
        });
        PENDING_REFUSAL.with_borrow_mut(|cause| *cause = None);
        let _probe = PendingProbeGuard;
        let error = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .err()
            .expect("real pending admission refuses");
        let cause = PENDING_REFUSAL
            .with_borrow_mut(Option::take)
            .expect("observe the original admission, not a resampled release");
        let AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        } = &cause
        else {
            panic!("the actual pending preparation must refuse with Capacity");
        };
        assert_eq!(*requested_bytes, demand.get());
        assert_eq!(*reserved_bytes, budget.limit_bytes());
        assert_eq!(*limit_bytes, budget.limit_bytes());
        let mut wait = Box::pin(release.clone().wait_for_release(&mut registration));
        let mut poll = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            wait.as_mut().poll(&mut poll),
            Poll::Pending,
            "pending proof/checkpoint preparation must keep earlier original allocations instead of self-waking"
        );
        let Error::Proof(ProofError::Deferred(deferred)) = error else {
            panic!("preserve the original typed refusal");
        };
        assert_eq!(deferred.allocation_refusal(), Some(&cause));
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert_eq!(cursor.original.as_ref().unwrap().native_height, 2);
        assert!(matches!(
            cursor.original.as_ref().unwrap().pending,
            Some(Pending::Successor(_))
        ));
        assert_eq!(
            cursor
                .original
                .as_ref()
                .unwrap()
                .checkpoint
                .as_ref()
                .unwrap()
                .as_slice(),
            preceding
        );
        let Err(Error::Proof(ProofError::Deferred(repeated))) =
            cursor.advance_current(&chain.state().view(), &budget, deadline(), one())
        else {
            panic!("retry the exact original pending preparation");
        };
        assert_eq!(repeated.allocation_refusal(), Some(&cause));
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
        assert_eq!(pointers.borrow().len(), 2);
        assert_eq!(
            pointers.borrow()[0],
            pointers.borrow()[1],
            "retry lends the original allocated graph"
        );
        if cancel {
            drop(cursor);
            assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
            drop(wait);
            drop(pressure.borrow_mut().take());
            assert_eq!(
                budget.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
            drop(registration);
            assert_eq!(budget.reserved_bytes(), 0);
            return;
        }
        drop(pressure.borrow_mut().take());
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
        drop(wait);
        let current = cursor
            .advance_current(&chain.state().view(), &budget, deadline(), one())
            .unwrap()
            .unwrap();
        assert_eq!(current.block().height(), 2);
        assert_eq!(current.block().block().hash(), hash);
        assert_eq!(current.native_block().block_hash(), hash);
        assert_eq!(current.block().result(), result);
        assert_eq!(current.native_block().result(), result);
        assert!(cursor.original.as_ref().unwrap().pending.is_none());
        assert_eq!(pointers.borrow().len(), 3);
        assert!(
            pointers
                .borrow()
                .iter()
                .all(|pointer| *pointer == pointers.borrow()[0])
        );
        drop(cursor);
        assert_eq!(current.native_block().result(), result);
        drop(current);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn native_cursor_pending_last_key_refusal_retains_original_graph_and_release() {
        native_cursor_pending_refusal(PendingStage::Key, false);
        native_cursor_pending_refusal(PendingStage::Key, true);
    }
    #[test]
    fn native_cursor_pending_envelope_refusal_retains_original_graph_and_release() {
        native_cursor_pending_refusal(PendingStage::Envelope, false);
        native_cursor_pending_refusal(PendingStage::Envelope, true);
    }
    #[test]
    fn native_cursor_pending_checkpoint_refusal_retains_original_graph_and_release() {
        native_cursor_pending_refusal(PendingStage::Checkpoint, false);
        native_cursor_pending_refusal(PendingStage::Checkpoint, true);
    }
}
