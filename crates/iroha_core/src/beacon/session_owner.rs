//! Exact original-pool construction of the sole canonical public session graph.
//!
//! The materializer owns actual nested buffers, compact keys and signature bytes.
//! The validated submodule admits its complete graph, verifier scratch and shared
//! control from one original reservation, then shares the immutable authenticated
//! owner with runtime lifecycle rows. The DKG child owns mutable rows and public
//! phase output backing; raw input decoding and final credential/transport buffers
//! retain separate explicit physical-ownership obligations.

use std::alloc::Layout;

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    InsufficientReservation, PrepaidBufferError, RetainedPayload, RetainedPayloadError,
};
use iroha_crypto::{PublicKey, PublicKeyAllocationError, Signature, SignatureAllocationError};
use iroha_data_model::consensus::{
    GlobalThresholdBeaconDkgDealerCommitmentV1, GlobalThresholdBeaconDkgEncryptedShareV1,
    GlobalThresholdBeaconDkgRecipientKeyV1, GlobalThresholdBeaconDkgShareAcceptanceV1,
    GlobalThresholdBeaconDkgTranscriptV1, GlobalThresholdBeaconKeySessionV1,
    GlobalThresholdBeaconPublicShareV1,
};
use iroha_model_base::peer::PeerId;

/// The standard writer facade over the original fixed byte backing.
/// Each write uses the canonical bounded append kernel and cannot grow or replace it.
pub(in crate::beacon) struct ChargedBytesWriter<'a>(
    pub(in crate::beacon) &'a mut ChargedBuffer<u8>,
);
impl std::io::Write for ChargedBytesWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Concrete original source or physical construction failure; never an authentication result.
#[derive(Debug, thiserror::Error)]
pub(super) enum SessionGraphError {
    /// Original finite admission is retained without formatting or source substitution.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Fixed backing or its exact prepaid partition could not be constructed.
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    /// A checked construction layout exceeded its unchanged original remainder.
    #[error(transparent)]
    Reservation(#[from] InsufficientReservation),
    /// Canonical compact-key backing refused its exact original charge.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyAllocationError),
    /// Canonical signature backing refused its exact original charge.
    #[error(transparent)]
    Signature(#[from] SignatureAllocationError),
    /// A sealed original payload/ledger source invariant failed.
    #[error(transparent)]
    Retention(#[from] RetainedPayloadError),
    /// A workspace encoder failed without authenticating its input.
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    /// A prepaid shared-control allocation could not be constructed.
    #[error(transparent)]
    Shared(#[from] iroha_allocation::PrepaidSharedError),
    /// A complete checked demand and materialization disagreed.
    #[error("canonical beacon session allocation plan changed")]
    PlanChanged,
}

#[derive(Default)]
pub(in crate::beacon) struct Demand {
    bytes: usize,
    charges: usize,
}
impl Demand {
    fn add(&mut self, layout: Layout) -> Result<(), SessionGraphError> {
        self.bytes = self
            .bytes
            .checked_add(layout.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        self.charges = self
            .charges
            .checked_add(1)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(())
    }
    fn array<T>(&mut self, count: usize) -> Result<(), SessionGraphError> {
        self.add(Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)?)
    }
    fn for_session(record: &GlobalThresholdBeaconKeySessionV1) -> Result<Self, SessionGraphError> {
        let mut demand = Self::default();
        let dkg = &record.adaptive_dkg;
        demand.array::<GlobalThresholdBeaconPublicShareV1>(record.public_shares.len())?;
        demand.array::<GlobalThresholdBeaconDkgDealerCommitmentV1>(dkg.dealer_commitments.len())?;
        for dealer in &dkg.dealer_commitments {
            demand.array::<[u8; 96]>(dealer.coefficient_commitments.len())?;
            demand.add(dealer.signature.retained_allocation_layout())?;
        }
        demand.array::<GlobalThresholdBeaconDkgRecipientKeyV1>(dkg.recipient_keys.len())?;
        for recipient in &dkg.recipient_keys {
            demand.add(
                recipient
                    .validator
                    .public_key()
                    .retained_allocation_layout(),
            )?;
            demand.array::<u8>(recipient.mlkem768_public_key.len())?;
            demand.add(recipient.signature.retained_allocation_layout())?;
        }
        demand.array::<GlobalThresholdBeaconDkgEncryptedShareV1>(dkg.encrypted_shares.len())?;
        for edge in &dkg.encrypted_shares {
            demand.array::<u8>(edge.mlkem768_ciphertext.len())?;
            demand.array::<u8>(edge.encrypted_share.len())?;
            demand.add(edge.signature.retained_allocation_layout())?;
        }
        demand.array::<GlobalThresholdBeaconDkgShareAcceptanceV1>(dkg.share_acceptances.len())?;
        for acceptance in &dkg.share_acceptances {
            demand.add(acceptance.signature.retained_allocation_layout())?;
        }
        demand.array::<u16>(dkg.qualified_dealers.len())?;
        Ok(demand)
    }
    fn total_bytes(&self) -> Result<usize, SessionGraphError> {
        let ledger = Layout::array::<AllocationCharge>(self.charges)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        self.bytes
            .checked_add(ledger.size())
            .ok_or(AllocationRefusal::DemandOverflow.into())
    }
}

// Declared before every constructed payload local so their actual allocations
// retire before the ledger on normal refusal. Like the existing schedule owner,
// uncertain partial destruction during unwind conservatively retains its credits.
pub(in crate::beacon) struct Construction<'a, 'r> {
    budget: &'a AllocationBudget,
    reservation: &'r mut AllocationReservation,
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Construction<'_, '_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(charges) = self.charges.take() {
                std::mem::forget(charges);
            }
        }
    }
}
impl<'a, 'r> Construction<'a, 'r> {
    fn new(
        source: &GlobalThresholdBeaconKeySessionV1,
        budget: &'a AllocationBudget,
        reservation: &'r mut AllocationReservation,
    ) -> Result<Self, SessionGraphError> {
        Self::with_demand(Demand::for_session(source)?, budget, reservation)
    }
    fn with_demand(
        demand: Demand,
        budget: &'a AllocationBudget,
        reservation: &'r mut AllocationReservation,
    ) -> Result<Self, SessionGraphError> {
        if !reservation.belongs_to(budget) {
            return Err(RetainedPayloadError::ForeignLedger.into());
        }
        let charges = ChargedBuffer::from_reservation(demand.charges, reservation)?;
        Ok(Self {
            budget,
            reservation,
            charges: Some(charges),
        })
    }
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), SessionGraphError> {
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("original construction ledger")
            .try_push(charge)
        {
            // The payload is already alive. Never turn an internal plan defect
            // into released capacity for an allocation not yet destroyed.
            std::mem::forget(charge);
            return Err(SessionGraphError::PlanChanged);
        }
        Ok(())
    }
    fn buffer<T>(&mut self, count: usize) -> Result<ChargedBuffer<T>, SessionGraphError> {
        Ok(ChargedBuffer::from_reservation(
            count,
            &mut self.reservation,
        )?)
    }
    #[allow(unsafe_code)]
    fn vector<T>(&mut self, values: ChargedBuffer<T>) -> Result<Vec<T>, SessionGraphError> {
        // SAFETY: exact backing moves into an immutable canonical field, with
        // every nested allocation separately retained in this same ledger.
        // No field can grow, mutate or escape the final RetainedPayload owner.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        self.retain(charge)?;
        Ok(values)
    }
    fn copied<T: Copy>(&mut self, source: &[T]) -> Result<Vec<T>, SessionGraphError> {
        let mut values = self.buffer(source.len())?;
        for value in source {
            values.push_reserved(*value);
        }
        self.vector(values)
    }
    #[allow(unsafe_code)]
    fn key(&mut self, source: &PublicKey) -> Result<PublicKey, SessionGraphError> {
        let charge = self
            .reservation
            .try_split(source.retained_allocation_layout())?;
        let owned = match source.try_clone_from_charge(self.budget, charge) {
            Ok(owned) => owned,
            Err((charge, error)) => {
                drop(charge);
                return Err(error.into());
            }
        };
        // SAFETY: exact immutable compact bytes move directly to a canonical
        // recipient field; this original charge outlives that field allocation.
        let (key, charge) = unsafe { owned.into_allocation_parts() };
        self.retain(charge)?;
        Ok(key)
    }
    #[allow(unsafe_code)]
    fn signature(&mut self, source: &Signature) -> Result<Signature, SessionGraphError> {
        let charge = self
            .reservation
            .try_split(source.retained_allocation_layout())?;
        let owned = match source.try_clone_from_charge(self.budget, charge) {
            Ok(owned) => owned,
            Err((charge, error)) => {
                drop(charge);
                return Err(error.into());
            }
        };
        // SAFETY: transfer the same canonical payload without ordinary Clone,
        // mutation or export. Its charge stays in the complete original ledger.
        let (signature, charge) = unsafe { owned.into_allocation_parts() };
        self.retain(charge)?;
        Ok(signature)
    }
    fn dealer(
        &mut self,
        source: &GlobalThresholdBeaconDkgDealerCommitmentV1,
    ) -> Result<GlobalThresholdBeaconDkgDealerCommitmentV1, SessionGraphError> {
        Ok(GlobalThresholdBeaconDkgDealerCommitmentV1 {
            dealer_index: source.dealer_index,
            coefficient_commitments: self.copied(&source.coefficient_commitments)?,
            constant_term_proof: source.constant_term_proof,
            signature: self.signature(&source.signature)?,
        })
    }
    fn recipient(
        &mut self,
        source: &GlobalThresholdBeaconDkgRecipientKeyV1,
    ) -> Result<GlobalThresholdBeaconDkgRecipientKeyV1, SessionGraphError> {
        Ok(GlobalThresholdBeaconDkgRecipientKeyV1 {
            recipient_index: source.recipient_index,
            validator: PeerId::new(self.key(source.validator.public_key())?),
            x25519_public_key: source.x25519_public_key,
            mlkem768_public_key: self.copied(&source.mlkem768_public_key)?,
            signature: self.signature(&source.signature)?,
        })
    }
    fn edge(
        &mut self,
        source: &GlobalThresholdBeaconDkgEncryptedShareV1,
    ) -> Result<GlobalThresholdBeaconDkgEncryptedShareV1, SessionGraphError> {
        Ok(GlobalThresholdBeaconDkgEncryptedShareV1 {
            dealer_index: source.dealer_index,
            recipient_index: source.recipient_index,
            dealer_commitment_hash: source.dealer_commitment_hash,
            recipient_key_hash: source.recipient_key_hash,
            delivery_height: source.delivery_height,
            ephemeral_x25519_public_key: source.ephemeral_x25519_public_key,
            mlkem768_ciphertext: self.copied(&source.mlkem768_ciphertext)?,
            encrypted_share: self.copied(&source.encrypted_share)?,
            signature: self.signature(&source.signature)?,
        })
    }
    fn acceptance(
        &mut self,
        source: &GlobalThresholdBeaconDkgShareAcceptanceV1,
    ) -> Result<GlobalThresholdBeaconDkgShareAcceptanceV1, SessionGraphError> {
        Ok(GlobalThresholdBeaconDkgShareAcceptanceV1 {
            dealer_index: source.dealer_index,
            recipient_index: source.recipient_index,
            dealer_commitment_hash: source.dealer_commitment_hash,
            encrypted_share_hash: source.encrypted_share_hash,
            accepted_height: source.accepted_height,
            signature: self.signature(&source.signature)?,
        })
    }
    #[expect(
        single_use_lifetimes,
        reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
    )]
    fn dealers<'s>(
        &mut self,
        source: impl ExactSizeIterator<Item = &'s GlobalThresholdBeaconDkgDealerCommitmentV1>,
    ) -> Result<Vec<GlobalThresholdBeaconDkgDealerCommitmentV1>, SessionGraphError> {
        let mut output = self.buffer(source.len())?;
        for source in source {
            output.push_reserved(self.dealer(source)?);
        }
        self.vector(output)
    }
    #[expect(
        single_use_lifetimes,
        reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
    )]
    fn recipients<'s>(
        &mut self,
        source: impl ExactSizeIterator<Item = &'s GlobalThresholdBeaconDkgRecipientKeyV1>,
    ) -> Result<Vec<GlobalThresholdBeaconDkgRecipientKeyV1>, SessionGraphError> {
        let mut output = self.buffer(source.len())?;
        for source in source {
            output.push_reserved(self.recipient(source)?);
        }
        self.vector(output)
    }
    #[expect(
        single_use_lifetimes,
        reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
    )]
    fn edges<'s>(
        &mut self,
        source: impl ExactSizeIterator<Item = &'s GlobalThresholdBeaconDkgEncryptedShareV1>,
    ) -> Result<Vec<GlobalThresholdBeaconDkgEncryptedShareV1>, SessionGraphError> {
        let mut output = self.buffer(source.len())?;
        for source in source {
            output.push_reserved(self.edge(source)?);
        }
        self.vector(output)
    }
    #[expect(
        single_use_lifetimes,
        reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
    )]
    fn acceptances<'s>(
        &mut self,
        source: impl ExactSizeIterator<Item = &'s GlobalThresholdBeaconDkgShareAcceptanceV1>,
    ) -> Result<Vec<GlobalThresholdBeaconDkgShareAcceptanceV1>, SessionGraphError> {
        let mut output = self.buffer(source.len())?;
        for source in source {
            output.push_reserved(self.acceptance(source)?);
        }
        self.vector(output)
    }
    #[allow(unsafe_code)]
    fn finish<T>(&mut self, payload: T) -> Result<RetainedPayload<T>, SessionGraphError> {
        let charges = self
            .charges
            .take()
            .expect("complete original construction ledger");
        if charges.as_slice().len() != charges.capacity() {
            drop(payload);
            drop(charges);
            return Err(SessionGraphError::PlanChanged);
        }
        // SAFETY: callers construct only the audited canonical fields through this
        // exact materializer. Their nested storage moves unchanged with every
        // original charge; the returned owner permits borrowing only.
        match unsafe { RetainedPayload::try_new(payload, charges, self.budget) } {
            Ok(owner) => Ok(owner),
            Err((payload, charges, error)) => {
                drop(payload);
                drop(charges);
                Err(error.into())
            }
        }
    }
}

/// Retain one complete canonical graph after preadmitting every destination allocation.
/// This copies only original bytes; the result does not claim semantic validity.
///
#[cfg(test)]
pub(super) fn retain_canonical_session(
    source: &GlobalThresholdBeaconKeySessionV1,
    budget: &AllocationBudget,
) -> Result<RetainedPayload<GlobalThresholdBeaconKeySessionV1>, SessionGraphError> {
    let mut reservation = budget.try_reserve_bytes(Demand::for_session(source)?.total_bytes()?)?;
    retain_prepaid_session(source, budget, &mut reservation)
}

/// Consume only the graph's exact part of the original aggregate session reservation.
#[allow(unsafe_code)]
fn retain_prepaid_session(
    source: &GlobalThresholdBeaconKeySessionV1,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<RetainedPayload<GlobalThresholdBeaconKeySessionV1>, SessionGraphError> {
    let remainder = reservation
        .remaining_bytes()
        .checked_sub(Demand::for_session(source)?.total_bytes()?)
        .ok_or(SessionGraphError::PlanChanged)?;
    let mut construction = Construction::new(source, budget, reservation)?;
    let public_shares = construction.copied(&source.public_shares)?;
    let source_dkg = &source.adaptive_dkg;
    let dealer_commitments = construction.dealers(source_dkg.dealer_commitments.iter())?;
    let recipient_keys = construction.recipients(source_dkg.recipient_keys.iter())?;
    let encrypted_shares = construction.edges(source_dkg.encrypted_shares.iter())?;
    let share_acceptances = construction.acceptances(source_dkg.share_acceptances.iter())?;
    let qualified_dealers = construction.copied(&source_dkg.qualified_dealers)?;
    let adaptive_dkg = GlobalThresholdBeaconDkgTranscriptV1 {
        session: source_dkg.session,
        generator_h: source_dkg.generator_h,
        generator_v: source_dkg.generator_v,
        dealer_commitments,
        recipient_keys,
        encrypted_shares,
        share_acceptances,
        qualified_dealers,
        event_hash: source_dkg.event_hash,
        finalized_at_height: source_dkg.finalized_at_height,
    };
    let record = GlobalThresholdBeaconKeySessionV1 {
        version: source.version,
        network_id: source.network_id,
        session_id: source.session_id,
        roster_hash: source.roster_hash,
        committee_size: source.committee_size,
        threshold: source.threshold,
        group_public_key: source.group_public_key,
        public_shares,
        adaptive_dkg,
        dkg_contribution_hash: source.dkg_contribution_hash,
        transcript_hash: source.transcript_hash,
    };
    if construction.reservation.remaining_bytes() != remainder {
        return Err(SessionGraphError::PlanChanged);
    }
    construction.finish(record)
}

mod dkg;
pub(in crate::beacon) use dkg::{
    DkgMessageWorkspace, DkgRows, PendingRow, retain_finalized_dkg, validate_dkg_acceptance_bounds,
    validate_dkg_dealer_bounds, validate_dkg_edge_bounds, validate_dkg_recipient_bounds,
};
pub use dkg::{
    RetainedGlobalThresholdBeaconDkgFinalizationV1, RetainedGlobalThresholdBeaconDkgSnapshotV1,
};
mod prepared_input;
pub use prepared_input::{
    GlobalThresholdBeaconInputDestinationErrorV1, GlobalThresholdBeaconInputErrorV1,
    PreparedGlobalThresholdBeaconDkgInputsV1, PreparedGlobalThresholdBeaconDkgPublicationV1,
    PreparedGlobalThresholdBeaconFinalSessionInputV1,
};
mod lifecycle;
mod validated;
pub use lifecycle::RetainedFinalizedGlobalThresholdBeaconSessionV1;
pub(super) use lifecycle::validate_lifecycle;
pub(super) use validated::verify_borrowed_session;
pub use validated::{
    GlobalThresholdBeaconSessionError, PreparedGlobalThresholdBeaconSessionVerificationV1,
    ValidatedGlobalThresholdBeaconSessionV1,
};

#[cfg(test)]
mod tests;
