//! Immutable PoP credentials and pairing scratch retained by one original caller pool.
//!
//! This owns cryptographic admission, not epoch, committee geometry, signed-genesis,
//! source, certificate or freshness authority. The enclosing native reader must retain
//! its independently authenticated source and fund every other allocation it creates.

use std::alloc::Layout;

use parking_lot::Mutex;

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    InsufficientReservation, PrepaidBufferError,
};
use iroha_crypto::{PublicKeyAllocationError, PublicKeyEnvelopeError, SignatureVerificationError};
use iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1;

use super::*;

/// Original typed local refusal or original key/PoP rejection; never an authority verdict.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommitteeAdmissionError {
    /// The complete physical graph did not fit its original finite pool.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The offered reservation belongs to another pool.
    #[error("committee reservation belongs to another original pool")]
    ForeignPool,
    /// A caller's complete reservation does not contain the declared demand.
    #[error(transparent)]
    Reservation(#[from] InsufficientReservation),
    /// A prepaid buffer could not be materialized.
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    /// The exact original compact-key layout could not be materialized.
    #[error(transparent)]
    KeyAllocation(#[from] PublicKeyAllocationError),
    /// Compact key inspection failed before the PoP relation.
    #[error("committee member {index} has a malformed key envelope: {error:?}")]
    Envelope {
        /// Position in the original immutable source.
        index: usize,
        /// Original fixed envelope error, without formatting or payload cloning.
        error: PublicKeyEnvelopeError,
    },
    /// Native consensus only admits BLS-normal keys.
    #[error("committee member {index} uses {algorithm}, not BLS-normal")]
    Algorithm {
        /// Position in the original immutable source.
        index: usize,
        /// Original key's algorithm.
        algorithm: Algorithm,
    },
    /// The original member's exact proof failed the shared uncached PoP relation.
    #[error("committee member {index} has an invalid proof of possession: {error:?}")]
    Proof {
        /// Position in the original immutable source.
        index: usize,
        /// Original unformatted cryptographic rejection.
        error: SignatureVerificationError,
    },
}

/// One exact compact allocation, always destroyed before its original credit.
struct PendingKey {
    key: IrohaPublicKey,
    charge: AllocationCharge,
}
impl PendingKey {
    fn verify(self, proof: &[u8], index: usize) -> Result<Credential, CommitteeAdmissionError> {
        let Self { key, charge } = self;
        // The moved key is owned inside this uncached, allocation-free relation.
        // It is destroyed there if unwinding occurs, before the caller's charge.
        match BlsNormalPopVerifiedKey::from_owned_uncached(key, proof) {
            Ok(verified) => Ok(Credential { verified, charge }),
            Err((key, error)) => {
                drop(key);
                drop(charge);
                Err(CommitteeAdmissionError::Proof { index, error })
            }
        }
    }
}
struct Credential {
    // Declaration order is physical custody: free compact bytes, then refund.
    verified: BlsNormalPopVerifiedKey,
    charge: AllocationCharge,
}

/// A fixed admitted credential graph with reusable pairing backing in the same pool.
///
/// No mutable admission, clone, detached credential or allocation extraction escapes.
/// Lookup and verification borrow the exact original graph without any new allocation.
/// The outer placement/control shell is the enclosing reader's separate obligation.
/// This owner does not retain or pay for the source epoch or the generic core committee.
///
/// The native successor reader supplies its original source pool and borrows the
/// authenticated parent epoch. This pays only the owned credentials and pairing
/// context; source/body decoding and other verifier scratch remain separate owners.
/// This owner alone must not enable the HTTP proof routes.
pub(crate) struct FundedBlsCommittee {
    credentials: ChargedBuffer<Credential>,
    scratch: Mutex<ConsensusAggregateScratch<AllocationCharge>>,
}

fn pairing_layout() -> Result<Layout, AllocationRefusal> {
    // The shared crypto API reports the exact u64-array backing of blst::Pairing.
    Layout::from_size_align(
        ConsensusAggregateScratch::<()>::backing_bytes(),
        std::mem::align_of::<u64>(),
    )
    .map_err(|_| AllocationRefusal::DemandOverflow)
}

impl FundedBlsCommittee {
    /// Sum actual credential-array, compact-key and pairing layouts without allocating.
    /// This measures source storage; it confers no committee validity or authority.
    pub(crate) fn allocation_demand(
        members: &[ValidatorCommitteeMemberV1],
    ) -> Result<usize, AllocationRefusal> {
        let backing = Layout::array::<Credential>(members.len())
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let bytes = backing
            .size()
            .checked_add(pairing_layout()?.size())
            .ok_or(AllocationRefusal::DemandOverflow)?;
        members.iter().try_fold(bytes, |sum, member| {
            sum.checked_add(
                member
                    .validator
                    .public_key()
                    .retained_allocation_layout()
                    .size(),
            )
            .ok_or(AllocationRefusal::DemandOverflow)
        })
    }

    /// Admit the whole graph once before constructing any owned key or pairing backing.
    /// Capacity refusal returns the original pool observation without partial allocations.
    #[cfg(test)]
    pub(crate) fn admit(
        members: &[ValidatorCommitteeMemberV1],
        budget: &AllocationBudget,
    ) -> Result<Self, CommitteeAdmissionError> {
        let demand = Self::allocation_demand(members)?;
        let mut original = budget.try_reserve_bytes(demand)?;
        Self::from_reservation(members, budget, &mut original)
    }

    /// Consume exactly this graph's share of an enclosing original reservation.
    ///
    /// This never reacquires capacity or replaces the pool. A foreign/short parent is
    /// refused before splitting. A key/allocator refusal drops all constructed storage
    /// before returning its credits. Unused parent remainder stays with the caller.
    /// Existing `ConsensusAggregateScratch` has an infallible physical allocation;
    /// its process-abort OOM behavior is not upgraded into a recoverable refusal here.
    #[allow(
        unsafe_code,
        reason = "exact compact key and charge move immediately into a private drop-ordered owner"
    )]
    pub(crate) fn from_reservation(
        members: &[ValidatorCommitteeMemberV1],
        budget: &AllocationBudget,
        parent: &mut AllocationReservation,
    ) -> Result<Self, CommitteeAdmissionError> {
        if !parent.belongs_to(budget) {
            return Err(CommitteeAdmissionError::ForeignPool);
        }
        let mut original = parent.try_partition_bytes(Self::allocation_demand(members)?)?;
        let pairing = pairing_layout()?;
        let scratch = ConsensusAggregateScratch::new(|bytes| {
            debug_assert_eq!(bytes, pairing.size());
            original.try_split(pairing)
        })?;
        let mut credentials = ChargedBuffer::from_reservation(members.len(), &mut original)?;
        for (index, member) in members.iter().enumerate() {
            let key = member.validator.public_key();
            let (algorithm, _) = key
                .borrowed_parts()
                .map_err(|error| CommitteeAdmissionError::Envelope { index, error })?;
            if algorithm != Algorithm::BlsNormal {
                return Err(CommitteeAdmissionError::Algorithm { index, algorithm });
            }
            let charge = original.try_split(key.retained_allocation_layout())?;
            let owned = key
                .try_clone_from_charge(budget, charge)
                .map_err(|(charge, error)| {
                    drop(charge);
                    CommitteeAdmissionError::KeyAllocation(error)
                })?;
            // SAFETY: no fallible/panicking work separates extraction from the private
            // owner. Its compact key always drops before this unchanged original charge.
            let (key, charge) = unsafe { owned.into_allocation_parts() };
            let pending = PendingKey { key, charge };
            #[cfg(test)]
            construction_checkpoint(Checkpoint::Key(index));
            let credential = pending.verify(&member.proof_of_possession, index)?;
            // The immutable source length equals exact capacity; this cannot grow.
            credentials.push_reserved(credential);
            #[cfg(test)]
            construction_checkpoint(Checkpoint::Credential(index));
        }
        debug_assert_eq!(original.remaining_bytes(), 0);
        #[cfg(test)]
        construction_checkpoint(Checkpoint::Complete);
        Ok(Self {
            credentials,
            scratch: Mutex::new(scratch),
        })
    }

    /// Observe original pool identity without acquiring capacity or copying any key.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        // All fields were split from the same checked reservation above.
        self.credentials.belongs_to(budget)
            && self
                .credentials
                .as_slice()
                .iter()
                .all(|key| key.charge.belongs_to(budget))
    }

    #[cfg(test)]
    pub(crate) fn admitted_len(&self) -> usize {
        self.credentials.as_slice().len()
    }

    fn lookup(&self, key: &PublicKey) -> Option<&BlsNormalPopVerifiedKey> {
        self.credentials
            .as_slice()
            .iter()
            .find(|credential| credential.verified.payload() == key.as_bytes())
            .map(|credential| &credential.verified)
    }

    /// Use exactly the node owner's shared admission checks and aggregate relation.
    pub(crate) fn verify_aggregate(
        &self,
        keys: &[&PublicKey],
        message: &[u8],
        aggregate: &AggregateSignature,
    ) -> bool {
        let Some(digest) = ConsensusDigest::from_preimage(message) else {
            return false;
        };
        let lookup = |key: &PublicKey| self.lookup(key);
        let Some(input) = AggregateInput::prepare(keys, digest, lookup) else {
            return false;
        };
        input.verify(&mut self.scratch.lock(), lookup, aggregate)
    }

    /// Use exactly the node owner's shared grouped admission and signature relation.
    pub(crate) fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        aggregate: &AggregateSignature,
    ) -> bool {
        let lookup = |key: &PublicKey| self.lookup(key);
        let Some(input) = AggregateGroups::prepare(groups, lookup) else {
            return false;
        };
        input.verify(&mut self.scratch.lock(), lookup, aggregate)
    }
}

impl Crypto for FundedBlsCommittee {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        Hash32(Hash::new_from_chunks(chunks).into())
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        verify_individual(pk, msg, sig)
    }

    fn aggregate(&self, signatures: &[Signature]) -> Result<AggregateSignature, AggregationError> {
        aggregate_signatures(signatures)
    }

    fn verify_aggregate(
        &self,
        keys: &[&PublicKey],
        message: &[u8],
        aggregate: &AggregateSignature,
    ) -> bool {
        FundedBlsCommittee::verify_aggregate(self, keys, message, aggregate)
    }

    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        aggregate: &AggregateSignature,
    ) -> bool {
        FundedBlsCommittee::verify_aggregate_multi(self, groups, aggregate)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checkpoint {
    Key(usize),
    Credential(usize),
    Complete,
}
#[cfg(test)]
thread_local! {
    static UNWIND_AT: std::cell::Cell<Option<Checkpoint>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn construction_checkpoint(checkpoint: Checkpoint) {
    if UNWIND_AT.with(|selected| selected.get() == Some(checkpoint)) {
        UNWIND_AT.with(|selected| selected.set(None));
        panic!("controlled funded committee construction unwind at {checkpoint:?}");
    }
}

#[cfg(test)]
mod tests;
