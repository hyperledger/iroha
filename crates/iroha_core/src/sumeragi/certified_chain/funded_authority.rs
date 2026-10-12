//! One caller-funded native successor authority borrowing its original parent epoch.
//!
//! The captured parent owns the authenticated epoch. This owner creates exactly one
//! generic committee and epoch box, plus the admitted PoP credentials and aggregate
//! pairing context, from one complete reservation in the original source pool. The
//! shared native certificate, availability and boundary relations consume a borrowed
//! projection; there is no second verifier or independently reconstructed authority.
//! TODO: mandatory context validation, source/result decoding, QC/preimage/bitmap and
//! availability scratch still require their complete original physical owners. The
//! existing cumulative scratch admission is preserved; this tranche does not close
//! request-wide custody or enable an HTTP proof route.

use std::{alloc::Layout, mem::ManuallyDrop};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferError, ChargedBufferFromChargeError, PrepaidBufferError,
};
use iroha_crypto::PublicKeyAllocationError;
use iroha_data_model::sumeragi::epoch::MAX_VALIDATORS;
use iroha_sumeragi::types::{ChainParams, EpochConfig, HeightConfig, PublicKey};

use super::*;
use crate::sumeragi::crypto::funded::{CommitteeAdmissionError, FundedBlsCommittee};

/// The original epoch is borrowed; all newly owned authority graph allocations are prepaid.
pub(super) struct FundedExecutionAuthority<'a> {
    material: &'a ValidatorEpochContextV1,
    graph: FundedAuthorityGraph,
}

/// Owned authority backing can remain beside the original receipt without a self-reference.
/// Its borrowed view is constructed only inside the source-bound parent-service owner.
pub(super) struct FundedAuthorityGraph {
    config: FundedHeightConfig,
    crypto: FundedBlsCommittee,
}

struct ConfigCharges {
    keys: [Option<AllocationCharge>; MAX_VALIDATORS],
    array: Option<AllocationCharge>,
    epoch: Option<AllocationCharge>,
}
impl ConfigCharges {
    fn empty() -> Self {
        Self {
            keys: std::array::from_fn(|_| None),
            array: None,
            epoch: None,
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.keys
            .iter()
            .flatten()
            .all(|charge| charge.belongs_to(budget))
            && self
                .array
                .as_ref()
                .is_some_and(|charge| charge.belongs_to(budget))
            && self
                .epoch
                .as_ref()
                .is_some_and(|charge| charge.belongs_to(budget))
    }
}

// Declaration order is physical custody on success, rejection and unwinding.
struct FundedHeightConfig {
    value: HeightConfig,
    charges: ConfigCharges,
}
struct ConfigConstruction {
    epoch: Option<Box<EpochConfig>>,
    committee: Option<Committee>,
    keys: Option<ChargedBuffer<PublicKey>>,
    charges: ConfigCharges,
}

fn config_demand(
    members: &[iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1],
) -> Result<usize, AllocationRefusal> {
    // The native context validator enforces this bound for both root scopes before
    // admission. Keep the storage-side check as well, before indexing fixed charges.
    if members.len() > MAX_VALIDATORS {
        return Err(AllocationRefusal::DemandOverflow);
    }
    let array =
        Layout::array::<PublicKey>(members.len()).map_err(|_| AllocationRefusal::DemandOverflow)?;
    members.iter().try_fold(
        array
            .size()
            .checked_add(Layout::new::<EpochConfig>().size())
            .ok_or(AllocationRefusal::DemandOverflow)?,
        |sum, member| {
            let (_, key) = member
                .validator
                .public_key()
                .borrowed_parts()
                .map_err(|_| AllocationRefusal::DemandOverflow)?;
            sum.checked_add(key.len())
                .ok_or(AllocationRefusal::DemandOverflow)
        },
    )
}

impl FundedHeightConfig {
    #[allow(
        unsafe_code,
        reason = "exact prepaid Vec layouts move into canonical fields whose private owner drops the entire body before the original charges"
    )]
    fn from_reservation(
        scheduled: &schedule::ScheduledConfig,
        epoch: EpochConfig,
        params: ChainParams,
        original: &mut AllocationReservation,
    ) -> Result<Self, CommitteeAdmissionError> {
        config_demand(&scheduled.epoch.committee)?;
        let mut construction = ConfigConstruction {
            epoch: None,
            committee: None,
            keys: Some(ChargedBuffer::from_reservation(
                scheduled.epoch.committee.len(),
                original,
            )?),
            charges: ConfigCharges::empty(),
        };
        for (index, member) in scheduled.epoch.committee.iter().enumerate() {
            let (algorithm, payload) = member
                .validator
                .public_key()
                .borrowed_parts()
                .map_err(|error| CommitteeAdmissionError::Envelope { index, error })?;
            if algorithm != iroha_crypto::Algorithm::BlsNormal {
                return Err(CommitteeAdmissionError::Algorithm { index, algorithm });
            }
            let mut bytes = ChargedBuffer::<u8>::from_reservation(payload.len(), original)?;
            for byte in payload {
                bytes.push_reserved(*byte);
            }
            // SAFETY: the unchanged byte allocation immediately enters PublicKey,
            // and its charge is retained by the earlier construction owner. On an
            // error/panic PublicKey::new destroys its owned argument before that owner.
            let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
            construction.charges.keys[index] = Some(charge);
            let key = PublicKey::new(bytes).map_err(|_| {
                CommitteeAdmissionError::Admission(AllocationRefusal::DemandOverflow)
            })?;
            // The exact source count was admitted; no append can grow.
            construction
                .keys
                .as_mut()
                .expect("construction owns its original key array")
                .push_reserved(key);
            #[cfg(test)]
            checkpoint(ConstructionStage::Key(index));
        }
        // SAFETY: the canonical committee moves and sorts the same fixed key array
        // in place. All nested key charges and this array charge stay in construction.
        let (keys, charge) = unsafe {
            construction
                .keys
                .take()
                .expect("original key array")
                .into_allocation_parts()
        };
        construction.charges.array = Some(charge);
        construction.committee =
            Some(schedule::global_committee(keys).map_err(|_| {
                CommitteeAdmissionError::Admission(AllocationRefusal::DemandOverflow)
            })?);
        #[cfg(test)]
        checkpoint(ConstructionStage::Committee);
        let mut epoch_buffer = ChargedBuffer::from_reservation(1, original)?;
        epoch_buffer.push_reserved(epoch);
        // SAFETY: this has exactly one initialized EpochConfig and capacity one.
        // Box and Vec use the same global allocator and exact size/alignment here.
        // The original charge stays in construction; no operation between extraction,
        // ManuallyDrop and installing the Box can panic or allocate.
        let (epoch_values, charge) = unsafe { epoch_buffer.into_allocation_parts() };
        construction.charges.epoch = Some(charge);
        let mut epoch_values = ManuallyDrop::new(epoch_values);
        construction.epoch = Some(unsafe { Box::from_raw(epoch_values.as_mut_ptr()) });
        #[cfg(test)]
        checkpoint(ConstructionStage::Epoch);
        let ConfigConstruction {
            epoch,
            committee,
            keys,
            charges,
        } = construction;
        // All remaining moves are infallible; payload and ledger are never separated
        // by a checkpoint or another fallible constructor.
        match (epoch, committee) {
            (Some(epoch), Some(committee)) => Ok(Self {
                value: HeightConfig {
                    epoch,
                    committee,
                    params,
                },
                charges,
            }),
            (epoch, committee) => {
                drop(epoch);
                drop(committee);
                drop(keys);
                drop(charges);
                Err(CommitteeAdmissionError::Admission(
                    AllocationRefusal::DemandOverflow,
                ))
            }
        }
    }
}

impl<'a> FundedExecutionAuthority<'a> {
    pub(super) fn admit(
        scheduled: &'a schedule::ScheduledConfig,
        height: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, VerificationReadError> {
        let malformed = |error: schedule::ScheduleError| ChainReadError::Committee {
            height,
            reason: error.to_string(),
        };
        let mut validation = EpochValidationScope::new();
        // This is the original mandatory structural/context relation. Its existing
        // scratch work is not falsely counted as part of the later owned graph.
        let (epoch, params) = scheduled
            .core_parameters_with_validation(&mut validation)
            .map_err(malformed)?;
        iroha_sumeragi::pacemaker::validate_height_parts(
            &epoch,
            &params,
            schedule::CHAIN_TRANSPORT_FRAME_LIMIT,
        )
        .map_err(|error| malformed(schedule::ScheduleError::Params(error)))?;
        let demand = config_demand(&scheduled.epoch.committee)
            .and_then(|config| {
                FundedBlsCommittee::allocation_demand(&scheduled.epoch.committee).and_then(
                    |crypto| {
                        config
                            .checked_add(crypto)
                            .ok_or(AllocationRefusal::DemandOverflow)
                    },
                )
            })
            .map_err(|original| VerificationReadError::Deferred(original.into()))?;
        // No candidate graph exists on capacity refusal, so the returned release
        // observation cannot be invalidated by dropping our own partial admission.
        let mut original = budget
            .try_reserve_bytes(demand)
            .map_err(|original| VerificationReadError::Deferred(original.into()))?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC13")))]
        state_certificate::query_scratch_admission(
            iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_bytes(),
        )
        .map_err(VerificationReadError::Resource)?;
        let config = FundedHeightConfig::from_reservation(scheduled, epoch, params, &mut original)
            .map_err(|error| admission_error(height, error))?;
        let crypto =
            FundedBlsCommittee::from_reservation(&scheduled.epoch.committee, budget, &mut original)
                .map_err(|error| admission_error(height, error))?;
        debug_assert_eq!(original.remaining_bytes(), 0);
        debug_assert!(config.charges.belongs_to(budget) && crypto.belongs_to(budget));
        #[cfg(test)]
        checkpoint(ConstructionStage::Complete);
        Ok(Self {
            material: &scheduled.epoch,
            graph: FundedAuthorityGraph { config, crypto },
        })
    }

    pub(super) fn projection(&self) -> AuthorityRef<'_> {
        self.graph.projection(self.material)
    }
    pub(super) fn config(&self) -> &HeightConfig {
        self.graph.config()
    }
    pub(super) fn into_graph(self) -> FundedAuthorityGraph {
        self.graph
    }
    #[cfg(test)]
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.graph.config.charges.belongs_to(budget) && self.graph.crypto.belongs_to(budget)
    }
}
impl FundedAuthorityGraph {
    // Private source owner supplies only the exact epoch used for admission.
    pub(super) fn projection<'a>(
        &'a self,
        material: &'a ValidatorEpochContextV1,
    ) -> AuthorityRef<'a> {
        AuthorityRef {
            material,
            epoch: self.config.value.epoch.id,
            committee: &self.config.value.committee,
            crypto: &self.crypto,
        }
    }
    pub(super) fn config(&self) -> &HeightConfig {
        &self.config.value
    }
}

fn admission_error(height: u64, error: CommitteeAdmissionError) -> VerificationReadError {
    use CommitteeAdmissionError as E;
    let unavailable = || {
        VerificationReadError::Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
    };
    // A complete original reservation already succeeded. Wrong custody, an
    // undersized prepaid child, or a different key layout cannot be repaired by
    // waiting for pool capacity; the native worker must enter local recovery.
    let invariant = || {
        let reason = if cfg!(all(test, sumeragi_core_mutation = "HC249")) {
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        } else {
            ivm::error::ExecutionDeferral::LocalInvariantViolation
        };
        VerificationReadError::Deferred(reason.into())
    };
    match error {
        E::Admission(original) => VerificationReadError::Deferred(original.into()),
        E::Buffer(PrepaidBufferError::Allocation(ChargedBufferError::Admission(original))) => {
            VerificationReadError::Deferred(original.into())
        }
        E::Buffer(PrepaidBufferError::Allocation(ChargedBufferError::Allocator { .. }))
        | E::KeyAllocation(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::Allocator { .. },
        )) => unavailable(),
        E::ForeignPool
        | E::Reservation(_)
        | E::Buffer(PrepaidBufferError::Reservation(_))
        | E::KeyAllocation(PublicKeyAllocationError::ForeignPool)
        | E::KeyAllocation(PublicKeyAllocationError::Allocation(
            ChargedBufferFromChargeError::DemandOverflow
            | ChargedBufferFromChargeError::LayoutMismatch { .. },
        )) => invariant(),
        error @ (E::Envelope { .. } | E::Algorithm { .. } | E::Proof { .. }) => {
            VerificationReadError::Source(ChainReadError::Committee {
                height,
                reason: error.to_string(),
            })
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionStage {
    Key(usize),
    Committee,
    Epoch,
    Complete,
}
#[cfg(test)]
thread_local! {
    static UNWIND_AT: std::cell::Cell<Option<ConstructionStage>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn checkpoint(stage: ConstructionStage) {
    if UNWIND_AT.with(|point| point.get() == Some(stage)) {
        UNWIND_AT.with(|point| point.set(None));
        panic!("controlled native authority construction unwind at {stage:?}");
    }
}

#[cfg(test)]
mod tests;
