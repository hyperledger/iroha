//! Immutable prefix authority: exact material, native configuration and pairing custody.

use super::*;
use iroha_allocation::ChargedShared;
use iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1;

/// Sharing keeps the complete original authority graph and every nested charge alive.
pub(crate) struct FundedPrefixAuthority {
    material: ValidatorEpochContextV1,
    graph: FundedAuthorityGraph,
    // Material is destroyed first, including its vector and both allocations per member.
    charges: MaterialCharges,
}

struct MaterialCharges {
    members: Option<AllocationCharge>,
    keys: [Option<AllocationCharge>; MAX_VALIDATORS],
    proofs: [Option<AllocationCharge>; MAX_VALIDATORS],
}
impl MaterialCharges {
    fn empty() -> Self {
        Self {
            members: None,
            keys: std::array::from_fn(|_| None),
            proofs: std::array::from_fn(|_| None),
        }
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.members
            .as_ref()
            .is_some_and(|charge| charge.belongs_to(budget))
            && self
                .keys
                .iter()
                .chain(&self.proofs)
                .flatten()
                .all(|charge| charge.belongs_to(budget))
    }
}

fn material_demand(source: &ValidatorEpochContextV1) -> Result<usize, AllocationRefusal> {
    if source.committee.len() > MAX_VALIDATORS {
        return Err(AllocationRefusal::DemandOverflow);
    }
    source.committee.iter().try_fold(
        Layout::array::<ValidatorCommitteeMemberV1>(source.committee.len())
            .map_err(|_| AllocationRefusal::DemandOverflow)?
            .size(),
        |bytes, member| {
            let proof = Layout::array::<u8>(member.proof_of_possession.len())
                .map_err(|_| AllocationRefusal::DemandOverflow)?;
            bytes
                .checked_add(
                    member
                        .validator
                        .public_key()
                        .retained_allocation_layout()
                        .size(),
                )
                .and_then(|bytes| bytes.checked_add(proof.size()))
                .ok_or(AllocationRefusal::DemandOverflow)
        },
    )
}

impl FundedPrefixAuthority {
    /// Exact retained authority demand for sibling admission and lifetime tests.
    #[cfg(test)]
    pub(in crate::sumeragi::certified_chain) fn allocation_bytes(
        source: &ValidatorEpochContextV1,
    ) -> Result<usize, AllocationRefusal> {
        Self::demand(source)
    }

    fn demand(source: &ValidatorEpochContextV1) -> Result<usize, AllocationRefusal> {
        material_demand(source)?
            .checked_add(config_demand(&source.committee)?)
            .and_then(|bytes| {
                bytes.checked_add(FundedBlsCommittee::allocation_demand(&source.committee).ok()?)
            })
            .and_then(|bytes| bytes.checked_add(ChargedShared::<Self>::allocation_layout().size()))
            .ok_or(AllocationRefusal::DemandOverflow)
    }

    pub(in crate::sumeragi::certified_chain) fn admit(
        scheduled: &schedule::ScheduledConfig,
        height: u64,
        validation: &mut EpochValidationScope,
        budget: &AllocationBudget,
    ) -> Result<ChargedShared<Self>, ExecutionAttemptError<ChainReadError>> {
        #[cfg(all(test, sumeragi_core_mutation = "HC958"))]
        let substituted_pool = AllocationBudget::new(budget.limit_bytes());
        #[cfg(all(test, sumeragi_core_mutation = "HC958"))]
        let budget = &substituted_pool;
        // The existing exact-context validator supplies the same canonical core values.
        // TODO(S8): shared validation error diagnostics still allocate Strings.
        // The exact validation cache stays inline; no cache clone is made here.
        let (epoch, params) = scheduled
            .core_parameters_with_validation(validation)
            .map_err(|error| ChainReadError::Committee {
                height,
                reason: error.to_string(),
            })?;
        iroha_sumeragi::pacemaker::validate_height_parts(
            &epoch,
            &params,
            schedule::CHAIN_TRANSPORT_FRAME_LIMIT,
        )
        .map_err(|error| ChainReadError::Committee {
            height,
            reason: error.to_string(),
        })?;
        let mut original = budget
            .try_reserve_bytes(
                Self::demand(&scheduled.epoch)
                    .map_err(|error| ExecutionAttemptError::Deferred(error.into()))?,
            )
            .map_err(|error| ExecutionAttemptError::Deferred(error.into()))?;
        let authority =
            Self::from_reservation(scheduled, epoch, params, height, budget, &mut original)?;
        debug_assert!(authority.belongs_to(budget) && Self::belongs_to(&authority, budget));
        debug_assert_eq!(original.remaining_bytes(), 0);
        Ok(authority)
    }

    fn from_reservation(
        scheduled: &schedule::ScheduledConfig,
        epoch: EpochConfig,
        params: ChainParams,
        height: u64,
        budget: &AllocationBudget,
        original: &mut AllocationReservation,
    ) -> Result<ChargedShared<Self>, ExecutionAttemptError<ChainReadError>> {
        // `admit` reserves from this same pool; the check keeps any later caller honest.
        if !original.belongs_to(budget) {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        let map = |error| match admission_error(height, error) {
            VerificationReadError::Deferred(original) => ExecutionAttemptError::Deferred(original),
            VerificationReadError::Source(original) => ExecutionAttemptError::Rejected(original),
        };
        let mut reservation = original
            .try_partition_bytes(
                Self::demand(&scheduled.epoch)
                    .map_err(|error| ExecutionAttemptError::Deferred(error.into()))?,
            )
            .map_err(|error| map(CommitteeAdmissionError::Reservation(error)))?;
        let (material, charges) =
            Self::copy_material(&scheduled.epoch, budget, &mut reservation).map_err(map)?;
        // Keep material before charges through every later allocation and unwind.
        struct PendingMaterial {
            material: ValidatorEpochContextV1,
            charges: MaterialCharges,
        }
        let pending = PendingMaterial { material, charges };
        let config =
            FundedHeightConfig::from_reservation(scheduled, epoch, params, &mut reservation)
                .map_err(map)?;
        let crypto = FundedBlsCommittee::from_reservation(
            &scheduled.epoch.committee,
            budget,
            &mut reservation,
        )
        .map_err(map)?;
        let value = Self {
            material: pending.material,
            graph: FundedAuthorityGraph { config, crypto },
            charges: pending.charges,
        };
        ChargedShared::from_reservation(value, &mut reservation).map_err(|(value, error)| {
            drop(value);
            ExecutionAttemptError::Deferred(retained_query_authority::shared_refusal(error))
        })
    }

    #[allow(
        unsafe_code,
        reason = "prepaid exact canonical vectors and keys move into a private immutable graph whose fields retire before its fixed charge ledger"
    )]
    fn copy_material(
        source: &ValidatorEpochContextV1,
        budget: &AllocationBudget,
        original: &mut AllocationReservation,
    ) -> Result<(ValidatorEpochContextV1, MaterialCharges), CommitteeAdmissionError> {
        material_demand(source)?;
        // Reverse local drop order: partial member values retire before their nested charges.
        let mut charges = MaterialCharges::empty();
        let mut members = ChargedBuffer::from_reservation(source.committee.len(), original)?;
        for (index, source) in source.committee.iter().enumerate() {
            let key = source.validator.public_key();
            let charge = original.try_split(key.retained_allocation_layout())?;
            let copy_key = || key.try_clone_from_charge(budget, charge);
            #[cfg(not(test))]
            let key = copy_key();
            #[cfg(test)]
            let key = material_allocation(
                MaterialAllocation::Key(index),
                key.retained_allocation_layout(),
                copy_key,
            );
            let key = key.map_err(|(charge, error)| {
                drop(charge);
                CommitteeAdmissionError::KeyAllocation(error)
            })?;
            #[cfg(not(test))]
            let mut proof =
                ChargedBuffer::from_reservation(source.proof_of_possession.len(), original)?;
            #[cfg(test)]
            let mut proof = material_allocation(
                MaterialAllocation::Proof(index),
                Layout::array::<u8>(source.proof_of_possession.len())
                    .expect("material demand already checked proof layout"),
                || ChargedBuffer::from_reservation(source.proof_of_possession.len(), original),
            )?;
            for byte in &source.proof_of_possession {
                proof.push_reserved(*byte);
            }
            // SAFETY: all remaining operations are allocation-free moves into proved spare
            // slots. The exact values die before charges on failure, success and unwinding.
            let (key, key_charge) = unsafe { key.into_allocation_parts() };
            let (proof, proof_charge) = unsafe { proof.into_allocation_parts() };
            charges.keys[index] = Some(key_charge);
            charges.proofs[index] = Some(proof_charge);
            members.push_reserved(ValidatorCommitteeMemberV1 {
                validator: iroha_model_base::peer::PeerId::new(key),
                proof_of_possession: proof,
            });
        }
        // SAFETY: the unchanged vector and all nested allocations immediately enter
        // the returned drop-ordered owner; no fallible work follows this extraction.
        let (committee, charge) = unsafe { members.into_allocation_parts() };
        charges.members = Some(charge);
        let ValidatorEpochContextV1 {
            version,
            network_id,
            mode,
            authorization,
            committee: _,
            leader_seed,
            da_layout,
        } = source;
        Ok((
            ValidatorEpochContextV1 {
                version: *version,
                network_id: *network_id,
                mode: *mode,
                authorization: *authorization,
                committee,
                leader_seed: *leader_seed,
                da_layout: *da_layout,
            },
            charges,
        ))
    }

    pub(in crate::sumeragi::certified_chain) fn projection(&self) -> AuthorityRef<'_> {
        self.graph.projection(&self.material)
    }
    pub(in crate::sumeragi::certified_chain) fn config(&self) -> &HeightConfig {
        self.graph.config()
    }
    pub(in crate::sumeragi::certified_chain) fn belongs_to(
        &self,
        budget: &AllocationBudget,
    ) -> bool {
        self.charges.belongs_to(budget)
            && self.graph.config.charges.belongs_to(budget)
            && self.graph.crypto.belongs_to(budget)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialAllocation {
    Key(usize),
    Proof(usize),
}

#[cfg(test)]
thread_local! {
    static REFUSE_MATERIAL_AT: std::cell::Cell<Option<MaterialAllocation>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn material_allocation<T>(
    stage: MaterialAllocation,
    layout: Layout,
    allocate: impl FnOnce() -> T,
) -> T {
    if REFUSE_MATERIAL_AT.with(|selected| selected.get() == Some(stage)) {
        REFUSE_MATERIAL_AT.with(|selected| selected.set(None));
        let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, allocate);
        assert!(
            refused,
            "selected original material allocation was attempted"
        );
        result
    } else {
        allocate()
    }
}

#[cfg(test)]
mod tests;
