//! Original-pool signer output retained beside the authenticated parent-service attempt.
//!
//! The native relation authenticates the offered QC before preparation and every lend.
//! This owner only retains its exact source, paid destination and unfinished allocation;
//! it grants no signature, quorum or committee authority of its own.

use super::*;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocatorRefusal, ChargedBuffer,
    ChargedBufferFromChargeError, ChargedShared, ReservedChargedShared, SharedFromChargeError,
};
use iroha_crypto::{ChargedPublicKey, PublicKeyAllocationError};
use iroha_data_model::sumeragi::epoch::MAX_VALIDATORS;
use iroha_model_base::peer::PeerId;
use std::alloc::Layout;

type Keys = ChargedBuffer<ChargedPublicKey>;

/// Immutable selected keys; cloning retains the same root, array and compact key allocations.
#[derive(Clone)]
pub(super) struct RetainedSigners(ChargedShared<Keys>);

impl RetainedSigners {
    pub(super) fn contains(&self, peer: &PeerId) -> bool {
        self.0
            .as_slice()
            .iter()
            .any(|key| key.get() == peer.public_key())
    }

    #[cfg(test)]
    pub(super) fn keys(&self) -> impl Iterator<Item = &iroha_crypto::PublicKey> {
        self.0.as_slice().iter().map(ChargedPublicKey::get)
    }
}

struct Original {
    source: ChargedShared<ChargedBuffer<u8>>,
    pool: AllocationBudget,
    kura: Arc<crate::kura::Kura>,
    tip: crate::state::NativeExecutionTip,
    proposal: HashOf<IrohaHeader>,
    predecessor: (HashOf<IrohaHeader>, Hash32, Hash32),
    current: (HashOf<IrohaHeader>, Hash32, Hash32),
    indices: [usize; MAX_VALIDATORS],
    count: usize,
}

fn coordinates(block: &CommittedBlock) -> (HashOf<IrohaHeader>, Hash32, Hash32) {
    (block.block_hash(), block.core_hash(), block.result())
}

impl Original {
    fn capture(
        view: &(impl StateReadOnly + ?Sized),
        proposal: &SignedBlock,
        predecessor: &CommittedBlock,
        current: &CommittedBlock,
        qc: &Qc,
    ) -> Result<Self, ParentServiceError> {
        let pool = view.execution_budget();
        let source = proposal
            .npos_consensus_effects()
            .and_then(|effects| effects.parent_service_commit_qc.as_ref())
            .and_then(|offered| offered.admitted_source())
            .filter(|source| source.belongs_to(&pool) && ChargedBuffer::belongs_to(source, &pool))
            .ok_or_else(|| parent_source_failure("signer output has no original admitted QC"))?;
        let tip = view.native_execution_tip().ok_or_else(|| {
            parent_source_failure("signer output has no original native execution cut")
        })?;
        let mut indices = [0; MAX_VALIDATORS];
        let mut count = 0;
        for index in qc.signers.ones() {
            let index = usize::try_from(index)
                .ok()
                .filter(|index| {
                    current
                        .commitment()
                        .schedule
                        .current
                        .committee
                        .get(*index)
                        .is_some()
                })
                .ok_or_else(|| {
                    ParentServiceError::Invalid("service signer outside committee".into())
                })?;
            if count == MAX_VALIDATORS {
                return Err(ParentServiceError::Invalid(
                    "service signer count exceeds native bound".into(),
                ));
            }
            indices[count] = index;
            count += 1;
        }
        Ok(Self {
            source: source.clone(),
            pool,
            kura: view.kura_handle(),
            tip,
            proposal: proposal.hash(),
            predecessor: coordinates(predecessor),
            current: coordinates(current),
            indices,
            count,
        })
    }

    fn require(
        &self,
        view: &(impl StateReadOnly + ?Sized),
        proposal: &SignedBlock,
        predecessor: &CommittedBlock,
        current: &CommittedBlock,
        qc: &Qc,
    ) -> Result<(), ParentServiceError> {
        if cfg!(all(test, sumeragi_core_mutation = "HC466")) {
            return Ok(());
        }
        let pool = view.execution_budget();
        let offered = proposal
            .npos_consensus_effects()
            .and_then(|effects| effects.parent_service_commit_qc.as_ref())
            .and_then(|offered| offered.admitted_source());
        if !offered.is_some_and(|offered| ChargedShared::ptr_eq(offered, &self.source))
            || !self.pool.same_pool(&pool)
            || !self.source.belongs_to(&pool)
            || !ChargedBuffer::belongs_to(&self.source, &pool)
            || !std::ptr::eq(self.kura.as_ref(), view.kura())
            || view.native_execution_tip() != Some(self.tip)
            || self.proposal != proposal.hash()
            || self.predecessor != coordinates(predecessor)
            || self.current != coordinates(current)
            || !qc
                .signers
                .ones()
                .map(|index| index as usize)
                .eq(self.indices[..self.count].iter().copied())
        {
            return Err(parent_source_failure(
                "signer output replaced its original QC, cut, proposal, order or pool",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Construction {
    keys: Option<Keys>,
    shell: Option<ReservedChargedShared<Keys>>,
    array_charge: Option<AllocationCharge>,
    root_charge: Option<AllocationCharge>,
    key_charge: Option<AllocationCharge>,
}

fn charge(pool: &AllocationBudget, layout: Layout) -> Result<AllocationCharge, ParentServiceError> {
    let mut reserved = pool
        .try_reserve(layout)
        .map_err(|original| ParentServiceError::Deferred(original.into()))?;
    Ok(reserved
        .try_split(layout)
        .expect("exact original signer allocation layout"))
}

fn buffer_error(original: ChargedBufferFromChargeError) -> ParentServiceError {
    match original {
        original @ ChargedBufferFromChargeError::Allocator { .. } => ParentServiceError::Deferred(
            AllocatorRefusal::try_from(original)
                .expect("original signer allocator refusal")
                .into(),
        ),
        invariant => parent_source_failure(invariant),
    }
}

impl Construction {
    fn prepare(
        &mut self,
        original: &Original,
        current: &CommittedBlock,
    ) -> Result<(), ParentServiceError> {
        let pool = &original.pool;
        if self.keys.is_none() {
            if self.array_charge.is_none() {
                self.array_charge = Some(charge(
                    pool,
                    Layout::array::<ChargedPublicKey>(original.count)
                        .expect("bounded authenticated signer array"),
                )?);
            }
            if self.root_charge.is_none() {
                self.root_charge = Some(charge(pool, ChargedShared::<Keys>::allocation_layout())?);
            }
            match Keys::try_from_charge(
                original.count,
                self.array_charge
                    .take()
                    .expect("original signer array charge"),
            ) {
                Ok(keys) => self.keys = Some(keys),
                Err((charge, error)) => {
                    self.array_charge = Some(charge);
                    return Err(buffer_error(error));
                }
            }
        }
        if self.shell.is_none() {
            match ChargedShared::<Keys>::reserve_from_charge(
                self.root_charge
                    .take()
                    .expect("original signer root charge"),
            ) {
                Ok(shell) => self.shell = Some(shell),
                Err((charge, error)) => {
                    self.root_charge = Some(charge);
                    return Err(match error {
                        original @ SharedFromChargeError::Allocator { .. } => {
                            ParentServiceError::Deferred(
                                AllocatorRefusal::try_from(original)
                                    .expect("original signer root refusal")
                                    .into(),
                            )
                        }
                        invariant => parent_source_failure(invariant),
                    });
                }
            }
        }
        let keys = self.keys.as_mut().expect("original signer array");
        let committee = &current.commitment().schedule.current.committee;
        for index in &original.indices[keys.as_slice().len()..original.count] {
            let key = committee[*index].validator.public_key();
            if self.key_charge.is_none() {
                self.key_charge = Some(charge(pool, key.retained_allocation_layout())?);
            }
            match key.try_clone_from_charge(
                pool,
                self.key_charge.take().expect("original compact key charge"),
            ) {
                Ok(key) => keys.push_reserved(key),
                Err((charge, error)) => {
                    self.key_charge = Some(charge);
                    return Err(match error {
                        PublicKeyAllocationError::Allocation(original) => buffer_error(original),
                        invariant => parent_source_failure(invariant),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Fixed original selection and the exact unfinished destination survive caller retries.
#[derive(Default)]
pub(super) struct ParentServiceSignersPreparation {
    original: Option<Original>,
    construction: Option<Construction>,
    complete: Option<RetainedSigners>,
}

impl ParentServiceSignersPreparation {
    #[cfg(test)]
    pub(super) fn retained_pointers(&self) -> (usize, usize, usize) {
        let keys = self.complete.as_ref().map(|owner| &*owner.0).or_else(|| {
            self.construction
                .as_ref()
                .and_then(|pending| pending.keys.as_ref())
        });
        (
            self.original
                .as_ref()
                .map_or(0, |original| original.source.as_slice().as_ptr().addr()),
            keys.map_or(0, |keys| keys.as_slice().as_ptr().addr()),
            keys.and_then(|keys| keys.as_slice().first())
                .map_or(0, |key| {
                    key.get().borrowed_parts().unwrap().1.as_ptr().addr()
                }),
        )
    }

    /// Called only after the sole native quorum/authority/boundary verifier succeeds.
    pub(super) fn prepare(
        &mut self,
        view: &(impl StateReadOnly + ?Sized),
        proposal: &SignedBlock,
        predecessor: &CommittedBlock,
        current: &CommittedBlock,
        qc: &Qc,
    ) -> Result<(), ParentServiceError> {
        if self.original.is_none() {
            self.original = Some(Original::capture(view, proposal, predecessor, current, qc)?);
        }
        let original = self.original.as_ref().expect("original signer source");
        original.require(view, proposal, predecessor, current, qc)?;
        if self.complete.is_some() {
            return Ok(());
        }
        // Store the owner before the first admission or physical allocation. Every
        // child is prepaid before copying, and later refusals retain the completed prefix.
        let construction = self.construction.get_or_insert_with(Construction::default);
        #[cfg(test)]
        admission_probe(
            &original.pool,
            Layout::array::<ChargedPublicKey>(original.count)
                .expect("bounded signer probe array")
                .size()
                + ChargedShared::<Keys>::allocation_layout().size()
                + original.indices[..original.count]
                    .first()
                    .map_or(0, |index| {
                        current.commitment().schedule.current.committee[*index]
                            .validator
                            .public_key()
                            .retained_allocation_layout()
                            .size()
                    }),
        );
        let prepared = construction.prepare(original, current);
        #[cfg(all(test, sumeragi_core_mutation = "HC465"))]
        if prepared.is_err() {
            self.construction = None;
        }
        prepared?;
        let construction = self
            .construction
            .as_mut()
            .expect("retained signer construction");
        self.complete = Some(RetainedSigners(
            construction
                .shell
                .take()
                .expect("original signer shell")
                .initialize(
                    construction
                        .keys
                        .take()
                        .expect("complete original signer keys"),
                ),
        ));
        Ok(())
    }

    /// Lend only after the caller reauthenticates the original native relation.
    pub(super) fn get(
        &self,
        view: &(impl StateReadOnly + ?Sized),
        proposal: &SignedBlock,
        predecessor: &CommittedBlock,
        current: &CommittedBlock,
        qc: &Qc,
    ) -> Result<RetainedSigners, ParentServiceError> {
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| parent_source_failure("original signer preparation absent"))?;
        original.require(view, proposal, predecessor, current, qc)?;
        let complete = self
            .complete
            .as_ref()
            .ok_or_else(|| parent_source_failure("original signer preparation incomplete"))?;
        let pool = &original.pool;
        let committee = &current.commitment().schedule.current.committee;
        if !complete.0.belongs_to(pool)
            || !ChargedBuffer::belongs_to(&complete.0, pool)
            || complete.0.as_slice().len() != original.count
            || complete
                .0
                .as_slice()
                .iter()
                .zip(&original.indices[..original.count])
                .any(|(key, index)| {
                    !key.belongs_to(pool)
                        || committee
                            .get(*index)
                            .is_none_or(|member| key.get() != member.validator.public_key())
                })
        {
            return Err(parent_source_failure(
                "original signer graph differs from authenticated selection",
            ));
        }
        Ok(complete.clone())
    }
}

#[cfg(test)]
thread_local! {
    static ADMISSION_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce(&AllocationBudget, usize)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
/// Remove an unconsumed test observation without changing production admission.
pub(crate) struct ParentServiceSignersAdmissionProbe;
#[cfg(test)]
impl Drop for ParentServiceSignersAdmissionProbe {
    fn drop(&mut self) {
        ADMISSION_PROBE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
/// Observe real signer admission; the callback may occupy actual original-pool capacity.
pub(crate) fn observe_parent_service_signers_admission(
    callback: impl FnOnce(&AllocationBudget, usize) + 'static,
) -> ParentServiceSignersAdmissionProbe {
    ADMISSION_PROBE.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "one original signer admission observer"
        );
        *slot.borrow_mut() = Some(Box::new(callback));
    });
    ParentServiceSignersAdmissionProbe
}
#[cfg(test)]
fn admission_probe(pool: &AllocationBudget, first_prefix_bytes: usize) {
    let probe = ADMISSION_PROBE.with(|slot| slot.borrow_mut().take());
    if let Some(probe) = probe {
        probe(pool, first_prefix_bytes);
    }
}

#[cfg(test)]
mod tests;
