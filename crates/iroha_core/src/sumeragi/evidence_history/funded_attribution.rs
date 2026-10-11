//! Actual offender vector and compact-key custody through native evidence admission.
//!
//! Only the completed offender graph is funded here. TODO(S8): the earlier decoded
//! proof-decoder scratch and crypto caches/context need their own original owners.
//! The completed graph moves into the immutable World record body without cloning. Partial construction retires on refusal; it does not retain
//! completed per-key work across retry. The enclosing lane reader keeps its source.

use std::fmt;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, RetainedPayload};
use iroha_crypto::ChargedPublicKey;
use iroha_data_model::{
    block::consensus::{EvidenceAttribution, EvidenceOffender, EvidenceScope},
    sumeragi_lanes::SumeragiLaneStakeBinding,
};

use super::NativeEvidenceError;
use crate::state::EvidencePreparationError;

/// Scalar canonical fields; no source, backing or allocation authority is created here.
pub(super) struct AttributionFields {
    pub(super) scope: EvidenceScope,
    pub(super) instance: [u8; 32],
    pub(super) height: u64,
    pub(super) epoch: u64,
    pub(super) context_id: [u8; 32],
    pub(super) authority_generation: [u8; 32],
    pub(super) safety_violation: bool,
}

/// Immutable actual vector/key allocations; no extraction or growth can shed credit.
pub(super) struct FundedOffenders(RetainedPayload<Vec<EvidenceOffender>>);

impl FundedOffenders {
    /// Construct in original signer order; each callback validates/copies the key
    /// and resolves its original binding before vector allocation for the first row.
    #[allow(unsafe_code)]
    pub(super) fn collect(
        count: usize,
        mut signers: impl Iterator<Item = u32>,
        budget: &AllocationBudget,
        mut next: impl FnMut(
            u32,
            &AllocationBudget,
        ) -> Result<
            (ChargedPublicKey, Option<SumeragiLaneStakeBinding>),
            NativeEvidenceError,
        >,
    ) -> Result<Self, NativeEvidenceError> {
        #[cfg(all(test, sumeragi_core_mutation = "HC180"))]
        let replacement = AllocationBudget::new(budget.limit_bytes());
        #[cfg(all(test, sumeragi_core_mutation = "HC180"))]
        let budget = &replacement;

        let first = match signers.next() {
            Some(signer) => Some((signer, next(signer, budget)?)),
            None if count == 0 => None,
            None => return Err(EvidencePreparationError::Invariant.into()),
        };
        let ledger_count = if count == 0 {
            0
        } else {
            count.checked_add(1).ok_or_else(|| {
                NativeEvidenceError::Preparation(EvidencePreparationError::Admission(
                    iroha_allocation::AllocationRefusal::DemandOverflow,
                ))
            })?
        };
        // The ledger is declared first so partial values die before their charges.
        // The first ChargedPublicKey is independently guarded on either backing refusal.
        let mut charges =
            ChargedBuffer::new(ledger_count, budget).map_err(EvidencePreparationError::from)?;
        let mut values =
            ChargedBuffer::new(count, budget).map_err(EvidencePreparationError::from)?;
        if let Some((signer, (key, binding))) = first {
            Self::append(&mut values, &mut charges, budget, signer, key, binding)?;
        }
        for signer in signers {
            let (key, binding) = next(signer, budget)?;
            Self::append(&mut values, &mut charges, budget, signer, key, binding)?;
        }
        if values.as_slice().len() != count || charges.as_slice().len() != count {
            return Err(EvidencePreparationError::Invariant.into());
        }
        // SAFETY: these exact fixed allocations immediately enter one immutable
        // RetainedPayload. The vector cannot grow or escape, and all key charges
        // follow their actual compact boxes. Both raw moves are allocation-free.
        let (values, backing) = unsafe { values.into_allocation_parts() };
        if count != 0 {
            charges.push_reserved(backing);
        } else {
            // A zero-capacity vector owns no physical backing or nested payload.
            drop(backing);
        }
        match unsafe { RetainedPayload::try_new(values, charges, budget) } {
            Ok(owner) => Ok(Self(owner)),
            Err((values, charges, _)) => {
                drop(values);
                drop(charges);
                Err(EvidencePreparationError::Invariant.into())
            }
        }
    }

    #[allow(unsafe_code)]
    fn append(
        values: &mut ChargedBuffer<EvidenceOffender>,
        charges: &mut ChargedBuffer<AllocationCharge>,
        budget: &AllocationBudget,
        signer: u32,
        key: ChargedPublicKey,
        lane_stake: Option<SumeragiLaneStakeBinding>,
    ) -> Result<(), NativeEvidenceError> {
        if !key.belongs_to(budget)
            || values.as_slice().len() == values.capacity()
            || charges.as_slice().len() == charges.capacity()
        {
            return Err(EvidencePreparationError::Invariant.into());
        }
        // SAFETY: no fallible work follows extraction. The fixed slots proved
        // above hold the exact key and charge in the same enclosing owner. Values
        // always retire before the ledger on refusal, success and unwind.
        let (key, charge) = unsafe { key.into_allocation_parts() };
        charges.push_reserved(charge);
        values.push_reserved(EvidenceOffender {
            signer,
            peer_id: iroha_model_base::peer::PeerId::new(key),
            lane_stake,
        });
        Ok(())
    }

    pub(super) fn as_slice(&self) -> &[EvidenceOffender] {
        self.0.get()
    }

    #[allow(unsafe_code)]
    pub(super) fn into_attribution(self, fields: AttributionFields) -> FundedEvidenceAttribution {
        // SAFETY: the closed mapping only moves this exact vector into its canonical
        // field. Scalar metadata copies create no storage, replacement or escape.
        FundedEvidenceAttribution(unsafe {
            self.0.map_payload(|offenders| EvidenceAttribution {
                scope: fields.scope,
                instance: fields.instance,
                height: fields.height,
                epoch: fields.epoch,
                context_id: fields.context_id,
                authority_generation: fields.authority_generation,
                offenders,
                safety_violation: fields.safety_violation,
            })
        })
    }
}
impl fmt::Debug for FundedOffenders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(formatter)
    }
}

/// Move-only canonical attribution retaining every actual offender allocation.
/// Ordinary clones of get() are separate unfunded graphs, never this admission.
pub(crate) struct FundedEvidenceAttribution(RetainedPayload<EvidenceAttribution>);
impl FundedEvidenceAttribution {
    /// Move only the original fields into the private immutable record body.
    #[allow(unsafe_code)]
    pub(crate) fn into_record_fields(
        self,
        evidence: iroha_data_model::block::consensus::Evidence,
    ) -> RetainedPayload<crate::sumeragi::evidence::record::EvidenceRecordBodyFields> {
        // SAFETY: exact offender Vec/key allocations and ledger move without
        // replacement. The separately retained proof charge follows the extra
        // Evidence field in EvidenceRecordBody until these complete fields die.
        unsafe {
            self.0.map_payload(|attribution| {
                crate::sumeragi::evidence::record::EvidenceRecordBodyFields {
                    evidence,
                    attribution,
                }
            })
        }
    }

    /// Borrow the canonical value; mutation/extraction cannot shed its backing charges.
    pub(crate) fn get(&self) -> &EvidenceAttribution {
        self.0.get()
    }
    /// Exact original physical pool, independent of equal limits or value equality.
    pub(crate) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }
    /// Actual vector, nested compact boxes and physical charge ledger geometry.
    #[cfg(test)]
    pub(crate) fn allocation_bytes(&self) -> Option<usize> {
        self.0.allocation_bytes()
    }
}
impl std::ops::Deref for FundedEvidenceAttribution {
    type Target = EvidenceAttribution;
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}
impl fmt::Debug for FundedEvidenceAttribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

#[cfg(test)]
mod tests;

#[path = "funded_attribution/restore.rs"]
mod restore;
pub(crate) use restore::restore_attribution;
