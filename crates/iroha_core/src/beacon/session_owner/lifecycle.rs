//! Canonical World lifecycle rows retain the original validated graph across generations.

use super::validated::{
    GlobalThresholdBeaconSessionError, ValidatedGlobalThresholdBeaconSessionV1,
};
use crate::beacon::{
    FinalizedGlobalThresholdBeaconKeySessionRecordV1, GlobalThresholdBeaconError,
    GlobalThresholdBeaconSessionBindingV1,
};
use iroha_allocation::AllocationBudget;
use norito::{NoritoSerialize, core::SerializePayload, derive::JsonSerialize};

/// The sole runtime lifecycle owner of a completely authenticated public beacon graph.
///
/// Signed input and snapshots use the canonical finalized-record DTO. A runtime row
/// is created only by explicit validation and original-pool admission; ordinary
/// decoding cannot install one. Clones share the same validated graph and control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedFinalizedGlobalThresholdBeaconSessionV1 {
    /// Immutable, completely verified public session and original allocation owner.
    pub session: ValidatedGlobalThresholdBeaconSessionV1,
    /// Committed activation height, if this frozen transcript has been installed.
    pub activated_at_height: Option<u64>,
    /// Committed retirement height, retaining all prior pulse evidence obligations.
    pub retired_at_height: Option<u64>,
}
impl RetainedFinalizedGlobalThresholdBeaconSessionV1 {
    /// Authenticate and admit a canonical signed or restored lifecycle record.
    /// Every fallible graph/control operation completes before callers install the row.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid session transcript, binding, or lifecycle,
    /// or if the original pool cannot admit or allocate its retained graph.
    pub fn admit(
        source: &FinalizedGlobalThresholdBeaconKeySessionRecordV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        let binding = GlobalThresholdBeaconSessionBindingV1 {
            network_id: source.session.network_id,
            session_id: source.session.session_id,
            roster_hash: source.session.roster_hash,
            transcript_hash: source.session.transcript_hash,
        };
        let session =
            ValidatedGlobalThresholdBeaconSessionV1::admit(&source.session, &binding, budget)?;
        let record = Self {
            session,
            activated_at_height: source.activated_at_height,
            retired_at_height: source.retired_at_height,
        };
        record.validate()?;
        Ok(record)
    }
    /// Recheck only mutable lifecycle ordering; immutable transcript authenticity is sealed.
    ///
    /// # Errors
    ///
    /// Returns an error if activation precedes DKG finalization, retirement lacks
    /// activation, or retirement is not strictly after activation.
    pub fn validate(&self) -> Result<(), GlobalThresholdBeaconError> {
        validate_lifecycle(
            self.session.adaptive_dkg.finalized_at_height,
            self.activated_at_height,
            self.retired_at_height,
        )
    }
    /// Activate at the exact committed height without cloning or revalidating public proofs.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid existing lifecycle, a retired key, a
    /// height before finalization, or a conflicting prior activation height.
    pub fn activate(&mut self, height: u64) -> Result<(), GlobalThresholdBeaconError> {
        self.validate()?;
        if self.retired_at_height.is_some()
            || height < self.session.adaptive_dkg.finalized_at_height
        {
            return Err(GlobalThresholdBeaconError::InvalidKeyLifecycle);
        }
        match self.activated_at_height {
            Some(existing) if existing != height => {
                Err(GlobalThresholdBeaconError::InvalidKeyLifecycle)
            }
            Some(_) => Ok(()),
            None => {
                self.activated_at_height = Some(height);
                Ok(())
            }
        }
    }
    /// Retire at a strictly later committed height while retaining the identical graph owner.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or inactive lifecycle, a retirement at or
    /// before activation, or a conflicting prior retirement height.
    pub fn retire(&mut self, height: u64) -> Result<(), GlobalThresholdBeaconError> {
        self.validate()?;
        let activated = self
            .activated_at_height
            .ok_or(GlobalThresholdBeaconError::InvalidKeyLifecycle)?;
        if height <= activated {
            return Err(GlobalThresholdBeaconError::InvalidKeyLifecycle);
        }
        match self.retired_at_height {
            Some(existing) if existing != height => {
                Err(GlobalThresholdBeaconError::InvalidKeyLifecycle)
            }
            Some(_) => Ok(()),
            None => {
                self.retired_at_height = Some(height);
                Ok(())
            }
        }
    }
    /// Whether the original authenticated lifecycle authorizes signing at this height.
    pub fn is_active_at(&self, height: u64) -> bool {
        self.activated_at_height
            .is_some_and(|start| start <= height)
            && self.retired_at_height.is_none_or(|end| height < end)
    }
    fn borrowed(&self) -> BorrowedRecord<'_> {
        BorrowedRecord {
            session: norito::core::PayloadRef(self.session.record()),
            activated_at_height: self.activated_at_height,
            retired_at_height: self.retired_at_height,
        }
    }
}

pub(in crate::beacon) fn validate_lifecycle(
    finalized: u64,
    activated: Option<u64>,
    retired: Option<u64>,
) -> Result<(), GlobalThresholdBeaconError> {
    match (activated, retired) {
        (None, None) => Ok(()),
        (Some(active), None) if active >= finalized => Ok(()),
        (Some(active), Some(retired)) if active >= finalized && retired > active => Ok(()),
        _ => Err(GlobalThresholdBeaconError::InvalidKeyLifecycle),
    }
}

// A serialization-only borrowed projection preserves the sole signed DTO field order;
// it owns no buffers and provides neither decoding nor a second wire schema.
#[derive(NoritoSerialize, JsonSerialize)]
struct BorrowedRecord<'a> {
    session: norito::core::PayloadRef<
        'a,
        iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
    >,
    activated_at_height: Option<u64>,
    retired_at_height: Option<u64>,
}
impl norito::NoritoSchema for RetainedFinalizedGlobalThresholdBeaconSessionV1 {
    fn nominal_name() -> String {
        <FinalizedGlobalThresholdBeaconKeySessionRecordV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <FinalizedGlobalThresholdBeaconKeySessionRecordV1 as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedFinalizedGlobalThresholdBeaconSessionV1 {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.borrowed().serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.borrowed().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.borrowed().encoded_len_exact()
    }
}
impl norito::json::JsonSerialize for RetainedFinalizedGlobalThresholdBeaconSessionV1 {
    fn json_serialize(&self, out: &mut String) {
        self.borrowed().json_serialize(out)
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.borrowed().json_serialize_to(out)
    }
}

#[cfg(test)]
mod tests;
