//! Immutable funded runtime custody of the canonical schedule graph.
//!
//! Cell current/undo clones share the same original graph allocation. No normal decoder can
//! manufacture this owner: snapshot values remain canonical DTOs until explicit original-pool
//! admission. EBR generations and their publication controls are separate resource obligations.

use super::{ConsensusSchedule, ScheduleError};
use iroha_allocation::{
    AllocationBudget, AllocationReservation, ChargedShared, PrepaidSharedError, RetainedPayload,
};
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonSerialize},
};
use std::{alloc::Layout, fmt, ops::Deref};

/// The only heap-bearing World schedule owner. Empty pregenesis state has no allocation.
#[derive(Clone, Default)]
pub struct RetainedConsensusSchedule {
    owner: Option<ChargedShared<RetainedPayload<ConsensusSchedule>>>,
}
impl RetainedConsensusSchedule {
    /// Exact shell layout, distinct from every nested allocation in the canonical graph.
    pub(crate) fn shared_layout() -> Layout {
        ChargedShared::<RetainedPayload<ConsensusSchedule>>::allocation_layout()
    }
    /// Wrap the exact admitted graph without copying it or reacquiring pool capacity.
    pub(crate) fn from_retained(
        original: RetainedPayload<ConsensusSchedule>,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, (RetainedPayload<ConsensusSchedule>, PrepaidSharedError)> {
        ChargedShared::from_reservation(original, reservation)
            .map(|owner| Self { owner: Some(owner) })
    }
    /// Admit a genuinely separate World graph from the original configured execution pool.
    /// All deep allocations plus the shared shell are reserved before materialization.
    pub(crate) fn admit(
        source: &ConsensusSchedule,
        budget: &AllocationBudget,
    ) -> Result<Self, ScheduleError> {
        crate::sumeragi::epoch_election::retain_schedule(source, budget).map_err(Into::into)
    }
    /// Borrow the next configuration from this exact validated applied cut.
    ///
    /// Only `epoch_election::retain_slots` constructs a nonempty owner, after
    /// `ConsensusSchedule::from_owned_entries` validates the complete graph and
    /// its original proofs. Sharing cannot mutate that graph. Informational
    /// readers can use this invariant without repeating cryptographic validation;
    /// an absent owner, different applied cut, overflow or pending boundary has
    /// no next configuration. Decoded DTO admission still validates independently.
    pub(crate) fn ready_after_tip(&self, applied_height: u64) -> Option<&super::ScheduledConfig> {
        self.owner.as_ref()?;
        let canonical = self.canonical();
        if canonical.tip() != Some(applied_height) {
            return None;
        }
        canonical.ready(applied_height.checked_add(1)?).ok()
    }
    /// Read the canonical value; callers cannot mutate, extract or replace its allocations.
    pub(crate) fn canonical(&self) -> &ConsensusSchedule {
        static EMPTY: ConsensusSchedule = ConsensusSchedule::empty();
        self.owner.as_ref().map_or(&EMPTY, |owner| owner.get())
    }
}
impl Deref for RetainedConsensusSchedule {
    type Target = ConsensusSchedule;
    fn deref(&self) -> &Self::Target {
        self.canonical()
    }
}
impl fmt::Debug for RetainedConsensusSchedule {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.canonical().fmt(out)
    }
}
impl PartialEq for RetainedConsensusSchedule {
    fn eq(&self, other: &Self) -> bool {
        self.canonical() == other.canonical()
    }
}
impl Eq for RetainedConsensusSchedule {}
impl norito::NoritoSchema for RetainedConsensusSchedule {
    fn nominal_name() -> String {
        <ConsensusSchedule as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <ConsensusSchedule as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedConsensusSchedule {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.canonical().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.canonical().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.canonical().encoded_len_exact()
    }
}
impl JsonSerialize for RetainedConsensusSchedule {
    fn json_serialize(&self, out: &mut String) {
        self.canonical().json_serialize(out)
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.canonical().json_serialize_to(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::{World, WorldReadOnly as _},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    };
    #[test]
    fn informational_next_config_binds_validated_owner_to_exact_applied_height() {
        assert!(
            RetainedConsensusSchedule::default()
                .ready_after_tip(0)
                .is_none()
        );
        for mode in [
            SumeragiConsensusMode::Permissioned,
            SumeragiConsensusMode::Npos,
        ] {
            let mut config = TestChainConfig::new(World::new(), 1000);
            config.consensus_mode = mode;
            if mode == SumeragiConsensusMode::Npos {
                config.genesis_parameters.push(Parameter::Custom(
                    SumeragiNposParameters {
                        epoch_seed: [0x61; 32],
                        ..Default::default()
                    }
                    .into_custom_parameter(),
                ));
            }
            let chain = CertifiedTestChain::start(config).unwrap();
            let view = chain.state().view();
            let source = view.world().consensus_schedule();
            assert_eq!(source.ready_after_tip(1), Some(source.ready(2).unwrap()));
            assert!(source.ready_after_tip(0).is_none());
            assert!(source.ready_after_tip(2).is_none());
            assert!(source.ready_after_tip(u64::MAX).is_none());
            let copy = source.clone();
            drop(view);
            assert_eq!(copy.ready_after_tip(1).unwrap().height, 2);
        }
    }
    #[test]
    fn informational_next_config_refuses_an_authenticated_pending_boundary() {
        use crate::sumeragi::schedule::{ScheduledConfig, ScheduledSlot};
        let mut config = TestChainConfig::new(World::new(), 1000);
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config.genesis_parameters.push(Parameter::Custom(
            SumeragiNposParameters {
                epoch_seed: [0x62; 32],
                ..Default::default()
            }
            .into_custom_parameter(),
        ));
        let chain = CertifiedTestChain::start(config).unwrap();
        let view = chain.state().view();
        let original = view.world().consensus_schedule().ready(2).unwrap();
        let boundary = original.epoch.authorization.last_height;
        let predecessor = original.epoch.context_id().unwrap();
        let params = original.params;
        let schedule = ConsensusSchedule::from_owned_entries(vec![
            ScheduledSlot::Ready(ScheduledConfig {
                height: boundary,
                epoch: original.epoch.clone(),
                params,
            }),
            ScheduledSlot::PendingBoundary {
                height: boundary + 1,
                boundary_height: boundary,
                predecessor_context_id: predecessor,
                params,
            },
            ScheduledSlot::PendingBoundary {
                height: boundary + 2,
                boundary_height: boundary,
                predecessor_context_id: predecessor,
                params,
            },
        ])
        .unwrap();
        let retained =
            RetainedConsensusSchedule::admit(&schedule, &AllocationBudget::new(1024 * 1024))
                .unwrap();
        assert_eq!(retained.tip(), Some(boundary));
        assert!(retained.ready(boundary).is_ok());
        assert!(retained.ready_after_tip(boundary).is_none());
    }
}
