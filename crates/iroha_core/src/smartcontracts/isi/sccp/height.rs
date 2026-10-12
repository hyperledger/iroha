//! Authenticated native height inputs for the SCCP post-execution hook: the committee of a
//! height and, at an epoch boundary, the next one (`specs/sccp.md` §4.2.2, §4.6).
//!
//! The original output finalizer advances the World consensus schedule before SCCP reads it.
//! Each ready slot retains the exact epoch authorization and ordered committee. At an epoch
//! boundary, the next roster must also be authorized; a pending slot fails closed. Neither
//! registration state nor unauthenticated staged genesis writes can create voting authority.

use crate::{
    state::WorldReadOnly,
    sumeragi::schedule::{RetainedConsensusSchedule, ScheduledSlot},
};
use iroha_data_model::{
    block::consensus::MAX_VALIDATORS_PER_HEIGHT, parameter::system::ConsensusMode,
};
use iroha_model_base::peer::PeerId;

/// Consensus inputs of one height for the SCCP generation step (§4.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpHeightInputsV1<'a> {
    /// Consensus mode that selected the roster.
    pub mode: ConsensusMode,
    /// Executing height `h`.
    pub height: u64,
    /// Epoch of `h`.
    pub epoch: u64,
    /// Last height of the epoch of `h`; `h` is a boundary iff it equals `height`.
    pub epoch_end_height: u64,
    /// Voting roster of `h`, in canonical consensus order.
    pub roster: SccpRosterV1<'a>,
    /// Voting roster of the next epoch, present exactly at a boundary.
    pub next_roster: Option<SccpRosterV1<'a>>,
}

/// Borrowed ordered voters backed by the original immutable schedule. The protocol permits
/// at most 31 seats; this projection never allocates or clones a peer or its key graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SccpRosterV1<'a> {
    peers: [Option<&'a PeerId>; MAX_VALIDATORS_PER_HEIGHT],
    len: usize,
}

impl<'a> SccpRosterV1<'a> {
    /// Borrow peers in their original order; generation validation checks keys and geometry.
    ///
    /// # Errors
    /// Refuses a roster exceeding the protocol's 31-seat bound before writing that entry.
    pub(super) fn from_peers(
        peers: impl IntoIterator<Item = &'a PeerId>,
    ) -> Result<Self, SccpHeightInputsError> {
        let mut out = Self {
            peers: [None; MAX_VALIDATORS_PER_HEIGHT],
            len: 0,
        };
        for peer in peers {
            let slot = out
                .peers
                .get_mut(out.len)
                .ok_or(SccpHeightInputsError::RosterTooLarge)?;
            *slot = Some(peer);
            out.len += 1;
        }
        Ok(out)
    }

    /// Iterate the original peer references in canonical schedule order.
    pub fn iter(&self) -> impl Iterator<Item = &'a PeerId> + '_ {
        self.into_iter()
    }
}

impl<'roster, 'peers> IntoIterator for &'roster SccpRosterV1<'peers> {
    type Item = &'peers PeerId;
    type IntoIter =
        std::iter::Copied<std::iter::Flatten<std::slice::Iter<'roster, Option<&'peers PeerId>>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers[..self.len].iter().flatten().copied()
    }
}

/// Captured ownership of the exact original schedule across the mutable SCCP tail.
/// Cloning shares its already charged payload and control allocation; the last reader
/// retires their original charges. Outer World/EBR custody remains the schedule owner's
/// separate obligation. No replacement schedule or inferred authority can enter this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedSccpHeightInputsV1 {
    schedule: RetainedConsensusSchedule,
    // Deliberate native-test mutation only: an independent graph without original charges.
    #[cfg(test)]
    reconstructed: Option<crate::sumeragi::schedule::ConsensusSchedule>,
    mode: ConsensusMode,
    height: u64,
    genesis_height: u64,
}

/// Where block validation takes the SCCP height inputs of the block it executes.
#[derive(Debug, Clone, Copy)]
pub enum SccpHeightSourceV1 {
    /// A component execution without independently authenticated consensus authority.
    Unauthenticated,
    /// The lag-2 schedule of the Sumeragi core, read after the block advanced it.
    SumeragiSchedule {
        /// The chain's genesis height.
        genesis_height: u64,
        /// Consensus mode of the chain.
        mode: ConsensusMode,
        /// Immutable root scope selected by the independently authenticated signed genesis.
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    },
}

/// Why the Sumeragi schedule does not yield the inputs of a height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpHeightInputsError {
    /// The height precedes the genesis height.
    #[error("height {height} precedes the genesis height {genesis_height}")]
    BeforeGenesis {
        /// Executing height.
        height: u64,
        /// Genesis height.
        genesis_height: u64,
    },
    /// The stored schedule has no configuration for a needed height.
    #[error("the consensus schedule has no configuration for height {0}")]
    Unscheduled(u64),
    /// The scheduled epoch length is zero.
    #[error("the scheduled epoch length of height {0} is zero")]
    ZeroEpochLength(u64),
    /// A roster exceeds the protocol's maximum committee size.
    #[error("the scheduled roster exceeds 31 seats")]
    RosterTooLarge,
    /// A height does not fit `u64`.
    #[error("height arithmetic overflows")]
    Overflow,
}

impl RetainedSccpHeightInputsV1 {
    /// Build the inputs of `height` from the Sumeragi core's lag-2 schedule in `world`.
    ///
    /// `world` must hold the schedule after the block of `height` advanced it, which the SCCP
    /// hook sees because the schedule step precedes it in the output-seal finalizer.
    ///
    /// # Errors
    ///
    /// Fails when `height` precedes genesis, the schedule lacks `height` (or `height + 1` at a
    /// boundary), or a required epoch is still pending boundary authorization.
    pub fn from_sumeragi_schedule(
        world: &(impl WorldReadOnly + ?Sized),
        height: u64,
        genesis_height: u64,
        mode: ConsensusMode,
    ) -> Result<Self, SccpHeightInputsError> {
        let schedule = world.consensus_schedule().clone();
        #[cfg(test)]
        let reconstructed = if cfg!(all(test, sumeragi_core_mutation = "HC231")) {
            Some(schedule.canonical().clone())
        } else {
            None
        };
        #[cfg(test)]
        let schedule = if reconstructed.is_some() {
            // The mutant substitutes value equality for the captured allocation owner.
            drop(schedule);
            RetainedConsensusSchedule::default()
        } else {
            schedule
        };
        let original = Self {
            schedule,
            #[cfg(test)]
            reconstructed,
            mode,
            height,
            genesis_height,
        };
        original.inputs()?;
        Ok(original)
    }

    /// Project borrowed inputs from this same original graph, without allocation or rereading
    /// mutable World state. The owner must outlive the entire hook attempt.
    ///
    /// # Errors
    /// Preserves the same typed height/authorization failures checked at capture.
    pub fn inputs(&self) -> Result<SccpHeightInputsV1<'_>, SccpHeightInputsError> {
        let (mode, height, genesis_height) = (self.mode, self.height, self.genesis_height);
        let schedule = self.schedule.canonical();
        #[cfg(test)]
        let schedule = self.reconstructed.as_ref().unwrap_or(schedule);
        if height < genesis_height {
            return Err(SccpHeightInputsError::BeforeGenesis {
                height,
                genesis_height,
            });
        }
        // `ready` has precisely this slot lookup and tag check. Its pending branch builds
        // error text that this projection would discard; preserve its rejection allocation-free.
        // Complete authority/range validation already belongs to original retained admission.
        let Some(ScheduledSlot::Ready(current)) = schedule.get(height) else {
            return Err(SccpHeightInputsError::Unscheduled(height));
        };
        let epoch = current.epoch.authorization.epoch;
        let epoch_end_height = current.epoch.authorization.last_height;
        let next_roster = if height == epoch_end_height {
            let next_height = height
                .checked_add(1)
                .ok_or(SccpHeightInputsError::Overflow)?;
            let Some(ScheduledSlot::Ready(next)) = schedule.get(next_height) else {
                return Err(SccpHeightInputsError::Unscheduled(next_height));
            };
            Some(SccpRosterV1::from_peers(
                next.epoch.committee.iter().map(|member| &member.validator),
            )?)
        } else {
            None
        };
        Ok(SccpHeightInputsV1 {
            mode,
            height,
            epoch,
            epoch_end_height,
            roster: SccpRosterV1::from_peers(
                current
                    .epoch
                    .committee
                    .iter()
                    .map(|member| &member.validator),
            )?,
            next_roster,
        })
    }
}

impl SccpHeightInputsV1<'_> {
    /// Return whether the height is the last one of its epoch (an epoch boundary, §4.2.2).
    #[must_use]
    pub fn is_boundary(&self) -> bool {
        self.height == self.epoch_end_height
    }
}

/// Return `(epoch, epoch_end_height)` of `height` for fixed-length Sumeragi-core epochs of
/// `epoch_length` heights after the genesis height (`specs/sumeragi.md` §11.7). The genesis
/// block and the first `epoch_length` heights after it form epoch 0.
///
/// # Errors
///
/// Fails on a zero epoch length, a height below genesis or an unrepresentable epoch end.
pub fn sumeragi_epoch(
    height: u64,
    genesis_height: u64,
    epoch_length: u64,
) -> Result<(u64, u64), SccpHeightInputsError> {
    if epoch_length == 0 {
        return Err(SccpHeightInputsError::ZeroEpochLength(height));
    }
    if height < genesis_height {
        return Err(SccpHeightInputsError::BeforeGenesis {
            height,
            genesis_height,
        });
    }
    let first = genesis_height
        .checked_add(1)
        .ok_or(SccpHeightInputsError::Overflow)?;
    let epoch = height.saturating_sub(first) / epoch_length;
    let end = epoch
        .checked_add(1)
        .and_then(|epochs| epochs.checked_mul(epoch_length))
        .and_then(|offset| genesis_height.checked_add(offset))
        .ok_or(SccpHeightInputsError::Overflow)?;
    Ok((epoch, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::test_support::{blank_state, header},
        sumeragi::schedule::{ChainParamsRecord, ConsensusSchedule, ScheduledConfig},
    };

    #[test]
    fn sumeragi_epochs_start_after_genesis_and_have_fixed_length() {
        assert_eq!(sumeragi_epoch(1, 1, 4), Ok((0, 5)), "genesis is in epoch 0");
        assert_eq!(sumeragi_epoch(2, 1, 4), Ok((0, 5)));
        assert_eq!(
            sumeragi_epoch(5, 1, 4),
            Ok((0, 5)),
            "the boundary of epoch 0"
        );
        assert_eq!(sumeragi_epoch(6, 1, 4), Ok((1, 9)));
        assert_eq!(sumeragi_epoch(9, 1, 4), Ok((1, 9)));
        assert_eq!(sumeragi_epoch(2, 1, 1), Ok((0, 2)));
        assert_eq!(sumeragi_epoch(3, 1, 1), Ok((1, 3)));
        assert_eq!(
            sumeragi_epoch(3, 1, 0),
            Err(SccpHeightInputsError::ZeroEpochLength(3))
        );
        assert_eq!(
            sumeragi_epoch(0, 1, 4),
            Err(SccpHeightInputsError::BeforeGenesis {
                height: 0,
                genesis_height: 1
            })
        );
        assert_eq!(
            sumeragi_epoch(u64::MAX, 1, u64::MAX),
            Err(SccpHeightInputsError::Overflow)
        );
    }

    #[test]
    fn schedule_inputs_reject_an_unauthorized_successor_at_the_boundary() {
        use crate::sumeragi::schedule::{RetainedConsensusSchedule, ScheduledSlot};
        let state = blank_state();
        let signed = crate::sumeragi::epoch::tests::genesis_fixture(
            iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
            5,
            false,
        );
        let epoch = crate::sumeragi::epoch::authenticated_genesis(&signed)
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        let roster = epoch
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect::<Vec<_>>();
        let params = ChainParamsRecord::from_parameters(&Default::default());
        let graph = ConsensusSchedule::from_owned_entries(vec![
            ScheduledSlot::Ready(ScheduledConfig {
                height: 4,
                epoch: epoch.clone(),
                params,
            }),
            ScheduledSlot::Ready(ScheduledConfig {
                height: 5,
                epoch: epoch.clone(),
                params,
            }),
            ScheduledSlot::PendingBoundary {
                height: 6,
                boundary_height: 5,
                predecessor_context_id: epoch.context_id().unwrap(),
                params,
            },
        ])
        .unwrap();
        let retained =
            RetainedConsensusSchedule::admit(&graph, &state.ivm_execution_budget()).unwrap();
        let mut block = state.block(header(4));
        *block.world.consensus_schedule.get_mut() = retained;
        let inner = RetainedSccpHeightInputsV1::from_sumeragi_schedule(
            &block.world,
            4,
            1,
            ConsensusMode::Npos,
        )
        .unwrap();
        let inner = inner.inputs().unwrap();
        assert!(inner.roster.iter().eq(&roster));
        assert_eq!(inner.epoch, 0);
        assert_eq!(inner.epoch_end_height, 5);
        assert_eq!(inner.next_roster, None);
        assert!(!inner.is_boundary());
        let occupied = state.ivm_execution_budget().reserved_bytes();
        let allocations = crate::test_allocations::allocations_during(|| {
            assert_eq!(
                RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                    &block.world,
                    5,
                    1,
                    ConsensusMode::Npos
                ),
                Err(SccpHeightInputsError::Unscheduled(6)),
                "only a certified boundary installs successor authority"
            );
            assert_eq!(
                RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                    &block.world,
                    7,
                    1,
                    ConsensusMode::Npos
                ),
                Err(SccpHeightInputsError::Unscheduled(7))
            );
            assert_eq!(
                RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                    &block.world,
                    0,
                    1,
                    ConsensusMode::Npos
                ),
                Err(SccpHeightInputsError::BeforeGenesis {
                    height: 0,
                    genesis_height: 1
                })
            );
        });
        assert_eq!(
            allocations, 0,
            "pending authorization must not allocate a discarded error"
        );
        assert_eq!(state.ivm_execution_budget().reserved_bytes(), occupied);
    }
    fn authenticated_schedule() -> ConsensusSchedule {
        let signed = crate::sumeragi::epoch::tests::genesis_fixture(
            iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
            5,
            false,
        );
        let epoch = crate::sumeragi::epoch::authenticated_genesis(&signed)
            .unwrap()
            .into_parts()
            .0;
        let params = ChainParamsRecord::from_parameters(&Default::default());
        ConsensusSchedule::from_owned_entries(
            (1..=3)
                .map(|height| {
                    ScheduledSlot::Ready(ScheduledConfig {
                        height,
                        epoch: epoch.clone(),
                        params,
                    })
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn height_capture_preserves_original_graph_without_admission_at_full_pool() {
        use crate::{state::World, sumeragi::schedule::ScheduleError};
        use iroha_allocation::AllocationRefusal;
        let state = blank_state();
        let budget = state.ivm_execution_budget();
        // The empty parent's admitted SCCP fields and this schedule use the same
        // original pool. Keep those independent fields live throughout the graph
        // refund measurement; only the unpublished overlay owns the schedule.
        let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
        let baseline = budget.reserved_bytes();
        let graph = authenticated_schedule();
        let original = RetainedConsensusSchedule::admit(&graph, &budget).unwrap();
        let charged = budget.reserved_bytes();
        assert!(charged > baseline);
        let mut source_block = world.try_block(&budget).unwrap();
        *source_block.consensus_schedule.get_mut() = original;
        let view = &source_block;
        let source = view.consensus_schedule().ready(2).unwrap();
        let first_peer = std::ptr::from_ref(&source.epoch.committee[0].validator);
        let key_bytes = source.epoch.committee[0]
            .validator
            .public_key()
            .try_to_bytes()
            .unwrap()
            .1
            .as_ptr();
        let pop_bytes = source.epoch.committee[0].proof_of_possession.as_ptr();
        let entries = view.consensus_schedule().entries().as_ptr();
        let occupied = budget.reserved_bytes();
        let external = budget
            .try_reserve_bytes(budget.limit_bytes() - occupied)
            .unwrap();
        assert!(
            matches!(
                RetainedConsensusSchedule::admit(&graph, &budget),
                Err(ScheduleError::Admission(AllocationRefusal::Capacity { .. }))
            ),
            "an independent graph really cannot be admitted"
        );
        let mut captured = None;
        let allocations = crate::test_allocations::allocations_during(|| {
            let original =
                RetainedSccpHeightInputsV1::from_sumeragi_schedule(view, 2, 1, ConsensusMode::Npos)
                    .unwrap();
            let inputs = original.inputs().unwrap();
            assert_eq!(
                std::ptr::from_ref(inputs.roster.iter().next().unwrap()),
                first_peer
            );
            assert_eq!(
                inputs
                    .roster
                    .iter()
                    .next()
                    .unwrap()
                    .public_key()
                    .try_to_bytes()
                    .unwrap()
                    .1
                    .as_ptr(),
                key_bytes
            );
            assert_eq!(original.schedule.entries().as_ptr(), entries);
            assert_eq!(
                original.schedule.ready(2).unwrap().epoch.committee[0]
                    .proof_of_possession
                    .as_ptr(),
                pop_bytes
            );
            let reader = original.clone();
            drop(original);
            captured = Some(reader);
        });
        assert_eq!(
            allocations, 0,
            "capture, clone and projection borrow the original graph"
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(source_block);
        assert!(
            world.consensus_schedule.view().get().entries().is_empty(),
            "the empty parent World cannot retain the private schedule graph"
        );
        drop(external);
        let original = captured.unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            charged,
            "dropping the original World overlay cannot refund a live captured graph"
        );
        let inputs = original.inputs().unwrap();
        assert_eq!(inputs.roster.iter().count(), 4);
        assert_eq!(
            std::ptr::from_ref(inputs.roster.iter().next().unwrap()),
            first_peer
        );
        assert_eq!(original.schedule.entries().as_ptr(), entries);
        assert_eq!(
            original.schedule.ready(2).unwrap().epoch.committee[0]
                .proof_of_possession
                .as_ptr(),
            pop_bytes
        );
        assert!(
            inputs.roster.iter().eq(graph
                .ready(2)
                .unwrap()
                .epoch
                .committee
                .iter()
                .map(|member| &member.validator))
        );
        drop(original);
        assert_eq!(
            budget.reserved_bytes(),
            baseline,
            "only the final reader refunds the exact graph and shared shell"
        );
    }

    #[test]
    fn height_capture_retires_original_charges_after_unwind_and_final_reader() {
        use crate::state::World;
        let state = blank_state();
        let budget = state.ivm_execution_budget();
        // The empty parent's admitted SCCP fields and this schedule use the same
        // original pool. Keep those independent fields live throughout the graph
        // refund measurement; only the unpublished overlay owns the schedule.
        let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
        let baseline = budget.reserved_bytes();
        let graph = authenticated_schedule();
        let original = RetainedConsensusSchedule::admit(&graph, &budget).unwrap();
        let charged = budget.reserved_bytes();
        let mut source_block = world.try_block(&budget).unwrap();
        *source_block.consensus_schedule.get_mut() = original;
        let survivor = RetainedSccpHeightInputsV1::from_sumeragi_schedule(
            &source_block,
            2,
            1,
            ConsensusMode::Npos,
        )
        .unwrap();
        let original_peer =
            std::ptr::from_ref(survivor.inputs().unwrap().roster.iter().next().unwrap());
        drop(source_block);
        assert!(
            world.consensus_schedule.view().get().entries().is_empty(),
            "the empty parent World cannot retain the private schedule graph"
        );
        let attempt = survivor.clone();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let inputs = attempt.inputs().unwrap();
            assert_eq!(
                std::ptr::from_ref(inputs.roster.iter().next().unwrap()),
                original_peer
            );
            panic!("original SCCP attempt unwinds");
        }));
        assert!(unwound.is_err());
        assert_eq!(budget.reserved_bytes(), charged);
        assert_eq!(
            std::ptr::from_ref(survivor.inputs().unwrap().roster.iter().next().unwrap()),
            original_peer
        );
        drop(survivor);
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    #[test]
    fn borrowed_roster_preserves_order_and_refuses_the_thirty_second_entry() {
        let graph = authenticated_schedule();
        let peers = &graph.ready(2).unwrap().epoch.committee;
        let order = [
            &peers[2].validator,
            &peers[0].validator,
            &peers[1].validator,
        ];
        let allocations = crate::test_allocations::allocations_during(|| {
            let projected = SccpRosterV1::from_peers(order).unwrap();
            for (actual, expected) in projected.iter().zip(order) {
                assert!(std::ptr::eq(actual, expected));
            }
            assert_eq!(projected.iter().count(), order.len());
            assert!(
                projected
                    .into_iter()
                    .zip(order)
                    .all(|(actual, expected)| std::ptr::eq(actual, expected))
            );
            let largest =
                SccpRosterV1::from_peers(std::iter::repeat_n(&peers[0].validator, 31)).unwrap();
            assert_eq!(largest.iter().count(), 31);
            assert_eq!(
                SccpRosterV1::from_peers(std::iter::repeat_n(&peers[0].validator, 32)),
                Err(SccpHeightInputsError::RosterTooLarge)
            );
            assert_eq!(
                SccpRosterV1::from_peers(std::iter::empty())
                    .unwrap()
                    .iter()
                    .count(),
                0
            );
        });
        assert_eq!(allocations, 0);
        // Projection preserves even malformed order/geometry; the generation validator owns
        // those rejections, covered by its existing unsorted/duplicate/boundary controls.
    }
    #[test]
    fn original_ready_slots_preserve_lookup_and_boundary_overflow_refusal() {
        use crate::state::World;
        let state = blank_state();
        let budget = state.ivm_execution_budget();
        // The empty parent's admitted SCCP fields and this schedule use the same
        // original pool. Keep those independent fields live throughout the graph
        // refund measurement; only the unpublished overlay owns the schedule.
        let world = World::try_with_execution_budget([], [], [], &budget).unwrap();
        let baseline = budget.reserved_bytes();
        // Permissioned genesis authenticates its original epoch through u64::MAX. This
        // structural window exercises arithmetic only; it does not claim execution at MAX.
        let signed = crate::sumeragi::epoch::tests::genesis_fixture(
            iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned,
            5,
            false,
        );
        let epoch = crate::sumeragi::epoch::authenticated_genesis(&signed)
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(epoch.authorization.last_height, u64::MAX);
        let params = ChainParamsRecord::from_parameters(&Default::default());
        let graph = ConsensusSchedule::from_owned_entries(
            (u64::MAX - 2..=u64::MAX)
                .map(|height| {
                    ScheduledSlot::Ready(ScheduledConfig {
                        height,
                        epoch: epoch.clone(),
                        params,
                    })
                })
                .collect(),
        )
        .unwrap();
        let mut source_block = world.try_block(&budget).unwrap();
        *source_block.consensus_schedule.get_mut() =
            RetainedConsensusSchedule::admit(&graph, &budget).unwrap();
        let view = &source_block;
        let charged = budget.reserved_bytes();
        let schedule = view.consensus_schedule();
        assert!(schedule.ready(u64::MAX).is_ok());
        assert!(schedule.ready(u64::MAX - 3).is_err());
        let allocations = crate::test_allocations::allocations_during(|| {
            let original = RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                view,
                u64::MAX - 1,
                1,
                ConsensusMode::Permissioned,
            )
            .unwrap();
            let inputs = original.inputs().unwrap();
            let ready = schedule.ready(u64::MAX - 1).unwrap();
            assert_eq!(inputs.height, ready.height);
            assert_eq!(inputs.epoch, ready.epoch.authorization.epoch);
            assert_eq!(
                inputs.epoch_end_height,
                ready.epoch.authorization.last_height
            );
            for (borrowed, member) in inputs.roster.iter().zip(&ready.epoch.committee) {
                assert!(std::ptr::eq(borrowed, &member.validator));
            }
            assert_eq!(inputs.roster.iter().count(), ready.epoch.committee.len());
            assert!(inputs.next_roster.is_none());
            assert_eq!(
                RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                    view,
                    u64::MAX,
                    1,
                    ConsensusMode::Permissioned
                ),
                Err(SccpHeightInputsError::Overflow)
            );
            assert_eq!(
                RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                    view,
                    u64::MAX - 3,
                    1,
                    ConsensusMode::Permissioned
                ),
                Err(SccpHeightInputsError::Unscheduled(u64::MAX - 3))
            );
        });
        assert_eq!(allocations, 0);
        assert_eq!(budget.reserved_bytes(), charged);
        drop(source_block);
        assert!(
            world.consensus_schedule.view().get().entries().is_empty(),
            "the empty parent World cannot retain the private schedule graph"
        );
        assert_eq!(budget.reserved_bytes(), baseline);
    }
}
