//! Rejoin the original native header capture before schedule or economic effects.

use super::*;

impl StateBlock<'_> {
    /// Check the original State, stable generation and exact pristine carrier together.
    pub(crate) fn validate_native_pristine_control_owner(
        &self,
        state: &State,
        generation: u64,
        header: &BlockHeader,
    ) -> Result<(), String> {
        if !std::ptr::eq(self.state_ref, state)
            || !is_stable_state_view_generation(generation, state.state_view_generation())
            || &self._curr_block != header
            || self.start_of_block_effects_applied
            || self.applied_npos_consensus_effects_hash.is_some()
            || !matches!(
                self.sumeragi_schedule,
                crate::sumeragi::schedule::ScheduleStep::Off
            )
            || !matches!(
                self.sumeragi_lanes_step,
                crate::sumeragi::lanes::step::LaneStep::Off
            )
            || !self.world.merge_execution_write_set_bytes().is_empty()
        {
            return Err("native controls lost their original pristine State owner".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::store::LiveQueryStore;
    #[test]
    fn pristine_source_rejoins_state_generation_header_and_unmodified_controls() {
        let state = State::new(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let foreign = State::new(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let generation = state.state_view_generation();
        let header = BlockHeader::new(NonZeroU64::MIN, None, None, 1000, 0);
        let outcome = state.block_with_pristine_stage(header, |overlay| {
            overlay
                .validate_native_pristine_control_owner(&state, generation, &header)
                .unwrap();
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&foreign, generation, &header)
                    .is_err()
            );
            assert!(
                overlay
                    .validate_native_pristine_control_owner(
                        &state,
                        generation.wrapping_add(2),
                        &header
                    )
                    .is_err()
            );
            let mut changed = header;
            changed.creation_time_ms += 1;
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&state, generation, &changed)
                    .is_err()
            );
            overlay.start_of_block_effects_applied = true;
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&state, generation, &header)
                    .is_err()
            );
            overlay.start_of_block_effects_applied = false;
            overlay.request_sumeragi_lanes(crate::sumeragi::lanes::merge::LaneStepInput::default());
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&state, generation, &header)
                    .is_err()
            );
            overlay.sumeragi_lanes_step = crate::sumeragi::lanes::step::LaneStep::FailedOwnerMoved;
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&state, generation, &header)
                    .is_err()
            );
            overlay.request_sumeragi_lanes(crate::sumeragi::lanes::merge::LaneStepInput::default());
            assert!(matches!(
                overlay.sumeragi_lanes_step,
                crate::sumeragi::lanes::step::LaneStep::FailedOwnerMoved
            ));
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&state, generation, &header)
                    .is_err()
            );
            // Begin an independent negative source-write probe in this test only.
            overlay.sumeragi_lanes_step = crate::sumeragi::lanes::step::LaneStep::Off;
            overlay
                .world
                .smart_contract_state
                .insert("source/changed".parse().unwrap(), vec![1]);
            assert!(
                overlay
                    .validate_native_pristine_control_owner(&state, generation, &header)
                    .is_err()
            );
            Err::<(), _>("finished before start effects")
        });
        assert!(matches!(
            outcome,
            Err(StateBlockStartError::Stage("finished before start effects"))
        ));
    }
}
