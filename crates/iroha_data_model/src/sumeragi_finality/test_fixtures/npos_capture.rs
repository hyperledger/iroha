//! Genuine short-epoch native certificates for schedule-wire fixtures.
//!
//! Execution roots and the certified beacon output remain synthetic. The QC,
//! signed genesis, parent chain, boundary barrier and retained-authority checks
//! are the production native verifier's; this is not beacon-ceremony evidence.

use super::*;
use crate::{
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1,
    },
    sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochBoundaryV1,
        ValidatorEpochDecisionV1,
    },
};

impl NativeFinalityFixture {
    /// Certify H1 genesis, H2 preboundary, H3 retention and H4 successor.
    /// The explicit short `NPoS` policy and exact quorum are valid for every
    /// supported seat count; the beacon output is synthetic execution data.
    #[cfg(test)]
    pub(crate) fn short_npos_boundary_chain(seats: usize) -> (Self, Vec<SumeragiFinalityProof>) {
        Self::short_npos_boundary_chain_parameters(seats, false)
    }

    /// Certify the short retention boundary from an explicitly parameterized signed genesis.
    /// Native adapters can derive their complete selected anchor from this same root;
    /// execution roots and beacon output remain synthetic fixture data.
    #[must_use]
    pub fn short_npos_boundary_chain_with_explicit_parameters(
        seats: usize,
    ) -> (Self, Vec<SumeragiFinalityProof>) {
        Self::short_npos_boundary_chain_parameters(seats, true)
    }

    fn short_npos_boundary_chain_parameters(
        seats: usize,
        explicit_parameters: bool,
    ) -> (Self, Vec<SumeragiFinalityProof>) {
        let parameters = crate::parameter::system::SumeragiNposParameters {
            epoch_length_blocks: NonZeroU64::new(3).unwrap(),
            finality_margin_blocks: 1,
            evidence_horizon_blocks: 3,
            activation_lag_blocks: 1,
            slashing_delay_blocks: 3,
            ..Default::default()
        };
        parameters.validate().unwrap();
        let mut fixture = Self::start_with_selected_npos_parameters(
            &format!("ordinary-load-npos-schedule-{seats}"),
            SumeragiConsensusMode::Npos,
            crate::block::consensus::SumeragiRootScope::Global,
            explicit_parameters,
            parameters,
            seats,
        );
        let mut chain = vec![fixture.genesis_proof().clone()];
        let parent = fixture
            .verifier
            .verify_retained_decision(&fixture.tip)
            .unwrap();
        let current = fixture.epoch.clone();
        let params = *parent.commitment().schedule.next.params();
        let ready = |height, epoch: &ValidatorEpochContextV1| {
            ScheduledSlot::Ready(ScheduledConfig {
                height,
                epoch: epoch.clone(),
                params,
            })
        };
        let (_, point) = fixture.keys[0].public_key().try_to_bytes().unwrap();
        let mut pulse = FinalizedGlobalThresholdBeaconPulseV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: fixture.network_id(),
            session_id: [1; 32],
            roster_hash: [2; 32],
            transcript_hash: [3; 32],
            context: GlobalThresholdBeaconPulseContextV1 {
                instance: fixture.verifier.instance().0,
                epoch: current.authorization.epoch,
                epoch_context_id: current.context_id().unwrap(),
                parent_consensus_hash: parent.core_hash().0,
                parent_result: parent.result().0,
            },
            height: 2,
            round: 0,
            finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
                height: 1,
                block_hash: parent.block().hash(),
            },
            signature: point.try_into().unwrap(),
            seed: [4; 32],
            pulse_id: [0; 32],
        };
        pulse.pulse_id = global_threshold_beacon_pulse_id_v1(&pulse, pulse.seed);
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let result = result_with_schedule(
            &block,
            ScheduleOutcome {
                height: 2,
                current: current.clone(),
                boundary: None,
                next: ready(3, &current),
                after_next: ScheduledSlot::PendingBoundary {
                    height: 4,
                    boundary_height: 3,
                    predecessor_context_id: current.context_id().unwrap(),
                    params,
                },
            },
            Some(&pulse),
        );
        chain.push(fixture.certify_result(block, &result));

        let mut successor = current.clone();
        successor.authorization.epoch = 1;
        successor.authorization.first_height = 4;
        successor.authorization.last_height = 6;
        successor.authorization.previous_authorization_id =
            current.authorization.authorization_id().unwrap();
        successor.authorization.decision = ValidatorEpochDecisionV1::Retain;
        successor.authorization.beacon =
            BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                session_id: pulse.session_id,
                transcript_hash: pulse.transcript_hash,
            });
        successor.leader_seed = global_threshold_beacon_npos_successor_seed_v1(&pulse, 3, 1);
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let result = result_with_schedule(
            &block,
            ScheduleOutcome {
                height: 3,
                current: current.clone(),
                boundary: Some(ValidatorEpochBoundaryV1 {
                    version: 1,
                    height: 3,
                    predecessor_context_id: current.context_id().unwrap(),
                    selection_anchor: fixture.tip.block_header.hash(),
                    next: successor.clone(),
                    preparation: None,
                }),
                next: ready(4, &successor),
                after_next: ready(5, &successor),
            },
            None,
        );
        chain.push(fixture.certify_result(block, &result));
        fixture.epoch = successor;
        let block = fixture.block_with_submitted_work(fixture.next_header());
        chain.push(fixture.certify(block));
        (fixture, chain)
    }
}

fn result_with_schedule(
    block: &SignedBlock,
    schedule: ScheduleOutcome,
    beacon: Option<&FinalizedGlobalThresholdBeaconPulseV1>,
) -> ExecutionResultCommitment {
    let height = block.header().height().get();
    let (native_lanes, root) =
        NativeLaneStateProof::empty_for_testing(schedule.current.network_id, height);
    let (len, hash) = block.executed_block_wire_identity().unwrap();
    ExecutionResultCommitment::new(
        height,
        ExecutionCommitment {
            parent_state_root: Hash::new(b"fixture parent"),
            post_state_root: root,
            ordinary_writes_root: root,
            parent_world_state_root: Hash::new(b"fixture parent world"),
            world_state_root: Hash::new(b"fixture world"),
            event_commitment: None,
            executed_block_wire_len: len,
            executed_block_wire_hash: hash,
            transaction_input_commitment: block.network_input_merkle_commitment(),
            transaction_output_commitment: block.output_merkle_commitment(),
        },
        schedule,
        beacon.copied(),
        native_lanes,
    )
    .unwrap()
}
