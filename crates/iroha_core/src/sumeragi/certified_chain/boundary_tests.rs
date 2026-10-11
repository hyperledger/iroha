//! Historical certification transcripts with genuine BLS votes and threshold pulses.
//! These fixtures verify exact BLS quorums and authenticated scheduling transitions.
//! They do not execute NPoS State transitions or establish monetary qualification.

use super::*;
use crate::state::WorldReadOnly as _;
use crate::sumeragi::{
    commitment::execution_commitment,
    payload,
    schedule::{ChainParamsRecord, ScheduleOutcome, ScheduledConfig, ScheduledSlot},
};
use iroha_data_model::sumeragi::epoch::{
    BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochAuthorizationV1,
    ValidatorEpochDecisionV1, ValidatorGenerationV1,
};
use iroha_data_model::{
    NetworkId,
    block::{
        consensus::ExecWitness,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
    },
    consensus::{GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1},
    parameter::system::{ConsensusMode, SumeragiNposParameters},
    sumeragi::epoch::{ValidatorCommitteeMemberV1, ValidatorEpochBoundaryV1},
    transaction::signed::TransactionResult,
};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::{Signer as _, form_qc},
    message::Vote,
    preimage::payload_hash,
    types::ChainParams,
};
use std::{num::NonZeroU64, sync::OnceLock, time::Duration};

fn keys(rotated: bool) -> Vec<KeyPair> {
    let start = if rotated { 0xD1u8 } else { 0xC1u8 };
    let mut keys = (start..=start + 3)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| core_key(key.public_key()).unwrap());
    keys
}
fn members(keys: &[KeyPair]) -> Vec<ValidatorCommitteeMemberV1> {
    keys.iter()
        .map(|key| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(key.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
        })
        .collect()
}

fn certificate(keys: &[KeyPair], header: &BlockHeader, result: Hash32, last: bool) -> Qc {
    let crypto = BlsCrypto::new();
    crypto
        .admit_committee(
            keys.iter()
                .map(|key| {
                    (
                        key.public_key(),
                        iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
                .iter()
                .map(|(key, pop)| (*key, pop.as_slice())),
        )
        .unwrap();
    let indices = if last { [1usize, 2, 3] } else { [0usize, 1, 2] };
    let votes = indices
        .into_iter()
        .map(|index| {
            let mut vote = Vote {
                kind: VoteKind::Commit,
                instance: header.instance,
                epoch: header.epoch,
                height: header.height,
                view: 0,
                block_hash: header.hash(&crypto),
                result,
                signer: index as u32,
                sig: iroha_sumeragi::types::Signature([0; iroha_sumeragi::types::SIGNATURE_LEN]),
            };

            vote.sig = crate::sumeragi::crypto::KeyPairSigner::new(&keys[index])
                .unwrap()
                .sign(&vote.preimage());
            vote
        })
        .collect::<Vec<_>>();
    form_qc(&crypto, keys.len(), &votes.iter().collect::<Vec<_>>()).unwrap()
}
fn install_structural_outputs(block: &mut SignedBlock) {
    let outputs = (0..block.external_transactions().count())
        .map(|index| {
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: index as u32,
                result: TransactionResult::new(Ok(Vec::new())),
                completions: Vec::new(),
            })
        })
        .collect();
    block
        .set_execution_outputs(
            outputs,
            0,
            Default::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            &crate::execution_output_test_support::structural_output_limits(),
        )
        .unwrap();
}
fn params() -> ChainParamsRecord {
    ChainParamsRecord::from_core(&ChainParams {
        epoch_length: 6,
        ..ChainParams::default()
    })
}
fn slot(height: u64, current: &ValidatorEpochContextV1) -> ScheduledSlot {
    if height <= current.authorization.last_height {
        ScheduledSlot::Ready(ScheduledConfig {
            height,
            epoch: current.clone(),
            params: params(),
        })
    } else {
        ScheduledSlot::PendingBoundary {
            height,
            boundary_height: current.authorization.last_height,
            predecessor_context_id: current.context_id().unwrap(),
            params: params(),
        }
    }
}
fn outcome(
    height: u64,
    current: &ValidatorEpochContextV1,
    boundary: Option<ValidatorEpochBoundaryV1>,
) -> ScheduleOutcome {
    let authorized = boundary.as_ref().map_or(current, |boundary| &boundary.next);
    let next = slot(height + 1, authorized);
    let after_next = slot(height + 2, authorized);
    ScheduleOutcome {
        height,
        current: current.clone(),
        boundary,
        next,
        after_next,
    }
}
/// Build a certificate transcript proposal without claiming native State execution.
/// Parent participation comes from the existing full pinned-prefix verifier; production
/// payload assembly continues to require its independently published native execution tip.
fn transcript_proposal(
    state: &State,
    history: &[iroha_data_model::block::SharedSignedBlock],
    transaction: crate::tx::AcceptedTransaction<'static>,
    time: Duration,
) -> SignedBlock {
    let parent = history.last().unwrap();
    let height = parent.header().height().get() + 1;
    let hashes = history.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let view = state.view();
    assert_eq!(view.canonical_history().height(), 0);
    assert!(view.native_execution_tip().is_none());
    let reader =
        CertifiedChain::from_frames(view.chain_id(), view.network_id(), &hashes, history).unwrap();
    let certified = reader.certified(height - 1).unwrap();
    assert_eq!(certified.block_hash(), parent.hash());
    let effects = (height > 2).then(|| {
        assert_eq!(certified.verification(), QcVerification::Verified);
        let original = certified.certificate().unwrap().commit_qc();
        assert!(!original.is_empty());
        assert!(original.len() <= iroha_data_model::consensus::PARENT_SERVICE_COMMIT_QC_MAX_BYTES);
        iroha_data_model::consensus::NposConsensusEffects {
            parent_service_commit_qc: Some(original.to_vec()),
            ..Default::default()
        }
    });
    let routing = crate::sumeragi::lanes::routing::RoutingSnapshot::of(&view).unwrap();
    let route = routing
        .inputs(view.world())
        .execution_route(&transaction, height)
        .unwrap()
        .unwrap();
    let context = iroha_data_model::block::BlockExecutionContextBundle::new(vec![
        iroha_data_model::block::ExternalExecutionContext::new(
            transaction.hash_as_entrypoint(),
            route.lane_id,
            route.dataspace_id,
        ),
    ]);
    let confidential =
        crate::state::compute_confidential_feature_digest(view.world(), view.zk(), height);
    let (_, time_source) = iroha_primitives::time::TimeSource::new_mock(time);
    let proposal =
        crate::block::BlockBuilder::new_with_time_source(vec![transaction.clone()], time_source)
            .chain(0, Some(parent))
            .with_da_proof_policies(Some(crate::da::active_proof_policy_bundle_at_height(
                &state.nexus_snapshot(),
                height,
            )))
            .with_confidential_features((!confidential.is_empty()).then_some(confidential))
            .with_execution_context(Some(context))
            .with_npos_consensus_effects(effects)
            .with_network_input_time_floor(time)
            .unwrap()
            .into_unsigned_proposal();
    assert_eq!(
        crate::block::ValidBlock::sumeragi_block_time(
            &proposal,
            parent.header().creation_time(),
            Duration::from_millis(1),
        )
        .unwrap(),
        time,
    );
    if height <= 3 {
        let assembled = payload::assemble(
            state,
            payload::Assembly {
                parent,
                view: 0,
                cadence: Duration::from_millis(1),
            },
            &[transaction],
        );
        if height == 2 {
            assert_eq!(
                proposal.encode_wire().unwrap(),
                assembled.unwrap().encode_wire().unwrap(),
                "the first transcript proposal preserves every original assembly field"
            );
        } else {
            assert!(
                matches!(assembled, Err(payload::PayloadError::ParentService(message))
                    if message.contains("Canonical history height 1")
                        && message.contains("ending at `0`")),
                "production assembly must refuse the absent committed parent history"
            );
        }
    }
    proposal
}

fn build_history(retain: bool) -> Vec<iroha_data_model::block::SharedSignedBlock> {
    let original_keys = keys(false);
    let genesis_key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
    let mut policy = SumeragiNposParameters::default();
    policy.epoch_seed = [0x35; 32];
    policy.epoch_length_blocks = NonZeroU64::new(6).unwrap();
    policy.evidence_horizon_blocks = 6;
    policy.slashing_delay_blocks = 6;
    policy.max_validators = 4;
    let validators = members(&original_keys)
        .into_iter()
        .map(|member| (member.validator, member.proof_of_possession))
        .collect::<Vec<_>>();
    let mut genesis = crate::sumeragi::test_chain::signed_genesis_fixture(
        &"sumeragi-certified-test-chain".parse().unwrap(),
        &genesis_key,
        &validators,
        Vec::new(),
        1000,
        ConsensusMode::Npos,
        Some(policy),
    )
    .unwrap();
    let mut current = crate::sumeragi::epoch::authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    assert_eq!(current.authorization.last_height, 6);
    let network = NetworkId::from_genesis_hash(genesis.hash());
    let instance =
        crate::sumeragi::node::root_instance(&genesis, "sumeragi-certified-test-chain").unwrap();
    // This certificate-transcript fixture does not execute NPoS transitions. Its test-only
    // proposal builder uses the original signed root-routing metadata. Project only that
    // exact genesis parameter into its routing World; absence never implies Global.
    let metadata = iroha_genesis::signed_genesis_consensus_metadata(&genesis).unwrap();
    let routing_world = World::new();
    {
        let mut parameters = routing_world.parameters.block();
        parameters.set_parameter(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::parameter::custom::CustomParameter::new(
                iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id(),
                iroha_primitives::json::Json::from_norito_value_ref(
                    &norito::json::value::to_value(&metadata).unwrap(),
                )
                .unwrap(),
            ),
        ));
        parameters.commit();
    }
    assert_eq!(
        crate::sumeragi::lanes::routing::committed_root_scope(&routing_world.view()),
        Some(metadata.sumeragi_context.root_scope),
    );
    let world = State::new_with_chain_and_network_id_for_testing(
        routing_world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        network,
    );
    let witness = complete_lane_state_witness(network, 1);
    install_structural_outputs(&mut genesis);
    let result = ExecutionResultCommitment::new(
        1,
        execution_commitment(&witness, &genesis, &synthetic_world()).unwrap(),
        outcome(1, &current, None),
        None,
        iroha_data_model::sumeragi_finality::NativeLaneStateProof::from_witness(
            &witness,
            &iroha_allocation::AllocationBudget::new(64 * 1024),
        )
        .unwrap(),
    )
    .unwrap();
    genesis = genesis.with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        Vec::new(),
        Vec::new(),
        result.preimage().unwrap(),
        Vec::new(),
    )));
    let mut history = vec![crate::block::reserve_block_for_tests().initialize(genesis)];
    let mut active_keys = original_keys;
    let mut active_beacon = crate::beacon::tests::HistoricalBeaconFixture::new(
        network,
        [0x61; 32],
        current.authorization.authority_generation,
        &active_keys,
    );
    for height in 2..=14 {
        let parent = read_frame(history.last().unwrap().clone(), height - 1).unwrap();
        let block_time = parent.block().header().creation_time() + Duration::from_millis(1);
        let (_, time_source) = iroha_primitives::time::TimeSource::new_mock(block_time);
        let mut transaction = iroha_data_model::transaction::TransactionBuilder::new(
            network,
            iroha_data_model::account::AccountId::new(genesis_key.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, format!("certified history {height}"))]);
        transaction.set_creation_time(parent.block().header().creation_time());
        let transaction = crate::tx::AcceptedTransaction::accept_with_time_source(
            transaction.sign(genesis_key.private_key()),
            &network,
            Duration::from_secs(1),
            world.view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time_source,
        )
        .unwrap();
        let entry_hash = transaction.hash_as_entrypoint();
        let mut block = transcript_proposal(&world, &history, transaction, block_time);
        assert_eq!(
            block.execution_context().unwrap().external,
            vec![iroha_data_model::block::ExternalExecutionContext::new(
                entry_hash,
                crate::sumeragi::lanes::routing::GLOBAL_LANE,
                metadata.sumeragi_context.root_scope.dataspace_id(),
            )],
            "certificate transcript commits the exact signed-root route",
        );
        let beacon = if height + 1 == current.authorization.last_height {
            Some(active_beacon.pulse(
                GlobalThresholdBeaconChainAnchorV1 {
                    height: height - 1,
                    block_hash: parent.block_hash(),
                },
                GlobalThresholdBeaconPulseContextV1 {
                    instance: instance.0,
                    epoch: current.authorization.epoch,
                    epoch_context_id: current.context_id().unwrap(),
                    parent_consensus_hash: parent.core_hash().0,
                    parent_result: parent.result().0,
                },
            ))
        } else {
            None
        };
        let mut successor = None;
        let boundary = if height == current.authorization.last_height {
            let next_keys = if retain {
                keys(false)
            } else {
                keys(height == 6)
            };
            let generation = ValidatorGenerationV1::from_committee(
                network,
                if retain {
                    current.authorization.authority_generation
                } else {
                    current.authorization.authority_generation + 1
                },
                &members(&next_keys),
            );
            let next_beacon = (!retain).then(|| {
                crate::beacon::tests::HistoricalBeaconFixture::new(
                    network,
                    [0x62 + (height / 12) as u8; 32],
                    generation.generation,
                    &next_keys,
                )
            });
            let record = next_beacon.as_ref().unwrap_or(&active_beacon).record();
            assert_eq!(
                record.adaptive_dkg.session.authority_generation,
                generation.generation
            );
            let authorization = ValidatorEpochAuthorizationV1 {
                version: 1,
                network_id: network,
                epoch: current.authorization.epoch + 1,
                first_height: current.authorization.last_height + 1,
                last_height: height + 6,
                authority_generation: generation.generation,
                authority_id: generation.generation_id().unwrap(),
                beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                    session_id: record.session_id,
                    transcript_hash: record.transcript_hash,
                }),
                previous_authorization_id: current.authorization.authorization_id().unwrap(),
                transition_id: if retain { [0; 32] } else { [height as u8; 32] },
                decision: if retain {
                    ValidatorEpochDecisionV1::Retain
                } else {
                    ValidatorEpochDecisionV1::Activate
                },
            };
            let next = ValidatorEpochContextV1 {
                da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
                version: 1,
                network_id: network,
                mode: ConsensusMode::Npos,
                authorization,
                committee: members(&next_keys),
                leader_seed: crate::beacon::global_threshold_beacon_npos_successor_seed_v1(
                    parent.commitment().beacon.as_ref().unwrap(),
                    height,
                    authorization.epoch,
                ),
            };
            next.validate_successor(&current).unwrap();
            successor = Some((next.clone(), next_keys, next_beacon));
            Some(ValidatorEpochBoundaryV1 {
                version: 1,
                height,
                predecessor_context_id: current.context_id().unwrap(),
                selection_anchor: parent.block_hash(),
                next,
                preparation: None,
            })
        } else {
            None
        };
        assert!(
            block.global_beacon_pulse().is_none(),
            "native header is the sole control owner"
        );
        install_structural_outputs(&mut block);
        let payload = payload::encode(&block).unwrap();
        let header = BlockHeader {
            control_witness: crate::sumeragi::epoch_beacon::control::encode(beacon).unwrap(),
            instance,
            epoch: schedule::core_epoch(&current).unwrap().id,
            height,
            origin_view: 0,
            parent_hash: parent.core_hash(),
            parent_result: parent.result(),
            payload_hash: payload_hash(&BlsCrypto::new(), &payload),
            availability_digest: Hash32::ZERO,
            payload_len: u32::try_from(payload.len()).unwrap(),
            proposer: 0,
            skipped_leaders: Vec::new(),
        };
        let budget = world.ivm_execution_budget();
        let mut backing = iroha_allocation::ChargedBuffer::new(payload.len(), &budget).unwrap();
        backing.append(&payload).unwrap();
        let payload = PayloadBytes::from_charged(backing, &budget)
            .unwrap_or_else(|_| panic!("original historical fixture payload admission"));
        let config = ScheduledConfig {
            height,
            epoch: current.clone(),
            params: params(),
        }
        .height_config()
        .unwrap();
        let crypto = BlsCrypto::new();
        crypto
            .admit_committee(current.committee.iter().map(|member| {
                (
                    member.validator.public_key(),
                    member.proof_of_possession.as_slice(),
                )
            }))
            .unwrap();
        let signer = crate::sumeragi::crypto::KeyPairSigner::new(&active_keys[0]).unwrap();
        let authored = PayloadAuthoring::new(header, payload)
            .complete(instance, &config, &budget, &crypto, &signer)
            .unwrap_or_else(|(_, error)| {
                panic!("actual historical signed RS16 authoring: {error:?}")
            });
        let header = authored.body.header().clone();
        let availability = norito::encode_canonical(authored.body.availability()).unwrap();
        let witness = complete_lane_state_witness(network, height);
        let commitment = ExecutionResultCommitment::new(
            height,
            execution_commitment(&witness, &block, &synthetic_world()).unwrap(),
            outcome(height, &current, boundary),
            beacon,
            iroha_data_model::sumeragi_finality::NativeLaneStateProof::from_witness(
                &witness,
                &iroha_allocation::AllocationBudget::new(64 * 1024),
            )
            .unwrap(),
        )
        .unwrap();
        let preimage = commitment.preimage().unwrap();
        let qc = certificate(&active_keys, &header, result_of_preimage(&preimage), false);
        block = block.with_commit_certificate(Some(
            commit_certificate(&header, &qc, preimage, availability).unwrap(),
        ));
        history.push(crate::block::reserve_block_for_tests().initialize(block));
        if let Some((next, keys, beacon)) = successor {
            current = next;
            active_keys = keys;
            if let Some(beacon) = beacon {
                active_beacon = beacon;
            }
        }
    }
    history
}
fn history() -> Vec<iroha_data_model::block::SharedSignedBlock> {
    static HISTORY: OnceLock<Vec<iroha_data_model::block::SharedSignedBlock>> = OnceLock::new();
    HISTORY.get_or_init(|| build_history(false)).clone()
}
fn retained_history() -> Vec<iroha_data_model::block::SharedSignedBlock> {
    static HISTORY: OnceLock<Vec<iroha_data_model::block::SharedSignedBlock>> = OnceLock::new();
    HISTORY.get_or_init(|| build_history(true)).clone()
}

#[test]
fn rotated_away_committee_verifies_from_authenticated_boundaries_with_bounded_authority() {
    let history = history();
    let state = state_with_history(&history);
    let view = state.view();
    let reader = CertifiedChain::new(&view).unwrap();
    assert_eq!(
        reader
            .walk(1, 14)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        14
    );
    {
        let cursor = reader.prefix.lock();
        let prefix = cursor.as_ref().unwrap();
        assert_eq!(prefix.tip.height(), 14);
        assert_eq!(
            prefix.authority.material.authorization.authority_generation,
            2
        );
        assert!(prefix.schedule.entries().len() <= 3);
    }
    let original = reader.certified(7).unwrap();
    let other = with_parts(&history[6], |header, qc, _| {
        *qc = certificate(&keys(true), header, qc.result, true)
    });
    let other = reader.check_certificate(other, 7).unwrap();
    assert_ne!(
        original.commit_qc().unwrap().signers,
        other.commit_qc().unwrap().signers
    );
    assert_eq!(original.id(), other.id());
    assert_eq!(original.commitment(), other.commitment());
    assert_eq!(
        reader.certified(14).unwrap().verification(),
        QcVerification::Verified
    );
}

#[test]
fn retained_generation_still_binds_new_epoch_and_fresh_leader_randomness() {
    let history = retained_history();
    let state = state_with_history(&history);
    let view = state.view();
    let reader = CertifiedChain::new(&view).unwrap();
    let before = reader.certified(6).unwrap();
    let after = reader.certified(7).unwrap();
    assert_eq!(
        before.commitment().schedule.current.generation(),
        after.commitment().schedule.current.generation()
    );
    assert_eq!(
        before.commitment().schedule.current.committee,
        after.commitment().schedule.current.committee
    );
    assert_ne!(
        before.header().unwrap().epoch,
        after.header().unwrap().epoch
    );
    assert_ne!(
        before.commitment().schedule.current.leader_seed,
        after.commitment().schedule.current.leader_seed
    );
    let old_epoch = with_parts(&history[6], |header, qc, _| {
        header.epoch = before.header().unwrap().epoch;
        *qc = certificate(&keys(false), header, qc.result, false);
    });
    assert!(matches!(
        reader.check_certificate(old_epoch, 7),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::HeaderMismatch { height: 7 }
        ))
    ));
}

#[test]
fn historical_authority_missing_reordered_or_forged_proofs_fail_closed() {
    let history = history();
    for mutation in 0..5 {
        let mut corrupt = history.clone();
        corrupt[5] = with_parts(&corrupt[5], |_, _, bytes| {
            let mut result = ExecutionResultCommitment::decode(bytes).unwrap();
            let next = &mut result.schedule.boundary.as_mut().unwrap().next;
            match mutation {
                0 => {
                    next.committee.pop();
                }
                1 => next.committee.swap(0, 1),
                2 => next.committee[0].proof_of_possession.clear(),
                3 => next.committee[0].proof_of_possession[0] ^= 1,
                _ => next.authorization.authority_generation += 1,
            }
            // The compact wire derives both successor epochs from the boundary. Keep
            // that projection consistent so the reader tests the forged authority itself.
            let changed = next.clone();
            for slot in [&mut result.schedule.next, &mut result.schedule.after_next] {
                if let ScheduledSlot::Ready(config) = slot {
                    config.epoch = changed.clone();
                }
            }
            *bytes = norito::encode_canonical(&result).unwrap();
        });
        let state = state_with_history(&corrupt);
        let view = state.view();
        assert!(matches!(
            CertifiedChain::new(&view).unwrap().certified(14),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                ChainReadError::Malformed { height: 6, .. }
            ))
        ));
    }
    let mut missing = history;
    missing[5] = crate::block::reserve_block_for_tests()
        .initialize(missing[5].as_ref().clone().with_commit_certificate(None));
    let state = state_with_history(&missing);
    let view = state.view();
    assert!(matches!(
        CertifiedChain::new(&view).unwrap().certified(14),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::MissingCertificate { height: 6 }
        ))
    ));
}

#[test]
fn boundary_authority_and_parent_links_cannot_self_authorize() {
    let original = history();
    for kind in 0..3 {
        let mut history = original.clone();
        let index = if kind == 0 { 5 } else { 6 };
        history[index] = with_parts(&history[index], |header, qc, _| {
            if kind == 1 {
                header.parent_result = Hash32([0x77; 32]);
            }
            *qc = certificate(&keys(kind != 2), header, qc.result, false);
        });
        let state = state_with_history(&history);
        let view = state.view();
        let result = CertifiedChain::new(&view).unwrap().certified(14);
        if kind == 1 {
            assert!(matches!(
                result,
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    ChainReadError::Discontinuous { height: 7 }
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    ChainReadError::Certificate { .. }
                ))
            ));
        }
    }
}

#[test]
fn nonempty_boundary_checks_exact_fresh_pulse() {
    let original = history();
    let state = state_with_history(&original);
    let view = state.view();
    let reader = CertifiedChain::new(&view).unwrap();
    let boundary = reader.certified(6).unwrap();
    assert!(boundary.header().unwrap().payload_len > 0);
    for mutation in 1..3 {
        let mut history = original.clone();
        history[5] = with_parts(&history[5], |header, qc, bytes| {
            {
                let mut result = ExecutionResultCommitment::decode(bytes).unwrap();
                let boundary = result.schedule.boundary.as_mut().unwrap();
                if mutation == 1 {
                    boundary.selection_anchor =
                        HashOf::from_untyped_unchecked(Hash::new(b"foreign cut"));
                } else {
                    boundary.next.leader_seed[0] ^= 1;
                    let changed = boundary.next.clone();
                    if let ScheduledSlot::Ready(next) = &mut result.schedule.next {
                        next.epoch = changed.clone();
                    }
                    if let ScheduledSlot::Ready(next) = &mut result.schedule.after_next {
                        next.epoch = changed;
                    }
                }
                *bytes = result.preimage().unwrap();
            }

            *qc = certificate(&keys(false), header, result_of_preimage(bytes), false);
        });
        let state = state_with_history(&history);
        let view = state.view();
        let result = CertifiedChain::new(&view).unwrap().certified(6);
        assert!(result.is_err(), "mutation {mutation}");
    }
}

#[test]
fn native_boundary_accepts_exact_quorum_and_rejects_changed_signature() {
    let original = history();
    let state = state_with_history(&original);
    let view = state.view();
    let reader = CertifiedChain::new(&view).unwrap();
    assert_eq!(
        reader
            .walk(1, 14)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        14
    );
    let boundary = reader.certified(6).unwrap();
    assert_eq!(boundary.verification(), QcVerification::Verified);
    assert!(boundary.commitment().schedule.boundary.is_some());
    assert!(boundary.header().unwrap().payload_len > 0);
    let qc = boundary.commit_qc().unwrap();
    assert_eq!(
        qc.signers,
        iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1, 2]).unwrap()
    );
    let bad_signature = with_parts(&original[5], |_, qc, _| qc.agg_sig.0[0] ^= 1);
    assert!(matches!(
        reader.check_certificate(bad_signature, 6),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Certificate { height: 6, .. }
        ))
    ));
}

#[test]
fn unsigned_genesis_result_cannot_substitute_the_signed_epoch_root() {
    let mut history = history();
    let original = history[0].as_ref();
    let certificate = original.commit_certificate().unwrap();
    let mut result = ExecutionResultCommitment::decode(certificate.result_preimage()).unwrap();
    let mut changed = result.schedule.current.clone();
    changed.leader_seed[0] ^= 1;
    result.schedule = outcome(1, &changed, None);
    let certificate = CommitCertificate::from_untrusted_parts(
        certificate.consensus_header().to_vec(),
        certificate.commit_qc().to_vec(),
        result.preimage().unwrap(),
        certificate.availability().to_vec(),
    );
    history[0] = crate::block::reserve_block_for_tests()
        .initialize(original.clone().with_commit_certificate(Some(certificate)));
    let state = state_with_history(&history);
    let view = state.view();
    assert!(read_frame(Clone::clone(&history[0]), 1).is_ok());
    assert!(
        committed_block(&view, 1).is_err(),
        "stored frames and a hash index cannot replace original execution provenance"
    );
    assert!(matches!(
        CertifiedChain::new(&view).unwrap().certified(1),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Committee { height: 1, .. }
        ))
    ));
}

#[test]
fn result_pulses_require_exact_height_network_session_and_parent_bindings() {
    let history = history();
    for mutation in 0..7 {
        let original = &history[if mutation == 6 { 10 } else { 4 }];
        let certificate = original.commit_certificate().unwrap();
        let mut result = ExecutionResultCommitment::decode(certificate.result_preimage()).unwrap();
        if mutation == 0 {
            result.beacon = None;
        } else {
            let pulse = result.beacon.as_mut().unwrap();
            match mutation {
                1 => pulse.height += 1,
                2 => {
                    pulse.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                        Hash::new(b"foreign pulse"),
                    ))
                }
                3 => pulse.finalized_chain_anchor.height -= 1,
                4 => pulse.seed[0] ^= 1,
                5 => pulse.round += 1,
                _ => {
                    pulse.session_id[0] ^= 1;
                    pulse.pulse_id =
                        crate::beacon::global_threshold_beacon_pulse_id_v1(pulse, pulse.seed);
                }
            }
        }
        assert!(
            ExecutionResultCommitment::decode(&norito::encode_canonical(&result).unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
    // A well-shaped pulse for a different parent still cannot authenticate this stored frame.
    let bad = with_parts(&history[4], |header, qc, bytes| {
        let mut result = ExecutionResultCommitment::decode(bytes).unwrap();
        let pulse = result.beacon.as_mut().unwrap();
        pulse.finalized_chain_anchor.block_hash =
            HashOf::from_untyped_unchecked(Hash::new(b"other parent"));
        pulse.pulse_id = crate::beacon::global_threshold_beacon_pulse_id_v1(pulse, pulse.seed);
        *bytes = result.preimage().unwrap();
        *qc = certificate(&keys(false), header, result_of_preimage(bytes), false);
    });
    assert!(matches!(
        read_frame(bad, 5),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Malformed { height: 5, .. }
        ))
    ));
}

#[test]
fn pinned_restoration_reuses_full_boundary_verification_and_one_authority_cursor() {
    let history = history();
    let kura = Kura::blank_kura_for_testing();
    for block in &history {
        kura.store_block(Clone::clone(block)).unwrap();
    }
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = NetworkId::from_genesis_hash(history[0].hash());
    let hashes = history.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let reader = CertifiedChain::from_pinned(
        &chain_id,
        &network,
        &hashes,
        &kura,
        &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
    )
    .unwrap();
    for (index, receipt) in reader.walk(1, 14).enumerate() {
        let receipt = receipt.unwrap();
        assert_eq!(receipt.block_hash(), hashes[index]);
        assert_eq!(
            receipt.verification(),
            if index == 0 {
                QcVerification::Genesis
            } else {
                QcVerification::Verified
            }
        );
    }
    {
        let cursor = reader.prefix.lock();
        let prefix = cursor.as_ref().unwrap();
        assert_eq!(prefix.tip.height(), 14);
        assert_eq!(
            prefix.authority.material.authorization.authority_generation,
            2
        );
        assert!(prefix.schedule.entries().len() <= 3);
    }
    // Old random reads replay the authenticated prefix; no rotated-away roster cache exists.
    assert_eq!(
        reader
            .certified(7)
            .unwrap()
            .commitment()
            .schedule
            .current
            .authorization
            .authority_generation,
        1
    );
    assert_eq!(
        reader
            .certified(14)
            .unwrap()
            .commitment()
            .schedule
            .current
            .authorization
            .authority_generation,
        2
    );
}

#[test]
fn historical_pulse_requires_signed_header_bytes_and_complete_native_context() {
    let history = history();
    let original = &history[4]; // genuine threshold pulse immediately before the first boundary
    let valid = read_frame(original.clone(), 5).unwrap();
    assert!(!valid.header().unwrap().control_witness.is_empty());
    for mutation in 0..3 {
        let corrupt = with_parts(original, |header, qc, bytes| {
            let mut result = ExecutionResultCommitment::decode(bytes).unwrap();
            if mutation == 0 {
                header.control_witness = iroha_sumeragi::types::ControlWitness::empty();
            } else {
                let prior = result.beacon.unwrap();
                let mut context = prior.context;
                if mutation == 1 {
                    context.parent_result[0] ^= 1;
                } else {
                    context.parent_consensus_hash[0] ^= 1;
                }
                let (_, pulses) = crate::beacon::tests::finalized_pulses_fixture_for_context_v1(
                    prior.network_id,
                    prior.session_id,
                    &keys(false),
                    &[(prior.finalized_chain_anchor, context)],
                );
                result.beacon = Some(pulses[0]);
                header.control_witness =
                    crate::sumeragi::epoch_beacon::control::encode(result.beacon).unwrap();
                *bytes = result.preimage().unwrap();
            }
            *qc = certificate(&keys(false), header, result_of_preimage(bytes), false);
        });
        assert!(
            read_frame(corrupt, 5).is_err(),
            "genuine threshold and QC signatures cannot rebind a pulse to another source"
        );
    }
}

/// Boundary-verifier fixture: a canonical complete lane-state write, not an execution corpus.
fn complete_lane_state_witness(network: NetworkId, height: u64) -> ExecWitness {
    let lanes = iroha_data_model::sumeragi_lanes::SumeragiLaneState::default();
    let commitment = iroha_data_model::sumeragi_finality::SumeragiLaneStateCommitment::from_state(
        network, height, &lanes,
    )
    .unwrap();
    ExecWitness {
        writes: vec![iroha_data_model::block::consensus::ExecKv {
            key: iroha_data_model::sumeragi_finality::SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
            value: norito::encode_canonical(&commitment).unwrap(),
        }],
        ..ExecWitness::default()
    }
}

/// Synthetic complete-World roots: these fixtures certify structural results, not a World.
fn synthetic_world() -> crate::sumeragi::commitment::WorldStateTransition {
    crate::sumeragi::commitment::WorldStateTransition {
        parent_world_state_root: iroha_crypto::Hash::new(b"synthetic parent World"),
        world_state_root: iroha_crypto::Hash::new(b"synthetic World"),
        event_commitment: None,
    }
}
