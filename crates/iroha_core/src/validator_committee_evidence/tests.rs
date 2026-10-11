//! Native committee evidence with exact BLS quorums, neutral generations and real DKG.
//! The constructed transcript tests offline proof admission; it does not execute NPoS custody
//! transitions or qualify a network. Genesis is actually signed; no height-one QC is fabricated.
//! Every successor binds its real resultless payload and original proposer-signed RS16 availability.

use super::*;
use crate::{
    state::{WorldReadOnly as _, threshold_key_lifecycle_certificate_preimage_v1},
    sumeragi::{
        commitment::{ExecutionResultCommitment, execution_commitment, result_of_preimage},
        crypto::{BlsCrypto, KeyPairSigner, core_key},
        payload,
        schedule::{self, ChainParamsRecord, ScheduleOutcome, ScheduledConfig, ScheduledSlot},
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_data_model::{
    block::{
        CommitCertificate, SignedBlock,
        consensus::ExecWitness,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
    },
    consensus::{GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1},
    isi::consensus_keys::ThresholdKeyLifecycleSignatureV1,
    nexus::ValidatorCommitteeSelectionStatusV1,
    parameter::system::{ConsensusMode, SumeragiNposParameters},
    sumeragi::{
        epoch::{ValidatorEpochBoundaryV1, ValidatorEpochContextV1},
        finality::NativeFinalityArtifact,
    },
    transaction::signed::TransactionResult,
};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::{Signer as _, form_qc},
    message::{BlockHeader, Vote, VoteKind},
    preimage::payload_hash,
    types::{ChainParams, Hash32},
};
use mv::storage::StorageReadOnly as _;
use std::{num::NonZeroU64, time::Duration};

fn chain_id() -> ChainId {
    ChainId::from("native-committee-evidence-tests")
}
fn limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 4 * 1024 * 1024,
        journal_bytes: 64 * 1024 * 1024,
        block_count: 64,
        allocated_bytes: 512 * 1024 * 1024,
    }
}
fn validate_anchor(journal: &NativeFinalityJournal, network: NetworkId) {
    let genesis = journal.blocks[0].decode_block(limits()).unwrap();
    assert_eq!(genesis.hash(), network.into_genesis_hash());
    let instance = crate::sumeragi::node::root_instance(&genesis, &chain_id().to_string()).unwrap();
    assert_ne!(instance, Hash32::ZERO);
}
fn outputs(block: &mut SignedBlock) {
    let values = (0..block.external_transactions().count())
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
            values,
            0,
            Default::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            &crate::execution_output_test_support::structural_output_limits(),
        )
        .unwrap();
}
fn outcome(
    height: u64,
    current: &ValidatorEpochContextV1,
    boundary: Option<ValidatorEpochBoundaryV1>,
) -> ScheduleOutcome {
    let authorized = boundary.as_ref().map_or(current, |value| &value.next);
    let slot = |height| {
        let params = ChainParamsRecord::from_core(&ChainParams {
            epoch_length: 10,
            ..ChainParams::default()
        });
        if height <= authorized.authorization.last_height {
            ScheduledSlot::Ready(ScheduledConfig {
                height,
                epoch: authorized.clone(),
                params,
            })
        } else {
            ScheduledSlot::PendingBoundary {
                height,
                boundary_height: authorized.authorization.last_height,
                predecessor_context_id: authorized.context_id().unwrap(),
                params,
            }
        }
    };
    ScheduleOutcome {
        height,
        current: current.clone(),
        next: slot(height + 1),
        after_next: slot(height + 2),
        boundary,
    }
}

/// Author a structural offline proposal from its actual signed root and retained parent.
/// This fixture has no executed successor World from which production routing can be read.
fn offline_proposal(
    genesis: &SignedBlock,
    parent: &SignedBlock,
    input: crate::tx::AcceptedTransaction<'static>,
) -> Result<SignedBlock, String> {
    let epoch = crate::sumeragi::epoch::authenticated_genesis(genesis)
        .map(|genesis| genesis.into_parts().0)
        .map_err(|error| error.to_string())?;
    let network = match input.entrypoint() {
        iroha_data_model::transaction::TransactionEntrypoint::External(transaction) => {
            transaction.network_id()
        }
        iroha_data_model::transaction::TransactionEntrypoint::SealedCommitment(commitment) => {
            Some(&commitment.payload().network_id)
        }
        iroha_data_model::transaction::TransactionEntrypoint::SealedReveal(reveal) => {
            reveal.signed_transaction().network_id()
        }
    };
    if network != Some(&epoch.network_id) {
        return Err("offline input does not belong to its original signed genesis".into());
    }
    let scope = iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(genesis)
        .map_err(|error| error.to_string())?
        .sumeragi_context
        .root_scope;
    let context = iroha_data_model::block::BlockExecutionContextBundle::new(vec![
        iroha_data_model::block::ExternalExecutionContext::new(
            input.hash_as_entrypoint(),
            iroha_model_base::topology::LaneId::SINGLE,
            scope.dataspace_id(),
        ),
    ]);
    let time = parent
        .header()
        .creation_time()
        .checked_add(Duration::from_millis(1))
        .ok_or("offline parent clock overflows")?;
    let (_, clock) = iroha_primitives::time::TimeSource::new_mock(time);
    Ok(
        crate::block::BlockBuilder::new_with_time_source(vec![input], clock)
            .chain(0, Some(parent))
            .with_execution_context(Some(context))
            .with_network_input_time_floor(time)
            .ok_or("offline input clock overflows")?
            .into_unsigned_proposal(),
    )
}

fn certify(keys: &[KeyPair], header: &BlockHeader, bytes: &[u8]) -> iroha_sumeragi::message::Qc {
    let crypto = BlsCrypto::new();
    let pops = keys
        .iter()
        .map(|key| iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap())
        .collect::<Vec<_>>();
    crypto
        .admit_committee(
            keys.iter()
                .zip(&pops)
                .map(|(key, pop)| (key.public_key(), pop.as_slice())),
        )
        .unwrap();
    let votes = (0..3)
        .map(|index| {
            let mut vote = Vote {
                kind: VoteKind::Commit,
                instance: header.instance,
                epoch: header.epoch,
                height: header.height,
                view: 0,
                block_hash: header.hash(&crypto),
                result: result_of_preimage(bytes),
                signer: index,
                sig: iroha_sumeragi::types::Signature([0; iroha_sumeragi::types::SIGNATURE_LEN]),
            };
            vote.sig = KeyPairSigner::new(&keys[index as usize])
                .unwrap()
                .sign(&vote.preimage());
            vote
        })
        .collect::<Vec<_>>();
    form_qc(&crypto, 4, &votes.iter().collect::<Vec<_>>()).unwrap()
}
fn evidence_fixture() -> ValidatorCommitteeProvisioningEvidenceV1 {
    use crate::beacon::{
        GlobalThresholdBeaconPartialSignerV1 as _, GlobalThresholdBeaconPulseAggregatorV1,
    };
    let mut keys = (1..=4)
        .map(|index| KeyPair::from_seed(vec![index; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| core_key(key.public_key()).unwrap());
    let validators = keys
        .iter()
        .map(|key| {
            (
                PeerId::new(key.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let mut policy = SumeragiNposParameters::default();
    policy.epoch_length_blocks = NonZeroU64::new(10).unwrap();
    policy.evidence_horizon_blocks = 10;
    policy.slashing_delay_blocks = 10;
    let mut genesis = crate::sumeragi::test_chain::signed_genesis_fixture(
        &chain_id(),
        &KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519),
        &validators,
        Vec::new(),
        1000,
        ConsensusMode::Npos,
        Some(policy),
    )
    .unwrap();
    let network = NetworkId::from_genesis_hash(genesis.hash());
    let instance = crate::sumeragi::node::root_instance(&genesis, &chain_id().to_string()).unwrap();
    let mut current = crate::sumeragi::epoch::authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let state = crate::state::State::new_with_chain_and_network_id_for_testing(
        World::new(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
        chain_id(),
        network,
    );
    let witness = complete_context_witness(network, 1);
    outputs(&mut genesis);
    let initial = ExecutionResultCommitment::new(
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
    let mut parent_result = result_of_preimage(&initial.preimage().unwrap());
    genesis = genesis.with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        Vec::new(),
        Vec::new(),
        initial.preimage().unwrap(),
        Vec::new(), // Genesis is the signed root, not a native proposal.
    )));
    let mut parent_core = Hash32(*network.as_bytes());
    let mut history = vec![crate::block::reserve_block_for_tests().initialize(genesis)];
    let mut boundary_pulse = None;
    let mut selected_fixture = None;
    let beacon_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    for height in 2..=14 {
        let parent = history.last().unwrap();
        let signer = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
        let mut builder = iroha_data_model::transaction::TransactionBuilder::new(
            network,
            iroha_data_model::account::AccountId::new(signer.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(parent.header().creation_time());
        let input = builder
            .with_instructions([iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                format!("offline committee transcript {height}"),
            )])
            .sign(signer.private_key());
        let mut block = offline_proposal(
            &history[0],
            parent,
            crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(input)),
        )
        .unwrap();
        outputs(&mut block);
        let context = GlobalThresholdBeaconPulseContextV1 {
            instance: instance.0,
            epoch: current.authorization.epoch,
            epoch_context_id: current.context_id().unwrap(),
            parent_consensus_hash: parent_core.0,
            parent_result: parent_result.0,
        };
        let pulse = if height == 9 {
            let fixture = crate::state::validator_committee::tests::fixture_with_native_selection(
                7,
                network,
                block.hash(),
                [0x31; 32],
            );
            let old = fixture
                .world
                .view()
                .global_beacon_key_sessions()
                .get(&[0x71; 32])
                .unwrap()
                .session
                .adaptive_dkg
                .session;
            let (session, signers) =
                crate::beacon::prepared_session_and_signers_fixture_for_keys_v1(
                    old,
                    &keys,
                    &beacon_budget,
                );
            let mut reducer = GlobalThresholdBeaconPulseAggregatorV1::new(
                session.clone(),
                height,
                GlobalThresholdBeaconChainAnchorV1 {
                    height: height - 1,
                    block_hash: parent.hash(),
                },
                context,
            )
            .unwrap();
            for signer in signers.iter().take(2) {
                reducer
                    .accept_partial(signer.sign_partial(&session, reducer.payload()).unwrap())
                    .unwrap();
            }
            Some(reducer.finalize().unwrap())
        } else {
            None
        };
        let boundary = if height == 10 {
            let pulse = boundary_pulse.as_ref().unwrap();
            let seed = crate::sumeragi::epoch_election::election_seed(network, 0, pulse).unwrap();
            let fixture = crate::state::validator_committee::tests::fixture_with_native_selection(
                7,
                network,
                parent.hash(),
                seed,
            );
            assert_eq!(fixture.incumbent, current.generation());
            let next = ValidatorEpochContextV1 {
                da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
                version: 1,
                network_id: network,
                mode: ConsensusMode::Npos,
                authorization: fixture.authorization,
                committee: current.committee.clone(),
                leader_seed: crate::beacon::global_threshold_beacon_npos_successor_seed_v1(
                    pulse, height, 1,
                ),
            };
            let boundary = ValidatorEpochBoundaryV1 {
                version: 1,
                height,
                predecessor_context_id: current.context_id().unwrap(),
                selection_anchor: parent.hash(),
                next,
                preparation: Some(fixture.transition.preparation.clone()),
            };
            selected_fixture = Some(fixture);
            Some(boundary)
        } else {
            None
        };
        let payload = payload::encode(&block).unwrap();
        let header = BlockHeader {
            instance,
            epoch: schedule::core_epoch(&current).unwrap().id,
            height,
            origin_view: 0,
            parent_hash: parent_core,
            parent_result,
            payload_hash: payload_hash(&BlsCrypto::new(), &payload),
            payload_len: u32::try_from(payload.len()).unwrap(),
            availability_digest: Hash32::ZERO,
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: crate::sumeragi::epoch_beacon::control::encode(pulse).unwrap(),
        };
        let config = ScheduledConfig {
            height,
            epoch: current.clone(),
            params: ChainParamsRecord::from_core(&ChainParams {
                epoch_length: 10,
                ..ChainParams::default()
            }),
        }
        .height_config()
        .unwrap();
        let budget = state.ivm_execution_budget();
        let mut backing = iroha_allocation::ChargedBuffer::new(payload.len(), &budget).unwrap();
        backing.append(&payload).unwrap();
        let charged_payload = PayloadBytes::from_charged(backing, &budget)
            .unwrap_or_else(|_| panic!("original committee fixture payload admission"));
        let crypto = BlsCrypto::new();
        crypto
            .admit_committee(current.committee.iter().map(|member| {
                (
                    member.validator.public_key(),
                    member.proof_of_possession.as_slice(),
                )
            }))
            .unwrap();
        let signer = KeyPairSigner::new(&keys[0]).unwrap();
        let authored = PayloadAuthoring::new(header, charged_payload)
            .complete(instance, &config, &budget, &crypto, &signer)
            .unwrap_or_else(|(_, error)| {
                panic!("original committee signed RS16 authoring: {error:?}")
            });
        assert!(authored.body.admitted_to(&budget));
        assert_eq!(authored.body.source().config(), &config);
        assert_eq!(authored.body.payload().as_slice(), payload);
        assert!(!authored.body.availability().as_slice().is_empty());
        let header = authored.body.header().clone();
        let availability = norito::encode_canonical(authored.body.availability()).unwrap();
        let witness = complete_context_witness(network, height);
        let result = ExecutionResultCommitment::new(
            height,
            execution_commitment(&witness, &block, &synthetic_world()).unwrap(),
            outcome(height, &current, boundary.clone()),
            pulse,
            iroha_data_model::sumeragi_finality::NativeLaneStateProof::from_witness(
                &witness,
                &iroha_allocation::AllocationBudget::new(64 * 1024),
            )
            .unwrap(),
        )
        .unwrap();
        let preimage = result.preimage().unwrap();
        let qc = certify(&keys, &header, &preimage);
        block = block.with_commit_certificate(Some(
            crate::sumeragi::block_store::commit_certificate(&header, &qc, preimage, availability)
                .unwrap(),
        ));
        parent_core = header.hash(&BlsCrypto::new());
        parent_result = qc.result;
        history.push(crate::block::reserve_block_for_tests().initialize(block));
        if let Some(pulse) = pulse {
            boundary_pulse = Some(pulse);
        }
        if let Some(boundary) = boundary {
            current = boundary.next;
        }
    }
    let fixture = selected_fixture.unwrap();
    let prep = &fixture.transition.preparation;
    let view = fixture.world.view();
    let record = view
        .global_beacon_key_sessions()
        .get(&prep.beacon_session_id().unwrap())
        .unwrap();
    let BeaconEpochBindingV1::Installed(active) = fixture.authorization.beacon else {
        unreachable!()
    };
    let mut certificate = ThresholdKeyLifecycleCertificateV1 {
        version: 1,
        action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        expected_active_session_id: Some(active.session_id),
        effective_height: 14,
        network_id: network,
        roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(
            &validators.iter().map(|v| v.0.clone()).collect::<Vec<_>>(),
        ),
        committee_size: 4,
        quorum: 3,
        session_id: record.session.session_id,
        transcript_hash: record.session.transcript_hash,
        public_state: norito::encode_canonical(record).unwrap(),
        signatures: Vec::new(),
    };
    let preimage = threshold_key_lifecycle_certificate_preimage_v1(&certificate).unwrap();
    certificate.signatures = keys
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, key)| ThresholdKeyLifecycleSignatureV1 {
            signer_index: index as u16,
            signature: Signature::new(key.private_key(), &preimage),
        })
        .collect();
    let blocks = history
        .iter()
        .map(|block| NativeFinalityArtifact::from_block(block, limits()).unwrap())
        .collect::<Vec<_>>();
    ValidatorCommitteeProvisioningEvidenceV1 {
        status: ValidatorCommitteeStatusV1 {
            network_id: network,
            target_epoch: 2,
            latest_finality: blocks[13].clone(),
            selected: Some(ValidatorCommitteeSelectionStatusV1 {
                transition: fixture.transition.clone(),
                selecting_finality: blocks[9].clone(),
            }),
            pending_beacon_session: Some(record.session.record().clone()),
        },
        finality_journal: NativeFinalityJournal { blocks },
        beacon_finalization: certificate,
    }
}

fn selection_evidence_fixture() -> ValidatorCommitteeSelectionEvidenceV1 {
    let fixture = evidence_fixture();
    let mut status = fixture.status;
    let selected = status.selected.as_mut().expect("frozen selection fixture");
    selected.transition.credentials = None;
    selected.transition.readiness.clear();
    status.pending_beacon_session = None;
    ValidatorCommitteeSelectionEvidenceV1 {
        status,
        finality_journal: fixture.finality_journal,
    }
}

#[test]
fn committee_boundary_requires_exact_native_quorum() {
    let evidence = evidence_fixture();
    let selecting = &evidence
        .status
        .selected
        .as_ref()
        .unwrap()
        .selecting_finality;
    let block = selecting.decode_block(limits()).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header: BlockHeader = norito::decode_canonical(certificate.consensus_header()).unwrap();
    let result = ExecutionResultCommitment::decode(certificate.result_preimage()).unwrap();
    let qc: iroha_sumeragi::message::Qc =
        norito::decode_canonical(certificate.commit_qc()).unwrap();
    assert_eq!(header.height, 10);
    assert!(result.schedule.boundary.is_some());

    assert_eq!(qc.signers.count_ones(), 3);

    let mut keys = (1..=4_u8)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let current = &result.schedule.current;
    assert_eq!(
        keys.iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
        current
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect::<Vec<_>>()
    );
    let crypto = BlsCrypto::new();
    let committee = iroha_data_model::sumeragi_finality::global_committee(
        crypto
            .admit_committee(current.committee.iter().map(|member| {
                (
                    member.validator.public_key(),
                    member.proof_of_possession.as_slice(),
                )
            }))
            .unwrap(),
    )
    .unwrap();
    let epoch = schedule::core_epoch(current).unwrap();
    let verifier =
        iroha_sumeragi::crypto::Verifier::new(&crypto, &header.instance, &epoch.id, &committee);
    assert_eq!(verifier.verify_qc(&qc), Ok(()));
    let resign = |qc: &mut iroha_sumeragi::message::Qc, count: usize| {
        qc.signers =
            iroha_sumeragi::types::Bitmap::from_indices(4, (0..count).map(|index| index as u32))
                .unwrap();
        let signatures = keys
            .iter()
            .take(count)
            .map(|key| Signature::try_new(key.private_key(), &qc.preimage()).unwrap())
            .collect::<Vec<_>>();
        qc.agg_sig = iroha_sumeragi::types::AggregateSignature(
            iroha_crypto::bls_normal_aggregate_signatures(
                &signatures
                    .iter()
                    .map(Signature::payload)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .try_into()
            .unwrap(),
        );
    };
    let mut insufficient = qc.clone();
    resign(&mut insufficient, 2);
    assert!(verifier.verify_qc(&insufficient).is_err());
    let mut oversized = qc.clone();
    resign(&mut oversized, 4);
    assert!(verifier.verify_qc(&oversized).is_err());
    let mut foreign = qc;
    foreign.instance.0[0] ^= 1;
    resign(&mut foreign, 3);
    assert!(verifier.verify_qc(&foreign).is_err());
}

#[test]
fn offline_committee_proposal_retains_signed_root_and_refuses_foreign_network_input() {
    let key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
    let genesis = crate::sumeragi::test_chain::signed_genesis_fixture(
        &chain_id(),
        &key,
        &crate::sumeragi::test_chain::fixture_validators(),
        Vec::new(),
        1000,
        ConsensusMode::Permissioned,
        None,
    )
    .unwrap();
    let network = NetworkId::from_genesis_hash(genesis.hash());
    let input = |network| {
        let mut builder = iroha_data_model::transaction::TransactionBuilder::new(
            network,
            iroha_data_model::account::AccountId::new(key.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(genesis.header().creation_time());
        crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(
            builder
                .with_instructions([iroha_data_model::isi::Log::new(
                    iroha_data_model::Level::INFO,
                    "offline original root".to_owned(),
                )])
                .sign(key.private_key()),
        ))
    };
    let original = input(network);
    let hash = original.hash_as_entrypoint();
    let input_time = original.entrypoint().creation_time_ms().unwrap();
    let genesis_input_floor = genesis
        .external_transactions()
        .map(|transaction| transaction.creation_time() + Duration::from_millis(1))
        .max()
        .expect("the original signed genesis has real inputs");
    assert_eq!(genesis.header().creation_time(), genesis_input_floor);
    assert_eq!(
        Duration::from_millis(input_time),
        genesis.header().creation_time()
    );
    let proposal = offline_proposal(&genesis, &genesis, original).unwrap();
    assert_eq!(proposal.header().height().get(), 2);
    assert_eq!(proposal.header().prev_block_hash(), Some(genesis.hash()));
    assert_eq!(
        proposal.header().creation_time(),
        genesis.header().creation_time() + Duration::from_millis(1)
    );
    assert_eq!(
        proposal.execution_context().unwrap().external,
        vec![iroha_data_model::block::ExternalExecutionContext::new(
            hash,
            iroha_model_base::topology::LaneId::SINGLE,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )]
    );
    assert!(proposal.is_resultless_proposal());
    assert_eq!(
        payload::decode(&payload::encode(&proposal).unwrap()).unwrap(),
        proposal
    );
    assert!(
        offline_proposal(
            &genesis,
            &genesis,
            input(NetworkId::from_genesis_hash(
                HashOf::from_untyped_unchecked(Hash::new(b"foreign offline signed root",))
            )),
        )
        .is_err()
    );
    let foreign_key = KeyPair::from_seed(vec![0xCF; 32], Algorithm::Ed25519);
    let mut substituted_root = genesis.clone();
    substituted_root
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([
                iroha_data_model::block::BlockSignature::new(
                    0,
                    iroha_crypto::SignatureOf::try_from_hash(
                        foreign_key.private_key(),
                        genesis.hash(),
                    )
                    .unwrap(),
                ),
            ])
            .expect("at most 31 block signatures"),
        )
        .unwrap();
    assert!(offline_proposal(&substituted_root, &genesis, input(network)).is_err());
}

#[test]
fn selection_evidence_authenticates_only_frozen_roster_before_any_dkg_credentials() {
    let session_budget = AllocationBudget::new(limits().allocated_bytes);
    let evidence = selection_evidence_fixture();
    let network = evidence.status.network_id;
    let chain_id = chain_id();
    validate_anchor(&evidence.finality_journal, network);
    let preparation = &evidence
        .status
        .selected
        .as_ref()
        .expect("selection")
        .transition
        .preparation;
    let attempt = preparation.transition_id().unwrap();
    let verify = |evidence: &ValidatorCommitteeSelectionEvidenceV1| {
        verify_validator_committee_selection_evidence_v1(
            evidence,
            &chain_id,
            network,
            2,
            attempt,
            limits(),
            &session_budget,
        )
    };
    let selected = verify(&evidence).expect("contiguous incumbent-certified E+1 selection");
    assert_eq!(selected.preparation(), preparation);
    assert_eq!(selected.observed_height(), 14);
    assert_eq!(selected.incumbent_authority().validators.len(), 4);
    assert_ne!(
        selected.incumbent_beacon().session_id,
        selected.preparation().beacon_session_id().unwrap()
    );
    assert!(
        verify_validator_committee_provisioning_evidence_v1(
            &ValidatorCommitteeProvisioningEvidenceV1 {
                status: evidence.status.clone(),
                finality_journal: evidence.finality_journal.clone(),
                beacon_finalization: evidence_fixture().beacon_finalization,
            },
            &chain_id,
            network,
            2,
            attempt,
            limits(),
            &session_budget,
        )
        .is_err(),
        "selection-only proof cannot authorize private-share import"
    );
    let binary = norito::encode_canonical(&evidence).unwrap();
    assert_eq!(
        norito::decode_canonical::<ValidatorCommitteeSelectionEvidenceV1>(&binary).unwrap(),
        evidence
    );
    let json = norito::json::to_vec(&evidence).unwrap();
    assert_eq!(
        norito::json::from_slice::<ValidatorCommitteeSelectionEvidenceV1>(&json).unwrap(),
        evidence
    );
    for mutation in 0..5 {
        let mut changed = evidence.clone();
        match mutation {
            0 => {
                changed
                    .status
                    .selected
                    .as_mut()
                    .unwrap()
                    .transition
                    .preparation
                    .election_seed[0] ^= 1
            }
            1 => changed.status.latest_finality.block_wire.push(0),
            2 => {
                changed.finality_journal.blocks.remove(1);
            }
            3 => changed
                .status
                .selected
                .as_mut()
                .unwrap()
                .selecting_finality
                .block_wire
                .push(0),
            _ => {
                changed.finality_journal.blocks[9].block_wire.push(0);
            }
        }
        assert!(verify(&changed).is_err(), "selection mutation {mutation}");
    }
    assert!(
        verify_validator_committee_selection_evidence_v1(
            &evidence,
            &ChainId::from("foreign-configured-chain"),
            network,
            2,
            attempt,
            limits(),
            &session_budget,
        )
        .is_err()
    );
    assert!(
        verify_validator_committee_selection_evidence_v1(
            &evidence,
            &chain_id,
            network,
            3,
            attempt,
            limits(),
            &session_budget,
        )
        .is_err()
    );
    assert!(
        verify_validator_committee_selection_evidence_v1(
            &evidence,
            &chain_id,
            network,
            2,
            [0xEE; 32],
            limits(),
            &session_budget,
        )
        .is_err()
    );
}

#[test]
fn committee_custody_evidence_authenticates_exact_pending_attempt_and_rejects_substitution() {
    let session_budget = AllocationBudget::new(limits().allocated_bytes);
    let evidence = evidence_fixture();
    let network = evidence.status.network_id;
    let chain_id = chain_id();
    validate_anchor(&evidence.finality_journal, network);
    let attempt = evidence
        .status
        .selected
        .as_ref()
        .unwrap()
        .transition
        .preparation
        .transition_id()
        .unwrap();
    let verify = |evidence: &ValidatorCommitteeProvisioningEvidenceV1| {
        verify_validator_committee_provisioning_evidence_v1(
            evidence,
            &chain_id,
            network,
            2,
            attempt,
            limits(),
            &session_budget,
        )
    };
    let accepted = verify(&evidence).unwrap();
    assert_eq!(accepted.observed_height(), 14);
    assert_eq!(
        accepted.session().record(),
        evidence.status.pending_beacon_session.as_ref().unwrap()
    );
    assert_eq!(accepted.transition().preparation.target_epoch, 2);
    assert_eq!(accepted.incumbent_authority().validators.len(), 4);
    assert_ne!(
        accepted.incumbent_beacon().session_id,
        accepted.session().session_id
    );
    let binary = norito::encode_canonical(&evidence).unwrap();
    assert_eq!(
        norito::decode_canonical::<ValidatorCommitteeProvisioningEvidenceV1>(&binary).unwrap(),
        evidence
    );
    let json = norito::json::to_vec(&evidence).unwrap();
    assert_eq!(
        norito::json::from_slice::<ValidatorCommitteeProvisioningEvidenceV1>(&json).unwrap(),
        evidence
    );
    for mutation in 0..10 {
        let mut changed = evidence.clone();
        match mutation {
            0 => changed
                .beacon_finalization
                .signatures
                .pop()
                .map(|_| ())
                .unwrap(),
            1 => changed.beacon_finalization.expected_active_session_id = Some([0xEE; 32]),
            2 => changed.beacon_finalization.transcript_hash[0] ^= 1,
            3 => {
                changed.finality_journal.blocks.remove(1);
            }
            4 => changed
                .status
                .selected
                .as_mut()
                .unwrap()
                .transition
                .preparation
                .committee
                .swap(0, 1),
            5 => {
                changed
                    .status
                    .pending_beacon_session
                    .as_mut()
                    .unwrap()
                    .session_id[0] ^= 1
            }
            6 => {
                changed
                    .status
                    .selected
                    .as_mut()
                    .unwrap()
                    .selecting_finality
                    .block_wire
                    .push(1);
            }
            7 => changed.status.latest_finality.block_wire.push(0),
            8 => {
                changed
                    .status
                    .selected
                    .as_mut()
                    .unwrap()
                    .transition
                    .readiness[0]
                    .beacon
                    .proof
                    .z_s[0] ^= 1
            }
            _ => {
                changed
                    .status
                    .selected
                    .as_mut()
                    .unwrap()
                    .transition
                    .credentials
                    .as_mut()
                    .unwrap()
                    .beacon
                    .transcript_hash[0] ^= 1
            }
        }
        assert!(verify(&changed).is_err(), "mutation {mutation}");
    }
    assert!(
        verify_validator_committee_provisioning_evidence_v1(
            &evidence,
            &ChainId::from("foreign-configured-chain"),
            network,
            2,
            attempt,
            limits(),
            &session_budget,
        )
        .is_err()
    );
    assert!(
        verify_validator_committee_provisioning_evidence_v1(
            &evidence,
            &chain_id,
            network,
            3,
            attempt,
            limits(),
            &session_budget,
        )
        .is_err()
    );
    assert!(
        verify_validator_committee_provisioning_evidence_v1(
            &evidence,
            &chain_id,
            network,
            2,
            [0xEE; 32],
            limits(),
            &session_budget,
        )
        .is_err()
    );
}

#[test]
fn committee_custody_evidence_retains_original_session_refusal_and_retries_unchanged_proof() {
    use crate::beacon::{
        GlobalThresholdBeaconSessionBindingV1, global_threshold_beacon_session_allocation_bytes_v1,
    };
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::task::{Context, Waker};

    let evidence = evidence_fixture();
    let network = evidence.status.network_id;
    let chain_id = chain_id();
    validate_anchor(&evidence.finality_journal, network);
    let attempt = evidence
        .status
        .selected
        .as_ref()
        .unwrap()
        .transition
        .preparation
        .transition_id()
        .unwrap();
    let source = evidence.status.pending_beacon_session.as_ref().unwrap();
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: source.network_id,
        session_id: source.session_id,
        roster_hash: source.roster_hash,
        transcript_hash: source.transcript_hash,
    };
    let demand = global_threshold_beacon_session_allocation_bytes_v1(source, &binding).unwrap();
    let observer_bytes = ReleaseRegistration::allocation_layout().size();
    let journal_count = evidence.finality_journal.blocks.len();
    let journal_controls =
        journal_count * iroha_data_model::block::SharedSignedBlock::allocation_layout().size();
    // The sole native verifier retains both actual ordered index arrays while constructing
    // the session. Their exact layouts are separate from each shared block control.
    let journal_index = std::alloc::Layout::array::<iroha_data_model::block::SharedSignedBlock>(
        journal_count,
    )
    .unwrap()
    .size()
        + std::alloc::Layout::array::<iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>>(
            journal_count,
        )
        .unwrap()
        .size();
    let journal_owners = journal_controls + journal_index;
    let pool = AllocationBudget::new(demand + journal_owners + observer_bytes);
    let mut observer = crate::unit_test_support::release_registration(&pool);
    let blocker = pool.try_reserve_bytes(1).unwrap();
    let expected = pool.try_reserve_bytes(demand + journal_owners).unwrap_err();
    let verify = || {
        verify_validator_committee_provisioning_evidence_v1(
            &evidence,
            &chain_id,
            network,
            2,
            attempt,
            limits(),
            &pool,
        )
    };
    let Err(ValidatorCommitteeProvisioningEvidenceError::Session(
        GlobalThresholdBeaconSessionError::Admission(actual),
    )) = verify()
    else {
        panic!("the verifier must preserve its original session admission refusal");
    };
    let AllocationRefusal::Capacity {
        release: expected_release,
        ..
    } = expected
    else {
        panic!("actual held capacity");
    };
    let AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    } = actual
    else {
        panic!("a held original pool must carry its exact release source");
    };
    assert_eq!(requested_bytes, demand);
    assert_eq!(reserved_bytes, observer_bytes + journal_owners + 1);
    assert_eq!(limit_bytes, pool.limit_bytes());
    assert_eq!(release, expected_release);
    assert_eq!(pool.reserved_bytes(), observer_bytes + 1);
    let mut context = Context::from_waker(Waker::noop());
    // Returning the failed attempt retires its temporary journal controls and index arrays. That is an
    // original-pool refund, not authority to assume enough capacity for the whole next proof.
    assert!(observer.poll_wait(&release, &mut context).is_ready());
    assert!(matches!(
        verify(),
        Err(ValidatorCommitteeProvisioningEvidenceError::Session(
            GlobalThresholdBeaconSessionError::Admission(AllocationRefusal::Capacity { .. })
        ))
    ));
    drop(blocker);
    assert!(observer.poll_wait(&release, &mut context).is_ready());
    observer.cancel();
    let verified = verify().expect("the identical authorized proof retries after actual refund");
    assert!(verified.session().belongs_to(&pool));
    assert_eq!(verified.session().record(), source);
    let shared = verified.session().clone();
    assert!(std::ptr::eq(shared.record(), verified.session().record()));
    let retained = pool.reserved_bytes();
    assert!(retained > observer_bytes);
    drop(verified);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(shared);
    assert_eq!(pool.reserved_bytes(), observer_bytes);
    drop(observer);
    assert_eq!(pool.reserved_bytes(), 0);

    let mut invalid = evidence.clone();
    invalid.beacon_finalization.expected_active_session_id = None;
    assert!(matches!(
        verify_validator_committee_provisioning_evidence_v1(
            &invalid,
            &chain_id,
            network,
            2,
            attempt,
            limits(),
            &pool,
        ),
        Err(ValidatorCommitteeProvisioningEvidenceError::Invalid(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn status_selection_binding_uses_the_same_actual_native_boundary_as_custody() {
    let evidence = selection_evidence_fixture();
    validate_anchor(&evidence.finality_journal, evidence.status.network_id);
    with_verified_native_journal(
        (&evidence.finality_journal).into(),
        &chain_id(),
        &evidence.status.network_id,
        limits(),
        &AllocationBudget::new(limits().allocated_bytes),
        |reader| {
            let latest = reader.certified(14).map_err(NativeJournalError::History)?;
            let selecting = reader.certified(10).map_err(NativeJournalError::History)?;
            let before = reader.certified(9).map_err(NativeJournalError::History)?;
            let selection = &evidence.status.selected.as_ref().unwrap().transition;
            validate_validator_committee_selection_binding_v1(selection, &selecting, &latest, 2)?;
            assert!(
                validate_validator_committee_selection_binding_v1(selection, &before, &latest, 2)
                    .is_err(),
                "ordinary result cannot stand in for a boundary"
            );
            assert!(
                validate_validator_committee_selection_binding_v1(
                    selection, &selecting, &latest, 3
                )
                .is_err()
            );
            for mutation in 0..4 {
                let mut changed = selection.clone();
                match mutation {
                    0 => changed.preparation.election_seed[0] ^= 1,
                    1 => {
                        changed.preparation.selection_anchor = HashOf::from_untyped_unchecked(
                            Hash::new(b"foreign selection predecessor"),
                        )
                    }
                    2 => changed.preparation.selection_height += 1,
                    _ => changed.preparation.preparing_authorization_id[0] ^= 1,
                }
                assert!(
                    validate_validator_committee_selection_binding_v1(
                        &changed, &selecting, &latest, 2
                    )
                    .is_err(),
                    "status binding mutation {mutation}"
                );
            }
            Ok(())
        },
    )
    .expect("genuine native prefix");
}

/// Complete-set proof fixture derived from an actual canonical ordinary write.
fn complete_context_witness(network: NetworkId, height: u64) -> ExecWitness {
    let contexts = iroha_data_model::sumeragi_lanes::SumeragiLaneState::default();
    let commitment = iroha_data_model::sumeragi_finality::SumeragiLaneStateCommitment::from_state(
        network, height, &contexts,
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

#[test]
fn verified_rotation_attempt_uses_exact_native_selection_source_and_original_wider_cutoff() {
    // Genuine signed native proof/selection verification through the maintained
    // producer. This structural proof fixture does not claim a real World execution
    // or network restart; those remain whole-candidate qualification boundaries.
    let evidence = selection_evidence_fixture();
    let network = evidence.status.network_id;
    let chain_id = chain_id();
    let budget = AllocationBudget::new(limits().allocated_bytes);
    let preparation = &evidence
        .status
        .selected
        .as_ref()
        .unwrap()
        .transition
        .preparation;
    validate_anchor(&evidence.finality_journal, network);
    let selected = verify_validator_committee_selection_evidence_v1(
        &evidence,
        &chain_id,
        network,
        2,
        preparation.transition_id().unwrap(),
        limits(),
        &budget,
    )
    .unwrap();
    let mut clock = crate::sumeragi::native_journal::NativeJournalCursor::new(
        chain_id.clone(),
        network,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits(),
        &budget,
    )
    .unwrap();
    clock.advance((&evidence.finality_journal).into()).unwrap();
    let authority =
        crate::beacon::AuthenticatedGlobalBeaconDkgAttemptV1::rotation(&selected, &clock).unwrap();
    assert_eq!(authority.session().start_height, selected.observed_height());
    assert_eq!(
        authority.session().attempt_id,
        preparation.transition_id().unwrap()
    );
    assert_eq!(
        authority.session().session_id,
        preparation.beacon_session_id().unwrap()
    );
    assert_eq!(
        authority.session().authority_generation,
        preparation.authority_generation
    );
    assert_eq!(authority.cutoff(), preparation.first_height - 1);
    assert!(authority.session().acceptances_end_height < authority.cutoff());
    let empty = crate::sumeragi::native_journal::NativeJournalCursor::new(
        chain_id,
        network,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits(),
        &budget,
    )
    .unwrap();
    assert!(
        crate::beacon::AuthenticatedGlobalBeaconDkgAttemptV1::rotation(&selected, &empty).is_err()
    );
}
