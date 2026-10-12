//! Proof/effect consumer controls over a real paid native chain through genuine due H60.
//! Route and reducer-produced certificate preconditions are installed before genesis only.
//! These tests do not qualify route establishment, live ballot/PQ proofs or emergency-pause
//! creation. No World write, fabricated result or substituted native authority follows certification.

use super::*;
use crate::{
    smartcontracts::isi::sccp::{
        escrow,
        generation_record::RetainedSccpGeneration,
        test_support::{ONE_XOR, outbound_record},
    },
    state::World,
    sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::block::consensus::SumeragiRootScope;
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetId},
    bridge::SccpNetworkV1,
    governance::types::{GovernanceCertificateId, GovernanceCertificateV1},
    isi::{InstructionBox, Mint, Register},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    sccp::{
        deployment::{SccpCommitteePinV1, SccpDeploymentV1, SccpEvmDeploymentV1},
        escrow::sccp_taira_xor_asset_definition_id,
        generation::{SccpCommitteeGenerationV1, SccpGenerationCauseV1},
        governance::{
            SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
            SccpSetDestinationPausedActionV1,
        },
        params::SccpParametersV1,
        registry::{SccpRouteActivationV1, SccpRouteRevisionV1, SccpRouteV1},
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_sccp::v1::finality::verify_certificate;
use iroha_sccp::v1::{
    hashes::history_leaf, history::verify_history_inclusion, merkle::verify_block_inclusion,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    task::{Context, Poll, Waker},
};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;

#[inline(never)]
fn control_chain(branch: bool) -> (Box<CertifiedTestChain>, GovernanceCertificateV1) {
    let key = KeyPair::from_seed(vec![0xce; 32], Algorithm::Ed25519);
    let sender = AccountId::new(key.public_key().clone());
    let xor = sccp_taira_xor_asset_definition_id();
    let mut world = World::with([], [Account::new(sender.clone()).build(&sender)], []);
    let params = SccpParametersV1::taira_default();
    world.sccp_parameters = mv::cell::Cell::new(Some(params));
    world.sccp_reset_nonce = mv::cell::Cell::new(Some([1; 32]));
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_key = key.clone();
    // The H60 reducer fixture below publishes only governance preconditions before
    // genesis. Asset registration and supply belong to the original signed G1,
    // which establishes their canonical AXT incarnation at execution.
    config.genesis_instructions.extend([
        Register::asset_definition(AssetDefinition::new(
            xor.clone(),
            "XOR",
            iroha_primitives::numeric::NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(
            escrow::xor_quantity(1_000 * ONE_XOR).unwrap(),
            AssetId::of(xor, sender.clone()),
        )
        .into(),
    ]);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    config.genesis_block_cadence_ms = 1_000.try_into().unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = sccp_taira_xor_asset_definition_id().canonical_address();
    nexus.staking.unbonding_delay = std::time::Duration::from_millis(
        crate::smartcontracts::isi::sccp::test_support::SCCP_UNBONDING_DELAY_MS,
    );
    nexus.staking.max_slash_bps = 10_000;
    config.nexus = Some(nexus);
    let mut prepared = CertifiedTestChain::prepare(config).expect("original signed Global genesis");
    let original = crate::sumeragi::epoch::authenticated_genesis(prepared.genesis.block()).unwrap();
    let (epoch, scope) = original.into_parts();
    assert_eq!(scope, SumeragiRootScope::Global);
    let time = prepared.genesis.block().header().creation_time_ms;
    let keys = epoch
        .committee
        .iter()
        .map(|member| {
            member
                .validator
                .public_key()
                .try_to_bytes()
                .unwrap()
                .1
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[u8; 48]>>();
    let root =
        iroha_data_model::sumeragi_finality::certified_result::committee_root(&keys).unwrap();
    let generation = SccpCommitteeGenerationV1 {
        generation: 1,
        committee_root: root,
        members: vec![None; keys.len()],
        keys,
        cause: SccpGenerationCauseV1::Genesis,
        start_height: 1,
        start_timestamp_ms: time,
        start_lc: time,
        validity_ms: params.committee_validity_ms,
        deadline_ms: time + params.committee_validity_ms,
        grace_ms: params.forgery_evidence_grace_ms,
        progress_cap_ms: params.destination_progress_cap_ms,
        liable_until_lc: time + params.committee_validity_ms + params.forgery_evidence_grace_ms,
        dest_cleared_lc: None,
        end: None,
    };
    let state = Arc::get_mut(&mut prepared.state).expect("pristine fixture is uniquely owned");
    let budget = state.ivm_execution_budget();
    let retained = RetainedSccpGeneration::admit(&generation, &budget).unwrap();
    state
        .world
        .sccp_committee_generations
        .try_with_admitted_block(|block| {
            block
                .try_insert_admitted(1, retained)
                .map(|_| ())
                .map_err(|(_, error)| error)
        })
        .unwrap();
    state.world.sccp_committee_current = mv::cell::CellInitialization::try_reserve(&budget)
        .unwrap()
        .initialize(1, None);
    state.world.sccp_liability_clock = mv::cell::CellInitialization::try_reserve(&budget)
        .unwrap()
        .initialize(time, None);
    for network in [ETH, BSC] {
        let escrow_id = escrow::escrow_account(&epoch.network_id, network).unwrap();
        let (id, account) = Account::new(escrow_id.clone())
            .build(&escrow_id)
            .into_key_value();
        state.world.accounts.insert(id, account);
        let mut route = SccpRouteV1::empty(network, escrow_id).unwrap();
        let mut revision = SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [if network == ETH { 0xc0 } else { 0xc1 }; 20],
                runtime_code_hash: [0x34; 32],
            }),
            SccpCommitteePinV1 {
                generation: 1,
                committee_root: root,
                start_height: 1,
                until_ms: generation.deadline_ms,
            },
            1_000 * ONE_XOR,
            1,
        );
        revision.activation = SccpRouteActivationV1::Bidirectional;
        revision.ever_activated = true;
        route.revisions.insert(1, revision);
        state.world.sccp_routes.insert(network, route);
    }
    let proposal = SccpGovernanceProposalV1 {
        network_id: epoch.network_id,
        base_revisions: vec![(SccpGovernanceSubjectV1::RouteControl(ETH), 0).into()],
        actions: vec![SccpGovernanceActionV1::SetDestinationPaused(
            SccpSetDestinationPausedActionV1 {
                network: ETH,
                revision: 1,
                paused: true,
            },
        )],
    };
    let mut pause = crate::smartcontracts::isi::sccp::test_support::sample_fast_pause(1);
    pause.enacted_at_ms = time;
    pause.until_ms = time + 120_000;
    let pause = crate::smartcontracts::isi::sccp::pause_record::RetainedSccpFastPause::admit(
        &pause, &budget,
    )
    .unwrap();
    state.world.sccp_fast_pauses.insert(ETH, pause);
    let certificate =
        crate::smartcontracts::isi::world::isi::seed_sccp_native_proof_certificate_before_genesis(
            state, &proposal,
        );
    assert_eq!(certificate.enact_at_height, 60);
    assert!(certificate.certified_at_height < 60);
    assert_eq!(state.view().height(), 0);
    let mut chain = CertifiedTestChain::from_prepared(prepared).expect("genuine original genesis");
    for height in 2..=61 {
        let mut instructions: Vec<InstructionBox> = vec![
            iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                if branch && height == 61 {
                    "alternate paid native branch"
                } else {
                    "paid control predecessor"
                }
                .to_owned(),
            )
            .into(),
        ];
        if height == 60 || height == 61 {
            for recipient in [[0x71; 20], [0x72; 20]] {
                let mut message = outbound_record(1, recipient);
                message.network = BSC;
                instructions.push(message.into());
            }
        }
        let time = height * 1_000;
        let valid = paid(&chain, &key, instructions, time);
        let expected = if height == 60 {
            // First leaf write in this paid transaction must disappear on the second
            // instruction's actual route-revision rejection. The block-start control survives.
            let mut first = outbound_record(1, [0xfa; 20]);
            first.network = BSC;
            let mut refused = outbound_record(1, [0xfb; 20]);
            refused.network = BSC;
            refused.expected_revision = 2;
            let failed = paid(&chain, &key, [first.into(), refused.into()], time + 1);
            assert_eq!(chain.commit_at(time, vec![failed, valid]), [false, true]);
            2
        } else {
            assert_eq!(chain.commit_at(time, vec![valid]), [true]);
            1
        };
        let native = chain.committed(height);
        for position in 0..expected {
            let output = native.block().network_output_at(position).unwrap().1;
            let fee = output
                .result
                .nexus_fee_receipt()
                .expect("actual signed paid native transaction");
            assert_eq!(fee.block_height, height);
            assert_eq!(fee.fee_asset_id, sccp_taira_xor_asset_definition_id());
            assert_eq!(
                fee.debit_source,
                iroha_data_model::nexus::FeeDebitSource::Account(sender.clone())
            );
            assert!(!fee.fee_amount.is_zero());
        }
        if height == 60 {
            let view = chain.state().view();
            let row = store::control_messages::get(view.world(), &(ETH, 1, 1)).unwrap();
            assert_eq!((row.height, row.commitment_index), (60, 0));
            assert_eq!(
                row.certificate_id,
                *GovernanceCertificateId::derive_v1(&certificate).as_bytes()
            );
            assert_eq!(row.effect_hash, certificate.effect_preimage_hash);
            assert!(row.parliament_paused);
            assert!(row.fast_pause_until_ms > time);
            assert_eq!(
                store::block_commitments::get(view.world(), &60)
                    .unwrap()
                    .message_count,
                3
            );
            assert_eq!(
                store::outbound_messages::len(view.world()),
                2,
                "failed transaction published no prefix"
            );
            assert_eq!(
                store::routes::get(view.world(), &BSC).unwrap().revisions[&1].next_outbound_nonce,
                2
            );
        }
    }
    (Box::new(chain), certificate)
}

fn paid(
    chain: &CertifiedTestChain,
    key: &KeyPair,
    instructions: impl IntoIterator<Item = InstructionBox>,
    created_ms: u64,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions);
    builder.set_creation_time(std::time::Duration::from_millis(created_ms));
    let draft = builder.clone().sign(key.private_key());
    let view = chain.state().view();
    let quote = crate::executor::quote_nexus_fee_admission_draft(
        view.world(),
        view.nexus(),
        view.pipeline(),
        &view.zk().gas,
        draft.payload(),
        created_ms,
        crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original committed fixture time"),
        chain.height() + 1,
        Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
    )
    .expect("the original funded sender can pay exact signed message fee bounds");
    assert!(!quote.recommended_intent.charge_limits().is_empty());
    builder
        .with_fee_payment_intent(quote.recommended_intent)
        .sign(key.private_key())
}

#[test]
fn native_control_binds_due_certificate_paid_rollback_and_current_fields_to_original_x() {
    let (chain, cause) = control_chain(false);
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let budget = chain.state().ivm_execution_budget();
    let cache_budget = AllocationBudget::new(1 << 20);
    let mut cache = SccpHistoryNodeCache::new();
    let expected_id = *GovernanceCertificateId::derive_v1(&cause).as_bytes();
    let row = *store::control_messages::get(view.world(), &(ETH, 1, 1)).unwrap();
    assert_ne!(expected_id, *cause.proposal_content_id.as_bytes());
    assert_eq!(store::control_messages::len(view.world()), 1);
    assert_eq!(store::outbound_messages::len(view.world()), 4);
    for height in [60, 61] {
        let native = reader.certified(height).unwrap();
        let occupied = budget.reserved_bytes();
        let retained = control_proof_from_native(
            &view,
            (ETH, 1, 1),
            &native,
            &mut cache,
            &cache_budget,
            &budget,
        )
        .unwrap();
        let proof = retained.bundle();
        assert_eq!(
            (proof.network, proof.revision, proof.control_nonce),
            (ETH, 1, 1)
        );
        assert_eq!(
            (
                proof.track,
                proof.parliament_paused,
                proof.fast_pause_until_ms
            ),
            (1, true, row.fast_pause_until_ms)
        );
        assert_eq!(proof.certificate_id, expected_id);
        assert_eq!(proof.effect_hash, cause.effect_preimage_hash);
        assert_eq!(
            (
                proof.block.height,
                proof.block.message_count,
                proof.leaf_index
            ),
            (60, 3, 0)
        );
        assert_eq!(
            &proof.certificate.header,
            native.certified_result().header().as_bytes()
        );
        assert_eq!(proof.certificate.height, height);
        let revision = &store::routes::get(view.world(), &ETH).unwrap().revisions[&1];
        let original_fields = ControlLeafV1 {
            route_revision: proof.revision,
            control_nonce: proof.control_nonce,
            track: proof.track,
            parliament_paused: u8::from(proof.parliament_paused),
            fast_pause_until_ms: proof.fast_pause_until_ms,
            certificate_id: proof.certificate_id,
            effect_hash: proof.effect_hash,
        };
        let leaf = control_leaf(
            view.network_id().as_bytes(),
            ETH,
            &revision.destination_word,
            &original_fields,
        )
        .unwrap();
        assert_eq!(leaf, row.leaf);
        verify_block_inclusion(
            &leaf,
            proof.leaf_index,
            proof.block.message_count,
            &proof.path,
            &proof.block.sccp_root,
        )
        .unwrap();
        for changed in [
            ControlLeafV1 {
                certificate_id: *cause.proposal_content_id.as_bytes(),
                ..original_fields
            },
            ControlLeafV1 {
                effect_hash: [0x65; 32],
                ..original_fields
            },
            ControlLeafV1 {
                fast_pause_until_ms: 0,
                ..original_fields
            },
            ControlLeafV1 {
                parliament_paused: 0,
                ..original_fields
            },
            ControlLeafV1 {
                control_nonce: 2,
                ..original_fields
            },
            ControlLeafV1 {
                route_revision: 2,
                ..original_fields
            },
            ControlLeafV1 {
                track: 2,
                ..original_fields
            },
        ] {
            let wrong = control_leaf(
                view.network_id().as_bytes(),
                ETH,
                &revision.destination_word,
                &changed,
            )
            .unwrap();
            assert_ne!(wrong, leaf);
            assert!(
                verify_block_inclusion(
                    &wrong,
                    proof.leaf_index,
                    proof.block.message_count,
                    &proof.path,
                    &proof.block.sccp_root
                )
                .is_err()
            );
        }
        if height == 60 {
            assert!(proof.block.history_path.is_empty());
            assert_eq!(proof.block.history_index, 0);
            assert_eq!(
                proof.block.sccp_root,
                native.certified_result().header().sccp_root()
            );
        } else {
            assert_eq!(proof.block.history_index, 0);
            assert!(!proof.block.history_path.is_empty());
            verify_history_inclusion(
                &history_leaf(60, &proof.block.sccp_root, 3),
                proof.block.history_index,
                native.certified_result().header().history_size(),
                &proof.block.history_path,
                &native.certified_result().header().history_root(),
            )
            .unwrap();
        }
        let verified = verify_certificate(
            &native.commit_qc().unwrap().instance.0,
            &proof.certificate.qc,
            &proof.certificate.header,
            &proof.certificate.aggregate_signature,
            &proof.certificate.committee,
        )
        .unwrap();
        assert_eq!(verified.result, native.result().0);
        let bytes = 32 * (proof.path.capacity() + proof.block.history_path.capacity())
            + 48 * proof.certificate.committee.capacity();
        assert_eq!(budget.reserved_bytes(), occupied + bytes);
        proof.check_shape().unwrap();
        drop(retained);
        assert_eq!(budget.reserved_bytes(), occupied);
    }
    let native = reader.certified(59).unwrap();
    let occupied = budget.reserved_bytes();
    assert!(matches!(
        control_proof_from_native(
            &view,
            (ETH, 1, 1),
            &native,
            &mut cache,
            &cache_budget,
            &budget
        ),
        Err(SccpProofReadError::Source("control record shape or height"))
    ));
    for absent in [
        (ETH, 1, 2),
        (ETH, 2, 1),
        (BSC, 1, 1),
        (SccpNetworkV1::SoraTaira, 1, 1),
    ] {
        assert!(matches!(
            control_proof_from_native(&view, absent, &native, &mut cache, &cache_budget, &budget),
            Err(SccpProofReadError::Missing("control record"))
        ));
    }
    assert_eq!(budget.reserved_bytes(), occupied);
    drop(cache);
    assert_eq!(cache_budget.reserved_bytes(), 0);
}

#[test]
fn native_control_capacity_preserves_original_wait_retry_and_unwind_custody() {
    let (chain, _) = control_chain(false);
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let native = reader.certified(61).unwrap();
    let original = *native.certified_result().header().as_bytes();
    let budget = chain.state().ivm_execution_budget();
    let mut registration = budget
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut waiter = ReleaseRegistration::from_reservation(&mut registration).unwrap();
    drop(registration);
    let occupied = budget.reserved_bytes();
    let external = budget
        .try_reserve_bytes(budget.limit_bytes() - occupied)
        .unwrap();
    let mut cache = SccpHistoryNodeCache::new();
    let error =
        control_proof_from_native(&view, (ETH, 1, 1), &native, &mut cache, &budget, &budget)
            .err()
            .unwrap();
    let SccpProofReadError::Admission(AllocationRefusal::Capacity {
        release,
        reserved_bytes,
        limit_bytes,
        ..
    }) = &error
    else {
        panic!("original source lost: {error:?}")
    };
    assert_eq!(*reserved_bytes, budget.limit_bytes());
    assert_eq!(*limit_bytes, budget.limit_bytes());
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Pending);
    assert_eq!(native.certified_result().header().as_bytes(), &original);
    drop(external);
    assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Ready(()));
    let proof =
        control_proof_from_native(&view, (ETH, 1, 1), &native, &mut cache, &budget, &budget)
            .unwrap();
    assert_eq!(proof.bundle().certificate.header, original);
    drop(proof);
    assert_eq!(budget.reserved_bytes(), occupied);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let proof = control_proof_from_native(
                &view,
                (ETH, 1, 1),
                &native,
                &mut cache,
                &budget,
                &budget,
            )
            .unwrap();
            assert_eq!(proof.bundle().block.height, 60);
            assert!(budget.reserved_bytes() > occupied);
            panic!("retained native control owner unwinds");
        }))
        .is_err()
    );
    assert_eq!(budget.reserved_bytes(), occupied);
    // A controlled unwind after actual certificate/path/scratch allocations must also
    // refund the partial graph, with no cache publication or lost original native owner.
    let row = *store::control_messages::get(view.world(), &(ETH, 1, 1)).unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let source = NativeProofSource::new(&view, &native).unwrap();
            let _partial = membership::assemble(
                view.world(),
                source,
                SelectedLeaf {
                    kind: SelectedKind::Control(ETH, 1, 1),
                    height: row.height,
                    index: row.commitment_index,
                    hash: row.leaf,
                },
                &mut cache,
                &budget,
                &budget,
                (1, |reservation| -> Result<(), SccpProofReadError> {
                    let mut backing =
                        iroha_allocation::ChargedBuffer::from_reservation(1, reservation)?;
                    backing.push_reserved(1_u8);
                    assert!(budget.reserved_bytes() > occupied);
                    panic!("partial membership construction after original physical allocations");
                }),
            );
        }))
        .is_err()
    );
    assert_eq!(budget.reserved_bytes(), occupied);
    assert_eq!(native.certified_result().header().as_bytes(), &original);
    let final_retry =
        control_proof_from_native(&view, (ETH, 1, 1), &native, &mut cache, &budget, &budget)
            .unwrap();
    assert_eq!(final_retry.bundle().certificate.header, original);
    drop(final_retry);
    drop(cache);
    assert_eq!(budget.reserved_bytes(), occupied);
    waiter.cancel();
}

#[test]
fn native_control_rejects_genuine_other_branch_with_same_instance_and_control_root() {
    let (chain, _) = control_chain(false);
    let (other, _) = control_chain(true);
    assert_eq!(chain.genesis().hash(), other.genesis().hash());
    let view = chain.state().view();
    let other_view = other.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let other_reader = CertifiedChain::new(&other_view).unwrap();
    let original = reader.certified(61).unwrap();
    let foreign = other_reader.certified(61).unwrap();
    assert_eq!(
        original.commit_qc().unwrap().instance,
        foreign.commit_qc().unwrap().instance
    );
    assert_ne!(original.block_hash(), foreign.block_hash());
    assert_eq!(
        original.certified_result().header().history_root(),
        foreign.certified_result().header().history_root()
    );
    assert_eq!(
        original.certified_result().header().sccp_root(),
        foreign.certified_result().header().sccp_root()
    );
    let budget = chain.state().ivm_execution_budget();
    let occupied = budget.reserved_bytes();
    let mut cache = SccpHistoryNodeCache::new();
    assert!(matches!(
        control_proof_from_native(&view, (ETH, 1, 1), &foreign, &mut cache, &budget, &budget),
        Err(SccpProofReadError::Source(
            "native receipt is not in the captured committed prefix"
        ))
    ));
    assert_eq!(budget.reserved_bytes(), occupied);
    let proof =
        control_proof_from_native(&view, (ETH, 1, 1), &original, &mut cache, &budget, &budget)
            .unwrap();
    assert_eq!(proof.bundle().control_nonce, 1);
    drop((proof, cache));
    assert_eq!(budget.reserved_bytes(), occupied);
}

mod lapse;
