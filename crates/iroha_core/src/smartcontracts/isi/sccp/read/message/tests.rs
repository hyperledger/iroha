//! Genuine native message execution, certification, proof binding and response custody.
//!
//! Route/generation preconditions are installed in the existing pristine State fixture seam
//! before genesis execution. This qualifies the proof producer, not route establishment:
//! RegisterRoute remains fail-closed. No State writes occur after native certification.

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
    asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetId},
    bridge::SccpNetworkV1,
    isi::InstructionBox,
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    sccp::{
        deployment::{SccpCommitteePinV1, SccpDeploymentV1, SccpEvmDeploymentV1},
        escrow::sccp_taira_xor_asset_definition_id,
        generation::{SccpCommitteeGenerationV1, SccpGenerationCauseV1},
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

#[inline(never)]
fn message_chain(branch: bool) -> Box<CertifiedTestChain> {
    let key = KeyPair::from_seed(vec![0xce; 32], Algorithm::Ed25519);
    let sender = AccountId::new(key.public_key().clone());
    let xor = sccp_taira_xor_asset_definition_id();
    let definition = AssetDefinition::new(
        xor.clone(),
        "XOR",
        iroha_primitives::numeric::NumericSpec::fractional(9),
        AssetBalancePolicy::Global,
        None,
    )
    .build(&sender);
    let mut world = World::with_assets(
        [],
        [Account::new(sender.clone()).build(&sender)],
        [definition],
        [Asset::new(
            AssetId::of(xor, sender.clone()),
            escrow::xor_quantity(100 * ONE_XOR).unwrap(),
        )],
        [],
    );
    let params = SccpParametersV1::taira_default();
    world.sccp_parameters = mv::cell::Cell::new(Some(params));
    world.sccp_reset_nonce = mv::cell::Cell::new(Some([1; 32]));
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_key = key.clone();
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
    let escrow_id = escrow::escrow_account(&epoch.network_id, ETH).unwrap();
    let (id, account) = Account::new(escrow_id.clone())
        .build(&escrow_id)
        .into_key_value();
    state.world.accounts.insert(id, account);
    let mut route = SccpRouteV1::empty(ETH, escrow_id).unwrap();
    let mut revision = SccpRouteRevisionV1::staged(
        1,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [0xc0; 20],
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
    state.world.sccp_routes.insert(ETH, route);
    assert_eq!(state.view().height(), 0);
    let mut chain =
        CertifiedTestChain::from_prepared(prepared).expect("execute and certify original genesis");
    let first = sign_paid_messages(
        &chain,
        &key,
        [
            outbound_record(1, [0x11; 20]).into(),
            outbound_record(2, [0x12; 20]).into(),
            outbound_record(3, [0x13; 20]).into(),
        ],
        2_000,
    );
    assert_eq!(
        chain.commit_at(2_000, vec![first]),
        [true],
        "original transaction output: {:?}",
        chain.committed(2).block().network_output_at(0)
    );
    let second = sign_paid_messages(
        &chain,
        &key,
        [
            outbound_record(4, [0x14; 20]).into(),
            iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                if branch {
                    "alternate certified branch"
                } else {
                    "original certified branch"
                }
                .to_owned(),
            )
            .into(),
        ],
        3_000,
    );
    assert_eq!(
        chain.commit_at(3_000, vec![second]),
        [true],
        "original transaction output: {:?}",
        chain.committed(3).block().network_output_at(0)
    );
    for height in [2, 3] {
        let committed = chain.committed(height);
        let output = committed.block().network_output_at(0).unwrap().1;
        let fee = output
            .result
            .nexus_fee_receipt()
            .expect("signed message work pays its fee");
        assert_eq!(fee.block_height, height);
        assert_eq!(fee.fee_asset_id, sccp_taira_xor_asset_definition_id());
        assert_eq!(
            fee.debit_source,
            iroha_data_model::nexus::FeeDebitSource::Account(sender.clone())
        );
        assert_eq!(
            fee.settlement,
            iroha_data_model::block::consensus::NexusFeeSettlementV1::Burn
        );
        assert!(!fee.fee_amount.is_zero());
    }
    Box::new(chain)
}

fn sign_paid_messages(
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

#[inline(never)]
fn with_messages(assert_original: fn(&CertifiedTestChain, [u8; 32], [u8; 32])) {
    let chain = message_chain(false);
    let (first, second) = {
        let view = chain.state().view();
        assert_eq!(*store::degraded_run::get(view.world()), 0);
        (
            *store::outbound_by_nonce::get(view.world(), &(ETH, 1, 2)).unwrap(),
            *store::outbound_by_nonce::get(view.world(), &(ETH, 1, 3)).unwrap(),
        )
    };
    assert_original(&chain, first, second);
}

#[test]
fn native_message_binds_real_odd_leaf_path_and_older_history_to_original_x() {
    with_messages(|chain, first, second| {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let native = reader.certified(3).unwrap();
        assert!(native.certified_result().header().is_active());
        let cache_budget = AllocationBudget::new(1 << 20);
        let request = chain.state().ivm_execution_budget();
        let occupied = request.reserved_bytes();
        let mut cache = SccpHistoryNodeCache::new();
        for (id, expected_height, expected_count, index) in [(first, 2, 3, 2), (second, 3, 1, 0)] {
            let retained =
                message_proof_from_native(&view, &id, &native, &mut cache, &cache_budget, &request)
                    .unwrap();
            let proof = retained.bundle();
            assert_eq!(proof.message_id, id);
            assert_eq!(proof.block.height, expected_height);
            assert_eq!(proof.block.message_count, expected_count);
            assert_eq!(proof.leaf_index, index);
            assert_eq!(proof.certificate.height, native.height());
            assert_eq!(
                &proof.certificate.header,
                native.certified_result().header().as_bytes()
            );
            let decoded = SccpTransferPayloadRefV1::decode(&proof.payload).unwrap();
            assert_eq!(proof.deadline_ms, decoded.deadline_ms);
            assert_eq!(
                message_id(
                    &decoded.lane_bytes(view.network_id().as_bytes()).unwrap(),
                    &payload_hash(&proof.payload)
                ),
                id
            );
            let revision = &store::routes::get(view.world(), &ETH).unwrap().revisions[&1];
            let leaf = transfer_leaf(&id, &revision.destination_word);
            verify_block_inclusion(
                &leaf,
                proof.leaf_index,
                proof.block.message_count,
                &proof.path,
                &proof.block.sccp_root,
            )
            .unwrap();
            if expected_height == native.height() {
                assert_eq!(
                    proof.block.sccp_root,
                    native.certified_result().header().sccp_root()
                );
                assert_eq!(proof.block.history_index, 0);
                assert!(proof.block.history_path.is_empty());
            } else {
                assert_eq!(proof.block.history_index, 0);
                assert!(!proof.block.history_path.is_empty());
                verify_history_inclusion(
                    &history_leaf(expected_height, &proof.block.sccp_root, expected_count),
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
            let bytes = proof.payload.capacity()
                + 32 * (proof.path.capacity() + proof.block.history_path.capacity())
                + 48 * proof.certificate.committee.capacity();
            assert_eq!(request.reserved_bytes(), occupied + bytes);
            drop(retained);
            assert_eq!(request.reserved_bytes(), occupied);
        }
        drop(cache);
        assert_eq!(cache_budget.reserved_bytes(), 0);
    });
}

#[test]
fn native_message_capacity_refusal_keeps_original_wait_and_same_receipt_retry() {
    with_messages(|chain, id, _| {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let native = reader.certified(3).unwrap();
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
        let error = message_proof_from_native(&view, &id, &native, &mut cache, &budget, &budget)
            .err()
            .unwrap();
        let SccpProofReadError::Admission(AllocationRefusal::Capacity {
            release,
            reserved_bytes,
            limit_bytes,
            ..
        }) = &error
        else {
            panic!("lost original refusal: {error:?}")
        };
        assert_eq!(*reserved_bytes, budget.limit_bytes());
        assert_eq!(*limit_bytes, budget.limit_bytes());
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Pending);
        assert_eq!(native.certified_result().header().as_bytes(), &original);
        drop(external);
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Ready(()));
        let retained =
            message_proof_from_native(&view, &id, &native, &mut cache, &budget, &budget).unwrap();
        assert_eq!(retained.bundle().certificate.header, original);
        drop(retained);
        drop(cache);
        assert_eq!(budget.reserved_bytes(), occupied);
        waiter.cancel();
    });
}

#[test]
fn native_message_missing_or_future_record_refuses_and_final_owner_unwind_refunds() {
    with_messages(|chain, first, second| {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let native = reader.certified(2).unwrap();
        let budget = chain.state().ivm_execution_budget();
        let occupied = budget.reserved_bytes();
        let mut cache = SccpHistoryNodeCache::new();
        assert!(matches!(
            message_proof_from_native(&view, &[0; 32], &native, &mut cache, &budget, &budget),
            Err(SccpProofReadError::Missing("outbound message"))
        ));
        assert!(matches!(
            message_proof_from_native(&view, &second, &native, &mut cache, &budget, &budget),
            Err(SccpProofReadError::Source("record height or payload size"))
        ));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let retained =
                    message_proof_from_native(&view, &first, &native, &mut cache, &budget, &budget)
                        .unwrap();
                assert_eq!(retained.bundle().block.height, 2);
                assert!(budget.reserved_bytes() > occupied);
                panic!("final native message owner unwinds");
            }))
            .is_err()
        );
        assert_eq!(budget.reserved_bytes(), occupied);
    });
}

#[test]
fn native_message_rejects_a_genuine_other_branch_with_the_same_history_and_instance() {
    with_messages(|chain, id, _| {
        let other = message_chain(true);
        assert_eq!(chain.genesis().hash(), other.genesis().hash());
        let view = chain.state().view();
        let other_view = other.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let other_reader = CertifiedChain::new(&other_view).unwrap();
        let original = reader.certified(3).unwrap();
        let foreign = other_reader.certified(3).unwrap();
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
        let pool = chain.state().ivm_execution_budget();
        let before = pool.reserved_bytes();
        let mut cache = SccpHistoryNodeCache::new();
        assert!(matches!(
            message_proof_from_native(&view, &id, &foreign, &mut cache, &pool, &pool),
            Err(SccpProofReadError::Source(
                "native receipt is not in the captured committed prefix"
            ))
        ));
        assert_eq!(pool.reserved_bytes(), before);
        let proof =
            message_proof_from_native(&view, &id, &original, &mut cache, &pool, &pool).unwrap();
        assert_eq!(proof.bundle().message_id, id);
        drop((proof, cache));
        assert_eq!(pool.reserved_bytes(), before);
    });
}
