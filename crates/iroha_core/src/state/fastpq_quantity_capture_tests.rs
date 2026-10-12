//! Actual owner capture, rollback and explicit refusal of incomplete quantity coverage.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore, smartcontracts::Execute};
use iroha_data_model::{
    account::Account,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition},
    block::{BlockExecutionContextBundle, ExternalExecutionContext, builder::BlockBuilder},
    domain::Domain,
    isi::{Burn, Mint, Register, Transfer, Unregister, error::InstructionExecutionError},
    prelude::{InstructionBox, TransactionBuilder},
    transaction::{FeePaymentIntent, SignedTransaction},
};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};
use std::{num::NonZeroU64, time::Duration};

fn fixture() -> (State, AssetId, AssetId) {
    let domain = DomainId::try_new("quantity-capture", "universal").unwrap();
    let definition = AssetDefinitionId::derive_from_components(domain, "units".parse().unwrap());
    fixture_with_asset_definition(definition)
}

fn fixture_with_asset_definition(definition: AssetDefinitionId) -> (State, AssetId, AssetId) {
    fixture_with_bob_balance(definition, None)
}

fn fixture_with_bob_balance(
    definition: AssetDefinitionId,
    bob_balance: Option<Quantity>,
) -> (State, AssetId, AssetId) {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let fees = &mut state.nexus.get_mut().fees;
    fees.base_fee = Quantity::zero();
    fees.per_byte_fee = Quantity::zero();
    fees.per_instruction_fee = Quantity::zero();
    fees.per_gas_unit_fee = Quantity::zero();
    let domain = DomainId::try_new("quantity-capture", "universal").unwrap();
    let alice = AssetId::of(definition.clone(), ALICE_ID.clone());
    let bob = AssetId::of(definition.clone(), BOB_ID.clone());
    {
        let mut setup = state.block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0));
        let mut transaction = setup.transaction_for_callback_testing();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        Register::account(Account::new(BOB_ID.clone()))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        Register::domain(Domain::new(domain))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        Register::asset_definition(AssetDefinition::numeric(
            definition,
            "Units",
            AssetBalancePolicy::Global,
            None,
        ))
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
        Mint::asset_quantity(10_u32, alice.clone())
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        if let Some(amount) = bob_balance {
            if amount.is_zero() {
                // Setup-only persisted zero: the producer under test is signed below.
                transaction.world.assets.insert(
                    bob.clone(),
                    iroha_data_model::asset::AssetValue::new(amount),
                );
            } else {
                Mint::asset_quantity(amount, bob.clone())
                    .execute(&ALICE_ID, &mut transaction)
                    .unwrap();
            }
        }
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let state = authenticate_quantity_state(state);
    (state, alice, bob)
}

/// Retain the component setup, then authenticate the original Network root.
fn authenticate_quantity_state(component: State) -> State {
    use crate::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let nexus = component.nexus_snapshot();
    let mut config = TestChainConfig::new(component.world, 0);
    config.chain_id = component.chain_id;
    config.pipeline = component.pipeline;
    config.governance = Some(component.gov);
    config.nexus = Some(nexus);
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("prepare quantity signed genesis");
    let state = Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished quantity State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_account,
        mode.into(),
        None,
    )
    .expect("apply quantity signed genesis");
    state
}

fn quantity_successor_header(state: &State) -> BlockHeader {
    let view = state.view();
    let parent = view
        .latest_block()
        .expect("completed original State read")
        .expect("original quantity genesis");
    let time_ms = u64::try_from(parent.header().creation_time().as_millis())
        .expect("quantity fixture timestamp fits")
        + 2;
    BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(parent.hash()),
        None,
        time_ms,
        0,
    )
}

#[test]
fn quantity_fixture_preserves_balances_and_original_authenticated_network_root() {
    let (state, alice, bob) = fixture();
    let view = state.view();
    assert_eq!(view.height(), 1);
    assert_eq!(view.kura().blocks_count(), 1);
    let parent = view.latest_block_hash().expect("original quantity genesis");
    assert_eq!(state.network_id_ref().into_genesis_hash(), parent);
    assert_eq!(
        quantity_successor_header(&state).prev_block_hash(),
        Some(parent)
    );
    assert!(
        quantity_successor_header(&state).creation_time()
            > view
                .latest_block()
                .expect("completed original State read")
                .unwrap()
                .header()
                .creation_time()
    );
    assert_eq!(
        view.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(10_u32)
    );
    assert!(view.world.assets.get(&bob).is_none());
    assert_eq!(
        view.world
            .asset_definitions
            .get(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
    assert!(state.nexus_snapshot().fees.base_fee.is_zero());
    assert!(crate::sumeragi::lanes::routing::committed_root_scope(view.world()).is_some());
}

fn source(state: &State, body: Vec<InstructionBox>) -> (SignedBlock, Hash) {
    source_with_fee(state, body, FeePaymentIntent::authority(vec![], None))
}

fn quantity_execution_context(
    state: &State,
    transaction: &SignedTransaction,
    header: &BlockHeader,
) -> ExternalExecutionContext {
    let accepted =
        crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Borrowed(transaction));
    let view = state.view();
    let snapshot = crate::sumeragi::lanes::routing::RoutingSnapshot::of(&view)
        .expect("quantity fixture reads its original committed routing");
    let native = snapshot
        .inputs(view.world())
        .execution_route(&accepted, header.height().get())
        .expect("quantity fixture completes its committed routing read")
        .expect("quantity input retains its exact committed native route");
    ExternalExecutionContext::new(
        accepted.hash_as_entrypoint(),
        native.lane_id,
        native.dataspace_id,
    )
}

fn source_with_fee(
    state: &State,
    body: Vec<InstructionBox>,
    fee: FeePaymentIntent,
) -> (SignedBlock, Hash) {
    let mut transaction = TransactionBuilder::new(state.network_id, ALICE_ID.clone(), fee);
    transaction.set_creation_time(
        quantity_successor_header(state).creation_time() - Duration::from_millis(1),
    );
    let transaction = transaction
        .with_instructions(body)
        .sign(ALICE_KEYPAIR.private_key());
    let hash =
        Hash::from(TransactionEntrypoint::External(transaction.clone()).execution_call_hash());
    let header = quantity_successor_header(state);
    let context = quantity_execution_context(state, &transaction, &header);
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(Some(BlockExecutionContextBundle::new(vec![context])));
    builder.push_transaction(transaction);
    (
        builder.build_with_signature(0, ALICE_KEYPAIR.private_key()),
        hash,
    )
}

#[test]
fn original_block_start_world_owners_preserve_exact_quantity_lineage() {
    let (state, alice, _) = fixture();
    let (source, _) = source(&state, vec![Mint::asset_quantity(1_u32, alice).into()]);
    let mut pristine = None;
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |block| {
                pristine = Some((
                    block.world.assets.write_observation(),
                    block.world.asset_definitions.write_observation(),
                    block.fastpq_quantity_candidate.applied_world_transactions,
                ));
                Ok::<(), String>(())
            },
            |error| error,
        )
        .unwrap();
    assert_eq!(pristine, Some(((false, 0), (false, 0), 0)));
    let expected = block.fastpq_quantity_candidate.applied_world_transactions;
    assert!(
        expected >= 2,
        "both original World-only start owners applied"
    );
    assert_eq!(block.world.assets.write_observation(), (false, expected));
    assert_eq!(
        block.world.asset_definitions.write_observation(),
        (false, expected)
    );
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

#[test]
fn classified_original_world_child_keeps_metadata_rollback_and_restored_raw_write_facts() {
    for raw_write in [false, true] {
        for apply in [false, true] {
            with_signed_quantity_block(|block, alice, _, _| {
                let original_count = block.fastpq_quantity_candidate.applied_world_transactions;
                let key: iroha_model_base::name::Name = "quantity_child_metadata".parse().unwrap();
                let value = iroha_primitives::json::Json::new("original child");
                let mut world = block
                    .world
                    .transaction_without_telemetry(LaneConfig::default(), 0);
                assert!(
                    world
                        .account_mut(&ALICE_ID)
                        .unwrap()
                        .insert(key.clone(), value.clone())
                        .is_none()
                );
                if raw_write {
                    let balance = world.assets.get_mut(alice).unwrap();
                    **balance = Quantity::from(99_u32);
                    **balance = Quantity::from(9_u32);
                }
                let mut pending = QuantityCandidateArchive::default();
                pending.observe(&world);
                if apply {
                    world.apply();
                    block.fastpq_quantity_candidate.apply(pending);
                } else {
                    drop(world);
                    drop(pending);
                }
                block.observe_quantity_block_journals();
                assert_eq!(
                    block.fastpq_quantity_candidate.applied_world_transactions,
                    original_count + u64::from(apply)
                );
                assert_eq!(
                    block.fastpq_quantity_candidate.issue,
                    (raw_write && apply).then_some(QuantityCaptureIssue::UnownedMutation)
                );
                assert_eq!(
                    block.world.account(&ALICE_ID).unwrap().metadata().get(&key),
                    apply.then_some(&value)
                );
                assert_eq!(
                    block.world.assets.get(alice).unwrap().as_ref(),
                    &Quantity::from(9_u32)
                );
            });
        }
    }
}

#[test]
fn signed_quantity_source_without_execution_context_is_rejected_before_execution() {
    let (state, alice, bob) = fixture();
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
    let (valid, _) = source(
        &state,
        vec![Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into()],
    );
    assert!(valid.execution_context().is_some());
    let original = valid.external_transactions().next().unwrap();
    let mut builder = BlockBuilder::new(quantity_successor_header(&state));
    builder.push_transaction(original.clone());
    let missing = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    assert!(missing.execution_context().is_none());
    assert!(missing.header().execution_context_hash().is_none());
    assert_eq!(missing.external_transactions().next().unwrap(), original);
    assert_ne!(valid.hash(), missing.hash());
    let (mut block, recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &missing,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&missing).unwrap();
    let fragments = block.committed_fragment_count();
    let error = block
        .execute_ordinary_output_plan(&missing, None)
        .unwrap_err();
    assert!(
        matches!(error, super::ExecutionOutputAttemptError::Owner(reason)
            if reason == "Network source has an invalid execution context")
    );
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(10_u32)
    );
    assert!(block.world.assets.get(&bob).is_none());
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert!(block.retained_execution_outputs_for_test().is_err());
    drop(block);
    drop(recording);
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
        before,
    );
    let view = state.view();
    assert_eq!(view.height(), 1);
    assert_eq!(view.kura().blocks_count(), 1);
    assert_eq!(
        view.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(10_u32)
    );
    assert!(view.world.assets.get(&bob).is_none());
}

#[test]
fn actual_signed_interleaving_keeps_scoped_lifecycle_and_complete_order_without_export() {
    let (state, alice, bob) = fixture();
    let (source, call) = source(
        &state,
        vec![
            Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into(),
            Mint::asset_quantity(5_u32, alice.clone()).into(),
            Burn::asset_quantity(1_u32, alice.clone()).into(),
            Transfer::asset_quantity(alice.clone(), 2_u32, BOB_ID.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(11_u32)
    );
    assert_eq!(
        block.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::from(3_u32)
    );
    let candidate = &block.fastpq_quantity_candidate;
    assert_exact_applied_measurement(candidate);
    assert_eq!(candidate.issue, None);
    assert_eq!(candidate.entries.len(), 1);
    let entry = &candidate.entries[&call];
    assert_eq!(
        entry
            .effects
            .iter()
            .map(|effect| effect.ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    assert_eq!(entry.context.entry.entry_hash, call);
    let token = *block
        .world
        .axt_asset_incarnations
        .get(alice.definition())
        .unwrap();
    for effect in &entry.effects {
        assert_eq!(
            effect.authority_digest,
            crate::fastpq::authority_digest(&ALICE_ID)
        );
        let balance = match &effect.kind {
            FastpqExecutionEffectKindV1::Transfer(effect) => &effect.source,
            FastpqExecutionEffectKindV1::Mint(effect)
            | FastpqExecutionEffectKindV1::Burn(effect) => &effect.balance,
            FastpqExecutionEffectKindV1::Retire(_) => panic!("this fixture contains no retirement"),
        };
        assert_eq!(balance.asset.incarnation, token);
        assert_eq!(balance.asset.definition, *alice.definition());
        assert_eq!(balance.scope, AssetBalanceScope::Global);
    }
    assert!(matches!(
        entry.effects[1].kind,
        FastpqExecutionEffectKindV1::Mint(_)
    ));
    assert!(matches!(
        entry.effects[2].kind,
        FastpqExecutionEffectKindV1::Burn(_)
    ));
    assert_eq!(
        candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

#[test]
fn rejected_signed_body_drops_captured_facts_and_unsupported_mutation_observation() {
    let (state, alice, _) = fixture();
    let (source, _) = source(
        &state,
        vec![
            Mint::asset_quantity(5_u32, alice.clone()).into(),
            Unregister::asset_definition(alice.definition().clone()).into(),
            Mint::asset_quantity(1_u32, alice.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(10_u32)
    );
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
    assert_eq!(
        block.fastpq_quantity_candidate.usage,
        QuantityCandidateUsage::default()
    );
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

#[test]
fn unsupported_actual_mutation_poison_applies_and_rolls_back_with_world() {
    let (state, alice, _) = fixture();
    let mut block = state.block(quantity_successor_header(&state));
    {
        let mut transaction = block.transaction();
        transaction
            .world
            .increase_asset_total_amount(alice.definition(), &Quantity::from(1_u32))
            .unwrap();
        transaction.poison_quantity_candidate_owner();
        assert!(transaction.world.quantity_mutation_observation.unowned);
        assert_eq!(
            transaction.pending_fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::UnsupportedOwner)
        );
    }
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
    let mut transaction = block.transaction();
    // The low-level helper is intentionally not a typed quantity owner.
    transaction
        .world
        .increase_asset_total_amount(alice.definition(), &Quantity::from(1_u32))
        .unwrap();
    transaction.apply();
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::UnownedMutation)
    );
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(11_u32)
    );
}

#[test]
fn returned_error_poison_and_scope_observation_never_grant_export() {
    let (state, _, _) = fixture();
    let mut block = state.block(quantity_successor_header(&state));
    let mut transaction = block.transaction();
    let result: Result<(), Error> = transaction.apply_with_quantity_candidate(
        Err(QuantityCaptureIssue::UnsupportedOwner),
        |_| {
            Err(Error::InvariantViolation(
                "original operation failure".into(),
            ))
        },
    );
    assert!(result.is_err());
    assert!(!transaction.world.quantity_mutation_observation.owned);
    assert_eq!(
        transaction
            .pending_fastpq_quantity_candidate
            .require_complete(),
        Err(QuantityCaptureIssue::UnsupportedOwner)
    );
}

#[test]
fn exact_capture_rejects_wrong_prestate_and_checks_actual_poststate_and_incarnation() {
    let (state, alice, _) = fixture();
    let mut block = state.block(quantity_successor_header(&state));
    let mut transaction = block.transaction();
    let balance = transaction.quantity_balance_identity(&alice).unwrap();
    let scoped = AssetId::with_scope(
        alice.definition().clone(),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(9)),
    );
    assert_ne!(
        transaction.quantity_balance_identity(&scoped).unwrap(),
        balance
    );
    let change = FastpqExecutionSupplyChangeV1 {
        balance,
        amount: Quantity::from(2_u32),
        balance_before: Quantity::from(10_u32),
        balance_after: Quantity::from(12_u32),
        supply_before: Quantity::from(10_u32),
        supply_after: Quantity::from(12_u32),
    };
    let expected = transaction
        .quantity_expected_state(&[FastpqExecutionEffectKindV1::Mint(change.clone())])
        .unwrap();
    assert!(!transaction.quantity_post_state_matches(&expected));
    let mut wrong = change.clone();
    wrong.balance_before = Quantity::from(9_u32);
    wrong.balance_after = Quantity::from(11_u32);
    assert!(matches!(
        transaction.quantity_expected_state(&[FastpqExecutionEffectKindV1::Mint(wrong)]),
        Err(QuantityCaptureIssue::InvalidFacts)
    ));
    transaction.world.assets.get_mut(&alice).unwrap().0 = Quantity::from(12_u32);
    transaction
        .world
        .increase_asset_total_amount(alice.definition(), &Quantity::from(2_u32))
        .unwrap();
    assert!(transaction.quantity_post_state_matches(&expected));
    transaction
        .world
        .axt_asset_incarnations
        .remove(alice.definition().clone());
    assert!(!transaction.quantity_post_state_matches(&expected));
    assert_eq!(
        transaction.quantity_balance_identity(&alice),
        Err(QuantityCaptureIssue::MissingIncarnation)
    );
}

fn assert_exact_applied_measurement(archive: &QuantityCandidateArchive) {
    let mut expected = QuantityCandidateUsage::default();
    for (hash, entry) in archive.entries.iter() {
        let input_bytes = entry
            .effects
            .iter()
            .map(|effect| u64::try_from(norito::encode_canonical(effect).unwrap().len()).unwrap())
            .sum::<u64>();
        let full = QuantityCandidateUsage {
            entries: 1,
            deltas: u64::try_from(entry.effects.len()).unwrap(),
            input_bytes,
            statement_bytes: u64::try_from(norito::encode_canonical(entry.wire()).unwrap().len())
                .unwrap(),
        };
        let measured = &archive.entries.get(hash).unwrap().measurement;
        assert_eq!(measured.baseline, QuantityCandidateUsage::default());
        assert_eq!(measured.full, full);
        expected.entries += full.entries;
        expected.deltas += full.deltas;
        expected.input_bytes += full.input_bytes;
        expected.statement_bytes += full.statement_bytes;
    }
    assert!(archive.base_usage.is_none());
    assert_eq!(expected.entries as usize, archive.entries.len());
    assert_eq!(archive.usage, expected);
}

#[test]
fn distinct_signed_entries_retain_exact_independent_counters() {
    let (state, alice, _) = fixture();
    let bodies: [Vec<InstructionBox>; 2] = [
        vec![
            Mint::asset_quantity(1_u32, alice.clone()).into(),
            Mint::asset_quantity(2_u32, alice.clone()).into(),
        ],
        vec![
            Burn::asset_quantity(1_u32, alice.clone()).into(),
            Mint::asset_quantity(3_u32, alice.clone()).into(),
        ],
    ];
    let header = quantity_successor_header(&state);
    let mut builder = BlockBuilder::new(header);
    let mut hashes = Vec::new();
    let mut contexts = Vec::new();
    for body in bodies {
        let mut transaction = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(
            quantity_successor_header(&state).creation_time() - Duration::from_millis(1),
        );
        let transaction = transaction
            .with_instructions(body)
            .sign(ALICE_KEYPAIR.private_key());
        hashes.push(Hash::from(
            TransactionEntrypoint::External(transaction.clone()).execution_call_hash(),
        ));
        contexts.push(quantity_execution_context(&state, &transaction, &header));
        builder.push_transaction(transaction);
    }
    builder.set_execution_context(Some(BlockExecutionContextBundle::new(contexts)));
    let source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let archive = &block.fastpq_quantity_candidate;
    assert_eq!(archive.issue, None);
    assert_eq!(archive.usage.entries, 2);
    assert_eq!(archive.usage.deltas, 4);
    assert_exact_applied_measurement(archive);
    for hash in hashes {
        assert_eq!(
            archive.entries[&hash]
                .effects
                .iter()
                .map(|effect| effect.ordinal)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(15_u32)
    );
}

#[test]
fn body_and_real_pipeline_fee_replace_one_complete_entry_counter() {
    use iroha_config::parameters::actual::{GasLiquidity, GasRate, GasVolatility};
    use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit};
    use iroha_primitives::numeric::Numeric;
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let (mut state, alice, bob) = fixture();
    {
        let mut setup = state.block(quantity_successor_header(&state));
        let mut transaction = setup.transaction_for_callback_testing();
        Mint::asset_quantity(1_000_000_000_u64, alice.clone())
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    state.pipeline.gas.tech_account_id = BOB_ID.to_string();
    state.pipeline.gas.accepted_assets = vec![alice.definition().canonical_address()];
    state.pipeline.gas.units_per_gas = vec![GasRate {
        asset: alice.definition().canonical_address(),
        units_per_gas: 1,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier1,
        volatility: GasVolatility::Stable,
    }];
    let body = vec![
        Mint::asset_quantity(2_u32, alice.clone()).into(),
        Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into(),
    ];
    let gas = crate::gas::meter_instructions(&body);
    assert!(gas > 0 && gas < 1_000_000_000);
    let fee = Quantity::from(gas);
    let (source, call) = source_with_fee(
        &state,
        body,
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::PipelineGas,
                alice.definition().clone(),
                fee.clone(),
            )],
            NonZeroU64::new(gas),
        ),
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let archive = &block.fastpq_quantity_candidate;
    assert_eq!(archive.issue, None);
    assert_eq!(archive.usage.entries, 1);
    assert_eq!(archive.usage.deltas, 3);
    assert_exact_applied_measurement(archive);
    let entry = &archive.entries[&call];
    assert_eq!(
        entry
            .effects
            .iter()
            .map(|effect| effect.ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(entry.effects.iter().any(|effect| matches!(&effect.kind, FastpqExecutionEffectKindV1::Transfer(transfer) if transfer.amount == fee)));
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(1_000_000_011_u64).checked_sub(&fee).unwrap()
    );
    assert_eq!(
        block.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::from(1_u32).checked_add(&fee).unwrap()
    );
}

#[test]
fn capture_capacity_refusal_keeps_exact_prefix_counters_and_original_business_result() {
    use iroha_data_model::parameter::{BlockParameter, FastpqSourcePolicyV1, Parameter};
    let (state, alice, _) = fixture();
    {
        let mut parameters = state.world.parameters.block();
        let previous = parameters.get().block().fastpq_source();
        let mut intrinsic = previous.intrinsic;
        intrinsic.max_transcripts = 1;
        intrinsic.max_deltas = 1;
        let policy = FastpqSourcePolicyV1::from_sizing(
            parameters.get().block().execution_output(),
            intrinsic,
            previous.mandatory,
            1,
        )
        .unwrap();
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::FastpqSource(policy)));
        parameters.commit();
    }
    let (source, call) = source(
        &state,
        vec![
            Mint::asset_quantity(1_u32, alice.clone()).into(),
            Mint::asset_quantity(2_u32, alice.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(13_u32)
    );
    let archive = &block.fastpq_quantity_candidate;
    assert_eq!(
        archive.require_complete(),
        Err(QuantityCaptureIssue::Capacity)
    );
    assert_eq!(archive.usage.entries, 1);
    assert_eq!(archive.usage.deltas, 1);
    assert_eq!(archive.entries[&call].effects.len(), 1);
    assert_exact_applied_measurement(archive);
    assert_eq!(
        archive.commitments.get(&call).unwrap().count(),
        2,
        "optional proof delta cap cannot truncate the mandatory supported source journal"
    );
    assert_eq!(archive.commitments.coverage_gap(), None);
    assert!(!archive.commitments.is_invalid());
}

#[test]
fn candidate_counter_arithmetic_refuses_overflow_and_underflow_in_every_dimension() {
    let unit = QuantityCandidateUsage {
        entries: 1,
        deltas: 1,
        input_bytes: 1,
        statement_bytes: 1,
    };
    let empty = QuantityCandidateUsage::default();
    assert_eq!(empty.checked_add(unit), Some(unit));
    assert_eq!(unit.checked_sub(unit), Some(empty));
    assert!(empty.checked_sub(unit).is_none());
    for dimension in 0..4 {
        let mut maximum = empty;
        match dimension {
            0 => maximum.entries = u64::MAX,
            1 => maximum.deltas = u64::MAX,
            2 => maximum.input_bytes = u64::MAX,
            3 => maximum.statement_bytes = u64::MAX,
            _ => unreachable!(),
        }
        assert!(maximum.checked_add(unit).is_none());
    }
}

fn sponsored_burn_fixture() -> (
    State,
    AssetId,
    iroha_data_model::nexus::FeeSponsorProgramId,
    InstructionBox,
) {
    use iroha_data_model::{isi::Log, nexus::*, prelude::Level};
    // Nexus debits must use the currency pinned by this original global root.
    let fee_asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    let (mut state, alice, custody) = fixture_with_asset_definition(fee_asset);
    let instruction = InstructionBox::from(Log::new(Level::INFO, "sponsored burn".into()));
    let wire_id = iroha_data_model::isi::instruction_wire_id(&instruction)
        .unwrap()
        .to_owned();
    let program_id = FeeSponsorProgramId::new(BOB_ID.clone(), "quantity".parse().unwrap());
    {
        let mut setup = state.block(quantity_successor_header(&state));
        let mut transaction = setup.transaction_for_callback_testing();
        Transfer::asset_quantity(alice, 10_u32, BOB_ID.clone())
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        let mut program = FeeSponsorProgram::new(program_id.clone(), BOB_ID.clone());
        program.lifecycle = FeeSponsorProgramLifecycle::Active;
        program.active_revision = Some(1);
        transaction
            .world
            .fee_sponsor_programs
            .insert(program_id.clone(), program);
        transaction.world.fee_sponsor_program_revisions.insert(
            FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
            FeeSponsorProgramRevision {
                program_id: program_id.clone(),
                revision: 1,
                eligibility: FeeSponsorEligibility::EnrolledOnly,
                rules: vec![FeeSponsorRule {
                    id: "allow_log".parse().unwrap(),
                    effect: FeeSponsorRuleEffect::Allow,
                    selectors: vec![FeeSponsorRuleSelector::NativeInstruction(
                        FeeSponsorNativeInstructionSelector {
                            wire_id,
                            asset_definition_id: None,
                        },
                    )],
                }],
                asset_budgets: vec![FeeSponsorAssetBudget {
                    asset_definition_id: custody.definition().clone(),
                    per_transaction: Quantity::from(10_u32),
                    per_block: Quantity::from(10_u32),
                    per_program_epoch: Quantity::from(10_u32),
                    per_beneficiary_epoch: Quantity::from(10_u32),
                    reserve_floor: Quantity::zero(),
                    epoch_length_blocks: NonZeroU64::MIN,
                }],
            },
        );
        let enrollment_key = FeeSponsorEnrollmentKey {
            program_id: program_id.clone(),
            beneficiary: ALICE_ID.clone(),
        };
        transaction.world.fee_sponsor_enrollments.insert(
            enrollment_key.clone(),
            FeeSponsorEnrollment {
                key: enrollment_key,
                enrolled_at_height: 1,
            },
        );
        let vault_key = FeeSponsorVaultKey {
            program_id: program_id.clone(),
            asset_definition_id: custody.definition().clone(),
        };
        transaction.world.fee_sponsor_vaults.insert(
            vault_key.clone(),
            FeeSponsorVault {
                key: vault_key,
                balance: Quantity::from(10_u32),
            },
        );
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let fees = &mut state.nexus.get_mut().fees;
    fees.settlement_mode = iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
    fees.fee_asset_id = custody.definition().canonical_address();
    fees.sponsor_vault_custody_account_id = BOB_ID.clone();
    fees.base_fee = Quantity::from(2_u32);
    {
        let view = state.view();
        assert_eq!(
            crate::block::resolve_network_xor_asset_definition(
                view.world(),
                &view.nexus.fees.fee_asset_id,
                u64::try_from(
                    quantity_successor_header(&state)
                        .creation_time()
                        .as_millis()
                )
                .unwrap(),
            )
            .expect("committed fee registry read completes"),
            Some(custody.definition().clone()),
        );
    }
    (state, custody, program_id, instruction)
}

#[test]
fn actual_signed_sponsor_debit_captures_exact_custody_balance_and_supply() {
    use iroha_data_model::{
        nexus::FeeSponsorVaultKey,
        transaction::{FeeChargeKind, FeeChargeLimit},
    };
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let (state, custody, program_id, instruction) = sponsored_burn_fixture();
    let (source, call) = source_with_fee(
        &state,
        vec![instruction],
        FeePaymentIntent::sponsor(
            program_id.clone(),
            1,
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                custody.definition().clone(),
                Quantity::from(2_u32),
            )],
            None,
        ),
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let outputs = block.retained_execution_outputs_for_test().unwrap();
    let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) = &outputs[0]
    else {
        panic!("signed sponsor source must retain its Network row");
    };
    assert!(output.result.is_ok(), "sponsor result: {:?}", output.result);
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("actual sponsor charge");
    receipt
        .validate_for_network_input(source.network_entrypoint_at(0).unwrap(), 2)
        .unwrap();
    assert_eq!(receipt.fee_asset_id, *custody.definition());
    assert_eq!(receipt.fee_amount, Quantity::from(2_u32));
    let archive = &block.fastpq_quantity_candidate;
    assert_eq!(archive.issue, None);
    assert_eq!(archive.usage.entries, 1);
    assert_eq!(archive.usage.deltas, 1);
    assert_exact_applied_measurement(archive);
    let effect = &archive.entries[&call].effects[0];
    assert_eq!(
        effect.authority_digest,
        crate::fastpq::authority_digest(&ALICE_ID)
    );
    let FastpqExecutionEffectKindV1::Burn(burn) = &effect.kind else {
        panic!("direct sponsor fee must retain its original burn operation");
    };
    assert_eq!(burn.balance.account, BOB_ID.clone());
    assert_eq!(burn.balance.scope, AssetBalanceScope::Global);
    assert_eq!(burn.balance.asset.definition, *custody.definition());
    assert_eq!(
        burn.balance.asset.incarnation,
        *block
            .world
            .axt_asset_incarnations
            .get(custody.definition())
            .unwrap()
    );
    assert_eq!(burn.amount, Quantity::from(2_u32));
    assert_eq!(burn.balance_before, Quantity::from(10_u32));
    assert_eq!(burn.balance_after, Quantity::from(8_u32));
    assert_eq!(burn.supply_before, Quantity::from(10_u32));
    assert_eq!(burn.supply_after, Quantity::from(8_u32));
    assert_eq!(
        block.world.assets.get(&custody).unwrap().as_ref(),
        &Quantity::from(8_u32)
    );
    assert_eq!(
        block
            .world
            .asset_definitions
            .get(custody.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(8_u32)
    );
    assert_eq!(
        block
            .world
            .fee_sponsor_vaults
            .get(&FeeSponsorVaultKey {
                program_id,
                asset_definition_id: custody.definition().clone(),
            })
            .unwrap()
            .balance,
        Quantity::from(8_u32)
    );
    assert_eq!(
        archive.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

#[test]
fn sponsor_business_capability_without_original_signed_source_cannot_capture() {
    let (mut state, custody, program_id, instruction) = sponsored_burn_fixture();
    state.nexus.get_mut().fees.base_fee = Quantity::zero();
    let (source, call) = source(&state, vec![instruction]);
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    let mut transaction = block.transaction();
    // The actual signed Log already retained E. Merely naming that entry
    // cannot supply the missing original signed sponsor-charge capability.
    transaction.tx_call_hash = Some(call);
    let charge = crate::executor::VerifiedFeeSponsorCharge::burn_for_test(
        ALICE_ID.clone(),
        program_id,
        custody.clone(),
        Quantity::from(2_u32),
    );
    crate::smartcontracts::isi::asset::isi::execute_verified_fee_sponsor_charge(
        &mut transaction,
        charge,
    )
    .unwrap();
    transaction.apply();
    assert_eq!(
        block.world.assets.get(&custody).unwrap().as_ref(),
        &Quantity::from(8_u32)
    );
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::UnsupportedOwner)
    );
}

fn genuine_signed_quantity_effect_capture_bytes() -> Vec<u8> {
    let (state, alice, bob) = fixture();
    let (mut source, call) = source(
        &state,
        vec![
            Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into(),
            Mint::asset_quantity(5_u32, alice.clone()).into(),
            Burn::asset_quantity(1_u32, alice.clone()).into(),
            Transfer::asset_quantity(alice.clone(), 2_u32, BOB_ID.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    block
        .seal_execution_outputs(&mut source, |state, original, routes| {
            assert_eq!(routes.len(), 1);
            Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                sccp_finality_header:
                    iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                        state.network_id().as_bytes().to_owned(),
                        original.header().height().get(),
                        original.header().creation_time_ms,
                    )
                    .unwrap(),
                committed_fragment_count: u64::try_from(state.committed_fragment_count()).unwrap(),
            })
        })
        .unwrap();
    block.observe_quantity_block_journals();
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(11_u32)
    );
    assert_eq!(
        block.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::from(3_u32)
    );
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(14_u32)
    );
    let candidate = &block.fastpq_quantity_candidate;
    assert_eq!(candidate.issue, None);
    assert_eq!(candidate.entries.len(), 1);
    assert_exact_applied_measurement(candidate);
    let entry = &candidate.entries[&call];
    assert_eq!(entry.effects.len(), 4);
    assert_eq!(entry.context.entry.entry_hash, call);
    assert_eq!(entry.context.source.network_id, state.network_id);
    assert_eq!(entry.context.source.height, source.header().height().get());
    for (ordinal, effect) in entry.effects.iter().enumerate() {
        assert_eq!(effect.ordinal, u32::try_from(ordinal).unwrap());
        assert_eq!(
            effect.authority_digest,
            crate::fastpq::authority_digest(&ALICE_ID)
        );
    }
    assert!(matches!(
        entry.effects[0].kind,
        FastpqExecutionEffectKindV1::Transfer(_)
    ));
    assert!(matches!(
        entry.effects[1].kind,
        FastpqExecutionEffectKindV1::Mint(_)
    ));
    assert!(matches!(
        entry.effects[2].kind,
        FastpqExecutionEffectKindV1::Burn(_)
    ));
    assert!(matches!(
        entry.effects[3].kind,
        FastpqExecutionEffectKindV1::Transfer(_)
    ));
    assert_eq!(
        candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );

    let original_inputs = iroha_data_model::fastpq::FastpqPublicInputs {
        dsid: crate::fastpq::dataspace_id_bytes(entry.context.entry.dataspace_id),
        slot: source.header().creation_time_ms.saturating_mul(1_000_000),
        old_root: [0; 32],
        new_root: [0; 32],
        perm_root: crate::fastpq::permission_table_root(block.world.roles.iter()),
        tx_set_hash: iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
            (0..source.network_entrypoint_count())
                .map(|index| source.network_entrypoint_at(index).unwrap()),
        )
        .unwrap()
        .into(),
    };
    let super::source_census::QuantitySourceCensusState::Sealed(census) = &candidate.source_census
    else {
        panic!("original completed native census");
    };
    let [seal] = census.entries() else {
        panic!("one complete executed entry")
    };
    assert_eq!(seal.context, entry.context);
    assert_eq!(seal.effect_count, 4);
    let inputs = census.statement_context(0).unwrap();
    assert_eq!(inputs, original_inputs);
    assert_eq!(
        seal.effects_digest,
        iroha_data_model::fastpq::execution_effects_digest_v1(entry.wire()).unwrap()
    );
    // The genuine transfer projection retains both occurrences. It must not
    // hide the gap by splitting the entry or synthesizing mint/burn transfers.
    let transfers = &source.fastpq_transcripts()[&call];
    assert_eq!(transfers.len(), 2);
    let transfer_only_result = crate::fastpq::quantity_statement_from_finalized_transcripts_for_testing(
        inputs,
        transfers,
        fastpq_prover::gadgets::public_transfer_statement::PublicTransferLimits::default(),
        fastpq_prover::gadgets::public_transfer_statement::TransferSmtBuildLimits::for_update_limit(8).unwrap(),
    );
    assert!(
        matches!(transfer_only_result, Err(fastpq_prover::Error::TransferInvariant { details }) if details.contains("repeated-key"))
    );

    let (manifest, leaves, manifest_bytes) = block.finalized_quantity_source_for_test().unwrap();
    assert_eq!(
        manifest.coverage,
        iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Complete
    );
    assert_eq!(manifest.executed_entry_count, 1);
    assert_eq!(manifest.statement_count, 1);
    assert_eq!(norito::decode_canonical::<iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1>(manifest_bytes).unwrap(), manifest);
    let [leaf] = leaves else {
        panic!("one original complete effect leaf")
    };
    assert_eq!(leaf.source, entry.context.source);
    assert_eq!(leaf.entry_hash, call);
    assert_eq!(leaf.effect_count, 4);
    assert_eq!(leaf.effects_digest, <[u8; 32]>::from(seal.effects_digest));
    assert_eq!(leaf.slot, inputs.slot);
    assert_eq!(leaf.perm_root, inputs.perm_root);
    assert_eq!(leaf.tx_set_hash, inputs.tx_set_hash);
    // Public disposable diagnostic only: preserve the actual original leaf, not
    // caller-reconstructed metadata. This frame grants no finality capability.
    let bytes = norito::encode_canonical(&(entry.wire().clone(), inputs, *leaf)).unwrap();
    assert!(bytes.len() <= 1_048_576);
    let decoded: (
        FastpqExecutionEffectsV1,
        iroha_data_model::fastpq::FastpqPublicInputs,
        iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1,
    ) = norito::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded, (entry.wire().clone(), inputs, *leaf));
    bytes
}

#[test]
fn genuine_completed_census_preserves_original_transfer_mint_burn_transfer_binding() {
    let bytes = genuine_signed_quantity_effect_capture_bytes();
    let (effects, inputs, leaf): (
        FastpqExecutionEffectsV1,
        iroha_data_model::fastpq::FastpqPublicInputs,
        iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1,
    ) = norito::decode_canonical(&bytes).unwrap();
    assert_eq!(effects.effects.len(), 4);
    assert_eq!(
        leaf.effects_digest,
        <[u8; 32]>::from(iroha_data_model::fastpq::execution_effects_digest_v1(&effects).unwrap())
    );
    assert_ne!(inputs.tx_set_hash, [0; 32]);
    for mutation in 0..5 {
        let mut changed = effects.clone();
        match mutation {
            0 => {
                changed.effects.remove(1);
            }
            1 => changed.effects.swap(0, 3),
            2 => changed.context.source.height += 1,
            3 => changed.effects[1].authority_digest = Hash::new(b"substituted mint authority"),
            _ => changed.effects[2].authorization_context = Hash::new(b"substituted burn owner"),
        }
        assert!(
            !iroha_data_model::fastpq::execution_effects_digest_v1(&changed)
                .is_ok_and(|digest| <[u8; 32]>::from(digest) == leaf.effects_digest),
            "mutation {mutation} must not reproduce the original effect digest",
        );
    }
}

#[test]
#[ignore = "explicit genuine fixture producer; retain its source-bound native output"]
fn emit_genuine_signed_quantity_effect_capture() {
    let bytes = genuine_signed_quantity_effect_capture_bytes();
    println!(
        "IROHA_FASTPQ_GENUINE_EFFECT_CAPTURE_V1 {} {}",
        hex::encode(Hash::new(&bytes).as_ref()),
        hex::encode(bytes)
    );
}

/// Begin from a genuine signed effect and its retained source/quota owner.
fn with_signed_quantity_block(test: impl FnOnce(&mut StateBlock<'_>, &AssetId, &AssetId, Hash)) {
    let (state, alice, bob) = fixture();
    let (source, call) = source(
        &state,
        vec![Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into()],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    test(&mut block, &alice, &bob, call);
}

fn prepare_owned_test_mint(
    transaction: &mut StateTransaction<'_, '_>,
    alice: &AssetId,
    call: Hash,
) -> PreparedQuantityCapture {
    transaction.tx_call_hash = Some(call);
    // Continue the already captured original entry under its exact retained route.
    // A raw default transaction has no lane and must not conflict with a routed source.
    let retained = transaction.block_fastpq_quantity_candidate.entries[&call]
        .context
        .entry;
    transaction.current_lane_id = match retained.route {
        iroha_data_model::fastpq::FastpqSourceRouteV1::Unrouted => None,
        iroha_data_model::fastpq::FastpqSourceRouteV1::Lane(lane) => Some(lane.lane_id),
    };
    transaction.current_dataspace_id = Some(retained.dataspace_id);
    transaction.world.current_dataspace_id = Some(retained.dataspace_id);
    let change = FastpqExecutionSupplyChangeV1 {
        balance: transaction.quantity_balance_identity(alice).unwrap(),
        amount: Quantity::from(1_u32),
        balance_before: Quantity::from(9_u32),
        balance_after: Quantity::from(10_u32),
        supply_before: Quantity::from(10_u32),
        supply_after: Quantity::from(11_u32),
    };
    transaction
        .prepare_quantity_candidate(
            &ALICE_ID,
            call,
            Hash::new(b"quantity-write-owner-regression"),
            vec![FastpqExecutionEffectKindV1::Mint(change)],
        )
        .expect("retained original source admits exact next mint")
}

fn apply_owned_test_mint(transaction: &mut StateTransaction<'_, '_>, alice: &AssetId) {
    assert!(
        transaction
            .world
            .quantity_mutation_observation
            .plan
            .is_some()
    );
    transaction
        .world
        .assign_quantity_balance_exact(alice, Quantity::from(10_u32))
        .unwrap();
    transaction
        .world
        .increase_asset_total_amount(alice.definition(), &Quantity::from(1_u32))
        .unwrap();
}

#[test]
fn original_signed_owner_typed_writes_and_state_application_match_mv_lineage() {
    with_signed_quantity_block(|block, alice, _, call| {
        let mut transaction = block.transaction();
        let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
        transaction
            .apply_with_quantity_candidate(Ok(prepared), |transaction| {
                apply_owned_test_mint(transaction, alice);
                Ok(())
            })
            .unwrap();
        assert_eq!(transaction.pending_fastpq_quantity_candidate.issue, None);
        transaction.apply();
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert_eq!(
            block.fastpq_quantity_candidate.entries[&call].effects.len(),
            2
        );
        assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
        assert_eq!(
            block.fastpq_quantity_candidate.require_complete(),
            Err(QuantityCaptureIssue::IncompleteCoverage)
        );
    });
}

#[test]
fn restored_raw_balance_and_supply_leases_inside_original_owned_callback_refuse_capture() {
    for supply in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let mut transaction = block.transaction();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            transaction
                .apply_with_quantity_candidate(Ok(prepared), |transaction| {
                    if supply {
                        let definition = transaction
                            .world
                            .asset_definition_mut(alice.definition())
                            .unwrap();
                        definition.total_quantity = Quantity::from(99_u32);
                        definition.total_quantity = Quantity::from(10_u32);
                    } else {
                        let raw = transaction.world.assets.get_mut(alice).unwrap();
                        **raw = Quantity::from(99_u32);
                        **raw = Quantity::from(9_u32);
                    }
                    apply_owned_test_mint(transaction, alice);
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                transaction.pending_fastpq_quantity_candidate.issue,
                Some(QuantityCaptureIssue::UnownedMutation)
            );
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .entries
                    .is_empty()
            );
            transaction.apply();
            block.observe_quantity_block_journals();
            assert_eq!(
                block.fastpq_quantity_candidate.issue,
                Some(QuantityCaptureIssue::UnownedMutation)
            );
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(10_u32)
            );
            assert_eq!(
                block
                    .world
                    .asset_definition(alice.definition())
                    .unwrap()
                    .total_quantity(),
                &Quantity::from(11_u32)
            );
        });
    }
}

#[test]
fn callback_errors_before_and_after_exact_final_port_preserve_business_and_refuse_facts() {
    for write_first in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let mut transaction = block.transaction();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            let result: Result<(), Error> =
                transaction.apply_with_quantity_candidate(Ok(prepared), |transaction| {
                    if write_first {
                        apply_owned_test_mint(transaction, alice);
                    }
                    Err(Error::InvariantViolation("original callback error".into()))
                });
            assert!(result.is_err());
            assert!(!transaction.world.quantity_mutation_observation.owned);
            assert!(
                transaction
                    .world
                    .quantity_mutation_observation
                    .plan
                    .is_none()
            );
            assert_eq!(
                transaction.pending_fastpq_quantity_candidate.issue,
                Some(if write_first {
                    QuantityCaptureIssue::InterruptedScope
                } else {
                    QuantityCaptureIssue::InvalidFacts
                })
            );
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .entries
                    .is_empty()
            );
            transaction.apply();
            block.observe_quantity_block_journals();
            assert!(block.fastpq_quantity_candidate.issue.is_some());
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(if write_first { 10_u32 } else { 9 })
            );
            assert_eq!(
                block.fastpq_quantity_candidate.entries[&call].effects.len(),
                1
            );
        });
    }
}

#[test]
fn unwind_before_and_after_final_port_refuses_apply_but_complete_rollback_has_no_parent_poison() {
    for write_first in [false, true] {
        for apply_after_catch in [false, true] {
            with_signed_quantity_block(|block, alice, _, call| {
                let mut transaction = block.transaction();
                let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
                let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _: Result<(), Error> =
                        transaction.apply_with_quantity_candidate(Ok(prepared), |transaction| {
                            if write_first {
                                apply_owned_test_mint(transaction, alice);
                            }
                            panic!("interrupt original capture scope");
                        });
                }));
                assert!(failure.is_err());
                assert!(transaction.world.quantity_mutation_observation.owned);
                assert!(
                    transaction
                        .world
                        .quantity_mutation_observation
                        .plan
                        .is_some()
                );
                if apply_after_catch {
                    transaction.apply();
                } else {
                    drop(transaction);
                }
                block.observe_quantity_block_journals();
                assert_eq!(
                    block.fastpq_quantity_candidate.issue,
                    apply_after_catch.then_some(QuantityCaptureIssue::InterruptedScope)
                );
                assert_eq!(
                    block.world.assets.get(alice).unwrap().as_ref(),
                    &Quantity::from(if write_first && apply_after_catch {
                        10_u32
                    } else {
                        9
                    })
                );
                assert_eq!(
                    block.fastpq_quantity_candidate.entries[&call].effects.len(),
                    1
                );
            });
        }
    }
}

#[test]
fn nested_callback_cannot_reuse_outer_plan_or_authorize_outer_raw_writes() {
    with_signed_quantity_block(|block, alice, _, call| {
        let mut transaction = block.transaction();
        let outer = prepare_owned_test_mint(&mut transaction, alice, call);
        let inner = prepare_owned_test_mint(&mut transaction, alice, call);
        transaction
            .apply_with_quantity_candidate(Ok(outer), |transaction| {
                transaction.apply_with_quantity_candidate(Ok(inner), |transaction| {
                    apply_owned_test_mint(transaction, alice);
                    Ok(())
                })?;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            transaction.pending_fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::InterruptedScope)
        );
        assert!(
            transaction
                .pending_fastpq_quantity_candidate
                .entries
                .is_empty()
        );
        drop(transaction);
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert_eq!(
            block.world.assets.get(alice).unwrap().as_ref(),
            &Quantity::from(9_u32)
        );
    });
}

#[test]
fn every_direct_world_block_quantity_write_survives_restore_and_refuses_capture() {
    for mutation in 0..8 {
        with_signed_quantity_block(|block, alice, bob, _| {
            match mutation {
                0 => {
                    let value = block.world.assets.get_mut(alice).unwrap();
                    **value = Quantity::from(99_u32);
                    **value = Quantity::from(9_u32);
                }
                1 => {
                    let original = block.world.assets.get(alice).unwrap().clone();
                    block.world.assets.insert(alice.clone(), original);
                }
                2 => {
                    let original = block.world.assets.remove(alice.clone()).unwrap();
                    block.world.assets.insert(alice.clone(), original);
                }
                3 => {
                    let absent = AssetId::with_scope(
                        bob.definition().clone(),
                        bob.account().clone(),
                        AssetBalanceScope::Dataspace(DataSpaceId::new(97)),
                    );
                    assert!(block.world.assets.remove(absent).is_none());
                }
                4 => {
                    let definition = block
                        .world
                        .asset_definitions
                        .get_mut(alice.definition())
                        .unwrap();
                    definition.total_quantity = Quantity::from(99_u32);
                    definition.total_quantity = Quantity::from(10_u32);
                }
                5 => {
                    let original = block
                        .world
                        .asset_definitions
                        .get(alice.definition())
                        .unwrap()
                        .clone();
                    block
                        .world
                        .asset_definitions
                        .insert(alice.definition().clone(), original);
                }
                6 => {
                    let original = block
                        .world
                        .asset_definitions
                        .remove(alice.definition().clone())
                        .unwrap();
                    block
                        .world
                        .asset_definitions
                        .insert(alice.definition().clone(), original);
                }
                7 => {
                    let absent = AssetDefinitionId::derive_from_components(
                        DomainId::try_new("absent-quantity-owner", "universal").unwrap(),
                        "absent".parse().unwrap(),
                    );
                    assert!(block.world.asset_definitions.remove(absent).is_none());
                }
                _ => unreachable!(),
            }
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(9_u32)
            );
            assert_eq!(
                block
                    .world
                    .asset_definition(alice.definition())
                    .unwrap()
                    .total_quantity(),
                &Quantity::from(10_u32)
            );
            block.observe_quantity_block_journals();
            assert_eq!(
                block.fastpq_quantity_candidate.issue,
                Some(QuantityCaptureIssue::UnownedMutation)
            );
        });
    }
}

#[test]
fn raw_world_child_apply_is_detected_even_when_empty_and_rollback_never_increments_lineage() {
    for write in [false, true] {
        for apply in [false, true] {
            with_signed_quantity_block(|block, alice, _, _| {
                let mut world = block
                    .world
                    .transaction_without_telemetry(LaneConfig::default(), 0);
                if write {
                    let value = world.assets.get_mut(alice).unwrap();
                    **value = Quantity::from(99_u32);
                    **value = Quantity::from(9_u32);
                }
                if apply {
                    world.apply();
                } else {
                    drop(world);
                }
                block.observe_quantity_block_journals();
                assert_eq!(
                    block.fastpq_quantity_candidate.issue,
                    apply.then_some(QuantityCaptureIssue::UnownedMutation)
                );
                assert_eq!(
                    block.world.assets.get(alice).unwrap().as_ref(),
                    &Quantity::from(9_u32)
                );
            });
        }
    }
}

#[test]
fn original_finite_port_reservation_is_atomic_retained_and_returned_on_refusal_or_drop() {
    with_signed_quantity_block(|block, _, _, call| {
        let effects = &block.fastpq_quantity_candidate.entries[&call].effects;
        let budget = iroha_allocation::AllocationBudget::new(1_048_576);
        let plan = QuantityWritePlan::from_effects(effects, 2, &budget).unwrap();
        let required = budget.reserved_bytes();
        assert!(required > 0);
        assert_eq!(budget.peak_reserved_bytes(), required);
        drop(plan);
        assert_eq!(budget.reserved_bytes(), 0);
        for limit in [0, required - 1] {
            let small = iroha_allocation::AllocationBudget::new(limit);
            assert!(matches!(
                QuantityWritePlan::from_effects(effects, 2, &small),
                Err(super::super::fastpq_quantity_write_plan::QuantityWritePlanError::Deferred(_))
            ));
            assert_eq!(small.reserved_bytes(), 0);
            assert_eq!(
                small.peak_reserved_bytes(),
                0,
                "refusal occurs before any plan allocation"
            );
        }
        let exact = iroha_allocation::AllocationBudget::new(required);
        let retained = QuantityWritePlan::from_effects(effects, 2, &exact).unwrap();
        assert_eq!(exact.reserved_bytes(), required);
        assert!(QuantityWritePlan::from_effects(effects, 2, &exact).is_err());
        assert_eq!(exact.reserved_bytes(), required);
        assert!(QuantityWritePlan::from_effects(effects, 1, &budget).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        drop(retained);
        assert_eq!(exact.reserved_bytes(), 0);
    });
}

#[test]
fn signed_zero_transfer_rejection_rolls_back_prior_capture_and_all_following_quantity_work() {
    let (state, alice, bob) = fixture();
    let (source, _) = source(
        &state,
        vec![
            Transfer::asset_quantity(alice.clone(), 5_u32, ALICE_ID.clone()).into(),
            Transfer::asset_quantity(alice.clone(), 0_u32, BOB_ID.clone()).into(),
            Burn::asset_quantity(10_u32, alice.clone()).into(),
            Mint::asset_quantity(3_u32, alice.clone()).into(),
            Transfer::asset_quantity(alice.clone(), 3_u32, BOB_ID.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    let fragments = block.committed_fragment_count();
    let applied_world_transactions = block.fastpq_quantity_candidate.applied_world_transactions;
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let outputs = block.retained_execution_outputs_for_test().unwrap();
    let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) = &outputs[0]
    else {
        panic!("original rejected source must retain its Network row");
    };
    assert!(
        matches!(output.result.as_ref(), Err(
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::InstructionFailed(
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(reason)
            )
        )
    ) if reason.as_ref() == "asset transfer amount must be non-zero"),
        "original rejection: {:?}",
        output.result
    );
    assert!(output.result.nexus_fee_receipt().is_none());
    assert!(output.result.batch_transfer_outcomes().is_empty());
    assert!(output.completions.is_empty());
    // The rejected business overlay and zero-fee settlement publish no fragment.
    // Time maintenance checks the empty local journal without publishing
    // an additional fragment or quantity source transaction.
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(
        block.fastpq_quantity_candidate.applied_world_transactions,
        applied_world_transactions
    );
    assert_eq!(
        block
            .fastpq_source_quota
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .ordinary_usage(),
        crate::fastpq::source_reservation::SourceUsage {
            executed_entries: 1,
            ..crate::fastpq::source_reservation::SourceUsage::ZERO
        }
    );
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.usage,
        QuantityCandidateUsage::default()
    );
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(10_u32)
    );
    assert!(block.world.assets.get(&bob).is_none());
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

#[test]
fn genuine_self_zero_exhaustion_burn_and_recreation_consume_exact_ordered_ports() {
    let (state, alice, bob) = fixture();
    let (source, call) = source(
        &state,
        vec![
            Transfer::asset_quantity(alice.clone(), 5_u32, ALICE_ID.clone()).into(),
            Burn::asset_quantity(0_u32, alice.clone()).into(),
            Burn::asset_quantity(10_u32, alice.clone()).into(),
            Mint::asset_quantity(3_u32, alice.clone()).into(),
            Transfer::asset_quantity(alice.clone(), 3_u32, BOB_ID.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let outputs = block.retained_execution_outputs_for_test().unwrap();
    let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) = &outputs[0]
    else {
        panic!("original successful source must retain its Network row");
    };
    assert!(
        output.result.is_ok(),
        "original source: {:?}",
        output.result
    );
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert_eq!(
        block.fastpq_quantity_candidate.entries[&call].effects.len(),
        5
    );
    let FastpqExecutionEffectKindV1::Burn(zero) =
        &block.fastpq_quantity_candidate.entries[&call].effects[1].kind
    else {
        panic!("zero burn must retain its exact original operation");
    };
    assert_eq!(zero.amount, Quantity::zero());
    assert_eq!(zero.balance_before, Quantity::from(10_u32));
    assert_eq!(zero.balance_after, Quantity::from(10_u32));
    assert_eq!(zero.supply_before, Quantity::from(10_u32));
    assert_eq!(zero.supply_after, Quantity::from(10_u32));
    assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
    assert!(block.world.assets.get(&alice).is_none());
    assert_eq!(
        block.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::from(3_u32)
    );
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(3_u32)
    );
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

#[test]
fn charged_complete_tape_preserves_exact_native_frame_and_refuses_before_clone_without_credit() {
    with_signed_quantity_block(|block, _, _, call| {
        let entry = &block.fastpq_quantity_candidate.entries[&call];
        let budget = iroha_allocation::AllocationBudget::new(1_048_576);
        let tape = QuantityTape::prepare(
            entry.context,
            &entry.effects,
            &[],
            Hash::new(b"unused"),
            Hash::new(b"unused"),
            entry.effects.len(),
            &budget,
        )
        .unwrap();
        assert_eq!(
            norito::encode_canonical(tape.wire()).unwrap(),
            norito::encode_canonical(entry.wire()).unwrap()
        );
        let required = budget.reserved_bytes();
        assert!(required > 0);
        assert_eq!(budget.peak_reserved_bytes(), required);
        drop(tape);
        assert_eq!(budget.reserved_bytes(), 0);
        let limited = iroha_allocation::AllocationBudget::new(required - 1);
        assert!(matches!(
            QuantityTape::prepare(
                entry.context,
                &entry.effects,
                &[],
                Hash::new(b"unused"),
                Hash::new(b"unused"),
                entry.effects.len(),
                &limited
            ),
            Err(QuantityCaptureIssue::Capacity)
        ));
        assert_eq!(limited.reserved_bytes(), 0);
        assert_eq!(limited.peak_reserved_bytes(), 0);
        let mut malformed = entry.effects.clone();
        malformed[0].ordinal = 1;
        assert!(matches!(
            QuantityTape::prepare(
                entry.context,
                &malformed,
                &[],
                Hash::new(b"unused"),
                Hash::new(b"unused"),
                malformed.len(),
                &budget
            ),
            Err(QuantityCaptureIssue::InvalidFacts)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn capture_preparation_and_transaction_rollback_return_every_archive_and_projection_credit() {
    with_signed_quantity_block(|block, alice, _, call| {
        let budget = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let original_parent = budget.reserved_bytes();
        let mut transaction = block.transaction();
        let original = budget.reserved_bytes();
        let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
        assert!(budget.reserved_bytes() > original);
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), original);
        let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
        transaction
            .apply_with_quantity_candidate(Ok(prepared), |transaction| {
                assert!(budget.reserved_bytes() > original);
                apply_owned_test_mint(transaction, alice);
                Ok(())
            })
            .unwrap();
        assert_eq!(transaction.pending_fastpq_quantity_candidate.issue, None);
        assert!(
            budget.reserved_bytes() > original,
            "pending full tape and pre-admitted parent slots retain original credits"
        );
        drop(transaction);
        assert_eq!(budget.reserved_bytes(), original_parent);
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert_eq!(
            block.fastpq_quantity_candidate.entries[&call].effects.len(),
            1
        );
    });
}

#[test]
fn nested_canonical_payloads_remain_charged_through_unwind_and_release_after_destruction() {
    with_signed_quantity_block(|block, _, _, call| {
        let entry = &block.fastpq_quantity_candidate.entries[&call];
        let budget = iroha_allocation::AllocationBudget::new(1_048_576);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let tape = QuantityTape::prepare(
                entry.context,
                &entry.effects,
                &[],
                Hash::new(b"unused"),
                Hash::new(b"unused"),
                entry.effects.len(),
                &budget,
            )
            .unwrap();
            assert_eq!(tape.wire(), entry.wire());
            assert!(
                budget.reserved_bytes() > 0,
                "original nested controller and quantity owners retain their credits"
            );
            panic!("unwind while exact nested canonical owners are retained");
        }));
        assert!(failure.is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(budget.peak_reserved_bytes() > 0);
    });
}

#[test]
fn callback_error_and_unwind_discard_new_tape_while_transaction_rollback_preserves_parent() {
    for unwind in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let budget = block.pipeline_ivm_prepared_cache.execution_budget().clone();
            let parent_bytes = budget.reserved_bytes();
            let mut transaction = block.transaction();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let result: Result<(), Error> =
                    transaction.apply_with_quantity_candidate(Ok(prepared), |transaction| {
                        apply_owned_test_mint(transaction, alice);
                        if unwind {
                            panic!("interrupt after final original port");
                        }
                        Err(Error::InvariantViolation(
                            "return after final original port".into(),
                        ))
                    });
                assert!(result.is_err());
            }));
            assert_eq!(failure.is_err(), unwind);
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .entries
                    .is_empty()
            );
            assert_eq!(
                transaction
                    .world
                    .quantity_mutation_observation
                    .plan
                    .is_some(),
                unwind
            );
            drop(transaction);
            assert_eq!(budget.reserved_bytes(), parent_bytes);
            block.observe_quantity_block_journals();
            assert_eq!(block.fastpq_quantity_candidate.issue, None);
            assert_eq!(
                block.fastpq_quantity_candidate.entries[&call].effects.len(),
                1
            );
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(9_u32)
            );
        });
    }
}

#[test]
fn complete_charged_replacement_moves_to_original_parent_before_world_publication() {
    with_signed_quantity_block(|block, alice, _, call| {
        let mut transaction = block.transaction();
        let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
        transaction
            .apply_with_quantity_candidate(Ok(prepared), |transaction| {
                apply_owned_test_mint(transaction, alice);
                Ok(())
            })
            .unwrap();
        let complete = norito::encode_canonical(
            transaction.pending_fastpq_quantity_candidate.entries[&call].wire(),
        )
        .unwrap();
        transaction.apply();
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert_eq!(
            block.fastpq_quantity_candidate.entries[&call].effects.len(),
            2
        );
        assert_eq!(
            norito::encode_canonical(block.fastpq_quantity_candidate.entries[&call].wire())
                .unwrap(),
            complete
        );
        assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
        assert_eq!(
            block.fastpq_quantity_candidate.require_complete(),
            Err(QuantityCaptureIssue::IncompleteCoverage)
        );
    });
}

#[test]
fn genuine_signed_quantity_execution_publishes_original_world_with_capture_gate_still_closed() {
    let (state, alice, bob) = fixture();
    let (source, call) = source(
        &state,
        vec![Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into()],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert_eq!(
        block.fastpq_quantity_candidate.entries[&call].effects.len(),
        1
    );
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
    // This explicitly test-owned component publication does not mint a finality credential.
    block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert_eq!(
        view.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(9_u32)
    );
    assert_eq!(
        view.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::from(1_u32)
    );
    assert_eq!(
        view.world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}

#[test]
fn borrowed_effect_inputs_preserve_every_owned_canonical_frame_and_exact_original_admission() {
    with_signed_quantity_block(|block, _, _, call| {
        let entry = &block.fastpq_quantity_candidate.entries[&call];
        let FastpqExecutionEffectKindV1::Transfer(original) = &entry.effects[0].kind else {
            panic!("genuine source supplies transfer identities")
        };
        let amount: Quantity = "18446744073709551616.0000000000000000000000000001"
            .parse()
            .unwrap();
        let before: Quantity = "36893488147419103232.0000000000000000000000000002"
            .parse()
            .unwrap();
        let zero = Quantity::zero();
        let transfer = FastpqExecutionTransferV1 {
            source: original.source.clone(),
            destination: original.destination.clone(),
            amount: amount.clone(),
            source_before: before.clone(),
            source_after: amount.clone(),
            destination_before: zero.clone(),
            destination_after: amount.clone(),
        };
        let mint = FastpqExecutionSupplyChangeV1 {
            balance: original.source.clone(),
            amount: amount.clone(),
            balance_before: amount.clone(),
            balance_after: before.clone(),
            supply_before: before.clone(),
            supply_after: before.checked_add(&amount).unwrap(),
        };
        let burn = FastpqExecutionSupplyChangeV1 {
            balance: original.destination.clone(),
            amount: amount.clone(),
            balance_before: amount.clone(),
            balance_after: zero,
            supply_before: mint.supply_after.clone(),
            supply_after: before,
        };
        let kinds = [
            FastpqExecutionEffectKindV1::Transfer(transfer),
            FastpqExecutionEffectKindV1::Mint(mint),
            FastpqExecutionEffectKindV1::Burn(burn),
        ];
        let authority = entry.effects[0].authority_digest;
        let authorization = entry.effects[0].authorization_context;
        let owned = FastpqExecutionEffectsV1 {
            context: entry.context,
            effects: kinds
                .iter()
                .enumerate()
                .map(|(ordinal, kind)| FastpqExecutionEffectV1 {
                    ordinal: u32::try_from(ordinal).unwrap(),
                    authority_digest: authority,
                    authorization_context: authorization,
                    kind: kind.clone(),
                })
                .collect(),
        };
        let expected = norito::encode_canonical(&owned).unwrap();
        for prefix_len in 0..=kinds.len() {
            let budget = iroha_allocation::AllocationBudget::new(1_048_576);
            let tape = QuantityTape::prepare_inputs(
                entry.context,
                &owned.effects[..prefix_len],
                kinds[prefix_len..].iter().map(|kind| Ok(kind.into())),
                authority,
                authorization,
                kinds.len(),
                &budget,
            )
            .unwrap();
            assert_eq!(norito::encode_canonical(tape.wire()).unwrap(), expected);
            let required = budget.reserved_bytes();
            assert!(required > 0);
            drop(tape);
            assert_eq!(budget.reserved_bytes(), 0);
            let limited = iroha_allocation::AllocationBudget::new(required - 1);
            assert!(matches!(
                QuantityTape::prepare_inputs(
                    entry.context,
                    &owned.effects[..prefix_len],
                    kinds[prefix_len..].iter().map(|kind| Ok(kind.into())),
                    authority,
                    authorization,
                    kinds.len(),
                    &limited,
                ),
                Err(QuantityCaptureIssue::Capacity)
            ));
            assert_eq!(limited.peak_reserved_bytes(), 0);
            assert_eq!(limited.reserved_bytes(), 0);
        }
        let budget = iroha_allocation::AllocationBudget::new(1_048_576);
        assert!(matches!(
            QuantityTape::prepare_inputs(
                entry.context,
                &[],
                std::iter::once(Err(QuantityCaptureIssue::MissingIncarnation)),
                authority,
                authorization,
                1,
                &budget,
            ),
            Err(QuantityCaptureIssue::MissingIncarnation)
        ));
        assert_eq!(budget.peak_reserved_bytes(), 0);
    });
}

#[test]
fn genuine_wide_decimal_supply_and_transfer_retain_original_values_without_narrowing() {
    let (state, alice, bob) = fixture();
    let amount: Quantity = "18446744073709551616.0000000000000000000000000001"
        .parse()
        .unwrap();
    let tiny: Quantity = "0.0000000000000000000000000001".parse().unwrap();
    let expected_after_mint = Quantity::from(10_u32).checked_add(&amount).unwrap();
    let expected_after_burn = expected_after_mint.checked_sub(&tiny).unwrap();
    let (source, call) = source(
        &state,
        vec![
            Mint::asset_quantity(amount.clone(), alice.clone()).into(),
            Burn::asset_quantity(tiny.clone(), alice.clone()).into(),
            Transfer::asset_quantity(alice.clone(), amount.clone(), BOB_ID.clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    let entry = &block.fastpq_quantity_candidate.entries[&call];
    assert_eq!(entry.effects.len(), 3);
    let FastpqExecutionEffectKindV1::Mint(mint) = &entry.effects[0].kind else {
        panic!("mint")
    };
    assert_eq!(mint.amount, amount);
    assert_eq!(mint.balance_before, Quantity::from(10_u32));
    assert_eq!(mint.balance_after, expected_after_mint);
    assert_eq!(mint.supply_before, Quantity::from(10_u32));
    assert_eq!(mint.supply_after, expected_after_mint);
    let FastpqExecutionEffectKindV1::Burn(burn) = &entry.effects[1].kind else {
        panic!("burn")
    };
    assert_eq!(burn.amount, tiny);
    assert_eq!(burn.balance_before, expected_after_mint);
    assert_eq!(burn.balance_after, expected_after_burn);
    assert_eq!(burn.supply_before, expected_after_mint);
    assert_eq!(burn.supply_after, expected_after_burn);
    let FastpqExecutionEffectKindV1::Transfer(transfer) = &entry.effects[2].kind else {
        panic!("transfer")
    };
    assert_eq!(transfer.amount, amount);
    assert_eq!(transfer.source_before, expected_after_burn);
    assert_eq!(
        &transfer.source_after,
        block.world.assets.get(&alice).unwrap().as_ref()
    );
    assert_eq!(
        &transfer.destination_after,
        block.world.assets.get(&bob).unwrap().as_ref()
    );
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &expected_after_burn
    );
    assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::IncompleteCoverage)
    );
}

fn with_sealed_quantity_source_census(
    action: impl FnOnce(&mut StateBlock<'_>, &SignedBlock, &AssetId, &AssetId),
) {
    use iroha_data_model::{isi::Log, prelude::Level};
    let (state, alice, bob) = fixture();
    let header = quantity_successor_header(&state);
    let mut builder = BlockBuilder::new(header);
    let mut contexts = Vec::new();
    let bodies: [Vec<InstructionBox>; 3] = [
        vec![Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into()],
        vec![Log::new(Level::INFO, "quantity census empty source".to_owned()).into()],
        vec![Burn::asset_quantity(99_u32, alice.clone()).into()],
    ];
    for body in bodies {
        let mut transaction = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(header.creation_time() - Duration::from_millis(1));
        let signed = transaction
            .with_instructions(body)
            .sign(ALICE_KEYPAIR.private_key());
        contexts.push(quantity_execution_context(&state, &signed, &header));
        builder.push_transaction(signed);
    }
    builder.set_execution_context(Some(BlockExecutionContextBundle::new(contexts)));
    let mut source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let rows = block.retained_execution_outputs_for_test().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows[0].result().is_ok());
    assert!(rows[1].result().is_ok());
    assert!(rows[2].result().is_err());
    block
        .seal_execution_outputs(&mut source, |state, original, routes| {
            assert_eq!(routes.len(), 3);
            Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                sccp_finality_header:
                    iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                        state.network_id().as_bytes().to_owned(),
                        original.header().height().get(),
                        original.header().creation_time_ms,
                    )
                    .unwrap(),
                committed_fragment_count: u64::try_from(state.committed_fragment_count()).unwrap(),
            })
        })
        .unwrap();
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert!(matches!(
        block.fastpq_quantity_candidate.source_census,
        super::source_census::QuantitySourceCensusState::Sealed(_)
    ));
    action(&mut block, &source, &alice, &bob);
}

#[test]
fn original_quantity_census_retains_ordered_success_empty_and_rejected_sources_with_native_bytes() {
    with_sealed_quantity_source_census(|block, source, alice, bob| {
        let super::source_census::QuantitySourceCensusState::Sealed(census) =
            &block.fastpq_quantity_candidate.source_census
        else {
            panic!("original census retained");
        };
        assert_eq!(census.entries().len(), 3);
        for (index, row) in census.entries().iter().enumerate() {
            assert_eq!(row.context.source.network_id, block.network_id);
            assert_eq!(row.context.source.height, source.header().height().get());
            assert_eq!(
                row.context.entry.entry_hash,
                Hash::from(
                    source
                        .network_entrypoint_at(index)
                        .unwrap()
                        .execution_call_hash()
                )
            );
            let empty = FastpqExecutionEffectsV1 {
                context: row.context,
                effects: Vec::new(),
            };
            let wire = block
                .fastpq_quantity_candidate
                .entries
                .get(&row.context.entry.entry_hash)
                .map_or(&empty, QuantityArchivedEntry::wire);
            let native = norito::encode_canonical(wire).unwrap();
            assert_ne!(
                row.effects_digest,
                Hash::new_from_chunks(&[b"fastpq:execution-effects:v1:source|", &native]),
                "the retired whole-frame digest is not an alias for the ordered commitment"
            );
            assert_eq!(
                row.effects_digest,
                block
                    .fastpq_quantity_candidate
                    .commitments
                    .original(row.context)
                    .unwrap()
                    .digest()
                    .unwrap()
            );
            assert_eq!(
                row.effects_digest,
                iroha_data_model::fastpq::execution_effects_digest_v1(wire).unwrap()
            );
            assert_ne!(row.effects_digest, Hash::new(&native));
            assert_eq!(row.frame_bytes, u64::try_from(native.len()).unwrap());
            assert_eq!(row.effect_count, if index == 0 { 1 } else { 0 });
        }
        assert_eq!(
            block.world.assets.get(alice).unwrap().as_ref(),
            &Quantity::from(9_u32)
        );
        assert_eq!(
            block.world.assets.get(bob).unwrap().as_ref(),
            &Quantity::from(1_u32)
        );
        assert_eq!(block.fastpq_quantity_candidate.usage.entries, 1);
        assert_eq!(
            block.fastpq_quantity_candidate.require_complete(),
            Err(QuantityCaptureIssue::IncompleteCoverage)
        );
    });
}

#[test]
fn original_quantity_census_reserves_exact_fixed_backing_and_returns_credit_on_refusal_and_unwind()
{
    use super::source_census::{QuantitySourceCensus, QuantitySourceEntrySeal};
    with_sealed_quantity_source_census(|block, _, _, _| {
        let entry_bytes = std::alloc::Layout::array::<QuantitySourceEntrySeal>(3)
            .unwrap()
            .size();
        let permission_bytes = crate::fastpq::permission_context::permission_table_backing_layout(
            block.world.roles.iter(),
        )
        .unwrap()
        .size();
        let shell_bytes = iroha_allocation::ChargedShared::<
            super::super::fastpq_quantity_archive::FrozenQuantityArchive<QuantityArchivedEntry>,
        >::allocation_layout()
        .size();
        let retained_bytes = entry_bytes.checked_add(shell_bytes).unwrap();
        let required = retained_bytes.checked_add(permission_bytes).unwrap();
        assert!(required > 0);
        let insufficient = iroha_allocation::AllocationBudget::new(required - 1);
        assert!(matches!(
            QuantitySourceCensus::prepare(block, &insufficient),
            Err(QuantityCaptureIssue::Capacity)
        ));
        assert_eq!(insufficient.reserved_bytes(), 0);
        assert_eq!(insufficient.peak_reserved_bytes(), 0);
        let exact = iroha_allocation::AllocationBudget::new(required);
        let retained = QuantitySourceCensus::prepare(block, &exact).unwrap();
        assert_eq!(exact.reserved_bytes(), retained_bytes);
        assert!(matches!(
            QuantitySourceCensus::prepare(block, &exact),
            Err(QuantityCaptureIssue::Capacity)
        ));
        assert_eq!(exact.reserved_bytes(), retained_bytes);
        assert_eq!(retained.entries().len(), 3);
        drop(retained);
        assert_eq!(exact.reserved_bytes(), 0);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let retained = QuantitySourceCensus::prepare(block, &exact).unwrap();
            assert_eq!(retained.entries().len(), 3);
            assert_eq!(exact.reserved_bytes(), retained_bytes);
            panic!("drop original census backing during unwind");
        }));
        assert!(unwind.is_err());
        assert_eq!(exact.reserved_bytes(), 0);
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        let original_pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let original_before = original_pool.reserved_bytes();
        block.reject_quantity_source_census();
        assert_eq!(
            original_pool.reserved_bytes() + entry_bytes,
            original_before
        );
        assert_eq!(
            block.fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::UnsupportedOwner)
        );
    });
}

#[test]
fn original_quantity_census_refuses_source_reconstruction_context_change_and_missing_effects() {
    for mutation in 0..5 {
        with_sealed_quantity_source_census(|block, _, _, _| {
            match mutation {
                0 => {
                    let original = block
                        .fastpq_source_inventory
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .unwrap();
                    block.fastpq_source_inventory = Some(Ok(Arc::new((**original).clone())));
                }
                1 => {
                    let original = block.fastpq_source_context.as_ref().unwrap();
                    block.fastpq_source_context = Some(Arc::new((**original).clone()));
                }
                2 => block._curr_block.creation_time_ms += 1,
                3 => {
                    block.fastpq_quantity_candidate.entries =
                        super::super::fastpq_quantity_archive::QuantityArchiveMap::default()
                }
                4 => {
                    // Completed backing exposes no mutable tape. A separately
                    // funded replacement cannot recover its original ownership.
                    let budget = block.pipeline_ivm_prepared_cache.execution_budget();
                    let mut replacement =
                        super::super::fastpq_quantity_archive::QuantityArchiveMap::default();
                    replacement.grow(
                        super::super::fastpq_quantity_archive::QuantityArchiveMap::reserve(
                            block.fastpq_quantity_candidate.entries.len(),
                            budget,
                        )
                        .unwrap(),
                    );
                    for (hash, entry) in block.fastpq_quantity_candidate.entries.iter() {
                        let mut tape = QuantityTape::prepare(
                            entry.context,
                            &entry.effects,
                            &[],
                            Hash::new(b"unused no new effects"),
                            Hash::new(b"unused no new effects"),
                            entry.effects.len(),
                            budget,
                        )
                        .unwrap();
                        tape.substitute_entry_hash_for_test(Hash::new(
                            b"substituted quantity entry context",
                        ));
                        replacement.insert_reserved(
                            *hash,
                            QuantityArchivedEntry {
                                tape,
                                measurement: entry.measurement,
                            },
                        );
                    }
                    block.fastpq_quantity_candidate.entries = replacement;
                }
                _ => unreachable!(),
            }
            block.observe_quantity_block_journals();
            assert!(block.fastpq_quantity_candidate.issue.is_some());
            assert!(matches!(
                block.fastpq_quantity_candidate.source_census,
                super::source_census::QuantitySourceCensusState::Failed
            ));
            block.retain_quantity_source_census();
            assert!(matches!(
                block.fastpq_quantity_candidate.source_census,
                super::source_census::QuantitySourceCensusState::Failed
            ));
            assert!(block.fastpq_quantity_candidate.require_complete().is_err());
        });
    }
}

#[test]
fn original_quantity_census_keeps_dropped_child_but_refuses_late_apply_and_restored_raw_write() {
    for mutation in 0..3 {
        with_sealed_quantity_source_census(|block, _, alice, _| {
            match mutation {
                0 | 1 => {
                    let mut child = block
                        .world
                        .transaction_without_telemetry(LaneConfig::default(), 0);
                    child.account_mut(&ALICE_ID).unwrap().insert(
                        "after_census".parse().unwrap(),
                        iroha_primitives::json::Json::new(true),
                    );
                    let mut pending = QuantityCandidateArchive::default();
                    pending.observe(&child);
                    if mutation == 0 {
                        drop(child);
                        drop(pending);
                    } else {
                        child.apply();
                        block.fastpq_quantity_candidate.apply(pending);
                    }
                }
                2 => {
                    let original = block.world.assets.get_mut(alice).unwrap();
                    **original = Quantity::from(99_u32);
                    **original = Quantity::from(9_u32);
                }
                _ => unreachable!(),
            }
            block.observe_quantity_block_journals();
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(9_u32)
            );
            if mutation == 0 {
                assert_eq!(block.fastpq_quantity_candidate.issue, None);
                assert!(matches!(
                    block.fastpq_quantity_candidate.source_census,
                    super::source_census::QuantitySourceCensusState::Sealed(_)
                ));
            } else {
                assert!(block.fastpq_quantity_candidate.issue.is_some());
                assert!(matches!(
                    block.fastpq_quantity_candidate.source_census,
                    super::source_census::QuantitySourceCensusState::Failed
                ));
            }
            assert!(block.fastpq_quantity_candidate.require_complete().is_err());
        });
    }
}

#[test]
fn original_quantity_census_interrupted_preparation_latch_cannot_reseal_or_recover() {
    with_sealed_quantity_source_census(|block, _, _, _| {
        // Inject the exact retained state left by a caught unwind after original
        // construction enters Preparing. The separate owner test proves credit Drop.
        block.fastpq_quantity_candidate.source_census =
            super::source_census::QuantitySourceCensusState::Preparing;
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        block.observe_quantity_block_journals();
        assert_eq!(
            block.fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::InterruptedScope)
        );
        assert!(matches!(
            block.fastpq_quantity_candidate.source_census,
            super::source_census::QuantitySourceCensusState::Failed
        ));
        block.retain_quantity_source_census();
        block.observe_quantity_block_journals();
        assert_eq!(
            block.fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::InterruptedScope)
        );
        assert!(matches!(
            block.fastpq_quantity_candidate.source_census,
            super::source_census::QuantitySourceCensusState::Failed
        ));
        assert_eq!(
            block.fastpq_quantity_candidate.require_complete(),
            Err(QuantityCaptureIssue::InterruptedScope)
        );
    });
}

fn account_removal_fixture(amount: Option<Quantity>) -> (State, AssetId, AssetId) {
    let domain = DomainId::try_new("quantity-capture", "universal").unwrap();
    let definition = AssetDefinitionId::derive_from_components(domain, "units".parse().unwrap());
    fixture_with_bob_balance(definition, amount)
}

fn bob_account_removal_source(state: &State, repeat: bool) -> (SignedBlock, Hash) {
    let mut transaction = TransactionBuilder::new(
        state.network_id,
        BOB_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(
        quantity_successor_header(state).creation_time() - Duration::from_millis(1),
    );
    let mut body = vec![InstructionBox::from(Unregister::account(BOB_ID.clone()))];
    if repeat {
        body.push(Unregister::account(BOB_ID.clone()).into());
    }
    let transaction = transaction
        .with_instructions(body)
        .sign(BOB_KEYPAIR.private_key());
    let call =
        Hash::from(TransactionEntrypoint::External(transaction.clone()).execution_call_hash());
    let header = quantity_successor_header(state);
    let context = quantity_execution_context(state, &transaction, &header);
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(Some(BlockExecutionContextBundle::new(vec![context])));
    builder.push_transaction(transaction);
    (
        builder.build_with_signature(0, ALICE_KEYPAIR.private_key()),
        call,
    )
}

#[test]
fn signed_account_removal_captures_original_supply_first_burn_and_exact_source_census() {
    for amount in [0_u32, 3] {
        let (state, alice, bob) = account_removal_fixture(Some(Quantity::from(amount)));
        let (mut source, call) = bob_account_removal_source(&state, false);
        let (mut block, _recording) = state
            .block_with_recorded_pristine_carrier_stage(
                &source,
                |_| Ok::<(), String>(()),
                |error| error,
            )
            .unwrap();
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block.execute_ordinary_output_plan(&source, None).unwrap();
        let rows = block.retained_execution_outputs_for_test().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].result().is_ok(),
            "original signed account removal: {:?}",
            rows[0].result()
        );
        assert!(block.world.accounts.get(&BOB_ID).is_none());
        assert!(block.world.assets.get(&bob).is_none());
        assert_eq!(
            block.world.assets.get(&alice).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert_eq!(
            block
                .world
                .asset_definition(alice.definition())
                .unwrap()
                .total_quantity(),
            &Quantity::from(10_u32)
        );
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        let entry = &block.fastpq_quantity_candidate.entries[&call];
        assert_eq!(entry.effects.len(), 1);
        let FastpqExecutionEffectKindV1::Burn(burn) = &entry.effects[0].kind else {
            panic!("original removal must retain one complete burn");
        };
        assert_eq!(burn.balance.account, *BOB_ID);
        assert_eq!(burn.balance_before, Quantity::from(amount));
        assert_eq!(burn.amount, Quantity::from(amount));
        assert_eq!(burn.balance_after, Quantity::zero());
        assert_eq!(burn.supply_before, Quantity::from(10 + amount));
        assert_eq!(burn.supply_after, Quantity::from(10_u32));
        // Exercise the production constructor with facts from the actual signed
        // source and the same original execution pool. Ordering only swaps
        // retained ports/lifecycles: it obtains no further allocation credit.
        let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let baseline = pool.reserved_bytes();
        let mut plan = QuantityWritePlan::from_effects(&entry.effects, 2, &pool).unwrap();
        assert_eq!(plan.lifecycles().len(), 2);
        assert_eq!(plan.lifecycles()[0], plan.lifecycles()[1]);
        assert_eq!(plan.lifecycles()[0].0, *bob.definition());
        assert_eq!(plan.lifecycles()[0].1, burn.balance.asset.incarnation);
        let reserved = pool.reserved_bytes();
        let peak = pool.peak_reserved_bytes();
        assert!(reserved > baseline);
        plan.order_supply_before_complete_removal(&bob, &Quantity::from(amount))
            .unwrap();
        assert_eq!(pool.reserved_bytes(), reserved);
        assert_eq!(pool.peak_reserved_bytes(), peak);
        assert_eq!(plan.lifecycles().len(), 2);
        assert_eq!(plan.lifecycles()[0], plan.lifecycles()[1]);
        plan.consume_supply(
            bob.definition(),
            &Quantity::from(10 + amount),
            &Quantity::from(10_u32),
        )
        .unwrap()
        .applied();
        plan.consume_balance(&bob, &Quantity::from(amount), &Quantity::zero())
            .unwrap()
            .applied();
        assert_eq!(plan.finish(), Ok(()));
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
        block
            .seal_execution_outputs(&mut source, |state, original, routes| {
                assert_eq!(routes.len(), 1);
                Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                    sccp_finality_header:
                        iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                            state.network_id().as_bytes().to_owned(),
                            original.header().height().get(),
                            original.header().creation_time_ms,
                        )
                        .unwrap(),
                    committed_fragment_count: u64::try_from(state.committed_fragment_count())
                        .unwrap(),
                })
            })
            .unwrap();
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        let super::source_census::QuantitySourceCensusState::Sealed(census) =
            &block.fastpq_quantity_candidate.source_census
        else {
            panic!("original source census required");
        };
        assert_eq!(census.entries().len(), 1);
        let row = &census.entries()[0];
        assert_eq!(row.context.entry.entry_hash, call);
        assert_eq!(row.effect_count, 1);
        let wire = block.fastpq_quantity_candidate.entries[&call].wire();
        let bytes = norito::encode_canonical(wire).unwrap();
        assert_eq!(
            row.effects_digest,
            iroha_data_model::fastpq::execution_effects_digest_v1(wire).unwrap()
        );
        assert_ne!(row.effects_digest, Hash::new(&bytes));
        assert_eq!(row.frame_bytes, u64::try_from(bytes.len()).unwrap());
        // Domain/definition lifecycle and other owner coverage are still incomplete.
        assert_eq!(
            block.fastpq_quantity_candidate.require_complete(),
            Err(QuantityCaptureIssue::IncompleteCoverage)
        );
    }
}

#[test]
fn signed_account_removal_rolls_back_balance_supply_account_and_capture_on_later_failure() {
    let (state, alice, bob) = account_removal_fixture(Some(Quantity::from(3_u32)));
    let (source, _) = bob_account_removal_source(&state, true);
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    let fragments = block.committed_fragment_count();
    let applied_world_transactions = block.fastpq_quantity_candidate.applied_world_transactions;
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let rows = block.retained_execution_outputs_for_test().unwrap();
    assert_eq!(rows.len(), 1);
    let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) = &rows[0]
    else {
        panic!("rejected original source must retain its Network row");
    };
    assert!(output.result.is_err());
    assert!(output.result.nexus_fee_receipt().is_none());
    assert!(output.result.batch_transfer_outcomes().is_empty());
    assert!(output.completions.is_empty());
    assert!(block.world.accounts.get(&BOB_ID).is_some());
    assert_eq!(
        block.world.assets.get(&bob).unwrap().as_ref(),
        &Quantity::from(3_u32)
    );
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(13_u32)
    );
    // The rejected business overlay and zero-fee settlement publish no fragment.
    // Time maintenance checks the empty local journal without publishing
    // an additional fragment or quantity source transaction.
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(
        block.fastpq_quantity_candidate.applied_world_transactions,
        applied_world_transactions
    );
    assert_eq!(
        block
            .fastpq_source_quota
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .ordinary_usage(),
        crate::fastpq::source_reservation::SourceUsage {
            executed_entries: 1,
            ..crate::fastpq::source_reservation::SourceUsage::ZERO
        }
    );
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.usage,
        QuantityCandidateUsage::default()
    );
}

#[test]
fn direct_account_removal_preserves_business_result_without_original_quantity_source() {
    let (state, alice, bob) = account_removal_fixture(Some(Quantity::from(3_u32)));
    let mut block = state.block(quantity_successor_header(&state));
    let mut transaction = block.transaction();
    assert!(transaction.tx_call_hash.is_none());
    Unregister::account(BOB_ID.clone())
        .execute(&BOB_ID, &mut transaction)
        .unwrap();
    assert!(transaction.world.accounts.get(&BOB_ID).is_none());
    assert!(transaction.world.assets.get(&bob).is_none());
    assert_eq!(
        transaction
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
    assert_eq!(
        transaction.pending_fastpq_quantity_candidate.issue,
        Some(QuantityCaptureIssue::UnsupportedOwner)
    );
    assert!(transaction.world.assets.has_raw_write());
    assert!(transaction.world.asset_definitions.has_raw_write());
    assert!(
        transaction
            .pending_fastpq_quantity_candidate
            .entries
            .is_empty()
    );
    transaction.apply();
    block.observe_quantity_block_journals();
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::UnsupportedOwner)
    );
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.usage,
        QuantityCandidateUsage::default()
    );
    assert!(block.world.accounts.get(&BOB_ID).is_none());
    assert!(block.world.assets.get(&bob).is_none());
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}

#[test]
fn account_removal_without_balance_does_not_invent_a_zero_burn() {
    let (state, _, _) = account_removal_fixture(None);
    let (source, _) = bob_account_removal_source(&state, false);
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert!(
        block.retained_execution_outputs_for_test().unwrap()[0]
            .result()
            .is_ok()
    );
    assert!(block.world.accounts.get(&BOB_ID).is_none());
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.usage,
        QuantityCandidateUsage::default()
    );
}

/// Original setup precedes the authentic signed genesis, including each lifecycle
/// and derived index. The source under test is a real signed native instruction.
fn retirement_fixture() -> (State, DomainId, Vec<AssetId>, AssetDefinitionId, AssetId) {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let fees = &mut state.nexus.get_mut().fees;
    fees.base_fee = Quantity::zero();
    fees.per_byte_fee = Quantity::zero();
    fees.per_instruction_fee = Quantity::zero();
    fees.per_gas_unit_fee = Quantity::zero();
    let domain = DomainId::try_new("retirement", "universal").unwrap();
    let other_domain = DomainId::try_new("unrelated", "universal").unwrap();
    let global =
        AssetDefinitionId::derive_from_components(domain.clone(), "global".parse().unwrap());
    let scoped =
        AssetDefinitionId::derive_from_components(domain.clone(), "scoped".parse().unwrap());
    let empty = AssetDefinitionId::derive_from_components(domain.clone(), "empty".parse().unwrap());
    let unrelated = AssetDefinitionId::derive_from_components(
        other_domain.clone(),
        "unrelated".parse().unwrap(),
    );
    let assets = vec![
        AssetId::of(global.clone(), ALICE_ID.clone()),
        AssetId::of(global.clone(), BOB_ID.clone()),
        AssetId::with_scope(
            scoped.clone(),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
        ),
    ];
    let untouched = AssetId::of(unrelated.clone(), BOB_ID.clone());
    {
        let mut setup = state.block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0));
        let mut transaction = setup.transaction_for_callback_testing();
        for account in [&*ALICE_ID, &*BOB_ID] {
            Register::account(Account::new(account.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        for id in [&domain, &other_domain] {
            Register::domain(Domain::new(id.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        for (id, policy, owner) in [
            (global, AssetBalancePolicy::Global, domain.clone()),
            (
                scoped,
                AssetBalancePolicy::DataspaceRestricted,
                domain.clone(),
            ),
            (empty.clone(), AssetBalancePolicy::Global, domain.clone()),
            (unrelated, AssetBalancePolicy::Global, other_domain),
        ] {
            Register::asset_definition(AssetDefinition::numeric(id, "Units", policy, Some(owner)))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        for (asset, amount) in [
            (&assets[0], 10_u32),
            (&assets[1], 3),
            (&assets[2], 4),
            (&untouched, 7),
        ] {
            Mint::asset_quantity(amount, asset.clone())
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    (
        authenticate_quantity_state(state),
        domain,
        assets,
        empty,
        untouched,
    )
}

#[test]
fn signed_definition_and_domain_retirement_capture_exact_original_enumeration_and_absence() {
    for remove_domain in [false, true] {
        let (state, domain, assets, empty, untouched) = retirement_fixture();
        let original: Vec<_> = {
            let view = state.view();
            view.world
                .asset_definitions
                .iter()
                .filter(|(id, _)| {
                    if remove_domain {
                        view.world.asset_definition_domains.get(*id) == Some(&domain)
                    } else {
                        *id == assets[0].definition()
                    }
                })
                .map(|(id, _)| {
                    (
                        id.clone(),
                        *view.world.axt_asset_incarnations.get(id).unwrap(),
                    )
                })
                .collect()
        };
        let instruction: InstructionBox = if remove_domain {
            Unregister::domain(domain.clone()).into()
        } else {
            Unregister::asset_definition(assets[0].definition().clone()).into()
        };
        let (mut source, call) = source(&state, vec![instruction]);
        let (mut block, _recording) = state
            .block_with_recorded_pristine_carrier_stage(
                &source,
                |_| Ok::<(), String>(()),
                |error| error,
            )
            .unwrap();
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block.execute_ordinary_output_plan(&source, None).unwrap();
        let outputs = block.retained_execution_outputs_for_test().unwrap();
        assert_eq!(outputs.len(), 1);
        assert!(
            outputs[0].result().is_ok(),
            "original teardown: {:?}",
            outputs[0].result()
        );
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert!(block.world.accounts.get(&ALICE_ID).is_some());
        assert!(block.world.accounts.get(&BOB_ID).is_some());
        assert_eq!(
            block.world.assets.get(&untouched).unwrap().as_ref(),
            &Quantity::from(7_u32)
        );
        assert_eq!(block.world.domains.get(&domain).is_none(), remove_domain);
        let entry = &block.fastpq_quantity_candidate.entries[&call];
        let expected_burns = if remove_domain { 3 } else { 2 };
        assert_eq!(entry.effects.len(), expected_burns + original.len());
        let mut burned = Vec::new();
        let mut retired = Vec::new();
        for (index, effect) in entry.effects.iter().enumerate() {
            assert_eq!(effect.ordinal as usize, index);
            assert_eq!(
                effect.authority_digest,
                crate::fastpq::authority_digest(&ALICE_ID)
            );
            match &effect.kind {
                FastpqExecutionEffectKindV1::Burn(burn) => {
                    assert!(
                        retired.is_empty(),
                        "all original balances precede lifecycle removal"
                    );
                    assert_eq!(burn.balance_before, burn.amount);
                    assert_eq!(burn.balance_after, Quantity::zero());
                    assert!(
                        burn.supply_after
                            .checked_add_equals(&burn.amount, &burn.supply_before)
                    );
                    burned.push(AssetId::with_scope(
                        burn.balance.asset.definition.clone(),
                        burn.balance.account.clone(),
                        burn.balance.scope,
                    ));
                }
                FastpqExecutionEffectKindV1::Retire(asset) => {
                    assert!(original.contains(&(asset.definition.clone(), asset.incarnation)));
                    assert!(
                        block
                            .world
                            .asset_definitions
                            .get(&asset.definition)
                            .is_none()
                    );
                    assert!(
                        block
                            .world
                            .axt_asset_incarnations
                            .get(&asset.definition)
                            .is_none()
                    );
                    assert!(
                        block
                            .world
                            .asset_definition_assets
                            .get(&asset.definition)
                            .is_none()
                    );
                    retired.push((asset.definition.clone(), asset.incarnation));
                }
                _ => panic!("teardown must emit original burn/retire facts only"),
            }
        }
        let mut selected: Vec<_> = assets
            .iter()
            .filter(|id| remove_domain || id.definition() == assets[0].definition())
            .cloned()
            .collect();
        selected.sort();
        assert_eq!(burned, selected);
        retired.sort();
        let mut expected = original;
        expected.sort();
        assert_eq!(retired, expected);
        if remove_domain {
            assert!(retired.iter().any(|(id, _)| id == &empty));
        }
        assert_exact_applied_measurement(&block.fastpq_quantity_candidate);
        block
            .seal_execution_outputs(&mut source, |state, original, routes| {
                assert_eq!(routes.len(), 1);
                Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                    sccp_finality_header:
                        iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                            state.network_id().as_bytes().to_owned(),
                            original.header().height().get(),
                            original.header().creation_time_ms,
                        )
                        .unwrap(),
                    committed_fragment_count: u64::try_from(state.committed_fragment_count())
                        .unwrap(),
                })
            })
            .unwrap();
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        let super::source_census::QuantitySourceCensusState::Sealed(census) =
            &block.fastpq_quantity_candidate.source_census
        else {
            panic!("actual source census");
        };
        let wire = block.fastpq_quantity_candidate.entries[&call].wire();
        let bytes = norito::encode_canonical(wire).unwrap();
        assert_eq!(
            census.entries()[0].effect_count as usize,
            wire.effects.len()
        );
        assert_eq!(
            census.entries()[0].effects_digest,
            iroha_data_model::fastpq::execution_effects_digest_v1(wire).unwrap()
        );
        assert_ne!(census.entries()[0].effects_digest, Hash::new(bytes));
        assert_eq!(
            block.fastpq_quantity_candidate.require_complete(),
            Err(QuantityCaptureIssue::IncompleteCoverage)
        );
    }
}

#[test]
fn signed_empty_definition_retirement_has_no_dummy_balance_burn_and_exact_one_shot_custody() {
    let (state, _, _, empty, _) = retirement_fixture();
    let (source, call) = source(
        &state,
        vec![Unregister::asset_definition(empty.clone()).into()],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert!(
        block.retained_execution_outputs_for_test().unwrap()[0]
            .result()
            .is_ok()
    );
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue, None);
    let effects = &block.fastpq_quantity_candidate.entries[&call].effects;
    assert_eq!(effects.len(), 1);
    let FastpqExecutionEffectKindV1::Retire(asset) = &effects[0].kind else {
        panic!("one original lifecycle erasure");
    };
    assert_eq!(asset.definition, empty);
    let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
    let baseline = pool.reserved_bytes();
    let plan = QuantityWritePlan::from_effects(effects, 1, &pool).unwrap();
    let charge = pool.reserved_bytes() - baseline;
    assert!(charge > 0);
    drop(plan);
    assert_eq!(pool.reserved_bytes(), baseline);
    let too_small = iroha_allocation::AllocationBudget::new(charge - 1);
    assert!(QuantityWritePlan::from_effects(effects, 1, &too_small).is_err());
    assert_eq!(too_small.peak_reserved_bytes(), 0);
    for attack in 0..8 {
        let mut plan = QuantityWritePlan::from_effects(effects, 1, &pool).unwrap();
        let zero = Quantity::zero();
        match attack {
            0 => {
                plan.consume_retirement(&empty, Some(asset.incarnation), Some(&zero))
                    .unwrap()
                    .applied();
                assert_eq!(plan.finish(), Ok(()));
            }
            1 => {
                assert!(plan.consume_retirement(&empty, None, Some(&zero)).is_err());
                assert!(plan.finish().is_err());
            }
            2 => {
                assert!(
                    plan.consume_retirement(&empty, Some(asset.incarnation), None)
                        .is_err()
                );
                assert!(plan.finish().is_err());
            }
            3 => {
                assert!(
                    plan.consume_retirement(
                        &empty,
                        Some(asset.incarnation),
                        Some(&Quantity::from(1_u32))
                    )
                    .is_err()
                );
                assert!(plan.finish().is_err());
            }
            4 => {
                drop(
                    plan.consume_retirement(&empty, Some(asset.incarnation), Some(&zero))
                        .unwrap(),
                );
                assert!(plan.finish().is_err());
            }
            5 => {
                plan.consume_retirement(&empty, Some(asset.incarnation), Some(&zero))
                    .unwrap()
                    .applied();
                assert!(
                    plan.consume_retirement(&empty, Some(asset.incarnation), Some(&zero))
                        .is_err()
                );
                assert!(plan.finish().is_err());
            }
            6 => {
                assert!(plan.consume_supply(&empty, &zero, &zero).is_err());
                assert!(plan.finish().is_err());
            }
            _ => assert!(plan.finish().is_err()),
        }
        assert_eq!(pool.reserved_bytes(), baseline);
    }
}

#[test]
fn signed_retirement_later_failure_rolls_back_balances_lifecycles_tape_and_original_quota() {
    for remove_domain in [false, true] {
        let (state, domain, assets, _, untouched) = retirement_fixture();
        let definition = assets[0].definition().clone();
        let incarnation = *state
            .view()
            .world
            .axt_asset_incarnations
            .get(&definition)
            .unwrap();
        let instruction: InstructionBox = if remove_domain {
            Unregister::domain(domain.clone()).into()
        } else {
            Unregister::asset_definition(definition.clone()).into()
        };
        let (source, _) = source(&state, vec![instruction.clone(), instruction]);
        let (mut block, _recording) = state
            .block_with_recorded_pristine_carrier_stage(
                &source,
                |_| Ok::<(), String>(()),
                |error| error,
            )
            .unwrap();
        let fragments = block.committed_fragment_count();
        let applied_world_transactions = block.fastpq_quantity_candidate.applied_world_transactions;
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block.execute_ordinary_output_plan(&source, None).unwrap();
        let rows = block.retained_execution_outputs_for_test().unwrap();
        assert_eq!(rows.len(), 1);
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) =
            &rows[0]
        else {
            panic!("rejected original source must retain its Network row");
        };
        assert!(output.result.is_err());
        assert!(output.result.nexus_fee_receipt().is_none());
        assert!(output.result.batch_transfer_outcomes().is_empty());
        assert!(output.completions.is_empty());
        // The original producer retains E=1 even for a rejected invocation;
        // every disposable business/source contribution must roll back to zero.
        assert_eq!(
            block
                .fastpq_source_quota
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .ordinary_usage(),
            crate::fastpq::source_reservation::SourceUsage {
                executed_entries: 1,
                ..crate::fastpq::source_reservation::SourceUsage::ZERO
            }
        );
        // The rejected business overlay and zero-fee settlement publish no fragment.
        // Time maintenance checks the empty local journal without publishing
        // an additional fragment or quantity source transaction.
        assert_eq!(block.committed_fragment_count(), fragments);
        assert_eq!(
            block.fastpq_quantity_candidate.applied_world_transactions,
            applied_world_transactions
        );
        assert!(block.world.domains.get(&domain).is_some());
        assert_eq!(
            block.world.axt_asset_incarnations.get(&definition),
            Some(&incarnation)
        );
        assert_eq!(
            block
                .world
                .asset_definition(&definition)
                .unwrap()
                .total_quantity(),
            &Quantity::from(13_u32)
        );
        for (asset, amount) in [
            (&assets[0], 10_u32),
            (&assets[1], 3),
            (&assets[2], 4),
            (&untouched, 7),
        ] {
            assert_eq!(
                block.world.assets.get(asset).unwrap().as_ref(),
                &Quantity::from(amount)
            );
        }
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert!(block.fastpq_quantity_candidate.entries.is_empty());
        assert_eq!(
            block.fastpq_quantity_candidate.usage,
            QuantityCandidateUsage::default()
        );
    }
}

#[test]
fn signed_retire_reregister_mint_uses_fresh_incarnation_and_keeps_registration_gap_closed() {
    let (state, domain, assets, _, _) = retirement_fixture();
    let id = assets[0].definition().clone();
    let before = *state.view().world.axt_asset_incarnations.get(&id).unwrap();
    let (source, _) = source(
        &state,
        vec![
            Unregister::asset_definition(id.clone()).into(),
            Register::asset_definition(AssetDefinition::numeric(
                id.clone(),
                "Units",
                AssetBalancePolicy::Global,
                Some(domain),
            ))
            .into(),
            Mint::asset_quantity(2_u32, assets[0].clone()).into(),
        ],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    assert!(
        block.retained_execution_outputs_for_test().unwrap()[0]
            .result()
            .is_ok()
    );
    assert_ne!(block.world.axt_asset_incarnations.get(&id), Some(&before));
    assert_eq!(
        block.world.assets.get(&assets[0]).unwrap().as_ref(),
        &Quantity::from(2_u32)
    );
    assert!(block.world.assets.get(&assets[1]).is_none());
    block.observe_quantity_block_journals();
    assert!(block.fastpq_quantity_candidate.issue.is_some());
    assert!(block.fastpq_quantity_candidate.require_complete().is_err());
}

#[test]
fn retirement_without_original_signed_entry_preserves_business_but_cannot_capture() {
    let (state, domain, _, _, untouched) = retirement_fixture();
    let mut block = state.block(quantity_successor_header(&state));
    // The callback fixture explicitly admits a component E owner; this control
    // must retain the absence of every original invocation instead.
    let mut transaction = block.transaction();
    assert_eq!(transaction.tx_call_hash, None);
    Unregister::domain(domain.clone())
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
    assert!(transaction.world.domains.get(&domain).is_none());
    assert!(transaction.world.accounts.get(&ALICE_ID).is_some());
    assert!(transaction.world.accounts.get(&BOB_ID).is_some());
    assert!(transaction.world.assets.get(&untouched).is_some());
    assert_eq!(
        transaction.pending_fastpq_quantity_candidate.issue,
        Some(QuantityCaptureIssue::UnsupportedOwner)
    );
    assert!(transaction.world.assets.has_raw_write());
    assert!(transaction.world.asset_definitions.has_raw_write());
    assert!(
        transaction
            .pending_fastpq_quantity_candidate
            .entries
            .is_empty()
    );
    transaction.apply();
    block.observe_quantity_block_journals();
    assert_eq!(
        block.fastpq_quantity_candidate.require_complete(),
        Err(QuantityCaptureIssue::UnsupportedOwner)
    );
    assert!(block.fastpq_quantity_candidate.entries.is_empty());
    assert_eq!(
        block.fastpq_quantity_candidate.usage,
        QuantityCandidateUsage::default()
    );
    assert!(block.world.domains.get(&domain).is_none());
    assert!(block.world.accounts.get(&ALICE_ID).is_some());
    assert!(block.world.accounts.get(&BOB_ID).is_some());
    assert!(block.world.assets.get(&untouched).is_some());
}

#[test]
fn retained_retirement_invocation_rejects_foreign_quota_pool_and_replaced_call() {
    // Authenticate the independent State before the original block owns this
    // thread's witness recorder; its distinct quota pool is still swapped below.
    let (foreign, _, _) = fixture();
    with_signed_quantity_block(|block, alice, _, call| {
        let mut other_block = foreign.block(quantity_successor_header(&foreign));
        let mut transaction = block.transaction();
        drop(prepare_owned_test_mint(&mut transaction, alice, call));
        let retained = transaction.retain_quantity_retirement_invocation().unwrap();
        assert_eq!(
            transaction.validate_quantity_retirement_invocation(&retained),
            Ok(call)
        );
        transaction.tx_call_hash = Some(Hash::new(b"foreign call"));
        assert!(
            transaction
                .validate_quantity_retirement_invocation(&retained)
                .is_err()
        );
        transaction.tx_call_hash = Some(call);
        assert_eq!(
            transaction.validate_quantity_retirement_invocation(&retained),
            Ok(call)
        );
        let mut other = other_block.transaction_for_callback_testing();
        std::mem::swap(
            &mut transaction.fastpq_source_quota,
            &mut other.fastpq_source_quota,
        );
        assert!(
            transaction
                .validate_quantity_retirement_invocation(&retained)
                .is_err()
        );
        std::mem::swap(
            &mut transaction.fastpq_source_quota,
            &mut other.fastpq_source_quota,
        );
        assert_eq!(
            transaction.validate_quantity_retirement_invocation(&retained),
            Ok(call)
        );
        let foreign_retained = QuantityRetirementInvocation {
            source: retained.source,
            owner: retained.owner.clone(),
            pool: iroha_allocation::AllocationBudget::new(usize::MAX),
        };
        assert!(
            transaction
                .validate_quantity_retirement_invocation(&foreign_retained)
                .is_err()
        );
    });
}

#[test]
fn retirement_missing_extra_stale_and_restored_raw_mutations_refuse_after_original_burns() {
    for attack in 0..5 {
        with_signed_quantity_block(|block, alice, bob, call| {
            let mut transaction = block.transaction();
            drop(prepare_owned_test_mint(&mut transaction, alice, call));
            assert!(matches!(
                transaction.prepare_quantity_retirement_candidate(
                    &ALICE_ID,
                    call,
                    Hash::new(b"premature"),
                    alice.definition()
                ),
                Err(QuantityCaptureIssue::InvalidFacts)
            ));
            Burn::asset_quantity(9_u32, alice.clone())
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
            Burn::asset_quantity(1_u32, bob.clone())
                .execute(&BOB_ID, &mut transaction)
                .unwrap();
            let prepared = transaction
                .prepare_quantity_retirement_candidate(
                    &ALICE_ID,
                    call,
                    Hash::new(b"original empty lifecycle"),
                    alice.definition(),
                )
                .unwrap();
            transaction
                .apply_with_quantity_candidate(Ok(prepared), |transaction| {
                    if attack == 0 {
                        return Ok(());
                    }
                    if attack == 2 {
                        transaction.world.axt_asset_incarnations.insert(
                            alice.definition().clone(),
                            iroha_data_model::nexus::AxtAssetIncarnationV1::try_from_bytes(
                                Hash::new(b"stale lifecycle replacement").into(),
                            )
                            .unwrap(),
                        );
                    }
                    if attack == 3 {
                        let raw = transaction
                            .world
                            .asset_definitions
                            .get_mut(alice.definition())
                            .unwrap();
                        raw.total_quantity = Quantity::from(1_u32);
                        raw.total_quantity = Quantity::zero();
                    }
                    if attack == 4 {
                        transaction
                            .world
                            .asset_definitions
                            .get_mut(alice.definition())
                            .unwrap()
                            .total_quantity = Quantity::from(1_u32);
                    }
                    assert!(
                        transaction
                            .world
                            .remove_asset_definition_entry(alice.definition())
                            .is_some()
                    );
                    if attack == 1 {
                        assert!(
                            transaction
                                .world
                                .remove_asset_definition_entry(alice.definition())
                                .is_none()
                        );
                    }
                    Ok(())
                })
                .unwrap();
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .issue
                    .is_some()
            );
        });
    }
}

/// Public synthetic facts isolate chronology work; signed original producers are
/// exercised separately above and no authenticated execution is claimed here.
fn chronology_work_burn(index: u32) -> FastpqExecutionEffectV1 {
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("chronology-work", "universal").unwrap(),
        "units".parse().unwrap(),
    );
    let incarnation = iroha_data_model::nexus::AxtAssetIncarnationV1::try_from_bytes(
        Hash::new(index.to_le_bytes()).into(),
    )
    .unwrap();
    FastpqExecutionEffectV1 {
        ordinal: index,
        authority_digest: Hash::new(b"synthetic work-only authority"),
        authorization_context: Hash::new(b"synthetic work-only context"),
        kind: FastpqExecutionEffectKindV1::Burn(FastpqExecutionSupplyChangeV1 {
            balance: FastpqExecutionBalanceV1 {
                asset: FastpqExecutionAssetV1 {
                    definition,
                    incarnation,
                },
                account: ALICE_ID.clone(),
                scope: AssetBalanceScope::Global,
            },
            amount: Quantity::zero(),
            balance_before: Quantity::zero(),
            balance_after: Quantity::zero(),
            supply_before: Quantity::zero(),
            supply_after: Quantity::zero(),
        }),
    }
}

#[test]
fn lifecycle_order_ordinary_growing_prefixes_remain_linear_without_allocation() {
    let effects = vec![chronology_work_burn(1); 4096];
    let pool = iroha_allocation::AllocationBudget::new(0);
    let mut preparation = 0usize;
    let mut checks = 0usize;
    for count in 0..=effects.len() {
        let mut order = QuantityLifecycleOrder::prepare(&effects[..count], &pool).unwrap();
        assert!(order.indices.is_none());
        assert!(order.matches(
            &effects[..count],
            |kind, retired| {
                assert!(!retired);
                StateTransaction::quantity_kind_arithmetic_matches(kind)
            },
            |_| panic!("ordinary tape has no retirement")
        ));
        assert_eq!(order.work.preparation_visits, count);
        assert_eq!(order.work.effect_checks, count);
        assert_eq!(order.work.sort_comparisons, 0);
        assert_eq!(order.work.group_comparisons, 0);
        assert_eq!(order.work.retired_group_checks, 0);
        preparation += order.work.preparation_visits;
        checks += order.work.effect_checks;
    }
    // This exercises the actual preparation/final-check loops for every growing
    // prefix. The superseded suffix scan takes 11,453,245,440 comparisons here.
    let expected = effects.len() * (effects.len() + 1) / 2;
    assert_eq!(preparation, expected);
    assert_eq!(checks, expected);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(pool.peak_reserved_bytes(), 0);
}

#[test]
fn lifecycle_order_mixed_chronology_has_charged_n_log_n_work_and_exact_refund() {
    let groups = 2048usize;
    let burns: Vec<_> = (0..groups)
        .map(|i| chronology_work_burn(i as u32))
        .collect();
    for reverse in [false, true] {
        let mut effects = burns.clone();
        for index in 0..groups {
            let index = if reverse { groups - index - 1 } else { index };
            let mut retired = burns[index].clone();
            retired.kind = FastpqExecutionEffectKindV1::Retire(
                QuantityLifecycleOrder::asset(&retired.kind).clone(),
            );
            effects.push(retired);
        }
        let bytes = std::alloc::Layout::array::<usize>(effects.len())
            .unwrap()
            .size();
        let too_small = iroha_allocation::AllocationBudget::new(bytes - 1);
        assert!(matches!(
            QuantityLifecycleOrder::prepare(&effects, &too_small),
            Err(QuantityCaptureIssue::Capacity)
        ));
        assert_eq!(too_small.reserved_bytes(), 0);
        assert_eq!(too_small.peak_reserved_bytes(), 0);
        let pool = iroha_allocation::AllocationBudget::new(bytes);
        let mut order = QuantityLifecycleOrder::prepare(&effects, &pool).unwrap();
        assert_eq!(pool.reserved_bytes(), bytes);
        assert!(order.matches(
            &effects,
            |kind, retired| {
                assert!(retired);
                StateTransaction::quantity_kind_arithmetic_matches(kind)
            },
            |_| true
        ));
        assert_eq!(order.work.preparation_visits, groups + 1);
        assert_eq!(order.work.effect_checks, effects.len());
        assert_eq!(order.work.retired_group_checks, groups);
        assert!(order.work.group_comparisons <= effects.len());
        let logarithm = effects.len().ilog2() as usize + 1;
        assert!(
            order.work.sort_comparisons <= 8 * effects.len() * logarithm,
            "actual sort work {:?}",
            order.work
        );
        drop(order);
        assert_eq!(pool.reserved_bytes(), 0);
        // Dropping a prepared but never consumed order refunds the same original pool.
        drop(QuantityLifecycleOrder::prepare(&effects, &pool).unwrap());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn lifecycle_order_preserves_terminal_retirement_and_original_final_absence_checks() {
    let burn = chronology_work_burn(1);
    let mut retired = burn.clone();
    retired.kind =
        FastpqExecutionEffectKindV1::Retire(QuantityLifecycleOrder::asset(&burn.kind).clone());
    for effects in [
        vec![retired.clone(), burn.clone()],
        vec![retired.clone(), retired.clone()],
    ] {
        let pool = iroha_allocation::AllocationBudget::new(2 * std::mem::size_of::<usize>());
        let mut order = QuantityLifecycleOrder::prepare(&effects, &pool).unwrap();
        assert!(!order.matches(
            &effects,
            |kind, _| StateTransaction::quantity_kind_arithmetic_matches(kind),
            |_| true
        ));
        drop(order);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let effects = vec![burn, retired];
    let pool = iroha_allocation::AllocationBudget::new(2 * std::mem::size_of::<usize>());
    let mut order = QuantityLifecycleOrder::prepare(&effects, &pool).unwrap();
    assert!(!order.matches(&effects, |_, _| true, |_| false));
    assert_eq!(order.work.retired_group_checks, 1);
    assert_eq!(order.work.effect_checks, 0);
}

/// Commit component fee setup before opening the signed quantity source. The
/// network root and both payout deployments come from the maintained certified
/// fixture; test enrollment DATA is not a live issuer or device grant.
fn retirement_due_fee_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    iroha_data_model::validation_fee::ValidationFeePolicyV1,
    AssetId,
    AssetDefinitionId,
) {
    use iroha_data_model::validation_fee::*;
    const START: u64 = 1_793_451_600_000;
    let (mut chain, binding) =
        crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture();
    while chain.height() < 21 {
        chain.commit_at((chain.height() + 1) * 1_000, Vec::new());
    }
    let signer =
        iroha_crypto::KeyPair::try_from_seed(vec![55; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let authority = AccountId::new(signer.public_key().clone());
    let wallet_key =
        iroha_crypto::KeyPair::try_from_seed(vec![3; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let wallet = AccountId::new(wallet_key.public_key().clone());
    let policy = ValidationFeePolicyV1 {
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: chain.network_id(),
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: binding.ds_asset_id.clone(),
        ds_scale: 2,
        fee: "0.10".parse().unwrap(),
        treasury_account_id: binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
        retail_schedule: RetailFeeScheduleV1::default(),
        effective_from_ms: START,
        notice_published_at_ms: START - RETAIL_FEE_NOTICE_MS,
        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.into()],
        reward_custody: binding.custody(),
    };
    let registry = crate::validation_fee::tests::policy_registry(
        std::slice::from_ref(&policy),
        std::slice::from_ref(&binding),
    );
    registry.validate().unwrap();
    let contract_domain = DomainId::try_new("contracts", "universal").unwrap();
    let source_definition = AssetDefinitionId::derive_from_components(
        contract_domain.clone(),
        "retirement_fee_source".parse().unwrap(),
    );
    let empty = AssetDefinitionId::derive_from_components(
        contract_domain.clone(),
        "retirement_fee_empty".parse().unwrap(),
    );
    let source_asset = AssetId::of(source_definition.clone(), authority.clone());
    {
        let state = chain.state();
        let mut block = state.block(BlockHeader::new(
            NonZeroU64::new(chain.height() + 1).unwrap(),
            state.view().latest_block_hash(),
            None,
            START + 1,
            0,
        ));
        let mut transaction = block.transaction_for_callback_testing();
        for id in [source_definition, empty.clone()] {
            Register::asset_definition(AssetDefinition::numeric(
                id,
                "Retirement fee test",
                AssetBalancePolicy::Global,
                Some(contract_domain.clone()),
            ))
            .execute(&authority, &mut transaction)
            .unwrap();
        }
        let wallet_asset = AssetId::new(policy.ds_asset_id.clone(), wallet.clone());
        Mint::asset_quantity(10_u32, wallet_asset)
            .execute(&authority, &mut transaction)
            .unwrap();
        let mut record = RetailFeeAccountStateV1::enroll(wallet.clone(), START, 1_000).unwrap();
        record.payments_used = 50;
        crate::retail_fee::write_account(&mut transaction.world, &record).unwrap();
        crate::validation_fee::tests::install_policy_registry_fixture(&registry, &mut transaction);
        transaction.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    (chain, policy, source_asset, empty)
}

/// Build the observed invocation from the fixture's original signer and current
/// committed route; no caller root or quantity authorization is manufactured.
fn retirement_fee_source(
    chain: &crate::sumeragi::test_chain::CertifiedTestChain,
    source_asset: &AssetId,
) -> (SignedBlock, Hash) {
    let now = 1_793_451_600_000 + 30 * 86_400_000;
    let key = iroha_crypto::KeyPair::try_from_seed(vec![55; 32], iroha_crypto::Algorithm::Ed25519)
        .unwrap();
    let transaction = chain.sign(
        &key,
        [Mint::asset_quantity(1_u32, source_asset.clone()).into()],
        now - 1,
    );
    let call =
        Hash::from(TransactionEntrypoint::External(transaction.clone()).execution_call_hash());
    let header = BlockHeader::new(
        NonZeroU64::new(chain.height() + 1).unwrap(),
        chain.state().view().latest_block_hash(),
        None,
        now,
        0,
    );
    let context = quantity_execution_context(chain.state(), &transaction, &header);
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(Some(BlockExecutionContextBundle::new(vec![context])));
    builder.push_transaction(transaction);
    (builder.build_with_signature(0, key.private_key()), call)
}

#[test]
fn actual_due_fee_write_refuses_retirement_capture_and_rolls_back_original_credit() {
    let (chain, policy, source_asset, empty) = retirement_due_fee_fixture();
    let wallet_key =
        iroha_crypto::KeyPair::try_from_seed(vec![3; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let wallet = AccountId::new(wallet_key.public_key().clone());
    let wallet_asset = AssetId::new(policy.ds_asset_id.clone(), wallet.clone());
    let treasury_asset = AssetId::new(
        policy.ds_asset_id.clone(),
        policy.treasury_account_id.clone(),
    );
    let (source, call) = retirement_fee_source(&chain, &source_asset);
    for inside_owned_retirement in [false, true] {
        for defer_after in [false, true] {
            let (mut block, _recording) = chain
                .state()
                .block_with_recorded_pristine_carrier_stage(
                    &source,
                    |_| Ok::<(), String>(()),
                    |error| error,
                )
                .unwrap();
            block.reserve_ordinary_execution_outputs(&source).unwrap();
            block.execute_ordinary_output_plan(&source, None).unwrap();
            assert!(
                block.retained_execution_outputs_for_test().unwrap()[0]
                    .result()
                    .is_ok()
            );
            block.observe_quantity_block_journals();
            assert_eq!(block.fastpq_quantity_candidate.issue, None);
            let old_usage = block
                .fastpq_source_quota
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .ordinary_usage();
            assert_eq!(old_usage.executed_entries, 1);
            let old_candidate_usage = block.fastpq_quantity_candidate.usage;
            let old_effects = block.fastpq_quantity_candidate.entries[&call].effects.len();
            let old_incarnation = *block.world.axt_asset_incarnations.get(&empty).unwrap();
            let old_record = crate::retail_fee::account_state(&block.world, &wallet)
                .unwrap()
                .unwrap();
            let old_treasury = block
                .world
                .assets
                .get(&treasury_asset)
                .map(|v| v.as_ref().clone());
            let old_receipts =
                crate::retail_fee::receipts(&block.world, &wallet, None, 10).unwrap();
            let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
            let old_credit = pool.reserved_bytes();
            let old_fragments = block.committed_fragment_count();
            let mut transaction = block.transaction();
            transaction.tx_call_hash = Some(call);
            let entry = transaction.block_fastpq_quantity_candidate.entries[&call]
                .context
                .entry;
            transaction.current_lane_id = match entry.route {
                iroha_data_model::fastpq::FastpqSourceRouteV1::Unrouted => None,
                iroha_data_model::fastpq::FastpqSourceRouteV1::Lane(lane) => Some(lane.lane_id),
            };
            transaction.current_dataspace_id = Some(entry.dataspace_id);
            transaction.world.current_dataspace_id = Some(entry.dataspace_id);
            let settle = |transaction: &mut StateTransaction<'_, '_>| {
                crate::retail_fee::settle_balance(&mut transaction.world, &wallet_asset).unwrap();
                assert_eq!(
                    transaction
                        .world
                        .assets
                        .get(&wallet_asset)
                        .unwrap()
                        .as_ref(),
                    &Quantity::from(9_u32)
                );
                assert_eq!(
                    transaction
                        .world
                        .assets
                        .get(&treasury_asset)
                        .unwrap()
                        .as_ref(),
                    &Quantity::from(1_u32)
                );
                let receipts =
                    crate::retail_fee::receipts(&transaction.world, &wallet, None, 10).unwrap();
                assert_eq!(receipts.len(), old_receipts.len() + 1);
                assert!(
                    receipts
                        .iter()
                        .any(|receipt| receipt.collected_minor == 100)
                );
                assert_eq!(transaction.world.retail_fee_pending_credits.len(), 1);
                assert_eq!(transaction.world.retail_fee_pending_transcripts.len(), 1);
            };
            if inside_owned_retirement {
                let prepared = transaction
                    .prepare_quantity_retirement_candidate(
                        source_asset.account(),
                        call,
                        Hash::new(b"original-fee-interleaving-retirement"),
                        &empty,
                    )
                    .unwrap();
                transaction
                    .apply_with_quantity_candidate(Ok(prepared), |transaction| {
                        settle(transaction);
                        assert!(
                            transaction
                                .world
                                .remove_asset_definition_entry(&empty)
                                .is_some()
                        );
                        Ok(())
                    })
                    .unwrap();
            } else {
                settle(&mut transaction);
                Unregister::asset_definition(empty.clone())
                    .execute(source_asset.account(), &mut transaction)
                    .unwrap();
            }
            assert!(transaction.world.asset_definitions.get(&empty).is_none());
            assert!(transaction.world.assets.has_raw_write());
            // The owned plan's first failed port remains the original error;
            // the later sticky raw-write observation must not replace it.
            assert_eq!(
                transaction.pending_fastpq_quantity_candidate.issue,
                Some(if inside_owned_retirement {
                    QuantityCaptureIssue::InvalidFacts
                } else {
                    QuantityCaptureIssue::UnownedMutation
                })
            );
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .entries
                    .is_empty()
            );
            if defer_after {
                transaction
                    .world
                    .defer_execution(ivm::error::ExecutionDeferral::AllocationUnavailable);
                transaction.apply();
            } else {
                drop(transaction);
            }
            assert_eq!(pool.reserved_bytes(), old_credit);
            assert_eq!(block.committed_fragment_count(), old_fragments);
            assert_eq!(
                block
                    .fastpq_source_quota
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .ordinary_usage(),
                old_usage
            );
            assert_eq!(
                block.world.axt_asset_incarnations.get(&empty),
                Some(&old_incarnation)
            );
            assert!(block.world.asset_definitions.get(&empty).is_some());
            assert_eq!(
                block.world.assets.get(&wallet_asset).unwrap().as_ref(),
                &Quantity::from(10_u32)
            );
            assert_eq!(
                block
                    .world
                    .assets
                    .get(&treasury_asset)
                    .map(|v| v.as_ref().clone()),
                old_treasury
            );
            assert_eq!(
                crate::retail_fee::account_state(&block.world, &wallet).unwrap(),
                Some(old_record)
            );
            assert_eq!(
                crate::retail_fee::receipts(&block.world, &wallet, None, 10).unwrap(),
                old_receipts
            );
            block.observe_quantity_block_journals();
            assert_eq!(block.fastpq_quantity_candidate.issue, None);
            assert_eq!(block.fastpq_quantity_candidate.usage, old_candidate_usage);
            assert_eq!(
                block.fastpq_quantity_candidate.entries[&call].effects.len(),
                old_effects
            );
        }
    }
}

#[test]
fn world_local_original_deferral_after_owned_retirement_rolls_back_all_disposable_credit() {
    with_signed_quantity_block(|block, alice, _, call| {
        let old_usage = block
            .fastpq_source_quota
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .ordinary_usage();
        assert_eq!(old_usage.executed_entries, 1);
        let old_effects = block.fastpq_quantity_candidate.entries[&call].effects.len();
        let old_candidate_usage = block.fastpq_quantity_candidate.usage;
        let old_incarnation = *block
            .world
            .axt_asset_incarnations
            .get(alice.definition())
            .unwrap();
        let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let old_credit = pool.reserved_bytes();
        let old_fragments = block.committed_fragment_count();
        let mut transaction = block.transaction();
        drop(prepare_owned_test_mint(&mut transaction, alice, call));
        Unregister::asset_definition(alice.definition().clone())
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        assert!(
            transaction
                .world
                .asset_definitions
                .get(alice.definition())
                .is_none()
        );
        assert_eq!(transaction.pending_fastpq_quantity_candidate.issue, None);
        assert!(matches!(
            transaction.pending_fastpq_quantity_candidate.entries[&call]
                .effects
                .last()
                .unwrap()
                .kind,
            FastpqExecutionEffectKindV1::Retire(_)
        ));
        assert!(pool.reserved_bytes() > old_credit);
        let original_budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = original_budget.try_reserve_bytes(8).unwrap();
        let original = original_budget.try_reserve_bytes(1).unwrap_err();
        transaction.world.defer_execution(original.clone());
        transaction.defer_execution(ivm::error::ExecutionDeferral::AllocationUnavailable);
        let retained = transaction.execution_deferral().unwrap();
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert_eq!(
            retained.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        transaction.apply();
        drop(occupied);
        assert_eq!(original_budget.reserved_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), old_credit);
        assert_eq!(block.committed_fragment_count(), old_fragments);
        assert_eq!(
            block
                .fastpq_source_quota
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .ordinary_usage(),
            old_usage
        );
        assert_eq!(
            block.world.axt_asset_incarnations.get(alice.definition()),
            Some(&old_incarnation)
        );
        assert_eq!(
            block
                .world
                .asset_definition(alice.definition())
                .unwrap()
                .total_quantity(),
            &Quantity::from(10_u32)
        );
        assert_eq!(
            block.world.assets.get(alice).unwrap().as_ref(),
            &Quantity::from(9_u32)
        );
        block.observe_quantity_block_journals();
        assert_eq!(block.fastpq_quantity_candidate.issue, None);
        assert_eq!(block.fastpq_quantity_candidate.usage, old_candidate_usage);
        assert_eq!(
            block.fastpq_quantity_candidate.entries[&call].effects.len(),
            old_effects
        );
    });
}

#[test]
fn original_quantity_census_binds_final_permission_context_and_rejects_late_role_changes() {
    use iroha_data_model::{
        permission::Permission,
        role::{Role, RoleId},
    };
    for epoch in [0, 7] {
        with_sealed_quantity_source_census(|block, _, _, _| {
            let id: RoleId = "late_quantity_role".parse().unwrap();
            let role = Role::new(id.clone(), ALICE_ID.clone())
                .add_permission_with_epoch(
                    Permission::new(
                        "quantity_permission".to_owned(),
                        iroha_primitives::json::Json::new(()),
                    ),
                    epoch,
                )
                .build(&ALICE_ID);
            block.world.roles.insert(id, role);
            block.observe_quantity_block_journals();
            assert_eq!(
                block.fastpq_quantity_candidate.issue,
                Some(QuantityCaptureIssue::InvalidFacts)
            );
            assert!(matches!(
                block.fastpq_quantity_candidate.source_census,
                super::source_census::QuantitySourceCensusState::Failed
            ));
            block.retain_quantity_source_census();
            assert!(block.fastpq_quantity_candidate.require_complete().is_err());
        });
    }
}

#[test]
fn completed_quantity_source_retains_original_tape_graph_and_credit_after_state_drop() {
    // Other Core tests can hold the process-global epoch for arbitrary work.
    // Execute every original source assertion with the stock isolated harness.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::fastpq_quantity_capture::tests::completed_quantity_source_retains_original_tape_graph_and_credit_after_state_drop",
    ) {
        return;
    }
    // State Cells retire through EBR; their credits are separate from this
    // retained quantity graph. Keep those generations fixed during its drop.
    let retirement_pin = crossbeam_epoch::pin();
    let mut retained = None;
    let mut original_pool = None;
    let mut original_ptr = std::ptr::null();
    let mut original_digest = None;
    with_sealed_quantity_source_census(|block, _, _, _| {
        let super::source_census::QuantitySourceCensusState::Sealed(census) =
            &block.fastpq_quantity_candidate.source_census
        else {
            panic!("original completed census")
        };
        let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let before = pool.reserved_bytes();
        let owner = census.retained_archive();
        assert!(owner.belongs_to(&pool));
        assert_eq!(owner.rows().len(), 1);
        let (hash, entry) = &owner.rows()[0];
        original_ptr = entry.effects.as_ptr();
        assert_eq!(
            original_ptr,
            block.fastpq_quantity_candidate.entries[hash]
                .effects
                .as_ptr()
        );
        original_digest =
            Some(iroha_data_model::fastpq::execution_effects_digest_v1(entry.wire()).unwrap());
        let second = owner.clone();
        assert!(iroha_allocation::ChargedShared::ptr_eq(&owner, &second));
        assert_eq!(
            pool.reserved_bytes(),
            before,
            "sharing performs no new admission"
        );
        drop(second);
        retained = Some(owner);
        original_pool = Some(pool);
    });
    let owner = retained.unwrap();
    let pool = original_pool.unwrap();
    assert!(
        pool.reserved_bytes() > 0,
        "original tape/map/control credits outlive State"
    );
    assert_eq!(owner.rows()[0].1.effects.as_ptr(), original_ptr);
    assert_eq!(
        Some(
            iroha_data_model::fastpq::execution_effects_digest_v1(owner.rows()[0].1.wire())
                .unwrap()
        ),
        original_digest
    );
    let with_retired_state_generations = pool.reserved_bytes();
    drop(owner);
    assert!(
        pool.reserved_bytes() < with_retired_state_generations,
        "the final source owner refunds its original graph while State retirement stays pinned"
    );
    drop(retirement_pin);
    // Drive the real grace period before requiring the whole State pool empty.
    // A retained generation or leaked graph still fails the exact zero check.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.reserved_bytes() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "original retired State credits remain: {}",
            pool.reserved_bytes(),
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "final source owner physically frees original graph before refund"
    );
}

#[test]
fn completed_quantity_source_refuses_equal_reconstruction_in_a_fresh_charged_map() {
    with_sealed_quantity_source_census(|block, _, _, _| {
        let budget = block.pipeline_ivm_prepared_cache.execution_budget();
        let mut replacement = super::super::fastpq_quantity_archive::QuantityArchiveMap::default();
        replacement.grow(
            super::super::fastpq_quantity_archive::QuantityArchiveMap::reserve(
                block.fastpq_quantity_candidate.entries.len(),
                budget,
            )
            .unwrap(),
        );
        for (hash, entry) in block.fastpq_quantity_candidate.entries.iter() {
            let tape = QuantityTape::prepare(
                entry.context,
                &entry.effects,
                &[],
                Hash::new(b"unused empty suffix"),
                Hash::new(b"unused empty suffix"),
                entry.effects.len(),
                budget,
            )
            .unwrap();
            assert_eq!(tape.wire(), entry.wire());
            assert_ne!(tape.effects.as_ptr(), entry.effects.as_ptr());
            replacement.insert_reserved(
                *hash,
                QuantityArchivedEntry {
                    tape,
                    measurement: entry.measurement,
                },
            );
        }
        block.fastpq_quantity_candidate.entries = replacement;
        block.observe_quantity_block_journals();
        assert_eq!(
            block.fastpq_quantity_candidate.issue,
            Some(QuantityCaptureIssue::InvalidFacts)
        );
        assert!(block.fastpq_quantity_candidate.require_complete().is_err());
    });
}

#[test]
fn mandatory_journal_uses_native_typed_effects_independently_of_optional_archive_pressure() {
    for starve_archive in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let original = block.fastpq_quantity_candidate.entries[&call]
                .wire()
                .clone();
            let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
            let mut transaction = block.transaction();
            let before = pool.reserved_bytes();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            let expected = iroha_data_model::fastpq::execution_effects_digest_v1(
                prepared.archive.as_ref().unwrap().tape.wire(),
            )
            .unwrap();
            let PreparedQuantityCapture { journal, archive } = prepared;
            drop(archive);
            let journal_bytes = pool.reserved_bytes() - before;
            assert!(journal.is_ok());
            assert!(journal_bytes > 0);
            drop(journal);
            assert_eq!(pool.reserved_bytes(), before);
            let pressure = starve_archive.then(|| {
                pool.try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - journal_bytes)
                    .unwrap()
            });
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            assert!(prepared.journal.is_ok());
            assert_eq!(prepared.archive.is_err(), starve_archive);
            assert!(transaction.execution_deferral().is_none());
            // Release only the unrelated diagnostic pressure; the actual already
            // prepared original journal/permits retain their unchanged credits.
            drop(pressure);
            transaction
                .apply_with_quantity_candidate(Ok(prepared), |state| {
                    apply_owned_test_mint(state, alice);
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .coverage_gap(),
                None
            );
            assert!(
                !transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .is_invalid()
            );
            assert_eq!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .get(&call)
                    .unwrap()
                    .digest()
                    .unwrap(),
                expected
            );
            assert_eq!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .issue
                    .is_some(),
                starve_archive
            );
            transaction.apply();
            block.observe_quantity_block_journals();
            let journal = block
                .fastpq_quantity_candidate
                .commitments
                .original(original.context)
                .unwrap();
            assert_eq!(journal.count(), 2);
            assert_eq!(journal.digest().unwrap(), expected);
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(10u32)
            );
            assert_eq!(
                block
                    .world
                    .asset_definition(alice.definition())
                    .unwrap()
                    .total_quantity(),
                &Quantity::from(11u32)
            );
            assert_eq!(
                block.fastpq_quantity_candidate.issue.is_some(),
                starve_archive
            );
        });
    }
}

#[test]
fn mandatory_journal_shortage_retains_original_refusal_and_never_runs_business_callback() {
    with_signed_quantity_block(|block, alice, _, call| {
        let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let original = *block
            .fastpq_quantity_candidate
            .commitments
            .get(&call)
            .unwrap();
        let mut transaction = block.transaction();
        let before = pool.reserved_bytes();
        let pressure = pool.try_reserve_bytes(pool.limit_bytes() - before).unwrap();
        let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
        let refusal = prepared
            .journal
            .as_ref()
            .err()
            .expect("original mandatory admission refusal")
            .clone();
        assert!(refusal.allocation_refusal().is_some());
        let mut called = false;
        assert!(
            transaction
                .apply_with_quantity_candidate(Ok(prepared), |_| {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
        assert_eq!(transaction.execution_deferral(), Some(refusal));
        assert_eq!(
            transaction
                .pending_fastpq_quantity_candidate
                .commitments
                .coverage_gap(),
            None
        );
        assert!(
            !transaction
                .pending_fastpq_quantity_candidate
                .commitments
                .is_invalid()
        );
        assert!(
            transaction
                .pending_fastpq_quantity_candidate
                .commitments
                .get(&call)
                .is_none()
        );
        drop(transaction);
        drop(pressure);
        assert_eq!(pool.reserved_bytes(), before);
        assert_eq!(
            block.fastpq_quantity_candidate.commitments.get(&call),
            Some(&original)
        );
        assert_eq!(
            block.world.assets.get(alice).unwrap().as_ref(),
            &Quantity::from(9u32)
        );
    });
}

#[test]
fn mandatory_journal_runtime_error_without_writes_preserves_empty_scope_and_rollback() {
    for apply in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let original = *block
                .fastpq_quantity_candidate
                .commitments
                .get(&call)
                .unwrap();
            let mut transaction = block.transaction();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            let result: Result<(), Error> =
                transaction.apply_with_quantity_candidate(Ok(prepared), |_| {
                    Err(InstructionExecutionError::InvariantViolation(
                        "original business refusal before writes".into(),
                    )
                    .into())
                });
            assert!(result.is_err());
            assert_eq!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .coverage_gap(),
                None
            );
            assert!(
                !transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .is_invalid()
            );
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .get(&call)
                    .is_none()
            );
            if apply {
                transaction.apply();
            } else {
                drop(transaction);
            }
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.get(&call),
                Some(&original)
            );
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.coverage_gap(),
                None
            );
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(9u32)
            );
        });
    }
}

#[test]
fn mandatory_journal_caught_partial_write_marks_typed_gap_only_when_original_overlay_applies() {
    for apply in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let original = *block
                .fastpq_quantity_candidate
                .commitments
                .get(&call)
                .unwrap();
            let mut transaction = block.transaction();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            let result: Result<(), Error> =
                transaction.apply_with_quantity_candidate(Ok(prepared), |state| {
                    state
                        .world
                        .assign_quantity_balance_exact(alice, Quantity::from(10u32))
                        .unwrap();
                    Err(InstructionExecutionError::InvariantViolation(
                        "original failure after one actual port".into(),
                    )
                    .into())
                });
            assert!(result.is_err());
            assert_eq!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .coverage_gap(),
                Some(CoverageGap::PartialTypedOperation)
            );
            assert!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .get(&call)
                    .is_none()
            );
            if apply {
                transaction.apply();
            } else {
                drop(transaction);
            }
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.get(&call),
                Some(&original)
            );
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.coverage_gap(),
                apply.then_some(CoverageGap::PartialTypedOperation)
            );
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(if apply { 10u32 } else { 9u32 })
            );
        });
    }
}

#[test]
fn mandatory_journal_complete_effect_survives_caught_late_error_and_rolls_back_with_world() {
    for apply in [false, true] {
        with_signed_quantity_block(|block, alice, _, call| {
            let original = *block
                .fastpq_quantity_candidate
                .commitments
                .get(&call)
                .unwrap();
            let mut transaction = block.transaction();
            let prepared = prepare_owned_test_mint(&mut transaction, alice, call);
            let result: Result<(), Error> =
                transaction.apply_with_quantity_candidate(Ok(prepared), |state| {
                    apply_owned_test_mint(state, alice);
                    Err(InstructionExecutionError::InvariantViolation(
                        "original later nonquantity refusal".into(),
                    )
                    .into())
                });
            assert!(result.is_err());
            let applied = *transaction
                .pending_fastpq_quantity_candidate
                .commitments
                .get(&call)
                .unwrap();
            assert_eq!(applied.count(), 2);
            assert_eq!(
                transaction
                    .pending_fastpq_quantity_candidate
                    .commitments
                    .coverage_gap(),
                None
            );
            if apply {
                transaction.apply();
            } else {
                drop(transaction);
            }
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.get(&call),
                Some(if apply { &applied } else { &original })
            );
            assert_eq!(
                block.fastpq_quantity_candidate.commitments.coverage_gap(),
                None
            );
            assert_eq!(
                block.world.assets.get(alice).unwrap().as_ref(),
                &Quantity::from(if apply { 10u32 } else { 9u32 })
            );
        });
    }
}

#[test]
fn mandatory_finalized_source_retains_complete_success_empty_and_rejected_positions() {
    with_sealed_quantity_source_census(|block, source, _, _| {
        let (manifest, leaves, bytes) = block.finalized_quantity_source_for_test().unwrap();
        assert_eq!(
            manifest.coverage,
            iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Complete
        );
        assert_eq!(manifest.executed_entry_count, 3);
        assert_eq!(manifest.statement_count, 1);
        let inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        assert_eq!(
            manifest.source_entries_digest,
            iroha_data_model::fastpq::fastpq_source_execution_entries_digest_v1(
                inventory.entries(),
                3
            )
            .unwrap()
        );
        let [leaf] = leaves else {
            panic!("exact nonempty source")
        };
        assert_eq!(leaf.entry_index, 0);
        assert_eq!(leaf.statement_index, 0);
        assert_eq!(leaf.effect_count, 1);
        assert_eq!(
            leaf.entry_hash,
            Hash::from(
                source
                    .network_entrypoint_at(0)
                    .unwrap()
                    .execution_call_hash()
            )
        );
        assert_eq!(leaf.tx_set_hash, inventory.tx_set_hash());
        assert_eq!(
            leaf.effects_digest,
            <[u8; 32]>::from(
                block
                    .fastpq_quantity_candidate
                    .commitments
                    .get(&leaf.entry_hash)
                    .unwrap()
                    .digest()
                    .unwrap()
            )
        );
        let tree: iroha_crypto::MerkleTree<_> = leaves
            .iter()
            .map(|leaf| {
                iroha_data_model::fastpq::fastpq_ordinary_source_statement_leaf_hash_v1(leaf)
                    .unwrap()
            })
            .collect();
        assert_eq!(manifest.statement_root, Hash::from(tree.root().unwrap()));
        assert_eq!(
            norito::decode_canonical::<
                iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1,
            >(bytes)
            .unwrap(),
            manifest
        );
        assert_eq!(bytes, norito::encode_canonical(&manifest).unwrap());
    });
}

#[test]
fn mandatory_source_bytes_ignore_optional_archive_loss_and_refusal() {
    let (state, alice, _) = fixture();
    let (proposal, call) = source(
        &state,
        vec![Mint::asset_quantity(2u32, alice.clone()).into()],
    );
    let mut original = None;
    for discard_optional in [false, true] {
        let mut source = proposal.clone();
        let (mut block, _recording) = state
            .block_with_recorded_pristine_carrier_stage(
                &source,
                |_| Ok::<(), String>(()),
                |error| error,
            )
            .unwrap();
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block.execute_ordinary_output_plan(&source, None).unwrap();
        let journal = *block
            .fastpq_quantity_candidate
            .commitments
            .get(&call)
            .unwrap();
        assert_eq!(journal.count(), 1);
        if discard_optional {
            // Dispose only the optional retained proof tape after authentic execution.
            // The separate real-pool-pressure control covers the refusal producer.
            block.fastpq_quantity_candidate.entries = QuantityArchiveMap::default();
            block
                .fastpq_quantity_candidate
                .poison(QuantityCaptureIssue::Capacity);
        }
        block
            .seal_execution_outputs(&mut source, |state, original, routes| {
                assert_eq!(routes.len(), 1);
                Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                    sccp_finality_header:
                        iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                            state.network_id().as_bytes().to_owned(),
                            original.header().height().get(),
                            original.header().creation_time_ms,
                        )
                        .unwrap(),
                    committed_fragment_count: u64::try_from(state.committed_fragment_count())
                        .unwrap(),
                })
            })
            .unwrap();
        let (manifest, leaves, bytes) = block.finalized_quantity_source_for_test().unwrap();
        assert_eq!(
            manifest.coverage,
            iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Complete
        );
        assert_eq!(leaves.len(), 1);
        assert_eq!(
            leaves[0].effects_digest,
            <[u8; 32]>::from(journal.digest().unwrap())
        );
        let observed = (manifest, leaves.to_vec(), bytes.to_vec());
        if let Some(expected) = &original {
            assert_eq!(&observed, expected);
        } else {
            original = Some(observed);
        }
        assert_eq!(
            block.fastpq_quantity_candidate.issue.is_some(),
            discard_optional
        );
        assert_eq!(
            block.world.assets.get(&alice).unwrap().as_ref(),
            &Quantity::from(12u32)
        );
    }
    assert_eq!(
        state.world.assets.view().get(&alice).unwrap().as_ref(),
        &Quantity::from(10u32)
    );
}

#[test]
fn mandatory_source_finalizer_memory_refusal_is_original_local_deferred_without_output() {
    let (state, alice, _) = fixture();
    let (mut source, call) = source(
        &state,
        vec![Mint::asset_quantity(2u32, alice.clone()).into()],
    );
    let proposal_bytes = source.encode_wire().unwrap();
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let journal = *block
        .fastpq_quantity_candidate
        .commitments
        .get(&call)
        .unwrap();
    let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
    let pressure = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let error = block
        .seal_execution_outputs(&mut source, |state, original, routes| {
            assert_eq!(routes.len(), 1);
            Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                sccp_finality_header:
                    iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                        state.network_id().as_bytes().to_owned(),
                        original.header().height().get(),
                        original.header().creation_time_ms,
                    )
                    .unwrap(),
                committed_fragment_count: u64::try_from(state.committed_fragment_count()).unwrap(),
            })
        })
        .unwrap_err();
    let crate::state::output_capacity::ExecutionOutputSealError::Deferred(original) = error else {
        panic!("original mandatory admission must remain a local deferral: {error:?}")
    };
    let refusal = original
        .allocation_refusal()
        .expect("original pool refusal preserved");
    let iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes, ..
    } = refusal
    else {
        panic!("occupied original finite pool")
    };
    assert!(*requested_bytes > 0);
    assert_eq!(
        pool.try_reserve_bytes(*requested_bytes).unwrap_err(),
        *refusal
    );
    assert_eq!(
        block.fastpq_quantity_candidate.commitments.get(&call),
        Some(&journal)
    );
    assert_eq!(
        block.fastpq_quantity_candidate.commitments.coverage_gap(),
        None
    );
    assert!(block.finalized_quantity_source_for_test().is_err());
    assert_eq!(source.encode_wire().unwrap(), proposal_bytes);
    assert_eq!(
        block.world.assets.get(&alice).unwrap().as_ref(),
        &Quantity::from(12u32)
    );
    drop(pressure);
    drop(block);
    assert_eq!(
        state.world.assets.view().get(&alice).unwrap().as_ref(),
        &Quantity::from(10u32)
    );
}

#[test]
fn mandatory_finalized_source_refuses_late_quantity_and_original_journal_mutations() {
    for mutation in 0..3 {
        with_sealed_quantity_source_census(|block, _, alice, _| {
            assert!(block.finalized_quantity_source_for_test().is_ok());
            match mutation {
                0 => {
                    let mut transaction = block.transaction();
                    transaction
                        .world
                        .increase_asset_total_amount(alice.definition(), &Quantity::from(1u32))
                        .unwrap();
                    transaction.apply();
                }
                1 => {
                    block.fastpq_quantity_candidate.commitments.invalidate();
                }
                _ => {
                    block
                        .fastpq_quantity_candidate
                        .commitments
                        .unsupported(CoverageGap::RawQuantityWrite);
                }
            }
            assert!(block.finalized_quantity_source_for_test().is_err());
        });
    }
}

#[test]
fn mandatory_source_marks_only_actual_untyped_quantity_mutation_as_unsupported() {
    let (state, alice, _) = fixture();
    let (mut source, call) = source(
        &state,
        vec![Mint::asset_quantity(2u32, alice.clone()).into()],
    );
    let (mut block, _recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let original = *block
        .fastpq_quantity_candidate
        .commitments
        .get(&call)
        .unwrap();
    block
        .seal_execution_outputs(&mut source, |state, original, _| {
            let mut transaction = state.transaction();
            transaction
                .world
                .increase_asset_total_amount(alice.definition(), &Quantity::from(1u32))
                .unwrap();
            transaction.apply();
            Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
                sccp_finality_header:
                    iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                        state.network_id().as_bytes().to_owned(),
                        original.header().height().get(),
                        original.header().creation_time_ms,
                    )
                    .unwrap(),
                committed_fragment_count: u64::try_from(state.committed_fragment_count()).unwrap(),
            })
        })
        .unwrap();
    let (manifest, leaves, bytes) = block.finalized_quantity_source_for_test().unwrap();
    assert_eq!(
        manifest.coverage,
        iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Unsupported
    );
    assert_eq!(manifest.executed_entry_count, 1);
    assert_eq!(leaves.len(), 1);
    assert_eq!(
        leaves[0].effects_digest,
        <[u8; 32]>::from(original.digest().unwrap())
    );
    assert_eq!(
        block.fastpq_quantity_candidate.commitments.coverage_gap(),
        Some(CoverageGap::RawQuantityWrite)
    );
    assert_eq!(
        block
            .world
            .asset_definition(alice.definition())
            .unwrap()
            .total_quantity(),
        &Quantity::from(13u32)
    );
    assert_eq!(norito::decode_canonical::<iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1>(bytes).unwrap(), manifest);
    let tree: iroha_crypto::MerkleTree<_> = leaves
        .iter()
        .map(|leaf| {
            iroha_data_model::fastpq::fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap()
        })
        .collect();
    assert!(
        !iroha_data_model::fastpq::verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[0],
            &leaves[0],
            &manifest,
            &tree.get_proof(0).unwrap(),
            1,
            1
        )
    );
}

#[path = "fastpq_quantity_capture_witness_tests.rs"]
mod witness_custody;
