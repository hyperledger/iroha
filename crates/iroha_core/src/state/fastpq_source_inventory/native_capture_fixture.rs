//! Genuine signed Network producer for source-capture custody controls.
//!
//! Setup is authenticated by signed genesis; every successor effect is executed
//! through its original output owner. Expected archives are read from the sealed
//! carrier. No supplied-array inventory creates the completed quantity source.

use crate::{
    exec_witness::ExecWitnessGuard,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, StateBlock, StateReadOnly, World},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    block::{
        BlockExecutionContextBundle, BlockHeader, ExternalExecutionContext, SignedBlock,
        builder::BlockBuilder,
    },
    domain::Domain,
    isi::{
        Log, Mint, Register, Transfer,
        transfer::{TransferAssetBatch, TransferAssetBatchEntry},
    },
    prelude::{InstructionBox, Level, TransactionBuilder},
    transaction::{FeePaymentIntent, SignedTransaction, TransactionEntrypoint},
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc, time::Duration};

fn component_fixture() -> (State, AssetId, AssetId) {
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let definition = AssetDefinitionId::derive_from_components(domain, "rose".parse().unwrap());
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
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
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
    (state, alice, bob)
}

fn fixture() -> (State, AssetId, AssetId) {
    let (component, alice, bob) = component_fixture();
    (authenticate_quantity_state(component), alice, bob)
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

/// Execute one genuine Network source; false is a successful zero-transfer Log.
pub(crate) fn with_native_capture_source<T>(
    with_transfer: bool,
    action: impl FnOnce(&State, Box<StateBlock<'_>>, ExecWitnessGuard, SignedBlock, Hash) -> T,
) -> T {
    with_native_capture_sources(
        &[usize::from(with_transfer)],
        |state, block, recording, source, hashes| {
            assert_eq!(hashes.len(), 1);
            action(state, block, recording, source, hashes[0])
        },
    )
}

/// Execute distinct original entries with the specified transfer counts.
/// A distinct diagnostic Log in every entry gives repeated equal transfer bodies
/// separate authentic identities without fabricating an execution-call hash.
pub(crate) fn with_native_capture_sources<T>(
    transfers_per_entry: &[usize],
    action: impl FnOnce(&State, Box<StateBlock<'_>>, ExecWitnessGuard, SignedBlock, Vec<Hash>) -> T,
) -> T {
    assert!(!transfers_per_entry.is_empty());
    let (state, alice, _) = fixture();
    with_native_state_sources(state, alice, transfers_per_entry, action)
}

fn with_native_state_sources<T>(
    state: State,
    alice: AssetId,
    transfers_per_entry: &[usize],
    action: impl FnOnce(&State, Box<StateBlock<'_>>, ExecWitnessGuard, SignedBlock, Vec<Hash>) -> T,
) -> T {
    let header = quantity_successor_header(&state);
    let mut builder = BlockBuilder::new(header);
    let mut contexts = Vec::new();
    let mut hashes = Vec::new();
    for (ordinal, &count) in transfers_per_entry.iter().enumerate() {
        let mut body = vec![InstructionBox::from(Log::new(
            Level::INFO,
            format!("native capture source {ordinal}"),
        ))];
        if count == 1 {
            body.push(Transfer::asset_quantity(alice.clone(), 1_u32, BOB_ID.clone()).into());
        } else if count > 1 {
            body.push(
                TransferAssetBatch::new(
                    (0..count)
                        .map(|leg| {
                            TransferAssetBatchEntry::with_leg_id(
                                format!("leg-{leg}"),
                                ALICE_ID.clone(),
                                BOB_ID.clone(),
                                alice.definition().clone(),
                                1_u32,
                            )
                        })
                        .collect(),
                )
                .into(),
            );
        }
        let mut transaction = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(header.creation_time() - Duration::from_millis(1));
        let mut transaction = transaction.with_instructions(body);
        {
            let view = state.view();
            if let Some(iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                dataspace_id,
                ..
            }) = crate::sumeragi::lanes::routing::committed_root_scope(view.world())
            {
                let draft = transaction.clone().sign(ALICE_KEYPAIR.private_key());
                let quote = crate::executor::quote_nexus_fee_admission_draft(
                    view.world(),
                    view.nexus(),
                    view.pipeline(),
                    &view.zk().gas,
                    draft.payload(),
                    u64::try_from(draft.creation_time().as_millis()).unwrap(),
                    header.height().get(),
                    Some(dataspace_id),
                )
                .expect("private quantity source pays its original signed fee policy");
                transaction = transaction.with_fee_payment_intent(quote.recommended_intent);
            }
        }
        let signed = transaction.sign(ALICE_KEYPAIR.private_key());
        hashes.push(Hash::from(
            TransactionEntrypoint::External(signed.clone()).execution_call_hash(),
        ));
        contexts.push(quantity_execution_context(&state, &signed, &header));
        builder.push_transaction(signed);
    }
    assert_eq!(
        hashes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        hashes.len()
    );
    builder.set_execution_context(Some(BlockExecutionContextBundle::new(contexts)));
    let source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    let (mut block, recording) = state
        .block_with_recorded_pristine_carrier_stage(
            &source,
            |_| Ok::<(), String>(()),
            |error| error,
        )
        .unwrap();
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block.execute_ordinary_output_plan(&source, None).unwrap();
    let rows = block.retained_execution_outputs_for_test().unwrap();
    assert_eq!(rows.len(), transfers_per_entry.len());
    assert!(rows.iter().all(|row| row.result().is_ok()), "{rows:?}");
    assert_eq!(source.header().height().get(), 2);
    action(&state, block, recording, source, hashes)
}

/// Complete the real owned output boundary and retain its quantity-source journal.
pub(crate) fn seal_native_source(
    block: &mut StateBlock<'_>,
    source: &mut SignedBlock,
) -> Result<(), crate::state::output_capacity::ExecutionOutputSealError<String>> {
    block.seal_execution_outputs(source, |state, source, routes| {
        assert_eq!(routes.len(), source.network_entrypoint_count());
        Ok::<_, String>(crate::state::output_capacity::ExecutionOutputSealMetadata {
            sccp_finality_header:
                iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                    *state.network_id().as_bytes(),
                    source.header().height().get(),
                    source.header().creation_time_ms,
                )
                .expect("nonzero fixture height"),
            committed_fragment_count: u64::try_from(state.committed_fragment_count()).unwrap(),
        })
    })?;
    block.observe_quantity_block_journals();
    assert_eq!(block.fastpq_quantity_candidate.issue_for_test(), None);
    Ok(())
}

#[test]
fn genuine_capture_fixture_retains_signed_root_and_complete_empty_and_transfer_sources() {
    for transfer in [false, true] {
        with_native_capture_source(
            transfer,
            |state, mut block, _recording, mut source, hash| {
                assert_eq!(state.committed_height(), 1);
                assert_eq!(
                    source.header().prev_block_hash(),
                    state.latest_block_hash_fast()
                );
                assert!(
                    source.header().creation_time()
                        > state
                            .view()
                            .latest_block()
                            .unwrap()
                            .unwrap()
                            .header()
                            .creation_time()
                );
                seal_native_source(&mut block, &mut source).unwrap();
                let inventory = block
                    .verified_fastpq_source_inventory_for_capture()
                    .unwrap();
                assert_eq!(inventory.entries().len(), 1);
                assert_eq!(inventory.entries()[0].entry_hash, hash);
                assert_eq!(source.fastpq_transcripts().len(), usize::from(transfer));
                assert!(block.fastpq_transcripts.is_empty());
                block.capture_exec_witness().unwrap();
                assert_eq!(
                    block.take_exec_witness().unwrap().fastpq_transcripts.len(),
                    usize::from(transfer)
                );
            },
        );
    }
}

/// Exercise original ordinary or mandatory quota custody with a real producer.
/// The mandatory branch is the genuine height-two expired governance-lock sweep;
/// its returned hash is read from that applied purpose's retained transcript.
pub(crate) fn with_native_capture_quota_source<T>(
    protocol: bool,
    action: impl FnOnce(&State, Box<StateBlock<'_>>, ExecWitnessGuard, SignedBlock, Hash) -> T,
) -> T {
    if !protocol {
        return with_native_capture_source(true, action);
    }
    use crate::state::{GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum};
    let (state, alice, bob) = fixture();
    let header = state.view().latest_block().unwrap().unwrap().header();
    {
        let mut setup = state.block(header);
        let mut tx = setup.transaction_for_callback_testing();
        Mint::asset_quantity(Quantity::one(), bob)
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        let custody = GovernanceLockCustody {
            escrowed: true,
            asset_definition_id: alice.definition().clone(),
            bond_escrow_account: BOB_ID.clone(),
            slash_receiver_account: BOB_ID.clone(),
        };
        tx.validate_fastpq_governance_lock("native-capture-expiry", &ALICE_ID, &custody)
            .unwrap();
        tx.world.put_governance_locks(
            "native-capture-expiry".into(),
            GovernanceLocksForReferendum {
                locks: BTreeMap::from([(
                    ALICE_ID.clone(),
                    GovernanceLockRecord {
                        owner: ALICE_ID.clone(),
                        amount: Quantity::one(),
                        slashed: Quantity::zero(),
                        expiry_height: 1,
                        direction: 0,
                        duration_blocks: 1,
                        custody,
                    },
                )]),
            },
        );
        tx.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    with_native_state_sources(
        state,
        alice,
        &[0],
        |state, block, recording, source, ordinary_hashes| {
            assert_eq!(block.fastpq_transcripts.len(), 1);
            let protocol_hash = *block.fastpq_transcripts.keys().next().unwrap();
            assert!(!ordinary_hashes.contains(&protocol_hash));
            action(state, block, recording, source, protocol_hash)
        },
    )
}

#[test]
fn genuine_capture_fixture_mandatory_source_is_original_expired_lock_work() {
    with_native_capture_quota_source(true, |_state, mut block, _recording, mut source, hash| {
        seal_native_source(&mut block, &mut source).unwrap();
        let inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        let entry = inventory
            .entries()
            .iter()
            .find(|entry| entry.entry_hash == hash)
            .unwrap();
        assert_eq!(
            entry.execution_kind,
            iroha_data_model::fastpq::FastpqSourceExecutionKindV1::ProtocolPurpose
        );
        assert_eq!(source.fastpq_transcripts().len(), 1);
        block.capture_exec_witness().unwrap();
        assert_eq!(
            block.take_exec_witness().unwrap().fastpq_transcripts[0].entry_hash,
            hash
        );
    });
}

/// Exercise refusal through the actual retained native producer and exact quorum.
/// Inspection can tamper only before certification. A rejected attempt cannot
/// replace its original result, durably append H2, or publish its State overlay.
pub(crate) fn assert_native_publication_refuses(
    with_transfer: bool,
    inspect: impl for<'borrow, 'state> FnOnce(
        crate::sumeragi::executor::PendingExecutionView<'borrow, 'state>,
    ) + Send
    + 'static,
) {
    use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
    let (component, alice, _) = component_fixture();
    let nexus = component.nexus_snapshot();
    let mut config = TestChainConfig::new(component.world, 0);
    config.chain_id = component.chain_id;
    config.pipeline = component.pipeline;
    config.governance = Some(component.gov);
    config.nexus = Some(nexus);
    let mut chain = CertifiedTestChain::start(config).expect("genuine source publication chain");
    let state = Arc::clone(chain.state());
    let kura = Arc::clone(chain.kura());
    let parent = chain.committed(1).block().encode_wire().unwrap();
    let creation = chain.committed(1).block().header().creation_time() + Duration::from_millis(1);
    let mut body = vec![InstructionBox::from(Log::new(
        Level::INFO,
        "native source publication refusal".to_owned(),
    ))];
    if with_transfer {
        body.push(Transfer::asset_quantity(alice, 1_u32, BOB_ID.clone()).into());
    }
    let mut tx = TransactionBuilder::new(
        *state.network_id_ref(),
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    tx.set_creation_time(creation);
    let tx = tx.with_instructions(body).sign(ALICE_KEYPAIR.private_key());
    // The actual assembler owns cadence and transaction/parent ordering.
    let proposal = chain.proposal(None, vec![tx]);
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    let original_result = pending.result();
    pending.inspect(inspect).unwrap();
    assert!(pending.prepare(Signers::Quorum).is_err());
    assert!(pending.publish(Signers::Quorum).is_err());
    assert_eq!(pending.result(), original_result);
    assert_eq!(kura.blocks_count(), 1);
    drop(pending);
    assert_eq!(state.view().height(), 1);
    assert_eq!(chain.committed(1).block().encode_wire().unwrap(), parent);
}

#[test]
fn native_publication_refuses_original_source_public_content_substitution() {
    assert_native_publication_refuses(true, |mut original| {
        let inventory = original
            .state
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        original.witness.offer_reconstructed_tamper(|offered| {
            offered.fastpq_transcripts[0].transcripts[0].authority_digest =
                Hash::new(b"publication substitution");
        });
        let error = inventory
            .verify_ordinary_witness_bundles(&original.witness.wire().fastpq_transcripts)
            .unwrap_err();
        assert_eq!(
            error,
            "FASTPQ final witness public content differs from the owned inventory seal"
        );
        assert!(
            original
                .state
                .verify_sumeragi_execution_witness(original.block.as_ref(), original.witness.wire())
                .is_err()
        );
    });
}

/// Execute a genuine transfer under a signed nondefault dataspace root.
/// Both native routing and physical asset scope originate in the actual signed genesis.
pub(crate) fn with_native_capture_dataspace_source<T>(
    action: impl FnOnce(&State, Box<StateBlock<'_>>, ExecWitnessGuard, SignedBlock, Hash) -> T,
) -> T {
    use crate::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        NetworkId, Registrable,
        asset::{Asset, AssetBalanceScope},
        block::consensus::{PrivateRootFeePolicy, SumeragiRootScope},
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        parameter::Parameter,
    };
    use iroha_model_base::topology::DataSpaceId;
    let ds = DataSpaceId::new(7);
    let domain = DomainId::parse_fully_qualified("app.capture-private").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "units".parse().unwrap());
    let mut asset_definition = AssetDefinition::numeric(
        definition.clone(),
        "Private units",
        AssetBalancePolicy::DataspaceRestricted,
        Some(domain.clone()),
    )
    .build(&ALICE_ID);
    asset_definition.total_quantity = 1_000_000_u32.into();
    let alice = AssetId::with_scope(
        definition.clone(),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(ds),
    );
    let world = World::with_assets(
        [Domain::new(domain).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [asset_definition],
        [Asset::new(alice.clone(), 1_000_000_u32)],
        [],
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_parameters.push(Parameter::Custom(
        PrivateRootFeePolicy {
            asset_definition_id: definition.clone(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    config.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"capture independent public parent",
            )),
        ),
        dataspace_id: ds,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = definition.to_string();
    nexus.lane_catalog = LaneCatalog::new(
        std::num::NonZeroU32::new(1).unwrap(),
        vec![LaneConfig {
            dataspace_id: ds,
            visibility: LaneVisibility::Restricted,
            ..Default::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: ds,
        alias: "capture-private".to_owned(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = ds;
    config.nexus = Some(nexus);
    let authority = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared =
        CertifiedTestChain::prepare(config).expect("signed nondefault dataspace genesis");
    let state = Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished fixture owner is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &authority,
        mode.into(),
        None,
    )
    .unwrap();
    with_native_state_sources(state, alice, &[1], |state, block, guard, source, hashes| {
        assert_eq!(hashes.len(), 1);
        action(state, block, guard, source, hashes[0])
    })
}

/// Signed root and funded Alice transfer source for actual native publication controls.
pub(crate) fn native_publication_chain()
-> (crate::sumeragi::test_chain::CertifiedTestChain, AssetId) {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let (component, alice, _) = component_fixture();
    let nexus = component.nexus_snapshot();
    let mut config = TestChainConfig::new(component.world, 0);
    config.chain_id = component.chain_id;
    config.pipeline = component.pipeline;
    config.governance = Some(component.gov);
    config.nexus = Some(nexus);
    (
        CertifiedTestChain::start(config).expect("genuine native source publication chain"),
        alice,
    )
}
