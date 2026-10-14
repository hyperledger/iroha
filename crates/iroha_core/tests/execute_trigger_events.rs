//! Validate that by-call trigger execution emits both the trigger event and resulting data events.

use iroha_core::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
use iroha_core::{
    smartcontracts::triggers::{
        set::{ExecutableRef, SetReadOnly},
        specialized::LoadedActionTrait,
    },
    state::{State, WorldReadOnly},
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use mv::storage::StorageReadOnly;
use std::sync::Arc;
fn build_state_and_ids() -> (CertifiedTestChain, NetworkId, TriggerId, AssetId) {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let asset_definition = AssetDefinition::new(
        asset_definition_id,
        "rose".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id.clone()),
    )
    .build(&ALICE_ID);
    let stored_asset_definition_id = asset_definition.id().clone();
    let fee_domain_id =
        DomainId::parse_fully_qualified("universal.universal").expect("fee domain id");
    let fee_domain = Domain::new(fee_domain_id.clone()).build(&ALICE_ID);
    let fee_asset_definition_id =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            fee_domain_id,
            "xor".parse().unwrap(),
        );
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let fee_asset = Asset::new(
        AssetId::new(fee_asset_definition_id, ALICE_ID.clone()),
        Quantity::from(100_000_u64),
    );
    let world = iroha_core::state::World::with_assets(
        [domain, fee_domain],
        [account],
        [asset_definition, fee_asset_definition],
        [fee_asset],
        [],
    );
    let chain =
        CertifiedTestChain::start(TestChainConfig::new(world, 0)).expect("native trigger genesis");
    let network_id = chain.network_id();
    let state = chain.state();
    let trigger_id: TriggerId = "sse_smoke_trigger".parse().expect("trigger id");
    let asset_id = AssetId::new(stored_asset_definition_id, ALICE_ID.clone());
    state
        .view()
        .world()
        .asset_definition(asset_id.definition())
        .expect("seeded asset definition must be resolvable");
    (chain, network_id, trigger_id, asset_id)
}
fn register_trigger(
    chain: &mut CertifiedTestChain,
    network_id: &NetworkId,
    trigger_id: &TriggerId,
    asset_id: &AssetId,
) -> usize {
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                asset_id.clone(),
            ))],
            Repeats::Indefinitely,
            ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(ALICE_ID.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ));
    let register_tx = TransactionBuilder::new(
        *network_id,
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([register_trigger])
    .sign(ALICE_KEYPAIR.private_key());
    let proposal = chain.proposal(None, vec![register_tx]);
    let mut pending = chain
        .begin_proposal(proposal, Default::default())
        .expect("native registration executes");
    let fragments = pending
        .inspect(|execution| execution.state.committed_fragment_count())
        .unwrap();
    let committed = pending
        .publish(Signers::Quorum)
        .expect("native registration publishes");
    assert!(
        committed.block().output_error(0).is_none(),
        "{:?}",
        committed.block().output_error(0)
    );
    fragments
}

fn execute_trigger(
    chain: &mut CertifiedTestChain,
    network_id: &NetworkId,
    trigger_id: &TriggerId,
    asset_id: &AssetId,
) -> (Vec<EventBox>, usize, Option<String>) {
    let exec_tx = TransactionBuilder::new(
        *network_id,
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([InstructionBox::from(ExecuteTrigger::new(
        trigger_id.clone(),
    ))])
    .sign(ALICE_KEYPAIR.private_key());
    chain
        .state()
        .view()
        .world()
        .asset_definition(asset_id.definition())
        .expect("seeded asset remains");
    chain.take_events().unwrap();
    let proposal = chain.proposal(None, vec![exec_tx]);
    let mut pending = chain
        .begin_proposal(proposal, Default::default())
        .expect("native trigger executes");
    let fragments = pending
        .inspect(|execution| execution.state.committed_fragment_count())
        .unwrap();
    let committed = pending
        .publish(Signers::Quorum)
        .expect("native trigger publishes");
    let execute_error = committed
        .block()
        .output_error(0)
        .map(|error| format!("{error:?}"));
    drop(pending);
    (chain.take_events().unwrap(), fragments, execute_error)
}

fn assert_trigger_registered(state: &State, trigger_id: &TriggerId, asset_id: &AssetId) {
    let view = state.view();
    let action = view
        .world()
        .triggers()
        .by_call_triggers()
        .get(trigger_id)
        .expect("trigger should be registered");
    let ExecutableRef::Instructions(instructions) = action.executable() else {
        panic!("trigger should store instruction executable");
    };
    let [instruction] = instructions.as_ref() else {
        panic!("trigger should store exactly one instruction");
    };
    let mint = match instruction.as_any().downcast_ref::<MintBox>() {
        Some(MintBox::Asset(mint)) => mint,
        _ => panic!("trigger instruction should mint a numeric asset"),
    };
    assert_eq!(
        mint.destination(),
        asset_id,
        "registered trigger must mint the seeded asset"
    );
}
fn assert_trigger_events(
    events: &[EventBox],
    trigger_id: &TriggerId,
    asset_id: &AssetId,
    alice_id: &AccountId,
) {
    let mut saw_execute = false;
    let mut saw_asset_added = false;
    for ev in events {
        match ev {
            EventBox::ExecuteTrigger(ev) => {
                if ev.trigger_id() == trigger_id && ev.authority() == alice_id {
                    saw_execute = true;
                }
            }
            EventBox::Data(shared) => {
                if let DataEvent::Domain(DomainEvent::Asset(ScopedAsset {
                    event: AssetEvent::Added(changed),
                    ..
                })) = shared.as_ref()
                    && changed.asset() == asset_id
                {
                    saw_asset_added = true;
                }
            }
            _ => {}
        }
    }
    assert!(
        saw_execute,
        "ExecuteTrigger event should be broadcast for by-call triggers"
    );
    assert!(
        saw_asset_added,
        "Minted asset should emit an AssetEvent::Added data event"
    );
}
#[test]
fn execute_trigger_emits_execute_and_data_events() {
    let (mut chain, chain_id, trigger_id, asset_id) = build_state_and_ids();
    let alice_id = ALICE_ID.clone();
    let register_fragments = register_trigger(&mut chain, &chain_id, &trigger_id, &asset_id);
    let state = Arc::clone(chain.state());
    assert!(
        register_fragments > 0,
        "register transaction should be applied"
    );
    assert_trigger_registered(&state, &trigger_id, &asset_id);
    state
        .view()
        .world()
        .asset_definition(asset_id.definition())
        .expect("asset definition must survive trigger registration");
    let (events, fragment_count, execute_error) =
        execute_trigger(&mut chain, &chain_id, &trigger_id, &asset_id);
    assert!(
        execute_error.is_none(),
        "ExecuteTrigger transaction rejected: {execute_error:?}"
    );
    assert!(fragment_count > 0, "execute transaction should be applied");
    assert_trigger_events(&events, &trigger_id, &asset_id, &alice_id);
}
