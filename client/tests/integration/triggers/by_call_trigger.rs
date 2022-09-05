#![allow(clippy::restriction)]

use std::{str::FromStr as _, sync::mpsc, thread, time::Duration};

use eyre::{eyre, Result, WrapErr};
use iroha_client::client::{self, Client};
use iroha_core::genesis::GenesisNetwork;
use iroha_data_model::prelude::*;
use test_network::*;

const TRIGGER_NAME: &str = "mint_rose";

#[test]
fn call_execute_trigger() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.clone(), vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTriggerBox::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

#[test]
fn execute_trigger_should_produce_event() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id, vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTriggerBox::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client
            .listen_for_events(ExecuteTriggerEventFilter::new(trigger_id, account_id).into())?;
        if event_it.next().is_some() {
            sender.send(())?;
            return Ok(());
        }
        Err(eyre!("No events emitted"))
    });

    test_client.submit(call_trigger)?;

    receiver
        .recv_timeout(Duration::from_secs(60))
        .wrap_err("Failed to receive event message")
}

#[test]
fn infinite_recursion_should_produce_one_call_per_block() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTriggerBox::new(trigger_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let instructions = vec![
        MintBox::new(1_u32, asset_id.clone()).into(),
        call_trigger.clone().into(),
    ];
    let register_trigger = build_register_trigger_isi(asset_id.clone(), instructions);
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

#[test]
fn trigger_failure_should_not_cancel_other_triggers_execution() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = AccountId::from_str("alice@wonderland")?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    // Registering trigger that should fail on execution
    let bad_trigger_id = <Trigger<FilterBox> as Identifiable>::Id::from_str("bad_trigger")?;
    // Invalid instruction
    let bad_trigger_instructions = vec![MintBox::new(1_u32, account_id.clone()).into()];
    let register_bad_trigger = RegisterBox::new(Trigger::new(
        bad_trigger_id.clone(),
        Action::new(
            Executable::from(bad_trigger_instructions),
            Repeats::Indefinitely,
            account_id.clone(),
            FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                bad_trigger_id.clone(),
                account_id.clone(),
            )),
        ),
    ));
    test_client.submit(register_bad_trigger)?;

    // Registering normal trigger
    let trigger_id = <Trigger<FilterBox> as Identifiable>::Id::from_str(TRIGGER_NAME)?;
    let trigger_instructions = vec![MintBox::new(1_u32, asset_id.clone()).into()];
    let register_trigger = RegisterBox::new(Trigger::new(
        trigger_id,
        Action::new(
            Executable::from(trigger_instructions),
            Repeats::Indefinitely,
            account_id,
            // Time-triggers (which are Pre-commit triggers) will be executed last
            FilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone())?;

    // Executing bad trigger
    test_client.submit_blocking(ExecuteTriggerBox::new(bad_trigger_id))?;

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_asset_value, prev_asset_value + 1);
    Ok(())
}

#[test]
fn trigger_should_not_be_executed_with_zero_repeats_count() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = AccountId::from_str("alice@wonderland")?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = <Trigger<FilterBox> as Identifiable>::Id::from_str("self_modifying_trigger")?;

    let trigger_instructions = vec![MintBox::new(1_u32, asset_id.clone()).into()];
    let register_trigger = RegisterBox::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            Executable::from(trigger_instructions),
            Repeats::from(1_u32),
            account_id.clone(),
            FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                account_id,
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone())?;

    // Executing trigger first time
    let execute_trigger = ExecuteTriggerBox::new(trigger_id);
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time
    assert!(matches!(
        test_client
            .submit_blocking(execute_trigger)
            .expect_err("Error expected")
            .root_cause()
            .downcast_ref::<InstructionExecutionFail>(),
        Some(&InstructionExecutionFail { .. })
    ));

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_asset_value, prev_asset_value + 1);

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_its_own_repeats_count() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = AccountId::from_str("alice@wonderland")?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = <Trigger<FilterBox> as Identifiable>::Id::from_str("self_modifying_trigger")?;

    let trigger_instructions = vec![
        MintBox::new(1_u32, trigger_id.clone()).into(),
        MintBox::new(1_u32, asset_id.clone()).into(),
    ];
    let register_trigger = RegisterBox::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            Executable::from(trigger_instructions),
            Repeats::from(1_u32),
            account_id.clone(),
            FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                account_id,
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone())?;

    // Executing trigger first time
    let execute_trigger = ExecuteTriggerBox::new(trigger_id);
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time
    test_client.submit_blocking(execute_trigger)?;

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_asset_value, prev_asset_value + 2);

    Ok(())
}

#[test]
fn unregister_trigger() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id = AccountId::from_str("alice@wonderland")?;

    // Registering trigger
    let trigger_id = <Trigger<FilterBox> as Identifiable>::Id::from_str("empty_trigger")?;
    let trigger_instructions = Vec::new();
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            Executable::from(trigger_instructions),
            Repeats::Indefinitely,
            account_id.clone(),
            FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                account_id,
            )),
        ),
    );
    let register_trigger = RegisterBox::new(trigger.clone());
    test_client.submit_blocking(register_trigger)?;

    // Finding trigger
    let find_trigger = FindTriggerById {
        id: trigger_id.clone().into(),
    };
    let found_trigger = test_client.request(find_trigger.clone())?;
    assert_eq!(found_trigger, trigger);

    // Unregistering trigger
    let unregister_trigger = UnregisterBox::new(trigger_id);
    test_client.submit_blocking(unregister_trigger)?;

    // Checking result
    assert!(test_client.request(find_trigger).is_err());

    Ok(())
}

/// Register wasm-trigger in genesis and execute it.
///
/// Not very representable from end-user point of view.
/// It's the problem of all ours *"integration"* tests that they are not really
/// integration.
/// Here it's easier to use the approach with `GenesisNetwork::test()` function
/// and extra isi insertion instead of a hardcoded genesis config.
/// This allows to not to update the hardcoded genesis every time
/// instructions/genesis API is changing.
///
/// Despite this simplification this test should really check
/// if we have the ability to pass a base64-encoded WASM trigger in the genesis.
#[test]
// TODO: Same suggestion here as in #2641.
// Let's use feature instead of ignore.
// This feature will be activated by the build-script on nightly builds/
#[ignore = "Only on nightly"]
fn trigger_in_genesis_using_base64() -> Result<()> {
    prepare_test_for_nextest!();

    // Reading wasm smartcontract
    let wasm = std::fs::read(concat!(
        env!("OUT_DIR"),
        "/wasm32-unknown-unknown/release/mint_rose.wasm"
    ))
    .wrap_err("Can't read smartcontract")?;
    println!("wasm size is {} bytes", wasm.len());
    let wasm_base64 = serde_json::json!({
        "raw_data": base64::encode(&wasm),
    })
    .to_string();

    let account_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let trigger_id = <Trigger<FilterBox> as Identifiable>::Id::from_str("genesis_trigger")?;
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            Executable::Wasm(
                serde_json::from_str(&wasm_base64)
                    .wrap_err("Can't deserialize wasm using base64")?,
            ),
            Repeats::Indefinitely,
            account_id.clone(),
            FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                account_id.clone(),
            )),
        ),
    );

    // Registering trigger in genesis
    let mut genesis = GenesisNetwork::test(true).expect("Expected genesis");
    match &mut genesis.transactions[0].as_mut_v1().payload.instructions {
        Executable::Instructions(instructions) => {
            instructions.push(RegisterBox::new(trigger).into());
        }
        Executable::Wasm(_) => panic!("Expected instructions"),
    }

    let (_rt, _peer, mut test_client) = <PeerBuilder>::new()
        .with_genesis(genesis)
        .start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    // Executing trigger
    let call_trigger = ExecuteTriggerBox::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    // Checking result
    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}

fn build_register_trigger_isi(
    asset_id: AssetId,
    trigger_instructions: Vec<Instruction>,
) -> RegisterBox {
    let trigger_id: TriggerId = TRIGGER_NAME.parse().expect("Valid");

    RegisterBox::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            Executable::from(trigger_instructions),
            Repeats::Indefinitely,
            asset_id.account_id.clone(),
            FilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id,
                asset_id.account_id,
            )),
        ),
    ))
}
