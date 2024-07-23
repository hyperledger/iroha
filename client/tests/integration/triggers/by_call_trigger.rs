use std::{str::FromStr as _, sync::mpsc, thread, time::Duration};

use executor_custom_data_model::mint_rose_args::MintRoseArgs;
use eyre::{eyre, Result, WrapErr};
use iroha::{
    client::{self, Client},
    crypto::KeyPair,
    data_model::{
        prelude::*,
        query::error::{FindError, QueryExecutionFail},
        transaction::{Executable, WasmSmartContract},
    },
};
use iroha_executor_data_model::permission::trigger::CanRegisterUserTrigger;
use iroha_genesis::GenesisBlock;
use iroha_logger::info;
use test_network::{Peer as TestPeer, *};
use test_samples::ALICE_ID;
use tokio::runtime::Runtime;

const TRIGGER_NAME: &str = "mint_rose";

#[test]
fn call_execute_trigger() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_005).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.account(), vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn execute_trigger_should_produce_event() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_010).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.account(), vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTrigger::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client.listen_for_events([ExecuteTriggerEventFilter::new()
            .for_trigger(trigger_id)
            .under_authority(account_id)])?;
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
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_015).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    let instructions = vec![
        Mint::asset_numeric(1u32, asset_id.clone()).into(),
        call_trigger.clone().into(),
    ];
    let register_trigger = build_register_trigger_isi(asset_id.account(), instructions);
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn trigger_failure_should_not_cancel_other_triggers_execution() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_020).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    // Registering trigger that should fail on execution
    let bad_trigger_id = TriggerId::from_str("bad_trigger")?;
    // Invalid instruction
    let fail_isi = Unregister::domain("dummy".parse()?);
    let bad_trigger_instructions = vec![fail_isi];
    let register_bad_trigger = Register::trigger(Trigger::new(
        bad_trigger_id.clone(),
        Action::new(
            bad_trigger_instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(bad_trigger_id.clone())
                .under_authority(account_id.clone()),
        ),
    ));
    test_client.submit(register_bad_trigger)?;

    // Registering normal trigger
    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id,
        Action::new(
            trigger_instructions,
            Repeats::Indefinitely,
            account_id,
            // Time-triggers (which are Pre-commit triggers) will be executed last
            TimeEventFilter::new(ExecutionTime::PreCommit),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing bad trigger
    test_client.submit_blocking(ExecuteTrigger::new(bad_trigger_id))?;

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(Numeric::ONE).unwrap()
    );
    Ok(())
}

#[test]
fn trigger_should_not_be_executed_with_zero_repeats_count() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_025).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = TriggerId::from_str("self_modifying_trigger")?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing trigger first time
    let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time

    // NOTE: Keep this for debugging purposes
    // let error = test_client
    //     .submit_blocking(execute_trigger)
    //     .expect_err("Error expected");
    // iroha_logger::info!(?error);

    assert!(matches!(
        test_client
            .submit_blocking(execute_trigger)
            .expect_err("Error expected")
            .chain()
            .last()
            .expect("At least two error causes expected")
            .downcast_ref::<QueryExecutionFail>(),
        Some(QueryExecutionFail::Find(FindError::Trigger(id))) if *id == trigger_id
    ));

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(Numeric::ONE).unwrap()
    );

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_its_own_repeats_count() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_030).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = TriggerId::from_str("self_modifying_trigger")?;

    let trigger_instructions = vec![
        InstructionBox::from(Mint::trigger_repetitions(1_u32, trigger_id.clone())),
        InstructionBox::from(Mint::asset_numeric(1u32, asset_id.clone())),
    ];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing trigger first time
    let execute_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time
    test_client.submit_blocking(execute_trigger)?;

    // Checking results
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(numeric!(2)).unwrap()
    );

    Ok(())
}

#[test]
fn only_account_with_permission_can_register_trigger() -> Result<()> {
    // Building a configuration
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_035).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let domain_id = ALICE_ID.domain().clone();
    let alice_account_id = ALICE_ID.clone();
    let rabbit_keys = KeyPair::random();
    let rabbit_account_id = AccountId::new(domain_id, rabbit_keys.public_key().clone());
    let rabbit_account = Account::new(rabbit_account_id.clone());

    let mut rabbit_client = test_client.clone();
    rabbit_client.account = rabbit_account_id.clone();
    rabbit_client.key_pair = rabbit_keys;

    // Permission for the trigger registration on behalf of alice
    let permission_on_registration = CanRegisterUserTrigger {
        account: ALICE_ID.clone(),
    };

    // Trigger with 'alice' as authority
    let trigger_id = TriggerId::from_str("alice_trigger")?;
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Indefinitely,
            alice_account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(alice_account_id.clone()),
        ),
    );

    // Register rabbit's account
    test_client.submit_blocking(Register::account(rabbit_account))?;

    test_client
        .query(client::account::all())
        .filter_with(|account| account.id.eq(rabbit_account_id.clone()))
        .execute_single()
        .expect("Account not found");
    info!("Rabbit is found.");

    // Trying register the trigger without permissions
    let _ = rabbit_client
        .submit_blocking(Register::trigger(trigger.clone()))
        .expect_err("Trigger should not be registered!");
    info!("Rabbit couldn't register the trigger");

    // Give permissions to the rabbit
    test_client.submit_blocking(Grant::account_permission(
        permission_on_registration,
        rabbit_account_id,
    ))?;
    info!("Rabbit has got the permission");

    // Trying register the trigger with permissions
    rabbit_client
        .submit_blocking(Register::trigger(trigger))
        .expect("Trigger should be registered!");

    let find_trigger = FindTriggerById {
        id: trigger_id.clone(),
    };
    let found_trigger = test_client.query_single(find_trigger)?;

    assert_eq!(found_trigger.id, trigger_id);

    Ok(())
}

#[test]
fn unregister_trigger() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_040).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id = ALICE_ID.clone();

    // Registering trigger
    let trigger_id = TriggerId::from_str("empty_trigger")?;
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    );
    let register_trigger = Register::trigger(trigger.clone());
    test_client.submit_blocking(register_trigger)?;

    // Finding trigger
    let find_trigger = FindTriggerById {
        id: trigger_id.clone(),
    };
    let found_trigger = test_client.query_single(find_trigger.clone())?;
    let found_action = found_trigger.action;
    let Executable::Instructions(found_instructions) = found_action.executable else {
        panic!("Expected instructions");
    };
    let found_trigger = Trigger::new(
        found_trigger.id,
        Action::new(
            Executable::Instructions(found_instructions),
            found_action.repeats,
            found_action.authority,
            found_action.filter,
        ),
    );
    assert_eq!(found_trigger, trigger);

    // Unregistering trigger
    let unregister_trigger = Unregister::trigger(trigger_id);
    test_client.submit_blocking(unregister_trigger)?;

    // Checking result
    assert!(test_client.query_single(find_trigger).is_err());

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
fn trigger_in_genesis_using_base64() -> Result<()> {
    // Building wasm trigger

    info!("Building trigger");
    let wasm = iroha_wasm_builder::Builder::new("../wasm_samples/mint_rose_trigger")
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;

    info!("WASM size is {} bytes", wasm.len());

    let engine = base64::engine::general_purpose::STANDARD;
    let wasm_base64 = serde_json::json!(base64::engine::Engine::encode(&engine, wasm)).to_string();
    let account_id = ALICE_ID.clone();
    let trigger_id = TriggerId::from_str("genesis_trigger")?;

    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            serde_json::from_str::<WasmSmartContract>(&wasm_base64)
                .wrap_err("Can't deserialize wasm using base64")?,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id.clone()),
        ),
    );

    let mut peer = TestPeer::new().expect("Failed to create peer");
    let topology = vec![peer.id.clone()];

    // Registering trigger in genesis
    let genesis = GenesisBlock::test_with_instructions([Register::trigger(trigger)], topology);

    let rt = Runtime::test();
    let builder = PeerBuilder::new().with_genesis(genesis).with_port(10_045);
    rt.block_on(builder.start_with_peer(&mut peer));
    let mut test_client = Client::test(&peer.api_address);
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing trigger
    test_client
        .submit_blocking(SetKeyValue::trigger(
            trigger_id.clone(),
            "VAL".parse()?,
            1_u32,
        ))
        .unwrap();
    let call_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    // Checking result
    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_other_trigger() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_085).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id_unregister = TriggerId::from_str("unregister_other_trigger")?;
    let trigger_id_to_be_unregistered = TriggerId::from_str("should_be_unregistered_trigger")?;

    let trigger_unregister_instructions =
        vec![Unregister::trigger(trigger_id_to_be_unregistered.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id_unregister.clone(),
        Action::new(
            trigger_unregister_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id_unregister.clone())
                .under_authority(account_id.clone()),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let trigger_should_be_unregistered_instructions =
        vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id_to_be_unregistered.clone(),
        Action::new(
            trigger_should_be_unregistered_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id_to_be_unregistered.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&mut test_client, asset_id.clone());

    // Executing triggers
    let execute_trigger_unregister = ExecuteTrigger::new(trigger_id_unregister);
    let execute_trigger_should_be_unregistered = ExecuteTrigger::new(trigger_id_to_be_unregistered);
    test_client.submit_all_blocking([
        execute_trigger_unregister,
        execute_trigger_should_be_unregistered,
    ])?;

    // Checking results
    // First trigger should cancel second one, so value should stay the same
    let new_asset_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_asset_value, prev_asset_value);

    Ok(())
}

#[test]
fn trigger_burn_repetitions() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_070).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = TriggerId::from_str("trigger")?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id)];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(1_u32),
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(Burn::trigger_repetitions(1_u32, trigger_id.clone()))?;

    // Executing trigger
    let execute_trigger = ExecuteTrigger::new(trigger_id);
    let _err = test_client
        .submit_blocking(execute_trigger)
        .expect_err("Should fail without repetitions");

    Ok(())
}

#[test]
fn unregistering_one_of_two_triggers_with_identical_wasm_should_not_cause_original_wasm_loss(
) -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_105).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id = ALICE_ID.clone();
    let first_trigger_id = TriggerId::from_str("mint_rose_1")?;
    let second_trigger_id = TriggerId::from_str("mint_rose_2")?;

    let wasm = iroha_wasm_builder::Builder::new("../wasm_samples/mint_rose_trigger")
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;
    let wasm = WasmSmartContract::from_compiled(wasm);

    let build_trigger = |trigger_id: TriggerId| {
        Trigger::new(
            trigger_id.clone(),
            Action::new(
                wasm.clone(),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id)
                    .under_authority(account_id.clone()),
            ),
        )
    };

    let first_trigger = build_trigger(first_trigger_id.clone());
    let second_trigger = build_trigger(second_trigger_id.clone());

    test_client.submit_all_blocking([
        Register::trigger(first_trigger),
        Register::trigger(second_trigger.clone()),
    ])?;

    test_client.submit_blocking(Unregister::trigger(first_trigger_id))?;
    let got_second_trigger = test_client
        .query_single(FindTriggerById {
            id: second_trigger_id,
        })
        .expect("Failed to request second trigger");

    assert_eq!(got_second_trigger, second_trigger);

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Numeric {
    let asset = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();

    let AssetValue::Numeric(val) = *asset.value() else {
        panic!("Unexpected asset value");
    };

    val
}

fn build_register_trigger_isi(
    account_id: &AccountId,
    trigger_instructions: Vec<InstructionBox>,
) -> Register<Trigger> {
    let trigger_id: TriggerId = TRIGGER_NAME.parse().expect("Valid");

    Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id)
                .under_authority(account_id.clone()),
        ),
    ))
}

#[test]
fn call_execute_trigger_with_args() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(11_265).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    let trigger_id = TriggerId::from_str(TRIGGER_NAME)?;
    let wasm = iroha_wasm_builder::Builder::new("../wasm_samples/mint_rose_trigger_args")
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;
    let wasm = WasmSmartContract::from_compiled(wasm);
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            wasm,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id.clone()),
        ),
    );

    test_client.submit_blocking(Register::trigger(trigger))?;

    let args: MintRoseArgs = MintRoseArgs { val: 42 };
    let call_trigger = ExecuteTrigger::new(trigger_id).with_args(&args);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(numeric!(42)).unwrap());

    Ok(())
}
