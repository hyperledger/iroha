use std::{sync::mpsc, thread, time::Duration};

use executor_custom_data_model::mint_rose_args::MintRoseArgs;
use eyre::{eyre, Result, WrapErr};
use iroha::{
    client::{self},
    crypto::KeyPair,
    data_model::{
        prelude::*,
        query::{builder::SingleQueryError, error::FindError, trigger::FindTriggers},
        transaction::Executable,
    },
};
use iroha_executor_data_model::permission::trigger::CanRegisterTrigger;
use iroha_test_network::*;
use iroha_test_samples::{load_sample_wasm, ALICE_ID};

use crate::integration::triggers::get_asset_value;

const TRIGGER_NAME: &str = "mint_rose";

#[test]
fn call_execute_trigger() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&test_client, asset_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.account(), vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TRIGGER_NAME.parse()?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn execute_trigger_should_produce_event() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.account(), vec![instruction.into()]);
    test_client.submit_blocking(register_trigger)?;

    let trigger_id = TRIGGER_NAME.parse::<TriggerId>()?;
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
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TRIGGER_NAME.parse()?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    let prev_value = get_asset_value(&test_client, asset_id.clone());

    let instructions = vec![
        Mint::asset_numeric(1u32, asset_id.clone()).into(),
        call_trigger.clone().into(),
    ];
    let register_trigger = build_register_trigger_isi(asset_id.account(), instructions);
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn trigger_failure_should_not_cancel_other_triggers_execution() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    // Registering trigger that should fail on execution
    let bad_trigger_id = "bad_trigger".parse::<TriggerId>()?;
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
    let trigger_id = TRIGGER_NAME.parse()?;
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
    let prev_asset_value = get_asset_value(&test_client, asset_id.clone());

    // Executing bad trigger
    test_client.submit_blocking(ExecuteTrigger::new(bad_trigger_id))?;

    // Checking results
    let new_asset_value = get_asset_value(&test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(Numeric::ONE).unwrap()
    );
    Ok(())
}

#[test]
fn trigger_should_not_be_executed_with_zero_repeats_count() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = "self_modifying_trigger".parse::<TriggerId>()?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            1_u32,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&test_client, asset_id.clone());

    // Executing trigger first time
    let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time

    // NOTE: Keep this for debugging purposes
    // let error = test_client
    //     .submit_blocking(execute_trigger)
    //     .expect_err("Error expected");
    // iroha_logger::info!(?error);

    let error = test_client
        .submit_blocking(execute_trigger)
        .expect_err("Error expected");
    let downcasted_error = error
        .chain()
        .last()
        .expect("At least two error causes expected")
        .downcast_ref::<FindError>();
    assert!(
        matches!(
            downcasted_error,
            Some(FindError::Trigger(id)) if *id == trigger_id
        ),
        "Unexpected error received: {error:?}",
    );

    // Checking results
    let new_asset_value = get_asset_value(&test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(Numeric::ONE).unwrap()
    );

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_its_own_repeats_count() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = "self_modifying_trigger".parse::<TriggerId>()?;

    let trigger_instructions: Vec<InstructionBox> = vec![
        Mint::trigger_repetitions(1_u32, trigger_id.clone()).into(),
        Mint::asset_numeric(1u32, asset_id.clone()).into(),
    ];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            1_u32,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&test_client, asset_id.clone());

    // Executing trigger first time
    let execute_trigger = ExecuteTrigger::new(trigger_id);
    test_client.submit_blocking(execute_trigger.clone())?;

    // Executing trigger second time
    test_client.submit_blocking(execute_trigger)?;

    // Checking results
    let new_asset_value = get_asset_value(&test_client, asset_id);
    assert_eq!(
        new_asset_value,
        prev_asset_value.checked_add(numeric!(2)).unwrap()
    );

    Ok(())
}

#[test]
fn only_account_with_permission_can_register_trigger() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let domain_id = ALICE_ID.domain().clone();
    let alice_account_id = ALICE_ID.clone();
    let rabbit_keys = KeyPair::random();
    let rabbit_account_id = AccountId::new(domain_id, rabbit_keys.public_key().clone());
    let rabbit_account = Account::new(rabbit_account_id.clone());

    let mut rabbit_client = test_client.clone();
    rabbit_client.account = rabbit_account_id.clone();
    rabbit_client.key_pair = rabbit_keys;

    // Permission for the trigger registration on behalf of alice
    let permission_on_registration = CanRegisterTrigger {
        authority: ALICE_ID.clone(),
    };

    // Trigger with 'alice' as authority
    let trigger_id = "alice_trigger".parse::<TriggerId>()?;
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
    println!("Rabbit is found.");

    // Trying register the trigger without permissions
    let _ = rabbit_client
        .submit_blocking(Register::trigger(trigger.clone()))
        .expect_err("Trigger should not be registered!");
    println!("Rabbit couldn't register the trigger");

    // Give permissions to the rabbit
    test_client.submit_blocking(Grant::account_permission(
        permission_on_registration,
        rabbit_account_id,
    ))?;
    println!("Rabbit has got the permission");

    // Trying register the trigger with permissions
    rabbit_client
        .submit_blocking(Register::trigger(trigger))
        .expect("Trigger should be registered!");

    let found_trigger = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(trigger_id.clone()))
        .execute_single()?;

    assert_eq!(found_trigger.id, trigger_id);

    Ok(())
}

#[test]
fn unregister_trigger() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let account_id = ALICE_ID.clone();

    // Registering trigger
    let trigger_id = "empty_trigger".parse::<TriggerId>()?;
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
    let found_trigger = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(trigger_id.clone()))
        .execute_single()?;
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
    let unregister_trigger = Unregister::trigger(trigger_id.clone());
    test_client.submit_blocking(unregister_trigger)?;

    // Checking result
    assert!(matches!(
        test_client
            .query(FindTriggers::new())
            .filter_with(|trigger| trigger.id.eq(trigger_id.clone()))
            .execute_single(),
        Err(SingleQueryError::ExpectedOneGotNone)
    ));

    Ok(())
}

#[test]
fn trigger_in_genesis() -> Result<()> {
    let wasm = load_sample_wasm("mint_rose_trigger");
    let account_id = ALICE_ID.clone();
    let trigger_id = "genesis_trigger".parse::<TriggerId>()?;

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

    let (network, _rt) = NetworkBuilder::new()
        .with_genesis_instruction(Register::trigger(trigger))
        .start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&test_client, asset_id.clone());

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
    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

#[test]
fn trigger_should_be_able_to_modify_other_trigger() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id_unregister = "unregister_other_trigger".parse::<TriggerId>()?;
    let trigger_id_to_be_unregistered = "should_be_unregistered_trigger".parse::<TriggerId>()?;

    let trigger_unregister_instructions =
        vec![Unregister::trigger(trigger_id_to_be_unregistered.clone())];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id_unregister.clone(),
        Action::new(
            trigger_unregister_instructions,
            1_u32,
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
            1_u32,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id_to_be_unregistered.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Saving current asset value
    let prev_asset_value = get_asset_value(&test_client, asset_id.clone());

    // Executing triggers
    let execute_trigger_unregister = ExecuteTrigger::new(trigger_id_unregister);
    let execute_trigger_should_be_unregistered = ExecuteTrigger::new(trigger_id_to_be_unregistered);
    test_client.submit_all_blocking([
        execute_trigger_unregister,
        execute_trigger_should_be_unregistered,
    ])?;

    // Checking results
    // First trigger should cancel second one, so value should stay the same
    let new_asset_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_asset_value, prev_asset_value);

    Ok(())
}

#[test]
fn trigger_burn_repetitions() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let trigger_id = "trigger".parse::<TriggerId>()?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id)];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            1_u32,
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
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let account_id = ALICE_ID.clone();
    let first_trigger_id = "mint_rose_1".parse::<TriggerId>()?;
    let second_trigger_id = "mint_rose_2".parse::<TriggerId>()?;

    let build_trigger = |trigger_id: TriggerId| {
        Trigger::new(
            trigger_id.clone(),
            Action::new(
                load_sample_wasm("mint_rose_trigger"),
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
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(second_trigger_id.clone()))
        .execute_single()?;

    assert_eq!(got_second_trigger, second_trigger);

    Ok(())
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
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let prev_value = get_asset_value(&test_client, asset_id.clone());

    let trigger_id = TRIGGER_NAME.parse::<TriggerId>()?;
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            load_sample_wasm("mint_rose_trigger_args"),
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id.clone()),
        ),
    );

    test_client.submit_blocking(Register::trigger(trigger))?;

    let args = &MintRoseArgs { val: 42 };
    let call_trigger = ExecuteTrigger::new(trigger_id).with_args(args);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(numeric!(42)).unwrap());

    Ok(())
}
