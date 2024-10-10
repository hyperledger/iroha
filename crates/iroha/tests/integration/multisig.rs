use std::collections::BTreeMap;

use executor_custom_data_model::multisig::{MultisigArgs, MultisigRegisterArgs};
use eyre::Result;
use iroha::{
    client,
    crypto::KeyPair,
    data_model::{
        asset::{AssetDefinition, AssetDefinitionId},
        parameter::SmartContractParameter,
        prelude::*,
        query::{builder::SingleQueryError, trigger::FindTriggers},
        transaction::TransactionBuilder,
    },
};
use iroha_executor_data_model::permission::asset_definition::CanRegisterAssetDefinition;
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, load_sample_wasm, ALICE_ID};
use nonzero_ext::nonzero;

#[test]
fn mutlisig() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new()
        .with_genesis_instruction(SetParameter::new(Parameter::SmartContract(
            SmartContractParameter::Fuel(nonzero!(100_000_000_u64)),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Executor(
            SmartContractParameter::Fuel(nonzero!(100_000_000_u64)),
        )))
        .start_blocking()?;
    let test_client = network.client();

    let account_id = ALICE_ID.clone();
    let multisig_register_trigger_id = "multisig_register".parse::<TriggerId>()?;

    let trigger = Trigger::new(
        multisig_register_trigger_id.clone(),
        Action::new(
            load_sample_wasm("multisig_register"),
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new().for_trigger(multisig_register_trigger_id.clone()),
        ),
    );

    // Register trigger which would allow multisig account creation in wonderland domain
    // Access to call this trigger shouldn't be restricted
    test_client.submit_blocking(Register::trigger(trigger))?;

    // Create multisig account id and destroy it's private key
    let multisig_account_id = gen_account_in("wonderland").0;

    let multisig_trigger_id: TriggerId = format!(
        "{}_{}_multisig_trigger",
        multisig_account_id.signatory(),
        multisig_account_id.domain()
    )
    .parse()?;

    let signatories = core::iter::repeat_with(|| gen_account_in("wonderland"))
        .take(5)
        .collect::<BTreeMap<AccountId, KeyPair>>();

    let args = &MultisigRegisterArgs {
        account: Account::new(multisig_account_id.clone()),
        signatories: signatories.keys().cloned().collect(),
    };

    test_client.submit_all_blocking(
        signatories
            .keys()
            .cloned()
            .map(Account::new)
            .map(Register::account),
    )?;

    let call_trigger = ExecuteTrigger::new(multisig_register_trigger_id).with_args(args);
    test_client.submit_blocking(call_trigger)?;

    // Check that multisig account exist
    test_client
        .submit_blocking(Grant::account_permission(
            CanRegisterAssetDefinition {
                domain: "wonderland".parse().unwrap(),
            },
            multisig_account_id.clone(),
        ))
        .expect("multisig account should be created after the call to register multisig trigger");

    // Check that multisig trigger exist
    let trigger = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(multisig_trigger_id.clone()))
        .execute_single()
        .expect("multisig trigger should be created after the call to register multisig trigger");

    assert_eq!(trigger.id(), &multisig_trigger_id);

    let asset_definition_id = "asset_definition_controlled_by_multisig#wonderland"
        .parse::<AssetDefinitionId>()
        .unwrap();
    let isi =
        vec![
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()))
                .into(),
        ];
    let isi_hash = HashOf::new(&isi);

    let mut signatories_iter = signatories.into_iter();

    if let Some((signatory, key_pair)) = signatories_iter.next() {
        let args = &MultisigArgs::Instructions(isi);
        let call_trigger = ExecuteTrigger::new(multisig_trigger_id.clone()).with_args(args);
        test_client.submit_transaction_blocking(
            &TransactionBuilder::new(test_client.chain.clone(), signatory)
                .with_instructions([call_trigger])
                .sign(key_pair.private_key()),
        )?;
    }

    // Check that asset definition isn't created yet
    let err = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id.clone()))
        .execute_single()
        .expect_err("asset definition shouldn't be created before enough votes are collected");
    assert!(matches!(err, SingleQueryError::ExpectedOneGotNone));

    for (signatory, key_pair) in signatories_iter {
        let args = &MultisigArgs::Vote(isi_hash);
        let call_trigger = ExecuteTrigger::new(multisig_trigger_id.clone()).with_args(args);
        test_client.submit_transaction_blocking(
            &TransactionBuilder::new(test_client.chain.clone(), signatory)
                .with_instructions([call_trigger])
                .sign(key_pair.private_key()),
        )?;
    }

    // Check that new asset definition was created and multisig account is owner
    let asset_definition = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id.clone()))
        .execute_single()
        .expect("asset definition should be created after enough votes are collected");

    assert_eq!(asset_definition.owned_by(), &multisig_account_id);

    Ok(())
}
