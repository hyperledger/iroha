use std::{collections::BTreeMap, str::FromStr};

use executor_custom_data_model::multisig::{MultisigArgs, MultisigRegisterArgs};
use eyre::Result;
use iroha::{
    client,
    crypto::KeyPair,
    data_model::{
        prelude::*,
        transaction::{TransactionBuilder, WasmSmartContract},
    },
};
use iroha_data_model::{parameter::SmartContractParameter, query::builder::SingleQueryError};
use nonzero_ext::nonzero;
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID};

#[test]
fn mutlisig() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_400).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    test_client.submit_all_blocking([
        SetParameter::new(Parameter::SmartContract(SmartContractParameter::Fuel(
            nonzero!(100_000_000_u64),
        ))),
        SetParameter::new(Parameter::Executor(SmartContractParameter::Fuel(nonzero!(
            100_000_000_u64
        )))),
    ])?;

    let account_id = ALICE_ID.clone();
    let multisig_register_trigger_id = TriggerId::from_str("multisig_register")?;

    let wasm = iroha_wasm_builder::Builder::new("../wasm_samples/multisig_register")
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;
    let wasm = WasmSmartContract::from_compiled(wasm);

    let trigger = Trigger::new(
        multisig_register_trigger_id.clone(),
        Action::new(
            wasm,
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

    let args = MultisigRegisterArgs {
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

    let call_trigger = ExecuteTrigger::new(multisig_register_trigger_id).with_args(&args);
    test_client.submit_blocking(call_trigger)?;

    // Check that multisig account exist
    let account = test_client
        .query(client::account::all())
        .filter_with(|account| account.id.eq(multisig_account_id.clone()))
        .execute_single()
        .expect("multisig account should be created after the call to register multisig trigger");

    assert_eq!(account.id(), &multisig_account_id);

    // Check that multisig trigger exist
    let trigger = test_client
        .query_single(client::trigger::by_id(multisig_trigger_id.clone()))
        .expect("multisig trigger should be created after the call to register multisig trigger");

    assert_eq!(trigger.id(), &multisig_trigger_id);

    let domain_id: DomainId = "domain_controlled_by_multisig".parse().unwrap();
    let isi = vec![Register::domain(Domain::new(domain_id.clone())).into()];
    let isi_hash = HashOf::new(&isi);

    let mut signatories_iter = signatories.into_iter();

    if let Some((signatory, key_pair)) = signatories_iter.next() {
        let args = MultisigArgs::Instructions(isi);
        let call_trigger = ExecuteTrigger::new(multisig_trigger_id.clone()).with_args(&args);
        test_client.submit_transaction_blocking(
            &TransactionBuilder::new(test_client.chain.clone(), signatory)
                .with_instructions([call_trigger])
                .sign(key_pair.private_key()),
        )?;
    }

    // Check that domain isn't created yet
    let err = test_client
        .query(client::domain::all())
        .filter_with(|domain| domain.id.eq(domain_id.clone()))
        .execute_single()
        .expect_err("domain shouldn't be created before enough votes are collected");
    assert!(matches!(err, SingleQueryError::ExpectedOneGotNone));

    for (signatory, key_pair) in signatories_iter {
        let args = MultisigArgs::Vote(isi_hash);
        let call_trigger = ExecuteTrigger::new(multisig_trigger_id.clone()).with_args(&args);
        test_client.submit_transaction_blocking(
            &TransactionBuilder::new(test_client.chain.clone(), signatory)
                .with_instructions([call_trigger])
                .sign(key_pair.private_key()),
        )?;
    }

    // Check that new domain was created and multisig account is owner
    let domain = test_client
        .query(client::domain::all())
        .filter_with(|domain| domain.id.eq(domain_id.clone()))
        .execute_single()
        .expect("domain should be created after enough votes are collected");

    assert_eq!(domain.owned_by(), &multisig_account_id);

    Ok(())
}
