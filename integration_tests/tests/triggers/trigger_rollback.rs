//! Tests that state changes made by failing triggers are reverted.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::{ValidationFail, prelude::*, query::error::FindError, trigger::TriggerId};
use iroha_data_model::isi::error::{InstructionExecutionError, InvalidParameterError};
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use tokio::task::spawn_blocking;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_trigger_revert() -> Result<()> {
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new(),
        stringify!(failed_trigger_revert),
    )
    .await?
    else {
        return Ok(());
    };
    let client = network.client();
    //When
    let trigger_id = "trigger".parse::<TriggerId>()?;
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "xor".parse()?,
    );
    let create_asset = Register::asset_definition({
        let __asset_definition_id = asset_definition_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    });
    let fail_isi = Unregister::domain(DomainId::try_new("dummy", "universal").unwrap());
    let instructions: [InstructionBox; 2] = [create_asset.into(), fail_isi.into()];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ));
    let _ = spawn_blocking({
        let client = client.clone();
        move || {
            client.submit(
                register_trigger,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await?;
    let call_trigger = ExecuteTrigger::new(trigger_id);
    let err = spawn_blocking({
        let client = client.clone();
        move || {
            client.submit(
                call_trigger,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await?
    .expect_err("should immediately result in error");
    // Newer execution path wraps the original FindError in a validation failure; accept either.
    if let Some(FindError::Domain(_)) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<FindError>())
    {
        // ok
    } else if let Some(instr_err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<InstructionExecutionError>())
    {
        match instr_err {
            InstructionExecutionError::Find(FindError::Domain(_)) => {}
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                msg,
            )) => {
                assert!(
                    msg.contains("unregister domain"),
                    "unexpected SmartContract message: {msg}"
                );
            }
            _ => panic!("unexpected instruction error: {instr_err:?}"),
        }
    } else if let Some(ValidationFail::NotPermitted(msg)) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<ValidationFail>())
    {
        assert!(
            !msg.trim().is_empty(),
            "NotPermitted message should not be empty"
        );
    } else {
        panic!("unexpected error: {err:?}");
    }
    //Then
    let query_result = match sandbox::handle_result(
        spawn_blocking({
            let client = client.clone();
            move || {
                client
                    .client()
                    .query(FindAssetDefinitions::new())
                    .execute_all()
            }
        })
        .await?
        .map_err(Into::into),
        stringify!(failed_trigger_revert),
    )? {
        Some(query_result) => query_result,
        None => return Ok(()),
    };
    assert!(
        query_result
            .iter()
            .all(|asset_definition| asset_definition.id() != &asset_definition_id)
    );
    Ok(())
}
