//! Orphaned trigger cleanup scenarios.
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{prelude::*, query::trigger::FindTriggers},
};
use iroha_executor_data_model::permission::trigger::CanRegisterTrigger;
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;
const TRIGGER_STATE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TRIGGER_STATE_TIMEOUT: Duration = Duration::from_secs(30);
async fn start_network(context: &'static str) -> eyre::Result<Option<sandbox::SerializedNetwork>> {
    sandbox::start_network_async_or_skip(NetworkBuilder::new(), context).await
}
async fn find_trigger(iroha: &Client, trigger_id: &TriggerId) -> eyre::Result<Option<Trigger>> {
    let client = iroha.clone();
    let trigger_id = trigger_id.clone();
    spawn_blocking(move || {
        Ok(client
            .client()
            .query(FindTriggers::new())
            .execute_all()
            .ok()
            .and_then(|triggers| {
                triggers
                    .into_iter()
                    .find(|trigger| trigger.id() == &trigger_id)
            }))
    })
    .await?
}
async fn wait_for_trigger_state(
    iroha: &Client,
    trigger_id: &TriggerId,
    expected_present: bool,
    context: &str,
) -> eyre::Result<Option<Trigger>> {
    let deadline = Instant::now() + TRIGGER_STATE_TIMEOUT;
    let mut last_observed = "trigger was not queried".to_owned();
    while Instant::now() < deadline {
        let observed = find_trigger(iroha, trigger_id).await?;
        last_observed = if observed.is_some() {
            "present".to_owned()
        } else {
            "absent".to_owned()
        };
        if observed.is_some() == expected_present {
            return Ok(observed);
        }
        tokio::time::sleep(TRIGGER_STATE_POLL_INTERVAL).await;
    }
    Err(eyre::eyre!(
        "timed out waiting for trigger {trigger_id} present={expected_present} after {context}; last_observed={last_observed}"
    ))
}
async fn set_up_trigger(
    network: &sandbox::SerializedNetwork,
) -> eyre::Result<(DomainId, AccountId, TriggerId)> {
    let iroha = network.client();
    let failand: DomainId = DomainId::try_new("failand", "universal")?;
    let create_failand = domain_setup_instruction(&failand, iroha.client().account())?;
    let (the_one_who_fails, account_keypair) = gen_account_in(failand.name());
    let create_the_one_who_fails = Register::account(Account::new(the_one_who_fails.clone()));
    let fail_on_account_events = "fail".parse::<TriggerId>()?;
    let fail_isi = Unregister::domain(DomainId::try_new("dummy", "universal").unwrap());
    let register_fail_on_account_events = Register::trigger(Trigger::new(
        fail_on_account_events.clone(),
        Action::new(
            [fail_isi],
            Repeats::Indefinitely,
            the_one_who_fails.clone(),
            AccountEventFilter::new().for_account(the_one_who_fails.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ));
    let grant_register_trigger_permission = Grant::account_permission(
        CanRegisterTrigger {
            authority: the_one_who_fails.clone(),
        },
        the_one_who_fails.clone(),
    );
    let authority_client = network
        .peers()
        .first()
        .expect("test network should expose at least one peer")
        .client_for(&the_one_who_fails, account_keypair.private_key().clone());
    spawn_blocking({
        let client = iroha.clone();
        let create_the_one_who_fails: InstructionBox = create_the_one_who_fails.into();
        let grant_register_trigger_permission: InstructionBox =
            grant_register_trigger_permission.into();
        move || {
            client.submit_all::<InstructionBox>(
                [
                    create_failand,
                    create_the_one_who_fails,
                    grant_register_trigger_permission,
                ],
                iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )?;
            eyre::Result::<()>::Ok(())
        }
    })
    .await??;
    spawn_blocking({
        let client = authority_client.clone();
        let register_fail_on_account_events: InstructionBox =
            register_fail_on_account_events.into();
        move || {
            client.submit::<InstructionBox>(
                register_fail_on_account_events,
                iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await??;
    Ok((failand, the_one_who_fails, fail_on_account_events))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_must_be_removed_on_action_authority_account_removal() -> eyre::Result<()> {
    let Some(network) = start_network(stringify!(
        trigger_must_be_removed_on_action_authority_account_removal
    ))
    .await?
    else {
        return Ok(());
    };
    let iroha = network.client();
    let (_, the_one_who_fails, fail_on_account_events) = set_up_trigger(&network).await?;
    let trigger = wait_for_trigger_state(
        &iroha,
        &fail_on_account_events,
        true,
        "trigger registration",
    )
    .await?;
    assert_eq!(
        trigger.as_ref().map(Identifiable::id),
        Some(&fail_on_account_events.clone())
    );
    spawn_blocking({
        let client = iroha.clone();
        let the_one_who_fails = the_one_who_fails.clone();
        move || {
            client.submit(
                Unregister::account(the_one_who_fails),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await??;
    assert_eq!(
        wait_for_trigger_state(
            &iroha,
            &fail_on_account_events,
            false,
            "authority account removal",
        )
        .await?,
        None
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_must_survive_action_authority_domain_removal() -> eyre::Result<()> {
    let Some(network) = start_network(stringify!(
        trigger_must_survive_action_authority_domain_removal
    ))
    .await?
    else {
        return Ok(());
    };
    let iroha = network.client();
    let (failand, _, fail_on_account_events) = set_up_trigger(&network).await?;
    let trigger = wait_for_trigger_state(
        &iroha,
        &fail_on_account_events,
        true,
        "trigger registration",
    )
    .await?;
    assert_eq!(
        trigger.as_ref().map(Identifiable::id),
        Some(&fail_on_account_events.clone())
    );
    spawn_blocking({
        let client = iroha.clone();
        let failand = failand.clone();
        move || {
            client.submit(
                Unregister::domain(failand),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        }
    })
    .await??;
    assert_eq!(
        wait_for_trigger_state(
            &iroha,
            &fail_on_account_events,
            true,
            "authority domain removal",
        )
        .await?
        .as_ref()
        .map(Identifiable::id),
        Some(&fail_on_account_events)
    );
    Ok(())
}
