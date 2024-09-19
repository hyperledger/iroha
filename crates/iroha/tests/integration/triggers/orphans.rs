use iroha::{
    client::Client,
    data_model::{prelude::*, query::trigger::FindTriggers},
};
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;

fn find_trigger(iroha: &Client, trigger_id: &TriggerId) -> Option<TriggerId> {
    iroha
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(trigger_id))
        .execute_single()
        .ok()
        .map(|trigger| trigger.id)
}

fn set_up_trigger(iroha: &Client) -> eyre::Result<(DomainId, AccountId, TriggerId)> {
    let failand: DomainId = "failand".parse()?;
    let create_failand = Register::domain(Domain::new(failand.clone()));

    let (the_one_who_fails, _account_keypair) = gen_account_in(failand.name());
    let create_the_one_who_fails = Register::account(Account::new(the_one_who_fails.clone()));

    let fail_on_account_events = "fail".parse::<TriggerId>()?;
    let fail_isi = Unregister::domain("dummy".parse().unwrap());
    let register_fail_on_account_events = Register::trigger(Trigger::new(
        fail_on_account_events.clone(),
        Action::new(
            [fail_isi],
            Repeats::Indefinitely,
            the_one_who_fails.clone(),
            AccountEventFilter::new(),
        ),
    ));
    iroha.submit_all_blocking::<InstructionBox>([
        create_failand.into(),
        create_the_one_who_fails.into(),
        register_fail_on_account_events.into(),
    ])?;
    Ok((failand, the_one_who_fails, fail_on_account_events))
}

#[test]
fn trigger_must_be_removed_on_action_authority_account_removal() -> eyre::Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let iroha = network.client();
    let (_, the_one_who_fails, fail_on_account_events) = set_up_trigger(&iroha)?;
    assert_eq!(
        find_trigger(&iroha, &fail_on_account_events),
        Some(fail_on_account_events.clone())
    );
    iroha.submit_blocking(Unregister::account(the_one_who_fails.clone()))?;
    assert_eq!(find_trigger(&iroha, &fail_on_account_events), None);
    Ok(())
}

#[test]
fn trigger_must_be_removed_on_action_authority_domain_removal() -> eyre::Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let iroha = network.client();
    let (failand, _, fail_on_account_events) = set_up_trigger(&iroha)?;
    assert_eq!(
        find_trigger(&iroha, &fail_on_account_events),
        Some(fail_on_account_events.clone())
    );
    iroha.submit_blocking(Unregister::domain(failand.clone()))?;
    assert_eq!(find_trigger(&iroha, &fail_on_account_events), None);
    Ok(())
}
