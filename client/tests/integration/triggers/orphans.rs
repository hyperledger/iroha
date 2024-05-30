use iroha::{
    client::{trigger, Client},
    data_model::prelude::*,
};
use test_network::{wait_for_genesis_committed, Peer, PeerBuilder};
use test_samples::gen_account_in;
use tokio::runtime::Runtime;

fn find_trigger(iroha: &Client, trigger_id: TriggerId) -> Option<TriggerId> {
    iroha
        .build_query(trigger::by_id(trigger_id))
        .execute()
        .ok()
        .map(|trigger| trigger.id)
}

fn set_up_trigger(
    port: u16,
) -> eyre::Result<(Runtime, Peer, Client, DomainId, AccountId, TriggerId)> {
    let (rt, peer, iroha) = <PeerBuilder>::new().with_port(port).start_with_runtime();
    wait_for_genesis_committed(&[iroha.clone()], 0);

    let failand: DomainId = "failand".parse()?;
    let create_failand: InstructionBox = Register::domain(Domain::new(failand.clone())).into();

    let (the_one_who_fails, _account_keypair) = gen_account_in(failand.name());
    let create_the_one_who_fails: InstructionBox =
        Register::account(Account::new(the_one_who_fails.clone())).into();

    let fail_on_account_events = "fail".parse::<TriggerId>()?;
    let register_fail_on_account_events: InstructionBox = Register::trigger(Trigger::new(
        fail_on_account_events.clone(),
        Action::new(
            [Fail::new(":(".to_owned())],
            Repeats::Indefinitely,
            the_one_who_fails.clone(),
            AccountEventFilter::new(),
        ),
    ))
    .into();
    iroha.submit_all_blocking([
        create_failand,
        create_the_one_who_fails,
        register_fail_on_account_events,
    ])?;
    Ok((
        rt,
        peer,
        iroha,
        failand,
        the_one_who_fails,
        fail_on_account_events,
    ))
}

#[test]
fn trigger_must_be_removed_on_action_authority_account_removal() -> eyre::Result<()> {
    let (_rt, _peer, iroha, _, the_one_who_fails, fail_on_account_events) = set_up_trigger(10_655)?;
    assert_eq!(
        find_trigger(&iroha, fail_on_account_events.clone()),
        Some(fail_on_account_events.clone())
    );
    iroha.submit_blocking(Unregister::account(the_one_who_fails.clone()))?;
    assert_eq!(find_trigger(&iroha, fail_on_account_events.clone()), None);
    Ok(())
}

#[test]
fn trigger_must_be_removed_on_action_authority_domain_removal() -> eyre::Result<()> {
    let (_rt, _peer, iroha, failand, _, fail_on_account_events) = set_up_trigger(10_660)?;
    assert_eq!(
        find_trigger(&iroha, fail_on_account_events.clone()),
        Some(fail_on_account_events.clone())
    );
    iroha.submit_blocking(Unregister::domain(failand.clone()))?;
    assert_eq!(find_trigger(&iroha, fail_on_account_events.clone()), None);
    Ok(())
}
