//! Tests for event data produced by instruction and IVM execution.
use eyre::{Result, WrapErr, eyre};
use futures_util::StreamExt;
use integration_tests::{sandbox, sync::get_status_with_retry_async};
use iroha::{
    blocking::Client,
    data_model::{
        asset::{AssetDefinitionId, AssetId},
        events::{
            EventBox,
            data::prelude::{
                AccountEventFilter, AccountEventSet, DomainEventSet, RoleEventFilter, RoleEventSet,
            },
        },
        prelude::*,
    },
};
use iroha_executor_data_model::permission::{
    account::CanModifyAccountMetadata, domain::CanModifyDomainMetadata,
};
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use std::collections::BTreeSet;
use tokio::{task::spawn_blocking, time::Instant};
const SNS_LEASE_PAYMENT_ASSET_DEFINITION: &str = "61CtjvNd9T3THAR65GsMVHr82Bjc";
fn produce_instructions(
    prefix: &str,
    owner: &AccountId,
) -> Result<(Vec<InstructionBox>, BTreeSet<DomainId>)> {
    let domains = (0..4)
        .map(|domain_index: usize| {
            DomainId::try_new(format!("{prefix}{domain_index}"), "universal")
                .expect("generated domain ids should be valid")
        })
        .collect::<Vec<_>>();
    let expected = domains.iter().cloned().collect::<BTreeSet<_>>();
    let instructions = domains
        .iter()
        .map(|domain| domain_setup_instruction(domain, owner))
        .collect::<Result<Vec<_>>>()?;
    Ok((instructions, expected))
}
fn is_tx_confirmation_timeout(err: &eyre::Report) -> bool {
    const NEEDLES: [&str; 3] = [
        "haven't got tx confirmation within",
        "transaction queued for too long",
        "Connection dropped without `Committed/Applied` or `Rejected` event",
    ];
    err.chain().any(|cause| {
        let text = cause.to_string();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}
fn genesis_account_id() -> AccountId {
    AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone())
}
fn genesis_client(network: &Network) -> Client {
    network
        .peers()
        .first()
        .expect("test network has at least one peer")
        .client_for(
            &genesis_account_id(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key().clone(),
        )
}
fn genesis_alias_payment_bootstrap() -> Result<Vec<InstructionBox>> {
    let genesis_id = genesis_account_id();
    let payment_asset_definition =
        AssetDefinitionId::parse_address_literal(SNS_LEASE_PAYMENT_ASSET_DEFINITION)
            .wrap_err("parse SNS lease payment asset definition")?;
    Ok(vec![
        Mint::asset_quantity(
            500_000_u32,
            AssetId::new(payment_asset_definition, genesis_id.clone()),
        )
        .into(),
    ])
}
async fn transaction_execution_should_produce_events(
    context: &'static str,
    network: &Network,
    client: &Client,
    executable: impl Into<Executable> + Send,
    mut expected_domains: BTreeSet<DomainId>,
) -> Result<()> {
    let executable = executable.into();
    // Wait for Torii to come up before subscribing to events.
    let status = get_status_with_retry_async(client)
        .await
        .map_err(|err| err.wrap_err(format!("{context}: wait for status")))?;
    let baseline_non_empty = status.blocks_non_empty;
    let mut events_stream = tokio::time::timeout(
        network.sync_timeout(),
        client
            .account_client()
            .events()
            .subscribe([DataEventFilter::Domain(
                DomainEventFilter::new().for_events(DomainEventSet::Created),
            )]),
    )
    .await
    .wrap_err_with(|| format!("{context}: timed out opening domain event stream"))??;
    let result = async {
        {
            let client = client.clone();
            let tx ={
    let account = client.account_client();
    account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(executable, iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None), <_>::default()))
        .and_then(|payload| account.sign_transaction(payload))
}.expect("build integration-test transaction");
            let submit_result = spawn_blocking(move || client.submit_transaction(&tx)).await?;
            if let Err(err) = submit_result {
                if is_tx_confirmation_timeout(&err) {
                    eprintln!(
                        "warning: {context} confirmation timed out; continuing to wait for domain events"
                    );
                } else {
                    return Err(err);
                }
            }
        }
        network
            .ensure_blocks_with(|h| h.non_empty > baseline_non_empty)
            .await?;
        let mut unexpected_domains = Vec::new();
        let deadline = Instant::now() + network.sync_timeout();
        while !expected_domains.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(eyre!(
                    "{context}: timed out waiting for domain events; missing: {:?}; unexpected: {:?}",
                    expected_domains,
                    unexpected_domains
                ));
            }
            let event_opt = tokio::time::timeout(remaining, events_stream.next())
                .await
                .wrap_err_with(|| {
                    format!(
                        "{context}: timed out waiting for next event; missing: {expected_domains:?}; unexpected: {unexpected_domains:?}"
                    )
                })?;
            let event = match event_opt {
                Some(event) => event?,
                None => {
                    return Err(eyre!(
                        "{context}: event stream ended; missing: {:?}; unexpected: {:?}",
                        expected_domains,
                        unexpected_domains
                    ));
                }
            };
            if let EventBox::Data(ev) = event
                && let DataEvent::Domain(DomainEvent::Created(domain)) = ev.as_ref()
            {
                let domain_id = domain.id().clone();
                if !expected_domains.remove(&domain_id) {
                    unexpected_domains.push(domain_id.to_string());
                }
            }
        }
        Ok(())
    }
    .await;
    events_stream.close().await?;
    result
}
fn unwrap_data_event(event: EventBox) -> DataEvent {
    match event {
        EventBox::Data(shared) => shared.as_ref().clone(),
        other => panic!("expected Data event, got {other:?}"),
    }
}
#[allow(clippy::too_many_lines)]
async fn produce_multiple_events_scenario(network: &Network) -> Result<()> {
    let status = get_status_with_retry_async(&network.client())
        .await
        .map_err(|err| err.wrap_err("produce_multiple_events: wait for status"))?;
    let baseline_non_empty = status.blocks_non_empty;
    // Register role
    let role_id = "TEST_ROLE_EVENTS".parse::<RoleId>()?;
    let wonderland_domain: DomainId = DomainId::try_new("wonderland", "universal")?;
    let permission_1 = CanModifyAccountMetadata {
        account: ALICE_ID.clone(),
    };
    let permission_2 = CanModifyDomainMetadata {
        domain: wonderland_domain,
    };
    let role = Role::new(role_id.clone(), ALICE_ID.clone())
        .add_permission(permission_1.clone())
        .add_permission(permission_2.clone());
    let register_role = Register::role(role.clone());
    // Grant the role to Bob
    let bob_id = BOB_ID.clone();
    let grant_role = Grant::account_role(role_id.clone(), BOB_ID.clone());
    // Unregister the role
    let unregister_role = Unregister::role(role_id.clone());
    let account_event_set = AccountEventSet::RoleGranted | AccountEventSet::RoleRevoked;
    let mut events_stream = tokio::time::timeout(
        network.sync_timeout(),
        network.client().account_client().events().subscribe([
            DataEventFilter::Role(
                RoleEventFilter::new()
                    .for_role(role_id.clone())
                    .for_events(RoleEventSet::Created | RoleEventSet::Deleted),
            ),
            DataEventFilter::Account(
                AccountEventFilter::new()
                    .for_account(ALICE_ID.clone())
                    .for_events(account_event_set),
            ),
            DataEventFilter::Account(
                AccountEventFilter::new()
                    .for_account(bob_id.clone())
                    .for_events(account_event_set),
            ),
        ]),
    )
    .await
    .wrap_err("produce_multiple_events: timed out opening event stream")??;
    {
        let client = network.client();
        spawn_blocking(move || {
            client.submit_all::<InstructionBox>(
                [
                    register_role.into(),
                    grant_role.into(),
                    unregister_role.into(),
                ],
                iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        })
        .await??;
    }
    network
        .ensure_blocks_with(|h| h.non_empty > baseline_non_empty)
        .await?;
    let mut pending_grants: BTreeSet<AccountId> =
        [ALICE_ID.clone(), bob_id.clone()].into_iter().collect();
    let mut pending_revokes = pending_grants.clone();
    let mut saw_role_created = false;
    let mut saw_role_deleted = false;
    let mut unexpected_events = Vec::new();
    let deadline = Instant::now() + network.sync_timeout();
    let result = async {
        while !(saw_role_created
            && saw_role_deleted
            && pending_grants.is_empty()
            && pending_revokes.is_empty())
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                eyre::bail!(
                    "timed out waiting for role/account events; pending grants: {:?}; pending revokes: {:?}; role_created: {}; role_deleted: {}; unexpected: {:?}",
                    pending_grants,
                    pending_revokes,
                    saw_role_created,
                    saw_role_deleted,
                    unexpected_events
                );
            }
            let event_opt = tokio::time::timeout(remaining, events_stream.next())
                .await
                .map_err(|_| {
                    eyre::eyre!(
                        "timed out waiting for next event; pending grants: {:?}; pending revokes: {:?}; role_created: {}; role_deleted: {}; unexpected: {:?}",
                        pending_grants,
                        pending_revokes,
                        saw_role_created,
                        saw_role_deleted,
                        unexpected_events
                    )
                })?;
            let event = match event_opt {
                Some(event) => event?,
                None => {
                    eyre::bail!(
                        "event stream ended before receiving all role/account events; pending grants: {:?}; pending revokes: {:?}; role_created: {}; role_deleted: {}; unexpected: {:?}",
                        pending_grants,
                        pending_revokes,
                        saw_role_created,
                        saw_role_deleted,
                        unexpected_events
                    );
                }
            };
            match unwrap_data_event(event) {
                DataEvent::Role(RoleEvent::Created(created_role)) => {
                    if created_role.id() != role.id() {
                        unexpected_events.push(format!(
                            "role created for unexpected id {:?}",
                            created_role.id()
                        ));
                        continue;
                    }
                    if saw_role_created {
                        unexpected_events.push("duplicate role created event".to_string());
                        continue;
                    }
                    assert!(
                        created_role.permissions().eq([
                            permission_1.clone().into(),
                            permission_2.clone().into()
                        ]
                        .iter())
                    );
                    saw_role_created = true;
                }
                DataEvent::Role(RoleEvent::Deleted(deleted_role)) => {
                    if deleted_role != role_id {
                        unexpected_events
                            .push(format!("role deleted for unexpected id {deleted_role:?}"));
                        continue;
                    }
                    if saw_role_deleted {
                        unexpected_events.push("duplicate role deleted event".to_string());
                        continue;
                    }
                    saw_role_deleted = true;
                }
                DataEvent::Account(AccountEvent::RoleGranted(event)) => {
                    if event.role != role_id {
                        unexpected_events.push(format!(
                            "role granted for unexpected role {:?} to {:?}",
                            event.role, event.account
                        ));
                        continue;
                    }
                    if !pending_grants.remove(&event.account) {
                        unexpected_events.push(format!(
                            "role grant already observed for {:?}",
                            event.account
                        ));
                    }
                }
                DataEvent::Account(AccountEvent::RoleRevoked(event)) => {
                    if event.role != role_id {
                        unexpected_events.push(format!(
                            "role revoked for unexpected role {:?} from {:?}",
                            event.role, event.account
                        ));
                        continue;
                    }
                    if !pending_revokes.remove(&event.account) {
                        unexpected_events.push(format!(
                            "role revoke already observed for {:?}",
                            event.account
                        ));
                    }
                }
                other => unexpected_events.push(format!("unexpected event: {other:?}")),
            }
        }
        Ok(())
    }
    .await;
    events_stream.close().await?;
    result
}
#[tokio::test]
#[allow(clippy::large_futures, clippy::too_many_lines)]
async fn data_event_scenarios() -> Result<()> {
    let genesis_id = genesis_account_id();
    let (instruction_instructions, instruction_expected) =
        produce_instructions("instr", &genesis_id)?;
    let (ivm_instructions, ivm_expected) = produce_instructions("ivm", &genesis_id)?;
    let payment_bootstrap = genesis_alias_payment_bootstrap()?;
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new()
            .with_peers(4)
            .with_genesis_post_topology_isi(payment_bootstrap),
        "data_events",
    )
    .await?
    else {
        return Ok(());
    };
    let submit_client = genesis_client(&network);
    if sandbox::handle_result(
        transaction_execution_should_produce_events(
            stringify!(instruction_execution_should_produce_events),
            &network,
            &submit_client,
            instruction_instructions,
            instruction_expected,
        )
        .await,
        stringify!(instruction_execution_should_produce_events),
    )?
    .is_none()
    {
        return Ok(());
    }
    if sandbox::handle_result(
        transaction_execution_should_produce_events(
            stringify!(ivm_execution_should_produce_events),
            &network,
            &submit_client,
            ivm_instructions,
            ivm_expected,
        )
        .await,
        stringify!(ivm_execution_should_produce_events),
    )?
    .is_none()
    {
        return Ok(());
    }
    if sandbox::handle_result(
        produce_multiple_events_scenario(&network).await,
        stringify!(produce_multiple_events),
    )?
    .is_none()
    {
        return Ok(());
    }
    Ok(())
}
