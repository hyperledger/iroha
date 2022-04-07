#![allow(clippy::restriction)]

use std::{str::FromStr as _, time::Duration};

use eyre::Result;
use iroha_client::client::{self, Client};
use iroha_core::block::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

/// Macro to abort compilation, if `e` isn't `true`
macro_rules! const_assert {
    ($e:expr) => {
        #[allow(trivial_casts)]
        const _: usize = ($e as bool) as usize - 1;
    };
}

/// Time-based triggers and block commitment process depend heavily on **current time** and **CPU**,
/// so it's impossible to create fully reproducible test scenario.
///
/// But in general it works well and this test demonstrates it
#[test]
#[allow(clippy::cast_precision_loss)]
fn time_trigger_execution_count_error_should_be_less_than_10_percent() -> Result<()> {
    const PERIOD_MS: u64 = 100;
    const ACCEPTABLE_ERROR_PERCENT: u8 = 10;
    const_assert!(PERIOD_MS < DEFAULT_CONSENSUS_ESTIMATION_MS);
    const_assert!(ACCEPTABLE_ERROR_PERCENT <= 100);

    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    let start_time = current_time();

    let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let asset_definition_id = "rose#wonderland".parse().expect("Valid");
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let schedule =
        TimeSchedule::starting_at(start_time).with_period(Duration::from_millis(PERIOD_MS));
    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = RegisterBox::new(Trigger::new(
        "mint_rose".parse()?,
        Action::new(
            Executable::from(vec![instruction.into()]),
            Repeats::Indefinitely,
            account_id.clone(),
            EventFilter::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))),
        ),
    ));
    test_client.submit(register_trigger)?;

    submit_sample_isi_on_every_block_commit(&mut test_client, &account_id, 3)?;
    std::thread::sleep(Duration::from_millis(DEFAULT_CONSENSUS_ESTIMATION_MS));

    let finish_time = current_time();
    let average_count = finish_time.saturating_sub(start_time).as_millis() / u128::from(PERIOD_MS);

    let actual_value = get_asset_value(&mut test_client, asset_id)?;
    let expected_value = prev_value + u32::try_from(average_count)?;
    let acceptable_error = expected_value as f32 * (f32::from(ACCEPTABLE_ERROR_PERCENT) / 100.0);
    let error = (core::cmp::max(actual_value, expected_value)
        - core::cmp::min(actual_value, expected_value)) as f32;
    assert!(
        error < acceptable_error,
        "error = {}, but acceptable error = {}",
        error,
        acceptable_error
    );

    Ok(())
}

#[test]
fn change_asset_metadata_after_1_sec() -> Result<()> {
    const PERIOD_MS: u64 = 1000;

    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    let start_time = current_time();

    let asset_definition_id =
        <AssetDefinition as Identifiable>::Id::from_str("rose#wonderland").expect("Valid");
    let account_id = <Account as Identifiable>::Id::from_str("alice@wonderland").expect("Valid");
    let key = Name::from_str("petal")?;

    let schedule = TimeSchedule::starting_at(start_time + Duration::from_millis(PERIOD_MS));
    let instruction = SetKeyValueBox::new(asset_definition_id.clone(), key.clone(), Value::U32(3));
    let register_trigger = RegisterBox::new(Trigger::new(
        "change_rose_metadata".parse().expect("Valid"),
        Action::new(
            Executable::from(vec![instruction.into()]),
            Repeats::Exactly(1),
            account_id.clone(),
            EventFilter::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))),
        ),
    ));
    test_client.submit(register_trigger)?;
    submit_sample_isi_on_every_block_commit(
        &mut test_client,
        &account_id,
        usize::try_from(PERIOD_MS / DEFAULT_CONSENSUS_ESTIMATION_MS + 1)?,
    )?;

    let value = test_client.request(FindAssetDefinitionKeyValueByIdAndKey {
        id: asset_definition_id.into(),
        key: key.into(),
    })?;
    assert!(matches!(value, Value::U32(3)));

    Ok(())
}

#[test]
fn pre_commit_trigger_should_be_executed() -> Result<()> {
    const CHECKS_COUNT: usize = 5;

    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse().expect("Valid");
    let account_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let mut prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = RegisterBox::new(Trigger::new(
        "mint_rose".parse()?,
        Action::new(
            Executable::from(vec![instruction.into()]),
            Repeats::Indefinitely,
            account_id.clone(),
            EventFilter::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        ),
    ));
    test_client.submit(register_trigger)?;

    let block_filter = EventFilter::Pipeline(
        PipelineEventFilter::new()
            .entity_kind(PipelineEntityKind::Block)
            .status_kind(PipelineStatusKind::Committed),
    );
    for _ in test_client
        .listen_for_events(block_filter)?
        .take(CHECKS_COUNT)
    {
        let new_value = get_asset_value(&mut test_client, asset_id.clone())?;
        assert_eq!(new_value, prev_value + 1);
        prev_value = new_value;

        // ISI just to create a new block
        let sample_isi = SetKeyValueBox::new(
            account_id.clone(),
            "key".parse::<Name>()?,
            String::from("value"),
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}

/// Get asset numeric value
fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}

/// Submit some sample ISIs to create new blocks
fn submit_sample_isi_on_every_block_commit(
    test_client: &mut Client,
    account_id: &AccountId,
    times: usize,
) -> Result<()> {
    let block_filter =
        EventFilter::Pipeline(PipelineEventFilter::new().entity_kind(PipelineEntityKind::Block));
    for _ in test_client
        .listen_for_events(block_filter)?
        .filter(|event| {
            if let Ok(Event::Pipeline(event)) = event {
                if event.status == PipelineStatus::Committed {
                    return true;
                }
            }
            false
        })
        .take(times)
    {
        std::thread::sleep(Duration::from_secs(1));
        // ISI just to create a new block
        let sample_isi = SetKeyValueBox::new(
            account_id.clone(),
            "key".parse::<Name>()?,
            String::from("value"),
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}
