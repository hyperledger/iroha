#![allow(clippy::restriction)]

use std::{fs, str::FromStr as _, time::Duration};

use eyre::{Context, Result};
use iroha_client::client::{self, Client};
use iroha_core::block::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_data_model::{prelude::*, transaction::WasmSmartContract};
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
            FilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))),
        ),
    ));
    test_client.submit(register_trigger)?;

    submit_sample_isi_on_every_block_commit(
        &mut test_client,
        &account_id,
        Duration::from_secs(1),
        3,
    )?;
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
            Repeats::from(1_u32),
            account_id.clone(),
            FilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))),
        ),
    ));
    test_client.submit(register_trigger)?;
    submit_sample_isi_on_every_block_commit(
        &mut test_client,
        &account_id,
        Duration::from_secs(1),
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
            FilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
        ),
    ));
    test_client.submit(register_trigger)?;

    let block_filter = FilterBox::Pipeline(
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

#[test]
#[ignore = "flaky and unreliable. Re-enable once performance improvements are made"]
fn mint_nft_for_every_user_every_1_sec() -> Result<()> {
    const TRIGGER_PERIOD_MS: u64 = 1000;
    const EXPECTED_COUNT: u64 = 4;

    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = "alice@wonderland"
        .parse::<<Account as Identifiable>::Id>()
        .expect("Valid");

    let accounts: Vec<AccountId> = vec![
        alice_id.clone(),
        "mad_hatter@wonderland".parse().expect("Valid"),
        "cheshire_cat@wonderland".parse().expect("Valid"),
        "caterpillar@wonderland".parse().expect("Valid"),
        "white_rabbit@wonderland".parse().expect("Valid"),
    ];

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .map(|account_id| RegisterBox::new(Account::new(account_id, [])).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    // Reading wasm smartcontract
    let wasm = fs::read(concat!(
        env!("OUT_DIR"),
        "/wasm32-unknown-unknown/release/create_nft_for_every_user_smartcontract.wasm"
    ))
    .wrap_err("Can't read smartcontract")?;
    println!("wasm size is {} bytes", wasm.len());

    // Registering trigger
    let start_time = current_time();
    let schedule =
        TimeSchedule::starting_at(start_time).with_period(Duration::from_millis(TRIGGER_PERIOD_MS));
    let register_trigger = RegisterBox::new(Trigger::new(
        "mint_nft_for_all".parse()?,
        Action::new(
            Executable::Wasm(WasmSmartContract { raw_data: wasm }),
            Repeats::Indefinitely,
            alice_id.clone(),
            FilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))),
        ),
    ));
    test_client.submit(register_trigger)?;

    // Time trigger will be executed on block commits, so we have to produce some transactions
    submit_sample_isi_on_every_block_commit(
        &mut test_client,
        &alice_id,
        Duration::from_millis(TRIGGER_PERIOD_MS),
        usize::try_from(EXPECTED_COUNT)?,
    )?;

    // Checking results
    for account_id in accounts {
        let start_pattern = "nft_number_";
        let end_pattern = format!("_for_{}#{}", account_id.name, account_id.domain_id);
        let assets = test_client.request(client::asset::by_account_id(account_id.clone()))?;
        let count: u64 = assets
            .into_iter()
            .filter(|asset| {
                let s = asset.id().definition_id.to_string();
                s.starts_with(&start_pattern) && s.ends_with(&end_pattern)
            })
            .count()
            .try_into()
            .expect("`usize` should always fit in `u64`");

        assert!(
            count >= EXPECTED_COUNT,
            "{account_id} has {count} NFT, but at least {EXPECTED_COUNT} expected",
        );
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
    timeout: Duration,
    times: usize,
) -> Result<()> {
    let block_filter =
        FilterBox::Pipeline(PipelineEventFilter::new().entity_kind(PipelineEntityKind::Block));
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
        std::thread::sleep(timeout);
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
