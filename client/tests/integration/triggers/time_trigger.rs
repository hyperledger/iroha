use std::time::Duration;

use eyre::Result;
use iroha::{
    client::{self, Client},
    data_model::{
        asset::AssetId,
        events::pipeline::{BlockEventFilter, BlockStatus},
        parameter::SumeragiParameters,
        prelude::*,
        transaction::WasmSmartContract,
        Level,
    },
};
use iroha_logger::info;
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID};

/// Default estimation of consensus duration.
pub fn default_consensus_estimation() -> Duration {
    let default_parameters = SumeragiParameters::default();

    default_parameters
        .block_time()
        .checked_add(
            default_parameters
                .commit_time()
                .checked_div(2)
                .map_or_else(|| unreachable!(), |x| x),
        )
        .map_or_else(|| unreachable!(), |x| x)
}

fn curr_time() -> core::time::Duration {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the current system time")
}

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
fn time_trigger_execution_count_error_should_be_less_than_15_percent() -> Result<()> {
    const PERIOD: Duration = Duration::from_millis(100);
    const ACCEPTABLE_ERROR_PERCENT: u8 = 15;
    assert!(PERIOD.as_millis() < default_consensus_estimation().as_millis());
    const_assert!(ACCEPTABLE_ERROR_PERCENT <= 100);

    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_775).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    let start_time = curr_time();

    // Start listening BEFORE submitting any transaction not to miss any block committed event
    let event_listener = get_block_committed_event_listener(&test_client)?;

    let account_id = ALICE_ID.clone();
    let asset_definition_id = "rose#wonderland".parse().expect("Valid");
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

    let schedule = TimeSchedule::starting_at(start_time).with_period(PERIOD);
    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose".parse()?,
        Action::new(
            vec![instruction],
            Repeats::Indefinitely,
            account_id.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
        ),
    ));
    test_client.submit(register_trigger)?;

    submit_sample_isi_on_every_block_commit(
        event_listener,
        &mut test_client,
        &account_id,
        Duration::from_secs(1),
        3,
    )?;
    std::thread::sleep(default_consensus_estimation());

    let finish_time = curr_time();
    let average_count = finish_time.saturating_sub(start_time).as_millis() / PERIOD.as_millis();

    let actual_value = get_asset_value(&mut test_client, asset_id);
    let expected_value = prev_value
        .checked_add(Numeric::new(average_count, 0))
        .unwrap();
    let acceptable_error = expected_value.to_f64() * (f64::from(ACCEPTABLE_ERROR_PERCENT) / 100.0);
    let error = core::cmp::max(actual_value, expected_value)
        .checked_sub(core::cmp::min(actual_value, expected_value))
        .unwrap()
        .to_f64();
    assert!(
        error < acceptable_error,
        "error = {error}, but acceptable error = {acceptable_error}"
    );

    Ok(())
}

#[test]
fn mint_asset_after_3_sec() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_665).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    // Sleep to certainly bypass time interval analyzed by genesis
    std::thread::sleep(default_consensus_estimation());

    let asset_definition_id = "rose#wonderland"
        .parse::<AssetDefinitionId>()
        .expect("Valid");
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());

    let init_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;

    let start_time = curr_time();
    // Create trigger with schedule which is in the future to the new block but within block estimation time
    let schedule = TimeSchedule::starting_at(start_time + Duration::from_secs(3));
    let instruction = Mint::asset_numeric(1_u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose".parse().expect("Valid"),
        Action::new(
            vec![instruction],
            Repeats::from(1_u32),
            account_id.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Schedule start is in the future so trigger isn't executed after creating a new block
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just to create block".to_string()))?;
    let after_registration_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;
    assert_eq!(init_quantity, after_registration_quantity);

    // Sleep long enough that trigger start is in the past
    std::thread::sleep(default_consensus_estimation());
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just to create block".to_string()))?;

    let after_wait_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;
    // Schedule is in the past now so trigger is executed
    assert_eq!(
        init_quantity.checked_add(1u32.into()).unwrap(),
        after_wait_quantity
    );

    Ok(())
}

#[test]
fn pre_commit_trigger_should_be_executed() -> Result<()> {
    const CHECKS_COUNT: usize = 5;

    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_600).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse().expect("Valid");
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let mut prev_value = get_asset_value(&mut test_client, asset_id.clone());

    // Start listening BEFORE submitting any transaction not to miss any block committed event
    let event_listener = get_block_committed_event_listener(&test_client)?;

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose".parse()?,
        Action::new(
            vec![instruction],
            Repeats::Indefinitely,
            account_id.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        ),
    ));
    test_client.submit(register_trigger)?;

    for _ in event_listener.take(CHECKS_COUNT) {
        let new_value = get_asset_value(&mut test_client, asset_id.clone());
        assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());
        prev_value = new_value;

        // ISI just to create a new block
        let sample_isi = SetKeyValue::account(
            account_id.clone(),
            "key".parse::<Name>()?,
            "value".parse::<JsonString>()?,
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}

#[test]
fn mint_nft_for_every_user_every_1_sec() -> Result<()> {
    const TRIGGER_PERIOD: Duration = Duration::from_millis(1000);
    const EXPECTED_COUNT: u64 = 4;

    info!("Building trigger");
    let wasm =
        iroha_wasm_builder::Builder::new("../wasm_samples/create_nft_for_every_user_trigger")
            .show_output()
            .build()?
            .optimize()?
            .into_bytes()?;

    info!("WASM size is {} bytes", wasm.len());

    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_780).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();

    let accounts: Vec<AccountId> = vec![
        alice_id.clone(),
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
    ];

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .map(|account_id| Register::account(Account::new(account_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    // Start listening BEFORE submitting any transaction not to miss any block committed event
    let event_listener = get_block_committed_event_listener(&test_client)?;

    // Registering trigger
    // Offset into the future to be able to register trigger
    let offset = Duration::from_secs(10);
    let start_time = curr_time() + offset;
    let schedule = TimeSchedule::starting_at(start_time).with_period(TRIGGER_PERIOD);

    let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));
    let register_trigger = Register::trigger(Trigger::new(
        "mint_nft_for_all".parse()?,
        Action::new(
            WasmSmartContract::from_compiled(wasm),
            Repeats::Indefinitely,
            alice_id.clone(),
            filter,
        ),
    ));
    test_client.submit_blocking(register_trigger)?;
    std::thread::sleep(offset);

    // Time trigger will be executed on block commits, so we have to produce some transactions
    submit_sample_isi_on_every_block_commit(
        event_listener,
        &mut test_client,
        &alice_id,
        TRIGGER_PERIOD,
        usize::try_from(EXPECTED_COUNT)?,
    )?;

    // Checking results
    for account_id in accounts {
        let start_pattern = "nft_number_";
        let end_pattern = format!("_for_{}#{}", account_id.signatory(), account_id.domain());
        let assets = test_client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()?;
        let count: u64 = assets
            .into_iter()
            .filter(|asset| {
                let s = asset.id().definition().to_string();
                s.starts_with(start_pattern) && s.ends_with(&end_pattern)
            })
            .count()
            .try_into()
            .expect("`usize` should always fit in `u64`");

        assert!(
            count >= EXPECTED_COUNT,
            "{account_id} has {count} NFTs, but at least {EXPECTED_COUNT} expected",
        );
    }

    Ok(())
}

/// Get block committed event listener
fn get_block_committed_event_listener(
    client: &Client,
) -> Result<impl Iterator<Item = Result<EventBox>>> {
    let block_filter = BlockEventFilter::default().for_status(BlockStatus::Applied);
    client.listen_for_events([block_filter])
}

/// Get asset numeric value
fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Numeric {
    let asset = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();

    let AssetValue::Numeric(val) = *asset.value() else {
        panic!("Unexpected asset value");
    };

    val
}

/// Submit some sample ISIs to create new blocks
fn submit_sample_isi_on_every_block_commit(
    block_committed_event_listener: impl Iterator<Item = Result<EventBox>>,
    test_client: &mut Client,
    account_id: &AccountId,
    timeout: Duration,
    times: usize,
) -> Result<()> {
    for _ in block_committed_event_listener.take(times) {
        std::thread::sleep(timeout);
        // ISI just to create a new block
        let sample_isi = SetKeyValue::account(
            account_id.clone(),
            "key".parse::<Name>()?,
            JsonString::new("value"),
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}
