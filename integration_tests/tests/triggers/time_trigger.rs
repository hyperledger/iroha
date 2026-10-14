//! Time-based trigger execution paths using bounded async waits.
use crate::triggers::get_asset_value;
use eyre::{Result, WrapErr};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{Level, asset::AssetId, prelude::*},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, gen_account_in, load_sample_ivm};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    task::spawn_blocking,
    time::{sleep, timeout},
};
static NEXT_SUBMIT_PEER_INDEX: AtomicUsize = AtomicUsize::new(0);
fn contract_entrypoint_metadata(entrypoint: &str) -> Metadata {
    let mut metadata = Metadata::default();
    metadata.insert(
        "contract_entrypoint"
            .parse::<Name>()
            .expect("static contract entrypoint metadata key is valid"),
        Json::new(entrypoint.to_owned()),
    );
    metadata
}
fn curr_time() -> Duration {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}
async fn run_or_skip<F, Fut>(context: &'static str, test: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if sandbox::handle_result(test().await, context)?.is_none() {
        return Ok(());
    }
    Ok(())
}
async fn submit_with_context(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    instruction: impl Into<InstructionBox>,
    context: &str,
) -> Result<()> {
    let client = leader_client_for_submit(network, client).await;
    let client = integration_tests::sync::rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout =
            effective_status_timeout(client.transaction_status_timeout, network.sync_timeout());
        client.transaction_ttl = Some(effective_transaction_ttl(
            client.transaction_ttl,
            network.sync_timeout(),
        ));
    });
    let instruction = instruction.into();
    let context = context.to_string();
    spawn_blocking(move || {
        client
            .submit(
                instruction,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err(context)
    })
    .await??;
    Ok(())
}
async fn submit_all_with_context(
    network: &sandbox::SerializedNetwork,
    client: &Client,
    instructions: Vec<InstructionBox>,
    context: &str,
) -> Result<()> {
    let client = leader_client_for_submit(network, client).await;
    let client = integration_tests::sync::rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout =
            effective_status_timeout(client.transaction_status_timeout, network.sync_timeout());
        client.transaction_ttl = Some(effective_transaction_ttl(
            client.transaction_ttl,
            network.sync_timeout(),
        ));
    });
    let context = context.to_string();
    spawn_blocking(move || {
        client
            .submit_all(
                instructions,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err(context)
    })
    .await??;
    Ok(())
}
async fn leader_client_for_submit(network: &sandbox::SerializedNetwork, probe: &Client) -> Client {
    let peer_count = network.peers().len();
    let status = probe.client().status().get().await.ok();
    let sumeragi = spawn_blocking({
        let client = probe.clone();
        move || client.client().get_sumeragi_status()
    })
    .await
    .ok()
    .and_then(Result::ok);
    let leader_index = sumeragi
        .as_ref()
        .and_then(|status| status.leader.as_ref())
        .and_then(|leader| {
            network
                .peers()
                .iter()
                .position(|peer| peer.id().public_key() == leader)
        })
        .filter(|&idx| idx < peer_count);
    let leader_is_connected = status
        .as_ref()
        .is_some_and(|status| status.peers >= min_connected_peers_for_submit(peer_count));
    let fallback_totals = network
        .peers()
        .iter()
        .map(|peer| {
            peer.best_effort_block_height()
                .map(|height| height.total)
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    let fallback_seed = NEXT_SUBMIT_PEER_INDEX.fetch_add(1, Ordering::Relaxed);
    let fallback_index = pick_fallback_submit_peer_index(&fallback_totals, fallback_seed);
    let selected_index = if leader_is_connected {
        leader_index.unwrap_or(fallback_index)
    } else {
        fallback_index
    };
    network
        .peers()
        .get(selected_index)
        .unwrap_or_else(|| {
            network
                .peers()
                .first()
                .expect("network should have at least one peer")
        })
        .client()
}
fn effective_status_timeout(current: Duration, sync_timeout: Duration) -> Duration {
    current.max(sync_timeout)
}
fn effective_transaction_ttl(current: Option<Duration>, sync_timeout: Duration) -> Duration {
    let baseline = sync_timeout.checked_mul(4).unwrap_or(sync_timeout);
    current.unwrap_or(baseline).max(baseline)
}
fn min_connected_peers_for_submit(peer_count: usize) -> u64 {
    match peer_count {
        0..=2 => 0,
        _ => u64::try_from(peer_count.saturating_sub(2)).expect("peer count should fit into u64"),
    }
}
fn pick_fallback_submit_peer_index(block_totals: &[u64], seed: usize) -> usize {
    if block_totals.is_empty() {
        return 0;
    }
    let best_total = block_totals.iter().copied().max().unwrap_or(0);
    let best_indices = block_totals
        .iter()
        .enumerate()
        .filter_map(|(idx, total)| (*total == best_total).then_some(idx))
        .collect::<Vec<_>>();
    if best_indices.is_empty() {
        return 0;
    }
    let offset = seed % best_indices.len();
    best_indices[offset]
}
fn counts_meet_expected(counts: &[u64], expected: u64) -> bool {
    counts.iter().copied().all(|count| count >= expected)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn time_trigger_scenarios() -> Result<()> {
    let is_retryable = |err: &eyre::Report| {
        err.chain().any(|cause| {
            let msg = cause.to_string();
            msg.contains("tx confirmation timed out")
                || msg.contains("haven't got tx confirmation within")
                || msg.contains("transaction queued for too long")
                || msg.contains("Transaction expired")
                || msg
                    .contains("Network overall height did not pass given predicate within timeout")
                || msg.contains("block sync predicate failed")
        })
    };
    let mut attempt = 0;
    loop {
        attempt += 1;
        let result = async {
            let Some(network) = sandbox::start_network_async_or_skip(
                NetworkBuilder::new().with_default_block_cadence(),
                stringify!(time_trigger_scenarios),
            )
            .await?
            else {
                return Ok(());
            };
            let test_client = network.client();
            network.ensure_blocks_with(|h| h.total >= 1).await?;
            mint_asset_after_3_sec_scenario(&network, &test_client).await?;
            pre_commit_trigger_should_be_executed_scenario(&network, &test_client).await?;
            mint_nft_for_every_user_every_1_sec_scenario(&network, &test_client).await?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(err) if attempt < 2 && is_retryable(&err) => {
                eprintln!("warning: retrying time trigger scenarios after transient error: {err}");
            }
            Err(err) => return Err(err),
        }
    }
}
async fn mint_asset_after_3_sec_scenario(
    network: &sandbox::SerializedNetwork,
    test_client: &Client,
) -> Result<()> {
    let test_client = test_client.clone();
    let sync_timeout = network.sync_timeout();
    run_or_skip(stringify!(mint_asset_after_3_sec), || async {
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            "rose".parse().expect("Valid"),
        );
        let account_id = ALICE_ID.clone();
        let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
        let init_quantity = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        let expected_value = init_quantity
            .clone()
            .checked_add(&1u32.into())
            .expect("quantity should increment");
        let mut target_height = network
            .peers()
            .iter()
            .filter_map(|peer| peer.best_effort_block_height())
            .map(|height| height.total)
            .max()
            .unwrap_or(0);
        let start_time = curr_time();
        let pipeline_time = network.block_cadence();
        let gap = std::cmp::max(
            Duration::from_millis(200),
            pipeline_time.checked_div(2).unwrap_or(pipeline_time),
        );
        let schedule_at = start_time + gap;
        let schedule = TimeSchedule::starting_at(schedule_at);
        let instruction = Mint::asset_quantity(1_u32, asset_id.clone());
        let register_trigger = Register::trigger(Trigger::new(
            "mint_rose_schedule".parse().expect("Valid"),
            Action::new(
                vec![instruction],
                Repeats::from(1_u32),
                account_id.clone(),
                TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        submit_with_context(
            network,
            &test_client,
            register_trigger,
            "mint_asset_after_3_sec register trigger",
        )
        .await?;
        target_height = target_height.saturating_add(1);
        network
            .ensure_blocks_with(|height| height.total >= target_height)
            .await?;
        submit_with_context(
            network,
            &test_client,
            Log::new(Level::DEBUG, "Just to create block".to_string()),
            "mint_asset_after_3_sec create block",
        )
        .await?;
        target_height = target_height.saturating_add(1);
        network
            .ensure_blocks_with(|height| height.total >= target_height)
            .await?;
        let after_registration_quantity = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        if after_registration_quantity == expected_value {
            // Scheduling can fire immediately if the block time already passed the schedule.
            return Ok(());
        }
        assert_eq!(init_quantity, after_registration_quantity);
        let poll_delay = pipeline_time.checked_div(2).unwrap_or(pipeline_time);
        // Ensure we create a block after the schedule time; block production can be faster than
        // pipeline_time, which would otherwise skip the scheduled window entirely.
        let wait_until = schedule_at.saturating_sub(curr_time());
        if !wait_until.is_zero() {
            sleep(wait_until).await;
        }
        submit_with_context(
            network,
            &test_client,
            Log::new(Level::DEBUG, "Just to create block".to_string()),
            "mint_asset_after_3_sec create block after poll delay",
        )
        .await?;
        target_height = target_height.saturating_add(1);
        network
            .ensure_blocks_with(|height| height.total >= target_height)
            .await?;
        timeout(sync_timeout, async {
            loop {
                let after_wait_quantity = spawn_blocking({
                    let client = test_client.clone();
                    let asset_id = asset_id.clone();
                    move || get_asset_value(&client, &asset_id)
                })
                .await??;
                if after_wait_quantity == expected_value {
                    break Ok::<(), eyre::Report>(());
                }
                sleep(poll_delay).await;
            }
        })
        .await??;
        Ok(())
    })
    .await
}
#[allow(clippy::items_after_statements)]
async fn pre_commit_trigger_should_be_executed_scenario(
    network: &sandbox::SerializedNetwork,
    test_client: &Client,
) -> Result<()> {
    const CHECKS_COUNT: usize = 3;
    let test_client = test_client.clone();
    run_or_skip(
        stringify!(pre_commit_trigger_should_be_executed),
        || async {
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("Valid"),
                "rose".parse().expect("Valid"),
            );
            let account_id = ALICE_ID.clone();
            let asset_id = AssetId::new(asset_definition_id, account_id.clone());
            let instruction = Mint::asset_quantity(1u32, asset_id.clone());
            let register_trigger = Register::trigger(Trigger::new(
                "mint_rose_precommit".parse()?,
                Action::new(
                    vec![instruction],
                    Repeats::Indefinitely,
                    account_id.clone(),
                    TimeEventFilter::new(ExecutionTime::PreCommit),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            let mut target_height = network
                .peers()
                .iter()
                .filter_map(|peer| peer.best_effort_block_height())
                .map(|height| height.total)
                .max()
                .unwrap_or(0);
            submit_with_context(
                network,
                &test_client,
                register_trigger,
                "pre_commit_trigger_should_be_executed register trigger",
            )
            .await?;
            target_height = target_height.saturating_add(1);
            network
                .ensure_blocks_with(|height| height.total >= target_height)
                .await?;
            let prev_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            for _ in 0..CHECKS_COUNT {
                let sample_isi = SetKeyValue::account(
                    account_id.clone(),
                    "key".parse::<Name>()?,
                    Json::from("value"),
                );
                // Submit without waiting for tx confirmation to avoid queue-timeout flakiness.
                let submit_client = leader_client_for_submit(network, &test_client).await;
                let context = "pre_commit_trigger_should_be_executed sample ISI".to_string();
                spawn_blocking(move || {
                    submit_client
                        .submit(
                            sample_isi,
                            iroha_data_model::transaction::FeePaymentIntent::authority(
                                Vec::new(),
                                None,
                            ),
                        )
                        .wrap_err(context)
                })
                .await??;
                target_height = target_height.saturating_add(1);
                network
                    .ensure_blocks_with(|height| height.total >= target_height)
                    .await?;
            }
            let expected_value = prev_value
                .checked_add(&Quantity::from(u32::try_from(CHECKS_COUNT)?))
                .expect("value increment should fit");
            let poll_delay = std::cmp::max(
                Duration::from_millis(200),
                network
                    .block_cadence()
                    .checked_div(2)
                    .unwrap_or_else(|| network.block_cadence()),
            );
            timeout(network.sync_timeout(), async {
                loop {
                    let new_value = spawn_blocking({
                        let client = test_client.clone();
                        let asset_id = asset_id.clone();
                        move || get_asset_value(&client, &asset_id)
                    })
                    .await??;
                    if new_value >= expected_value {
                        break Ok::<(), eyre::Report>(());
                    }
                    sleep(poll_delay).await;
                }
            })
            .await
            .wrap_err("pre_commit_trigger_should_be_executed poll timed out")??;
            let trigger_id: TriggerId = "mint_rose_precommit".parse()?;
            submit_with_context(
                network,
                &test_client,
                Unregister::trigger(trigger_id),
                "pre_commit_trigger_should_be_executed unregister trigger",
            )
            .await?;
            target_height = target_height.saturating_add(1);
            network
                .ensure_blocks_with(|height| height.total >= target_height)
                .await?;
            Ok(())
        },
    )
    .await
}
async fn mint_nft_for_every_user_every_1_sec_scenario(
    network: &sandbox::SerializedNetwork,
    test_client: &Client,
) -> Result<()> {
    let test_client = test_client.clone();
    let trigger_period = std::cmp::max(
        Duration::from_millis(300),
        network
            .block_cadence()
            .checked_div(2)
            .unwrap_or_else(|| network.block_cadence()),
    );
    let expected_count: u64 = 3;
    run_or_skip(stringify!(mint_nft_for_every_user_every_1_sec), || async {
        let alice_id = ALICE_ID.clone();
        let accounts: Vec<AccountId> = vec![
            alice_id.clone(),
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
        ];
        let register_accounts = accounts
            .iter()
            .skip(1)
            .cloned()
            .map(|account_id| Register::account(Account::new(account_id.clone())))
            .collect::<Vec<_>>();
        let mut target_height = network
            .peers()
            .iter()
            .filter_map(|peer| peer.best_effort_block_height())
            .map(|height| height.total)
            .max()
            .unwrap_or(0);
        let register_accounts = register_accounts
            .into_iter()
            .map(InstructionBox::from)
            .collect::<Vec<_>>();
        submit_all_with_context(
            network,
            &test_client,
            register_accounts,
            "mint_nft_for_every_user_every_1_sec register accounts",
        )
        .await?;
        target_height = target_height.saturating_add(1);
        network
            .ensure_blocks_with(|height| height.total >= target_height)
            .await?;
        println!("registered additional accounts for time trigger");
        let mut baseline_counts = Vec::with_capacity(accounts.len());
        for account_id in &accounts {
            let account_id_clone = account_id.clone();
            let count: u64 = spawn_blocking({
                let client = test_client.clone();
                move || {
                    client
                        .client()
                        .query(FindNfts::new())
                        .execute_all()
                        .map(|nfts| {
                            nfts.into_iter()
                                .filter(|nft| nft.owned_by() == &account_id_clone)
                                .count()
                        })
                }
            })
            .await??
            .try_into()
            .expect("`usize` should always fit in `u64`");
            baseline_counts.push(count);
        }
        let offset = trigger_period.saturating_mul(2);
        let start_time = curr_time() + offset;
        let schedule = TimeSchedule::starting_at(start_time).with_period(trigger_period);
        let filter = TimeEventFilter::new(ExecutionTime::Schedule(schedule));
        let register_trigger = Register::trigger(Trigger::new(
            "mint_nft_for_all".parse()?,
            Action::new(
                load_sample_ivm("create_nft_for_every_user_trigger"),
                Repeats::Exactly(u32::try_from(expected_count)?),
                alice_id.clone(),
                filter,
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(contract_entrypoint_metadata("run")),
        ));
        submit_with_context(
            network,
            &test_client,
            register_trigger,
            "mint_nft_for_every_user_every_1_sec register trigger",
        )
        .await?;
        target_height = target_height.saturating_add(1);
        network
            .ensure_blocks_with(|height| height.total >= target_height)
            .await?;
        sleep(offset).await;
        // Drive one extra block to cover schedule hits that fall on end-exclusive boundaries.
        let blocks_to_drive = usize::try_from(expected_count)? + 1;
        println!("registered time trigger, driving {blocks_to_drive} blocks");
        submit_sample_isi_on_every_block_commit(
            network,
            &test_client,
            &alice_id,
            trigger_period,
            blocks_to_drive,
        )
        .await?;
        let poll_delay = std::cmp::max(
            Duration::from_millis(200),
            trigger_period.checked_div(2).unwrap_or(trigger_period),
        );
        timeout(network.sync_timeout(), async {
            loop {
                let mut minted_counts = Vec::with_capacity(accounts.len());
                for (idx, account_id) in accounts.iter().enumerate() {
                    let account_id_clone = account_id.clone();
                    let count: u64 = spawn_blocking({
                        let client = test_client.clone();
                        move || {
                            client
                                .client()
                                .query(FindNfts::new())
                                .execute_all()
                                .map(|nfts| {
                                    nfts.into_iter()
                                        .filter(|nft| nft.owned_by() == &account_id_clone)
                                        .count()
                                })
                        }
                    })
                    .await??
                    .try_into()
                    .expect("`usize` should always fit in `u64`");
                    let baseline = baseline_counts.get(idx).copied().unwrap_or(0);
                    minted_counts.push(count.saturating_sub(baseline));
                }
                if counts_meet_expected(&minted_counts, expected_count) {
                    break Ok::<(), eyre::Report>(());
                }
                sleep(poll_delay).await;
            }
        })
        .await
        .wrap_err("mint_nft_for_every_user_every_1_sec poll timed out")??;
        Ok(())
    })
    .await
}
/// Submit some sample ISIs to create new blocks
async fn submit_sample_isi_on_every_block_commit(
    network: &sandbox::SerializedNetwork,
    test_client: &Client,
    account_id: &AccountId,
    timeout: Duration,
    times: usize,
) -> Result<()> {
    let initial_height = network
        .peers()
        .iter()
        .filter_map(|peer| peer.best_effort_block_height())
        .map(|height| height.total)
        .max()
        .unwrap_or(0);
    for idx in 0..times {
        sleep(timeout).await;
        let sample_isi = SetKeyValue::account(
            account_id.clone(),
            "key".parse::<Name>()?,
            Json::new(format!("value_{idx}")),
        );
        // Submit without waiting for tx confirmation to avoid queue-timeout flakiness.
        let submit_client = leader_client_for_submit(network, test_client).await;
        let context = "time_trigger sample ISI".to_string();
        spawn_blocking(move || {
            submit_client
                .submit(
                    sample_isi,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .wrap_err(context)
        })
        .await??;
        println!("submitted sample ISI {}/{}", idx + 1, times);
    }
    // Ensure at least one additional block committed after submissions were sent.
    network
        .ensure_blocks_with(|height| height.total >= initial_height.saturating_add(1))
        .await?;
    Ok(())
}
#[cfg(test)]
mod timeout_tests {
    use super::{
        counts_meet_expected, effective_status_timeout, effective_transaction_ttl,
        min_connected_peers_for_submit, pick_fallback_submit_peer_index,
    };
    use std::time::Duration;
    #[test]
    fn status_timeout_prefers_larger_value() {
        let short = Duration::from_secs(30);
        let long = Duration::from_secs(120);
        assert_eq!(effective_status_timeout(short, long), long);
        assert_eq!(effective_status_timeout(long, short), long);
    }
    #[test]
    fn transaction_ttl_prefers_sync_timeout_floor() {
        let short = Some(Duration::from_secs(30));
        let long = Duration::from_secs(45);
        assert_eq!(
            effective_transaction_ttl(short, long),
            Duration::from_secs(180)
        );
        assert_eq!(
            effective_transaction_ttl(Some(Duration::from_secs(300)), long),
            Duration::from_secs(300)
        );
        assert_eq!(
            effective_transaction_ttl(None, long),
            Duration::from_secs(180)
        );
    }
    #[test]
    fn submit_connection_threshold_scales_with_peer_count() {
        assert_eq!(min_connected_peers_for_submit(0), 0);
        assert_eq!(min_connected_peers_for_submit(1), 0);
        assert_eq!(min_connected_peers_for_submit(2), 0);
        assert_eq!(min_connected_peers_for_submit(3), 1);
        assert_eq!(min_connected_peers_for_submit(4), 2);
    }
    #[test]
    fn fallback_submit_peer_index_rotates_across_best_peers() {
        let totals = [7, 9, 9, 5];
        assert_eq!(pick_fallback_submit_peer_index(&totals, 0), 1);
        assert_eq!(pick_fallback_submit_peer_index(&totals, 1), 2);
        assert_eq!(pick_fallback_submit_peer_index(&totals, 2), 1);
    }
    #[test]
    fn fallback_submit_peer_index_defaults_to_zero_when_empty() {
        assert_eq!(pick_fallback_submit_peer_index(&[], 42), 0);
    }
    #[test]
    fn counts_meet_expected_requires_each_account_to_reach_target() {
        assert!(counts_meet_expected(&[3, 4, 3], 3));
        assert!(!counts_meet_expected(&[3, 2, 3], 3));
    }
}
