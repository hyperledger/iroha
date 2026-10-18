//! Lanes on real peers (`specs/sumeragi_lanes.md`): four validators run the global chain and a
//! fixed lane over P2P. A transaction routed to the lane is carried by a certified lane block,
//! merged by the global chain and committed on every peer, before and after the whole cluster
//! restarts.
use std::time::{Duration, Instant};

use eyre::{Result, bail};
use integration_tests::{
    sandbox::{self, SerializedNetwork},
    sync::sumeragi_statuses_reach_height,
};
use iroha::data_model::{
    account::Account,
    isi::{Log, Register, SetParameter},
    parameter::{Parameter, system::SumeragiParameters},
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
        SumeragiLaneStatus,
    },
};
use iroha_data_model::level::Level;
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_test_network::{Network, NetworkBuilder, NetworkPeer, init_instruction_registry};
use iroha_test_samples::gen_account_in;
use tokio::runtime::Runtime;

/// The long-running P2P lane soak (ignored by default).
#[path = "sumeragi_lanes_soak.rs"]
mod soak;

/// Independent native committees, stalled-lane isolation and retained-history restart.
#[path = "sumeragi_lanes_disjoint.rs"]
mod disjoint;

const TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES: i64 = 1024 * 1024 * 1024;
const LANE: LaneId = LaneId::new(2);

/// Fixed lane 2 over the whole validator set; `Log` instructions route to it.
fn lane_policy(topology: &[GenesisTopologyEntry]) -> SumeragiLanePolicy {
    SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 64,
        max_merge_blocks: 16,
        stall_window: 10_000,
        lane_params: SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: LANE,
            dataspace: DataSpaceId::new(0),
            committee: topology
                .iter()
                .map(|entry| SumeragiLaneMember {
                    peer: entry.peer.clone(),
                    pop: entry
                        .pop_bytes()
                        .expect("a well-formed PoP")
                        .expect("every validator provides a PoP"),
                })
                .collect(),
        }],
        routes: vec![SumeragiLaneRoute {
            lane: LANE,
            account: None,
            instruction: Some("Log".to_owned()),
        }],
        autoscale: None,
    }
}

fn builder() -> NetworkBuilder {
    NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_genesis_instruction(iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom({
                let mut fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
                fees.fee_sink_account_id = iroha_test_samples::ALICE_ID.clone();
                fees.base_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_byte_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_instruction_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_gas_unit_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.into_custom_parameter()
                    .expect("explicit signed fixture fee policy")
            }),
        ))
        .with_config_layer(|layer| {
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                // Isolate consensus from fee funding: keep the fee asset, quote zero charges.



                ;
        })
        .with_genesis_post_topology_isi_from(|topology| {
            vec![
                SetParameter::new(Parameter::Custom(
                    lane_policy(topology).into_custom_parameter(),
                ))
                .into(),
            ]
        })
}

fn start(name: &str) -> Result<Option<(SerializedNetwork, Runtime)>> {
    init_instruction_registry();
    sandbox::start_network_blocking_or_skip(builder(), name)
}

fn running_peer(network: &Network) -> Result<&NetworkPeer> {
    network
        .peers()
        .iter()
        .find(|peer| peer.is_running())
        .ok_or_else(|| eyre::eyre!("no peer is running"))
}

fn committed_height(network: &Network) -> Result<u64> {
    Ok(running_peer(network)?
        .client()
        .client()
        .get_sumeragi_status()?
        .committed_height)
}

/// Wait for every configured global peer; exits remain failed observations.
fn wait_for_committed(network: &Network, height: u64, limit: Duration) -> Result<()> {
    let peers = network.peers();
    let deadline = Instant::now() + limit;
    loop {
        let statuses: Vec<_> = peers
            .iter()
            .map(|peer| peer.client().client().get_sumeragi_status())
            .collect();
        if sumeragi_statuses_reach_height(&statuses, height)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("peers did not commit height {height} in {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Every configured peer's view of lane 2; a stopped peer cannot disappear from a wait.
fn lane_statuses(network: &Network) -> Result<Vec<SumeragiLaneStatus>> {
    if network.peers().is_empty() {
        bail!("cannot establish lane progress without any configured peers");
    }
    network
        .peers()
        .iter()
        .map(|peer| {
            let lanes = peer.client().client().get_sumeragi_lanes()?;
            lanes
                .into_iter()
                .find(|status| status.record.lane == LANE)
                .ok_or_else(|| eyre::eyre!("peer {} has no lane {LANE}", peer.id()))
        })
        .collect()
}

/// Wait until every running peer runs its instance of lane 2 (member of the pinned committee).
fn wait_for_lane_instances(network: &Network, limit: Duration) -> Result<()> {
    let deadline = Instant::now() + limit;
    loop {
        if let Ok(statuses) = lane_statuses(network)
            && statuses.iter().all(|status| {
                status
                    .instance
                    .as_ref()
                    .is_some_and(|instance| instance.halted.is_none())
            })
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("not every peer runs lane {LANE} within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Register a fresh account (a global-lane transaction) and wait for every peer.
fn register_account_everywhere(network: &Network) -> Result<()> {
    let (account, _) = gen_account_in("wonderland");
    running_peer(network)?.client().submit(
        Register::account(Account::new(account)),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let height = committed_height(network)?;
    wait_for_committed(network, height, Duration::from_secs(60))
}

/// Submit a `Log` transaction (routed to lane 2) and wait until every peer merged a lane block
/// beyond `merged`.
fn log_through_the_lane(network: &Network, message: &str, merged: u64) -> Result<u64> {
    running_peer(network)?.client().submit(
        Log::new(Level::INFO, message.to_owned()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let statuses = lane_statuses(network)?;
        let frontiers = statuses
            .iter()
            .map(|status| status.record.merged.height)
            .collect::<Vec<_>>();
        if frontiers.iter().all(|height| *height > merged) {
            return Ok(frontiers.into_iter().min().unwrap_or(merged));
        }
        if Instant::now() >= deadline {
            bail!("lane {LANE} did not merge past {merged}: frontiers {frontiers:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_fixed_lane_carries_transactions_over_p2p_across_a_restart() -> Result<()> {
    let Some((network, rt)) = start(stringify!(
        a_fixed_lane_carries_transactions_over_p2p_across_a_restart
    ))?
    else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout())?;
        // Genesis creates the lane, active from global height 3: two global transactions get
        // the global chain there, and every validator starts the lane.
        register_account_everywhere(&network)?;
        register_account_everywhere(&network)?;
        wait_for_lane_instances(&network, Duration::from_secs(60))?;
        let merged = log_through_the_lane(&network, "through the lane", 0)?;
        // The whole cluster restarts: replay merges from the lane stores on disk, the lane
        // instances resume, and the lane keeps carrying transactions.
        let height = committed_height(&network)?;
        for peer in network.peers() {
            rt.block_on(peer.shutdown());
        }
        for peer in network.peers() {
            let layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            rt.block_on(peer.start_checked(layers.iter(), None))?;
        }
        wait_for_committed(&network, height, Duration::from_secs(60))?;
        wait_for_lane_instances(&network, Duration::from_secs(60))?;
        log_through_the_lane(&network, "through the lane after the restart", merged)?;
        Ok(())
    })();
    rt.block_on(async { network.shutdown().await });
    result
}
