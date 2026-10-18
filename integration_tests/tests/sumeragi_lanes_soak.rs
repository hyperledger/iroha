//! P2P lane soak (`specs/sumeragi_lanes.md`, `specs/sumeragi.md` §13.5), a module of the
//! `sumeragi_lanes` test crate: four validators run the global chain, a fixed lane and an
//! elastic lane over real P2P under sustained load while validators are killed with `SIGKILL`
//! and restarted, one at a time.
//!
//! Load: a dedicated account's `Log` transactions are routed to the fixed lane by an account
//! route; Alice's and a second-shard account's `Log` transactions take the default route, whose
//! utilization opens the elastic lane (autoscale), after which the second-shard account's
//! transactions are carried by it. Every submission waits for its `Applied` finality.
//!
//! Assertions: the global chain, the fixed lane's merged frontier and its merge height advance
//! in every check window; the elastic lane opens and carries merged blocks; at the end every
//! peer holds the same global block hashes and the same lane records.
//!
//! The soak is `#[ignore]`d, so the default suite stays fast:
//! `cargo test -p integration_tests --test sumeragi_lanes -- --ignored soak`. Its length comes
//! from the test-only knob `SUMERAGI_LANES_SOAK_SECS` (default 300). With
//! `SUMERAGI_LANES_SOAK_OUT=<dir>` it also writes the run, passed or failed (a failed restart is
//! an exited lifetime), in the layout of `scripts/sumeragi_soak.py` (per-boot JSON node logs with
//! the driver's audit lines, the timeline of kills and restarts, load and thresholds), so that
//! `python3 scripts/sumeragi_soak.py --analyze <dir>` computes O-AGR, O-SIGN, O-LIVE and O-PERF
//! from the nodes' logs.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eyre::{Result, WrapErr, bail, eyre};
use integration_tests::sandbox::{self, SerializedNetwork};
use iroha::data_model::{
    account::{Account, AccountId},
    isi::{Log, Register, SetParameter},
    parameter::{Parameter, system::SumeragiParameters},
    query::{block::prelude::FindBlockHeaders, builder::QueryBuilderExt as _},
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneAutoscale, SumeragiLaneMember, SumeragiLanePolicy,
        SumeragiLaneRecord, SumeragiLaneRoute,
    },
    transaction::FeePaymentIntent,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::level::Level;
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_test_network::{Network, NetworkBuilder, NetworkPeer, init_instruction_registry};
use norito::json::{Map, Value};
use tokio::runtime::Runtime;

const TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES: i64 = 1024 * 1024 * 1024;
const FIXED_LANE: LaneId = LaneId::new(2);
const ELASTIC_LANE: LaneId = LaneId::new(16);
const DURATION_ENV: &str = "SUMERAGI_LANES_SOAK_SECS";
const OUT_ENV: &str = "SUMERAGI_LANES_SOAK_OUT";
const DEFAULT_DURATION: Duration = Duration::from_secs(300);
const MIN_DURATION: Duration = Duration::from_secs(120);
/// Every check window must show progress of the global chain and the fixed lane.
const CHECK_WINDOW: Duration = Duration::from_secs(45);
/// How long a killed validator stays down before its restart.
const DOWNTIME: Duration = Duration::from_secs(8);
/// Filter that enables the driver's audit lines (the durable-record line is DEBUG).
const AUDIT_LOG_FILTER: &str = "info,iroha_core::sumeragi::driver::audit=debug";

/// Length of the soak from the test-only knob.
fn soak_duration() -> Result<Duration> {
    let duration = match std::env::var(DURATION_ENV) {
        Ok(raw) => Duration::from_secs(
            raw.trim()
                .parse::<u64>()
                .wrap_err_with(|| format!("{DURATION_ENV} must be whole seconds, got {raw:?}"))?,
        ),
        Err(_) => DEFAULT_DURATION,
    };
    if duration < MIN_DURATION {
        bail!(
            "{DURATION_ENV} must be at least {} s",
            MIN_DURATION.as_secs()
        );
    }
    Ok(duration)
}

/// A deterministic Ed25519 account of `seed`.
fn account(seed: u8) -> (AccountId, KeyPair) {
    let key = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
    (AccountId::new(key.public_key().clone()), key)
}

/// The account routed to the fixed lane.
fn fixed_lane_account() -> (AccountId, KeyPair) {
    account(0xF0)
}

/// An account whose default route is the elastic lane once it is open (shard 1 of 2).
fn elastic_lane_account() -> (AccountId, KeyPair) {
    (1u8..=u8::MAX)
        .map(account)
        .find(|(id, _)| iroha_core::sumeragi::lanes::routing::default_shard(id, 2) == 1)
        .expect("a seed whose account lies on the second shard")
}

/// Fixed lane 2 (the whole validator set, the fixed-lane account's transactions) and one
/// elastic lane (16) opened by default-route utilization.
fn lane_policy(topology: &[GenesisTopologyEntry]) -> SumeragiLanePolicy {
    let committee: Vec<SumeragiLaneMember> = topology
        .iter()
        .map(|entry| SumeragiLaneMember {
            peer: entry.peer.clone(),
            pop: entry
                .pop_bytes()
                .expect("a well-formed PoP")
                .expect("every validator provides a PoP"),
        })
        .collect();
    SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 64,
        max_merge_blocks: 16,
        stall_window: 10_000,
        lane_params: SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: FIXED_LANE,
            dataspace: DataSpaceId::new(0),
            committee,
        }],
        routes: vec![SumeragiLaneRoute {
            lane: FIXED_LANE,
            // The router matches the account's literal (or its encoded form).
            account: Some(fixed_lane_account().0.to_string()),
            instruction: None,
        }],
        autoscale: Some(SumeragiLaneAutoscale {
            min_lane: ELASTIC_LANE,
            max_lane_exclusive: LaneId::new(17),
            dataspace: DataSpaceId::new(0),
            committee_size: 4,
            per_lane_target_tps: 1,
            window: 3,
            scale_out_permille: 300,
            scale_in_permille: 150,
            cooldown: 3,
        }),
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
                // JSON logs with the driver's audit lines, for the soak oracles.
                .write(["logger", "format"], "json")
                .write(["logger", "filter"], AUDIT_LOG_FILTER)
                // No SCCP light-client keeper: it polls public Ethereum RPC endpoints by
                // default, which a consensus soak must not depend on or contact.
                .write(["sccp", "light_client_keeper", "enabled"], false);
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

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64() * 1000.0)
}

fn running(network: &Network) -> Vec<NetworkPeer> {
    network
        .peers()
        .iter()
        .filter(|peer| peer.is_running())
        .cloned()
        .collect()
}

/// The lowest committed global height of the running peers, failing on a halted peer.
fn min_committed_height(network: &Network) -> Result<u64> {
    let mut lowest = u64::MAX;
    for peer in running(network) {
        let status = peer.client().client().get_sumeragi_status()?;
        if let Some(halted) = status.halted {
            bail!("peer {} halted: {halted:?}", peer.id());
        }
        lowest = lowest.min(status.committed_height);
    }
    if lowest == u64::MAX {
        bail!("no peer is running");
    }
    Ok(lowest)
}

/// One running peer's lane records by lane.
fn lane_records(peer: &NetworkPeer) -> Result<BTreeMap<LaneId, SumeragiLaneRecord>> {
    Ok(peer
        .client()
        .client()
        .get_sumeragi_lanes()?
        .into_iter()
        .map(|status| (status.record.lane, status.record))
        .collect())
}

/// Wait until `condition` holds, polling every 250 ms.
fn wait_until(
    limit: Duration,
    what: &str,
    mut condition: impl FnMut() -> Result<bool>,
) -> Result<()> {
    let deadline = Instant::now() + limit;
    loop {
        if condition().unwrap_or(false) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{what} within {limit:?}");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// A commit-latency sample of one `Applied`-finality submission.
#[derive(Clone, Copy)]
struct Probe {
    start_ms: f64,
    end_ms: f64,
    ok: bool,
}

/// Load of one account: `Log` transactions submitted one at a time through a running peer.
struct Submitter {
    name: &'static str,
    account: AccountId,
    key: KeyPair,
    submitted: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

impl Submitter {
    fn new(name: &'static str, (account, key): (AccountId, KeyPair)) -> Self {
        Self {
            name,
            account,
            key,
            submitted: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
        }
    }

    fn spawn(
        &self,
        peers: Vec<NetworkPeer>,
        stop: Arc<AtomicBool>,
        probes: Arc<Mutex<Vec<Probe>>>,
    ) -> thread::JoinHandle<()> {
        let (name, account, key) = (self.name, self.account.clone(), self.key.clone());
        let (submitted, failed) = (Arc::clone(&self.submitted), Arc::clone(&self.failed));
        thread::spawn(move || {
            let mut sequence = 0u64;
            while !stop.load(Ordering::Relaxed) {
                sequence += 1;
                let Some(peer) = peers
                    .iter()
                    .cycle()
                    .skip(usize::try_from(sequence).unwrap_or(0) % peers.len())
                    .take(peers.len())
                    .find(|peer| peer.is_running())
                else {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                };
                let start_ms = now_ms();
                let result = peer.client_for(&account, key.private_key().clone()).submit(
                    Log::new(Level::INFO, format!("lane soak {name} {sequence}")),
                    FeePaymentIntent::authority(Vec::new(), None),
                );
                let probe = Probe {
                    start_ms,
                    end_ms: now_ms(),
                    ok: result.is_ok(),
                };
                probes.lock().expect("probe lock").push(probe);
                if result.is_ok() {
                    submitted.fetch_add(1, Ordering::Relaxed);
                } else {
                    failed.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(500));
                }
            }
        })
    }
}

/// Progress between check windows: the global chain, the fixed lane's merged frontier and its
/// merge height advance in every window; the elastic lane is tracked.
struct Progress {
    height: u64,
    fixed: (u64, u64),
    checked: u32,
    elastic_opened: bool,
    elastic_merged: u64,
}

impl Progress {
    fn new(height: u64) -> Self {
        Self {
            height,
            fixed: (0, 0),
            checked: 0,
            elastic_opened: false,
            elastic_merged: 0,
        }
    }

    /// Wait one [`CHECK_WINDOW`] and judge it; `false` when the soak ends first (an incomplete
    /// window is not judged).
    fn check_after(&mut self, network: &Network, deadline: Instant) -> Result<bool> {
        let end = Instant::now() + CHECK_WINDOW;
        if end > deadline {
            thread::sleep(deadline.saturating_duration_since(Instant::now()));
            return Ok(false);
        }
        thread::sleep(CHECK_WINDOW);
        let height = min_committed_height(network)?;
        if height <= self.height {
            bail!(
                "the global chain did not advance past {} in {CHECK_WINDOW:?}",
                self.height
            );
        }
        self.height = height;
        let peers = running(network);
        let peer = peers.first().ok_or_else(|| eyre!("no peer is running"))?;
        let records = lane_records(peer)?;
        let fixed = records
            .get(&FIXED_LANE)
            .ok_or_else(|| eyre!("the fixed lane disappeared"))?;
        let frontier = (fixed.merged.height, fixed.merged_at);
        if frontier.0 <= self.fixed.0 || frontier.1 <= self.fixed.1 {
            bail!(
                "the fixed lane did not merge in {CHECK_WINDOW:?}: frontier {frontier:?}, before {:?}",
                self.fixed
            );
        }
        self.fixed = frontier;
        if let Some(elastic) = records.get(&ELASTIC_LANE) {
            self.elastic_opened = true;
            self.elastic_merged = self.elastic_merged.max(elastic.merged.height);
        }
        self.checked += 1;
        Ok(true)
    }

    /// The elastic lane opened under default-route load and had blocks merged.
    fn require_elastic_lane(&self) -> Result<()> {
        if self.checked < 2 {
            bail!(
                "the soak judged {} windows; it needs a longer duration",
                self.checked
            );
        }
        if !self.elastic_opened {
            bail!("the elastic lane never opened under default-route load");
        }
        if self.elastic_merged == 0 {
            bail!("the elastic lane opened but never had a block merged");
        }
        Ok(())
    }
}

/// One process lifetime of a peer, for the soak export.
struct BootRecord {
    peer: usize,
    index: u32,
    start_ms: f64,
    end_ms: Option<f64>,
    ended: &'static str,
    log: Option<PathBuf>,
}

/// Kill a peer's process with `SIGKILL` and reap it.
fn kill_hard(rt: &Runtime, peer: &NetworkPeer) -> Result<()> {
    let pid = rt
        .block_on(peer.process_id())
        .ok_or_else(|| eyre!("peer {} has no process", peer.id()))?;
    let status = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .wrap_err("run kill -9")?;
    if !status.success() {
        bail!("kill -9 {pid} failed: {status}");
    }
    rt.block_on(peer.shutdown());
    Ok(())
}

#[test]
#[ignore = "long-running P2P lane soak; length from SUMERAGI_LANES_SOAK_SECS"]
fn lanes_progress_merge_and_agree_under_load_and_restarts() -> Result<()> {
    let duration = soak_duration()?;
    init_instruction_registry();
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        builder(),
        stringify!(lanes_progress_merge_and_agree_under_load_and_restarts),
    )?
    else {
        return Ok(());
    };
    let started_ms = now_ms();
    let result = soak(&network, &rt, duration, started_ms);
    rt.block_on(async { network.shutdown().await });
    result
}

fn soak(
    network: &SerializedNetwork,
    rt: &Runtime,
    duration: Duration,
    started_ms: f64,
) -> Result<()> {
    let peers = network.peers().clone();
    let mut boots: Vec<BootRecord> = (0..peers.len())
        .map(|peer| BootRecord {
            peer,
            index: 0,
            start_ms: started_ms,
            end_ms: None,
            ended: "running",
            log: None,
        })
        .collect();
    let mut windows: Vec<(f64, f64, usize)> = Vec::new();
    wait_until(
        network.sync_timeout(),
        "the network did not commit height 1",
        || Ok(min_committed_height(network)? >= 1),
    )?;
    // Register the two load accounts (global-lane transactions); two commits also take the
    // global chain past the fixed lane's activation height.
    for (account, _) in [fixed_lane_account(), elastic_lane_account()] {
        peers[0].client().submit(
            Register::account(Account::new(account)),
            FeePaymentIntent::authority(Vec::new(), None),
        )?;
    }
    wait_until(
        Duration::from_secs(90),
        "not every peer runs the fixed lane",
        || {
            Ok(running(network).iter().all(|peer| {
                peer.client()
                    .client()
                    .get_sumeragi_lanes()
                    .is_ok_and(|lanes| {
                        lanes.iter().any(|status| {
                            status.record.lane == FIXED_LANE
                                && status
                                    .instance
                                    .as_ref()
                                    .is_some_and(|instance| instance.halted.is_none())
                        })
                    })
            }))
        },
    )?;

    let stop = Arc::new(AtomicBool::new(false));
    let probes = Arc::new(Mutex::new(Vec::new()));
    let submitters = [
        Submitter::new("fixed", fixed_lane_account()),
        Submitter::new(
            "default",
            (
                iroha_test_samples::ALICE_ID.clone(),
                iroha_test_samples::ALICE_KEYPAIR.clone(),
            ),
        ),
        Submitter::new("elastic", elastic_lane_account()),
    ];
    let handles: Vec<_> = submitters
        .iter()
        .map(|submitter| submitter.spawn(peers.clone(), Arc::clone(&stop), Arc::clone(&probes)))
        .collect();

    let outcome = (|| -> Result<()> {
        let deadline = Instant::now() + duration;
        let mut progress = Progress::new(min_committed_height(network)?);
        // A fault-free window first, then cycles of one kill -9 and restart followed by two
        // windows that must each show progress.
        progress.check_after(network, deadline)?;
        let mut victim = 0usize;
        while Instant::now() + DOWNTIME + CHECK_WINDOW < deadline {
            victim = (victim + 1) % peers.len();
            let peer = &peers[victim];
            let log = peer.latest_stdout_log_path();
            let kill_ms = now_ms();
            kill_hard(rt, peer)?;
            if let Some(boot) = boots.iter_mut().rev().find(|boot| boot.peer == victim) {
                boot.end_ms = Some(kill_ms);
                boot.ended = "killed";
                boot.log = log;
            }
            thread::sleep(DOWNTIME);
            let layers: Vec<_> = network.config_layers_for_peer(peer).collect();
            let restart_begin_ms = now_ms();
            let started = rt.block_on(peer.start_checked(layers.iter(), None));
            let restart_ms = now_ms();
            windows.push((kill_ms, restart_ms, victim));
            let index = boots.iter().filter(|boot| boot.peer == victim).count();
            // A restart that fails is an exited lifetime of the peer (O-LIVE `unexpected-exit`
            // in the exported run), with the log that says why.
            let failed = started.is_err();
            boots.push(BootRecord {
                peer: victim,
                index: u32::try_from(index).unwrap_or(u32::MAX),
                start_ms: restart_begin_ms,
                end_ms: failed.then_some(restart_ms),
                ended: if failed { "exited:startup" } else { "running" },
                log: if failed {
                    peer.latest_stdout_log_path()
                } else {
                    None
                },
            });
            started?;
            for _ in 0..2 {
                if !progress.check_after(network, deadline)? {
                    break;
                }
            }
        }
        progress.require_elastic_lane()
    })();
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.join();
    }
    let result = outcome.and_then(|()| {
        for submitter in &submitters {
            if submitter.submitted.load(Ordering::Relaxed) == 0 {
                bail!("the {} load never committed a transaction", submitter.name);
            }
        }
        agree(network)
    });

    // The run is exported whether it passed or not: the node logs and the timeline are what
    // `scripts/sumeragi_soak.py --analyze` judges a failure from.
    if let Ok(out) = std::env::var(OUT_ENV) {
        for peer_index in 0..peers.len() {
            if let Some(boot) = boots
                .iter_mut()
                .rev()
                .find(|boot| boot.peer == peer_index && boot.end_ms.is_none())
            {
                boot.end_ms = Some(now_ms());
                boot.ended = "stopped";
                boot.log = peers[peer_index].latest_stdout_log_path();
            }
        }
        let load = submitters
            .iter()
            .map(|submitter| submitter.submitted.load(Ordering::Relaxed))
            .sum::<u64>();
        let attempted = load
            + submitters
                .iter()
                .map(|submitter| submitter.failed.load(Ordering::Relaxed))
                .sum::<u64>();
        let probes = probes.lock().expect("probe lock").clone();
        let exported = export(
            Path::new(&out),
            started_ms,
            &boots,
            &windows,
            &probes,
            load,
            attempted,
        );
        // The soak's own failure is the one to report when both fail.
        if let Err(error) = exported {
            return result.and(Err(error));
        }
    }
    result
}

/// Agreement: once idle, every running peer holds the same global blocks and lane records.
fn agree(network: &Network) -> Result<()> {
    let mut target = 0;
    wait_until(
        Duration::from_secs(120),
        "the peers did not converge on one height",
        || {
            let heights = running(network)
                .iter()
                .map(|peer| {
                    Ok(peer
                        .client()
                        .client()
                        .get_sumeragi_status()?
                        .committed_height)
                })
                .collect::<Result<Vec<_>>>()?;
            target = heights.iter().copied().max().unwrap_or(0);
            Ok(heights.iter().all(|height| *height == target))
        },
    )?;
    let mut reference: Option<(Vec<(u64, String)>, BTreeMap<LaneId, SumeragiLaneRecord>)> = None;
    for peer in running(network) {
        let mut headers: Vec<(u64, String)> = peer
            .client()
            .client()
            .query(FindBlockHeaders)
            .execute_all()?
            .into_iter()
            .map(|header| (header.height().get(), header.hash().to_string()))
            .filter(|(height, _)| *height <= target)
            .collect();
        headers.sort();
        let lanes = lane_records(&peer)?;
        match &reference {
            None => reference = Some((headers, lanes)),
            Some((expected_headers, expected_lanes)) => {
                if &headers != expected_headers {
                    bail!("peer {} disagrees on the global chain", peer.id());
                }
                if &lanes != expected_lanes {
                    bail!("peer {} disagrees on the lane records", peer.id());
                }
            }
        }
    }
    Ok(())
}

/// A JSON object of `entries`.
fn object(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::from(map)
}

/// Write the run in the layout of `scripts/sumeragi_soak.py` for `--analyze`.
fn export(
    out: &Path,
    started_ms: f64,
    boots: &[BootRecord],
    windows: &[(f64, f64, usize)],
    probes: &[Probe],
    submitted: u64,
    attempted: u64,
) -> Result<()> {
    let end_ms = now_ms();
    for boot in boots {
        let target = out.join("logs").join(format!("peer{}", boot.peer));
        fs::create_dir_all(&target)?;
        if let Some(log) = &boot.log {
            fs::copy(log, target.join(format!("boot{}.log", boot.index)))
                .wrap_err_with(|| format!("copy {}", log.display()))?;
        }
    }
    let peer_names = |peers: &mut dyn Iterator<Item = usize>| {
        Value::from(
            peers
                .map(|peer| Value::from(format!("peer{peer}")))
                .collect::<Vec<_>>(),
        )
    };
    let timeline = object(vec![
        ("start_ms", Value::from(started_ms)),
        ("end_ms", Value::from(end_ms)),
        ("nodes", peer_names(&mut (0..4))),
        (
            "windows",
            Value::from(
                windows
                    .iter()
                    .map(|(start, end, peer)| {
                        object(vec![
                            ("start_ms", Value::from(*start)),
                            ("end_ms", Value::from(*end)),
                            ("kind", Value::from("kill")),
                            ("nodes", peer_names(&mut std::iter::once(*peer))),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "boots",
            Value::from(
                boots
                    .iter()
                    .map(|boot| {
                        object(vec![
                            ("node", Value::from(format!("peer{}", boot.peer))),
                            ("index", Value::from(boot.index)),
                            ("start_ms", Value::from(boot.start_ms)),
                            ("end_ms", boot.end_ms.map_or(Value::Null, Value::from)),
                            ("ended", Value::from(boot.ended)),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "tolerated_exit_kinds",
            Value::from(vec![Value::from("disk")]),
        ),
    ]);
    let run = object(vec![
        (
            "source",
            Value::from("integration_tests/tests/sumeragi_lanes_soak.rs"),
        ),
        ("validators", Value::from(4u32)),
        ("faults", Value::from(vec![Value::from("kill")])),
        ("net_mode", Value::from("off")),
        ("platform", Value::from(std::env::consts::OS)),
        ("duration_s", Value::from((end_ms - started_ms) / 1000.0)),
        (
            "thresholds",
            object(vec![
                // The soak's own bound: every running peer advances in every check window. It
                // is shorter than the fault-free intervals (two windows between kills), so
                // O-LIVE can judge them.
                (
                    "live_bound_ms",
                    Value::from(u64::try_from(CHECK_WINDOW.as_millis()).unwrap_or(u64::MAX)),
                ),
                ("max_gap_p99_ms", Value::from(15_000.0)),
                ("max_gap_ms", Value::from(60_000.0)),
                ("max_latency_p99_ms", Value::from(60_000.0)),
                ("min_tps", Value::from(0.0)),
                ("warmup_heights", Value::from(5u32)),
            ]),
        ),
    ]);
    let load = object(vec![
        ("submitted", Value::from(submitted)),
        ("attempted", Value::from(attempted)),
        ("samples", Value::from(Vec::<Value>::new())),
        (
            "probes",
            Value::from(
                probes
                    .iter()
                    .map(|probe| {
                        object(vec![
                            ("start_ms", Value::from(probe.start_ms)),
                            ("end_ms", Value::from(probe.end_ms)),
                            ("ok", Value::from(probe.ok)),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    fs::create_dir_all(out)?;
    fs::write(
        out.join("timeline.json"),
        norito::json::to_json_pretty(&timeline)?,
    )?;
    fs::write(out.join("run.json"), norito::json::to_json_pretty(&run)?)?;
    fs::write(out.join("load.json"), norito::json::to_json_pretty(&load)?)?;
    Ok(())
}
