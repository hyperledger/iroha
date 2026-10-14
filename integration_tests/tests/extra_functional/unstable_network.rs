//! Adversarial relay and partition scenarios for unstable networks.
use eyre::{Result, eyre};
use futures_util::{StreamExt, stream::FuturesUnordered};
use integration_tests::sandbox;
use iroha_config::parameters::defaults;
use iroha_config_base::toml::WriteExt;
use iroha_core::sumeragi::network_topology::Topology;
use iroha_crypto::Hash;
use iroha_data_model::{
    Level, asset::AssetDefinition, block::consensus::is_valid_committee_size, isi::Register,
    parameter::BlockParameter, prelude::*,
};
use iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_primitives::addr::socket_addr;
use iroha_test_network::{BlockHeight, Network, NetworkBuilder, NetworkPeer, once_blocks_sync};
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use rand::{SeedableRng, prelude::IteratorRandom};
use rand_chacha::ChaCha8Rng;
use relay::P2pRelay;
use std::{
    any::Any,
    borrow::Cow,
    collections::{HashMap, HashSet},
    panic::{self, AssertUnwindSafe},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    self,
    task::spawn_blocking,
    time::{sleep, timeout},
};
use toml::{Table, Value as TomlValue};
mod relay {
    //! Utilities to build a peer-to-peer network relay using TCP proxies with ability to targetly
    //! suspend communication.
    //!
    //! For each peer-to-peer pair, [`P2pRelay`] reserves a port and starts a TCP listener on it. This
    //! listener is sipmly forwarding packages, but also provides a toggle to suspend the
    //! forwarding. Peers' `trusted_peers` configuration must be set up to use the relay's proxies
    //! and not directly the other peers.
    //!
    //! First, create [`P2pRelay`] with the given _real topology_ (a set of peers'
    //! real network addresses and public keys), by [`P2pRelay::new`] or [`P2pRelay::for_network`].
    //! Then, start each peer, setting `trusted_peers` config parameter with the _virtual topology_ provided by
    //! the relay ([`P2pRelay::trusted_peers_for`]). Then, start the relay itself ([`P2pRelay::start`]).
    //!
    //! It is possible to "suspend" a particular peer in the network by suspending all incoming/outgoing packages from/to other peers.
    //! Relay provides [`P2pRelay::suspend`] to acquire a [`Suspend`] control (per-peer), which provides
    //! [`Suspend::activate`] and [`Suspend::deactivate`] in turn.
    use futures_util::{StreamExt, stream::FuturesUnordered};
    use iroha_data_model::prelude::Peer;
    use iroha_model_base::peer::PeerId;
    use iroha_primitives::{
        addr::{SocketAddr, socket_addr},
        unique_vec::UniqueVec,
    };
    use iroha_test_network::{Network, fslock_ports::AllocatedPort};
    use std::{
        collections::HashMap,
        iter::once,
        net::TcpListener as StdTcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        select,
        sync::Notify,
        task::JoinSet,
    };
    use tracing::{Instrument, Level};
    #[derive(Debug)]
    pub struct P2pRelay {
        peers: HashMap<PeerId, RelayPeer>,
        tasks: JoinSet<()>,
    }
    #[derive(Debug)]
    struct RelayPeer {
        real_addr: SocketAddr,
        /// Map of proxied destinations. Key is a peer id of
        mock_outgoing: HashMap<PeerId, (SocketAddr, AllocatedPort)>,
        suspend: Suspend,
    }
    impl P2pRelay {
        /// Construct a relay with the given topology.
        pub fn new(real_topology: &UniqueVec<Peer>) -> Self {
            let peers: HashMap<_, _> = real_topology
                .iter()
                .map(|peer| {
                    let id = peer.id();
                    let real_addr = peer.address().clone();
                    let mock_outgoing = real_topology
                        .iter()
                        .map(iroha_data_model::peer::Peer::id)
                        .filter(|x| *x != id)
                        .map(|other_id| {
                            let mock_port = AllocatedPort::new();
                            let mock_addr = socket_addr!(127.0.0.1:*mock_port);
                            (other_id.clone(), (mock_addr, mock_port))
                        })
                        .collect();
                    let relay_peer = RelayPeer {
                        real_addr,
                        mock_outgoing,
                        suspend: Suspend::new(),
                    };
                    (id.clone(), relay_peer)
                })
                .collect();
            let mut table = ascii_table::AsciiTable::default();
            table.set_max_width(ascii_table::Width::Fixed(30 * (1 + real_topology.len())));
            table.column(0).set_header("From");
            for (i, id) in real_topology.iter().enumerate() {
                table
                    .column(i + 1)
                    .set_header(format!("To {}", id.address()));
            }
            let rows: Vec<Vec<String>> = real_topology
                .iter()
                .map(|peer| {
                    once(format!("{}", peer.address()))
                        .chain(real_topology.iter().map(|other_peer| {
                            if other_peer.id() == peer.id() {
                                String::new()
                            } else {
                                let (mock_addr, _) = peers
                                    .get(peer.id())
                                    .unwrap()
                                    .mock_outgoing
                                    .get(other_peer.id())
                                    .unwrap();
                                format!("{mock_addr}")
                            }
                        }))
                        .collect::<Vec<_>>()
                })
                .collect();
            let mut table_buf = Vec::new();
            table
                .writeln(&mut table_buf, &rows)
                .expect("writing ascii table should succeed");
            let table_formatted = String::from_utf8(table_buf)
                .unwrap_or_else(|_| "<table render failed>".to_string());
            iroha_logger::debug!("TCP relay table:\n{table_formatted}");
            Self {
                peers,
                tasks: <_>::default(),
            }
        }
        /// Construct a relay using the given network's peers as topology.
        pub fn for_network(network: &Network) -> Self {
            Self::new(
                &network
                    .peers()
                    .iter()
                    .map(|peer| Peer::new(peer.p2p_address(), peer.id()))
                    .collect(),
            )
        }
        /// Get trusted peers for a particular peer in the given topology.
        ///
        /// The relay constructs "virtual" set of addresses of other peers for each peer. This must
        /// be passed to the peer's configuration.
        pub fn trusted_peers_for(&self, peer: &PeerId) -> UniqueVec<Peer> {
            let peer_info = self
                .peers
                .get(peer)
                .expect("existing peer must be supplied");
            peer_info
                .mock_outgoing
                .iter()
                .map(|(other, (addr, _port))| Peer::new(addr.clone(), other.clone()))
                .chain(Some(Peer::new(peer_info.real_addr.clone(), peer.clone())))
                .collect()
        }
        /// Start the relay, i.e. the set of TCP proxies between the peers.
        pub fn start(&mut self) -> eyre::Result<()> {
            let mut proxy_specs = Vec::new();
            for peer in self.peers.values() {
                for (other, (other_mock_addr, _)) in &peer.mock_outgoing {
                    let other_peer = self.peers.get(other).expect("must be present");
                    let suspend =
                        SuspendIfAny(vec![peer.suspend.clone(), other_peer.suspend.clone()]);
                    proxy_specs.push((
                        other_mock_addr.clone(),
                        other_peer.real_addr.clone(),
                        suspend,
                    ));
                }
            }
            // Bind every proxy before spawning any accept loop. This makes `start` a readiness
            // barrier: once it returns, the kernel can queue connections for every virtual peer
            // address, even if the spawned tasks have not yet been polled.
            let mut ready = Vec::with_capacity(proxy_specs.len());
            for (from, to, suspend) in proxy_specs {
                let listener = StdTcpListener::bind(from.to_string())?;
                listener.set_nonblocking(true)?;
                let listener = TcpListener::from_std(listener)?;
                ready.push((listener, from, to, suspend));
            }
            for (listener, from, to, suspend) in ready {
                P2pRelay::run_proxy(&mut self.tasks, listener, from, to, suspend);
            }
            Ok(())
        }
        fn run_proxy(
            tasks: &mut JoinSet<()>,
            listener: TcpListener,
            from: SocketAddr,
            to: SocketAddr,
            suspend: SuspendIfAny,
        ) {
            let span = tracing::span!(Level::INFO, "proxy_run", from = %from, to = %to);
            let mut proxy = Proxy::new(listener, from, to, suspend);
            tasks.spawn(
                async move {
                    if let Err(err) = proxy.run().await {
                        iroha_logger::error!("proxy at {} exited with an error: {err}", proxy.from);
                    } else {
                        iroha_logger::info!("proxy exited normally");
                    }
                }
                .instrument(span),
            );
        }
        /// Acquire a [`Suspend`] control for a peer
        pub fn suspend(&self, peer: &PeerId) -> Suspend {
            self.peers
                .get(peer)
                .expect("must be present")
                .suspend
                .clone()
        }
    }
    #[derive(Clone, Debug)]
    pub struct Suspend {
        active: Arc<AtomicBool>,
        notify: Arc<Notify>,
    }
    impl Suspend {
        fn new() -> Self {
            Self {
                active: <_>::default(),
                notify: <_>::default(),
            }
        }
        pub fn activate(&self) {
            self.active.store(true, Ordering::Release);
        }
        pub fn deactivate(&self) {
            self.active.store(false, Ordering::Release);
            self.notify.notify_waiters();
        }
    }
    #[derive(Clone, Debug)]
    struct SuspendIfAny(Vec<Suspend>);
    impl SuspendIfAny {
        async fn is_not_active(&self) {
            loop {
                let waited_for = self
                    .0
                    .iter()
                    .filter_map(|x| {
                        x.active
                            .load(Ordering::Acquire)
                            .then_some(x.notify.notified())
                    })
                    .collect::<FuturesUnordered<_>>()
                    .collect::<Vec<_>>()
                    .await
                    .len();
                if waited_for == 0 {
                    break;
                }
            }
        }
    }
    struct Proxy {
        listener: TcpListener,
        from: SocketAddr,
        to: SocketAddr,
        suspend: SuspendIfAny,
    }
    impl Proxy {
        fn new(
            listener: TcpListener,
            from: SocketAddr,
            to: SocketAddr,
            suspend: SuspendIfAny,
        ) -> Self {
            Self {
                listener,
                from,
                to,
                suspend,
            }
        }
        async fn run(&mut self) -> eyre::Result<()> {
            loop {
                let (client, _) = self.listener.accept().await?;
                let server = match TcpStream::connect(self.to.to_string()).await {
                    Ok(server) => server,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            from = %self.from,
                            to = %self.to,
                            "proxy connect failed; dropping client"
                        );
                        continue;
                    }
                };
                let (mut eread, mut ewrite) = client.into_split();
                let (mut oread, mut owrite) = server.into_split();
                let suspend = self.suspend.clone();
                let mut e2o =
                    tokio::spawn(
                        async move { Proxy::copy(&suspend, &mut eread, &mut owrite).await },
                    );
                let suspend = self.suspend.clone();
                let mut o2e =
                    tokio::spawn(
                        async move { Proxy::copy(&suspend, &mut oread, &mut ewrite).await },
                    );
                select! {
                    _ = &mut e2o => {
                        o2e.abort();
                        let _ = o2e.await;
                    },
                    _ = &mut o2e => {
                        e2o.abort();
                        let _ = e2o.await;
                    },
                }
            }
        }
        async fn copy<R, W>(
            suspend: &SuspendIfAny,
            mut reader: R,
            mut writer: W,
        ) -> std::io::Result<()>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            // NOTE: quite large to allocate on stack, causing overflow
            let mut buf = vec![0u8; 2usize.pow(20)];
            loop {
                suspend.is_not_active().await;
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n]).await?;
            }
            Ok(())
        }
    }
}
#[derive(Default)]
enum GenesisPeer {
    #[default]
    Whichever,
    Nth(usize),
}
fn scaled_timeout(base: Duration, peer_count: usize) -> Duration {
    let scale = ((peer_count + 3) / 4).max(1) as u32;
    base.saturating_mul(scale)
}
fn non_faulty_sync_timeout(
    sync_timeout: Duration,
    pipeline_time: Duration,
    faulty_peers: usize,
) -> Duration {
    if faulty_peers == 0 {
        return sync_timeout;
    }
    // Keep relay partitions within the Sumeragi liveness windows so fault injection does not span
    // unnecessary view rotations.
    let cap = if faulty_peers > 1 {
        pipeline_time
            .saturating_mul(2)
            .saturating_add(Duration::from_secs(2))
    } else {
        // One faulty validator is within quorum tolerance. Allow one absolute round timeout
        // for a faulty leader to rotate, followed by one normal pipeline window to finalize.
        pipeline_time
            .saturating_mul(defaults::sumeragi::ROUND_TIMEOUT_CADENCE_MULTIPLIER)
            .saturating_add(pipeline_time)
            .saturating_add(Duration::from_secs(2))
    };
    sync_timeout.min(cap)
}
fn submit_retry_backoff(attempt: usize) -> Duration {
    let step = Duration::from_millis(200);
    let scaled = step.saturating_mul(u32::try_from(attempt).unwrap_or(u32::MAX));
    scaled.min(Duration::from_secs(2))
}
fn initial_resubmit_delay(sync_timeout: Duration, pipeline_time: Duration) -> Duration {
    let early = pipeline_time.saturating_mul(4);
    let half = sync_timeout.checked_div(2).unwrap_or(sync_timeout);
    early.min(half)
}
fn recovered_submit_window(sync_timeout: Duration, pipeline_time: Duration) -> Duration {
    pipeline_time
        .saturating_mul(2)
        .max(Duration::from_secs(5))
        .min(sync_timeout)
}
fn stagger_recovery_gap(pipeline_time: Duration) -> Duration {
    pipeline_time
        .checked_div(2)
        .unwrap_or(Duration::from_secs(1))
        .max(Duration::from_secs(1))
}
fn should_resubmit_tx(allow_resubmit: bool, now: Instant, next_resubmit_at: Instant) -> bool {
    allow_resubmit && now >= next_resubmit_at
}
fn is_submission_accepted_duplicate(err: &eyre::Report) -> bool {
    err.chain().any(|cause| {
        let text = cause.to_string();
        text.contains("ALREADY_ENQUEUED")
            || text.contains("ALREADY_COMMITTED")
            || text.to_ascii_lowercase().contains("already committed")
    })
}
fn allow_supply_resubmit(faulty_peers: usize) -> bool {
    faulty_peers > 0
}
fn allow_round_supply_deadline_slip(faulty_peers: usize) -> bool {
    // Under partitioned rounds, transaction dissemination can lag one round behind while
    // still converging globally; defer strictness to the final supply assertion.
    faulty_peers > 0
}
fn permissioned_prf_seed(chain_id: &ChainId) -> [u8; 32] {
    let hash = Hash::new(chain_id.as_str().as_bytes());
    <[u8; 32]>::from(hash)
}
fn topology_for_permissioned_round(
    peer_ids: &[PeerId],
    chain_id: &ChainId,
    height: u64,
    view: u64,
) -> Vec<PeerId> {
    let mut ordered = peer_ids.to_vec();
    ordered.sort();
    ordered.dedup();
    let mut topology = Topology::new(ordered);
    topology.shuffle_prf(permissioned_prf_seed(chain_id), height);
    topology.nth_rotation(view);
    topology.into_iter().collect()
}
async fn start_network_under_relay(
    network: &Network,
    relay: &P2pRelay,
    genesis_peer: GenesisPeer,
) -> Result<()> {
    // Callers already hold the serial guard via SerializedNetwork.
    // Iroha refuses to start on empty storage without a genesis file, so hand the
    // canonical genesis block to every peer up front.
    let genesis_block = network.genesis();
    let mut pops_by_peer_id = HashMap::new();
    for peer in network.peers() {
        let pop = peer.bls_pop().expect("network peers should have BLS PoPs");
        pops_by_peer_id.insert(peer.id(), pop.to_vec());
    }
    let designated_genesis_index = match genesis_peer {
        GenesisPeer::Whichever => 0,
        GenesisPeer::Nth(n) => n,
    };
    if designated_genesis_index >= network.peers().len() {
        return Err(eyre!(
            "designated genesis peer index {designated_genesis_index} out of range for {} peers",
            network.peers().len()
        ));
    }
    // Start the designated genesis peer first, then the remaining peers. A small stagger reduces
    // thundering-herd effects and makes genesis submission ordering more deterministic.
    let mut start_order: Vec<usize> = (0..network.peers().len()).collect();
    start_order.retain(|&idx| idx != designated_genesis_index);
    start_order.insert(0, designated_genesis_index);
    let start_stage_by_index: HashMap<usize, usize> = start_order
        .into_iter()
        .enumerate()
        .map(|(stage, idx)| (idx, stage))
        .collect();
    let startup_timeout = scaled_timeout(network.peer_startup_timeout(), network.peers().len());
    let start_results = match timeout(
        startup_timeout,
        network
            .peers()
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                let start_stage = start_stage_by_index.get(&i).copied().unwrap_or(i);
                let trusted_peers = relay.trusted_peers_for(&peer.id());
                let trusted_peers_list = trusted_peers
                    .iter()
                    .map(|peer| peer.to_string())
                    .collect::<Vec<_>>();
                let mut trusted_peers_pop = Vec::new();
                let mut seen = HashSet::new();
                for trusted in trusted_peers.iter() {
                    let peer_id = trusted.id();
                    if !seen.insert(peer_id.clone()) {
                        continue;
                    }
                    let pop = pops_by_peer_id.get(peer_id).unwrap_or_else(|| {
                        panic!("missing PoP for trusted peer {}", peer_id.public_key())
                    });
                    let mut pop_entry = Table::new();
                    pop_entry.insert(
                        "public_key".into(),
                        TomlValue::String(peer_id.public_key().to_string()),
                    );
                    pop_entry.insert(
                        "pop_hex".into(),
                        TomlValue::String(format!("0x{}", hex::encode(pop))),
                    );
                    trusted_peers_pop.push(TomlValue::Table(pop_entry));
                }
                let config = network.config_layers().chain(Some(Cow::Owned(
                    Table::new()
                        .write(["trusted_peers"], trusted_peers_list)
                        .write(["trusted_peers_pop"], TomlValue::Array(trusted_peers_pop))
                        // We don't want peers to gossip any actual addresses, because each peer has
                        // its own set of incoming and outgoing proxies with every other peer.
                        // Thus, we are giving this addr which should always reject connections and
                        // peers should rely on what they got in the `sumeragi.trusted_peers`.
                        .write(
                            ["network", "public_address"],
                            // This IP is in the range of IPs reserved for "documentation and examples"
                            // https://en.wikipedia.org/wiki/Reserved_IP_addresses#:~:text=192.0.2.0/24
                            socket_addr!(192.0.2.133:1337).to_literal(),
                        ),
                )));
                let genesis = Some(genesis_block.clone());
                async move {
                    if start_stage > 0 {
                        let delay = Duration::from_millis(200)
                            .checked_mul(start_stage as u32)
                            .unwrap_or(Duration::from_secs(u64::MAX));
                        if delay > Duration::ZERO {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    peer.start_checked(config, genesis.as_ref()).await
                }
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>(),
    )
    .await
    {
        Ok(results) => results,
        Err(_) => {
            let snapshot = network.startup_snapshot();
            return Err(eyre!(
                "expected peers to start within timeout ({startup_timeout:?}); startup snapshot: [{}]",
                snapshot
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    };
    for result in start_results {
        result?;
    }
    network.ensure_blocks(1).await?;
    Ok(())
}
async fn wait_for_full_peer_connectivity(network: &Network, wait_timeout: Duration) -> Result<()> {
    let expected = u64::try_from(network.peers().len().saturating_sub(1))
        .expect("test-network peer count should fit into u64");
    let deadline = Instant::now() + wait_timeout;
    loop {
        let mut all_ready = true;
        let mut snapshot = Vec::with_capacity(network.peers().len());
        for peer in network.peers() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                all_ready = false;
                snapshot.push(format!("{}: deadline elapsed", peer.mnemonic()));
                break;
            }
            match timeout(remaining.min(Duration::from_secs(5)), peer.status()).await {
                Ok(Ok(status)) => {
                    all_ready &= status.peers >= expected;
                    snapshot.push(format!("{}: peers={}", peer.mnemonic(), status.peers));
                }
                Ok(Err(err)) => {
                    all_ready = false;
                    snapshot.push(format!("{}: status error: {err:?}", peer.mnemonic()));
                }
                Err(_) => {
                    all_ready = false;
                    snapshot.push(format!("{}: status timed out", peer.mnemonic()));
                }
            }
        }
        if all_ready && snapshot.len() == network.peers().len() {
            iroha_logger::info!(
                expected_remote_peers = expected,
                snapshot = ?snapshot,
                "relay network reached full peer connectivity"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "relay network did not reach {expected} remote peers on every node within {wait_timeout:?}; last snapshot: [{}]",
                snapshot.join(", ")
            ));
        }
        sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250)),
        )
        .await;
    }
}
fn panic_reason(panic: &(dyn Any + Send)) -> Option<String> {
    panic
        .downcast_ref::<&str>()
        .map(std::string::ToString::to_string)
        .or_else(|| panic.downcast_ref::<String>().cloned())
}
fn is_sandbox_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("permission denied") || lower.contains("operation not permitted")
}
#[allow(clippy::unnecessary_wraps)]
fn run_or_skip_on_sandbox_panic<T, F>(context: &str, build: F) -> Result<Option<T>>
where
    F: FnOnce() -> T,
{
    match panic::catch_unwind(AssertUnwindSafe(build)) {
        Ok(value) => Ok(Some(value)),
        Err(panic) => {
            if let Some(reason) = panic_reason(panic.as_ref())
                && is_sandbox_message(&reason)
            {
                eprintln!(
                    "sandboxed network restriction detected while running {context}; skipping network startup ({reason})"
                );
                return Ok(None);
            }
            panic::resume_unwind(panic);
        }
    }
}
#[test]
fn sandbox_panic_skips_network_build() -> Result<()> {
    let result = run_or_skip_on_sandbox_panic("sandbox_panic_skips_network_build", || -> usize {
        panic!("operation not permitted");
    })?;
    assert!(result.is_none());
    Ok(())
}
#[test]
fn non_sandbox_panic_is_propagated() {
    let result = panic::catch_unwind(|| {
        let _ = run_or_skip_on_sandbox_panic("non_sandbox_panic_is_propagated", || -> usize {
            panic!("boom");
        });
    });
    assert!(result.is_err());
}
#[tokio::test]
async fn network_starts_with_relay() -> Result<()> {
    let Some((network, mut relay)) =
        run_or_skip_on_sandbox_panic(stringify!(network_starts_with_relay), || {
            let guard = sandbox::serial_guard();
            let network = NetworkBuilder::new()
                .with_auto_populated_trusted_peers()
                .with_peers(4)
                .build();
            let network = sandbox::SerializedNetwork::new(network, guard);
            let relay = P2pRelay::for_network(&network);
            (network, relay)
        })?
    else {
        return Ok(());
    };
    relay.start()?;
    if sandbox::handle_result(
        start_network_under_relay(&network, &relay, GenesisPeer::Whichever).await,
        stringify!(network_starts_with_relay),
    )?
    .is_none()
    {
        return Ok(());
    }
    let status_deadline = Instant::now() + network.peer_startup_timeout();
    loop {
        match network.peer().status().await {
            Ok(_) => break,
            Err(err) => {
                if Instant::now() >= status_deadline {
                    return Err(err.wrap_err("network_starts_with_relay torii not ready"));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let client = network
        .peers()
        .iter()
        .min_by(|left, right| left.id().cmp(&right.id()))
        .expect("relay network should have at least one peer")
        .client();
    if sandbox::handle_result(
        network.ensure_blocks(1).await,
        stringify!(network_starts_with_relay),
    )?
    .is_none()
    {
        return Ok(());
    }
    spawn_blocking(move || {
        client.submit(
            Log::new(Level::INFO, "relay started".to_owned()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await??;
    timeout(
        network.sync_timeout(),
        once_blocks_sync(network.peers().iter(), BlockHeight::predicate_non_empty(2)),
    )
    .await??;
    Ok(())
}
#[tokio::test]
async fn network_doesnt_start_without_relay_being_started() -> Result<()> {
    let Some((network, relay)) = run_or_skip_on_sandbox_panic(
        stringify!(network_doesnt_start_without_relay_being_started),
        || {
            let guard = sandbox::serial_guard();
            let network = NetworkBuilder::new()
                .with_auto_populated_trusted_peers()
                .with_peers(4)
                .build();
            let network = sandbox::SerializedNetwork::new(network, guard);
            let relay = P2pRelay::for_network(&network);
            (network, relay)
        },
    )?
    else {
        return Ok(());
    };
    if sandbox::handle_result(
        start_network_under_relay(&network, &relay, GenesisPeer::Whichever).await,
        stringify!(network_doesnt_start_without_relay_being_started),
    )?
    .is_none()
    {
        return Ok(());
    }
    let client = network.client();
    spawn_blocking(move || {
        client.submit(
            Log::new(Level::INFO, "relay stalled".to_owned()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await??;
    let Err(_) = timeout(
        Duration::from_secs(3),
        once_blocks_sync(network.peers().iter(), BlockHeight::predicate_non_empty(2)),
    )
    .await
    else {
        panic!("network must not start!")
    };
    Ok(())
}
#[tokio::test]
async fn suspending_works() -> Result<()> {
    const N_PEERS: usize = 4;
    const { assert!(N_PEERS > 0) };
    let Some((network, mut relay)) =
        run_or_skip_on_sandbox_panic(stringify!(suspending_works), || {
            let guard = sandbox::serial_guard();
            let network = NetworkBuilder::new()
                .with_auto_populated_trusted_peers()
                .with_peers(N_PEERS)
                .build();
            let network = sandbox::SerializedNetwork::new(network, guard);
            let relay = P2pRelay::for_network(&network);
            (network, relay)
        })?
    else {
        return Ok(());
    };
    let sync_timeout = network.sync_timeout();
    let sync_probe = network.block_cadence() + Duration::from_secs(3);
    // we will plug/unplug the last peer to simulate a short partition
    let last_peer = network
        .peers()
        .last()
        .expect("there are more than 0 of them");
    let suspend = relay.suspend(&last_peer.id());
    suspend.activate();
    relay.start()?;
    if sandbox::handle_result(
        start_network_under_relay(&network, &relay, GenesisPeer::Whichever).await,
        stringify!(suspending_works),
    )?
    .is_none()
    {
        return Ok(());
    }
    let client = network.client();
    spawn_blocking(move || {
        client.submit(
            Log::new(Level::INFO, "suspend tick".to_owned()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await??;
    // all peers except the last one should get the non-empty block
    timeout(
        sync_timeout,
        once_blocks_sync(
            network.peers().iter().take(N_PEERS - 1),
            BlockHeight::predicate_non_empty(2),
        ),
    )
    .await??;
    if timeout(
        sync_probe,
        last_peer.once_block_with(BlockHeight::predicate_non_empty(2)),
    )
    .await
    .is_ok()
    {
        return Err(eyre!("suspending_works: peer caught up while suspended"));
    }
    // unsuspend, the last peer should get the block too
    suspend.deactivate();
    timeout(
        sync_timeout,
        last_peer.once_block_with(BlockHeight::predicate_non_empty(2)),
    )
    .await
    .map_err(|_| eyre!("suspending_works: timed out waiting for peer to catch up"))?;
    Ok(())
}
#[tokio::test]
async fn block_after_genesis_is_synced() -> Result<()> {
    // A consensus anomaly occurred deterministically depending on the peer set
    // (how public keys of different peers are sorted to each other, which determines consensus
    // roles) and which peer submits the genesis. The values below are an experimentally found
    // case.
    const SEED: &str = "we want a determined order of peers";
    const GENESIS_PEER_INDEX: usize = 3;
    let Some((network, mut relay)) =
        run_or_skip_on_sandbox_panic(stringify!(block_after_genesis_is_synced), || {
            let guard = sandbox::serial_guard();
            let network = NetworkBuilder::new()
                .with_base_seed(SEED)
                .with_peers(7)
                // Align test timing with the new consensus pipeline (3s block, 6s commit).
                .with_block_cadence(Duration::from_secs(9))
                .build();
            let network = sandbox::SerializedNetwork::new(network, guard);
            let relay = P2pRelay::for_network(&network);
            (network, relay)
        })?
    else {
        return Ok(());
    };
    let pipeline_window = network.block_cadence() + Duration::from_secs(3);
    let sync_timeout = scaled_timeout(network.sync_timeout(), network.peers().len());
    relay.start()?;
    if sandbox::handle_result(
        start_network_under_relay(&network, &relay, GenesisPeer::Nth(GENESIS_PEER_INDEX)).await,
        stringify!(block_after_genesis_is_synced),
    )?
    .is_none()
    {
        return Ok(());
    }
    network.ensure_blocks(1).await?;
    for peer in network.peers() {
        relay.suspend(&peer.id()).activate();
    }
    let client = network.client();
    spawn_blocking(move || {
        client.submit(
            Log::new(Level::INFO, "tick".to_owned()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await??;
    let Err(_) = timeout(
        pipeline_window,
        once_blocks_sync(network.peers().iter(), BlockHeight::predicate_non_empty(2)),
    )
    .await
    else {
        panic!("should not sync with relay being suspended")
    };
    for peer in network.peers() {
        relay.suspend(&peer.id()).deactivate();
    }
    // Allow enough time for a full pipeline (propose+commit) after resuming the relay.
    // Using the broader sync timeout keeps the assertion tolerant of slower machines
    // and scenarios where consensus gating adds a little extra latency.
    timeout(
        sync_timeout,
        once_blocks_sync(network.peers().iter(), BlockHeight::predicate_non_empty(2)),
    )
    .await??;
    Ok(())
}
// ======= ACTUAL TESTS BEGIN HERE =======
struct UnstableNetwork {
    n_peers: usize,
    n_faulty_peers: usize,
    n_rounds: usize,
}
impl UnstableNetwork {
    async fn run(self) -> Result<()> {
        if !is_valid_committee_size(self.n_peers) {
            return Err(eyre!(
                "expected an exact revision-4 3f + 1 committee in 4..=31, got {} peers",
                self.n_peers
            ));
        }
        if self.n_peers <= self.n_faulty_peers {
            return Err(eyre!(
                "expected more peers than faulty peers (peers={}, faulty={})",
                self.n_peers,
                self.n_faulty_peers
            ));
        }
        let commit_quorum = iroha_sumeragi::types::quorum(self.n_peers);
        let fault_budget = Self::fault_budget_for_peer_count(self.n_peers);
        if self.n_faulty_peers > fault_budget {
            return Err(eyre!(
                "faulty peers ({}) exceed commit quorum budget ({}) for {} peers (commit quorum {})",
                self.n_faulty_peers,
                fault_budget,
                self.n_peers,
                commit_quorum
            ));
        }
        let account_id = ALICE_ID.clone();
        let asset_owning_domain = DomainId::try_new("wonderland", "universal").expect("Valid");
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            asset_owning_domain.clone(),
            "unstable".parse().expect("Valid"),
        );
        let Some((network, mut relay)) =
            run_or_skip_on_sandbox_panic("unstable_network::run", || {
                let guard = sandbox::serial_guard();
                let network = self.build_network(&asset_definition_id);
                let network = sandbox::SerializedNetwork::new(network, guard);
                let relay = P2pRelay::for_network(&network);
                (network, relay)
            })?
        else {
            return Ok(());
        };
        relay.start()?;
        let start_result =
            start_network_under_relay(&network, &relay, GenesisPeer::Whichever).await;
        if sandbox::handle_result(start_result, "unstable_network::run")?.is_none() {
            return Ok(());
        }
        wait_for_full_peer_connectivity(
            &network,
            scaled_timeout(network.sync_timeout(), network.peers().len()),
        )
        .await?;
        let init_blocks = 1;
        let preexisting_faulty_ids =
            Self::wait_for_initial_sync_budget(&network, init_blocks, self.n_faulty_peers).await?;
        let peers = network.peers();
        let initial_non_empty = peers
            .iter()
            .filter_map(|peer| peer.best_effort_block_height())
            .map(|height| height.non_empty)
            .max()
            .unwrap_or(0);
        let round_ctx = RoundContext {
            initial_non_empty,
            asset_definition_id: &asset_definition_id,
            account_id: &account_id,
        };
        for i in 0..self.n_rounds {
            self.execute_round(
                i,
                &round_ctx,
                &network,
                &mut relay,
                peers.as_slice(),
                &preexisting_faulty_ids,
            )
            .await?;
        }
        let expected_height =
            round_ctx.initial_non_empty + u64::try_from(self.n_rounds).unwrap_or(0);
        Self::assert_total_supply(
            &network,
            &asset_definition_id,
            self.n_rounds,
            expected_height,
        )
        .await?;
        Ok(())
    }
    fn fault_budget_for_peer_count(peer_count: usize) -> usize {
        peer_count.saturating_sub(iroha_sumeragi::types::quorum(peer_count))
    }
    fn fault_round_seed(round_index: usize, n_faulty_peers: usize, fault_budget: usize) -> usize {
        if n_faulty_peers >= fault_budget {
            0
        } else {
            round_index
        }
    }
    fn select_faulty_peer_ids(
        peer_ids: &[PeerId],
        n_faulty_peers: usize,
        round_index: usize,
        chain_id: &ChainId,
        height: u64,
        preferred_faulty_ids: &HashSet<PeerId>,
    ) -> Vec<PeerId> {
        if n_faulty_peers == 0 {
            return Vec::new();
        }
        let rotated = topology_for_permissioned_round(peer_ids, chain_id, height, 0);
        let commit_quorum = iroha_sumeragi::types::quorum(rotated.len());
        let leader_id = rotated.first();
        let is_safe_fault = |peer: &PeerId| leader_id.is_none_or(|leader| leader != peer);
        let mut candidates = Vec::new();
        let mut candidate_seen = HashSet::new();
        if let Some(tail) = rotated.get(commit_quorum..) {
            for peer in tail.iter().filter(|peer| is_safe_fault(peer)) {
                if candidate_seen.insert(peer.clone()) {
                    candidates.push(peer.clone());
                }
            }
        }
        let head = rotated.iter().skip(1).take(commit_quorum.saturating_sub(1));
        for peer in head.filter(|peer| is_safe_fault(peer)) {
            if candidate_seen.insert(peer.clone()) {
                candidates.push(peer.clone());
            }
        }
        if candidates.len() < n_faulty_peers {
            for peer in rotated.iter().skip(1) {
                if candidate_seen.insert(peer.clone()) {
                    candidates.push(peer.clone());
                }
            }
        }
        let mut selected = Vec::new();
        let mut seen = HashSet::new();
        for peer in rotated
            .iter()
            .filter(|peer| preferred_faulty_ids.contains(*peer))
            .filter(|peer| is_safe_fault(peer))
        {
            if selected.len() == n_faulty_peers {
                break;
            }
            if seen.insert(peer.clone()) {
                selected.push(peer.clone());
            }
        }
        if selected.len() == n_faulty_peers {
            return selected;
        }
        let mut rng =
            ChaCha8Rng::seed_from_u64(0x5553_5442 + u64::try_from(round_index).unwrap_or(0));
        let remaining = n_faulty_peers.saturating_sub(selected.len());
        selected.extend(
            candidates
                .iter()
                .filter(|peer| !seen.contains(*peer))
                .choose_multiple(&mut rng, remaining)
                .into_iter()
                .cloned(),
        );
        selected
    }
    fn build_network(&self, asset_definition_id: &AssetDefinitionId) -> Network {
        let builder = NetworkBuilder::new()
            .with_auto_populated_trusted_peers()
            .with_peers(self.n_peers)
            .with_default_block_cadence()
            // Slow gossip slightly so the relay toggles mirror the higher RTT budget of
            // the default consensus pipeline.
            .with_block_sync_gossip_period(Duration::from_millis(400))
            .with_config_layer(|cfg| {
                // Keep handshake PoW enabled while reducing its Argon2 work to the supported
                // minimum. This test targets consensus partitions, not handshake-puzzle cost.
                cfg.write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                );
            })
            .with_genesis_instruction(SetParameter::new(Parameter::Block(
                BlockParameter::MaxTransactions(nonzero!(1u64)),
            )))
            .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id.clone(),
                "unstable".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )))
            .with_genesis_instruction(Grant::account_permission(
                CanMintAssetWithDefinition {
                    asset_definition: asset_definition_id.clone(),
                },
                ALICE_ID.clone(),
            ));
        builder.build()
    }
    async fn wait_for_initial_sync_budget(
        network: &Network,
        target_height: u64,
        fault_budget: usize,
    ) -> Result<HashSet<PeerId>> {
        let deadline =
            Instant::now() + scaled_timeout(network.sync_timeout(), network.peers().len());
        let running_count = network
            .peers()
            .iter()
            .filter(|peer| peer.is_running())
            .count();
        let commit_quorum = iroha_sumeragi::types::quorum(running_count);
        let mut last_ready = 0usize;
        let mut last_lagging = Vec::new();
        loop {
            let mut ready = 0usize;
            let mut lagging = Vec::new();
            for peer in network.peers().iter().filter(|peer| peer.is_running()) {
                let non_empty = match peer.status().await {
                    Ok(status) => BlockHeight::from(status).non_empty,
                    Err(_) => peer
                        .best_effort_block_height()
                        .map(|height| height.non_empty)
                        .unwrap_or(0),
                };
                if non_empty >= target_height {
                    ready += 1;
                } else {
                    lagging.push((peer.id().clone(), peer.mnemonic().to_owned(), non_empty));
                }
            }
            if lagging.is_empty() {
                return Ok(HashSet::new());
            }
            if lagging.len() <= fault_budget && ready >= commit_quorum {
                iroha_logger::warn!(
                    target_height,
                    ready,
                    commit_quorum,
                    lagging = ?lagging
                        .iter()
                        .map(|(_, mnemonic, non_empty)| (mnemonic.clone(), *non_empty))
                        .collect::<Vec<_>>(),
                    "initial network sync left lagging peers within configured fault budget; carrying them into round fault selection"
                );
                return Ok(lagging.into_iter().map(|(peer_id, _, _)| peer_id).collect());
            }
            if Instant::now() >= deadline {
                let lagging_snapshot = last_lagging
                    .iter()
                    .map(|(mnemonic, non_empty)| format!("{mnemonic}@{non_empty}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(eyre!(
                    "initial network sync did not reach height {target_height}; ready peers: {last_ready}/{running_count}, lagging peers: [{lagging_snapshot}]"
                ));
            }
            last_ready = ready;
            last_lagging = lagging
                .iter()
                .map(|(_, mnemonic, non_empty)| (mnemonic.clone(), *non_empty))
                .collect();
            sleep(Duration::from_millis(200)).await;
        }
    }
    async fn execute_round(
        &self,
        round_index: usize,
        ctx: &RoundContext<'_>,
        network: &Network,
        relay: &mut P2pRelay,
        peers: &[NetworkPeer],
        preferred_faulty_ids: &HashSet<PeerId>,
    ) -> Result<()> {
        iroha_logger::info!(
            round = round_index + 1,
            total = self.n_rounds,
            "Begin round"
        );
        let target_height = ctx.initial_non_empty + (round_index as u64) + 1;
        let chain_id = network.chain_id();
        let peer_ids: Vec<_> = peers.iter().map(NetworkPeer::id).collect();
        let peers_by_id: HashMap<PeerId, NetworkPeer> = peers
            .iter()
            .cloned()
            .map(|peer| (peer.id(), peer))
            .collect();
        let rotated_topology =
            topology_for_permissioned_round(&peer_ids, &chain_id, target_height, 0);
        let leader_id = rotated_topology
            .first()
            .cloned()
            .expect("topology always has a leader");
        let fault_budget = Self::fault_budget_for_peer_count(self.n_peers);
        let fault_round_seed =
            Self::fault_round_seed(round_index, self.n_faulty_peers, fault_budget);
        let faulty_ids: HashSet<_> = Self::select_faulty_peer_ids(
            &peer_ids,
            self.n_faulty_peers,
            fault_round_seed,
            &chain_id,
            target_height,
            preferred_faulty_ids,
        )
        .into_iter()
        .collect();
        let faulty: Vec<_> = peers
            .iter()
            .filter(|peer| faulty_ids.contains(&peer.id()))
            .cloned()
            .collect();
        let sync_timeout = scaled_timeout(network.sync_timeout(), peers.len());
        let relay_pause =
            non_faulty_sync_timeout(sync_timeout, network.block_cadence(), self.n_faulty_peers);
        let min_ttl = sync_timeout.saturating_add(Duration::from_secs(300));
        let submit_while_partitioned = self.n_faulty_peers <= 1;
        let stagger_faults = self.n_faulty_peers > 1;
        let primary_peer = peers
            .iter()
            .find(|peer| peer.id() == leader_id)
            .filter(|peer| !faulty_ids.contains(&peer.id()))
            .cloned()
            .unwrap_or_else(|| {
                let mut rng = ChaCha8Rng::seed_from_u64(
                    0x5553_5052 + u64::try_from(round_index).unwrap_or(0),
                );
                peers
                    .iter()
                    .filter(|peer| !faulty_ids.contains(&peer.id()))
                    .choose(&mut rng)
                    .expect("there should be some working peers")
                    .clone()
            });
        let mut candidates: Vec<_> = peers
            .iter()
            .filter(|peer| !faulty_ids.contains(&peer.id()))
            .cloned()
            .collect();
        if let Some(pos) = candidates
            .iter()
            .position(|peer| peer.id() == primary_peer.id())
        {
            let primary = candidates.remove(pos);
            candidates.insert(0, primary);
        }
        // After recovery the round may experience view changes. If the transaction only exists on
        // one peer, a later-view leader might never observe it. Submitting to all peers (best
        // effort) makes the scenario resilient to delayed tx gossip and leadership rotation.
        let recovered_candidates: Vec<_> = rotated_topology
            .iter()
            .filter_map(|peer_id| peers_by_id.get(peer_id))
            .cloned()
            .collect();
        let builder_client = primary_peer.client();
        let builder_client =
            integration_tests::sync::rebind_blocking_client(&builder_client, |client| {
                if client.transaction_ttl.is_some_and(|ttl| ttl < min_ttl) {
                    client.transaction_ttl = Some(min_ttl);
                }
            });
        let mint_asset = Mint::asset_quantity(
            1_u32,
            AssetId::new(ctx.asset_definition_id.clone(), ctx.account_id.clone()),
        );
        let mut tx_metadata = Metadata::default();
        tx_metadata.insert(
            "unstable_network_round"
                .parse()
                .expect("valid metadata key"),
            u64::try_from(round_index).unwrap_or(u64::MAX),
        );
        tx_metadata.insert(
            "unstable_network_target_height"
                .parse()
                .expect("valid metadata key"),
            target_height,
        );
        let tx = Arc::new(
            {
                let account = builder_client.account_client();
                account
                    .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                        vec![mint_asset],
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                        tx_metadata,
                    ))
                    .and_then(|payload| account.sign_transaction(payload))
            }
            .expect("build integration-test transaction"),
        );
        let partition_submit_window = relay_pause
            .min(
                network
                    .block_cadence()
                    .saturating_mul(2)
                    .max(Duration::from_secs(5)),
            )
            .max(Duration::from_secs(2));
        if stagger_faults {
            let max_stagger_pause = network.block_cadence().max(Duration::from_secs(2));
            let per_peer_pause = relay_pause
                .checked_div(u32::try_from(self.n_faulty_peers).unwrap_or(1))
                .unwrap_or(Duration::from_secs(1))
                .max(Duration::from_millis(200))
                .min(max_stagger_pause);
            let recovery_gap =
                stagger_recovery_gap(network.block_cadence()).min(Duration::from_secs(2));
            for (idx, peer) in faulty.iter().enumerate() {
                relay.suspend(&peer.id()).activate();
                iroha_logger::info!(peer = peer.mnemonic(), "Suspended");
                sleep(per_peer_pause).await;
                relay.suspend(&peer.id()).deactivate();
                iroha_logger::info!(peer = peer.mnemonic(), "Unsuspended");
                if idx + 1 < faulty.len() {
                    sleep(recovery_gap).await;
                }
            }
        } else {
            for peer in &faulty {
                relay.suspend(&peer.id()).activate();
                iroha_logger::info!(peer = peer.mnemonic(), "Suspended");
            }
        }
        let submit_tx = |phase: &'static str,
                         timeout_window: Duration,
                         submit_peers: Vec<NetworkPeer>| {
            let tx = Arc::clone(&tx);
            async move {
                let deadline = Instant::now() + timeout_window;
                let per_attempt_timeout = timeout_window
                    .min(Duration::from_secs(10))
                    .max(Duration::from_secs(2));
                let mut attempts = 0usize;
                loop {
                    attempts = attempts.saturating_add(1);
                    let mut accepted = false;
                    let mut attempt_err: Option<eyre::Report> = None;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(eyre!(
                            "transaction submission failed on all peers during {phase}"
                        ));
                    }
                    let attempt_timeout = per_attempt_timeout.min(remaining);
                    let mut submissions = FuturesUnordered::new();
                    for peer in &submit_peers {
                        let client = peer.client();
                        let mnemonic = peer.mnemonic().to_owned();
                        iroha_logger::info!(
                            phase,
                            via_peer = peer.mnemonic(),
                            "Submit transaction"
                        );
                        let tx = Arc::clone(&tx);
                        submissions.push(async move {
                            let res = timeout(
                                attempt_timeout,
                                client.account_client().submit_transaction(&tx),
                            )
                            .await;
                            (mnemonic, res)
                        });
                    }
                    while let Some((mnemonic, res)) = submissions.next().await {
                        match res {
                            Ok(Ok(_hash)) => accepted = true,
                            Ok(Err(err)) => {
                                if is_submission_accepted_duplicate(&err) {
                                    accepted = true;
                                    continue;
                                }
                                attempt_err = Some(err);
                            }
                            Err(err) => {
                                attempt_err = Some(eyre!(
                                    "transaction submission timed out on peer {mnemonic} during {phase} after {attempt_timeout:?}: {err}"
                                ));
                            }
                        }
                    }
                    if accepted {
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        return Err(attempt_err.unwrap_or_else(|| {
                            eyre!("transaction submission failed on all peers during {phase}")
                        }));
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(attempt_err.unwrap_or_else(|| {
                            eyre!("transaction submission failed on all peers during {phase}")
                        }));
                    }
                    sleep(submit_retry_backoff(attempts).min(remaining)).await;
                }
            }
        };
        if submit_while_partitioned {
            match submit_tx("partitioned", partition_submit_window, candidates.clone()).await {
                Ok(()) => {}
                Err(err) => {
                    iroha_logger::warn!(
                        ?err,
                        "partitioned submit failed; will retry after recovery"
                    );
                }
            }
        }
        if !stagger_faults {
            if submit_while_partitioned {
                match timeout(
                    relay_pause,
                    once_blocks_sync(
                        network.peers().iter().filter(|x| !faulty.contains(x)),
                        BlockHeight::predicate_non_empty(target_height),
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        iroha_logger::warn!(
                            ?err,
                            target_height,
                            "non-suspended peers failed to sync during partition window"
                        );
                    }
                    Err(err) => {
                        iroha_logger::warn!(
                            ?err,
                            target_height,
                            "non-suspended peers did not sync within partition window"
                        );
                    }
                }
            } else {
                sleep(relay_pause).await;
            }
            for peer in &faulty {
                relay.suspend(&peer.id()).deactivate();
                iroha_logger::info!(peer = peer.mnemonic(), "Unsuspended");
            }
        }
        // Let connections settle after partitions before confirming the transaction.
        let recovery_delay = if submit_while_partitioned {
            network.block_cadence().max(Duration::from_secs(2))
        } else {
            relay_pause
                .saturating_add(network.block_cadence())
                .max(network.block_cadence().saturating_mul(2))
        };
        sleep(recovery_delay).await;
        if let Err(err) = submit_tx(
            "recovered",
            recovered_submit_window(sync_timeout, network.block_cadence()),
            recovered_candidates.clone(),
        )
        .await
        {
            iroha_logger::warn!(
                ?err,
                "recovered submit failed before supply wait; continuing with supply retries"
            );
        }
        let expected_supply = Quantity::from((round_index + 1) as u128);
        let supply_start = Instant::now();
        let supply_deadline = supply_start + sync_timeout;
        let initial_resubmit_at =
            supply_start + initial_resubmit_delay(sync_timeout, network.block_cadence());
        let allow_resubmit = allow_supply_resubmit(self.n_faulty_peers);
        let supply_peers: Vec<_> = peers
            .iter()
            .filter(|peer| !faulty_ids.contains(&peer.id()))
            .collect();
        let mut last_seen = None;
        let mut last_height = None;
        let mut resubmit_attempt = 0usize;
        let mut next_resubmit_at = initial_resubmit_at;
        'wait_supply: loop {
            let mut converged_peers = 0usize;
            for peer in &supply_peers {
                if let Some(height) = peer.best_effort_block_height() {
                    last_height = Some(height);
                }
                let client = peer.client();
                let asset_id =
                    AssetId::new(ctx.asset_definition_id.clone(), ctx.account_id.clone());
                let asset = match spawn_blocking(move || {
                    client.client().query_single(FindAssetById::new(asset_id))
                })
                .await
                {
                    Ok(Ok(asset)) => Some(asset),
                    Ok(Err(err)) => {
                        iroha_logger::debug!(
                            ?err,
                            peer = peer.mnemonic(),
                            "exact asset query did not resolve during supply check"
                        );
                        None
                    }
                    Err(err) => {
                        iroha_logger::warn!(
                            ?err,
                            peer = peer.mnemonic(),
                            "asset query task failed during supply check"
                        );
                        None
                    }
                };
                let asset_value = asset.as_ref().map(|asset| asset.value().clone());
                if let Some(asset) = asset.as_ref() {
                    if asset.value() == &expected_supply {
                        converged_peers = converged_peers.saturating_add(1);
                        continue;
                    }
                }
                last_seen = asset_value;
            }
            if converged_peers == supply_peers.len() {
                break 'wait_supply;
            }
            let now = Instant::now();
            if should_resubmit_tx(allow_resubmit, now, next_resubmit_at) {
                let attempt = resubmit_attempt.saturating_add(1);
                let remaining = supply_deadline.saturating_duration_since(now);
                if !remaining.is_zero() {
                    if let Err(err) =
                        submit_tx("recovered_retry", remaining, recovered_candidates.clone()).await
                    {
                        iroha_logger::warn!(
                            ?err,
                            attempt,
                            "recovered submit retry failed while waiting for supply"
                        );
                    }
                }
                resubmit_attempt = attempt;
                next_resubmit_at = Instant::now() + submit_retry_backoff(attempt);
            }
            if now >= supply_deadline {
                if allow_round_supply_deadline_slip(self.n_faulty_peers) {
                    iroha_logger::warn!(
                        ?expected_supply,
                        ?last_seen,
                        ?last_height,
                        faulty_peers = self.n_faulty_peers,
                        target_height,
                        "round supply did not converge before deadline; continuing and relying on final supply assertion"
                    );
                    break 'wait_supply;
                }
                return Err(eyre!(
                    "total supply did not reach expected {expected_supply}; last seen value: {last_seen:?}; last height: {last_height:?}"
                ));
            }
            sleep(Duration::from_millis(200)).await;
        }
        let catch_up_timeout = sync_timeout.min(Duration::from_secs(180));
        match timeout(
            catch_up_timeout,
            once_blocks_sync(
                network.peers().iter().filter(|x| !faulty.contains(x)),
                BlockHeight::predicate_non_empty(target_height),
            ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(eyre!(
                    "non-faulty peers failed to catch up to height {target_height}: {err}"
                ));
            }
            Err(err) => {
                return Err(eyre!(
                    "non-faulty peers did not catch up to height {target_height} within {catch_up_timeout:?}: {err}"
                ));
            }
        }
        if !faulty.is_empty() {
            match timeout(
                catch_up_timeout,
                once_blocks_sync(
                    faulty.iter(),
                    BlockHeight::predicate_non_empty(target_height),
                ),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(eyre!(
                        "healed peers failed to catch up to height {target_height}: {err}"
                    ));
                }
                Err(err) => {
                    return Err(eyre!(
                        "healed peers did not catch up to height {target_height} within {catch_up_timeout:?}: {err}"
                    ));
                }
            }
        }
        Ok(())
    }
    async fn assert_total_supply(
        network: &Network,
        asset_definition_id: &AssetDefinitionId,
        rounds: usize,
        expected_height: u64,
    ) -> Result<()> {
        let peers = network.peers();
        let expected = Quantity::from(rounds as u128);
        let deadline =
            Instant::now() + scaled_timeout(network.sync_timeout(), network.peers().len());
        loop {
            let mut last_seen = None;
            let mut last_height = None;
            let mut converged_peers = 0usize;
            for peer in peers {
                let observed_height = peer.best_effort_block_height();
                if let Some(height) = observed_height {
                    last_height = Some(height);
                }
                let client = peer.client();
                let asset_id = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
                let asset = match spawn_blocking(move || {
                    client.client().query_single(FindAssetById::new(asset_id))
                })
                .await
                {
                    Ok(Ok(asset)) => Some(asset),
                    Ok(Err(err)) => {
                        iroha_logger::debug!(
                            ?err,
                            peer = peer.mnemonic(),
                            "exact asset query did not resolve during final supply check"
                        );
                        None
                    }
                    Err(err) => {
                        iroha_logger::warn!(
                            ?err,
                            peer = peer.mnemonic(),
                            "asset query task failed during final supply check"
                        );
                        None
                    }
                };
                let asset_value = asset.as_ref().map(|asset| asset.value().clone());
                if let Some(asset) = asset.as_ref() {
                    let supply_matches = asset.value() == &expected;
                    let height_matches =
                        observed_height.is_some_and(|height| height.non_empty >= expected_height);
                    if supply_matches && height_matches {
                        converged_peers = converged_peers.saturating_add(1);
                        continue;
                    }
                }
                last_seen = asset_value;
            }
            if converged_peers == peers.len() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(eyre!(
                    "total supply did not reach expected {expected} with expected height >= {expected_height}; last seen value: {last_seen:?}; last height: {last_height:?}"
                ));
            }
            sleep(Duration::from_millis(200)).await;
        }
    }
}
struct RoundContext<'a> {
    initial_non_empty: u64,
    asset_definition_id: &'a AssetDefinitionId,
    account_id: &'a AccountId,
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use std::collections::BTreeSet;
    #[test]
    fn faulty_peer_selection_preserves_the_active_leader() {
        let peer_ids: Vec<_> = (0..10)
            .map(|_| PeerId::new(KeyPair::random().public_key().clone()))
            .collect();
        let chain_id: ChainId = "unstable-network-selection".parse().expect("chain id");
        let height = 7_u64;
        let rotated = topology_for_permissioned_round(&peer_ids, &chain_id, height, 0);
        let selected_single = UnstableNetwork::select_faulty_peer_ids(
            &peer_ids,
            1,
            0,
            &chain_id,
            height,
            &HashSet::new(),
        );
        assert_eq!(selected_single.len(), 1);
        assert_ne!(Some(&selected_single[0]), rotated.first());
        let selected_multi: BTreeSet<_> = UnstableNetwork::select_faulty_peer_ids(
            &peer_ids,
            3,
            0,
            &chain_id,
            height,
            &HashSet::new(),
        )
        .into_iter()
        .collect();
        assert_eq!(selected_multi.len(), 3);
        assert!(
            rotated
                .first()
                .is_none_or(|leader| !selected_multi.contains(leader))
        );
    }
    #[test]
    fn preferred_faulty_peers_are_selected_first() {
        let peer_ids: Vec<_> = (0..4)
            .map(|_| PeerId::new(KeyPair::random().public_key().clone()))
            .collect();
        let chain_id: ChainId = "unstable-network-preferred-faults"
            .parse()
            .expect("chain id");
        let height = 3_u64;
        let rotated = topology_for_permissioned_round(&peer_ids, &chain_id, height, 0);
        let preferred = rotated
            .iter()
            .skip(1)
            .next()
            .expect("test roster should have a safe preferred peer")
            .clone();
        let preferred_faulty_ids = HashSet::from([preferred.clone()]);
        let selected = UnstableNetwork::select_faulty_peer_ids(
            &peer_ids,
            1,
            0,
            &chain_id,
            height,
            &preferred_faulty_ids,
        );
        assert_eq!(selected, vec![preferred]);
    }
    #[test]
    fn preferred_active_leader_does_not_override_safe_selection() {
        let peer_ids: Vec<_> = (0..7)
            .map(|_| PeerId::new(KeyPair::random().public_key().clone()))
            .collect();
        let chain_id: ChainId = "unstable-network-unsafe-preferred"
            .parse()
            .expect("chain id");
        let height = 5_u64;
        let rotated = topology_for_permissioned_round(&peer_ids, &chain_id, height, 0);
        let preferred_leader = rotated
            .first()
            .expect("test roster should have a leader")
            .clone();
        let preferred_faulty_ids = HashSet::from([preferred_leader.clone()]);
        let selected = UnstableNetwork::select_faulty_peer_ids(
            &peer_ids,
            1,
            0,
            &chain_id,
            height,
            &preferred_faulty_ids,
        );
        assert_eq!(selected.len(), 1);
        assert_ne!(selected[0], preferred_leader);
    }
    #[test]
    fn fault_budget_matches_commit_quorum_tail() {
        let peer_count = 10;
        let commit_quorum = iroha_sumeragi::types::quorum(peer_count);
        let fault_budget = UnstableNetwork::fault_budget_for_peer_count(peer_count);
        assert_eq!(fault_budget, peer_count - commit_quorum);
    }
    #[test]
    fn fault_round_seed_sticks_at_budget() {
        let budget = UnstableNetwork::fault_budget_for_peer_count(13);
        assert!(budget > 0);
        let sticky = UnstableNetwork::fault_round_seed(4, budget, budget);
        assert_eq!(sticky, 0);
        let rotating = UnstableNetwork::fault_round_seed(4, budget.saturating_sub(1), budget);
        assert_eq!(rotating, 4);
    }
    #[test]
    fn non_faulty_sync_timeout_caps_multi_faults() {
        let sync_timeout = Duration::from_secs(180);
        let pipeline_time = Duration::from_secs(9);
        let capped = non_faulty_sync_timeout(sync_timeout, pipeline_time, 2);
        assert!(capped < sync_timeout);
        assert!(capped <= pipeline_time * 2 + Duration::from_secs(2));
        let single_fault = non_faulty_sync_timeout(sync_timeout, pipeline_time, 1);
        assert!(single_fault < sync_timeout);
        let expected_cap = pipeline_time
            .saturating_mul(defaults::sumeragi::ROUND_TIMEOUT_CADENCE_MULTIPLIER)
            + pipeline_time
            + Duration::from_secs(2);
        assert_eq!(single_fault, expected_cap);
        let no_faults = non_faulty_sync_timeout(sync_timeout, pipeline_time, 0);
        assert_eq!(no_faults, sync_timeout);
    }
    #[test]
    fn submit_retry_backoff_caps_delay() {
        assert_eq!(submit_retry_backoff(1), Duration::from_millis(200));
        assert_eq!(submit_retry_backoff(5), Duration::from_millis(1000));
        assert_eq!(submit_retry_backoff(20), Duration::from_secs(2));
    }
    #[test]
    fn resubmit_gate_respects_flags_and_deadline() {
        let now = Instant::now();
        assert!(!should_resubmit_tx(false, now, now));
        assert!(should_resubmit_tx(true, now, now));
        assert!(!should_resubmit_tx(true, now, now + Duration::from_secs(1)));
    }
    #[test]
    fn supply_resubmit_is_reserved_for_faulted_rounds() {
        assert!(!allow_supply_resubmit(0));
        assert!(allow_supply_resubmit(1));
    }
    #[test]
    fn round_supply_deadline_slip_is_reserved_for_faulted_rounds() {
        assert!(!allow_round_supply_deadline_slip(0));
        assert!(allow_round_supply_deadline_slip(1));
        assert!(allow_round_supply_deadline_slip(2));
    }
    #[test]
    fn submit_acceptance_accepts_enqueued_or_committed_duplicate() {
        let enqueued = eyre!("PRTRY:ALREADY_ENQUEUED");
        assert!(is_submission_accepted_duplicate(&enqueued));
        let committed = eyre!("transaction already committed to the blockchain");
        assert!(is_submission_accepted_duplicate(&committed));
    }
    #[test]
    fn initial_resubmit_delay_caps_at_half_sync_timeout() {
        let delay = initial_resubmit_delay(Duration::from_secs(10), Duration::from_secs(4));
        assert_eq!(delay, Duration::from_secs(5));
    }
    #[test]
    fn initial_resubmit_delay_prefers_pipeline_multiple() {
        let delay = initial_resubmit_delay(Duration::from_secs(600), Duration::from_secs(6));
        assert_eq!(delay, Duration::from_secs(24));
    }
    #[test]
    fn recovered_submit_window_has_minimum_probe_delay() {
        let delay = recovered_submit_window(Duration::from_secs(600), Duration::from_secs(2));
        assert_eq!(delay, Duration::from_secs(5));
    }
    #[test]
    fn recovered_submit_window_caps_at_sync_timeout() {
        let delay = recovered_submit_window(Duration::from_secs(3), Duration::from_secs(10));
        assert_eq!(delay, Duration::from_secs(3));
    }
    #[test]
    fn stagger_recovery_gap_scales_with_pipeline() {
        assert_eq!(
            stagger_recovery_gap(Duration::from_secs(6)),
            Duration::from_secs(3)
        );
        assert_eq!(
            stagger_recovery_gap(Duration::from_millis(500)),
            Duration::from_secs(1)
        );
    }
}
#[tokio::test]
async fn unstable_network_4_peers_1_fault() -> Result<()> {
    UnstableNetwork {
        n_peers: 4,
        n_faulty_peers: 1,
        n_rounds: 5,
    }
    .run()
    .await
}
#[tokio::test]
async fn unstable_network_7_peers_1_fault() -> Result<()> {
    UnstableNetwork {
        n_peers: 7,
        n_faulty_peers: 1,
        n_rounds: 3,
    }
    .run()
    .await
}
#[tokio::test]
async fn unstable_network_7_peers_2_faults() -> Result<()> {
    UnstableNetwork {
        n_peers: 7,
        n_faulty_peers: 2,
        n_rounds: 3,
    }
    .run()
    .await
}
#[tokio::test]
async fn unstable_network_10_peers_3_faults() -> Result<()> {
    UnstableNetwork {
        n_peers: 10,
        n_faulty_peers: 3,
        // Keep this high-fault scenario to two rounds to reduce host-load flakiness in the
        // grouped `network_functional` harness while still exercising repeated partition recovery.
        n_rounds: 2,
    }
    .run()
    .await
}
#[tokio::test]
async fn unstable_network_13_peers_4_faults() -> Result<()> {
    UnstableNetwork {
        n_peers: 13,
        n_faulty_peers: 4,
        n_rounds: 1,
    }
    .run()
    .await
}
#[tokio::test]
async fn unstable_network_rejects_non_revision4_committee_geometry() {
    let error = UnstableNetwork {
        n_peers: 5,
        n_faulty_peers: 1,
        n_rounds: 1,
    }
    .run()
    .await
    .expect_err("invalid revision-4 committee geometry must fail before startup");
    assert!(
        error.to_string().contains("exact revision-4 3f + 1"),
        "unexpected geometry error: {error}"
    );
}
