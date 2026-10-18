//! Regression test ensuring `Torii::start` waits for shutdown.
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{State, World},
};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_torii::{MaybeTelemetry, OnlinePeersProvider, Torii, test_utils};
use std::{sync::Arc, time::Duration};
#[tokio::test]
async fn torii_start_blocks_until_shutdown_signal() {
    // Some sandboxed test environments forbid binding sockets (for example, when networking is
    // disabled). This regression test exercises `Torii::start`, which binds a listener; if the
    // platform rejects `bind(2)` with `EPERM`, skip rather than failing the entire suite.
    if let Err(err) = std::net::TcpListener::bind("127.0.0.1:0") {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!(
                "skipping torii_start_blocks_until_shutdown_signal: socket bind not permitted: {err}"
            );
            return;
        }
        panic!("failed to probe socket bind capability: {err}");
    }
    let cfg = test_utils::mk_minimal_root_cfg();
    let (kiso, _kiso_child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(
        World::default(),
        kura.clone(),
        query,
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, events.clone()));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    drop(peers_tx);
    let _data_dir = test_utils::TestDataDirGuard::new();
    let torii = Torii::new_with_handle(
        cfg.common.chain.clone(),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        events,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid Torii startup fixture");
    let shutdown = ShutdownSignal::new();
    let shutdown_for_task = shutdown.clone();
    let join_handle = tokio::spawn(async move { torii.start(shutdown_for_task).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    if join_handle.is_finished() {
        let early = join_handle
            .await
            .expect("join handle should complete without panicking");
        panic!("Torii::start returned before receiving shutdown signal: {early:?}");
    }
    shutdown.send();
    let join_result = tokio::time::timeout(Duration::from_secs(5), join_handle)
        .await
        .expect("Torii::start should exit after shutdown");
    if let Err(err) = join_result {
        panic!("Torii::start should terminate successfully: {err:?}");
    }
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
