use super::{
    Error, PipelineStatusCache, ShutdownOnDrop, SocketAdmission, ToriiCriticalWorker,
    ToriiCriticalWorkerExit, ToriiCriticalWorkerFailure, ValidatedToriiHttpTransport,
    WriteTimeoutIo, bind_torii_tcp_listener, observe_torii_connection_completion,
    rollback_torii_startup_workers, serve_torii_public, start_pipeline_status_projection_worker,
    supervise_torii_critical_workers,
};
use axum::{Router, body::Body, routing::get};
use iroha_config::parameters::actual::ToriiHttpTransport;
use iroha_futures::supervisor::ShutdownSignal;
use iroha_primitives::addr::SocketAddr;
use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr as StdSocketAddr, SocketAddrV4},
    num::NonZeroUsize,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

#[test]
fn shutdown_guard_signals_when_start_future_is_dropped() {
    let shutdown = ShutdownSignal::new();
    {
        let _guard = ShutdownOnDrop::new(shutdown.clone());
        assert!(!shutdown.is_sent());
    }
    assert!(shutdown.is_sent());
}

#[test]
fn invalid_http_transport_is_rejected_before_serving() {
    let config = ToriiHttpTransport {
        max_connections: NonZeroUsize::new(1).expect("nonzero"),
        max_connections_per_ip: NonZeroUsize::new(2).expect("nonzero"),
        ..Default::default()
    };
    assert!(ValidatedToriiHttpTransport::new(config).is_err());

    let config = ToriiHttpTransport {
        header_read_timeout: Duration::ZERO,
        ..Default::default()
    };
    assert!(ValidatedToriiHttpTransport::new(config).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn panicked_http_connection_is_contained_to_its_socket() {
    let mut connections = JoinSet::new();
    connections.spawn(crate::panic_recovery::catch_async_recoverable(async move {
        assert!(
            iroha_panic_hook::is_suppressed(),
            "the physical connection future must run inside its recovery boundary"
        );
        panic!("injected attacker-controlled HTTP connection panic");
        #[allow(unreachable_code)]
        (
            StdSocketAddr::from((Ipv4Addr::LOCALHOST, 41_337)),
            Ok::<(), std::io::Error>(()),
        )
    }));

    let completion = connections
        .join_next()
        .await
        .expect("connection wrapper must produce a result");
    observe_torii_connection_completion(completion)
        .expect("a panicked connection must not terminate the listener");
    assert!(
        !iroha_panic_hook::is_suppressed(),
        "connection panic suppression must not leak into the listener"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn critical_worker_exit_fails_closed_and_stops_server() {
    let shutdown = ShutdownSignal::new();
    let server_shutdown = shutdown.clone();
    let result = supervise_torii_critical_workers(
        shutdown.clone(),
        vec![ToriiCriticalWorker {
            name: "probe",
            task: tokio::spawn(async { ToriiCriticalWorkerExit::UnexpectedExit }),
        }],
        async move {
            server_shutdown.receive().await;
            Ok(())
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(ToriiCriticalWorkerFailure::ExitedUnexpectedly("probe"))
    ));
    assert!(shutdown.is_sent());
}

#[tokio::test(flavor = "current_thread")]
async fn critical_workers_are_joined_on_graceful_shutdown() {
    let shutdown = ShutdownSignal::new();
    let worker_shutdown = shutdown.clone();
    let server_shutdown = shutdown.clone();
    let supervision = supervise_torii_critical_workers(
        shutdown.clone(),
        vec![ToriiCriticalWorker {
            name: "probe",
            task: tokio::spawn(async move {
                worker_shutdown.receive().await;
                ToriiCriticalWorkerExit::StoppedByShutdown
            }),
        }],
        async move {
            server_shutdown.receive().await;
            Ok(())
        },
    );
    tokio::pin!(supervision);
    tokio::task::yield_now().await;
    shutdown.send();
    assert!(matches!(supervision.await, Ok(Ok(()))));
}

#[tokio::test(flavor = "current_thread")]
async fn startup_rollback_signals_and_joins_every_started_worker() {
    let shutdown = ShutdownSignal::new();
    let worker_shutdown = shutdown.clone();
    let (stopping_tx, stopping_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let joined = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let joined_by_worker = std::sync::Arc::clone(&joined);
    let worker = ToriiCriticalWorker {
        name: "startup_probe",
        task: tokio::spawn(async move {
            worker_shutdown.receive().await;
            let _ = stopping_tx.send(());
            let _ = release_rx.await;
            joined_by_worker.store(true, std::sync::atomic::Ordering::Release);
            ToriiCriticalWorkerExit::StoppedByShutdown
        }),
    };
    let rollback_shutdown = shutdown.clone();
    let mut rollback = tokio::spawn(async move {
        rollback_torii_startup_workers(
            &rollback_shutdown,
            vec![worker],
            error_stack::Report::new(Error::StartServer),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), stopping_rx)
        .await
        .expect("worker must promptly observe startup rollback")
        .expect("worker must report startup rollback");
    assert!(
        !rollback.is_finished(),
        "startup rollback must remain pending until the worker physically exits"
    );
    assert!(
        !joined.load(std::sync::atomic::Ordering::Acquire),
        "worker must still be running before its release signal"
    );
    release_tx.send(()).expect("release startup worker");
    let _failure = tokio::time::timeout(Duration::from_secs(1), &mut rollback)
        .await
        .expect("startup rollback must finish after the worker exits")
        .expect("startup rollback task must join");
    assert!(shutdown.is_sent());
    assert!(joined.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test(flavor = "current_thread")]
async fn panicked_critical_worker_stops_server_and_joins_siblings() {
    let shutdown = ShutdownSignal::new();
    let sibling_shutdown = shutdown.clone();
    let server_shutdown = shutdown.clone();
    let sibling_joined = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sibling_joined_by_task = std::sync::Arc::clone(&sibling_joined);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        supervise_torii_critical_workers(
            shutdown.clone(),
            vec![
                ToriiCriticalWorker {
                    name: "panic_probe",
                    task: tokio::spawn(async { panic!("critical worker probe") }),
                },
                ToriiCriticalWorker {
                    name: "sibling_probe",
                    task: tokio::spawn(async move {
                        sibling_shutdown.receive().await;
                        sibling_joined_by_task.store(true, std::sync::atomic::Ordering::Release);
                        ToriiCriticalWorkerExit::StoppedByShutdown
                    }),
                },
            ],
            async move {
                server_shutdown.receive().await;
                Ok(())
            },
        ),
    )
    .await
    .expect("critical-worker supervision must drain within its shutdown bound");
    assert!(matches!(
        result,
        Err(ToriiCriticalWorkerFailure::Panicked("panic_probe"))
    ));
    assert!(shutdown.is_sent());
    assert!(sibling_joined.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test(flavor = "current_thread")]
async fn closed_pipeline_projection_channel_is_a_critical_exit() {
    let (events, _) = tokio::sync::broadcast::channel(1);
    let shutdown = ShutdownSignal::new();
    let worker = start_pipeline_status_projection_worker(
        std::sync::Arc::new(PipelineStatusCache::new()),
        std::sync::Arc::new(iroha_core::state::State::new_for_testing(
            iroha_core::state::World::new(),
            iroha_core::kura::Kura::blank_kura_for_testing(),
            iroha_core::query::store::LiveQueryStore::start_test(),
        )),
        &events,
        shutdown,
    );
    drop(events);
    let exit = tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("pipeline projection worker should stop")
        .expect("pipeline projection worker should join");
    assert_eq!(exit, ToriiCriticalWorkerExit::UnexpectedExit);
}

#[tokio::test(flavor = "current_thread")]
async fn torii_reusable_tcp_listener_binds_loopback() {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let listener = bind_torii_tcp_listener(SocketAddr::Ipv4(addr.into()))
        .await
        .expect("Torii reusable listener should bind");
    assert_ne!(
        listener
            .local_addr()
            .expect("listener has local addr")
            .port(),
        0,
        "OS should assign an ephemeral port"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn torii_reusable_tcp_listener_rejects_active_listener() {
    let active =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("active listener should bind");
    let addr = match active.local_addr().expect("active listener has local addr") {
        StdSocketAddr::V4(addr) => addr,
        StdSocketAddr::V6(_) => unreachable!("test binds IPv4 loopback"),
    };
    let err = bind_torii_tcp_listener(SocketAddr::Ipv4(addr.into()))
        .await
        .expect_err("active listener must not be shadowed by reusable bind");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}
#[test]
fn socket_admission_enforces_global_and_canonical_source_limits() {
    let admission = SocketAdmission::new(
        NonZeroUsize::new(2).expect("non-zero global limit"),
        NonZeroUsize::new(1).expect("non-zero per-IP limit"),
    );
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mapped_loopback = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let loopback_permit = admission
        .try_acquire(loopback)
        .expect("first source socket is admitted");
    assert!(
        admission.try_acquire(mapped_loopback).is_none(),
        "IPv4-mapped IPv6 must share the IPv4 source limit"
    );
    let other_permit = admission
        .try_acquire(other)
        .expect("second source socket is admitted");
    assert!(
        admission
            .try_acquire(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
            .is_none(),
        "global socket limit must apply across source IPs"
    );
    drop(loopback_permit);
    let replacement = admission
        .try_acquire(mapped_loopback)
        .expect("dropping a permit immediately releases both counters");
    drop(replacement);
    drop(other_permit);
    let state = admission.state.lock();
    assert_eq!(state.active, 0);
    assert!(state.active_by_ip.is_empty());
}
#[tokio::test(flavor = "current_thread")]
async fn stalled_socket_write_hits_progress_deadline() {
    let (writer, _unread_peer) = tokio::io::duplex(1);
    let mut writer = WriteTimeoutIo::new(writer, Duration::from_millis(20));
    let error = writer
        .write_all(&[0xA5, 0x5A])
        .await
        .expect_err("an unread full socket must hit the write-progress deadline");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}
#[tokio::test(flavor = "current_thread")]
async fn partial_http_head_is_closed_at_listener_deadline() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("test listener should bind");
    let address = listener.local_addr().expect("test listener address");
    let config = ToriiHttpTransport {
        header_read_timeout: Duration::from_millis(25),
        write_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let shutdown = ShutdownSignal::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        serve_torii_public(
            listener,
            None,
            Router::new().route("/", get(|| async { "ok" })),
            ValidatedToriiHttpTransport::new(config).expect("valid test HTTP transport"),
            server_shutdown,
        )
        .await
    });
    let mut client = TcpStream::connect(address)
        .await
        .expect("test client should connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost:")
        .await
        .expect("partial request head should reach Torii");
    let mut response = Vec::new();
    let read_result =
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("partial request head must not retain a socket past its deadline");
    if let Err(error) = read_result {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ),
            "unexpected read failure after header timeout: {error}"
        );
    }
    shutdown.send();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("Torii test server should stop")
        .expect("Torii test task should not panic")
        .expect("Torii test server should exit cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_aborts_a_response_that_never_finishes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("test listener should bind");
    let address = listener.local_addr().expect("test listener address");
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(entered_tx)));
    let router = Router::new().route(
        "/",
        get({
            let entered_tx = std::sync::Arc::clone(&entered_tx);
            move || {
                if let Some(tx) = entered_tx.lock().expect("entry signal lock").take() {
                    let _ = tx.send(());
                }
                async {
                    Body::from_stream(futures::stream::pending::<
                        Result<axum::body::Bytes, Infallible>,
                    >())
                }
            }
        }),
    );
    let config = ToriiHttpTransport {
        write_timeout: Duration::from_millis(25),
        ..Default::default()
    };
    let shutdown = ShutdownSignal::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        serve_torii_public(
            listener,
            None,
            router,
            ValidatedToriiHttpTransport::new(config).expect("valid test HTTP transport"),
            server_shutdown,
        )
        .await
    });
    let mut client = TcpStream::connect(address)
        .await
        .expect("test client should connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request should reach Torii");
    tokio::time::timeout(Duration::from_secs(1), entered_rx)
        .await
        .expect("handler should be entered")
        .expect("handler entry signal should be delivered");

    shutdown.send();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("bounded connection drain must stop Torii")
        .expect("Torii test task should not panic")
        .expect("Torii test server should exit cleanly");
}
