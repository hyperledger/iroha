//! Explicit installed-binary qualification for a standalone owner-private four-validator root.
//!
//! This fixture never contacts or mutates its synthetic parent network. It checks local native
//! execution, persistence and listener isolation; parent attachment needs separate qualification.

use super::super::*;
use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Instant,
};

struct StopOnDrop<'a> {
    store: &'a ManagedStore,
    name: &'a str,
}

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.store.down(self.name) {
            eprintln!(
                "private smoke authenticated cleanup failed at {}: {error}",
                self.store.root().display()
            );
        }
    }
}

fn require_ready(status: &ManagedStatus) {
    assert_eq!(status.phase, ManagedPhase::Ready, "{status:?}");
    assert_eq!(status.running_peers, 4);
}

fn require_anonymous_rejection(endpoint: &str, path: &str) {
    let url: url::Url = endpoint.parse().unwrap();
    assert_eq!(url.scheme(), "http");
    let address: SocketAddr = format!(
        "{}:{}",
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap()
    )
    .parse()
    .unwrap();
    assert!(address.ip().is_loopback());
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    socket.take(8193).read_to_end(&mut response).unwrap();
    assert!(response.len() <= 8192);
    let response = std::str::from_utf8(&response).unwrap();
    assert!(response.starts_with("HTTP/1.1 401 "), "{path}: {response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("cache-control: private, no-store"),
        "{path}: anonymous private-root responses must not be publicly cached"
    );
}

#[test]
#[ignore = "diagnoses installed-binary startup costs without starting validators; run after timing acceptance"]
fn installed_private_root_startup_cost_diagnostic() {
    let _resources = super::super::native_test_guard();
    let runtime_directory = PathBuf::from(
        std::env::var_os("IROHA_TEST_RUNTIME_DIRECTORY")
            .expect("set IROHA_TEST_RUNTIME_DIRECTORY to the matching installed binaries"),
    );
    let runtime = InstalledRuntime::from_directory(&runtime_directory).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let request = runtime.private_root_request("private", Duration::from_secs(30));
    let spec = super::private_spec();
    let directory = iroha_fs::PrivateDirectory::open(store.root())
        .unwrap()
        .open_child("networks")
        .unwrap()
        .create_child(&request.name)
        .unwrap();
    let _operation = store::acquire(&directory, "operation.lock", &request.name).unwrap();
    let ports = LocalnetPorts::reserve().unwrap();

    fn measured<T>(label: &str, operation: impl FnOnce() -> Result<T>) -> T {
        let started = Instant::now();
        let result = operation().unwrap();
        eprintln!("startup cost diagnostic: {label}: {:?}", started.elapsed());
        result
    }

    let launcher = measured("foreground launcher pin", || {
        store::pin_binary(&request.launcher)
    });
    let daemon = measured("foreground daemon pin", || {
        store::pin_binary(&request.daemon)
    });
    let retained = measured("complete private generation and atomic publication", || {
        generation::prepare(
            &directory,
            &request,
            RootKind::Private { spec },
            launcher,
            daemon,
            &ports,
        )
    });
    measured("foreground launcher reverification", || {
        store::verify_binary(&retained.launcher)
    });
    measured("worker retained generation validation", || {
        store::validate_prepared(
            &request.name,
            directory.path(),
            &retained.prepared,
            &retained.root_kind,
        )
    });
    measured("worker launcher pin", || {
        store::verify_binary(&retained.launcher)
    });
    measured("worker daemon pin", || {
        store::verify_binary(&retained.daemon)
    });
    let current = measured("worker running-image equivalent pin", || {
        store::pin_binary(&retained.launcher.path)
    });
    assert_eq!(current.blake3, retained.launcher.blake3);
    eprintln!("startup cost diagnostic only; no validator startup or latency qualification");
}

#[test]
#[ignore = "requires a current matching Kagami/iroha3d pair and starts four real validators"]
fn installed_private_root_lifecycle_and_listener_isolation() {
    let _resources = super::super::native_test_guard();
    let runtime_directory = PathBuf::from(
        std::env::var_os("IROHA_TEST_RUNTIME_DIRECTORY")
            .expect("set IROHA_TEST_RUNTIME_DIRECTORY to the matching installed binaries"),
    );
    let runtime = InstalledRuntime::from_directory(&runtime_directory).unwrap();
    let root = match std::env::var_os("IROHA_TEST_PRIVATE_STORE") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(path.is_absolute() && !path.exists());
            path
        }
        None => tempfile::Builder::new()
            .prefix("iroha-private-native-smoke-")
            .tempdir()
            .unwrap()
            .keep()
            .join("managed"),
    };
    let store = ManagedStore::open(&root).unwrap();
    eprintln!("PRIVATE_SMOKE_STORE={}", store.root().display());
    let request = runtime.private_root_request("private", Duration::from_secs(30));
    let spec = super::private_spec();
    let _cleanup = StopOnDrop {
        store: &store,
        name: &request.name,
    };
    let started = Instant::now();
    let ready = store.up_private_root(&request, &spec).unwrap();
    let elapsed = started.elapsed();
    require_ready(&ready);
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
    eprintln!("private fresh startup: {elapsed:?}");
    let prepared = store.prepared("private").unwrap();
    let registration = prepared.load_private_registration().unwrap();
    for peer in &prepared.peers {
        let mut config = prepared.context.load_client_config().unwrap();
        assert!(config.api_token.is_some());
        config.torii_api_url = peer.torii_url.parse().unwrap();
        config.torii_request_timeout = Duration::from_secs(3);
        let client = iroha::blocking::Client::new(config).unwrap();
        assert_eq!(
            client
                .client()
                .get_private_root_registration(spec.scope())
                .unwrap(),
            registration,
            "every live peer must match original locally executed genesis"
        );
        for path in [
            "/status",
            "/v1/private-root/registration",
            "/v1/sorafs/cid/smoke",
        ] {
            require_anonymous_rejection(&peer.torii_url, path);
        }
    }
    let repeated = store.up_private_root(&request, &spec).unwrap();
    require_ready(&repeated);
    assert_eq!(repeated.context, ready.context);
    let stopped = store.down("private").unwrap();
    assert_eq!(stopped.phase, ManagedPhase::Stopped);
    assert_eq!(stopped.running_peers, 0);
    let started = Instant::now();
    let restarted = store.up_retained(&request, &prepared.context).unwrap();
    let elapsed = started.elapsed();
    require_ready(&restarted);
    assert_eq!(restarted.context, ready.context);
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
    eprintln!("private retained startup: {elapsed:?}");
    assert_eq!(store.prepared("private").unwrap(), prepared);
    assert_eq!(store.context(None).unwrap(), ready.context);
    let stopped = store.down("private").unwrap();
    assert_eq!(stopped.phase, ManagedPhase::Stopped);
    assert_eq!(stopped.running_peers, 0);
    eprintln!(
        "PRIVATE_SMOKE_STOPPED_STORE={} (retained for exact CLI deployment follow-up)",
        store.root().display()
    );
}
