//! Native socket ownership, bounded gap refusal, and joined responder handoff controls.

use super::*;
use crate::managed::{LocalnetPorts, native_operation::test_support::UnavailablePeers};
use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

fn request(url: &url::Url, path: &str) -> Vec<u8> {
    let mut socket =
        TcpStream::connect_timeout(&endpoint(url).unwrap(), Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut bytes = Vec::new();
    socket.take(8193).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 8192);
    bytes
}

fn fresh() -> (ReservedHttpListeners, Vec<url::Url>) {
    let listeners: Vec<_> = (0..4)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect();
    let endpoints: Vec<_> = listeners
        .iter()
        .map(|listener| {
            format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap()
        })
        .collect();
    (
        ReservedHttpListeners::new(listeners, &endpoints).unwrap(),
        endpoints,
    )
}

fn server(owner: &ReservedHttpListeners, endpoints: &[url::Url]) -> UnavailablePeers {
    let loans = owner.loan_all(endpoints).unwrap();
    let listeners = loans
        .iter()
        .map(|loan| loan.clone_listener().unwrap())
        .collect();
    UnavailablePeers::from_listeners(listeners, loans)
}

fn assert_reserved(endpoints: &[url::Url]) {
    for url in endpoints {
        assert_eq!(
            TcpListener::bind(endpoint(url).unwrap())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AddrInUse
        );
    }
}

#[test]
fn original_reservations_survive_joined_http_handoffs_and_owner_drop() {
    let _guard = crate::managed::native_test_guard();
    let ports = LocalnetPorts::reserve().unwrap();
    let endpoints: Vec<url::Url> = (0..4)
        .map(|offset| {
            format!("http://127.0.0.1:{}/", ports.base_api + offset)
                .parse()
                .unwrap()
        })
        .collect();
    let owner =
        ReservedHttpListeners::new(ports.clone_api_listeners().unwrap(), &endpoints).unwrap();
    drop(ports);
    assert_reserved(&endpoints);
    let mut first = server(&owner, &endpoints);
    for url in &endpoints {
        assert!(request(url, "/v1/node/capabilities").starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(
            owner.loan(url).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    first.finish();
    assert_eq!(first.requests.lock().unwrap().len(), 4);
    assert_reserved(&endpoints);

    let mut second = server(&owner, &endpoints);
    assert!(
        second.requests.lock().unwrap().is_empty(),
        "fresh phase request census"
    );
    for url in &endpoints {
        assert!(
            request(url, "/v1/bridge/finality/1")
                .starts_with(b"HTTP/1.1 503 Service Unavailable\r\n")
        );
    }
    second.finish();
    assert_eq!(second.requests.lock().unwrap().len(), 4);
    assert_eq!(first.requests.lock().unwrap().len(), 4);
    assert_reserved(&endpoints);

    let weak: Vec<_> = owner.listeners.iter().map(Arc::downgrade).collect();
    let final_phase = server(&owner, &endpoints);
    drop(owner);
    assert_reserved(&endpoints);
    assert!(request(&endpoints[0], "/v1/node/capabilities").starts_with(b"HTTP/1.1 200 OK\r\n"));
    drop(final_phase); // Drop joins all four workers before releasing their original sockets.
    assert!(weak.iter().all(|owner| owner.upgrade().is_none()));
}

#[test]
fn exclusive_loans_refuse_wrong_endpoints_and_roll_back_partial_acquisition() {
    let (owner, endpoints) = fresh();
    let busy = owner.loan(&endpoints[2]).unwrap();
    assert_eq!(
        owner.loan(&endpoints[2]).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        owner.loan_all(&endpoints).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    for index in [0, 1, 3] {
        drop(owner.loan(&endpoints[index]).unwrap());
    }
    let wrong: url::Url = "http://127.0.0.1:1/".parse().unwrap();
    assert_eq!(
        owner.loan(&wrong).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    for wrong in [
        "http://127.0.0.2:1/",
        "https://127.0.0.1:1/",
        "http://user@127.0.0.1:1/",
    ] {
        assert_eq!(
            owner.loan(&wrong.parse().unwrap()).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let mut changed = endpoints.clone();
    changed.swap(0, 1);
    assert_eq!(
        owner.loan_all(&changed).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_reserved(&endpoints);
    drop(busy);
    drop(owner.loan_all(&endpoints).unwrap());
}

#[test]
fn queued_gap_request_is_refused_before_starting_a_fresh_phase() {
    let (owner, endpoints) = fresh();
    let mut socket =
        TcpStream::connect_timeout(&endpoint(&endpoints[2]).unwrap(), Duration::from_secs(2))
            .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .write_all(b"GET /unexpected-gap HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let error = owner.loan_all(&endpoints).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "request queued without an active fixture responder"
    );
    assert!(
        owner
            .listeners
            .iter()
            .all(|owner| !owner.busy.load(Ordering::SeqCst)),
        "all partial loans returned without any worker"
    );
    assert_reserved(&endpoints);
}
