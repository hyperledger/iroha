//! Lazy native-pool ownership, fallible initialization and pre-dispatch deadline controls.

use super::*;
use std::{
    cell::Cell,
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

thread_local! {
    static CONSTRUCTIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn record_construction() {
    CONSTRUCTIONS.with(|value| {
        if let Some(count) = value.get() {
            value.set(Some(count.checked_add(1).expect("test construction count")));
        }
    });
}

struct Count(Option<usize>);
impl Count {
    fn start() -> Self {
        Self(CONSTRUCTIONS.with(|value| value.replace(Some(0))))
    }
    fn value() -> usize {
        CONSTRUCTIONS.with(|value| value.get().expect("active test count"))
    }
}
impl Drop for Count {
    fn drop(&mut self) {
        CONSTRUCTIONS.with(|value| value.set(self.0));
    }
}

fn request(url: &Url, direct_loopback: bool, timeout: Duration) -> TransportRequest {
    TransportRequest {
        method: Method::POST,
        url: url.clone(),
        headers: vec![],
        body: b"one exact request".to_vec(),
        timeout: Some(timeout),
        max_response_bytes: 16,
        direct_loopback,
    }
}

fn server(requests: usize) -> (Url, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/request", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    (url, serve(listener, requests))
}

fn serve(listener: TcpListener, requests: usize) -> thread::JoinHandle<usize> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = 0;
        while seen < requests && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = [0_u8; 2048];
                    assert!(stream.read(&mut bytes).unwrap() > 0);
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .unwrap();
                    seen += 1;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("test listener: {error}"),
            }
        }
        seen
    })
}

#[tokio::test]
async fn construction_and_cloning_do_not_initialize_native_pools() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DefaultHttpTransport>();
    assert_send_sync::<ReqwestHttpTransport>();
    let _count = Count::start();
    let transport = DefaultHttpTransport::new();
    let clone = transport.clone();
    let bounded = clone.with_deadline(Instant::now() + Duration::from_secs(5));
    let _public = crate::http::PublicHttpClient::new();
    assert!(transport.shares_pools_with(&bounded));
    assert_eq!(Count::value(), 0);
    let raw = ReqwestHttpTransport::default();
    assert!(raw.asynchronous.get().is_none());
    assert!(raw.asynchronous_direct_loopback.get().is_none());
    assert!(raw.blocking.get().is_none());
    assert!(raw.blocking_direct_loopback.get().is_none());
}

#[tokio::test]
async fn first_send_initializes_only_selected_pool_and_clones_reuse_it() {
    let _count = Count::start();
    let pools = Arc::new(ReqwestHttpTransport::default());
    let transport = DefaultHttpTransport::from_shared(pools.clone());
    let clone = transport.clone();
    let untouched = ReqwestHttpTransport::default();
    let (url, server) = server(3);
    for sender in [&transport, &clone] {
        let response = sender
            .send(request(&url, true, Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(response.body(), b"ok");
    }
    assert_eq!(Count::value(), 1);
    assert!(pools.asynchronous.get().is_none());
    assert!(pools.asynchronous_direct_loopback.get().is_some());
    assert!(pools.blocking.get().is_none());
    assert!(pools.blocking_direct_loopback.get().is_none());
    let response = transport
        .send(request(&url, false, Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(response.body(), b"ok");
    assert_eq!(Count::value(), 2);
    assert!(pools.asynchronous.get().is_some());
    assert!(untouched.asynchronous.get().is_none());
    assert!(untouched.asynchronous_direct_loopback.get().is_none());
    assert_eq!(server.join().unwrap(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_sends_share_one_successful_initialization() {
    let pools = Arc::new(ReqwestHttpTransport::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let (url, server) = server(2);
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let pools = Arc::clone(&pools);
        let calls = Arc::clone(&calls);
        let barrier = Arc::clone(&barrier);
        let request = request(&url, true, Duration::from_secs(5));
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            pools
                .send_async_with(request, |direct| {
                    assert!(direct);
                    calls.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(30));
                    build_direct_loopback_async_http_client()
                })
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().body(), b"ok");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(pools.asynchronous.get().is_none());
    assert!(pools.asynchronous_direct_loopback.get().is_some());
    assert_eq!(server.join().unwrap(), 2);
}

#[tokio::test]
async fn failed_initialization_preserves_error_and_later_request_retries_construction() {
    let pools = ReqwestHttpTransport::default();
    let (url, server) = server(1);
    let failed = pools
        .send_async_with(request(&url, true, Duration::from_secs(5)), |_| {
            Err(crate::Error::TransportConstruction {
                details: "controlled native construction failure".into(),
            })
        })
        .await
        .unwrap_err();
    assert!(
        matches!(failed.downcast_ref::<crate::Error>(), Some(crate::Error::TransportConstruction { details }) if details == "controlled native construction failure")
    );
    assert!(pools.asynchronous_direct_loopback.get().is_none());
    let response = pools
        .send_async_with(request(&url, true, Duration::from_secs(5)), |direct| {
            assert!(direct);
            build_direct_loopback_async_http_client()
        })
        .await
        .unwrap();
    assert_eq!(response.body(), b"ok");
    assert!(pools.asynchronous_direct_loopback.get().is_some());
    assert_eq!(server.join().unwrap(), 1);
}

#[tokio::test]
async fn initialization_expiry_refuses_dispatch_but_preserves_the_successful_pool() {
    let pools = ReqwestHttpTransport::default();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url: Url = format!("http://{}/request", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let client = build_direct_loopback_async_http_client().unwrap();
    let error = pools
        .send_async_with(request(&url, true, Duration::from_millis(1)), |_| {
            thread::sleep(Duration::from_millis(30));
            Ok(client)
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        ErrorKind::TimedOut
    );
    assert!(pools.asynchronous_direct_loopback.get().is_some());
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
    let server = serve(listener, 1);
    let response = pools
        .send_async_with(request(&url, true, Duration::from_secs(5)), |_| {
            panic!("successful pool must remain shared after one request expires")
        })
        .await
        .unwrap();
    assert_eq!(response.body(), b"ok");
    assert_eq!(server.join().unwrap(), 1);
}

#[tokio::test]
async fn expired_outer_deadline_refuses_before_any_native_initialization() {
    let pools = Arc::new(ReqwestHttpTransport::default());
    let transport = DefaultHttpTransport::from_shared(pools.clone()).with_deadline(Instant::now());
    let url = "http://127.0.0.1:1/request".parse().unwrap();
    let error = transport
        .send(request(&url, true, Duration::from_secs(5)))
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        ErrorKind::TimedOut
    );
    assert!(pools.asynchronous.get().is_none());
    assert!(pools.asynchronous_direct_loopback.get().is_none());
    assert!(pools.blocking.get().is_none());
    assert!(pools.blocking_direct_loopback.get().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_initialization_waiter_does_not_dispatch_or_cancel_shared_owner() {
    let pools = Arc::new(ReqwestHttpTransport::default());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url: Url = format!("http://{}/request", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let owner_pool = Arc::clone(&pools);
    let owner_request = request(&url, true, Duration::from_secs(5));
    let owner = tokio::spawn(async move {
        owner_pool
            .send_async_with(owner_request, move |direct| {
                assert!(direct);
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                build_direct_loopback_async_http_client()
            })
            .await
            .unwrap()
    });
    entered_rx.await.unwrap();
    let waiter_pool = Arc::clone(&pools);
    let waiter_request = request(&url, true, Duration::from_secs(5));
    let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
    let waiter = tokio::spawn(async move {
        let mut send = Box::pin(waiter_pool.send_async_with(waiter_request, |_| {
            panic!("waiting request must not run a second initializer")
        }));
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(send.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        polled_tx.send(()).unwrap();
        send.await
    });
    polled_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
    let server = serve(listener, 2);
    release_tx.send(()).unwrap();
    assert_eq!(owner.await.unwrap().body(), b"ok");
    assert!(pools.asynchronous_direct_loopback.get().is_some());
    let response = pools
        .send_async_with(request(&url, true, Duration::from_secs(5)), |_| {
            panic!("the surviving owner's successful pool remains available")
        })
        .await
        .unwrap();
    assert_eq!(response.body(), b"ok");
    assert_eq!(server.join().unwrap(), 2);
}
