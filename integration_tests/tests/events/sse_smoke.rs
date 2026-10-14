//! SSE smoke test: verify that `/v1/events/sse` streams trigger and data events.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::addr::SocketAddr as IrohaSocketAddr;
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::ALICE_ID;
use norito::json::{self, Value as JsonValue};
use std::{
    io::{BufRead, BufReader, ErrorKind, Write},
    net::{TcpStream, ToSocketAddrs},
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, Instant},
};
// Match the client status timeout so slow test networks don't drop SSE readers early.
const SSE_TIMEOUT: Duration = Duration::from_secs(300);
struct SseReader {
    rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
}
impl Deref for SseReader {
    type Target = Receiver<String>;
    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}
impl Drop for SseReader {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}
fn sse_reader_should_stop(deadline: Instant, shutdown: &AtomicBool) -> bool {
    shutdown.load(Ordering::Acquire) || Instant::now() >= deadline
}
fn is_read_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}
fn parse_sse_data_line(line: &str) -> Option<&str> {
    let line = line.trim_end_matches(['\r', '\n']);
    let rest = line.strip_prefix("data:")?;
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let rest = rest.trim();
    if rest.is_empty() { None } else { Some(rest) }
}
/// Wait for the SSE reader to establish a connection (the reader emits a
/// synthetic `{"connected":true}` payload when headers have been consumed).
fn wait_for_sse_ready(rx: &Receiver<String>) -> Result<()> {
    wait_for_sse(rx, SSE_TIMEOUT, |val| {
        val.get("connected").and_then(JsonValue::as_bool) == Some(true)
    })
    .map(|_| ())
}
#[test]
fn sse_smoke_scenarios() -> Result<()> {
    use iroha::data_model::events::time::{ExecutionTime, TimeEventFilter};
    let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(
        NetworkBuilder::new().with_min_peers(4),
        stringify!(sse_smoke_scenarios),
    )?
    else {
        return Ok(());
    };
    let peer = network.peer();
    let client = peer.client();
    // Scenario 1: Execute trigger event + data event.
    {
        let rx = spawn_sse_reader(peer.api_address());
        wait_for_sse_ready(&rx)?;
        let trigger_id: TriggerId = "sse_smoke_trigger_exec".parse()?;
        let asset_id = AssetId::new(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            ),
            ALICE_ID.clone(),
        );
        let asset_id_literal = asset_id.canonical_literal();
        let register = Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                vec![InstructionBox::from(Mint::asset_quantity(1_u32, asset_id))],
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(ALICE_ID.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        if sandbox::handle_result(
            client.submit(
                register,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            ),
            stringify!(sse_emits_execute_trigger_event),
        )?
        .is_none()
        {
            return Ok(());
        }
        if sandbox::handle_result(
            client.submit(
                ExecuteTrigger::new(trigger_id),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            ),
            stringify!(sse_emits_execute_trigger_event),
        )?
        .is_none()
        {
            return Ok(());
        }
        let result: Result<()> = (|| {
            let exec_evt = wait_for_sse(&rx, SSE_TIMEOUT, |val| {
                summary_contains(val, "ExecuteTriggerEvent")
            })?;
            assert_eq!(exec_evt["category"].as_str(), Some("Other"));
            let data_evt = wait_for_sse(&rx, SSE_TIMEOUT, |val| {
                val["category"].as_str() == Some("Data")
                    && summary_contains(val, "Asset(Added")
                    && summary_contains(val, &asset_id_literal)
            })?;
            assert_eq!(data_evt["category"].as_str(), Some("Data"));
            Ok(())
        })();
        if sandbox::handle_result(result, stringify!(sse_emits_execute_trigger_event))?.is_none() {
            return Ok(());
        }
    }
    // Scenario 2: Time trigger + metadata event.
    {
        let rx = spawn_sse_reader(peer.api_address());
        wait_for_sse_ready(&rx)?;
        let key: Name = "sse_tick".parse()?;
        let time_trigger = Trigger::new(
            "sse_time_trigger_event".parse()?,
            Action::new(
                vec![InstructionBox::from(SetKeyValue::account(
                    ALICE_ID.clone(),
                    key.clone(),
                    Json::from(norito::json!("tick")),
                ))],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        if sandbox::handle_result(
            client.submit(
                Register::trigger(time_trigger),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            ),
            stringify!(sse_captures_time_trigger_and_metadata_events),
        )?
        .is_none()
        {
            return Ok(());
        }
        if sandbox::handle_result(
            client.submit(
                Log::new(Level::INFO, "trigger tick".to_string()),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            ),
            stringify!(sse_captures_time_trigger_and_metadata_events),
        )?
        .is_none()
        {
            return Ok(());
        }
        let result: Result<()> = (|| {
            let time_evt =
                wait_for_sse(&rx, SSE_TIMEOUT, |val| summary_contains(val, "TimeEvent"))?;
            assert_eq!(time_evt["category"].as_str(), Some("Other"));
            let meta_evt = wait_for_sse(&rx, SSE_TIMEOUT, |val| {
                val["category"].as_str() == Some("Data")
                    && summary_contains(val, "MetadataInserted")
                    && summary_contains(val, key.as_ref())
            })?;
            assert_eq!(meta_evt["category"].as_str(), Some("Data"));
            Ok(())
        })();
        if sandbox::handle_result(
            result,
            stringify!(sse_captures_time_trigger_and_metadata_events),
        )?
        .is_none()
        {
            return Ok(());
        }
    }
    Ok(())
}
fn spawn_sse_reader(addr: IrohaSocketAddr) -> SseReader {
    let (tx, rx) = mpsc::channel::<String>();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    std::thread::spawn(move || {
        let target = addr
            .to_socket_addrs()
            .expect("resolve SSE endpoint")
            .next()
            .expect("SSE endpoint yields socket address");
        let host = target.to_string();
        let deadline = Instant::now() + SSE_TIMEOUT;
        let mut backoff = Duration::from_millis(200);
        // Retry connecting until the server is ready or the overall SSE timeout elapses.
        while !sse_reader_should_stop(deadline, &shutdown_flag) {
            if let Ok(mut stream) = TcpStream::connect(target) {
                stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
                let req = format!(
                    "GET /v1/events/sse HTTP/1.1\r\nHost: {host}\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n"
                );
                if stream.write_all(req.as_bytes()).is_err() {
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, Duration::from_secs(1));
                    continue;
                }
                let _ = stream.flush();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                // Consume headers.
                let mut headers_complete = false;
                loop {
                    if sse_reader_should_stop(deadline, &shutdown_flag) {
                        return;
                    }
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            if line.trim_end().is_empty() {
                                headers_complete = true;
                                break;
                            }
                        }
                        Err(err) if is_read_timeout(&err) => continue,
                        Err(_) => break,
                    }
                }
                if !headers_complete {
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, Duration::from_secs(1));
                    continue;
                }
                // Signal readiness so the test can submit transactions only after the
                // SSE connection is live.
                if tx.send(r#"{"connected":true}"#.to_owned()).is_err() {
                    return;
                }
                // Stream SSE payloads; if the server closes the connection unexpectedly,
                // retry until the overall deadline.
                loop {
                    if sse_reader_should_stop(deadline, &shutdown_flag) {
                        return;
                    }
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Err(err) if is_read_timeout(&err) => continue,
                        Err(_) => break,
                        Ok(_) => {
                            if let Some(rest) = parse_sse_data_line(&line) {
                                if tx.send(rest.to_owned()).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            } else {
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, Duration::from_secs(1));
            }
        }
    });
    SseReader { rx, shutdown }
}
fn wait_for_sse<F>(rx: &Receiver<String>, timeout: Duration, predicate: F) -> Result<JsonValue>
where
    F: Fn(&JsonValue) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(eyre::eyre!(
                "timed out waiting for SSE payload matching predicate"
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        let raw = match rx.recv_timeout(remaining) {
            Ok(raw) => raw,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(eyre::eyre!("SSE channel closed before matching event"));
            }
        };
        let val: JsonValue = json::from_str(raw.trim()).expect("valid SSE JSON");
        if predicate(&val) {
            return Ok(val);
        }
    }
}
fn summary_contains(val: &JsonValue, needle: &str) -> bool {
    val.get("summary")
        .and_then(JsonValue::as_str)
        .is_some_and(|s| s.contains(needle))
}
#[test]
fn sse_reader_should_stop_honors_deadline_and_shutdown() {
    let shutdown = AtomicBool::new(false);
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("checked_sub should not underflow");
    assert!(sse_reader_should_stop(expired, &shutdown));
    let future = Instant::now() + Duration::from_secs(1);
    assert!(!sse_reader_should_stop(future, &shutdown));
    shutdown.store(true, Ordering::Release);
    assert!(sse_reader_should_stop(future, &shutdown));
}
#[test]
fn is_read_timeout_matches_timeout_kinds() {
    assert!(is_read_timeout(&std::io::Error::new(
        ErrorKind::TimedOut,
        "timed out"
    )));
    assert!(is_read_timeout(&std::io::Error::new(
        ErrorKind::WouldBlock,
        "would block"
    )));
    assert!(!is_read_timeout(&std::io::Error::new(
        ErrorKind::Other,
        "other"
    )));
}
#[test]
fn parse_sse_data_line_accepts_optional_space() {
    assert_eq!(
        parse_sse_data_line("data: {\"ok\":true}\r\n"),
        Some("{\"ok\":true}")
    );
    assert_eq!(
        parse_sse_data_line("data:{\"ok\":true}\n"),
        Some("{\"ok\":true}")
    );
    assert_eq!(parse_sse_data_line("data:\r\n"), None);
    assert_eq!(parse_sse_data_line(": comment\n"), None);
}
#[test]
fn sse_reader_connects_and_reads_data_lines() -> Result<()> {
    use std::net::TcpListener;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    let (data_tx, data_rx): (Sender<()>, Receiver<()>) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept SSE client");
        let mut reader = BufReader::new(stream.try_clone().expect("clone SSE stream"));
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => return,
                Ok(_) if line.trim_end().is_empty() => break,
                Ok(_) => {}
                Err(_) => return,
            }
        }
        let headers = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Cache-Control: no-cache\r\n",
            "\r\n"
        );
        stream.write_all(headers.as_bytes()).expect("write headers");
        let _ = stream.flush();
        if data_rx.recv_timeout(SSE_TIMEOUT).is_err() {
            return;
        }
        stream
            .write_all(b"data:{\"noop\":true}\n\n")
            .expect("write data");
        stream
            .write_all(b"data: {\"ok\":true}\n\n")
            .expect("write data");
        let _ = stream.flush();
        std::thread::sleep(Duration::from_millis(50));
    });
    let rx = spawn_sse_reader(addr.into());
    wait_for_sse_ready(&rx)?;
    let _ = data_tx.send(());
    let payload = wait_for_sse(&rx, SSE_TIMEOUT, |val| {
        val.get("ok").and_then(JsonValue::as_bool) == Some(true)
            || val.get("noop").and_then(JsonValue::as_bool) == Some(true)
    })?;
    let saw_ok = payload.get("ok").and_then(JsonValue::as_bool) == Some(true);
    let saw_noop = payload.get("noop").and_then(JsonValue::as_bool) == Some(true);
    assert!(saw_ok || saw_noop, "expected ok or noop payload");
    drop(rx);
    let _ = server.join();
    Ok(())
}
