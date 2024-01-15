//! Telemetry sent to a server

use chrono::Local;
use eyre::{eyre, Result};
use futures::{stream::SplitSink, Sink, SinkExt, StreamExt};
use iroha_config::parameters::telemetry::RegularTelemetryConfig;
use iroha_logger::telemetry::Event as Telemetry;
use serde_json::Map;
use tokio::{
    net::TcpStream,
    sync::{broadcast, mpsc},
    task::JoinHandle,
};
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};
use tokio_tungstenite::{
    tungstenite::{Error, Message},
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

use crate::retry_period::RetryPeriod;

type WebSocketSplitSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

const INTERNAL_CHANNEL_CAPACITY: usize = 10;

/// Starts telemetry sending data to a server
/// # Errors
/// Fails if unable to connect to the server
pub async fn start(
    RegularTelemetryConfig {
        name,
        url,
        max_retry_delay_exponent,
        min_retry_period,
    }: RegularTelemetryConfig,
    telemetry: broadcast::Receiver<Telemetry>,
) -> Result<JoinHandle<()>> {
    iroha_logger::info!(%url, "Starting telemetry");
    let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let (write, _read) = ws.split();
    let (internal_sender, internal_receiver) = mpsc::channel(INTERNAL_CHANNEL_CAPACITY);
    let client = Client::new(
        name,
        write,
        WebsocketSinkFactory::new(url),
        RetryPeriod::new(min_retry_period, max_retry_delay_exponent),
        internal_sender,
    );
    let handle = tokio::task::spawn(async move {
        client.run(telemetry, internal_receiver).await;
    });

    Ok(handle)
}

struct Client<S, F> {
    name: String,
    sink_factory: F,
    retry_period: RetryPeriod,
    internal_sender: mpsc::Sender<InternalMessage>,
    sink: Option<S>,
    init_msg: Option<Message>,
}

impl<S, F> Client<S, F>
where
    S: SinkExt<Message> + Sink<Message, Error = Error> + Send + Unpin,
    F: SinkFactory<Sink = S> + Send,
{
    pub fn new(
        name: String,
        sink: S,
        sink_factory: F,
        retry_period: RetryPeriod,
        internal_sender: mpsc::Sender<InternalMessage>,
    ) -> Self {
        Self {
            name,
            sink_factory,
            retry_period,
            internal_sender,
            sink: Some(sink),
            init_msg: None,
        }
    }

    pub async fn run(
        mut self,
        receiver: broadcast::Receiver<Telemetry>,
        internal_receiver: mpsc::Receiver<InternalMessage>,
    ) {
        let mut stream = BroadcastStream::new(receiver).fuse();
        let mut internal_stream = ReceiverStream::new(internal_receiver).fuse();
        loop {
            tokio::select! {
                msg = stream.next() => {
                    if let Some(Ok(msg)) = msg {
                        self.on_telemetry(msg).await;
                    } else {
                        break;
                    }
                }
                msg = internal_stream.next() => {
                    if matches!(msg, Some(InternalMessage::Reconnect)) {
                        self.on_reconnect().await;
                    }
                }
            }
        }
    }

    async fn on_telemetry(&mut self, telemetry: Telemetry) {
        match prepare_message(&self.name, telemetry) {
            Ok((msg, msg_kind)) => {
                if matches!(msg_kind, Some(MessageKind::Initialization)) {
                    self.init_msg = Some(msg.clone());
                }
                self.send_message(msg).await;
            }
            Err(error) => {
                iroha_logger::error!(%error, "prepare_message failed");
            }
        }
    }

    async fn on_reconnect(&mut self) {
        if let Ok(sink) = self.sink_factory.create().await {
            if let Some(msg) = self.init_msg.as_ref() {
                iroha_logger::debug!("Reconnected telemetry");
                self.sink = Some(sink);
                let msg = msg.clone();
                self.send_message(msg).await;
            } else {
                // The reconnect is required if sending a message fails.
                // The first message to be sent is initialization.
                // The path is assumed to be unreachable.
                iroha_logger::error!(
                    "Cannot reconnect telemetry because there is no initialization message"
                );
            }
        } else {
            self.schedule_reconnect();
        }
    }

    async fn send_message(&mut self, msg: Message) {
        if let Some(sink) = self.sink.as_mut() {
            match sink.send(msg).await {
                Ok(()) => {}
                Err(Error::AlreadyClosed | Error::ConnectionClosed) => {
                    iroha_logger::debug!("Closed connection to telemetry");
                    self.sink = None;
                    self.schedule_reconnect();
                }
                Err(error) => {
                    iroha_logger::error!(%error, "send failed");
                }
            }
        }
    }

    fn schedule_reconnect(&mut self) {
        self.retry_period.increase_exponent();
        let period = self.retry_period.period();
        iroha_logger::debug!(
            "Scheduled reconnecting to telemetry in {} seconds",
            period.as_secs()
        );
        let sender = self.internal_sender.clone();
        tokio::task::spawn(async move {
            tokio::time::sleep(period).await;
            let _ = sender.send(InternalMessage::Reconnect).await;
        });
    }
}

#[derive(Debug)]
enum InternalMessage {
    Reconnect,
}

fn prepare_message(name: &str, telemetry: Telemetry) -> Result<(Message, Option<MessageKind>)> {
    let fields = telemetry.fields.0;
    let msg_kind = fields
        .iter()
        .find_map(|(this_name, map)| (*this_name == "msg").then_some(map))
        .and_then(|v| {
            v.as_str().map(|val| match val {
                "system.connected" => Some(MessageKind::Initialization),
                _ => None,
            })
        })
        .ok_or_else(|| eyre!("Failed to read 'msg'"))?;
    let mut payload: Map<_, _> = fields
        .into_iter()
        .map(|(field, map)| {
            let field = field.to_owned();
            let map = if field == "genesis_hash" || field == "best" || field == "finalized_hash" {
                map.as_str()
                    .map_or_else(|| unreachable!(), |hash| format!("0x{hash}").into())
            } else {
                map
            };
            (field, map)
        })
        .collect();
    if matches!(msg_kind, Some(MessageKind::Initialization)) {
        payload.insert("name".into(), name.into());
        payload.insert("chain".into(), "Iroha".into());
        payload.insert("implementation".into(), "".into());
        payload.insert(
            "version".into(),
            format!(
                "{}-{}-{}",
                env!("CARGO_PKG_VERSION"),
                env!("VERGEN_GIT_SHA"),
                env!("VERGEN_CARGO_TARGET_TRIPLE")
            )
            .into(),
        );
        payload.insert("config".into(), "".into());
        payload.insert("authority".into(), false.into());
        payload.insert(
            "startup_time".into(),
            Local::now().timestamp_millis().to_string().into(),
        );
        payload.insert("network_id".into(), "".into());
    }
    let mut map = Map::new();
    map.insert("id".into(), 0_i32.into());
    map.insert("ts".into(), Local::now().to_rfc3339().into());
    map.insert("payload".into(), payload.into());
    let msg = Message::Binary(serde_json::to_vec(&map)?);
    Ok((msg, msg_kind))
}

#[derive(Debug, Clone, Copy)]
enum MessageKind {
    Initialization,
}

#[async_trait::async_trait]
trait SinkFactory {
    type Sink: SinkExt<Message> + Sink<Message, Error = Error> + Send + Unpin;

    async fn create(&mut self) -> Result<Self::Sink>;
}

struct WebsocketSinkFactory {
    url: Url,
}

impl WebsocketSinkFactory {
    #[inline]
    pub const fn new(url: Url) -> Self {
        Self { url }
    }
}

#[async_trait::async_trait]
impl SinkFactory for WebsocketSinkFactory {
    type Sink = WebSocketSplitSink;

    async fn create(&mut self) -> Result<Self::Sink> {
        let (ws, _) = tokio_tungstenite::connect_async(&self.url).await?;
        let (write, _) = ws.split();
        Ok(write)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        task::{Context, Poll},
        time::Duration,
    };

    use eyre::{eyre, Result};
    use futures::{Sink, StreamExt};
    use iroha_logger::telemetry::{Event, Fields};
    use serde_json::{Map, Value};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::{Error, Message};

    use crate::ws::{Client, RetryPeriod, SinkFactory};

    #[derive(Clone)]
    pub struct FallibleSender<T, F> {
        sender: futures::channel::mpsc::Sender<T>,
        before_send: F,
    }

    impl<T, F> FallibleSender<T, F> {
        pub fn new(sender: futures::channel::mpsc::Sender<T>, before_send: F) -> Self {
            Self {
                sender,
                before_send,
            }
        }
    }

    impl<T, E, F> Sink<T> for FallibleSender<T, F>
    where
        F: FnMut() -> Result<(), E> + Unpin,
    {
        type Error = E;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let this = Pin::into_inner(self);
            match this.sender.poll_ready(cx) {
                Poll::Ready(r) => {
                    let result = (this.before_send)().map(|()| r.expect("failed to send"));
                    Poll::Ready(result)
                }
                Poll::Pending => Poll::Pending,
            }
        }

        fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
            let this = Pin::into_inner(self);
            this.sender.start_send(item).map_err(|_err| unreachable!())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let this = Pin::into_inner(self);
            Pin::new(&mut this.sender)
                .poll_flush(cx)
                .map_err(|_err| unreachable!())
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let this = Pin::into_inner(self);
            Pin::new(&mut this.sender)
                .poll_close(cx)
                .map_err(|_err| unreachable!())
        }
    }

    struct MockSinkFactory<F> {
        fail: Arc<AtomicBool>,
        sender: FallibleSender<Message, F>,
    }

    #[async_trait::async_trait]
    impl<F> SinkFactory for MockSinkFactory<F>
    where
        F: FnMut() -> Result<(), Error> + Clone + Send + Unpin,
    {
        type Sink = FallibleSender<Message, F>;

        async fn create(&mut self) -> Result<Self::Sink> {
            if self.fail.load(Ordering::SeqCst) {
                Err(eyre!("failed to create"))
            } else {
                Ok(self.sender.clone())
            }
        }
    }

    struct Suite {
        fail_send: Arc<AtomicBool>,
        fail_factory_create: Arc<AtomicBool>,
        telemetry_sender: tokio::sync::broadcast::Sender<Event>,
        message_receiver: futures::channel::mpsc::Receiver<Message>,
    }

    impl Suite {
        pub fn new() -> (Self, JoinHandle<()>) {
            let (telemetry_sender, telemetry_receiver) = tokio::sync::broadcast::channel(100);
            let (message_sender, message_receiver) = futures::channel::mpsc::channel(100);
            let fail_send = Arc::new(AtomicBool::new(false));
            let message_sender = {
                let fail = Arc::clone(&fail_send);
                FallibleSender::new(message_sender, move || {
                    if fail.load(Ordering::SeqCst) {
                        Err(Error::ConnectionClosed)
                    } else {
                        Ok(())
                    }
                })
            };
            let fail_factory_create = Arc::new(AtomicBool::new(false));
            let (internal_sender, internal_receiver) = tokio::sync::mpsc::channel(10);
            let run_handle = {
                let client = Client::new(
                    "node".to_owned(),
                    message_sender.clone(),
                    MockSinkFactory {
                        fail: Arc::clone(&fail_factory_create),
                        sender: message_sender,
                    },
                    RetryPeriod::new(Duration::from_secs(1), 0),
                    internal_sender,
                );
                tokio::task::spawn(async move {
                    client.run(telemetry_receiver, internal_receiver).await;
                })
            };
            let me = Self {
                fail_send,
                fail_factory_create,
                telemetry_sender,
                message_receiver,
            };
            (me, run_handle)
        }
    }

    fn system_connected_telemetry() -> Event {
        Event {
            target: "telemetry::test",
            fields: Fields(vec![
                ("msg", Value::String("system.connected".to_owned())),
                (
                    "genesis_hash",
                    Value::String("00000000000000000000000000000000".to_owned()),
                ),
            ]),
        }
    }

    fn system_interval_telemetry(peers: u64) -> Event {
        Event {
            target: "telemetry::test",
            fields: Fields(vec![
                ("msg", Value::String("system.interval".to_owned())),
                ("peers", Value::Number(peers.into())),
            ]),
        }
    }

    async fn send_succeeds_with_suite(suite: Suite) {
        let Suite {
            telemetry_sender,
            mut message_receiver,
            ..
        } = suite;

        // The first message is `initialization`
        telemetry_sender.send(system_connected_telemetry()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        {
            let msg = message_receiver.next().await.unwrap();
            let Message::Binary(bytes) = msg else {
                panic!()
            };
            let map: Map<String, Value> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(map.get("id"), Some(&Value::Number(0_i32.into())));
            assert!(map.contains_key("ts"));
            let payload = map.get("payload").unwrap().as_object().unwrap();
            assert_eq!(
                payload.get("msg"),
                Some(&Value::String("system.connected".to_owned()))
            );
            assert_eq!(
                payload.get("genesis_hash"),
                Some(&Value::String(
                    "0x00000000000000000000000000000000".to_owned()
                ))
            );
            assert!(payload.contains_key("chain"));
            assert!(payload.contains_key("implementation"));
            assert!(payload.contains_key("version"));
            assert!(payload.contains_key("config"));
            assert!(payload.contains_key("authority"));
            assert!(payload.contains_key("startup_time"));
            assert!(payload.contains_key("network_id"));
        }

        // The second message is `update`
        telemetry_sender.send(system_interval_telemetry(2)).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        {
            let msg = message_receiver.next().await.unwrap();
            let Message::Binary(bytes) = msg else {
                panic!()
            };
            let map: Map<String, Value> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(map.get("id"), Some(&Value::Number(0_i32.into())));
            assert!(map.contains_key("ts"));
            assert!(map.contains_key("payload"));
            let payload = map.get("payload").unwrap().as_object().unwrap();
            assert_eq!(
                payload.get("msg"),
                Some(&Value::String("system.interval".to_owned()))
            );
            assert_eq!(payload.get("peers"), Some(&Value::Number(2_i32.into())));
        }
    }

    async fn reconnect_fails_with_suite(suite: Suite) {
        let Suite {
            fail_send,
            fail_factory_create,
            telemetry_sender,
            mut message_receiver,
        } = suite;

        // Fail sending the first message
        fail_send.store(true, Ordering::SeqCst);
        telemetry_sender.send(system_connected_telemetry()).unwrap();
        message_receiver.try_next().unwrap_err();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The second message is not sent because the sink is reset
        fail_send.store(false, Ordering::SeqCst);
        telemetry_sender.send(system_interval_telemetry(1)).unwrap();
        message_receiver.try_next().unwrap_err();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Fail the reconnection
        fail_factory_create.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;

        // The third message is not sent because the sink is not created yet
        telemetry_sender.send(system_interval_telemetry(1)).unwrap();
        message_receiver.try_next().unwrap_err();
    }

    async fn send_after_reconnect_fails_with_suite(suite: Suite) {
        let Suite {
            fail_send,
            telemetry_sender,
            mut message_receiver,
            ..
        } = suite;

        // Fail sending the first message
        fail_send.store(true, Ordering::SeqCst);
        telemetry_sender.send(system_connected_telemetry()).unwrap();
        message_receiver.try_next().unwrap_err();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The second message is not sent because the sink is reset
        fail_send.store(false, Ordering::SeqCst);
        telemetry_sender.send(system_interval_telemetry(1)).unwrap();
        message_receiver.try_next().unwrap_err();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Fail sending the first message after reconnect
        fail_send.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        message_receiver.try_next().unwrap_err();

        // The message is sent
        fail_send.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        message_receiver.try_next().unwrap();
    }

    macro_rules! test_with_suite {
        ($ident:ident, $future:ident) => {
            #[tokio::test]
            async fn $ident() {
                let (suite, run_handle) = Suite::new();
                $future(suite).await;
                run_handle.await.unwrap();
            }
        };
    }

    test_with_suite!(send_succeeds, send_succeeds_with_suite);
    test_with_suite!(reconnect_fails, reconnect_fails_with_suite);
    test_with_suite!(
        send_after_reconnect_fails,
        send_after_reconnect_fails_with_suite
    );
}
