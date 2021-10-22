//! Telemetry sent to a server

use chrono::Local;
use eyre::{eyre, Result};
use futures::{Sink, SinkExt, StreamExt};
use iroha_logger::telemetry::Telemetry;
use serde_json::Map;
use tokio::sync::mpsc::Receiver;
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::tungstenite::{Error, Message};

use crate::Configuration;

/// Starts telemetry sending data to a server
/// # Errors
/// Fails if unable to connect to the server
pub async fn start(config: &Configuration, telemetry: Receiver<Telemetry>) -> Result<bool> {
    if let (Some(name), Some(url)) = (&config.name, &config.url) {
        iroha_logger::info!("Starting telemetry to {}", url);
        let (ws, _) = tokio_tungstenite::connect_async(url).await?;
        let name = name.clone();
        tokio::task::spawn(async move {
            let (write, _read) = ws.split();
            run(name, telemetry, write).await;
        });
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn run<S>(name: String, receiver: Receiver<Telemetry>, mut sink: S)
where
    S: SinkExt<Message> + Sink<Message, Error = Error> + Send + Unpin,
{
    let mut stream = ReceiverStream::new(receiver);
    while let Some(telemetry) = stream.next().await {
        match prepare_message(&name, telemetry) {
            Ok(msg) => {
                match sink.send(msg).await {
                    Ok(_) => {}
                    Err(Error::AlreadyClosed | Error::ConnectionClosed) => {
                        iroha_logger::debug!("websocket closed");
                        // TBD: It makes sense to retry connection. Should we wait, should we have limit number of attempts?
                    }
                    Err(e) => {
                        iroha_logger::error!("send failed: {:?}", e);
                        // TBD: What is the proper way to signal about it?
                    }
                }
            }
            Err(e) => {
                iroha_logger::error!("prepare_message failed: {:?}", e);
                // TBD: What is the proper way to signal about it?
            }
        }
    }
}

fn prepare_message(name: &str, telemetry: Telemetry) -> Result<Message> {
    enum Msg {
        SystemConnected,
        Other,
    }
    let fields = telemetry.fields.0;
    let msg = fields
        .iter()
        .find_map(|(name, map)| (*name == "msg").then(|| map))
        .and_then(|v| {
            v.as_str().map(|v| match v {
                "system.connected" => Msg::SystemConnected,
                _ => Msg::Other,
            })
        })
        .ok_or_else(|| eyre!("Failed to read 'msg'"))?;
    let mut payload: Map<_, _> = fields
        .into_iter()
        .map(|(field, map)| {
            let field = field.to_owned();
            let map = if field == "genesis_hash" || field == "best" || field == "finalized_hash" {
                if let Some(hash) = map.as_str() {
                    format!("0x{}", hash).into()
                } else {
                    unreachable!()
                }
            } else {
                map
            };
            (field, map)
        })
        .collect();
    if let Msg::SystemConnected = msg {
        payload.insert("name".into(), name.into());
        payload.insert("chain".into(), "Iroha".into());
        payload.insert("implementation".into(), "".into());
        payload.insert(
            "version".into(),
            format!(
                "{}-{}-{}",
                env!("VERGEN_GIT_SEMVER"),
                env!("VERGEN_GIT_SHA_SHORT"),
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
    map.insert("id".into(), 0.into());
    map.insert("ts".into(), Local::now().to_rfc3339().into());
    map.insert("payload".into(), payload.into());
    Ok(Message::Binary(serde_json::to_vec(&map)?))
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{channel::mpsc::Sender, Sink, StreamExt};
    use iroha_logger::telemetry::{Telemetry, TelemetryFields};
    use serde_json::{Map, Value};
    use tokio_tungstenite::tungstenite::{Error, Message};

    pub struct ManagedSender<T, E> {
        sender: Sender<T>,
        before_send: Box<dyn FnMut() -> Result<(), E> + Send>,
    }

    impl<T, E> ManagedSender<T, E> {
        pub fn new(
            sender: Sender<T>,
            before_send: Box<dyn FnMut() -> Result<(), E> + Send>,
        ) -> Self {
            Self {
                sender,
                before_send,
            }
        }
    }

    impl<T, E> Sink<T> for ManagedSender<T, E> {
        type Error = E;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let this = Pin::into_inner(self);
            match this.sender.poll_ready(cx) {
                Poll::Ready(r) => {
                    Poll::Ready((this.before_send)().map(|_| r.expect("failed to send")))
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

    #[tokio::test]
    async fn run() {
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        let (sender_sink, mut receiver_sink) = futures::channel::mpsc::channel(100);
        let mut send_index = 0;
        let sender_sink = ManagedSender::new(
            sender_sink,
            Box::new(move || {
                if send_index < 2 {
                    send_index += 1;
                    Ok(())
                } else {
                    Err(Error::ConnectionClosed)
                }
            }),
        );
        let run_handle = tokio::task::spawn(super::run("Node".to_owned(), receiver, sender_sink));
        sender
            .send(Telemetry {
                target: "telemetry::test",
                fields: TelemetryFields(vec![
                    ("msg", Value::String("system.connected".to_owned())),
                    (
                        "genesis_hash",
                        Value::String("00000000000000000000000000000000".to_owned()),
                    ),
                ]),
            })
            .await
            .unwrap();
        sender
            .send(Telemetry {
                target: "telemetry::test",
                fields: TelemetryFields(vec![
                    ("msg", Value::String("system.interval".to_owned())),
                    ("peers", Value::Number(10.into())),
                ]),
            })
            .await
            .unwrap();
        sender
            .send(Telemetry {
                target: "telemetry::test",
                fields: TelemetryFields(vec![
                    ("msg", Value::String("system.interval".to_owned())),
                    ("peers", Value::Number(10.into())),
                ]),
            })
            .await
            .unwrap();
        {
            let msg = receiver_sink.next().await.unwrap();
            let bytes = if let Message::Binary(bytes) = msg {
                bytes
            } else {
                panic!()
            };
            let map: Map<String, Value> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(map.get("id"), Some(&Value::Number(0.into())));
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
        {
            let msg = receiver_sink.next().await.unwrap();
            let bytes = if let Message::Binary(bytes) = msg {
                bytes
            } else {
                panic!()
            };
            let map: Map<String, Value> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(map.get("id"), Some(&Value::Number(0.into())));
            assert!(map.contains_key("ts"));
            assert!(map.contains_key("payload"));
            let payload = map.get("payload").unwrap().as_object().unwrap();
            assert_eq!(
                payload.get("msg"),
                Some(&Value::String("system.interval".to_owned()))
            );
            assert_eq!(payload.get("peers"), Some(&Value::Number(10.into())));
        }
        drop(sender);
        run_handle.await.unwrap();
    }
}
