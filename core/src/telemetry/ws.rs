use chrono::Local;
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use iroha_logger::telemetry::Telemetry;
use serde_json::Map;
use tokio::sync::mpsc::Receiver;
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::tungstenite::{Error, Message};
use url::Url;

pub async fn start(name: String, url: Url, telemetry: Receiver<Telemetry>) -> Result<()> {
    iroha_logger::info!("Starting telemetry to {}", url);
    let (ws, _) = tokio_tungstenite::connect_async(url).await?;
    let (mut write, _read) = ws.split();
    let mut stream = ReceiverStream::new(telemetry);
    while let Some(telemetry) = stream.next().await {
        match prepare_message(&name, telemetry) {
            Ok(msg) => {
                match write.send(msg).await {
                    Ok(_) => {}
                    Err(Error::AlreadyClosed | Error::ConnectionClosed) => {
                        // TBD: It makes sense to retry connection. Should we wait, should we have limit number of attempts?
                    }
                    Err(_e) => {
                        iroha_logger::error!("send failed: {:?}", _e);
                        // TBD: What is the proper way to signal about it?
                    }
                }
            }
            Err(_e) => {
                iroha_logger::error!("prepare_message failed: {:?}", _e);
                // TBD: What is the proper way to signal about it?
            }
        }
    }
    Ok(())
}

fn prepare_message(name: &String, telemetry: Telemetry) -> Result<Message> {
    enum Msg {
        SystemConnected,
        Other,
    }
    let fields = telemetry.fields.0;
    let msg = fields
        .iter()
        .find_map(|(name, value)| if *name == "msg" { Some(value) } else { None })
        .and_then(|v| {
            v.as_str().map(|v| match v {
                "system.connected" => Msg::SystemConnected,
                _ => Msg::Other,
            })
        })
        .ok_or_else(|| eyre!("Failed to read 'msg'"))?;
    let mut payload: Map<_, _> = fields
        .into_iter()
        .map(|(field, value)| {
            let field = field.to_string();
            let value = if field == "genesis_hash" || field == "best" || field == "finalized_hash" {
                if let Some(hash) = value.as_str() {
                    format!("0x{}", hash).into()
                } else {
                    unreachable!()
                }
            } else {
                value
            };
            (field, value)
        })
        .collect();
    if let Msg::SystemConnected = msg {
        payload.insert("name".into(), name.clone().into());
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
    map.insert("ts".into(), Local::now().to_rfc3339().to_string().into());
    map.insert("payload".into(), payload.into());
    Ok(Message::Binary(serde_json::to_vec(&map)?))
}
