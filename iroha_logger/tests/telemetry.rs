#![allow(clippy::restriction)]

use std::time::Duration;

use async_std::future;
use iroha_logger::{
    config::LoggerConfiguration,
    info, init,
    telemetry::{Telemetry, TelemetryFields},
};

#[async_std::test]
async fn test() {
    let reciever = init(LoggerConfiguration::default()).unwrap();
    info!(target: "telemetry::test", a = 2, c = true, d = "this won't be logged");
    info!("This will be logged");
    let telemetry = Telemetry {
        target: "test",
        fields: TelemetryFields(vec![
            ("a", serde_json::json!(2)),
            ("c", serde_json::json!(true)),
            ("d", serde_json::json!("this won't be logged")),
        ]),
    };
    let recieved = future::timeout(Duration::from_millis(10), reciever.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recieved, telemetry);
}
