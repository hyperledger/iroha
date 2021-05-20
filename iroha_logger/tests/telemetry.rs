#![allow(clippy::restriction)]

use std::time::Duration;

use iroha_logger::{
    config::LoggerConfiguration,
    info, init,
    telemetry::{Telemetry, TelemetryFields},
};
use tokio::time;

#[tokio::test]
async fn test() {
    let mut reciever = init(LoggerConfiguration::default()).unwrap();
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
    let output = time::timeout(Duration::from_millis(10), reciever.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output, telemetry);
}
