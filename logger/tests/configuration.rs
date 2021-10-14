#![allow(clippy::restriction)]

use std::time::Duration;

use iroha_logger::{
    config::LoggerConfiguration,
    info, init,
    telemetry::{Telemetry, TelemetryFields},
};
use tokio::time;

#[tokio::test]
async fn telemetry_separation_custom() {
    let config = LoggerConfiguration {
        max_log_level: iroha_logger::config::LevelEnv::TRACE,
        telemetry_capacity: 100,
        compact_mode: true,
        log_file_path: Some("/dev/stdout".into()),
    };
    let mut reciever = init(&config).unwrap().unwrap();
    info!(target: "telemetry::test", a = 2, c = true, d = "this won't be logged");
    info!("This will be logged in bunyan-readable format");
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
