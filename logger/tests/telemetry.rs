#![allow(clippy::restriction)]

use std::time::Duration;

use iroha_config::base::proxy::Builder;
use iroha_logger::{info, init, ConfigurationProxy, Telemetry, TelemetryFields};
use tokio::time;

#[tokio::test]
async fn telemetry_separation_default() {
    let (mut receiver, _) = init(&ConfigurationProxy::default().build().unwrap())
        .unwrap()
        .unwrap();
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
    let output = time::timeout(Duration::from_millis(10), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output, telemetry);
}
