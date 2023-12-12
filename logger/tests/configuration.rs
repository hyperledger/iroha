use std::time::Duration;

use iroha_logger::{
    info,
    telemetry::{Channel, Event, Fields},
    test_logger,
};
use tokio::time;

#[tokio::test]
async fn telemetry_separation_custom() {
    let mut receiver = test_logger()
        .subscribe_on_telemetry(Channel::Regular)
        .await
        .unwrap();
    info!(target: "telemetry::test", a = 2, c = true, d = "this won't be logged");
    info!("This will be logged in bunyan-readable format");
    let telemetry = Event {
        target: "test",
        fields: Fields(vec![
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
