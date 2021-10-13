use iroha_logger::{config::LoggerConfiguration, init};

#[tokio::test]
async fn setting_logger_twice_fails() {
    // This function must be run after `test_telemetry_separation_default`.
    let receiver = init(LoggerConfiguration::default());
    match receiver {
        Some(_) => assert!(true),
        None => assert!(false),
    }
    let receiver = init(LoggerConfiguration::default());
    match receiver {
        Some(_) => assert!(false),
        None => assert!(true),
    }
}
