use iroha_logger::{config::LoggerConfiguration, init};

#[tokio::test]
async fn setting_logger_twice_fails() {
    assert!(init(LoggerConfiguration::default()).is_some());
    assert!(init(LoggerConfiguration::default()).is_none());
}
