#![allow(clippy::restriction)]

use iroha_logger::{config::LoggerConfiguration, init};

#[tokio::test]
async fn setting_logger_twice_fails() {
    #[allow(clippy::expect_used)]
    assert!(init(&LoggerConfiguration::default()).is_some());

    #[allow(clippy::expect_used)]
    assert!(init(&LoggerConfiguration::default()).is_none());
}
