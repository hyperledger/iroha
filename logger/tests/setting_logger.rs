#![allow(clippy::restriction, clippy::expect_used)]

use iroha_logger::{config::LoggerConfiguration, init};

#[tokio::test]
async fn setting_logger_twice_fails() {
    assert!(init(&LoggerConfiguration::default()).is_ok());
    let second_init = init(&LoggerConfiguration::default());
    assert!(second_init.is_ok());
    assert!(second_init.unwrap().is_none());
}
