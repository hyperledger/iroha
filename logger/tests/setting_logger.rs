#![allow(clippy::restriction, clippy::expect_used)]

use iroha_logger::{init, Configuration};

#[tokio::test]
async fn setting_logger_twice_fails() {
    assert!(init(&Configuration::default()).is_ok());
    let second_init = init(&Configuration::default());
    assert!(second_init.is_ok());
    assert!(second_init.unwrap().is_none());
}

#[test]
fn install_panic_hook_multiple_times_works() {
    iroha_logger::install_panic_hook().unwrap();
    iroha_logger::install_panic_hook().unwrap();
}
