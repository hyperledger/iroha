use iroha_logger::{init_global, Config};

#[tokio::test]
async fn setting_logger_twice_fails() {
    let cfg = Config::default();

    let first = init_global(&cfg, false);
    assert!(first.is_ok());

    let second = init_global(&cfg, false);
    assert!(second.is_err());
}

#[test]
fn install_panic_hook_multiple_times_works() {
    iroha_logger::install_panic_hook().unwrap();
    iroha_logger::install_panic_hook().unwrap();
}
