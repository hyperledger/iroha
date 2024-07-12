use iroha_logger::{init_global, Config, InitConfig};

#[tokio::test]
async fn setting_logger_twice_fails() {
    let cfg = Config::default();

    let first = init_global(InitConfig::new(cfg.clone(), false));
    assert!(first.is_ok());

    let second = init_global(InitConfig::new(cfg, false));
    assert!(second.is_err());
}

#[test]
fn install_panic_hook_multiple_times_works() {
    iroha_logger::install_panic_hook().unwrap();
    iroha_logger::install_panic_hook().unwrap();
}
