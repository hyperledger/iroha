#![allow(clippy::restriction)]
use iroha_config::{logger::Level::*, PostConfiguration};
use test_network::{prepare_test_for_nextest, PeerBuilder};

#[test]
fn reload_log_level() {
    prepare_test_for_nextest!();
    let (_dont_drop, _dont_drop_either, cl) = <PeerBuilder>::new().start_with_runtime();

    let verify = |level| {
        let field: bool = cl.set_config(PostConfiguration::LogLevel(level)).unwrap();
        assert!(field);
    };
    verify(ERROR);
    verify(TRACE);
    verify(WARN);
    verify(DEBUG);
}
