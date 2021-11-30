#![allow(clippy::restriction)]
use iroha_config::{logger::Level::*, PostConfiguration};
use test_network::Peer as TestPeer;

#[test]
fn reload_log_level() {
    let (_dont_drop, _dont_drop_either, cl) = <TestPeer>::start_test_with_runtime();

    let verify = |level| {
        let field: bool = cl.set_config(PostConfiguration::LogLevel(level)).unwrap();
        assert!(field);
    };
    verify(ERROR);
    verify(TRACE);
    verify(WARN);
    verify(DEBUG);
}
