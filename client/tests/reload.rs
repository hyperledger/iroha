#![cfg(not(feature = "mock_world"))]
#![allow(clippy::restriction)]

use iroha_config::{logger::Level::*, PostConfiguration};
use test_network::PeerBuilder;

#[test]
fn reload_log_level() {
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
