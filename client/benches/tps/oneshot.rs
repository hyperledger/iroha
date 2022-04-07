//! Single trial of the benchmark

mod lib;

#[allow(clippy::expect_used)]
fn main() {
    let config = lib::Config::from_path("benches/tps/config.json").expect("Failed to configure");
    let tps = config.measure().expect("Failed to measure");
    iroha_logger::info!(?config);
    iroha_logger::info!(%tps);
}
