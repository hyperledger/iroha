//! Oneshot execution of `apply_blocks` benchmark.

//! Can be useful to profile using flamegraph.
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --release --example apply_blocks
//! ```
mod apply_blocks;
use apply_blocks::{CertifiedBlocks, StateApplyBlocks};
use iroha_config::base::{env::std_env, read::ConfigReader};
use iroha_logger::Config;
fn main() {
    // The logger handle's actor task runs on this runtime; the chains do not need it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");
    {
        let _guard = rt.enter();
        let mut config: Config = ConfigReader::new()
            .with_env(std_env)
            .read_and_complete()
            .expect("Failed to load config");
        config.terminal_colors = true;
        let _ = iroha_logger::init_global(config).expect("Failed to initialize logger");
    }
    iroha_logger::info!("Starting...");
    let blocks = CertifiedBlocks::setup();
    let mut bench = StateApplyBlocks::setup(&blocks);
    bench.measure();
}
