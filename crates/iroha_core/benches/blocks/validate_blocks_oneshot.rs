//! Oneshot execution of `validate_blocks` benchmark.

//! Can be useful to profile using flamegraph.
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --release --example validate_blocks
//! ```
mod validate_blocks;
use iroha_config::base::{env::std_env, read::ConfigReader};
use iroha_logger::Config;
use validate_blocks::StateValidateBlocks;
fn main() {
    // The logger handle's actor task runs on this runtime; the chain does not need it.
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
    let mut bench = StateValidateBlocks::setup();
    bench.measure();
}
