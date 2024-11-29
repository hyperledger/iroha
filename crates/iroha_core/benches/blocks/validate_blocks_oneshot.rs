//! Oneshot execution of `validate_blocks` benchmark.
//! Can be useful to profile using flamegraph.
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --release --example validate_blocks
//! ```

mod validate_blocks;

use iroha_config::base::{env::std_env, read::ConfigReader};
use iroha_logger::InitConfig;
use validate_blocks::StateValidateBlocks;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");
    {
        let _guard = rt.enter();
        let config: iroha_config::parameters::user::Logger = ConfigReader::new()
            .with_env(std_env)
            .read_and_complete()
            .expect("Failed to load config");
        let config = config.parse().expect("Failed to parse config");

        let config = InitConfig::new(config, true);
        let _ = iroha_logger::init_global(config).expect("Failed to initialize logger");
    }
    iroha_logger::info!("Starting...");
    let bench = StateValidateBlocks::setup(rt.handle());
    StateValidateBlocks::measure(bench);
}
