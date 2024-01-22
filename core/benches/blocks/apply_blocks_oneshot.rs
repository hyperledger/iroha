//! Oneshot execution of `apply_blocks` benchmark.
//! Can be useful to profile using flamegraph.
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --release --example apply_blocks
//! ```

mod apply_blocks;

use apply_blocks::WsvApplyBlocks;

#[tokio::main]
async fn main() {
    iroha_logger::test_logger();
    iroha_logger::info!("Starting...");
    let bench = WsvApplyBlocks::setup().expect("Failed to setup benchmark");
    WsvApplyBlocks::measure(&bench).expect("Failed to execute benchmark");
}
