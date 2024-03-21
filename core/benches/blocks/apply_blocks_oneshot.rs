//! Oneshot execution of `apply_blocks` benchmark.
//! Can be useful to profile using flamegraph.
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --release --example apply_blocks
//! ```

mod apply_blocks;

use apply_blocks::StateApplyBlocks;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");
    {
        let _guard = rt.enter();
        iroha_logger::test_logger();
    }
    iroha_logger::info!("Starting...");
    let bench = StateApplyBlocks::setup(rt.handle());
    StateApplyBlocks::measure(&bench).expect("Failed to execute benchmark");
}
