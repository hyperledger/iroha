//! Oneshot execution of `validate_blocks` benchmark.
//! Can be useful to profile using flamegraph.
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --release --example validate_blocks
//! ```

mod validate_blocks;

use validate_blocks::WsvValidateBlocks;

fn main() {
    let bench = WsvValidateBlocks::setup().expect("Failed to setup benchmark");
    WsvValidateBlocks::measure(bench).expect("Failed to execute bnechmark");
}
