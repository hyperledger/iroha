use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Kura inspector
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"))]
struct Opts {
    /// Height of the block up to which exclude from the inspection.
    /// Defaults to the previous one from the current top
    #[clap(short, long, name = "BLOCK_HEIGHT")]
    skip_to: Option<u64>,
    /// Find blocks whose data collapsed
    #[clap(long)]
    scan: bool,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print contents of a certain length of the blocks
    Print {
        /// Number of the blocks to print.
        /// The excess will be truncated
        #[clap(short = 'n', long, default_value_t = 1)]
        length: u64,
    },
    /// Listen for additions to the storage and report it
    Follow,
}

fn main() {
    let opts = Opts::parse();
    // kura_inspector::run()
}
