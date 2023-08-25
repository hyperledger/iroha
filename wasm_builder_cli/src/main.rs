struct Args {
    /// Path to the smartcontract
    path: String,
    /// Apply `cargo check` to the smartcontract
    #[arg(long, short)]
    check: bool,
    /// Enable smartcontract formatting using `cargo fmt`.
    #[arg(long, short)]
    format: bool,
    #[arg(long, short)]
    optimize: bool,
    // TODO: output file? stdout?
}

fn main() {}
