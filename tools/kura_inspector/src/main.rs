use clap::{Parser, Subcommand};
use kura_inspector::{print, Config, DefaultOutput};

/// Kura inspector
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"))]
struct Opts {
    /// Height of the block from which start the inspection.
    /// Defaults to the latest block height
    #[clap(short, long, name = "BLOCK_HEIGHT")]
    from: Option<usize>,
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
        length: usize,
    },
}

#[tokio::main]
#[allow(clippy::use_debug, clippy::print_stderr)]
async fn main() {
    let opts = Opts::parse();
    let mut output = DefaultOutput::new();
    Config::from(opts)
        .run(&mut output)
        .await
        .unwrap_or_else(|e| eprintln!("{:?}", e))
}

impl From<Opts> for Config {
    fn from(src: Opts) -> Self {
        let Opts { from, command } = src;

        match command {
            Command::Print { length } => Config::Print(print::Config { from, length }),
        }
    }
}
