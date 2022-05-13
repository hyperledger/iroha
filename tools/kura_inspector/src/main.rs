//! Kura inspector binary. For usage run with `--help`.  
use clap::{Parser, Subcommand};
use kura_inspector::{print, Config, DefaultOutput};

/// Kura inspector
#[derive(Parser)]
#[clap(author, version, about)]
struct Args {
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
    let args = Args::parse();
    let mut output = DefaultOutput::new();
    Config::from(args)
        .run(&mut output)
        .await
        .unwrap_or_else(|e| eprintln!("{:?}", e))
}

impl From<Args> for Config {
    fn from(src: Args) -> Self {
        let Args { from, command } = src;

        match command {
            Command::Print { length } => Config::Print(print::Config { from, length }),
        }
    }
}
