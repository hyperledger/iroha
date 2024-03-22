//! Iroha peer command-line interface.
use std::env;

use clap::Parser;
use color_eyre::eyre::Result;
use iroha::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.terminal_colors {
        color_eyre::install()?;
    }

    let (config, logger_config, genesis) = iroha::read_config_and_genesis(&args)?;
    let logger = iroha_logger::init_global(logger_config)?;

    iroha_logger::info!(
        version = env!("CARGO_PKG_VERSION"),
        git_commit_sha = env!("VERGEN_GIT_SHA"),
        "Hyperledgerいろは2にようこそ！(translation) Welcome to Hyperledger Iroha!"
    );

    if genesis.is_some() {
        iroha_logger::debug!("Submitting genesis.");
    }

    iroha::Iroha::new(config, genesis, logger)
        .await?
        .start()
        .await?;

    Ok(())
}
