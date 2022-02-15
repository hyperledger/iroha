//! Iroha peer command-line interface.

use std::str::FromStr;

use iroha::Arguments;
use iroha_core::prelude::AllowAll;
use iroha_permissions_validators::public_blockchain::default_permissions;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    let mut args = Arguments::default();
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    if std::env::args().any(|arg| arg == "--submit" || arg == "--submit-genesis" || arg == "-s") {
        args.submit_genesis = true;
    }

    if let Ok(config_path) = std::env::var("IROHA2_CONFIG_PATH") {
        args.config_path = std::path::PathBuf::from_str(&config_path)?;
    }

    if let Ok(genesis_path) = std::env::var("IROHA2_GENESIS_PATH") {
        args.genesis_path = std::path::PathBuf::from_str(&genesis_path)?;
    }

    <iroha::Iroha>::new(&args, default_permissions(), AllowAll.into())
        .await?
        .start()
        .await?;
    Ok(())
}

#[allow(clippy::print_stdout)]
fn print_help() {
    println!("Iroha 2");
    println!("pass `--help` or `-h` for this message");
    println!("pass `--submit` `--submit-genesis` or `-s` to submit genesis from this peer");
    println!();
    println!("Iroha 2 is configured via environment variables:");
    println!("    IROHA2_CONFIG_PATH is the location of your `config.json`");
    println!("    IROHA2_GENESIS_PATH is the location of `genesis.json`");
    println!("If either of these is not provided, Iroha checks the current directory.");
    // TODO: would be nice to be able to provide the configuration environment variables as well.
}
