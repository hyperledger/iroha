//! Iroha peer command-line interface.

use std::str::FromStr;

use iroha::Arguments;
use iroha_core::prelude::AllowAll;
use iroha_permissions_validators::public_blockchain::default_permissions;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    let mut args = Arguments::default();
    if std::env::args().any(|a| is_help(&a)) {
        print_help();
        return Ok(());
    }

    if std::env::args().any(|a| is_submit(&a)) {
        args.submit_genesis = true;
    }

    for arg in std::env::args().skip(1) {
        if !is_help(&arg) && !is_submit(&arg) {
            print_help();
            return Err(eyre::eyre!("Unrecognised command-line flag `{}`", arg));
        }
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

fn is_help(arg: &str) -> bool {
    ["--help", "-h"].contains(&arg)
}

fn is_submit(arg: &str) -> bool {
    ["--submit-genesis", "-s"].contains(&arg)
}

#[allow(clippy::print_stdout)]
fn print_help() {
    println!("Iroha 2");
    println!("pass `--help` or `-h` for this message");
    println!("pass `--submit-genesis` or `-s` to submit genesis from this peer");
    println!();
    println!("Iroha 2 is configured via environment variables:");
    println!("    IROHA2_CONFIG_PATH is the location of your `config.json`");
    println!("    IROHA2_GENESIS_PATH is the location of `genesis.json`");
    println!("If either of these is not provided, Iroha checks the current directory.");
}
