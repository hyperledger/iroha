//! Iroha peer command-line interface.

use std::{
    env::{args, var},
    path::PathBuf,
    str::FromStr,
};

use eyre::eyre;
use iroha::Arguments;
use iroha_core::prelude::AllowAll;
use iroha_permissions_validators::public_blockchain::default_permissions;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    let mut args = Arguments::default();
    if args().any(|a| is_help(&a)) {
        print_help();
        return Ok(());
    }

    if args().any(|a| is_submit(&a)) {
        args.submit_genesis = true;
    }

    for arg in args().skip(1) {
        if !arg.is_empty() && !is_help(&arg) && !is_submit(&arg) {
            print_help();
            return Err(eyre!("Unrecognised command-line flag `{}`", arg));
        }
    }

    if let Ok(config_path) = var("IROHA2_CONFIG_PATH") {
        args.config_path = PathBuf::from_str(&config_path)?;
    }

    if let Ok(genesis_path) = var("IROHA2_GENESIS_PATH") {
        args.genesis_path = PathBuf::from_str(&genesis_path)?;
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
