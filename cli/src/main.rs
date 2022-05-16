//! Iroha peer command-line interface.

use std::str::FromStr;

use eyre::WrapErr as _;
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
        if !arg.is_empty() && !is_help(&arg) && !is_submit(&arg) {
            print_help();
            return Err(eyre::eyre!("Unrecognised command-line flag `{}`", arg));
        }
    }

    if let Ok(config_path) = std::env::var("IROHA2_CONFIG_PATH") {
        args.config_path = std::path::PathBuf::from_str(&config_path)?;
    }
    if !args.config_path.exists() {
        // Require all the fields defined in default `config.json`
        // to be specified as env vars with their respective prefixes
        let required_var_names = [
            "IROHA_TORII",
            "IROHA_SUMERAGI",
            "IROHA_KURA",
            "IROHA_BLOCK_SYNC",
            "IROHA_PUBLIC_KEY",
            "IROHA_PRIVATE_KEY",
            "IROHA_GENESIS",
        ];
        for var_name in required_var_names {
            std::env::var(var_name).wrap_err(format!(
                "Failed to retrieve required environment variable: {var_name}"
            ))?;
        }
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
    println!(
        "Additionally, in case of absence of both IROHA2_CONFIG_PATH and `config.json`
in the current directory, all the variables from `config.json` should be set via the environment
as follows:"
    );
    println!("    IROHA_TORII is the torii gateway config");
    println!("    IROHA_SUMERAGI is the consensus config");
    println!("    IROHA_KURA is block storage config");
    println!("    IROHA_BLOCK_SYNC is block synchronization config");
    println!("    IROHA_PUBLIC_KEY is the peer's public key");
    println!("    IROHA_PRIVATE_KEY is the peer's private key");
    println!("    IROHA_GENESIS is the genesis block config");
    println!("Examples of these variables can be found in the default `configs/peer/config.json`.")
}
