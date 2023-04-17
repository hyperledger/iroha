//! Iroha peer command-line interface.
#![allow(clippy::print_stdout)]
use std::env;

use color_eyre::eyre::WrapErr as _;
use iroha::style::Styling;
use iroha_config::path::Path as ConfigPath;
use iroha_genesis::{GenesisNetwork, GenesisNetworkTrait as _, RawGenesisBlock};
use owo_colors::OwoColorize as _;

const HELP_ARG: [&str; 2] = ["--help", "-h"];
const SUBMIT_ARG: [&str; 2] = ["--submit-genesis", "-s"];
const VERSION_ARG: [&str; 2] = ["--version", "-V"];

const REQUIRED_ENV_VARS: [(&str, &str); 7] = [
    ("IROHA_TORII", "Torii (gateway) endpoint configuration"),
    (
        "IROHA_SUMERAGI",
        "Sumeragi (emperor) consensus configuration",
    ),
    (
        "IROHA_KURA",
        "Kura (storage). Configuration of block storage ",
    ),
    ("IROHA_BLOCK_SYNC", "Block synchronisation configuration"),
    ("IROHA_PUBLIC_KEY", "Peer public key"),
    ("IROHA_PRIVATE_KEY", "Peer private key"),
    ("IROHA_GENESIS", "Genesis block configuration"),
];

#[tokio::main]
/// To make `Iroha` peer work all actors should be started first.
/// After that moment it you can start it with listening to torii events.
///
/// # Side effect
/// - Prints welcome message in the log
///
/// # Errors
/// - Reading genesis from disk
/// - Reading config file
/// - Reading config from `env`
/// - Missing required fields in combined configuration
/// - Telemetry setup
/// - [`Sumeragi`] init
async fn main() -> Result<(), color_eyre::Report> {
    let styling = Styling::new();
    if !iroha::style::should_disable_color() {
        color_eyre::install()?;
    }
    let mut args = iroha::Arguments::default();
    if env::args().any(|a| HELP_ARG.contains(&a.as_str())) {
        print_help(&styling)?;
        return Ok(());
    }

    if env::args().any(|a| VERSION_ARG.contains(&a.as_str())) {
        print_version(&styling);
        return Ok(());
    }

    if env::args().any(|a| SUBMIT_ARG.contains(&a.as_str())) {
        args.submit_genesis = true;
        if let Ok(genesis_path) = env::var("IROHA2_GENESIS_PATH") {
            args.genesis_path =
                Some(ConfigPath::user_provided(&genesis_path)
                     .wrap_err_with(
                         ||
                             "Required, because `--submit-genesis` was specified.")
                     .wrap_err_with(
                         ||
                             format!("Could not read `{genesis_path}`"))?);
        }
    } else {
        args.genesis_path = None;
    }

    for arg in env::args().skip(1) {
        if !arg.is_empty()
            && !([HELP_ARG, SUBMIT_ARG]
                .iter()
                .any(|group| group.contains(&arg.as_str())))
        {
            print_help(&styling)?;
            eyre::bail!(
                "Unrecognised command-line flag `{}`",
                arg.style(styling.negative)
            );
        }
    }

    if let Ok(config_path) = env::var("IROHA2_CONFIG_PATH") {
        args.config_path = ConfigPath::user_provided(&config_path)
            .wrap_err_with(|| format!("Failed to parse `{config_path}` as configuration path"))?;
    }
    if !args.config_path.exists() {
        // Require all the fields defined in default `config.json`
        // to be specified as env vars with their respective prefixes

        // TODO: Consider moving these into the
        // `iroha::combine_configs` and dependent functions.
        for var_name in REQUIRED_ENV_VARS {
            // Rather than short circuit and require the person to fix
            // the missing env vars one by one, print out the whole
            // list of missing environment variables.
            let _ = env::var(var_name.0).map_err(|e| {
                println!(
                    "{}: {}",
                    var_name.0.style(styling.highlight),
                    e.style(styling.negative)
                );
            });
        }
    }

    let config = iroha::combine_configs(&args)?;
    let telemetry = iroha_logger::init(&config.logger)?;
    if !config.disable_panic_terminal_colors {
        iroha_logger::warn!("The configuration parameter `DISABLE_PANIC_TERMINAL_COLORS` is deprecated. Set `TERMINAL_COLORS=false` instead. ")
    }
    iroha_logger::info!(
        git_commit_sha = env!("VERGEN_GIT_SHA"),
        "Hyperledgerいろは2にようこそ！(translation) Welcome to Hyperledger Iroha {}!",
        env!("CARGO_PKG_VERSION")
    );

    let genesis = if let Some(genesis_path) = &args.genesis_path {
        GenesisNetwork::from_configuration(
            args.submit_genesis,
            RawGenesisBlock::from_path(
                genesis_path
                    .first_existing_path()
                    .ok_or({
                        color_eyre::eyre::eyre!("Genesis block file {genesis_path:?} doesn't exist")
                    })?
                    .as_ref(),
            )?,
            Some(&config.genesis),
            &config.sumeragi.transaction_limits,
        )
        .wrap_err("Failed to initialize genesis.")?
    } else {
        None
    };

    iroha::Iroha::with_genesis(
        genesis,
        config,
        telemetry,
    )
    .await?;
    Ok(())
}

#[allow(clippy::print_stdout)]
fn print_help(styling: &Styling) -> Result<(), std::io::Error> {
    use std::io::Write;

    let stdout = std::io::stdout();
    let lock = stdout.lock();
    #[allow(clippy::arithmetic_side_effects)] // No overflow
    let mut buffer = std::io::BufWriter::with_capacity(1024 * REQUIRED_ENV_VARS.len(), lock);
    writeln!(buffer, "{}", "Iroha 2".bold().green())?;
    writeln!(buffer, "pass {} for this message", styling.or(&HELP_ARG))?;
    writeln!(
        buffer,
        "pass {} to submit genesis from this peer",
        styling.or(&SUBMIT_ARG)
    )?;
    writeln!(
        buffer,
        "pass {} to print version information",
        styling.or(&VERSION_ARG)
    )?;
    writeln!(buffer)?;
    writeln!(buffer, "Iroha 2 is configured via environment variables:")?;
    writeln!(
        buffer,
        "    {} is the location of your {}",
        "IROHA2_CONFIG_PATH".style(styling.highlight),
        styling.with_json_file_ext("config")
    )?;
    writeln!(
        buffer,
        "    {} is the location of your {}",
        "IROHA2_GENESIS_PATH".style(styling.highlight),
        styling.with_json_file_ext("genesis")
    )?;
    writeln!(
        buffer,
        "If either of these is not provided, Iroha checks the current directory."
    )?;
    writeln!(buffer)?;
    writeln!(
        buffer,
        "Additionally, in case of absence of both {} and {}
in the current directory, all the variables from {} should be set via the environment
as follows:",
        "IROHA2_CONFIG_PATH".style(styling.highlight),
        styling.with_json_file_ext("config"),
        styling.with_json_file_ext("config")
    )?;
    for var in REQUIRED_ENV_VARS {
        writeln!(buffer, "    {}: {}", var.0.style(styling.highlight), var.1)?;
    }
    writeln!(
        buffer,
        "Examples of these variables can be found in the default `configs/peer/config.json`."
    )?;
    Ok(())
}

#[allow(clippy::print_stdout)]
fn print_version(styling: &Styling) {
    println!(
        "{} {} (git hash {}) \n {}: {}",
        "Hyperledger Iroha".style(styling.positive),
        env!("CARGO_PKG_VERSION").style(styling.highlight),
        env!("VERGEN_GIT_SHA"),
        "cargo features".style(styling.highlight),
        env!("VERGEN_CARGO_FEATURES")
    );
}
