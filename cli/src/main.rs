//! Iroha peer command-line interface.
use std::env;

use color_eyre::eyre::WrapErr as _;
use iroha::{style::Styling, TerminalColorsArg};
use iroha_config::path::Path as ConfigPath;
use iroha_genesis::{GenesisNetwork, RawGenesisBlock};
use owo_colors::OwoColorize as _;

const HELP_ARG: [&str; 2] = ["--help", "-h"];
const SUBMIT_ARG: [&str; 2] = ["--submit-genesis", "-s"];
const VERSION_ARG: [&str; 2] = ["--version", "-V"];
const TERMINAL_COLORS_ARG: &str = "--terminal-colors";
const NO_TERMINAL_COLORS_ARG: &str = "--no-terminal-colors";

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
    let mut args = iroha::Arguments::default();

    let terminal_colors = env::var("TERMINAL_COLORS")
        .ok()
        .map(|s| !s.as_str().parse().unwrap_or(true))
        .or_else(|| {
            if env::args().any(|a| a == TERMINAL_COLORS_ARG) {
                Some(true)
            } else if env::args().any(|a| a == NO_TERMINAL_COLORS_ARG) {
                Some(false)
            } else {
                None
            }
        })
        .map_or(TerminalColorsArg::Default, TerminalColorsArg::UserSet)
        .evaluate();

    if terminal_colors {
        color_eyre::install()?;
    }

    let styling = Styling::new(terminal_colors);

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
            args.genesis_path = Some(
                ConfigPath::user_provided(&genesis_path)
                    .wrap_err_with(|| "Required, because `--submit-genesis` was specified.")
                    .wrap_err_with(|| format!("Could not read `{genesis_path}`"))?,
            );
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
    let logger = iroha_logger::init_global(&config.logger, terminal_colors)?;
    if !config.disable_panic_terminal_colors {
        // FIXME: it shouldn't be logged here; it is a part of configuration domain
        //        this message can be very simply broken by the changes in the configuration
        //        https://github.com/hyperledger/iroha/issues/3506
        iroha_logger::warn!("The configuration parameter `DISABLE_PANIC_TERMINAL_COLORS` is deprecated. Set `TERMINAL_COLORS=false` instead. ")
    }
    iroha_logger::info!(
        version = %env!("CARGO_PKG_VERSION"), git_commit_sha = env!("VERGEN_GIT_SHA"),
        "Hyperledgerいろは2にようこそ！(translation) Welcome to Hyperledger Iroha!"
    );

    assert!(args.submit_genesis || config.sumeragi.trusted_peers.peers.len() > 1,
        "Only peer in network, yet required to receive genesis topology. This is a configuration error."
    );

    let genesis = args
        .submit_genesis
        .then_some(())
        .and(args.genesis_path)
        .map(|genesis_path| {
            let genesis_path = genesis_path.first_existing_path().ok_or({
                color_eyre::eyre::eyre!("Genesis block file {genesis_path:?} doesn't exist")
            })?;

            let genesis_block = RawGenesisBlock::from_path(genesis_path.as_ref())?;
            GenesisNetwork::from_configuration(genesis_block, Some(&config.genesis))
                .wrap_err("Failed to initialize genesis.")
        })
        .transpose()?;

    iroha::Iroha::with_genesis(genesis, config, logger)
        .await?
        .start()
        .await?;
    Ok(())
}

fn print_help(styling: &Styling) -> Result<(), std::io::Error> {
    use std::io::Write;

    let stdout = std::io::stdout();
    let lock = stdout.lock();
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
