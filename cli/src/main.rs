//! Iroha peer command-line interface.
use std::{env, path::PathBuf};

use clap::Parser;
use color_eyre::eyre::Result;

fn is_colouring_supported() -> bool {
    supports_color::on(supports_color::Stream::Stdout).is_some()
}

fn default_terminal_colors_str() -> clap::builder::OsStr {
    is_colouring_supported().to_string().into()
}

/// Iroha peer Command-Line Interface.
#[derive(Parser, Debug)]
#[command(name = "iroha", version = concat!("version=", env!("CARGO_PKG_VERSION"), " git_commit_sha=", env!("VERGEN_GIT_SHA")), author)]
struct Args {
    /// Path to the configuration file
    #[arg(long, short, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    config: PathBuf,
    /// Whether to enable ANSI colored output or not
    ///
    /// By default, Iroha determines whether the terminal supports colors or not.
    ///
    /// In order to disable this flag explicitly, pass `--terminal-colors=false`.
    #[arg(
        long,
        env,
        default_missing_value("true"),
        default_value(default_terminal_colors_str()),
        action(clap::ArgAction::Set),
        require_equals(true),
        num_args(0..=1),
    )]
    terminal_colors: bool,
    /// Whether the current peer should submit the genesis block or not
    ///
    /// Only one peer in the network should submit the genesis block.
    ///
    /// This argument must be set alongside with `genesis.file` and `genesis.private_key`
    /// configuration options. If not, Iroha will exit with an error.
    ///
    /// In case when the network consists only of this one peer, i.e. the amount of trusted
    /// peers in the configuration (`sumeragi.trusted_peers`) is less than 2, this peer must
    /// submit the genesis, since there are no other peers who can provide it. In this case, Iroha
    /// will exit with an error if `--submit-genesis` is not set.
    #[arg(long)]
    submit_genesis: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.terminal_colors {
        color_eyre::install()?;
    }

    let (config, genesis) = iroha::read_config_and_genesis(args.config, args.submit_genesis)?;
    let logger = iroha_logger::init_global(&config.logger, args.terminal_colors)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn default_args() -> Result<()> {
        let args = Args::try_parse_from(["test"])?;

        assert_eq!(args.config, PathBuf::from("config.toml"));
        assert_eq!(args.terminal_colors, is_colouring_supported());
        assert_eq!(args.submit_genesis, false);

        Ok(())
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn terminal_colors_works_as_expected() -> Result<()> {
        fn try_with(arg: &str) -> Result<bool> {
            Ok(Args::try_parse_from(["test", arg])?.terminal_colors)
        }

        assert_eq!(
            Args::try_parse_from(["test"])?.terminal_colors,
            is_colouring_supported()
        );
        assert_eq!(try_with("--terminal-colors")?, true);
        assert_eq!(try_with("--terminal-colors=false")?, false);
        assert_eq!(try_with("--terminal-colors=true")?, true);
        assert!(try_with("--terminal-colors=random").is_err());

        Ok(())
    }

    #[test]
    fn user_provided_config_path_works() -> Result<()> {
        let args = Args::try_parse_from(["test", "--config", "/home/custom/file.json"])?;

        assert_eq!(args.config, PathBuf::from("/home/custom/file.json"));

        Ok(())
    }

    #[test]
    fn user_can_provide_any_extension() {
        let _args = Args::try_parse_from(["test", "--config", "file.toml.but.not"])
            .expect("should allow doing this as well");
    }
}
