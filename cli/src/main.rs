//! Iroha peer command-line interface.
use std::{env, path::PathBuf};

use clap::Parser;
use color_eyre::eyre::Result;

const DEFAULT_CONFIG_PATH: &str = "config.toml";

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
    /// Path to the configuration file, defaults to `config.json`/`config.json5`
    ///
    /// Supported extensions are `.json` and `.json5`. By default, Iroha looks for a
    /// `config` file with one of the supported extensions in the current working directory.
    /// If the default config file is not found, Iroha will rely on default values and environment
    /// variables. However, if the config path is set explicitly with this argument and the file
    /// is not found, Iroha will exit with an error.
    #[arg(
        long,
        short,
        env("IROHA_CONFIG"),
        value_name("PATH"),
        value_hint(clap::ValueHint::FilePath),
        default_value_t = DEFAULT_CONFIG_PATH.to_owned()
    )]
    config: String,
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

    let (config, genesis) =
        iroha::read_config_and_genesis(PathBuf::from(args.config), args.submit_genesis)?;
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
    use assertables::{assert_contains, assert_contains_as_result};

    use super::*;

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn default_args() -> Result<()> {
        let args = Args::try_parse_from(["test"])?;

        assert_eq!(args.config, "config.toml".to_owned());
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

        assert_eq!(args.config, "/home/custom/file.json".to_owned());

        Ok(())
    }

    #[test]
    fn user_cannot_provide_invalid_extension() {
        let err = Args::try_parse_from(["test", "--config", "file.toml"])
            .expect_err("Should not allow TOML");

        let formatted = format!("{err}");
        assert_contains!(formatted, "invalid value 'file.toml' for '--config");
        assert_contains!(formatted, "unsupported file extension `toml`");
    }
}
