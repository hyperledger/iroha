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

#[cfg(test)]
mod tests {
    use iroha::is_colouring_supported;

    use super::*;

    #[test]
    #[allow(clippy::bool_assert_comparison)] // for expressiveness
    fn default_args() -> Result<()> {
        let args = Args::try_parse_from(["test"])?;

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

        assert_eq!(args.config, Some(PathBuf::from("/home/custom/file.json")));

        Ok(())
    }

    #[test]
    fn user_can_provide_any_extension() {
        let _args = Args::try_parse_from(["test", "--config", "file.toml.but.not"])
            .expect("should allow doing this as well");
    }
}
