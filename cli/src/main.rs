//! Iroha peer command-line interface.
use std::env;

use clap::Parser;
use error_stack::{IntoReportCompat, ResultExt};
use iroha::Args;

#[derive(thiserror::Error, Debug)]
enum MainError {
    #[error("Could not set up configuration tracing")]
    TraceConfigSetup,
    #[error("Configuration error")]
    Config,
    #[error("Could not initialize logger")]
    Logger,
    #[error("Could not start Iroha")]
    IrohaStart,
}

#[tokio::main]
async fn main() -> error_stack::Result<(), MainError> {
    let args = Args::parse();

    if args.trace_config {
        iroha_config::enable_tracing()
            .change_context(MainError::TraceConfigSetup)
            .attach_printable("was enabled by `--trace-config` argument")?;
    }

    error_stack::Report::set_color_mode(if args.terminal_colors {
        error_stack::fmt::ColorMode::Color
    } else {
        error_stack::fmt::ColorMode::None
    });

    let (config, logger_config, genesis) =
        iroha::read_config_and_genesis(&args).change_context(MainError::Config).attach_printable_lazy(|| {
            if let Some(path) = &args.config {
                format!("config path is specified by `--config` arg: {}", path.display())
            } else {
                "`--config` arg was not set, therefore configuration relies fully on environment variables".to_owned()
            }
        })?;
    let logger = iroha_logger::init_global(logger_config)
        .into_report()
        // https://github.com/hashintel/hash/issues/4295
        .map_err(|report| report.change_context(MainError::Logger))?;

    iroha_logger::info!(
        version = env!("CARGO_PKG_VERSION"),
        git_commit_sha = env!("VERGEN_GIT_SHA"),
        "Hyperledgerいろは2にようこそ！(translation) Welcome to Hyperledger Iroha!"
    );

    if genesis.is_some() {
        iroha_logger::debug!("Submitting genesis.");
    }

    let _iroha = iroha::Iroha::start_network(config, genesis, logger)
        .await
        .change_context(MainError::IrohaStart)?
        .start_torii()
        .await
        .change_context(MainError::IrohaStart)?;

    Ok(())
}
