//! General objects independent from executables.

use std::path::Path;

use iroha_config::Configurable;
use iroha_core::kura;

pub mod print;

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum Config {
    Print(print::Config),
}

/// Where to write the results of the inspection.
pub struct Output<T, E>
where
    T: std::io::Write + Send,
    E: std::io::Write + Send,
{
    /// Writer for valid data
    pub ok: T,
    /// Writer for invalid data
    pub err: E,
}

impl Config {
    /// Configure [`kura::BlockStore`] and route to the subcommand.
    ///
    /// # Errors
    /// Fails if
    /// 1. Fails to configure [`kura::BlockStore`].
    /// 2. Fails to run the subcommand.
    pub async fn run<T, E>(&self, output: &mut Output<T, E>) -> Result<(), Error>
    where
        T: std::io::Write + Send,
        E: std::io::Write + Send,
    {
        let block_store = block_store().await?;
        match self {
            Self::Print(cfg) => cfg.run(&block_store, output).await.map_err(Error::Print)?,
        }
        Ok(())
    }
}

async fn block_store() -> Result<kura::BlockStore<kura::DefaultIO>, Error> {
    let mut kura_config = kura::config::KuraConfiguration::default();
    kura_config.load_environment().map_err(Error::KuraConfig)?;
    kura::BlockStore::new(
        Path::new(&kura_config.block_store_path),
        kura_config.blocks_per_storage_file,
        kura::DefaultIO,
    )
    .await
    .map_err(Error::SetBlockStore)
}

/// [`Output`] for CLI use.
pub type DefaultOutput = Output<std::io::Stdout, std::io::Stderr>;

impl DefaultOutput {
    /// Construct [`DefaultOutput`].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ok: std::io::stdout(),
            err: std::io::stderr(),
        }
    }
}

#[derive(Debug)]
#[allow(missing_docs)]
pub enum Error {
    KuraConfig(iroha_config::derive::Error),
    SetBlockStore(kura::Error),
    Print(print::Error),
}
