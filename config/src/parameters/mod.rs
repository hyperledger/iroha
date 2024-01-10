use std::{
    fmt::Debug,
    fs::File,
    io::{BufReader, Read},
    iter,
    path::{Path, PathBuf},
};

use eyre::{eyre, Context, Report, Result};
use serde::{Deserialize, Serialize};

use crate::{Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvResult, ReadEnv};

pub mod chain_wide;
pub mod genesis;
pub mod iroha;
pub mod kura;
pub mod logger;
pub mod queue;
pub mod snapshot;
pub mod sumeragi;
pub mod telemetry;
pub mod torii;

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    #[serde(default)]
    iroha: iroha::UserLayer,
    #[serde(default)]
    genesis: genesis::UserLayer,
    #[serde(default)]
    kura: kura::UserLayer,
    #[serde(default)]
    sumeragi: sumeragi::UserLayer,
    #[serde(default)]
    logger: logger::UserLayer,
    #[serde(default)]
    queue: queue::UserLayer,
    #[serde(default)]
    snapshot: snapshot::UserLayer,
    #[serde(default)]
    telemetry: telemetry::UserLayer,
    #[serde(default)]
    torii: torii::UserLayer,
    #[serde(default)]
    chain_wide: chain_wide::UserLayer,
}

impl UserLayer {
    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, eyre::Error> {
        let contents = {
            let mut file = File::open(path.as_ref()).wrap_err_with(|| {
                eyre!("cannot open file at location `{}`", path.as_ref().display())
            })?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            contents
        };
        let mut parsed: Self = toml::from_str(&contents).wrap_err("failed to parse toml")?;
        parsed.normalise_paths(
            path.as_ref()
                .parent()
                .expect("the config file path could not be empty or root"),
        );
        Ok(parsed)
    }

    fn normalise_paths(&mut self, relative_to: impl AsRef<Path>) {
        let path = relative_to.as_ref();

        macro_rules! patch {
            ($value:expr) => {
                $value.as_mut().map(|x| {
                    *x = path.join(&x);
                })
            };
        }

        patch!(self.genesis.file);
        patch!(self.snapshot.store_path);
        patch!(self.kura.block_store_path);
        patch!(self.telemetry.dev.file);
    }

    #[must_use]
    pub fn merge(self, _other: Self) -> Self {
        todo!()
    }
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        let mut emitter = Emitter::new();

        macro_rules! complete_nested {
            ($item:expr) => {
                match $crate::Complete::complete($item) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        emitter.emit_collection(error);
                        None
                    }
                }
            };
        }

        let iroha = complete_nested!(self.iroha);
        let genesis = complete_nested!(self.genesis);
        let kura = complete_nested!(self.kura);
        let sumeragi = complete_nested!(self.sumeragi);
        let logger = complete_nested!(self.logger);
        let queue = complete_nested!(self.queue);
        let snapshot = complete_nested!(self.snapshot);
        let telemetry = complete_nested!(self.telemetry);
        let torii = complete_nested!(self.torii);
        let chain_wide = complete_nested!(self.chain_wide);

        emitter.finish()?;

        Ok(Config {
            iroha: iroha.unwrap(),
            genesis: genesis.unwrap(),
            kura: kura.unwrap(),
            sumeragi: sumeragi.unwrap(),
            logger: logger.unwrap(),
            queue: queue.unwrap(),
            snapshot: snapshot.unwrap(),
            telemetry: telemetry.unwrap(),
            torii: torii.unwrap(),
            chain_wide: chain_wide.unwrap(),
        })
    }
}

impl FromEnv for UserLayer {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self> {
        fn from_env_nested<T: FromEnv>(
            env: &impl ReadEnv,
            emitter: &mut Emitter<Report>,
        ) -> Option<T> {
            match FromEnv::from_env(env) {
                Ok(parsed) => Some(parsed),
                Err(errors) => {
                    emitter.emit_collection(errors);
                    None
                }
            }
        }

        let mut emitter = Emitter::new();

        let iroha = from_env_nested(env, &mut emitter);
        let genesis = from_env_nested(env, &mut emitter);
        let kura = from_env_nested(env, &mut emitter);
        let sumeragi = from_env_nested(env, &mut emitter);
        let logger = from_env_nested(env, &mut emitter);
        let queue = from_env_nested(env, &mut emitter);
        let snapshot = from_env_nested(env, &mut emitter);
        let telemetry = from_env_nested(env, &mut emitter);
        let torii = from_env_nested(env, &mut emitter);
        let chain_wide = from_env_nested(env, &mut emitter);

        emitter.finish()?;

        Ok(Self {
            iroha: iroha.unwrap(),
            genesis: genesis.unwrap(),
            kura: kura.unwrap(),
            sumeragi: sumeragi.unwrap(),
            logger: logger.unwrap(),
            queue: queue.unwrap(),
            snapshot: snapshot.unwrap(),
            telemetry: telemetry.unwrap(),
            torii: torii.unwrap(),
            chain_wide: chain_wide.unwrap(),
        })
    }
}

#[derive(Debug)]
pub struct Config {
    pub iroha: iroha::Config,
    pub genesis: genesis::Config,
    pub kura: kura::Config,
    pub sumeragi: sumeragi::Config,
    pub logger: logger::Config,
    pub queue: queue::Config,
    pub snapshot: snapshot::Config,
    pub telemetry: telemetry::Config,
    pub torii: torii::Config,
    pub chain_wide: chain_wide::Config,
}
