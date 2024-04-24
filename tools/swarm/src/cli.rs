use std::{num::NonZeroU16, path::PathBuf};

use clap::{Args, Parser};

#[derive(Parser, Debug)]
pub struct Cli {
    /// How many peers to generate within the Docker Compose setup.
    #[arg(long, short)]
    pub peers: NonZeroU16,
    /// The Unicode `seed` string for deterministic key-generation.
    #[arg(long, short)]
    pub seed: Option<String>,
    /// Explicit keypair in json format. Takes precedence over seed parameter.
    #[arg(long)]
    pub key_pair: Option<String>,
    /// Genesis signature. Should be set with --key-pair.
    #[arg(long, requires = "key_pair")]
    pub signature: Option<String>,
    /// Includes a health check configuration to each service in the Docker Compose output.
    ///
    /// The health checks use predefined settings.
    ///
    /// For more details on health check configurations in Docker Compose files, visit:
    /// https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck
    #[arg(long)]
    pub health_check: bool,
    /// Re-create the target file if it already exists.
    #[arg(long)]
    pub force: bool,
    /// Path to a generated Docker Compose configuration.
    ///
    /// If file exists, the app will prompt its overwriting. If the TTY is not
    /// interactive, the app will stop execution with a non-zero exit code. In order to
    /// overwrite the file anyway, pass `--force` flag.
    #[arg(long, short)]
    pub out_file: PathBuf,
    /// Disable banner in the file saying that the file is generated.
    ///
    /// It includes all passed arguments in order to help with reproducibility.
    #[arg(long)]
    pub no_banner: bool,
    /// Path to a directory with Iroha configuration. It will be mapped as volume for containers.
    ///
    /// The directory should contain `genesis.json` with executor.
    #[arg(long, short)]
    pub config_dir: PathBuf,
    #[command(flatten)]
    pub source: SourceArgs,
    // TODO: add an argument to specify an optional configuration file path?
    //       or think about other ways for users to customise peers' configuration
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct SourceArgs {
    /// Use specified docker image.
    ///
    /// Be careful with specifying a Dockerhub image as a source: Swarm only guarantees that
    /// the docker-compose configuration it generates is compatible with the same Git revision it
    /// is built from itself. Therefore, if specified image is not compatible with the version of Swarm
    /// you are running, the generated configuration might not work.
    #[arg(long)]
    pub image: Option<String>,
    /// Use local path location of the Iroha source code to build images from.
    ///
    /// If the path is relative, it will be resolved relative to the CWD.
    #[arg(long, value_name = "PATH")]
    pub build: Option<PathBuf>,
}

pub enum SourceParsed {
    Image { name: String },
    Build { path: PathBuf },
}

impl From<SourceArgs> for SourceParsed {
    fn from(value: SourceArgs) -> Self {
        match value {
            SourceArgs {
                image: Some(name),
                build: None,
            } => Self::Image { name },
            SourceArgs {
                image: None,
                build: Some(path),
            } => Self::Build { path },
            _ => unreachable!("clap invariant"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Display, Formatter};

    use clap::{ArgMatches, Command, Error as ClapError};

    use super::*;

    struct ClapErrorWrap(ClapError);

    impl From<ClapError> for ClapErrorWrap {
        fn from(value: ClapError) -> Self {
            Self(value)
        }
    }

    impl Debug for ClapErrorWrap {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            Display::fmt(&self.0, f)
        }
    }

    fn match_args(args_str: impl AsRef<str>) -> Result<ArgMatches, ClapErrorWrap> {
        let cmd = Command::new("test");
        let cmd = Cli::augment_args(cmd);
        let matches =
            cmd.try_get_matches_from(std::iter::once("test").chain(args_str.as_ref().split(' ')))?;
        Ok(matches)
    }

    #[test]
    fn work_with_build_source() {
        let _ = match_args("-p 20 --build . --config-dir ./config --outfile sample.yml").unwrap();
    }

    #[test]
    fn doesnt_allow_multiple_sources() {
        let _ = match_args("-p 1 --build . --image hp/iroha --config-dir ./ --outfile test.yml")
            .unwrap_err();
    }

    #[test]
    fn doesnt_allow_omitting_source() {
        let _ = match_args("-p 1 --outfile test.yml --config-dir ./").unwrap_err();
    }
}
