use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::File,
    io::Write,
    num::NonZeroU16,
    ops::Deref,
    path::{Path, PathBuf},
};

use color_eyre::{
    eyre::{eyre, Context, ContextCompat},
    Result,
};
use iroha_crypto::{error::Error as IrohaCryptoError, KeyGenConfiguration, KeyPair};
use iroha_data_model::prelude::PeerId;
use path_absolutize::Absolutize;
use serialize_docker_compose::{DockerCompose, DockerComposeService, ServiceSource};
use ui::UserInterface;

use super::Outcome;

const GIT_REVISION: &str = env!("VERGEN_GIT_SHA");
const GIT_ORIGIN: &str = "https://github.com/hyperledger/iroha.git";
/// Config directory that is generated in the output directory
const DIR_CONFIG: &str = "config";
/// Config directory inside of the docker image
const DIR_CONFIG_IN_DOCKER: &str = "/config";
const DIR_CLONE: &str = "iroha-cloned";
const FILE_VALIDATOR: &str = "validator.wasm";
const FILE_CONFIG: &str = "config.json";
const FILE_GENESIS: &str = "genesis.json";
const FILE_COMPOSE: &str = "docker-compose.yml";
const FORCE_ARG_SUGGESTION: &str =
    "You can pass `--force` flag to remove the file/directory without prompting";
const GENESIS_KEYPAIR_SEED: &[u8; 7] = b"genesis";

mod clap_args {
    use clap::{Args, Subcommand};

    use super::*;

    #[derive(Args, Debug)]
    pub struct SwarmArgs {
        /// How many peers to generate within the Docker Compose setup.
        #[arg(long, short)]
        pub peers: NonZeroU16,
        /// Might be useful for deterministic key generation.
        ///
        /// It could be any string. Its UTF-8 bytes will be used as a seed.
        #[arg(long, short)]
        pub seed: Option<String>,
        /// Re-create the target directory (for `dir` subcommand) or file (for `file` subcommand)
        /// if they already exist.
        #[arg(long)]
        pub force: bool,

        #[command(subcommand)]
        pub command: SwarmMode,
    }

    #[derive(Subcommand, Debug)]
    pub enum SwarmMode {
        /// Produce a directory with Docker Compose configuration, Iroha configuration, and an option
        /// to clone Iroha and use it as a source.
        ///
        /// This command builds Docker Compose configuration in a specified directory. If the source
        /// is a GitHub repo, it will be cloned into the directory. Also, the default configuration is
        /// built and put into `<target>/config` directory, unless `--no-default-configuration` flag is
        /// provided. The default configuration is equivalent to running `kagami config peer`,
        /// `kagami validator`, and `kagami genesis default --compiled-validator-path ./validator.wasm`
        /// consecutively.
        ///
        /// Default configuration building will fail if Kagami is run outside of Iroha repo (tracking
        /// issue: https://github.com/hyperledger/iroha/issues/3473). If you are going to run it outside
        /// of the repo, make sure to pass `--no-default-configuration` flag.
        Dir {
            /// Target directory where to place generated files.
            ///
            /// If the directory is not empty, Kagami will prompt it's re-creation. If the TTY is not
            /// interactive, Kagami will stop execution with non-zero exit code. In order to re-create
            /// the directory anyway, pass `--force` flag.
            outdir: PathBuf,
            /// Do not create default configuration in the `<outdir>/config` directory.
            ///
            /// Default `config.json`, `genesis.json` and `validator.wasm` are generated and put into
            /// the `<outdir>/config` directory. That directory is specified in the `volumes` field
            /// of the Docker Compose file.
            ///
            /// Setting this flag prevents copying of default configuration files into the output folder.
            /// The `config` directory will still be created, but the necessary configuration should be put
            /// there by the user manually.
            #[arg(long)]
            no_default_configuration: bool,
            #[command(flatten)]
            source: ModeDirSource,
        },
        /// Produce only a single Docker Compose configuration file
        File {
            /// Path to a generated Docker Compose configuration.
            ///
            /// If file exists, Kagami will prompt its overwriting. If the TTY is not
            /// interactive, Kagami will stop execution with non-zero exit code. In order to
            /// overwrite the file anyway, pass `--force` flag.
            outfile: PathBuf,
            /// Path to a directory with Iroha configuration. It will be mapped as volume for containers.
            ///
            /// The directory should contain `config.json` and `genesis.json`.
            #[arg(long)]
            config_dir: PathBuf,
            #[command(flatten)]
            source: ModeFileSource,
        },
    }

    #[derive(Args, Debug)]
    #[group(required = true, multiple = false)]
    pub struct ModeDirSource {
        /// Use Iroha GitHub source as a build source
        ///
        /// Clone `hyperledger/iroha` repo from the revision Kagami is built itself,
        /// and use the cloned source code to build images from.
        #[arg(long)]
        pub build_from_github: bool,
        /// Use specified docker image.
        ///
        /// Be careful with specifying a Dockerhub image as a source: Kagami Swarm only guarantees that
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

    #[derive(Args, Debug)]
    #[group(required = true, multiple = false)]
    // FIXME: I haven't found a way how to share `image` and `build` options between `file` and
    //        `dir` modes with correct grouping logic. `command(flatten)` doesn't work for it,
    //        so it's hard to share a single struct with "base source options"
    pub struct ModeFileSource {
        /// Same as `--image` for `swarm dir` subcommand
        #[arg(long)]
        pub image: Option<String>,
        /// Same as `--build` for `swarm build` subcommand
        #[arg(long, value_name = "PATH")]
        pub build: Option<PathBuf>,
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
            let cmd = SwarmArgs::augment_args(cmd);
            let matches = cmd.try_get_matches_from(
                std::iter::once("test").chain(args_str.as_ref().split(' ')),
            )?;
            Ok(matches)
        }

        #[test]
        fn works_in_file_mode() {
            let _ = match_args("-p 20 file --build . --config-dir ./config sample.yml").unwrap();
        }

        #[test]
        fn works_in_dir_mode_with_github_source() {
            let _ = match_args("-p 20 dir --build-from-github swarm").unwrap();
        }

        #[test]
        fn doesnt_allow_config_dir_for_dir_mode() {
            let _ = match_args("-p 1 dir --build-from-github  --config-dir ./ swarm").unwrap_err();
        }

        #[test]
        fn doesnt_allow_multiple_sources_in_dir_mode() {
            let _ = match_args("-p 1 dir --build-from-github --build . swarm").unwrap_err();
        }

        #[test]
        fn doesnt_allow_multiple_sources_in_file_mode() {
            let _ = match_args("-p 1 file --build . --image hp/iroha --config-dir ./ test.yml")
                .unwrap_err();
        }

        #[test]
        fn doesnt_allow_github_source_in_file_mode() {
            let _ =
                match_args("-p 1 file --build-from-github --config-dir ./ test.yml").unwrap_err();
        }

        #[test]
        fn doesnt_allow_omitting_source_in_dir_mode() {
            let _ = match_args("-p 1 dir ./test").unwrap_err();
        }

        #[test]
        fn doesnt_allow_omitting_source_in_file_mode() {
            let _ = match_args("-p 1 file test.yml --config-dir ./").unwrap_err();
        }
    }
}

pub use clap_args::SwarmArgs as Args;
use clap_args::{ModeDirSource, ModeFileSource};

impl Args {
    pub fn run(self) -> Outcome {
        let parsed: ParsedArgs = self.into();
        parsed.run()
    }
}

/// Type-strong version of [`Args`] with no ambiguity between arguments relationships
struct ParsedArgs {
    peers: NonZeroU16,
    seed: Option<String>,
    /// User allowance to override existing files/directories
    force: bool,
    mode: ParsedMode,
}

impl From<Args> for ParsedArgs {
    fn from(
        Args {
            peers,
            force,
            seed,
            command,
        }: Args,
    ) -> Self {
        let mode: ParsedMode = match command {
            clap_args::SwarmMode::File {
                outfile,
                config_dir,
                source,
            } => ParsedMode::File {
                target_file: outfile,
                config_dir,
                image_source: source.into(),
            },
            clap_args::SwarmMode::Dir {
                outdir,
                no_default_configuration,
                source,
            } => ParsedMode::Directory {
                target_dir: outdir,
                no_default_configuration,
                image_source: source.into(),
            },
        };

        Self {
            peers,
            force,
            seed,
            mode,
        }
    }
}

impl ParsedArgs {
    pub fn run(self) -> Outcome {
        let ui = UserInterface::new();

        let Self {
            peers,
            seed,
            force,
            mode,
        } = self;
        let seed = seed.map(String::into_bytes);
        let seed = seed.as_deref();

        match mode {
            ParsedMode::Directory {
                target_dir,
                no_default_configuration,
                image_source,
            } => {
                let target_file_raw = target_dir.join(FILE_COMPOSE);
                let target_dir = TargetDirectory::new(AbsolutePath::absolutize(&target_dir)?);
                let config_dir = AbsolutePath::absolutize(&target_dir.path.join(DIR_CONFIG))?;
                let target_file = AbsolutePath::absolutize(&target_file_raw)?;

                let prepare_dir_strategy = if force {
                    PrepareDirectoryStrategy::ForceRecreate
                } else {
                    PrepareDirectoryStrategy::Prompt
                };

                if let EarlyEnding::Halt = target_dir
                    .prepare(&prepare_dir_strategy, &ui)
                    .wrap_err("Failed to prepare directory")?
                {
                    return Ok(());
                }

                let image_source = image_source
                    .resolve(&target_dir, &ui)
                    .wrap_err("Failed to resolve the source of image")?;

                let ui = if no_default_configuration {
                    PrepareConfigurationStrategy::GenerateOnlyDirectory
                } else {
                    PrepareConfigurationStrategy::GenerateDefault
                }
                .run(&config_dir, ui)
                .wrap_err("Failed to prepare configuration")?;

                DockerComposeBuilder {
                    target_file: &target_file,
                    config_dir: &config_dir,
                    image_source,
                    peers,
                    seed,
                }
                .build_and_write()?;

                ui.log_directory_mode_complete(&target_dir.path, &target_file_raw);

                Ok(())
            }
            ParsedMode::File {
                target_file,
                config_dir,
                image_source,
            } => {
                let target_file_raw = target_file;
                let target_file = AbsolutePath::absolutize(&target_file_raw)?;
                let config_dir = AbsolutePath::absolutize(&config_dir)?;

                if target_file.exists() && !force {
                    if let ui::PromptAnswer::No = ui.prompt_remove_target_file(&target_file)? {
                        return Ok(());
                    }
                }

                let image_source = image_source
                    .resolve()
                    .wrap_err("Failed to resolve the source of image")?;

                DockerComposeBuilder {
                    target_file: &target_file,
                    config_dir: &config_dir,
                    image_source,
                    peers,
                    seed,
                }
                .build_and_write()?;

                ui.log_file_mode_complete(&target_file, &target_file_raw);

                Ok(())
            }
        }
    }
}

enum ParsedMode {
    Directory {
        target_dir: PathBuf,
        no_default_configuration: bool,
        image_source: SourceForDirectory,
    },
    File {
        target_file: PathBuf,
        config_dir: PathBuf,
        image_source: SourceForFile,
    },
}

enum SourceForDirectory {
    SameAsForFile(SourceForFile),
    BuildFromGitHub,
}

impl From<ModeDirSource> for SourceForDirectory {
    fn from(value: ModeDirSource) -> Self {
        match value {
            ModeDirSource {
                build: Some(path),
                image: None,
                build_from_github: false,
            } => Self::SameAsForFile(SourceForFile::Build { path }),
            ModeDirSource {
                build: None,
                image: Some(name),
                build_from_github: false,
            } => Self::SameAsForFile(SourceForFile::Image { name }),
            ModeDirSource {
                build: None,
                image: None,
                build_from_github: true,
            } => Self::BuildFromGitHub,
            _ => unreachable!("clap invariant"),
        }
    }
}

impl SourceForDirectory {
    /// Has a side effect: if self is [`Self::BuildFromGitHub`], it clones the repo into
    /// the target directory.
    fn resolve(self, target: &TargetDirectory, ui: &UserInterface) -> Result<ResolvedImageSource> {
        match self {
            Self::SameAsForFile(source_for_file) => source_for_file.resolve(),
            Self::BuildFromGitHub => {
                let clone_dir = target.path.join(DIR_CLONE);
                let clone_dir = AbsolutePath::absolutize(&clone_dir)?;

                ui.log_cloning_repo();

                shallow_git_clone(GIT_ORIGIN, GIT_REVISION, &clone_dir)
                    .wrap_err("Failed to clone the repo")?;

                Ok(ResolvedImageSource::Build { path: clone_dir })
            }
        }
    }
}

enum SourceForFile {
    Image { name: String },
    Build { path: PathBuf },
}

impl From<ModeFileSource> for SourceForFile {
    fn from(value: ModeFileSource) -> Self {
        match value {
            ModeFileSource {
                image: Some(name),
                build: None,
            } => Self::Image { name },
            ModeFileSource {
                image: None,
                build: Some(path),
            } => Self::Build { path },
            _ => unreachable!("clap invariant"),
        }
    }
}

impl SourceForFile {
    fn resolve(self) -> Result<ResolvedImageSource> {
        let resolved = match self {
            Self::Image { name } => ResolvedImageSource::Image { name },
            Self::Build { path: relative } => {
                let absolute =
                    AbsolutePath::absolutize(&relative).wrap_err("Failed to resolve build path")?;
                ResolvedImageSource::Build { path: absolute }
            }
        };

        Ok(resolved)
    }
}

#[derive(Debug)]
enum ResolvedImageSource {
    Image { name: String },
    Build { path: AbsolutePath },
}

fn shallow_git_clone(
    remote: impl AsRef<str>,
    revision: impl AsRef<str>,
    dir: &AbsolutePath,
) -> Result<()> {
    use duct::cmd;

    std::fs::create_dir(dir)?;

    cmd!("git", "init").dir(dir).run()?;
    cmd!("git", "remote", "add", "origin", remote.as_ref())
        .dir(dir)
        .run()?;
    cmd!("git", "fetch", "--depth=1", "origin", revision.as_ref())
        .dir(dir)
        .run()?;
    cmd!(
        "git",
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "FETCH_HEAD"
    )
    .dir(dir)
    .run()?;

    Ok(())
}

enum PrepareConfigurationStrategy {
    GenerateDefault,
    GenerateOnlyDirectory,
}

impl PrepareConfigurationStrategy {
    fn run(&self, config_dir: &AbsolutePath, ui: UserInterface) -> Result<UserInterface> {
        std::fs::create_dir(config_dir).wrap_err("Failed to create the config directory")?;

        let ui = match self {
            Self::GenerateOnlyDirectory => {
                ui.warn_no_default_config(config_dir);
                ui
            }
            Self::GenerateDefault => {
                let path_validator = PathBuf::from(FILE_VALIDATOR);

                let raw_genesis_block = {
                    let block = super::genesis::generate_default(Some(path_validator.clone()))
                        .wrap_err("Failed to generate genesis")?;
                    serde_json::to_string_pretty(&block)?
                };

                let default_config = {
                    let proxy = iroha_config::iroha::ConfigurationProxy::default();
                    serde_json::to_string_pretty(&proxy)?
                };

                let spinner = ui.spinner_validator();

                let validator = super::validator::construct_validator()
                    .wrap_err("Failed to construct the validator")?;

                let ui = spinner.done();

                File::create(config_dir.join(FILE_GENESIS))?
                    .write_all(raw_genesis_block.as_bytes())?;
                File::create(config_dir.join(FILE_CONFIG))?.write_all(default_config.as_bytes())?;
                File::create(config_dir.join(path_validator))?.write_all(validator.as_slice())?;

                ui.log_default_configuration_is_written(config_dir);
                ui
            }
        };

        Ok(ui)
    }
}

enum PrepareDirectoryStrategy {
    ForceRecreate,
    Prompt,
}

enum EarlyEnding {
    Halt,
    Continue,
}

#[derive(Clone, Debug)]
struct TargetDirectory {
    path: AbsolutePath,
}

impl TargetDirectory {
    fn new(path: AbsolutePath) -> Self {
        Self { path }
    }

    fn prepare(
        &self,
        strategy: &PrepareDirectoryStrategy,
        ui: &UserInterface,
    ) -> Result<EarlyEnding> {
        // FIXME: use [`std::fs::try_exists`] when it is stable
        let was_removed = if self.path.exists() {
            match strategy {
                PrepareDirectoryStrategy::ForceRecreate => {
                    self.remove_dir()?;
                }
                PrepareDirectoryStrategy::Prompt => {
                    if let EarlyEnding::Halt = self.remove_directory_with_prompt(ui)? {
                        return Ok(EarlyEnding::Halt);
                    }
                }
            }
            true
        } else {
            false
        };

        self.make_dir_recursive()?;

        ui.log_target_directory_ready(
            &self.path,
            if was_removed {
                ui::TargetDirectoryAction::Recreated
            } else {
                ui::TargetDirectoryAction::Created
            },
        );

        Ok(EarlyEnding::Continue)
    }

    /// `rm -r <dir>`
    fn remove_dir(&self) -> Result<()> {
        std::fs::remove_dir_all(&self.path)
            .wrap_err_with(|| eyre!("Failed to remove the directory: {}", self.path.display()))
    }

    /// If user says "no", program should just exit, so it returns [`EarlyEnding::Halt`].
    ///
    /// # Errors
    ///
    /// - If TTY is not interactive
    fn remove_directory_with_prompt(&self, ui: &UserInterface) -> Result<EarlyEnding> {
        if let ui::PromptAnswer::Yes =
            ui.prompt_remove_target_dir(&self.path).wrap_err_with(|| {
                eyre!(
                    "Failed to prompt removal for the directory: {}",
                    self.path.display()
                )
            })?
        {
            self.remove_dir()?;
            Ok(EarlyEnding::Continue)
        } else {
            Ok(EarlyEnding::Halt)
        }
    }

    /// `mkdir -r <dir>`
    fn make_dir_recursive(&self) -> Result<()> {
        std::fs::create_dir_all(&self.path).wrap_err_with(|| {
            eyre!(
                "Failed to recursively create the directory: {}",
                self.path.display()
            )
        })
    }
}

#[derive(Debug)]
struct DockerComposeBuilder<'a> {
    /// Needed to compute a relative source build path
    target_file: &'a AbsolutePath,
    /// Needed to put into `volumes`
    config_dir: &'a AbsolutePath,
    image_source: ResolvedImageSource,
    peers: NonZeroU16,
    /// Crypto seed to use for keys generation
    seed: Option<&'a [u8]>,
}

impl DockerComposeBuilder<'_> {
    fn build(&self) -> Result<DockerCompose> {
        let target_file_dir = self.target_file.parent().ok_or_else(|| {
            eyre!(
                "Cannot get a directory of a file {}",
                self.target_file.display()
            )
        })?;

        let peers = peer_generator::generate_peers(self.peers, self.seed)
            .wrap_err("Failed to generate peers")?;
        let genesis_key_pair = generate_key_pair(self.seed, GENESIS_KEYPAIR_SEED)
            .wrap_err("Failed to generate genesis key pair")?;
        let service_source = match &self.image_source {
            ResolvedImageSource::Build { path } => {
                ServiceSource::Build(path.relative_to(target_file_dir)?)
            }
            ResolvedImageSource::Image { name } => ServiceSource::Image(name.clone()),
        };
        let volumes = vec![(
            self.config_dir
                .relative_to(target_file_dir)?
                .to_str()
                .wrap_err("Config directory path is not a valid string")?
                .to_owned(),
            DIR_CONFIG_IN_DOCKER.to_owned(),
        )];

        let trusted_peers: BTreeSet<PeerId> =
            peers.values().map(peer_generator::Peer::id).collect();

        let mut peers_iter = peers.iter();

        let first_peer_service = {
            let (name, peer) = peers_iter.next().expect("There is non-zero count of peers");
            let service = DockerComposeService::new(
                peer,
                service_source.clone(),
                volumes.clone(),
                trusted_peers.clone(),
                Some(genesis_key_pair),
            );

            (name.clone(), service)
        };

        let services = peers_iter
            .map(|(name, peer)| {
                let service = DockerComposeService::new(
                    peer,
                    service_source.clone(),
                    volumes.clone(),
                    trusted_peers.clone(),
                    None,
                );

                (name.clone(), service)
            })
            .chain(std::iter::once(first_peer_service))
            .collect();

        let compose = DockerCompose::new(services);
        Ok(compose)
    }

    fn build_and_write(&self) -> Result<()> {
        let target_file = self.target_file;
        let compose = self
            .build()
            .wrap_err("Failed to build a docker compose file")?;
        compose.write_file(&target_file.path)
    }
}

#[derive(Clone, Debug)]
struct AbsolutePath {
    path: PathBuf,
}

impl Deref for AbsolutePath {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for AbsolutePath {
    fn as_ref(&self) -> &Path {
        self.path.as_path()
    }
}

impl AsRef<OsStr> for AbsolutePath {
    fn as_ref(&self) -> &OsStr {
        self.path.as_ref()
    }
}

impl AbsolutePath {
    fn absolutize(path: &PathBuf) -> Result<Self> {
        Ok(Self {
            path: if path.is_absolute() {
                path.clone()
            } else {
                path.absolutize()?.to_path_buf()
            },
        })
    }

    /// Relative path from self to other.
    fn relative_to(&self, other: &(impl AsRef<Path> + ?Sized)) -> Result<PathBuf> {
        pathdiff::diff_paths(self, other)
                .ok_or_else(|| {
                    eyre!(
                        "failed to build relative path from {} to {}",
                        other.as_ref().display(),
                        self.display(),
                    )
                })
                // docker-compose might not like "test" path, but "./test" instead 
                .map(|rel| {
                    if rel.starts_with("..") {
                        rel
                    } else {
                        Path::new("./").join(rel)

                    }
                })
    }
}

/// Swarm-specific seed-based key pair generation
pub fn generate_key_pair(
    base_seed: Option<&[u8]>,
    additional_seed: &[u8],
) -> Result<KeyPair, IrohaCryptoError> {
    let cfg = base_seed
        .map(|base| {
            let seed: Vec<_> = base.iter().chain(additional_seed).copied().collect();
            KeyGenConfiguration::default().use_seed(seed)
        })
        .unwrap_or_default();

    KeyPair::generate_with_configuration(cfg)
}

mod peer_generator {
    use std::{collections::BTreeMap, num::NonZeroU16};

    use color_eyre::{eyre::Context, Report};
    use iroha_crypto::KeyPair;
    use iroha_data_model::prelude::PeerId;
    use iroha_primitives::addr::{SocketAddr, SocketAddrHost};

    const BASE_PORT_P2P: u16 = 1337;
    const BASE_PORT_API: u16 = 8080;
    const BASE_PORT_TELEMETRY: u16 = 8180;
    const BASE_SERVICE_NAME: &'_ str = "iroha";

    pub struct Peer {
        pub name: String,
        pub port_p2p: u16,
        pub port_api: u16,
        pub port_telemetry: u16,
        pub key_pair: KeyPair,
    }

    impl Peer {
        pub fn id(&self) -> PeerId {
            PeerId::new(&self.addr(self.port_p2p), self.key_pair.public_key())
        }

        pub fn addr(&self, port: u16) -> SocketAddr {
            SocketAddr::Host(SocketAddrHost {
                host: self.name.clone().into(),
                port,
            })
        }
    }

    pub fn generate_peers(
        peers: NonZeroU16,
        base_seed: Option<&[u8]>,
    ) -> Result<BTreeMap<String, Peer>, Report> {
        (0u16..peers.get())
            .map(|i| {
                let service_name = format!("{BASE_SERVICE_NAME}{i}");

                let key_pair = super::generate_key_pair(base_seed, service_name.as_bytes())
                    .wrap_err("Failed to generate key pair")?;

                let peer = Peer {
                    name: service_name.clone(),
                    port_p2p: BASE_PORT_P2P + i,
                    port_api: BASE_PORT_API + i,
                    port_telemetry: BASE_PORT_TELEMETRY + i,
                    key_pair,
                };

                Ok((service_name, peer))
            })
            .collect()
    }
}

mod serialize_docker_compose {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt::Display,
        fs::File,
        io::Write,
        path::PathBuf,
    };

    use color_eyre::eyre::{eyre, Context};
    use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
    use iroha_data_model::prelude::PeerId;
    use iroha_primitives::addr::SocketAddr;
    use serde::{ser::Error as _, Serialize, Serializer};

    use super::peer_generator::Peer;

    const COMMAND_SUBMIT_GENESIS: &str = "iroha --submit-genesis";
    const DOCKER_COMPOSE_VERSION: &str = "3.8";

    #[derive(Serialize, Debug)]
    pub struct DockerCompose {
        version: DockerComposeVersion,
        services: BTreeMap<String, DockerComposeService>,
    }

    impl DockerCompose {
        pub fn new(services: BTreeMap<String, DockerComposeService>) -> Self {
            Self {
                version: DockerComposeVersion,
                services,
            }
        }

        pub fn write_file(&self, path: &PathBuf) -> Result<(), color_eyre::Report> {
            let yaml = serde_yaml::to_string(self).wrap_err("Failed to serialise YAML")?;
            File::create(path)
                .wrap_err_with(|| eyre!("Failed to create file {}", path.display()))?
                .write_all(yaml.as_bytes())
                .wrap_err_with(|| eyre!("Failed to write YAML content into {}", path.display()))?;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct DockerComposeVersion;

    impl Serialize for DockerComposeVersion {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(DOCKER_COMPOSE_VERSION)
        }
    }

    #[derive(Serialize, Debug)]
    pub struct DockerComposeService {
        #[serde(flatten)]
        source: ServiceSource,
        environment: FullPeerEnv,
        ports: Vec<PairColon<u16, u16>>,
        volumes: Vec<PairColon<String, String>>,
        init: AlwaysTrue,
        #[serde(skip_serializing_if = "ServiceCommand::is_none")]
        command: ServiceCommand,
    }

    impl DockerComposeService {
        pub fn new(
            peer: &Peer,
            source: ServiceSource,
            volumes: Vec<(String, String)>,
            trusted_peers: BTreeSet<PeerId>,
            genesis_key_pair: Option<KeyPair>,
        ) -> Self {
            let ports = vec![
                PairColon(peer.port_p2p, peer.port_p2p),
                PairColon(peer.port_api, peer.port_api),
                PairColon(peer.port_telemetry, peer.port_telemetry),
            ];

            let command = if genesis_key_pair.is_some() {
                ServiceCommand::SubmitGenesis
            } else {
                ServiceCommand::None
            };

            let compact_env = CompactPeerEnv {
                trusted_peers,
                key_pair: peer.key_pair.clone(),
                genesis_key_pair,
                p2p_addr: peer.addr(peer.port_p2p),
                api_addr: peer.addr(peer.port_api),
                telemetry_addr: peer.addr(peer.port_telemetry),
            };

            Self {
                source,
                command,
                init: AlwaysTrue,
                volumes: volumes.into_iter().map(|(a, b)| PairColon(a, b)).collect(),
                ports,
                environment: compact_env.into(),
            }
        }
    }

    #[derive(Debug)]
    struct AlwaysTrue;

    impl Serialize for AlwaysTrue {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_bool(true)
        }
    }

    #[derive(Debug)]
    enum ServiceCommand {
        SubmitGenesis,
        None,
    }

    impl ServiceCommand {
        fn is_none(&self) -> bool {
            matches!(self, Self::None)
        }
    }

    impl Serialize for ServiceCommand {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::None => serializer.serialize_none(),
                Self::SubmitGenesis => serializer.serialize_str(COMMAND_SUBMIT_GENESIS),
            }
        }
    }

    /// Serializes as `"{0}:{1}"`
    #[derive(derive_more::Display, Debug)]
    #[display(fmt = "{_0}:{_1}")]
    struct PairColon<T, U>(T, U)
    where
        T: Display,
        U: Display;

    impl<T, U> Serialize for PairColon<T, U>
    where
        T: Display,
        U: Display,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.collect_str(self)
        }
    }

    #[derive(Serialize, Clone, Debug)]
    #[serde(rename_all = "lowercase")]
    pub enum ServiceSource {
        Image(String),
        Build(PathBuf),
    }

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    struct FullPeerEnv {
        iroha_public_key: PublicKey,
        iroha_private_key: SerializeAsJsonStr<PrivateKey>,
        torii_p2p_addr: SocketAddr,
        torii_api_url: SocketAddr,
        torii_telemetry_url: SocketAddr,
        #[serde(skip_serializing_if = "Option::is_none")]
        iroha_genesis_account_public_key: Option<PublicKey>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iroha_genesis_account_private_key: Option<SerializeAsJsonStr<PrivateKey>>,
        sumeragi_trusted_peers: SerializeAsJsonStr<BTreeSet<PeerId>>,
    }

    struct CompactPeerEnv {
        key_pair: KeyPair,
        /// Genesis key pair is only needed for a peer that is submitting the genesis block
        genesis_key_pair: Option<KeyPair>,
        p2p_addr: SocketAddr,
        api_addr: SocketAddr,
        telemetry_addr: SocketAddr,
        trusted_peers: BTreeSet<PeerId>,
    }

    impl From<CompactPeerEnv> for FullPeerEnv {
        fn from(value: CompactPeerEnv) -> Self {
            let (genesis_public_key, genesis_private_key) =
                value.genesis_key_pair.map_or((None, None), |key_pair| {
                    (
                        Some(key_pair.public_key().clone()),
                        Some(SerializeAsJsonStr(key_pair.private_key().clone())),
                    )
                });

            Self {
                iroha_public_key: value.key_pair.public_key().clone(),
                iroha_private_key: SerializeAsJsonStr(value.key_pair.private_key().clone()),
                iroha_genesis_account_public_key: genesis_public_key,
                iroha_genesis_account_private_key: genesis_private_key,
                torii_p2p_addr: value.p2p_addr,
                torii_api_url: value.api_addr,
                torii_telemetry_url: value.telemetry_addr,
                sumeragi_trusted_peers: SerializeAsJsonStr(value.trusted_peers),
            }
        }
    }

    #[derive(Debug)]
    struct SerializeAsJsonStr<T>(T);

    impl<T> serde::Serialize for SerializeAsJsonStr<T>
    where
        T: serde::Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let json = serde_json::to_string(&self.0).map_err(|json_err| {
                S::Error::custom(format!("failed to serialize as JSON: {json_err}"))
            })?;
            serializer.serialize_str(&json)
        }
    }

    #[cfg(test)]
    mod test {
        use std::{
            cell::RefCell,
            collections::{BTreeMap, BTreeSet, HashMap, HashSet},
            env::VarError,
            ffi::OsStr,
            path::PathBuf,
            str::FromStr,
        };

        use color_eyre::eyre::Context;
        use iroha_config::{
            base::proxy::{FetchEnv, LoadFromEnv, Override},
            iroha::ConfigurationProxy,
        };
        use iroha_crypto::{KeyGenConfiguration, KeyPair};
        use iroha_primitives::addr::SocketAddr;

        use super::{
            CompactPeerEnv, DockerCompose, DockerComposeService, DockerComposeVersion, FullPeerEnv,
            PairColon, ServiceSource,
        };
        use crate::swarm::serialize_docker_compose::{AlwaysTrue, ServiceCommand};

        struct TestEnv {
            env: HashMap<String, String>,
            /// Set of env variables that weren't fetched yet
            untouched: RefCell<HashSet<String>>,
        }

        impl From<FullPeerEnv> for TestEnv {
            fn from(peer_env: FullPeerEnv) -> Self {
                let json = serde_json::to_string(&peer_env).expect("Must be serializable");
                let env: HashMap<_, _> =
                    serde_json::from_str(&json).expect("Must be deserializable into a hash map");
                let untouched = env.keys().map(Clone::clone).collect();
                Self {
                    env,
                    untouched: RefCell::new(untouched),
                }
            }
        }

        impl From<CompactPeerEnv> for TestEnv {
            fn from(value: CompactPeerEnv) -> Self {
                let full: FullPeerEnv = value.into();
                full.into()
            }
        }

        impl FetchEnv for TestEnv {
            fn fetch<K: AsRef<OsStr>>(&self, key: K) -> Result<String, VarError> {
                let key_str = key
                    .as_ref()
                    .to_str()
                    .ok_or_else(|| VarError::NotUnicode(key.as_ref().into()))?;

                let res = self
                    .env
                    .get(key_str)
                    .ok_or(VarError::NotPresent)
                    .map(std::clone::Clone::clone);

                if res.is_ok() {
                    self.untouched.borrow_mut().remove(key_str);
                }

                res
            }
        }

        impl TestEnv {
            fn assert_everything_covered(&self) {
                assert_eq!(*self.untouched.borrow(), HashSet::new());
            }
        }

        #[test]
        fn default_config_with_swarm_env_are_exhaustive() {
            let keypair = KeyPair::generate().unwrap();
            let env: TestEnv = CompactPeerEnv {
                key_pair: keypair.clone(),
                genesis_key_pair: Some(keypair),
                p2p_addr: SocketAddr::from_str("127.0.0.1:1337").unwrap(),
                api_addr: SocketAddr::from_str("127.0.0.1:1338").unwrap(),
                telemetry_addr: SocketAddr::from_str("127.0.0.1:1339").unwrap(),
                trusted_peers: BTreeSet::new(),
            }
            .into();

            let proxy = ConfigurationProxy::default()
                .override_with(ConfigurationProxy::from_env(&env).expect("valid env"));

            let _cfg = proxy
                .build()
                .wrap_err("Failed to build configuration")
                .expect("Default configuration with swarm's env should be exhaustive");

            env.assert_everything_covered();
        }

        #[test]
        fn serialize_image_source() {
            let source = ServiceSource::Image("hyperledger/iroha2:stable".to_owned());
            let serialised = serde_json::to_string(&source).unwrap();
            assert_eq!(serialised, r#"{"image":"hyperledger/iroha2:stable"}"#);
        }

        #[test]
        fn serialize_docker_compose() {
            let compose = DockerCompose {
                version: DockerComposeVersion,
                services: {
                    let mut map = BTreeMap::new();

                    let key_pair = KeyPair::generate_with_configuration(
                        KeyGenConfiguration::default().use_seed(vec![1, 5, 1, 2, 2, 3, 4, 1, 2, 3]),
                    )
                    .unwrap();

                    map.insert(
                        "iroha0".to_owned(),
                        DockerComposeService {
                            source: ServiceSource::Build(PathBuf::from(".")),
                            environment: CompactPeerEnv {
                                key_pair: key_pair.clone(),
                                genesis_key_pair: Some(key_pair),
                                p2p_addr: SocketAddr::from_str("iroha1:1339").unwrap(),
                                api_addr: SocketAddr::from_str("iroha1:1338").unwrap(),
                                telemetry_addr: SocketAddr::from_str("iroha1:1337").unwrap(),
                                trusted_peers: BTreeSet::new(),
                            }
                            .into(),
                            ports: vec![
                                PairColon(1337, 1337),
                                PairColon(8080, 8080),
                                PairColon(8081, 8081),
                            ],
                            volumes: vec![PairColon(
                                "./configs/peer/legacy_stable".to_owned(),
                                "/config".to_owned(),
                            )],
                            init: AlwaysTrue,
                            command: ServiceCommand::SubmitGenesis,
                        },
                    );

                    map
                },
            };

            let actual = serde_yaml::to_string(&compose).expect("Should be serialisable");
            let expected = expect_test::expect![[r#"
                version: '3.8'
                services:
                  iroha0:
                    build: .
                    environment:
                      IROHA_PUBLIC_KEY: ed012039E5BF092186FACC358770792A493CA98A83740643A3D41389483CF334F748C8
                      IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"db9d90d20f969177bd5882f9fe211d14d1399d5440d04e3468783d169bbc4a8e39e5bf092186facc358770792a493ca98a83740643a3d41389483cf334f748c8"}'
                      TORII_P2P_ADDR: iroha1:1339
                      TORII_API_URL: iroha1:1338
                      TORII_TELEMETRY_URL: iroha1:1337
                      IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed012039E5BF092186FACC358770792A493CA98A83740643A3D41389483CF334F748C8
                      IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"db9d90d20f969177bd5882f9fe211d14d1399d5440d04e3468783d169bbc4a8e39e5bf092186facc358770792a493ca98a83740643a3d41389483cf334f748c8"}'
                      SUMERAGI_TRUSTED_PEERS: '[]'
                    ports:
                    - 1337:1337
                    - 8080:8080
                    - 8081:8081
                    volumes:
                    - ./configs/peer/legacy_stable:/config
                    init: true
                    command: iroha --submit-genesis
            "#]];
            expected.assert_eq(&actual);
        }

        #[test]
        fn empty_genesis_key_pair_is_skipped_in_env() {
            let env: FullPeerEnv = CompactPeerEnv {
                key_pair: KeyPair::generate_with_configuration(
                    KeyGenConfiguration::default().use_seed(vec![0, 1, 2]),
                )
                .unwrap(),
                genesis_key_pair: None,
                p2p_addr: SocketAddr::from_str("iroha0:1337").unwrap(),
                api_addr: SocketAddr::from_str("iroha0:1337").unwrap(),
                telemetry_addr: SocketAddr::from_str("iroha0:1337").unwrap(),
                trusted_peers: BTreeSet::new(),
            }
            .into();

            let actual = serde_yaml::to_string(&env).unwrap();
            let expected = expect_test::expect![[r#"
                IROHA_PUBLIC_KEY: ed0120415388A90FA238196737746A70565D041CFB32EAA0C89FF8CB244C7F832A6EBD
                IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"6bf163fd75192b81a78cb20c5f8cb917f591ac6635f2577e6ca305c27a456a5d415388a90fa238196737746a70565d041cfb32eaa0c89ff8cb244c7f832a6ebd"}'
                TORII_P2P_ADDR: iroha0:1337
                TORII_API_URL: iroha0:1337
                TORII_TELEMETRY_URL: iroha0:1337
                SUMERAGI_TRUSTED_PEERS: '[]'
            "#]];
            expected.assert_eq(&actual);
        }
    }
}

mod ui {
    use std::path::Path;

    use color_eyre::Help;
    use owo_colors::OwoColorize;

    use super::{AbsolutePath, Result, FORCE_ARG_SUGGESTION};

    mod prefix {
        use owo_colors::{FgColorDisplay, OwoColorize};

        pub fn info() -> FgColorDisplay<'static, owo_colors::colors::BrightBlue, &'static str> {
            "ℹ".bright_blue()
        }

        pub fn success() -> FgColorDisplay<'static, owo_colors::colors::Green, &'static str> {
            "✓".green()
        }

        pub fn warning() -> FgColorDisplay<'static, owo_colors::colors::Yellow, &'static str> {
            "‼".yellow()
        }
    }

    pub(super) struct UserInterface;

    pub(super) enum PromptAnswer {
        Yes,
        No,
    }

    impl From<bool> for PromptAnswer {
        fn from(value: bool) -> Self {
            if value {
                Self::Yes
            } else {
                Self::No
            }
        }
    }

    #[derive(Copy, Clone)]
    pub(super) enum TargetDirectoryAction {
        Created,
        Recreated,
    }

    impl UserInterface {
        pub(super) fn new() -> Self {
            Self
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_target_directory_ready(
            &self,
            dir: &AbsolutePath,
            action: TargetDirectoryAction,
        ) {
            println!(
                "{} {} directory: {}",
                prefix::info(),
                match action {
                    TargetDirectoryAction::Created => "Created",
                    TargetDirectoryAction::Recreated => "Re-created",
                },
                dir.display().green().bold()
            );
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_default_configuration_is_written(&self, dir: &AbsolutePath) {
            println!(
                "{} Generated default configuration in {}",
                prefix::info(),
                dir.display().green().bold()
            );
        }

        #[allow(clippy::unused_self)]
        pub(super) fn warn_no_default_config(&self, dir: &AbsolutePath) {
            println!(
                "{} {}\n\n    {}\n",
                prefix::warning().bold(),
                "Config directory is created, but the configuration itself is not.\
                    \n  Without any configuration, generated peers will be unable to start.\
                    \n  Don't forget to put the configuration into:"
                    .yellow(),
                dir.display().bold().yellow()
            );
        }

        #[allow(clippy::unused_self)]
        pub(super) fn prompt_remove_target_dir(&self, dir: &AbsolutePath) -> Result<PromptAnswer> {
            inquire::Confirm::new(&format!(
                "Directory {} already exists. Remove it?",
                dir.display().blue().bold()
            ))
            .with_default(false)
            .prompt()
            .suggestion(FORCE_ARG_SUGGESTION)
            .map(PromptAnswer::from)
        }

        #[allow(clippy::unused_self)]
        pub(super) fn prompt_remove_target_file(
            &self,
            file: &AbsolutePath,
        ) -> Result<PromptAnswer> {
            inquire::Confirm::new(&format!(
                "File {} already exists. Remove it?",
                file.display().blue().bold()
            ))
            .with_default(false)
            .prompt()
            .suggestion(FORCE_ARG_SUGGESTION)
            .map(PromptAnswer::from)
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_cloning_repo(&self) {
            println!("{} Cloning git repo...", prefix::info());
        }

        pub(super) fn spinner_validator(self) -> SpinnerValidator {
            SpinnerValidator::new(self)
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_directory_mode_complete(&self, dir: &AbsolutePath, file_raw: &Path) {
            println!(
                "{} Docker compose configuration is ready at:\n\n    {}\
                    \n\n  You could run `{} {} {}`",
                prefix::success(),
                dir.display().green().bold(),
                "docker compose -f".blue(),
                file_raw.display().blue().bold(),
                "up".blue(),
            );
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_file_mode_complete(&self, file: &AbsolutePath, file_raw: &Path) {
            println!(
                "{} Docker compose configuration is ready at:\n\n    {}\
                    \n\n  You could run `{} {} {}`",
                prefix::success(),
                file.display().green().bold(),
                "docker compose -f".blue(),
                file_raw.display().blue().bold(),
                "up".blue(),
            );
        }
    }

    struct Spinner {
        inner: spinoff::Spinner,
        ui: UserInterface,
    }

    impl Spinner {
        fn new(message: impl AsRef<str>, ui: UserInterface) -> Self {
            let inner = spinoff::Spinner::new(
                spinoff::spinners::Dots,
                message.as_ref().to_owned(),
                spinoff::Color::White,
            );

            Self { inner, ui }
        }

        fn done(self, message: impl AsRef<str>) -> UserInterface {
            self.inner
                .stop_and_persist(&format!("{}", prefix::success()), message.as_ref());
            self.ui
        }
    }

    pub(super) struct SpinnerValidator(Spinner);

    impl SpinnerValidator {
        fn new(ui: UserInterface) -> Self {
            Self(Spinner::new("Constructing the default validator...", ui))
        }

        pub(super) fn done(self) -> UserInterface {
            self.0.done("Constructed the validator")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{AbsolutePath, Absolutize, DockerComposeBuilder, ResolvedImageSource};

    impl AbsolutePath {
        fn from_virtual(path: &PathBuf, virtual_root: impl AsRef<Path> + Sized) -> Self {
            let path = path
                .absolutize_virtually(virtual_root)
                .unwrap()
                .to_path_buf();
            Self { path }
        }
    }

    #[test]
    fn relative_inner_path_starts_with_dot() {
        let root = PathBuf::from("/");
        let a = AbsolutePath::from_virtual(&PathBuf::from("./a/b/c"), &root);
        let b = AbsolutePath::from_virtual(&PathBuf::from("./"), &root);

        assert_eq!(a.relative_to(&b).unwrap(), PathBuf::from("./a/b/c"));
    }

    #[test]
    fn relative_outer_path_starts_with_dots() {
        let root = Path::new("/");
        let a = AbsolutePath::from_virtual(&PathBuf::from("./a/b/c"), root);
        let b = AbsolutePath::from_virtual(&PathBuf::from("./cde"), root);

        assert_eq!(b.relative_to(&a).unwrap(), PathBuf::from("../../../cde"));
    }

    #[test]
    fn generate_peers_deterministically() {
        let root = Path::new("/");
        let seed = Some(b"iroha".to_vec());
        let seed = seed.as_deref();

        let composed = DockerComposeBuilder {
            target_file: &AbsolutePath::from_virtual(
                &PathBuf::from("/test/docker-compose.yml"),
                root,
            ),
            config_dir: &AbsolutePath::from_virtual(&PathBuf::from("/test/config"), root),
            peers: 4.try_into().unwrap(),
            image_source: ResolvedImageSource::Build {
                path: AbsolutePath::from_virtual(&PathBuf::from("/test/iroha-cloned"), root),
            },
            seed,
        }
        .build()
        .expect("should build with no errors");

        let yaml = serde_yaml::to_string(&composed).unwrap();
        let expected = expect_test::expect![[r#"
            version: '3.8'
            services:
              iroha0:
                build: ./iroha-cloned
                environment:
                  IROHA_PUBLIC_KEY: ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13
                  IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5f8d1291bf6b762ee748a87182345d135fd167062857aa4f20ba39f25e74c4b0f0321eb4139163c35f88bf78520ff7071499d7f4e79854550028a196c7b49e13"}'
                  TORII_P2P_ADDR: iroha0:1337
                  TORII_API_URL: iroha0:8080
                  TORII_TELEMETRY_URL: iroha0:8180
                  IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed01203420F48A9EEB12513B8EB7DAF71979CE80A1013F5F341C10DCDA4F6AA19F97A9
                  IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5a6d5f06a90d29ad906e2f6ea8b41b4ef187849d0d397081a4a15ffcbe71e7c73420f48a9eeb12513b8eb7daf71979ce80a1013f5f341c10dcda4f6aa19f97a9"}'
                  SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                ports:
                - 1337:1337
                - 8080:8080
                - 8180:8180
                volumes:
                - ./config:/config
                init: true
                command: iroha --submit-genesis
              iroha1:
                build: ./iroha-cloned
                environment:
                  IROHA_PUBLIC_KEY: ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C
                  IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"8d34d2c6a699c61e7a9d5aabbbd07629029dfb4f9a0800d65aa6570113edb465a88554aa5c86d28d0eebec497235664433e807881cd31e12a1af6c4d8b0f026c"}'
                  TORII_P2P_ADDR: iroha1:1338
                  TORII_API_URL: iroha1:8081
                  TORII_TELEMETRY_URL: iroha1:8181
                  SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                ports:
                - 1338:1338
                - 8081:8081
                - 8181:8181
                volumes:
                - ./config:/config
                init: true
              iroha2:
                build: ./iroha-cloned
                environment:
                  IROHA_PUBLIC_KEY: ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4
                  IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"cf4515a82289f312868027568c0da0ee3f0fde7fef1b69deb47b19fde7cbc169312c1b7b5de23d366adcf23cd6db92ce18b2aa283c7d9f5033b969c2dc2b92f4"}'
                  TORII_P2P_ADDR: iroha2:1339
                  TORII_API_URL: iroha2:8082
                  TORII_TELEMETRY_URL: iroha2:8182
                  SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                ports:
                - 1339:1339
                - 8082:8082
                - 8182:8182
                volumes:
                - ./config:/config
                init: true
              iroha3:
                build: ./iroha-cloned
                environment:
                  IROHA_PUBLIC_KEY: ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE
                  IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"ab0e99c2b845b4ac7b3e88d25a860793c7eb600a25c66c75cba0bae91e955aa6854457b2e3d6082181da73dc01c1e6f93a72d0c45268dc8845755287e98a5dee"}'
                  TORII_P2P_ADDR: iroha3:1340
                  TORII_API_URL: iroha3:8083
                  TORII_TELEMETRY_URL: iroha3:8183
                  SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                ports:
                - 1340:1340
                - 8083:8083
                - 8183:8183
                volumes:
                - ./config:/config
                init: true
        "#]];
        expected.assert_eq(&yaml);
    }
}
