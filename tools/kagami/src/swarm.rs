use std::{
    collections::BTreeSet,
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
use iroha_data_model::prelude::PeerId;
use path_absolutize::Absolutize;
use serialize_docker_compose::{DockerCompose, DockerComposeService, ServiceSource};
use ui::UserInterface;

use super::{ClapArgs, Outcome};

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
const DIR_FORCE_SUGGESTION: &str =
    "You can pass `--outdir-force` flag to remove the directory without prompting";
const GENESIS_KEYPAIR_SEED: &[u8; 7] = b"genesis";

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(flatten)]
    source: ImageSourceArgs,
    /// How many peers to generate within the docker-compose.
    #[arg(long, short)]
    peers: NonZeroU16,
    /// Target directory where to place generated files.
    ///
    /// If the directory is not empty, Kagami will prompt it's re-creation. If the TTY is not
    /// interactive, Kagami will stop execution with non-zero exit code. In order to re-create
    /// the directory anyway, pass `--outdir-force` flag.
    #[arg(long)]
    outdir: PathBuf,
    /// Re-create the target directory if it already exists.
    #[arg(long)]
    outdir_force: bool,
    /// Do not create default configuration in the `<outdir>/config` directory.
    ///
    /// Default `config.json`, `genesis.json` and `validator.wasm` are generated and put into
    /// the `<outdir>/config` directory. That directory is specified in the Docker Compose
    /// `volumes` field.
    ///
    /// If you don't need the defaults, you could set this flag. The `config` directory will be
    /// created anyway, but you should put the necessary configuration there by yourself.
    #[arg(long)]
    no_default_configuration: bool,
    /// Might be useful for deterministic key generation.
    ///
    /// It could be any string. Its UTF-8 bytes will be used as a seed.
    #[arg(long, short)]
    seed: Option<String>,
}

impl Args {
    pub fn run(self) -> Outcome {
        let ui = UserInterface::new();

        let prepare_dir_strategy = if self.outdir_force {
            PrepareDirectoryStrategy::ForceRecreate
        } else {
            PrepareDirectoryStrategy::Prompt
        };
        let source = ImageSource::from(self.source);
        let target_dir = TargetDirectory::new(AbsolutePath::absolutize(self.outdir)?);

        if let EarlyEnding::Halt = target_dir
            .prepare(&prepare_dir_strategy, &ui)
            .wrap_err("failed to prepare directory")?
        {
            return Ok(());
        }

        let config_dir = AbsolutePath::absolutize(target_dir.path.join(DIR_CONFIG))?;

        let source = source
            .resolve(&target_dir, &ui)
            .wrap_err("failed to resolve the source of image")?;

        let ui = if self.no_default_configuration {
            PrepareConfigurationStrategy::GenerateOnlyDirectory
        } else {
            PrepareConfigurationStrategy::GenerateDefault
        }
        .run(&config_dir, ui)
        .wrap_err("failed to prepare configuration")?;

        DockerComposeBuilder {
            target_dir: target_dir.path.clone(),
            config_dir,
            source,
            peers: self.peers,
            seed: self.seed.map(String::into_bytes),
        }
        .build()
        .wrap_err("failed to build docker compose")?
        .write_file(&target_dir.path.join(FILE_COMPOSE))
        .wrap_err("failed to write compose file")?;

        ui.log_complete(&target_dir.path);

        Ok(())
    }
}

#[derive(ClapArgs, Clone, Debug)]
#[group(required = true, multiple = false)]
struct ImageSourceArgs {
    /// Use specified docker image.
    #[arg(long)]
    image: Option<String>,
    /// Use local path location of the Iroha source code to build images from.
    ///
    /// If the path is relative, it will be resolved relative to the CWD.
    #[arg(long, value_name = "PATH")]
    build: Option<PathBuf>,
    /// Clone `hyperledger/iroha` repo from the revision Kagami is built itself,
    /// and use the cloned source code to build images from.
    #[arg(long)]
    build_from_github: bool,
}

/// Parsed version of [`ImageSourceArgs`]
#[derive(Clone, Debug)]
enum ImageSource {
    Image {
        name: String,
    },
    GitHub {
        revision: String,
    },
    /// Raw path passed from user
    Path(PathBuf),
}

impl From<ImageSourceArgs> for ImageSource {
    fn from(args: ImageSourceArgs) -> Self {
        match args {
            ImageSourceArgs {
                image: Some(name), ..
            } => Self::Image { name },
            ImageSourceArgs {
                build_from_github: true,
                ..
            } => Self::GitHub {
                revision: GIT_REVISION.to_owned(),
            },
            ImageSourceArgs {
                build: Some(path), ..
            } => Self::Path(path),
            _ => unreachable!("Clap must ensure the invariant"),
        }
    }
}

impl ImageSource {
    /// Has a side effect: if self is [`Self::GitHub`], it clones the repo into
    /// the target directory.
    fn resolve(self, target: &TargetDirectory, ui: &UserInterface) -> Result<ResolvedImageSource> {
        let source = match self {
            Self::Path(path) => ResolvedImageSource::Build {
                path: AbsolutePath::absolutize(path).wrap_err("failed to resolve build path")?,
            },
            Self::GitHub { revision } => {
                let clone_dir = target.path.join(DIR_CLONE);
                let clone_dir = AbsolutePath::absolutize(clone_dir)?;

                ui.log_cloning_repo();

                shallow_git_clone(GIT_ORIGIN, revision, &clone_dir)
                    .wrap_err("failed to clone the repo")?;

                ResolvedImageSource::Build { path: clone_dir }
            }
            Self::Image { name } => ResolvedImageSource::Image { name },
        };

        Ok(source)
    }
}

fn shallow_git_clone(
    remote: impl AsRef<str>,
    revision: impl AsRef<str>,
    dir: &AbsolutePath,
) -> Result<()> {
    use duct::{cmd, Expression};

    trait CurrentDirExt {
        fn current_dir(&mut self, dir: PathBuf) -> Self;
    }

    impl CurrentDirExt for Expression {
        fn current_dir(&mut self, dir: PathBuf) -> Self {
            self.before_spawn(move |cmd| {
                // idk how to avoid cloning here, cuz the closure is `Fn`, not `FnOnce`
                cmd.current_dir(dir.clone());
                Ok(())
            })
        }
    }

    std::fs::create_dir(dir)?;

    let dir = dir.to_path_buf();

    cmd!("git", "init").current_dir(dir.clone()).run()?;
    cmd!("git", "remote", "add", "origin", remote.as_ref())
        .current_dir(dir.clone())
        .run()?;
    cmd!("git", "fetch", "--depth=1", "origin", revision.as_ref())
        .current_dir(dir.clone())
        .run()?;
    cmd!(
        "git",
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "FETCH_HEAD"
    )
    .current_dir(dir)
    .run()?;

    Ok(())
}

#[derive(Debug)]
enum ResolvedImageSource {
    Image { name: String },
    Build { path: AbsolutePath },
}

enum PrepareConfigurationStrategy {
    GenerateDefault,
    GenerateOnlyDirectory,
}

impl PrepareConfigurationStrategy {
    fn run(&self, config_dir: &AbsolutePath, ui: UserInterface) -> Result<UserInterface> {
        std::fs::create_dir(config_dir).wrap_err("failed to create the config directory")?;

        let ui = match self {
            Self::GenerateOnlyDirectory => {
                ui.warn_no_default_config(config_dir);
                ui
            }
            Self::GenerateDefault => {
                let path_validator = PathBuf::from(FILE_VALIDATOR);

                let raw_genesis_block = {
                    let block = super::genesis::generate_default(Some(path_validator.clone()))
                        .wrap_err("failed to generate genesis")?;
                    serde_json::to_string_pretty(&block)?
                };

                let default_config = {
                    let proxy = iroha_config::iroha::ConfigurationProxy::default();
                    serde_json::to_string_pretty(&proxy)?
                };

                let spinner = ui.spinner_validator();

                let validator = super::validator::construct_validator()
                    .wrap_err("failed to construct the validator")?;

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
            .wrap_err_with(|| eyre!("failed to remove the directory: {}", self.path.display()))
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
                    "failed to prompt removal for the directory: {}",
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
                "failed to recursively create the directory: {}",
                self.path.display()
            )
        })
    }
}

#[derive(Debug)]
struct DockerComposeBuilder {
    target_dir: AbsolutePath,
    config_dir: AbsolutePath,
    source: ResolvedImageSource,
    peers: NonZeroU16,
    seed: Option<Vec<u8>>,
}

impl DockerComposeBuilder {
    fn build(&self) -> Result<DockerCompose> {
        let base_seed = self.seed.as_deref();

        let peers = peer_generator::generate_peers(self.peers, base_seed)
            .wrap_err("failed to generate peers")?;
        let genesis_key_pair = key_gen::generate(base_seed, GENESIS_KEYPAIR_SEED)
            .wrap_err("failed to generate genesis key pair")?;
        let service_source = match &self.source {
            ResolvedImageSource::Build { path } => {
                ServiceSource::Build(path.relative_to(&self.target_dir)?)
            }
            ResolvedImageSource::Image { name } => ServiceSource::Image(name.clone()),
        };
        let volumes = vec![(
            self.config_dir
                .relative_to(&self.target_dir)?
                .to_str()
                .wrap_err("config directory path is not a valid string")?
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

impl AbsolutePath {
    fn absolutize(path: PathBuf) -> Result<Self> {
        Ok(Self {
            path: if path.is_absolute() {
                path
            } else {
                path.absolutize()?.to_path_buf()
            },
        })
    }

    /// Relative path from self to other.
    fn relative_to(&self, other: &AbsolutePath) -> Result<PathBuf> {
        pathdiff::diff_paths(self, other)
                .ok_or_else(|| {
                    eyre!(
                        "failed to build relative path from {} to {}",
                        other.display(),
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

mod key_gen {
    use iroha_crypto::{error::Error, KeyGenConfiguration, KeyPair};

    /// If there is no base seed, the additional one will be ignored
    pub fn generate(base_seed: Option<&[u8]>, additional_seed: &[u8]) -> Result<KeyPair, Error> {
        let cfg = base_seed
            .map(|base| {
                let seed: Vec<_> = base.iter().chain(additional_seed).copied().collect();
                KeyGenConfiguration::default().use_seed(seed)
            })
            .unwrap_or_default();

        KeyPair::generate_with_configuration(cfg)
    }
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

                let key_pair = super::key_gen::generate(base_seed, service_name.as_bytes())
                    .wrap_err("failed to generate key pair")?;

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

    use crate::swarm::peer_generator::Peer;

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
            let yaml = serde_yaml::to_string(self).wrap_err("failed to serialise YAML")?;
            File::create(path)
                .wrap_err(eyre!("failed to create file: {:?}", path))?
                .write_all(yaml.as_bytes())
                .wrap_err("failed to write YAML content")?;
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
                .wrap_err("failed to build configuration")
                .expect("default configuration with swarm's env should be exhaustive");

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
    use color_eyre::Help;
    use owo_colors::OwoColorize;

    use super::{AbsolutePath, Result};
    use crate::swarm::DIR_FORCE_SUGGESTION;

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
            .suggestion(DIR_FORCE_SUGGESTION)
            .map(|flag| {
                if flag {
                    PromptAnswer::Yes
                } else {
                    PromptAnswer::No
                }
            })
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_cloning_repo(&self) {
            println!("{} Cloning git repo...", prefix::info());
        }

        pub(super) fn spinner_validator(self) -> SpinnerValidator {
            SpinnerValidator::new(self)
        }

        #[allow(clippy::unused_self)]
        pub(super) fn log_complete(&self, dir: &AbsolutePath) {
            println!(
                "{} Docker compose configuration is ready at:\n\n    {}\
                    \n\n  You could `{}` in it.",
                prefix::success(),
                dir.display().green().bold(),
                "docker compose up".blue()
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
        let seed: Vec<_> = b"iroha".to_vec();

        let composed = DockerComposeBuilder {
            target_dir: AbsolutePath::from_virtual(&PathBuf::from("/test"), root),
            config_dir: AbsolutePath::from_virtual(&PathBuf::from("/test/config"), root),
            peers: 4.try_into().unwrap(),
            source: ResolvedImageSource::Build {
                path: AbsolutePath::from_virtual(&PathBuf::from("/test/iroha-cloned"), root),
            },
            seed: Some(seed),
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
