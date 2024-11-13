//! Docker Compose schema.

use iroha_data_model::Identifiable;

use crate::{path, peer, ImageSettings, PeerSettings};

mod serde_impls;

/// Schema serialization error.
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Could not write the banner: {0}
    BannerWrite(std::io::Error),
    /// Could not serialize the schema: {0}
    SerdeYaml(serde_yaml::Error),
}

impl std::error::Error for Error {}

/// Image identifier.
#[derive(serde::Serialize, Copy, Clone, Debug)]
#[serde(transparent)]
struct ImageId<'a>(&'a str);

/// Dictates how the image provider will build the image from a Dockerfile.
#[derive(serde::Serialize, Copy, Clone, Debug)]
enum Build {
    /// Rebuild the image, ignoring the local cache.
    #[serde(rename = "build")]
    IgnoreCache,
    /// Only build the image when it is missing from the local cache.
    #[serde(rename = "never")]
    OnCacheMiss,
}

/// Dictates that a service must use the built image.
#[derive(serde::Serialize, Copy, Clone, Debug)]
enum UseBuilt {
    #[serde(rename = "never")]
    UseCached,
}

/// Dictates how a service will pull the image from Docker Hub.
#[derive(serde::Serialize, Copy, Clone, Debug)]
enum Pull {
    /// Always pull the image, ignoring the local cache.
    #[serde(rename = "always")]
    IgnoreCache,
    /// Only pull the image when it is missing from the local cache.
    #[serde(rename = "missing")]
    OnCacheMiss,
}

impl Pull {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_on_cache_miss(&self) -> bool {
        matches!(self, Self::OnCacheMiss)
    }
}

/// Path on the host.
#[derive(serde::Serialize, Copy, Clone, Debug)]
#[serde(transparent)]
struct HostPath<'a>(&'a path::RelativePath);

/// Image build settings.
#[derive(serde::Serialize, Copy, Clone, Debug)]
struct BuildImage<'a> {
    image: ImageId<'a>,
    build: HostPath<'a>,
    pull_policy: Build,
}

impl<'a> BuildImage<'a> {
    fn new(image: ImageId<'a>, build: HostPath<'a>, ignore_cache: bool) -> Self {
        Self {
            image,
            build,
            pull_policy: if ignore_cache {
                Build::IgnoreCache
            } else {
                Build::OnCacheMiss
            },
        }
    }
}

/// Reference to the first peer.
#[derive(Copy, Clone, Debug)]
struct Irohad0Ref;

const IROHAD0: &str = "irohad0";

/// Image that has been built.
#[derive(serde::Serialize, Copy, Clone, Debug)]
struct BuiltImage<'a> {
    depends_on: [Irohad0Ref; 1],
    image: ImageId<'a>,
    pull_policy: UseBuilt,
}

/// Image that has been pulled.
#[derive(serde::Serialize, Copy, Clone, Debug)]
struct PulledImage<'a> {
    image: ImageId<'a>,
    #[serde(skip_serializing_if = "Pull::is_on_cache_miss")]
    pull_policy: Pull,
}

impl<'a> BuiltImage<'a> {
    fn new(image: ImageId<'a>) -> Self {
        Self {
            depends_on: [Irohad0Ref],
            image,
            pull_policy: UseBuilt::UseCached,
        }
    }
}

impl<'a> PulledImage<'a> {
    fn new(image: ImageId<'a>, ignore_cache: bool) -> Self {
        Self {
            image,
            pull_policy: if ignore_cache {
                Pull::IgnoreCache
            } else {
                Pull::OnCacheMiss
            },
        }
    }
}

/// Compile-time boolean literal.
#[derive(Debug)]
struct Bool<const VALUE: bool>;

/// Peer environment variables.
#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
struct PeerEnv<'a> {
    chain: &'a iroha_data_model::ChainId,
    public_key: &'a iroha_crypto::PublicKey,
    private_key: &'a iroha_crypto::ExposedPrivateKey,
    p2p_public_address: iroha_primitives::addr::SocketAddr,
    p2p_address: iroha_primitives::addr::SocketAddr,
    api_address: iroha_primitives::addr::SocketAddr,
    genesis_public_key: &'a iroha_crypto::PublicKey,
    #[serde(skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    #[serde_as(as = "serde_with::json::JsonString")]
    trusted_peers: std::collections::BTreeSet<&'a iroha_data_model::peer::Peer>,
}

impl<'a> PeerEnv<'a> {
    fn new(
        (public_key, private_key): &'a peer::ExposedKeyPair,
        [port_p2p, port_api]: [u16; 2],
        chain: &'a iroha_data_model::ChainId,
        genesis_public_key: &'a iroha_crypto::PublicKey,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Self {
        let p2p_public_address = topology
            .iter()
            .find(|&peer| peer.id().public_key() == public_key)
            .unwrap()
            .address()
            .clone();
        Self {
            chain,
            public_key,
            private_key,
            p2p_public_address,
            p2p_address: iroha_primitives::addr::socket_addr!(0.0.0.0:port_p2p),
            api_address: iroha_primitives::addr::socket_addr!(0.0.0.0:port_api),
            genesis_public_key,
            trusted_peers: topology
                .iter()
                .filter(|&peer| peer.id().public_key() != public_key)
                .collect(),
        }
    }
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
struct GenesisEnv<'a> {
    #[serde(flatten)]
    base: PeerEnv<'a>,
    genesis_private_key: &'a iroha_crypto::ExposedPrivateKey,
    genesis: ContainerFile<'a>,
    #[serde_as(as = "serde_with::json::JsonString")]
    topology: std::collections::BTreeSet<&'a iroha_data_model::peer::PeerId>,
}

impl<'a> GenesisEnv<'a> {
    fn new(
        key_pair: &'a peer::ExposedKeyPair,
        ports: [u16; 2],
        chain: &'a iroha_data_model::ChainId,
        (genesis_public_key, genesis_private_key): peer::ExposedKeyRefPair<'a>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Self {
        Self {
            base: PeerEnv::new(key_pair, ports, chain, genesis_public_key, topology),
            genesis_private_key,
            genesis: CONTAINER_SIGNED_GENESIS,
            topology: topology
                .iter()
                .map(iroha_data_model::prelude::Peer::id)
                .collect(),
        }
    }
}

/// Mapping between `host:container` ports.
#[derive(Debug)]
struct PortMapping(u16, u16);

#[derive(Copy, Clone, Debug)]
struct Filename<'a>(&'a str);

impl std::fmt::Display for Filename<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Path on the host.
#[derive(Copy, Clone, Debug)]
struct HostFile<'a>(&'a path::RelativePath, Filename<'a>);

impl std::fmt::Display for HostFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}{}", self.0.as_ref().display(), self.1))
    }
}

/// Path inside the container.
#[derive(Copy, Clone, Debug)]
struct ContainerPath<'a>(&'a str);

impl std::fmt::Display for ContainerPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Path inside the container.
#[derive(Copy, Clone, Debug)]
struct ContainerFile<'a>(ContainerPath<'a>, Filename<'a>);

impl std::fmt::Display for ContainerFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}{}", self.0, self.1))
    }
}

const GENESIS_FILE: Filename = Filename("genesis.json");
const CONFIG_FILE: Filename = Filename("client.toml");
const GENESIS_SIGNED_SCALE: Filename = Filename("genesis.signed.scale");

const CONTAINER_CONFIG_DIR: ContainerPath = ContainerPath("/config/");
const CONTAINER_TMP_DIR: ContainerPath = ContainerPath("/tmp/");

const CONTAINER_GENESIS_CONFIG: ContainerFile = ContainerFile(CONTAINER_CONFIG_DIR, GENESIS_FILE);
const CONTAINER_CLIENT_CONFIG: ContainerFile = ContainerFile(CONTAINER_CONFIG_DIR, CONFIG_FILE);
const CONTAINER_SIGNED_GENESIS: ContainerFile =
    ContainerFile(CONTAINER_TMP_DIR, GENESIS_SIGNED_SCALE);

#[derive(Copy, Clone, Debug)]
struct ReadOnly;

/// Mapping between `host:container` paths.
#[derive(Copy, Clone, Debug)]
struct PathMapping<'a>(HostFile<'a>, ContainerFile<'a>, ReadOnly);

/// Mapping between host and container paths.
type Volumes<'a> = [PathMapping<'a>; 2];

/// Healthcheck parameters.
#[derive(Debug)]
struct Healthcheck {
    port: u16,
}

// half of default pipeline time
const HEALTH_CHECK_INTERVAL: &str = "2s";
// status request usually resolves immediately
const HEALTH_CHECK_TIMEOUT: &str = "1s";
// try within one minute given the interval
const HEALTH_CHECK_RETRIES: u8 = 30u8;
// default pipeline time
const HEALTH_CHECK_START_PERIOD: &str = "4s";

/// Iroha peer service.
#[derive(serde::Serialize, Debug)]
struct Irohad<'a, Image, Environment = PeerEnv<'a>>
where
    Image: serde::Serialize,
    Environment: serde::Serialize,
{
    #[serde(flatten)]
    image: Image,
    environment: Environment,
    ports: [PortMapping; 2],
    volumes: Volumes<'a>,
    init: Bool<true>,
    #[serde(skip_serializing_if = "Option::is_none")]
    healthcheck: Option<Healthcheck>,
}

impl<'a, Image, Environment> Irohad<'a, Image, Environment>
where
    Image: serde::Serialize,
    Environment: serde::Serialize,
{
    fn new(
        image: Image,
        environment: Environment,
        [port_p2p, port_api]: [u16; 2],
        volumes: Volumes<'a>,
        healthcheck: bool,
    ) -> Self {
        Self {
            image,
            environment,
            ports: [
                PortMapping(port_p2p, port_p2p),
                PortMapping(port_api, port_api),
            ],
            volumes,
            init: Bool,
            healthcheck: healthcheck.then_some(Healthcheck { port: port_api }),
        }
    }
}

/// Command used by the genesis service to sign and submit genesis.
#[derive(Debug)]
struct SignAndSubmitGenesis;

const SIGN_AND_SUBMIT_GENESIS: &str = r#"/bin/sh -c "
    EXECUTOR_RELATIVE_PATH=$(jq -r '.executor' /config/genesis.json) && \\
    EXECUTOR_ABSOLUTE_PATH=$(realpath \"/config/$$EXECUTOR_RELATIVE_PATH\") && \\
    WASM_DIR_RELATIVE_PATH=$(jq -r '.wasm_dir' /config/genesis.json) && \\
    WASM_DIR_ABSOLUTE_PATH=$(realpath \"/config/$$WASM_DIR_RELATIVE_PATH\") && \\
    jq \\
        --arg executor \"$$EXECUTOR_ABSOLUTE_PATH\" \\
        --arg wasm_dir \"$$WASM_DIR_ABSOLUTE_PATH\" \\
        --argjson topology \"$$TOPOLOGY\" \\
        '.executor = $$executor | .wasm_dir = $$wasm_dir | .topology = $$topology' /config/genesis.json \\
        >/tmp/genesis.json && \\
    kagami genesis sign /tmp/genesis.json \\
        --public-key $$GENESIS_PUBLIC_KEY \\
        --private-key $$GENESIS_PRIVATE_KEY \\
        --out-file $$GENESIS \\
    && \\
    exec irohad
""#;

/// Configuration of the `irohad` service that submits genesis.
#[derive(serde::Serialize, Debug)]
struct Irohad0<'a, Image>
where
    Image: serde::Serialize,
{
    #[serde(flatten)]
    base: Irohad<'a, Image, GenesisEnv<'a>>,
    command: SignAndSubmitGenesis,
}

impl<'a, Image> Irohad0<'a, Image>
where
    Image: serde::Serialize,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        image: Image,
        environment: GenesisEnv<'a>,
        ports: [u16; 2],
        volumes: Volumes<'a>,
        healthcheck: bool,
    ) -> Self {
        Self {
            base: Irohad::new(image, environment, ports, volumes, healthcheck),
            command: SignAndSubmitGenesis,
        }
    }
}

/// Reference to an `irohad` service.
#[derive(Debug, PartialOrd, PartialEq, Ord, Eq)]
struct IrohadRef(u16);

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
enum BuildOrPull<'a> {
    Build {
        irohad0: Irohad0<'a, BuildImage<'a>>,
        #[serde(flatten, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        irohads: std::collections::BTreeMap<IrohadRef, Irohad<'a, BuiltImage<'a>>>,
    },
    Pull {
        irohad0: Irohad0<'a, PulledImage<'a>>,
        #[serde(flatten, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        irohads: std::collections::BTreeMap<IrohadRef, Irohad<'a, PulledImage<'a>>>,
    },
}

impl<'a> BuildOrPull<'a> {
    fn pull(
        image: PulledImage<'a>,
        volumes: Volumes<'a>,
        healthcheck: bool,
        chain: &'a iroha_data_model::ChainId,
        (genesis_public_key, genesis_private_key): &'a peer::ExposedKeyPair,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Self {
        Self::Pull {
            irohad0: Self::irohad0(
                image,
                volumes,
                healthcheck,
                chain,
                (genesis_public_key, genesis_private_key),
                network,
                topology,
            ),
            irohads: Self::irohads(
                image,
                volumes,
                healthcheck,
                chain,
                genesis_public_key,
                network,
                topology,
            ),
        }
    }

    fn build(
        image: BuildImage<'a>,
        volumes: Volumes<'a>,
        healthcheck: bool,
        chain: &'a iroha_data_model::ChainId,
        (genesis_public_key, genesis_private_key): &'a peer::ExposedKeyPair,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Self {
        Self::Build {
            irohad0: Self::irohad0(
                image,
                volumes,
                healthcheck,
                chain,
                (genesis_public_key, genesis_private_key),
                network,
                topology,
            ),
            irohads: Self::irohads(
                BuiltImage::new(image.image),
                volumes,
                healthcheck,
                chain,
                genesis_public_key,
                network,
                topology,
            ),
        }
    }

    fn irohad0<Image: serde::Serialize>(
        image: Image,
        volumes: Volumes<'a>,
        healthcheck: bool,
        chain: &'a iroha_data_model::ChainId,
        (genesis_public_key, genesis_private_key): peer::ExposedKeyRefPair<'a>,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Irohad0<'a, Image> {
        let (_, ports, key_pair) = network.get(&0).expect("irohad0 must be present");
        Irohad0::new(
            image,
            GenesisEnv::new(
                key_pair,
                *ports,
                chain,
                (genesis_public_key, genesis_private_key),
                topology,
            ),
            *ports,
            volumes,
            healthcheck,
        )
    }

    fn irohads<Image: serde::Serialize + Copy>(
        image: Image,
        volumes: Volumes<'a>,
        healthcheck: bool,
        chain: &'a iroha_data_model::ChainId,
        genesis_public_key: &'a iroha_crypto::PublicKey,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> std::collections::BTreeMap<IrohadRef, Irohad<'a, Image>> {
        network
            .iter()
            .skip(1)
            .map(|(id, (_, ports, key_pair))| {
                (
                    IrohadRef(*id),
                    Irohad::new(
                        image,
                        PeerEnv::new(key_pair, *ports, chain, genesis_public_key, topology),
                        *ports,
                        volumes,
                        healthcheck,
                    ),
                )
            })
            .collect()
    }
}

/// Docker Compose configuration.
#[derive(serde::Serialize, Debug)]
pub struct DockerCompose<'a> {
    services: BuildOrPull<'a>,
}

impl<'a> DockerCompose<'a> {
    /// Constructs a Compose configuration.
    pub(super) fn new(
        ImageSettings {
            name,
            build_dir,
            ignore_cache,
        }: &'a ImageSettings,
        PeerSettings {
            healthcheck,
            config_dir,
            chain,
            genesis_key_pair,
            network,
            topology,
        }: &'a PeerSettings,
    ) -> Self {
        let image = ImageId(name);
        let volumes = [
            PathMapping(
                HostFile(config_dir, GENESIS_FILE),
                CONTAINER_GENESIS_CONFIG,
                ReadOnly,
            ),
            PathMapping(
                HostFile(config_dir, CONFIG_FILE),
                CONTAINER_CLIENT_CONFIG,
                ReadOnly,
            ),
        ];
        Self {
            services: build_dir.as_ref().map_or_else(
                || {
                    BuildOrPull::pull(
                        PulledImage::new(image, *ignore_cache),
                        volumes,
                        *healthcheck,
                        chain,
                        genesis_key_pair,
                        network,
                        topology,
                    )
                },
                |build| {
                    BuildOrPull::build(
                        BuildImage::new(image, HostPath(build), *ignore_cache),
                        volumes,
                        *healthcheck,
                        chain,
                        genesis_key_pair,
                        network,
                        topology,
                    )
                },
            ),
        }
    }

    /// Serializes the schema into a writer as YAML, with optional `banner` comment lines.
    pub fn write<W>(self, mut writer: W, banner: Option<&[&str]>) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        if let Some(banner) = banner {
            for line in banner {
                writeln!(writer, "# {line}").map_err(Error::BannerWrite)?;
            }
            writeln!(writer).map_err(Error::BannerWrite)?;
        }
        serde_yaml::to_writer(writer, &self).map_err(Error::SerdeYaml)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BASE_PORT_API, BASE_PORT_P2P};

    impl<'a> From<PeerEnv<'a>> for iroha_config::base::env::MockEnv {
        fn from(env: PeerEnv<'a>) -> Self {
            let json = serde_json::to_string(&env).expect("should be serializable");
            let map = serde_json::from_str(&json).expect("should be deserializable into a map");
            Self::with_map(map)
        }
    }

    impl<'a> From<GenesisEnv<'a>> for iroha_config::base::env::MockEnv {
        fn from(env: GenesisEnv<'a>) -> Self {
            let json = serde_json::to_string(&env).expect("should be serializable");
            let map = serde_json::from_str(&json).expect("should be deserializable into a map");
            Self::with_map(map)
        }
    }

    #[test]
    fn peer_env_produces_exhaustive_config() {
        let key_pair = peer::generate_key_pair(None, &[]);
        let genesis_key_pair = peer::generate_key_pair(None, &[]);
        let ports = [BASE_PORT_P2P, BASE_PORT_API];
        let chain = peer::chain();
        let topology = [peer::peer("dummy", BASE_PORT_API, key_pair.0.clone())].into();
        let env = PeerEnv::new(&key_pair, ports, &chain, &genesis_key_pair.0, &topology);
        let mock_env = iroha_config::base::env::MockEnv::from(env);
        let _ = iroha_config::base::read::ConfigReader::new()
            .with_env(mock_env.clone())
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .expect("config in env should be exhaustive");
        assert!(mock_env.unvisited().is_empty());
    }

    #[test]
    fn genesis_env_produces_exhaustive_config_sans_genesis_private_key_and_topology() {
        let key_pair = peer::generate_key_pair(None, &[]);
        let (genesis_public_key, genesis_private_key) = &peer::generate_key_pair(None, &[]);
        let ports = [BASE_PORT_P2P, BASE_PORT_API];
        let chain = peer::chain();
        let topology = [peer::peer("dummy", BASE_PORT_API, key_pair.0.clone())].into();
        let env = GenesisEnv::new(
            &key_pair,
            ports,
            &chain,
            (genesis_public_key, genesis_private_key),
            &topology,
        );
        let mock_env = iroha_config::base::env::MockEnv::from(env);
        let _ = iroha_config::base::read::ConfigReader::new()
            .with_env(mock_env.clone())
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .expect("config in env should be exhaustive");
        assert_eq!(
            mock_env.unvisited(),
            ["GENESIS_PRIVATE_KEY", "TOPOLOGY"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect()
        );
    }
}
