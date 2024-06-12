//! Docker Compose schema.

use crate::{path, peer, ImageSettings, PeerSettings};

mod serde_impls;

/// Image identifier.
#[derive(serde::Serialize, Copy, Clone, Debug)]
#[serde(transparent)]
struct ImageId<'a>(&'a str);

/// Dictates how the image provider will pull the image from Docker Hub.
#[derive(serde::Serialize, Debug)]
enum PullPolicy {
    /// Always pull the image, ignoring the local cache.
    #[serde(rename = "always")]
    IgnoreCache,
    /// Only pull the image when it is missing from the local cache.
    #[serde(rename = "missing")]
    OnCacheMiss,
}

/// Dictates how the image provider will build the image from a Dockerfile.
#[derive(serde::Serialize, Debug)]
//#[serde(untagged)]
enum BuildPolicy {
    /// Rebuild the image, ignoring the local cache.
    #[serde(rename = "build")]
    IgnoreCache,
    /// Only build the image when it is missing from the local cache.
    #[serde(rename = "never")]
    OnCacheMiss,
}

/// Path on the host.
#[derive(serde::Serialize, Copy, Clone, Debug)]
#[serde(transparent)]
struct HostPath<'a>(&'a path::RelativePath);

/// Dictates whether the image provider will pull or build the image.
#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
#[allow(variant_size_differences)]
enum ImagePolicy<'a> {
    Pull {
        pull_policy: PullPolicy,
    },
    Build {
        build: HostPath<'a>,
        pull_policy: BuildPolicy,
    },
}

/// Dummy command used to terminate a service instead of running the image.
#[derive(Debug)]
struct EchoOk;

const ECHO_OK: &str = "echo ok";

/// Dummy service that pulls or builds the image and terminates.
#[derive(serde::Serialize, Debug)]
struct ImageProvider<'a> {
    image: ImageId<'a>,
    #[serde(flatten)]
    policy: ImagePolicy<'a>,
    command: EchoOk,
}

/// Reference to the image provider.
#[derive(Debug)]
struct ImageProviderRef;

const IMAGE_PROVIDER: &str = "image_provider";

/// Always use the image from the local cache.
#[derive(Debug)]
struct UseCached;

const USE_CACHED: &str = "never";

/// Image that has been pulled or built.
#[derive(serde::Serialize, Debug)]
struct LocalImage<'a> {
    image: ImageId<'a>,
    pull_policy: UseCached,
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
    p2p_address: iroha_primitives::addr::SocketAddr,
    api_address: iroha_primitives::addr::SocketAddr,
    genesis_public_key: &'a iroha_crypto::PublicKey,
    #[serde(skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    #[serde_as(as = "serde_with::json::JsonString")]
    sumeragi_trusted_peers: std::collections::BTreeSet<&'a iroha_data_model::peer::PeerId>,
}

impl<'a> PeerEnv<'a> {
    fn new(
        (public_key, private_key): &'a peer::ExposedKeyPair,
        [port_p2p, port_api]: [u16; 2],
        chain: &'a iroha_data_model::ChainId,
        genesis_public_key: &'a iroha_crypto::PublicKey,
        trusted_peers: impl Iterator<Item = &'a iroha_data_model::peer::PeerId>,
    ) -> Self {
        let sumeragi_trusted_peers = trusted_peers
            .filter(|&trusted| trusted.public_key() != public_key)
            .collect();
        Self {
            chain,
            public_key,
            private_key,
            p2p_address: iroha_primitives::addr::socket_addr!(0.0.0.0:port_p2p),
            api_address: iroha_primitives::addr::socket_addr!(0.0.0.0:port_api),
            genesis_public_key,
            sumeragi_trusted_peers,
        }
    }
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
struct GenesisEnv<'a> {
    #[serde(flatten)]
    base: PeerEnv<'a>,
    genesis_signed_file: ContainerPath<'a>,
}

/// Mapping between `host:container` ports.
#[derive(Debug)]
struct PortMapping(u16, u16);

/// Path inside the container.
#[derive(serde::Serialize, Copy, Clone, Debug)]
#[serde(transparent)]
struct ContainerPath<'a>(&'a str);

const CONTAINER_CONFIG_DIR: &str = "/config";
const GENESIS_SIGNED_FILE: &str = "/tmp/genesis.signed.scale";

/// Mapping between `host:container` paths.
#[derive(Copy, Clone, Debug)]
struct PathMapping<'a>(HostPath<'a>, ContainerPath<'a>);

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

/// Base Iroha peer service.
#[derive(serde::Serialize, Debug)]
struct BaseIrohad<'a, Env: serde::Serialize> {
    depends_on: [ImageProviderRef; 1],
    #[serde(flatten)]
    image: LocalImage<'a>,
    environment: Env,
    ports: [PortMapping; 2],
    volumes: [PathMapping<'a>; 1],
    init: Bool<true>,
    #[serde(skip_serializing_if = "Option::is_none")]
    healthcheck: Option<Healthcheck>,
}

impl<'a, Env: serde::Serialize> BaseIrohad<'a, Env> {
    fn new(
        image: ImageId<'a>,
        environment: Env,
        [port_p2p, port_api]: [u16; 2],
        volumes: [PathMapping<'a>; 1],
        healthcheck: bool,
    ) -> Self {
        Self {
            depends_on: [ImageProviderRef],
            image: LocalImage {
                image,
                pull_policy: UseCached,
            },
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
struct SignAndSubmitGenesis<'a>(&'a peer::ExposedKeyPair);

const SIGN_AND_SUBMIT_GENESIS: &str = r#"/bin/sh -c "
  kagami genesis sign /config/genesis.json \
    --public-key $$GENESIS_PUBLIC_KEY \
    --private-key $$GENESIS_PRIVATE_KEY \
    --out-file $$GENESIS_SIGNED_FILE && \
  irohad --submit-genesis
""#;

/// Configuration of the `irohad` service that submits genesis.
#[derive(serde::Serialize, Debug)]
struct Irohad0<'a> {
    #[serde(flatten)]
    base: BaseIrohad<'a, GenesisEnv<'a>>,
    command: SignAndSubmitGenesis<'a>,
}

impl<'a> Irohad0<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        key_pair: &'a peer::ExposedKeyPair,
        ports: [u16; 2],
        image: ImageId<'a>,
        volumes: [PathMapping<'a>; 1],
        healthcheck: bool,
        chain: &'a iroha_data_model::ChainId,
        genesis_key_pair: &'a peer::ExposedKeyPair,
        trusted_peers: impl Iterator<Item = &'a iroha_data_model::peer::PeerId>,
    ) -> Self {
        Self {
            base: BaseIrohad::new(
                image,
                GenesisEnv {
                    base: PeerEnv::new(key_pair, ports, chain, &genesis_key_pair.0, trusted_peers),
                    genesis_signed_file: ContainerPath(GENESIS_SIGNED_FILE),
                },
                ports,
                volumes,
                healthcheck,
            ),
            command: SignAndSubmitGenesis(key_pair),
        }
    }
}

/// Configuration of a regular `irohad` service.
#[derive(serde::Serialize, Debug)]
struct Irohad<'a> {
    #[serde(flatten)]
    base: BaseIrohad<'a, PeerEnv<'a>>,
}

impl<'a> Irohad<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        image: ImageId<'a>,
        key_pair: &'a peer::ExposedKeyPair,
        ports: [u16; 2],
        volumes: [PathMapping<'a>; 1],
        healthcheck: bool,
        chain: &'a iroha_data_model::ChainId,
        genesis_public_key: &'a iroha_crypto::PublicKey,
        trusted_peers: impl Iterator<Item = &'a iroha_data_model::peer::PeerId>,
    ) -> Self {
        Self {
            base: BaseIrohad::new(
                image,
                PeerEnv::new(key_pair, ports, chain, genesis_public_key, trusted_peers),
                ports,
                volumes,
                healthcheck,
            ),
        }
    }
}

/// Reference to an `irohad` service.
#[derive(Debug, PartialOrd, PartialEq, Ord, Eq)]
struct IrohadRef(u16);

/// Compose services.
#[derive(serde::Serialize, Debug)]
struct Services<'a> {
    image_provider: ImageProvider<'a>,
    irohad0: Irohad0<'a>,
    #[serde(flatten, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    irohads: std::collections::BTreeMap<IrohadRef, Irohad<'a>>,
}

/// Schema serialization error.
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Could not write the banner: {0}.
    BannerWrite(std::io::Error),
    /// Could not serialize the schema: {0}.
    SerdeYaml(serde_yaml::Error),
}

impl std::error::Error for Error {}

/// Docker Compose configuration.
#[derive(serde::Serialize, Debug)]
pub struct DockerCompose<'a> {
    services: Services<'a>,
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
            trusted_peers,
        }: &'a PeerSettings,
    ) -> Self {
        let image = ImageId(name);
        let volumes = [PathMapping(
            HostPath(config_dir),
            ContainerPath(CONTAINER_CONFIG_DIR),
        )];
        Self {
            services: Services {
                image_provider: ImageProvider {
                    image,
                    policy: build_dir.as_ref().map_or(
                        ImagePolicy::Pull {
                            pull_policy: match ignore_cache {
                                true => PullPolicy::IgnoreCache,
                                false => PullPolicy::OnCacheMiss,
                            },
                        },
                        |build| ImagePolicy::Build {
                            build: HostPath(build),
                            pull_policy: match ignore_cache {
                                true => BuildPolicy::IgnoreCache,
                                false => BuildPolicy::OnCacheMiss,
                            },
                        },
                    ),
                    command: EchoOk,
                },
                irohad0: {
                    let (_, irohad0_ports, irohad0_key_pair) =
                        network.get(&0).expect("irohad0 must be present");
                    Irohad0::new(
                        irohad0_key_pair,
                        *irohad0_ports,
                        image,
                        volumes,
                        *healthcheck,
                        chain,
                        genesis_key_pair,
                        trusted_peers.iter(),
                    )
                },
                irohads: network
                    .iter()
                    .skip(1)
                    .map(|(id, (_, ports, key_pair))| {
                        (
                            IrohadRef(*id),
                            Irohad::new(
                                image,
                                key_pair,
                                *ports,
                                volumes,
                                *healthcheck,
                                chain,
                                &genesis_key_pair.0,
                                trusted_peers.iter(),
                            ),
                        )
                    })
                    .collect(),
            },
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
        let peer_id = peer::peer_id("dummy", BASE_PORT_API, key_pair.0.clone());
        let env = PeerEnv::new(
            &key_pair,
            ports,
            &chain,
            &genesis_key_pair.0,
            std::iter::once(&peer_id),
        );
        let mock_env = iroha_config::base::env::MockEnv::from(env);
        let _ = iroha_config::base::read::ConfigReader::new()
            .with_env(mock_env.clone())
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .expect("config in env should be exhaustive");
        assert!(mock_env.unvisited().is_empty());
    }

    #[test]
    fn genesis_env_produces_exhaustive_config() {
        let key_pair = peer::generate_key_pair(None, &[]);
        let genesis_key_pair = peer::generate_key_pair(None, &[]);
        let ports = [BASE_PORT_P2P, BASE_PORT_API];
        let chain = peer::chain();
        let peer_id = peer::peer_id("dummy", BASE_PORT_API, key_pair.0.clone());
        let env = GenesisEnv {
            base: PeerEnv::new(
                &key_pair,
                ports,
                &chain,
                &genesis_key_pair.0,
                std::iter::once(&peer_id),
            ),
            genesis_signed_file: ContainerPath("/"),
        };
        let mock_env = iroha_config::base::env::MockEnv::from(env);
        let _ = iroha_config::base::read::ConfigReader::new()
            .with_env(mock_env.clone())
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .expect("config in env should be exhaustive");
        assert!(mock_env.unvisited().is_empty());
    }
}
