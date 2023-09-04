use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    fs::File,
    io::Write,
    num::NonZeroU16,
    path::PathBuf,
};

use color_eyre::eyre::{eyre, Context, ContextCompat};
use iroha_crypto::{
    error::Error as IrohaCryptoError, KeyGenConfiguration, KeyPair, PrivateKey, PublicKey,
};
use iroha_data_model::prelude::PeerId;
use iroha_primitives::addr::SocketAddr;
use peer_generator::Peer;
use serde::{ser::Error as _, Serialize, Serializer};

use crate::{cli::SourceParsed, util::AbsolutePath};

/// Config directory inside of the docker image
const DIR_CONFIG_IN_DOCKER: &str = "/config";
const GENESIS_KEYPAIR_SEED: &[u8; 7] = b"genesis";
const COMMAND_SUBMIT_GENESIS: &str = "iroha --submit-genesis";
const DOCKER_COMPOSE_VERSION: &str = "3.8";
const PLATFORM_ARCHITECTURE: &str = "linux/amd64";

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

#[derive(Debug)]
struct PlatformArchitecture;

impl Serialize for PlatformArchitecture {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(PLATFORM_ARCHITECTURE)
    }
}

#[derive(Serialize, Debug)]
pub struct DockerComposeService {
    #[serde(flatten)]
    source: ServiceSource,
    platform: PlatformArchitecture,
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
            platform: PlatformArchitecture,
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

#[derive(Debug)]
pub struct DockerComposeBuilder<'a> {
    /// Needed to compute a relative source build path
    pub target_file: &'a AbsolutePath,
    /// Needed to put into `volumes`
    pub config_dir: &'a AbsolutePath,
    pub image_source: ResolvedImageSource,
    pub peers: NonZeroU16,
    /// Crypto seed to use for keys generation
    pub seed: Option<&'a [u8]>,
}

impl DockerComposeBuilder<'_> {
    fn build(&self) -> color_eyre::Result<DockerCompose> {
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

    pub(crate) fn build_and_write(&self) -> color_eyre::Result<()> {
        let target_file = self.target_file;
        let compose = self
            .build()
            .wrap_err("Failed to build a docker compose file")?;
        compose.write_file(&target_file.path)
    }
}

fn generate_key_pair(
    base_seed: Option<&[u8]>,
    additional_seed: &[u8],
) -> color_eyre::Result<KeyPair, IrohaCryptoError> {
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

#[derive(Debug)]
pub enum ResolvedImageSource {
    Image { name: String },
    Build { path: AbsolutePath },
}

impl TryFrom<SourceParsed> for ResolvedImageSource {
    type Error = color_eyre::Report;

    fn try_from(value: SourceParsed) -> Result<Self, Self::Error> {
        let resolved = match value {
            SourceParsed::Image { name } => Self::Image { name },
            SourceParsed::Build { path: relative } => {
                let absolute =
                    AbsolutePath::absolutize(&relative).wrap_err("Failed to resolve build path")?;
                Self::Build { path: absolute }
            }
        };

        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        env::VarError,
        ffi::OsStr,
        path::{Path, PathBuf},
        str::FromStr,
    };

    use color_eyre::eyre::Context;
    use iroha_config::{
        base::proxy::{FetchEnv, LoadFromEnv, Override},
        iroha::ConfigurationProxy,
    };
    use iroha_crypto::{KeyGenConfiguration, KeyPair};
    use iroha_primitives::addr::SocketAddr;
    use path_absolutize::Absolutize;

    use super::*;

    impl AbsolutePath {
        pub(crate) fn from_virtual(path: &PathBuf, virtual_root: impl AsRef<Path> + Sized) -> Self {
            let path = path
                .absolutize_virtually(virtual_root)
                .unwrap()
                .to_path_buf();
            Self { path }
        }
    }

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
                        platform: PlatformArchitecture,
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
                    platform: linux/amd64
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
                platform: linux/amd64
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
                platform: linux/amd64
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
                platform: linux/amd64
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
                platform: linux/amd64
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
