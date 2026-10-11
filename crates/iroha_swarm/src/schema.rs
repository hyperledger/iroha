//! Docker Compose schema.
use crate::{
    GenesisArtifactSettings, ImageSettings, PeerSettings, PreparedRuntimeConfig,
    PreparedRuntimeSource, base64_standard, path, peer,
};
use norito::json::{self, Map, Value};
use std::fmt::Write as _;
fn peer_env_to_value(env: &PeerEnv<'_>) -> norito::json::Value {
    let mut map = Map::new();
    map.insert(
        "CHAIN".into(),
        json::to_value(env.chain).expect("serialize chain id"),
    );
    map.insert(
        "PUBLIC_KEY".into(),
        json::to_value(env.public_key).expect("serialize public key"),
    );
    if let Some(private_key) = env.private_key {
        map.insert(
            "PRIVATE_KEY".into(),
            json::to_value(private_key).expect("serialize private key"),
        );
    }
    map.insert(
        "P2P_SORANET_TRANSPORT_PUBLIC_KEY".into(),
        json::to_value(env.soranet_transport_public_key)
            .expect("serialize SoraNet transport public key"),
    );
    if let Some(private_key) = env.soranet_transport_private_key {
        map.insert(
            "P2P_SORANET_TRANSPORT_PRIVATE_KEY".into(),
            json::to_value(private_key).expect("serialize SoraNet transport private key"),
        );
    }
    if let Some(public_key) = env.streaming_identity_public_key {
        map.insert(
            "STREAMING_IDENTITY_PUBLIC_KEY".into(),
            json::to_value(public_key).expect("serialize streaming identity public key"),
        );
    }
    if let Some(private_key) = env.streaming_identity_private_key {
        map.insert(
            "STREAMING_IDENTITY_PRIVATE_KEY".into(),
            json::to_value(private_key).expect("serialize streaming identity private key"),
        );
    }
    map.insert(
        "P2P_PUBLIC_ADDRESS".into(),
        Value::String(env.p2p_public_address.to_string()),
    );
    map.insert(
        "P2P_ADDRESS".into(),
        Value::String(env.p2p_address.to_string()),
    );
    map.insert(
        "API_ADDRESS".into(),
        Value::String(env.api_address.to_string()),
    );
    if !env.trusted_peers.is_empty() {
        let peers: Vec<String> = env
            .trusted_peers
            .iter()
            .map(|peer| peer.id().to_string())
            .collect();
        let trusted = json::to_json(&peers).expect("serialize trusted peers list");
        map.insert("TRUSTED_PEERS".into(), Value::String(trusted));
    }
    if !env.trusted_peers_pop.is_empty() {
        let mut pops = Vec::with_capacity(env.trusted_peers_pop.len());
        for (pk, pop) in &env.trusted_peers_pop {
            let mut entry = Map::new();
            entry.insert("public_key".into(), Value::String(pk.to_string()));
            entry.insert(
                "pop_hex".into(),
                Value::String(format!("0x{}", encode_hex(pop))),
            );
            pops.push(Value::Object(entry));
        }
        let trusted = json::to_json(&pops).expect("serialize trusted peers PoP list");
        map.insert("TRUSTED_PEERS_POP".into(), Value::String(trusted));
    }
    Value::Object(map)
}
fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("format hex byte");
    }
    out
}
fn trusted_peers_pop_map(
    network: &std::collections::BTreeMap<u16, peer::PeerInfo>,
) -> std::collections::BTreeMap<iroha_crypto::PublicKey, Vec<u8>> {
    let mut pops = std::collections::BTreeMap::new();
    for peer_info in network.values() {
        pops.insert(peer_info.key_pair.0.clone(), peer_info.pop.clone());
    }
    pops
}
#[cfg(test)]
mod json_value_tests {
    use super::*;
    use crate::peer;
    use norito::json::{self, Map, Value};
    type SampleTopology = (
        peer::ExposedKeyPair,
        peer::ExposedKeyPair,
        peer::ExposedKeyPair,
        [u16; 2],
        iroha_model_base::chain::ChainId,
        std::collections::BTreeSet<iroha_data_model::prelude::Peer>,
        std::collections::BTreeMap<iroha_crypto::PublicKey, Vec<u8>>,
    );
    fn sample_topology() -> SampleTopology {
        let chain = peer::chain();
        let (primary_pair, primary_pop) =
            peer::generate_bls_key_pair(Some(b"swarm-json-primary"), b"node-0")
                .expect("seeded primary BLS key generation should succeed");
        let (secondary_pair, secondary_pop) =
            peer::generate_bls_key_pair(Some(b"swarm-json-secondary"), b"node-1")
                .expect("seeded secondary BLS key generation should succeed");
        let transport_pair =
            peer::generate_soranet_transport_key_pair(Some(b"swarm-json-primary"), b"node-0")
                .expect("seeded primary transport key generation should succeed");
        let streaming_pair =
            peer::generate_streaming_identity_key_pair(Some(b"swarm-json-primary"), b"node-0")
                .expect("seeded primary streaming identity generation should succeed");
        let ports = [crate::BASE_PORT_P2P, crate::BASE_PORT_API];
        let other_ports = [crate::BASE_PORT_P2P + 1, crate::BASE_PORT_API + 1];
        let mut topology = std::collections::BTreeSet::new();
        topology.insert(peer::peer("irohad0", ports[0], primary_pair.0.clone()));
        topology.insert(peer::peer(
            "irohad1",
            other_ports[0],
            secondary_pair.0.clone(),
        ));
        let mut trusted_pops = std::collections::BTreeMap::new();
        trusted_pops.insert(primary_pair.0.clone(), primary_pop);
        trusted_pops.insert(secondary_pair.0.clone(), secondary_pop);
        (
            primary_pair,
            transport_pair,
            streaming_pair,
            ports,
            chain,
            topology,
            trusted_pops,
        )
    }
    #[test]
    fn peer_env_to_value_matches_expected_fields() {
        let (primary_pair, transport_pair, streaming_pair, ports, chain, topology, trusted_pops) =
            sample_topology();
        let env = PeerEnv::new(
            &primary_pair,
            &transport_pair,
            Some(&streaming_pair),
            ports,
            &chain,
            &topology,
            trusted_pops.clone(),
        );
        let actual = peer_env_to_value(&env);
        let mut expected = Map::new();
        expected.insert("CHAIN".into(), json::to_value(env.chain).unwrap());
        expected.insert("PUBLIC_KEY".into(), json::to_value(env.public_key).unwrap());
        if let Some(private_key) = env.private_key {
            expected.insert("PRIVATE_KEY".into(), json::to_value(private_key).unwrap());
        }
        expected.insert(
            "P2P_SORANET_TRANSPORT_PUBLIC_KEY".into(),
            json::to_value(env.soranet_transport_public_key).unwrap(),
        );
        if let Some(private_key) = env.soranet_transport_private_key {
            expected.insert(
                "P2P_SORANET_TRANSPORT_PRIVATE_KEY".into(),
                json::to_value(private_key).unwrap(),
            );
        }
        expected.insert(
            "STREAMING_IDENTITY_PUBLIC_KEY".into(),
            json::to_value(&streaming_pair.0).unwrap(),
        );
        expected.insert(
            "STREAMING_IDENTITY_PRIVATE_KEY".into(),
            json::to_value(
                streaming_pair
                    .1
                    .as_ref()
                    .expect("development streaming private key"),
            )
            .unwrap(),
        );
        expected.insert(
            "P2P_PUBLIC_ADDRESS".into(),
            Value::String(env.p2p_public_address.to_string()),
        );
        expected.insert(
            "P2P_ADDRESS".into(),
            Value::String(env.p2p_address.to_string()),
        );
        expected.insert(
            "API_ADDRESS".into(),
            Value::String(env.api_address.to_string()),
        );
        if !env.trusted_peers.is_empty() {
            let peers: Vec<String> = env
                .trusted_peers
                .iter()
                .map(|peer| peer.id().to_string())
                .collect();
            let trusted = json::to_json(&peers).unwrap();
            expected.insert("TRUSTED_PEERS".into(), Value::String(trusted.clone()));
            // Ensure the embedded JSON string remains valid Norito JSON.
            let parsed = json::parse_value(&trusted).expect("parse trusted peers JSON");
            assert!(matches!(parsed, Value::Array(_)));
        }
        if !env.trusted_peers_pop.is_empty() {
            let mut pops = Vec::new();
            for (pk, pop) in &env.trusted_peers_pop {
                let mut entry = Map::new();
                entry.insert("public_key".into(), Value::String(pk.to_string()));
                entry.insert(
                    "pop_hex".into(),
                    Value::String(format!("0x{}", encode_hex(pop))),
                );
                pops.push(Value::Object(entry));
            }
            let trusted = json::to_json(&pops).unwrap();
            expected.insert("TRUSTED_PEERS_POP".into(), Value::String(trusted.clone()));
            let parsed = json::parse_value(&trusted).expect("parse trusted peers pop JSON");
            assert!(matches!(parsed, Value::Array(_)));
        }
        assert_eq!(actual, Value::Object(expected));
    }
    #[test]
    fn peer_env_without_streaming_identity_renders_no_streaming_keys() {
        let (primary_pair, transport_pair, _, ports, chain, topology, trusted_pops) =
            sample_topology();
        let env = PeerEnv::new(
            &primary_pair,
            &transport_pair,
            None,
            ports,
            &chain,
            &topology,
            trusted_pops,
        );
        let Value::Object(map) = peer_env_to_value(&env) else {
            panic!("peer environment is an object");
        };
        for key in [
            "STREAMING_IDENTITY_PUBLIC_KEY",
            "STREAMING_IDENTITY_PRIVATE_KEY",
        ] {
            assert!(
                !map.contains_key(key),
                "an environment without a streaming identity must not render {key}"
            );
        }
        assert!(map.contains_key("P2P_SORANET_TRANSPORT_PUBLIC_KEY"));
    }
}
trait ComposeImageFields {
    fn into_fields(self) -> norito::json::Map;
}
/// Schema serialization error.
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Could not write the banner: {0}
    BannerWrite(std::io::Error),
    /// Could not serialize the schema: {0}
    Yaml(norito::yaml::Error),
}
impl std::error::Error for Error {}
/// Image identifier.
#[derive(Copy, Clone, Debug)]
struct ImageId<'a>(&'a str);
impl ImageId<'_> {
    fn as_value(self) -> norito::json::Value {
        norito::json::Value::String(self.0.to_owned())
    }
}
/// Dictates how the image provider will build the image from a Dockerfile.
#[derive(Copy, Clone, Debug)]
enum Build {
    /// Rebuild the image, ignoring the local cache.
    IgnoreCache,
    /// Only build the image when it is missing from the local cache.
    OnCacheMiss,
}
impl Build {
    fn as_str(self) -> &'static str {
        match self {
            Self::IgnoreCache => "build",
            Self::OnCacheMiss => "never",
        }
    }
}
/// Dictates that a service must use the built image.
#[derive(Copy, Clone, Debug)]
enum UseBuilt {
    UseCached,
}
impl UseBuilt {
    fn is_on_cache_miss(self) -> bool {
        match self {
            Self::UseCached => false,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::UseCached => "never",
        }
    }
}
/// Dictates how a service will pull the image from Docker Hub.
#[derive(Copy, Clone, Debug)]
enum Pull {
    /// Always pull the image, ignoring the local cache.
    IgnoreCache,
    /// Only pull the image when it is missing from the local cache.
    OnCacheMiss,
}
impl Pull {
    fn as_str(self) -> &'static str {
        match self {
            Self::IgnoreCache => "always",
            Self::OnCacheMiss => "missing",
        }
    }
}
/// Path on the host.
#[derive(Copy, Clone, Debug)]
struct HostPath<'a>(&'a path::RelativePath);
/// Image build settings.
#[derive(Copy, Clone, Debug)]
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
impl ComposeImageFields for BuildImage<'_> {
    fn into_fields(self) -> norito::json::Map {
        let mut map = norito::json::Map::new();
        map.insert("image".into(), self.image.as_value());
        map.insert(
            "build".into(),
            norito::json::Value::String(compose_path_literal(
                &self.build.0.as_ref().display().to_string(),
            )),
        );
        map.insert(
            "pull_policy".into(),
            norito::json::Value::String(self.pull_policy.as_str().into()),
        );
        map
    }
}
/// Image that has been built.
#[derive(Copy, Clone, Debug)]
struct BuiltImage<'a> {
    image: ImageId<'a>,
    pull_policy: UseBuilt,
}
/// Image that has been pulled.
#[derive(Copy, Clone, Debug)]
struct PulledImage<'a> {
    image: ImageId<'a>,
    pull_policy: Pull,
}
impl<'a> BuiltImage<'a> {
    fn new(image: ImageId<'a>) -> Self {
        Self {
            image,
            pull_policy: UseBuilt::UseCached,
        }
    }
}
impl ComposeImageFields for BuiltImage<'_> {
    fn into_fields(self) -> norito::json::Map {
        let mut map = norito::json::Map::new();
        map.insert("image".into(), self.image.as_value());
        if !self.pull_policy.is_on_cache_miss() {
            map.insert(
                "pull_policy".into(),
                norito::json::Value::String(self.pull_policy.as_str().into()),
            );
        }
        map
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
impl ComposeImageFields for PulledImage<'_> {
    fn into_fields(self) -> norito::json::Map {
        let mut map = norito::json::Map::new();
        map.insert("image".into(), self.image.as_value());
        map.insert(
            "pull_policy".into(),
            norito::json::Value::String(self.pull_policy.as_str().into()),
        );
        map
    }
}
/// Peer environment variables.
#[derive(Debug)]
struct PeerEnv<'a> {
    chain: &'a iroha_model_base::chain::ChainId,
    public_key: &'a iroha_crypto::PublicKey,
    private_key: Option<&'a iroha_crypto::ExposedPrivateKey>,
    soranet_transport_public_key: &'a iroha_crypto::PublicKey,
    soranet_transport_private_key: Option<&'a iroha_crypto::ExposedPrivateKey>,
    streaming_identity_public_key: Option<&'a iroha_crypto::PublicKey>,
    streaming_identity_private_key: Option<&'a iroha_crypto::ExposedPrivateKey>,
    p2p_public_address: iroha_primitives::addr::SocketAddr,
    p2p_address: iroha_primitives::addr::SocketAddr,
    api_address: iroha_primitives::addr::SocketAddr,
    trusted_peers: std::collections::BTreeSet<&'a iroha_data_model::peer::Peer>,
    trusted_peers_pop: std::collections::BTreeMap<iroha_crypto::PublicKey, Vec<u8>>,
}
impl<'a> PeerEnv<'a> {
    fn new(
        (public_key, private_key): &'a peer::ExposedKeyPair,
        (soranet_transport_public_key, soranet_transport_private_key): &'a peer::ExposedKeyPair,
        streaming_identity: Option<&'a peer::ExposedKeyPair>,
        [port_p2p, port_api]: [u16; 2],
        chain: &'a iroha_model_base::chain::ChainId,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
        trusted_peers_pop: std::collections::BTreeMap<iroha_crypto::PublicKey, Vec<u8>>,
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
            private_key: private_key.as_ref(),
            soranet_transport_public_key,
            soranet_transport_private_key: soranet_transport_private_key.as_ref(),
            streaming_identity_public_key: streaming_identity.map(|(public_key, _)| public_key),
            streaming_identity_private_key: streaming_identity
                .and_then(|(_, private_key)| private_key.as_ref()),
            p2p_public_address,
            p2p_address: iroha_primitives::addr::socket_addr!(0.0.0.0:port_p2p),
            api_address: iroha_primitives::addr::socket_addr!(0.0.0.0:port_api),
            trusted_peers: topology
                .iter()
                .filter(|&peer| peer.id().public_key() != public_key)
                .collect(),
            trusted_peers_pop,
        }
    }
}
/// Mapping between `host:container` ports.
#[derive(Debug)]
struct PortMapping(u16, u16);
const GENESIS_PUBLIC_KEY_SECRET: &str = "iroha_genesis_public_key";
const GENESIS_EXPECTED_HASH_SECRET: &str = "iroha_genesis_expected_hash";
const CONTAINER_SIGNED_GENESIS: &str = "/genesis/genesis.signed.nrt";
const CONTAINER_PEER_CONFIG: &str = "/config/peer.toml";
const CONTAINER_STORAGE: &str = "/storage";
const GENESIS_PUBLIC_KEY_FILE_SOURCE: &str = "${IROHA_GENESIS_PUBLIC_KEY_FILE:?set IROHA_GENESIS_PUBLIC_KEY_FILE to an owner-controlled genesis public-key file}";
const GENESIS_EXPECTED_HASH_FILE_SOURCE: &str = "${IROHA_GENESIS_EXPECTED_HASH_FILE:?set IROHA_GENESIS_EXPECTED_HASH_FILE to an owner-controlled checked genesis network-identity file}";
const GENESIS_SIGNED_FILE_SOURCE: &str = "${IROHA_GENESIS_SIGNED_FILE:?set IROHA_GENESIS_SIGNED_FILE to an owner-prepared signed genesis block}";
fn artifact_source<'a>(
    settings: &'a GenesisArtifactSettings,
    prepared: impl FnOnce(
        &'a path::RelativePath,
        &'a path::RelativePath,
        &'a path::RelativePath,
    ) -> &'a path::RelativePath,
    environment: &'static str,
) -> String {
    let source = match settings {
        GenesisArtifactSettings::Environment => environment.to_owned(),
        GenesisArtifactSettings::Prepared {
            signed_block,
            public_key,
            expected_hash,
        } => prepared(signed_block, public_key, expected_hash)
            .as_ref()
            .display()
            .to_string(),
    };
    if matches!(settings, GenesisArtifactSettings::Prepared { .. }) {
        compose_path_literal(&source)
    } else {
        source
    }
}
fn signed_block_source(settings: &GenesisArtifactSettings) -> String {
    artifact_source(
        settings,
        |signed_block, _, _| signed_block,
        GENESIS_SIGNED_FILE_SOURCE,
    )
}
fn public_key_source(settings: &GenesisArtifactSettings) -> String {
    artifact_source(
        settings,
        |_, public_key, _| public_key,
        GENESIS_PUBLIC_KEY_FILE_SOURCE,
    )
}
fn expected_hash_source(settings: &GenesisArtifactSettings) -> String {
    artifact_source(
        settings,
        |_, _, expected_hash| expected_hash,
        GENESIS_EXPECTED_HASH_FILE_SOURCE,
    )
}
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
impl Healthcheck {
    fn into_value(self) -> Value {
        let mut map = norito::json::Map::new();
        map.insert(
            "test".into(),
            Value::String(format!(
                "test $$(curl -s http://127.0.0.1:{}/status/blocks) -gt 0",
                self.port
            )),
        );
        map.insert(
            "interval".into(),
            Value::String(HEALTH_CHECK_INTERVAL.into()),
        );
        map.insert("timeout".into(), Value::String(HEALTH_CHECK_TIMEOUT.into()));
        map.insert(
            "retries".into(),
            Value::Number(norito::json::Number::from(u64::from(HEALTH_CHECK_RETRIES))),
        );
        map.insert(
            "start_period".into(),
            Value::String(HEALTH_CHECK_START_PERIOD.into()),
        );
        Value::Object(map)
    }
}
fn secret_names(runtime: Option<&PreparedRuntimeConfig>) -> Value {
    let mut secrets = vec![
        Value::String(GENESIS_PUBLIC_KEY_SECRET.into()),
        Value::String(GENESIS_EXPECTED_HASH_SECRET.into()),
    ];
    if let Some(runtime) = runtime {
        let mut peer_config = Map::new();
        peer_config.insert(
            "source".into(),
            Value::String(prepared_peer_config_name(runtime)),
        );
        peer_config.insert("target".into(), Value::String(CONTAINER_PEER_CONFIG.into()));
        secrets.push(Value::Object(peer_config));
        for (index, secret) in runtime.secrets.iter().enumerate() {
            let mut reference = Map::new();
            reference.insert(
                "source".into(),
                Value::String(prepared_runtime_secret_name(runtime, index)),
            );
            reference.insert("target".into(), Value::String(secret.target.clone()));
            secrets.push(Value::Object(reference));
        }
    }
    Value::Array(secrets)
}
fn compose_secrets(
    settings: &GenesisArtifactSettings,
    prepared_runtime: Option<&std::collections::BTreeMap<u16, PreparedRuntimeConfig>>,
) -> Value {
    let mut public = Map::new();
    public.insert("file".into(), Value::String(public_key_source(settings)));
    let mut expected_hash = Map::new();
    expected_hash.insert("file".into(), Value::String(expected_hash_source(settings)));
    let mut secrets = Map::new();
    secrets.insert(GENESIS_PUBLIC_KEY_SECRET.into(), Value::Object(public));
    secrets.insert(
        GENESIS_EXPECTED_HASH_SECRET.into(),
        Value::Object(expected_hash),
    );
    if let Some(prepared_runtime) = prepared_runtime {
        for runtime in prepared_runtime.values() {
            let mut peer_config = Map::new();
            peer_config.insert(
                "file".into(),
                Value::String(compose_path_literal(
                    &runtime.source.as_ref().display().to_string(),
                )),
            );
            secrets.insert(
                prepared_peer_config_name(runtime),
                Value::Object(peer_config),
            );
            for (index, secret) in runtime.secrets.iter().enumerate() {
                let mut runtime_secret = Map::new();
                runtime_secret.insert(
                    "file".into(),
                    Value::String(compose_path_literal(
                        &secret.source.as_ref().display().to_string(),
                    )),
                );
                secrets.insert(
                    prepared_runtime_secret_name(runtime, index),
                    Value::Object(runtime_secret),
                );
            }
        }
    }
    Value::Object(secrets)
}
fn signed_genesis_mount(settings: &GenesisArtifactSettings) -> Value {
    let mut mount = Map::new();
    mount.insert("type".into(), Value::String("bind".into()));
    mount.insert(
        "source".into(),
        Value::String(signed_block_source(settings)),
    );
    mount.insert(
        "target".into(),
        Value::String(CONTAINER_SIGNED_GENESIS.into()),
    );
    mount.insert("read_only".into(), Value::Bool(true));
    Value::Object(mount)
}
fn private_file_mount(source: String, target: &str) -> Value {
    let mut bind = Map::new();
    bind.insert("create_host_path".into(), Value::Bool(false));
    let mut mount = Map::new();
    mount.insert("bind".into(), Value::Object(bind));
    mount.insert("type".into(), Value::String("bind".into()));
    mount.insert("source".into(), Value::String(source));
    mount.insert("target".into(), Value::String(target.to_owned()));
    mount.insert("read_only".into(), Value::Bool(true));
    Value::Object(mount)
}
fn private_config_mounts(runtime: Option<&PreparedRuntimeConfig>, peer_index: u16) -> Vec<Value> {
    if runtime.is_some() {
        return Vec::new();
    }
    vec![private_file_mount(
        format!(
            "${{IROHA_PEER{peer_index}_CONFIG_FILE:?set IROHA_PEER{peer_index}_CONFIG_FILE to this nodes existing owner-0600 TOML}}"
        ),
        CONTAINER_PEER_CONFIG,
    )]
}
fn prepared_storage_name(runtime: &PreparedRuntimeConfig) -> String {
    format!("{}_data", runtime.compose_name_prefix)
}
fn prepared_storage_mount(runtime: &PreparedRuntimeConfig) -> Value {
    let mut mount = Map::new();
    mount.insert("type".into(), Value::String("volume".into()));
    mount.insert(
        "source".into(),
        Value::String(prepared_storage_name(runtime)),
    );
    mount.insert("target".into(), Value::String(CONTAINER_STORAGE.into()));
    Value::Object(mount)
}
fn compose_volumes(
    prepared_runtime: &std::collections::BTreeMap<u16, PreparedRuntimeConfig>,
) -> Value {
    let mut volumes = Map::new();
    for runtime in prepared_runtime.values() {
        volumes.insert(prepared_storage_name(runtime), Value::Object(Map::new()));
    }
    Value::Object(volumes)
}
fn prepared_peer_config_name(runtime: &PreparedRuntimeConfig) -> String {
    format!("{}_peer_config", runtime.compose_name_prefix)
}
fn prepared_runtime_secret_name(runtime: &PreparedRuntimeConfig, index: usize) -> String {
    format!("{}_runtime_secret_{index}", runtime.compose_name_prefix)
}
fn prepared_runtime_file_name(file: &PreparedRuntimeSource) -> String {
    format!("runtime_file_{}", iroha_crypto::Hash::new(&file.content))
}
fn prepared_runtime_encoded_target(file: &PreparedRuntimeSource) -> String {
    format!(
        "/run/secrets/iroha_runtime_{}.b64",
        iroha_crypto::Hash::new(&file.content)
    )
}
fn prepared_config_reference(source: String, target: &str) -> Value {
    let mut reference = Map::new();
    reference.insert("source".into(), Value::String(source));
    reference.insert("target".into(), Value::String(target.to_owned()));
    Value::Object(reference)
}
fn prepared_service_configs(runtime: &PreparedRuntimeConfig) -> Vec<Value> {
    let mut names = std::collections::BTreeSet::new();
    runtime
        .files
        .iter()
        .filter_map(|file| {
            let name = prepared_runtime_file_name(file);
            names
                .insert(name.clone())
                .then(|| prepared_config_reference(name, &prepared_runtime_encoded_target(file)))
        })
        .collect()
}
fn compose_path_literal(content: &str) -> String {
    // Compose interpolates every scalar, including file and bind source paths.
    // Doubling the sigil preserves a literal path component.
    content.replace('$', "$$")
}
fn prepared_compose_configs(
    prepared_runtime: &std::collections::BTreeMap<u16, PreparedRuntimeConfig>,
) -> Value {
    let mut configs = Map::new();
    for runtime in prepared_runtime.values() {
        for file in &runtime.files {
            let name = prepared_runtime_file_name(file);
            let mut runtime_file = Map::new();
            let rendered_content = base64_standard::encode(&file.content);
            runtime_file.insert("content".into(), Value::String(rendered_content.clone()));
            match configs.insert(name.clone(), Value::Object(runtime_file)) {
                Some(Value::Object(existing))
                    if existing.get("content") != Some(&Value::String(rendered_content)) =>
                {
                    panic!("prepared runtime config digest collision for {name}");
                }
                _ => {}
            }
        }
    }
    Value::Object(configs)
}
fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)]);
        encoded.push(HEX[usize::from(byte & 0x0f)]);
    }
    String::from_utf8(encoded).expect("hex alphabet is valid UTF-8")
}
fn load_signed_genesis_and_run(runtime: Option<&PreparedRuntimeConfig>) -> String {
    let launch = runtime.map_or_else(
        || {
            "export GENESIS_PUBLIC_KEY GENESIS GENESIS_EXPECTED_HASH_FILE && \
             exec iroha3d --config /config/peer.toml"
                .to_owned()
        },
        |runtime| {
            let sora = if runtime.requires_sora_profile {
                " --sora"
            } else {
                ""
            };
            let config_blake3 = lowercase_hex(&runtime.blake3);
            let mut materialize = String::new();
            if !runtime.files.is_empty() {
                materialize.push_str("umask 077 && mkdir -p /config/runtime && ");
                for file in &runtime.files {
                    let parent = std::path::Path::new(&file.target)
                        .parent()
                        .expect("validated runtime target has a parent")
                        .display();
                    let encoded = prepared_runtime_encoded_target(file);
                    let temporary = format!("{}.kagami-tmp", file.target);
                    write!(
                        &mut materialize,
                        "mkdir -p {parent} && base64 -d < {encoded} > {temporary} && \
                         chmod 0400 {temporary} && mv -f {temporary} {} && ",
                        file.target
                    )
                    .expect("format runtime materialization command");
                }
            }
            format!(
                "{materialize}exec env -i PATH=/usr/local/bin:/usr/bin:/bin \
                 HOME=/opt/iroha USER=iroha \
                 iroha3d{sora} --config /config/peer.toml \
                 --config-blake3 {config_blake3}"
            )
        },
    );
    // Local Compose file binds retain host ownership and mode. Require originals and private
    // projected TOML to be native owner-0600 files for the actual daemon UID; never pretend
    // Compose secret uid/mode fields perform a cross-UID custody transfer.
    let custody_checks = format!(
        r#"require_private_file() {{
        test -f \"$$1\" && test ! -L \"$$1\" && test -r \"$$1\" && test -s \"$$1\" &&
        test \"$$(stat -c '%u:%a:%h' \"$$1\")\" = \"$$(id -u):600:1\" &&
        test \"$$(wc -c < \"$$1\")\" -le \"$$2\" || {{
            printf '%s\n' 'required configuration original is absent or lacks native owner-0600 single-link custody' >&2; exit 1;
        }};
    }} &&
    require_private_file /config/peer.toml 8388608 &&"#
    );
    format!(
        r#"/bin/sh -eu -c "
    GENESIS_PUBLIC_KEY_FILE=/run/secrets/iroha_genesis_public_key && \\
    GENESIS=/genesis/genesis.signed.nrt && \\
    GENESIS_EXPECTED_HASH_FILE=/run/secrets/iroha_genesis_expected_hash && \\
    test -s \"$$GENESIS\" && \\
    test -s \"$$GENESIS_EXPECTED_HASH_FILE\" && \\
    test -s \"$$GENESIS_PUBLIC_KEY_FILE\" && \\
    test \"$$(wc -l < \"$$GENESIS_PUBLIC_KEY_FILE\")\" -eq 1 && \\
    test -z \"$$(tail -c 1 < \"$$GENESIS_PUBLIC_KEY_FILE\")\" && \\
    IFS= read -r GENESIS_PUBLIC_KEY < \"$$GENESIS_PUBLIC_KEY_FILE\" && \\
    test -n \"$$GENESIS_PUBLIC_KEY\" && \\
    printf '%s\n' \"$$GENESIS_PUBLIC_KEY\" | grep -Eq '^[^[:space:]]+$$' && \\
    test \"$$(wc -l < \"$$GENESIS_EXPECTED_HASH_FILE\")\" -eq 1 && \\
    test -z \"$$(tail -c 1 < \"$$GENESIS_EXPECTED_HASH_FILE\")\" && \\
    IFS= read -r GENESIS_NETWORK_ID < \"$$GENESIS_EXPECTED_HASH_FILE\" && \\
    printf '%s\n' \"$$GENESIS_NETWORK_ID\" | grep -Eq '^hash:[0-9A-F]{{63}}[13579BDF]#[0-9A-F]{{4}}$$' && \\
    {custody_checks}
    {launch}
""#
    )
}
/// Iroha peer service.
#[derive(Debug)]
struct Irohad<'a, Image>
where
    Image: ComposeImageFields,
{
    image: Image,
    environment: PeerEnv<'a>,
    ports: [PortMapping; 2],
    healthcheck: Option<Healthcheck>,
    genesis: &'a GenesisArtifactSettings,
    runtime: Option<&'a PreparedRuntimeConfig>,
    peer_index: u16,
}
impl<'a, Image> Irohad<'a, Image>
where
    Image: ComposeImageFields,
{
    fn new(
        image: Image,
        environment: PeerEnv<'a>,
        [port_p2p, port_api]: [u16; 2],
        healthcheck: bool,
        genesis: &'a GenesisArtifactSettings,
        runtime: Option<&'a PreparedRuntimeConfig>,
        peer_index: u16,
    ) -> Self {
        Self {
            image,
            environment,
            ports: [
                PortMapping(port_p2p, port_p2p),
                PortMapping(port_api, port_api),
            ],
            healthcheck: healthcheck.then_some(Healthcheck { port: port_api }),
            genesis,
            runtime,
            peer_index,
        }
    }
    fn into_map(self) -> norito::json::Map {
        let mut map = self.image.into_fields();
        if self.runtime.is_none() {
            map.insert("environment".into(), peer_env_to_value(&self.environment));
        }
        map.insert(
            "ports".into(),
            norito::json::Value::Array(
                self.ports
                    .into_iter()
                    .map(|mapping| {
                        norito::json::Value::String(format!("{}:{}", mapping.0, mapping.1))
                    })
                    .collect(),
            ),
        );
        let mut volumes = vec![signed_genesis_mount(self.genesis)];
        volumes.extend(private_config_mounts(self.runtime, self.peer_index));
        if let Some(runtime) = self.runtime {
            volumes.push(prepared_storage_mount(runtime));
        }
        map.insert("volumes".into(), Value::Array(volumes));
        map.insert(
            "command".into(),
            Value::String(load_signed_genesis_and_run(self.runtime)),
        );
        map.insert("secrets".into(), secret_names(self.runtime));
        if let Some(runtime) = self.runtime {
            let configs = prepared_service_configs(runtime);
            if !configs.is_empty() {
                map.insert("configs".into(), Value::Array(configs));
            }
        }
        map.insert("init".into(), norito::json::Value::Bool(true));
        if let Some(healthcheck) = self.healthcheck {
            map.insert("healthcheck".into(), healthcheck.into_value());
        }
        map
    }
}
/// Reference to an `irohad` service.
#[derive(Debug, PartialOrd, PartialEq, Ord, Eq)]
struct IrohadRef(String);
impl IrohadRef {
    fn service_name(&self) -> String {
        self.0.clone()
    }
}
#[derive(Debug)]
enum BuildOrPull<'a> {
    Build {
        primary: Box<(IrohadRef, Irohad<'a, BuildImage<'a>>)>,
        irohads: std::collections::BTreeMap<IrohadRef, Irohad<'a, BuiltImage<'a>>>,
    },
    Pull {
        irohads: std::collections::BTreeMap<IrohadRef, Irohad<'a, PulledImage<'a>>>,
    },
}
impl<'a> BuildOrPull<'a> {
    fn pull(
        image: PulledImage<'a>,
        healthcheck: bool,
        genesis: &'a GenesisArtifactSettings,
        prepared_runtime: Option<&'a std::collections::BTreeMap<u16, PreparedRuntimeConfig>>,
        chain: &'a iroha_model_base::chain::ChainId,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Self {
        let trusted_peers_pop = trusted_peers_pop_map(network);
        Self::Pull {
            irohads: Self::irohads(
                image,
                healthcheck,
                genesis,
                prepared_runtime,
                chain,
                network,
                topology,
                &trusted_peers_pop,
            ),
        }
    }
    fn build(
        image: BuildImage<'a>,
        healthcheck: bool,
        genesis: &'a GenesisArtifactSettings,
        prepared_runtime: Option<&'a std::collections::BTreeMap<u16, PreparedRuntimeConfig>>,
        chain: &'a iroha_model_base::chain::ChainId,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    ) -> Self {
        let trusted_peers_pop = trusted_peers_pop_map(network);
        let mut peers = network.iter();
        let (primary_index, primary_info) = peers
            .next()
            .expect("a swarm always contains at least one validator");
        Self::Build {
            primary: Box::new((
                IrohadRef(primary_info.name.clone()),
                Self::irohad(
                    image,
                    healthcheck,
                    genesis,
                    prepared_runtime.and_then(|configs| configs.get(primary_index)),
                    chain,
                    topology,
                    &trusted_peers_pop,
                    primary_info,
                    *primary_index,
                ),
            )),
            irohads: peers
                .map(|(index, info)| {
                    (
                        IrohadRef(info.name.clone()),
                        Self::irohad(
                            BuiltImage::new(image.image),
                            healthcheck,
                            genesis,
                            prepared_runtime.and_then(|configs| configs.get(index)),
                            chain,
                            topology,
                            &trusted_peers_pop,
                            info,
                            *index,
                        ),
                    )
                })
                .collect(),
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Compose service assembly requires the complete peer deployment context"
    )]
    fn irohad<Image: ComposeImageFields>(
        image: Image,
        healthcheck: bool,
        genesis: &'a GenesisArtifactSettings,
        runtime: Option<&'a PreparedRuntimeConfig>,
        chain: &'a iroha_model_base::chain::ChainId,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
        trusted_peers_pop: &std::collections::BTreeMap<iroha_crypto::PublicKey, Vec<u8>>,
        peer_info: &'a peer::PeerInfo,
        peer_index: u16,
    ) -> Irohad<'a, Image> {
        Irohad::new(
            image,
            PeerEnv::new(
                &peer_info.key_pair,
                &peer_info.soranet_transport_key_pair,
                peer_info.streaming_identity_key_pair.as_ref(),
                peer_info.ports,
                chain,
                topology,
                trusted_peers_pop.clone(),
            ),
            peer_info.ports,
            healthcheck,
            genesis,
            runtime,
            peer_index,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Compose service assembly requires the complete peer deployment context"
    )]
    fn irohads<Image: ComposeImageFields + Copy>(
        image: Image,
        healthcheck: bool,
        genesis: &'a GenesisArtifactSettings,
        prepared_runtime: Option<&'a std::collections::BTreeMap<u16, PreparedRuntimeConfig>>,
        chain: &'a iroha_model_base::chain::ChainId,
        network: &'a std::collections::BTreeMap<u16, peer::PeerInfo>,
        topology: &'a std::collections::BTreeSet<iroha_data_model::peer::Peer>,
        trusted_peers_pop: &std::collections::BTreeMap<iroha_crypto::PublicKey, Vec<u8>>,
    ) -> std::collections::BTreeMap<IrohadRef, Irohad<'a, Image>> {
        network
            .iter()
            .map(|(index, info)| {
                (
                    IrohadRef(info.name.clone()),
                    Self::irohad(
                        image,
                        healthcheck,
                        genesis,
                        prepared_runtime.and_then(|configs| configs.get(index)),
                        chain,
                        topology,
                        trusted_peers_pop,
                        info,
                        *index,
                    ),
                )
            })
            .collect()
    }
    fn into_services_map(self) -> norito::json::Map {
        let mut services = norito::json::Map::new();
        match self {
            BuildOrPull::Build { primary, irohads } => {
                let (service_ref, service) = *primary;
                services.insert(
                    service_ref.service_name(),
                    norito::json::Value::Object(service.into_map()),
                );
                for (service_ref, service) in irohads {
                    services.insert(
                        service_ref.service_name(),
                        norito::json::Value::Object(service.into_map()),
                    );
                }
            }
            BuildOrPull::Pull { irohads } => {
                for (service_ref, service) in irohads {
                    services.insert(
                        service_ref.service_name(),
                        norito::json::Value::Object(service.into_map()),
                    );
                }
            }
        }
        services
    }
}
/// Docker Compose configuration.
#[derive(Debug)]
pub struct DockerCompose<'a> {
    services: BuildOrPull<'a>,
    genesis: &'a GenesisArtifactSettings,
    prepared_runtime: Option<&'a std::collections::BTreeMap<u16, PreparedRuntimeConfig>>,
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
            chain,
            network,
            topology,
            prepared_runtime,
        }: &'a PeerSettings,
        genesis: &'a GenesisArtifactSettings,
    ) -> Self {
        let image = ImageId(name);
        Self {
            services: build_dir.as_ref().map_or_else(
                || {
                    BuildOrPull::pull(
                        PulledImage::new(image, *ignore_cache),
                        *healthcheck,
                        genesis,
                        prepared_runtime.as_ref(),
                        chain,
                        network,
                        topology,
                    )
                },
                |build| {
                    BuildOrPull::build(
                        BuildImage::new(image, HostPath(build), *ignore_cache),
                        *healthcheck,
                        genesis,
                        prepared_runtime.as_ref(),
                        chain,
                        network,
                        topology,
                    )
                },
            ),
            genesis,
            prepared_runtime: prepared_runtime.as_ref(),
        }
    }
    fn into_value(self) -> norito::json::Value {
        let mut root = norito::json::Map::new();
        root.insert(
            "secrets".into(),
            compose_secrets(self.genesis, self.prepared_runtime),
        );
        if let Some(prepared_runtime) = self.prepared_runtime {
            root.insert("volumes".into(), compose_volumes(prepared_runtime));
            let configs = prepared_compose_configs(prepared_runtime);
            if let Value::Object(ref map) = configs
                && !map.is_empty()
            {
                root.insert("configs".into(), configs);
            }
        }
        root.insert(
            "services".into(),
            norito::json::Value::Object(self.services.into_services_map()),
        );
        norito::json::Value::Object(root)
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
        let value = self.into_value();
        norito::yaml::to_writer_from_value(&mut writer, &value).map_err(Error::Yaml)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    impl<'a> From<PeerEnv<'a>> for iroha_config::base::env::MockEnv {
        fn from(env: PeerEnv<'a>) -> Self {
            mock_env_from_value(peer_env_to_value(&env))
        }
    }
    fn mock_env_from_value(value: Value) -> iroha_config::base::env::MockEnv {
        let Value::Object(map) = value else {
            panic!("environment payload must be an object");
        };
        let mut vars = HashMap::new();
        for (key, value) in map {
            let value = match value {
                Value::String(s) => s,
                other => json::to_json(&other).expect("serialize environment value"),
            };
            vars.insert(key, value);
        }
        iroha_config::base::env::MockEnv::with_map(vars)
    }
    #[test]
    fn peer_env_produces_exhaustive_config() {
        let genesis_public_key = peer::generate_key_pair(None, &[])
            .expect("random genesis key generation should succeed")
            .0;
        let chain = peer::chain();
        for validator_count in [4_u16, 7, 31] {
            let network = peer::network(
                validator_count,
                Some(b"iroha-swarm-canonical-config-admission"),
            )
            .expect("derive deterministic validator network");
            let topology = peer::topology(network.values());
            let local = network.get(&0).expect("network has a first validator");
            assert_eq!(
                local.soranet_transport_key_pair.0.algorithm(),
                iroha_crypto::Algorithm::Ed25519
            );
            assert_ne!(local.soranet_transport_key_pair.0, local.key_pair.0);
            iroha_crypto::KeyPair::new(
                local.soranet_transport_key_pair.0.clone(),
                local
                    .soranet_transport_key_pair
                    .1
                    .as_ref()
                    .expect("transport private key")
                    .0
                    .clone(),
            )
            .expect("transport key pair must match");
            let streaming_identity = local
                .streaming_identity_key_pair
                .as_ref()
                .expect("development validators render a streaming identity");
            assert_eq!(
                streaming_identity.0.algorithm(),
                iroha_crypto::Algorithm::Ed25519,
                "streaming admission requires an Ed25519 identity"
            );
            assert_ne!(streaming_identity.0, local.key_pair.0);
            assert_ne!(streaming_identity.0, local.soranet_transport_key_pair.0);
            iroha_crypto::KeyPair::new(
                streaming_identity.0.clone(),
                streaming_identity
                    .1
                    .as_ref()
                    .expect("streaming private key")
                    .0
                    .clone(),
            )
            .expect("streaming key pair must match");
            let trusted_pops = network
                .values()
                .map(|peer| (peer.key_pair.0.clone(), peer.pop.clone()))
                .collect::<BTreeMap<_, _>>();
            let env = PeerEnv::new(
                &local.key_pair,
                &local.soranet_transport_key_pair,
                Some(streaming_identity),
                local.ports,
                &chain,
                &topology,
                trusted_pops,
            );
            let mut value = peer_env_to_value(&env);
            let Value::Object(ref mut map) = value else {
                unreachable!("peer environment is an object");
            };
            map.insert(
                "GENESIS_PUBLIC_KEY".into(),
                Value::String(genesis_public_key.to_string()),
            );
            map.insert(
                "GENESIS_EXPECTED_HASH".into(),
                Value::String(
                    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                        .to_owned(),
                ),
            );
            let mock_env = mock_env_from_value(value);
            let reader = iroha_config::base::read::ConfigReader::new().with_env(mock_env.clone());
            let config = reader
                .read_and_complete::<iroha_config::parameters::user::Root>()
                .expect("config in env should be exhaustive");
            let admitted = config
                .parse()
                .expect("generated peer environment must pass config parsing");
            assert_eq!(
                admitted.streaming.key_material.identity().public_key(),
                &streaming_identity.0,
                "the node must admit the rendered streaming identity instead of a fallback"
            );
            assert!(mock_env.unvisited().is_empty());
        }
    }
}
