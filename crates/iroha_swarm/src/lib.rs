//! Docker Compose configuration generator for Iroha.
mod base64_standard;
mod path;
mod peer;
mod schema;
pub use crate::peer::PeerOverride;
const CHAIN_ID: &str = "00000000-0000-0000-0000-000000000000";
const BASE_PORT_P2P: u16 = 1337;
const BASE_PORT_API: u16 = 8080;
/// Swarm error.
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Peer count ({actual}) must form an exact Sumeragi `3f + 1` committee (4..=31).
    InvalidPeerCount {
        /// Number of peers requested for the swarm manifest.
        actual: u16,
    },
    /// Target file path points to a directory.
    TargetFileIsADirectory,
    /// Target directory not found.
    NoTargetDirectory,
    /// Peer overrides count ({actual}) does not match the requested peer count ({expected}).
    InvalidPeerOverrideCount {
        /// Number of peers requested for the swarm manifest.
        expected: u16,
        /// Number of override entries supplied by the caller.
        actual: usize,
    },
    /// Failed to generate cryptographic swarm material: {0}
    KeyGeneration(String),
    /// Deterministic development mode requires a non-empty seed.
    EmptyDevelopmentSeed,
    /// A prepared validator bundle must contain at least one validator.
    EmptyPreparedValidators,
    /// Prepared validator count ({actual}) exceeds the supported u16 range.
    PreparedValidatorCountOverflow {
        /// Number of prepared validators supplied by the caller.
        actual: usize,
    },
    /// Prepared validator {index} has an invalid BLS proof of possession: {reason}
    InvalidPreparedValidatorPop {
        /// Zero-based validator index.
        index: usize,
        /// Cryptographic verification error.
        reason: String,
    },
    /// Prepared validator {index} has an invalid SoraNet transport identity: {reason}.
    #[expect(
        clippy::doc_markdown,
        reason = "displaydoc uses this text verbatim; Markdown markup would alter the error"
    )]
    InvalidPreparedTransportIdentity {
        /// Zero-based validator index.
        index: usize,
        /// Failed transport identity invariant.
        reason: String,
    },
    /// Prepared validator {index} repeats another validator's SoraNet transport identity.
    #[expect(
        clippy::doc_markdown,
        reason = "displaydoc uses this text verbatim; Markdown markup would alter the error"
    )]
    DuplicatePreparedTransportIdentity {
        /// Zero-based validator index.
        index: usize,
    },
    /// Prepared validator {index} runtime file target `{target}` must be a normalized path below `/config/runtime`.
    InvalidPreparedRuntimeTarget {
        /// Zero-based validator index.
        index: usize,
        /// Invalid container target.
        target: String,
    },
    /// Prepared validator {index} repeats runtime file target `{target}`.
    DuplicatePreparedRuntimeTarget {
        /// Zero-based validator index.
        index: usize,
        /// Duplicated container target.
        target: String,
    },
    /// Prepared validator {index} runtime file target `{target}` overlaps `{other}`.
    OverlappingPreparedRuntimeTarget {
        /// Zero-based validator index.
        index: usize,
        /// New container target.
        target: String,
        /// Existing ancestor or descendant target.
        other: String,
    },
    /// Prepared validator {index} secret target `{target}` must be one portable file below `/run/secrets`.
    InvalidPreparedSecretTarget {
        /// Zero-based validator index.
        index: usize,
        /// Invalid secret target.
        target: String,
    },
    /// Prepared validator {index} repeats secret target `{target}`.
    DuplicatePreparedSecretTarget {
        /// Zero-based validator index.
        index: usize,
        /// Duplicated secret target.
        target: String,
    },
    /// Peer {index} must use distinct non-zero P2P/API ports, got {p2p_port}/{api_port}.
    #[expect(
        clippy::doc_markdown,
        reason = "displaydoc uses this text verbatim; Markdown markup would alter the error"
    )]
    InvalidPeerPorts {
        /// Zero-based validator index.
        index: usize,
        /// P2P host/container port.
        p2p_port: u16,
        /// Torii host/container port.
        api_port: u16,
    },
    /// Peer {index} reuses host port {port}.
    DuplicateHostPort {
        /// Zero-based validator index.
        index: usize,
        /// Duplicated host port.
        port: u16,
    },
    /// Peer {index} has invalid Compose service name `{name}`.
    InvalidPeerServiceName {
        /// Zero-based peer index.
        index: u16,
        /// Invalid service name.
        name: String,
    },
    /// Compose service name `{name}` is used by more than one peer.
    DuplicatePeerServiceName {
        /// Duplicated service name.
        name: String,
    },
    /// {0}
    PathConversion(path::Error),
}
impl std::error::Error for Error {}
/// Swarm settings.
pub struct Swarm<'a> {
    /// Peer settings.
    peer: PeerSettings,
    /// Docker image settings.
    image: ImageSettings<'a>,
    /// Runtime genesis artifact sources.
    genesis: GenesisArtifactSettings,
    /// Absolute target path.
    target_path: path::AbsolutePath,
}
/// One validator identity from an already prepared and signed deployment bundle.
#[derive(Debug)]
pub struct PreparedValidator {
    /// Human-readable Compose service name.
    pub name: String,
    /// P2P port exposed by the validator service.
    pub p2p_port: u16,
    /// Torii API port exposed by the validator service.
    pub api_port: u16,
    /// Validator signing identity.
    pub key_pair: iroha_crypto::KeyPair,
    /// Dedicated Ed25519 `SoraNet` transport public identity from the admitted runtime config.
    pub soranet_transport_public_key: iroha_crypto::PublicKey,
    /// BLS proof of possession committed by the signed genesis topology.
    pub pop: Vec<u8>,
    /// Launch this validator with the explicit Sora/Nexus profile switch.
    pub requires_sora_profile: bool,
    /// Container-safe effective TOML preserving the admitted consensus policy.
    ///
    /// The file is mounted as a Compose secret and therefore does not expose
    /// validator or streaming private keys in the generated YAML.
    pub runtime_config_path: std::path::PathBuf,
    /// BLAKE3 digest of the exact projected TOML bytes.
    ///
    /// `irohad` verifies this digest while parsing the same byte buffer, so a
    /// host-side file replacement cannot silently change admitted policy.
    pub runtime_config_blake3: [u8; 32],
    /// Read-only public runtime files referenced by the projected configuration.
    pub runtime_files: Vec<PreparedRuntimeFile>,
    /// File-backed private runtime inputs that must not appear in Compose YAML.
    pub secret_files: Vec<PreparedSecretFile>,
}
/// One byte-exact runtime file materialized through a Compose config.
#[derive(Debug)]
pub struct PreparedRuntimeFile {
    /// Absolute path at which the file is visible inside the validator container.
    pub target: String,
    /// Exact public runtime bytes.
    ///
    /// Equal contents are interned into one immutable Compose config shared by
    /// every validator that consumes them.
    pub content: Vec<u8>,
}
/// One private runtime file mounted as a Compose secret.
#[derive(Debug)]
pub struct PreparedSecretFile {
    /// Absolute target below `/run/secrets` inside the validator container.
    pub target: String,
    /// Owner-protected host projection containing the exact secret bytes.
    pub source_path: std::path::PathBuf,
}
/// Host-prepared genesis artifacts consumed read-only by validators.
#[derive(Copy, Clone, Debug)]
pub struct PreparedGenesisArtifacts<'a> {
    /// Canonical signed genesis wire body.
    pub signed_block: &'a std::path::Path,
    /// Canonical one-line genesis verifier key.
    pub public_key: &'a std::path::Path,
    /// Canonical LF-terminated checked `NetworkId` for the exact genesis header hash.
    pub expected_hash: &'a std::path::Path,
}
/// Runtime genesis artifact paths, normalized relative to the Compose file.
#[derive(Debug)]
enum GenesisArtifactSettings {
    Environment,
    Prepared {
        signed_block: path::RelativePath,
        public_key: path::RelativePath,
        expected_hash: path::RelativePath,
    },
}
impl GenesisArtifactSettings {
    fn prepared(
        artifacts: PreparedGenesisArtifacts<'_>,
        target_dir: &path::AbsolutePath,
    ) -> Result<Self, Error> {
        let relative =
            |artifact: &std::path::Path| path::AbsolutePath::new(artifact)?.relative_to(target_dir);
        Ok(Self::Prepared {
            signed_block: relative(artifacts.signed_block)?,
            public_key: relative(artifacts.public_key)?,
            expected_hash: relative(artifacts.expected_hash)?,
        })
    }
}
/// Iroha peer settings.
struct PeerSettings {
    /// If `true`, include a healthcheck for every service in the configuration.
    healthcheck: bool,
    chain: iroha_model_base::chain::ChainId,
    network: std::collections::BTreeMap<u16, peer::PeerInfo>,
    topology: std::collections::BTreeSet<iroha_data_model::peer::Peer>,
    prepared_runtime: Option<std::collections::BTreeMap<u16, PreparedRuntimeConfig>>,
}
#[derive(Debug)]
struct PreparedRuntimeConfig {
    compose_name_prefix: String,
    source: path::RelativePath,
    blake3: [u8; 32],
    files: Vec<PreparedRuntimeSource>,
    secrets: Vec<PreparedSecretSource>,
    requires_sora_profile: bool,
}
#[derive(Debug)]
struct PreparedRuntimeSource {
    target: String,
    content: Vec<u8>,
}
#[derive(Debug)]
struct PreparedSecretSource {
    target: String,
    source: path::RelativePath,
}
impl PeerSettings {
    fn is_valid_runtime_target(target: &str) -> bool {
        let Some(relative) = target.strip_prefix("/config/runtime/") else {
            return false;
        };
        !relative.is_empty()
            && !target.contains('\\')
            && !target.contains("//")
            && relative.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
                    && !segment.ends_with(".kagami-tmp")
            })
    }
    fn is_valid_secret_target(target: &str) -> bool {
        let Some(name) = target.strip_prefix("/run/secrets/") else {
            return false;
        };
        !name.is_empty()
            && name != "."
            && name != ".."
            && !name.starts_with("iroha_runtime_")
            && !matches!(
                name,
                "iroha_genesis_public_key" | "iroha_genesis_expected_hash"
            )
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }
    fn validate_committee_size(count: u16) -> Result<(), Error> {
        if !iroha_data_model::block::consensus::is_valid_committee_size(usize::from(count)) {
            return Err(Error::InvalidPeerCount { actual: count });
        }
        Ok(())
    }
    fn validate_service_names(
        network: &std::collections::BTreeMap<u16, peer::PeerInfo>,
    ) -> Result<(), Error> {
        let mut names = std::collections::BTreeSet::new();
        for (index, peer_info) in network {
            let name = &peer_info.name;
            let valid = name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
            if !valid {
                return Err(Error::InvalidPeerServiceName {
                    index: *index,
                    name: name.clone(),
                });
            }
            if !names.insert(name.clone()) {
                return Err(Error::DuplicatePeerServiceName { name: name.clone() });
            }
        }
        Ok(())
    }
    fn validate_host_ports(
        ports: impl IntoIterator<Item = (usize, u16, u16)>,
    ) -> Result<(), Error> {
        let mut host_ports = std::collections::BTreeSet::new();
        for (index, p2p_port, api_port) in ports {
            if p2p_port == 0 || api_port == 0 || p2p_port == api_port {
                return Err(Error::InvalidPeerPorts {
                    index,
                    p2p_port,
                    api_port,
                });
            }
            for port in [p2p_port, api_port] {
                if !host_ports.insert(port) {
                    return Err(Error::DuplicateHostPort { index, port });
                }
            }
        }
        Ok(())
    }
    fn deterministic_dev(
        count: std::num::NonZeroU16,
        overrides: Option<Vec<peer::PeerOverride>>,
        seed: &[u8],
        healthcheck: bool,
    ) -> Result<Self, Error> {
        Self::validate_committee_size(count.get())?;
        if seed.is_empty() {
            return Err(Error::EmptyDevelopmentSeed);
        }
        let network = if let Some(overrides) = overrides {
            let expected = count.get();
            if overrides.len() != expected as usize {
                return Err(Error::InvalidPeerOverrideCount {
                    expected,
                    actual: overrides.len(),
                });
            }
            Self::validate_host_ports(
                overrides
                    .iter()
                    .enumerate()
                    .map(|(index, peer)| (index, peer.p2p_port, peer.api_port)),
            )?;
            overrides
                .into_iter()
                .enumerate()
                .map(|(idx, override_)| {
                    let nth = u16::try_from(idx).expect("peer override index must fit into u16");
                    let extra_seed = nth.to_be_bytes();
                    let name = override_.name;
                    let (key_pair, pop) = peer::generate_bls_key_pair(Some(seed), &extra_seed)
                        .map_err(|error| {
                            Error::KeyGeneration(format!(
                                "failed to generate BLS key pair for peer {name}: {error}"
                            ))
                        })?;
                    let soranet_transport_key_pair = peer::generate_soranet_transport_key_pair(
                        Some(seed),
                        &extra_seed,
                    )
                    .map_err(|error| {
                        Error::KeyGeneration(format!(
                            "failed to generate SoraNet transport key pair for peer {name}: {error}"
                        ))
                    })?;
                    let streaming_identity_key_pair = peer::generate_streaming_identity_key_pair(
                        Some(seed),
                        &extra_seed,
                    )
                    .map_err(|error| {
                        Error::KeyGeneration(format!(
                            "failed to generate streaming identity key pair for peer {name}: {error}"
                        ))
                    })?;
                    Ok((
                        nth,
                        peer::PeerInfo {
                            name,
                            ports: [override_.p2p_port, override_.api_port],
                            key_pair,
                            soranet_transport_key_pair,
                            streaming_identity_key_pair: Some(streaming_identity_key_pair),
                            pop,
                        },
                    ))
                })
                .collect::<Result<_, Error>>()?
        } else {
            peer::network(count.get(), Some(seed)).map_err(|error| {
                Error::KeyGeneration(format!("failed to generate peer network keys: {error}"))
            })?
        };
        Self::validate_service_names(&network)?;
        let topology = peer::topology(network.values());
        Ok(Self {
            healthcheck,
            chain: peer::chain(),
            network,
            topology,
            prepared_runtime: None,
        })
    }
    fn prepared(
        chain: iroha_model_base::chain::ChainId,
        validators: Vec<PreparedValidator>,
        healthcheck: bool,
        target_dir: &path::AbsolutePath,
    ) -> Result<Self, Error> {
        if validators.is_empty() {
            return Err(Error::EmptyPreparedValidators);
        }
        if validators.len() > usize::from(u16::MAX) {
            return Err(Error::PreparedValidatorCountOverflow {
                actual: validators.len(),
            });
        }
        let validator_count =
            u16::try_from(validators.len()).expect("prepared validator count was bounded above");
        Self::validate_committee_size(validator_count)?;
        let mut network = std::collections::BTreeMap::new();
        let mut prepared_runtime = std::collections::BTreeMap::new();
        Self::validate_host_ports(
            validators
                .iter()
                .enumerate()
                .map(|(index, validator)| (index, validator.p2p_port, validator.api_port)),
        )?;
        let mut transport_public_keys = std::collections::BTreeSet::new();
        for (index, validator) in validators.into_iter().enumerate() {
            iroha_crypto::bls_normal_pop_verify(validator.key_pair.public_key(), &validator.pop)
                .map_err(|error| Error::InvalidPreparedValidatorPop {
                    index,
                    reason: error.to_string(),
                })?;
            if validator.soranet_transport_public_key.algorithm()
                != iroha_crypto::Algorithm::Ed25519
            {
                return Err(Error::InvalidPreparedTransportIdentity {
                    index,
                    reason: "transport key must use Ed25519".to_owned(),
                });
            }
            if validator.soranet_transport_public_key == *validator.key_pair.public_key() {
                return Err(Error::InvalidPreparedTransportIdentity {
                    index,
                    reason: "transport key reuses the validator signing identity".to_owned(),
                });
            }
            if !transport_public_keys.insert(validator.soranet_transport_public_key.clone()) {
                return Err(Error::DuplicatePreparedTransportIdentity { index });
            }
            let id = u16::try_from(index).expect("prepared validator index fits u16");
            let source =
                path::AbsolutePath::new(&validator.runtime_config_path)?.relative_to(target_dir)?;
            let mut targets = std::collections::BTreeSet::new();
            let mut runtime_files = Vec::with_capacity(validator.runtime_files.len());
            for file in validator.runtime_files {
                if !Self::is_valid_runtime_target(&file.target) {
                    return Err(Error::InvalidPreparedRuntimeTarget {
                        index,
                        target: file.target,
                    });
                }
                if !targets.insert(file.target.clone()) {
                    return Err(Error::DuplicatePreparedRuntimeTarget {
                        index,
                        target: file.target,
                    });
                }
                if let Some(other) = targets.iter().find(|other| {
                    *other != &file.target
                        && (other.starts_with(&format!("{}/", file.target))
                            || file.target.starts_with(&format!("{other}/")))
                }) {
                    return Err(Error::OverlappingPreparedRuntimeTarget {
                        index,
                        target: file.target,
                        other: other.clone(),
                    });
                }
                runtime_files.push(PreparedRuntimeSource {
                    target: file.target,
                    content: file.content,
                });
            }
            let compose_name_prefix = validator.name.clone();
            let mut secret_targets = std::collections::BTreeSet::new();
            let mut secret_files = Vec::with_capacity(validator.secret_files.len());
            for secret in validator.secret_files {
                if !Self::is_valid_secret_target(&secret.target) {
                    return Err(Error::InvalidPreparedSecretTarget {
                        index,
                        target: secret.target,
                    });
                }
                if !secret_targets.insert(secret.target.clone()) {
                    return Err(Error::DuplicatePreparedSecretTarget {
                        index,
                        target: secret.target,
                    });
                }
                secret_files.push(PreparedSecretSource {
                    target: secret.target,
                    source: path::AbsolutePath::new(&secret.source_path)?
                        .relative_to(target_dir)?,
                });
            }
            let runtime = PreparedRuntimeConfig {
                compose_name_prefix,
                source,
                blake3: validator.runtime_config_blake3,
                files: runtime_files,
                secrets: secret_files,
                requires_sora_profile: validator.requires_sora_profile,
            };
            let (public_key, private_key) = validator.key_pair.into_parts();
            drop(private_key);
            network.insert(
                id,
                peer::PeerInfo {
                    name: validator.name,
                    ports: [validator.p2p_port, validator.api_port],
                    key_pair: (public_key, None),
                    soranet_transport_key_pair: (validator.soranet_transport_public_key, None),
                    // The admitted runtime config already binds the streaming identity.
                    streaming_identity_key_pair: None,
                    pop: validator.pop,
                },
            );
            prepared_runtime.insert(id, runtime);
        }
        Self::validate_service_names(&network)?;
        let topology = peer::topology(network.values());
        Ok(Self {
            healthcheck,
            chain,
            network,
            topology,
            prepared_runtime: Some(prepared_runtime),
        })
    }
}
/// Docker image settings.
struct ImageSettings<'a> {
    /// Image identifier.
    name: &'a str,
    /// Path to the Dockerfile directory relative to the target path.
    build_dir: Option<path::RelativePath>,
    /// If `true`, image will be pulled or built even if cached.
    ignore_cache: bool,
}
impl<'a, 'temp> ImageSettings<'a> {
    fn new(
        name: &'a str,
        build_dir: Option<&std::path::Path>,
        ignore_cache: bool,
        target_dir: &'temp path::AbsolutePath,
    ) -> Result<Self, Error> {
        Ok(Self {
            name,
            build_dir: build_dir
                .map(path::AbsolutePath::new)
                .transpose()?
                .map(|dir| dir.relative_to(target_dir))
                .transpose()?,
            ignore_cache,
        })
    }
}
impl<'a> Swarm<'a> {
    /// Creates a deterministic development-only Swarm generator.
    ///
    /// Every validator receives a BLS validator key and dedicated Ed25519 `SoraNet` transport and
    /// streaming identities, all derived from `seed` and the validator index. The two Ed25519
    /// identities use separate derivation domains, so no key serves two roles.
    ///
    /// The generated manifest requires the signed genesis body, verifier key, and exact hash
    /// through explicit host-file environment variables, as well as a per-node existing
    /// owner-only TOML. These variables select mount sources, never runtime settings or secret
    /// bytes. Host private-file ownership must match the container daemon UID. Production callers use
    /// [`Self::from_prepared`] so the validator roster and signed artifacts come from one
    /// authoritative prepared bundle.
    #[allow(clippy::missing_errors_doc)]
    #[expect(
        clippy::too_many_arguments,
        reason = "preserve the established public deterministic-development constructor"
    )]
    pub fn deterministic_dev(
        count: std::num::NonZeroU16,
        seed: &[u8],
        healthcheck: bool,
        image: &'a str,
        build_dir: Option<&std::path::Path>,
        ignore_cache: bool,
        target_path: &std::path::Path,
        peer_overrides: Option<Vec<peer::PeerOverride>>,
    ) -> Result<Self, Error> {
        let peer = PeerSettings::deterministic_dev(count, peer_overrides, seed, healthcheck)?;
        Self::with_settings(
            peer,
            GenesisArtifactSettings::Environment,
            image,
            build_dir,
            ignore_cache,
            target_path,
        )
    }
    /// Creates a Swarm from one authoritative prepared validator/genesis bundle.
    #[allow(clippy::missing_errors_doc, clippy::too_many_arguments)]
    pub fn from_prepared(
        chain: iroha_model_base::chain::ChainId,
        validators: Vec<PreparedValidator>,
        artifacts: PreparedGenesisArtifacts<'_>,
        healthcheck: bool,
        image: &'a str,
        build_dir: Option<&std::path::Path>,
        ignore_cache: bool,
        target_path: &std::path::Path,
    ) -> Result<Self, Error> {
        if target_path.is_dir() {
            return Err(Error::TargetFileIsADirectory);
        }
        let target_path = path::AbsolutePath::new(target_path)?;
        let target_dir = target_path.parent().ok_or(Error::NoTargetDirectory)?;
        let peer = PeerSettings::prepared(chain, validators, healthcheck, &target_dir)?;
        let genesis = GenesisArtifactSettings::prepared(artifacts, &target_dir)?;
        Ok(Self {
            peer,
            image: ImageSettings::new(image, build_dir, ignore_cache, &target_dir)?,
            genesis,
            target_path,
        })
    }
    fn with_settings(
        peer: PeerSettings,
        genesis: GenesisArtifactSettings,
        image: &'a str,
        build_dir: Option<&std::path::Path>,
        ignore_cache: bool,
        target_path: &std::path::Path,
    ) -> Result<Self, Error> {
        if target_path.is_dir() {
            return Err(Error::TargetFileIsADirectory);
        }
        let target_path = path::AbsolutePath::new(target_path)?;
        let target_dir = target_path.parent().ok_or(Error::NoTargetDirectory)?;
        Ok(Self {
            peer,
            image: ImageSettings::new(image, build_dir, ignore_cache, &target_dir)?,
            genesis,
            target_path,
        })
    }
    /// Builds the schema.
    #[allow(clippy::missing_errors_doc)]
    pub fn build(&self) -> schema::DockerCompose<'_> {
        schema::DockerCompose::new(&self.image, &self.peer, &self.genesis)
    }
    /// Returns the absolute target file path.
    pub fn absolute_target_path(&self) -> &std::path::Path {
        self.target_path.as_ref()
    }
}
impl From<path::Error> for Error {
    fn from(error: path::Error) -> Self {
        Self::PathConversion(error)
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines, clippy::needless_raw_string_hashes)]
    use crate::{
        PreparedGenesisArtifacts, PreparedRuntimeFile, PreparedSecretFile, PreparedValidator,
        Swarm, base64_standard,
        peer::{self, PeerOverride},
    };
    const IMAGE: &str = "hyperledger/iroha:dev";
    const TARGET_PATH: &str = "./defaults/docker-compose.yml";
    struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        fn new(label: &str) -> Self {
            let unique_suffix = format!(
                "iroha_swarm_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time should be monotonic")
                    .as_nanos()
            );
            Self {
                path: std::env::temp_dir().join(unique_suffix),
            }
        }
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    struct ComposePaths<'a> {
        target_path: &'a std::path::Path,
        peer_overrides: Option<Vec<PeerOverride>>,
    }
    fn build_with_paths(
        count: std::num::NonZeroU16,
        healthcheck: bool,
        build_dir: Option<&std::path::Path>,
        ignore_cache: bool,
        banner: Option<&[&str]>,
        paths: ComposePaths<'_>,
    ) -> String {
        let ComposePaths {
            target_path,
            peer_overrides,
        } = paths;
        let mut buffer = Vec::new();
        Swarm::deterministic_dev(
            count,
            b"iroha-swarm-tests",
            healthcheck,
            IMAGE,
            build_dir,
            ignore_cache,
            target_path,
            peer_overrides,
        )
        .unwrap()
        .build()
        .write(&mut buffer, banner)
        .unwrap();
        String::from_utf8(buffer).unwrap()
    }
    fn build_as_string(
        count: std::num::NonZeroU16,
        healthcheck: bool,
        build_dir: Option<&str>,
        ignore_cache: bool,
        banner: Option<&[&str]>,
    ) -> String {
        build_with_paths(
            count,
            healthcheck,
            build_dir.map(std::path::Path::new),
            ignore_cache,
            banner,
            ComposePaths {
                target_path: TARGET_PATH.as_ref(),
                peer_overrides: None,
            },
        )
    }
    fn valid_peer_overrides() -> Vec<PeerOverride> {
        [
            ("alpha", 2000, 9000),
            ("beta", 2001, 9001),
            ("gamma", 2002, 9002),
            ("delta", 2003, 9003),
        ]
        .into_iter()
        .map(|(name, p2p_port, api_port)| PeerOverride {
            name: name.to_owned(),
            p2p_port,
            api_port,
        })
        .collect()
    }
    fn assert_runtime_genesis_artifact_contract(output: &str, peer_count: usize) {
        for required in [
            "IROHA_GENESIS_PUBLIC_KEY_FILE:?set",
            "IROHA_GENESIS_EXPECTED_HASH_FILE:?set",
            "IROHA_GENESIS_SIGNED_FILE:?set",
        ] {
            assert!(
                output.contains(required),
                "Compose must require {required}: {output}"
            );
        }
        assert_eq!(
            output.matches("exec iroha3d").count(),
            peer_count,
            "the manifest must contain validators only: {output}"
        );
        assert!(
            !output.contains("exec irohad"),
            "the retired irohad executable name must not appear: {output}"
        );
        assert_eq!(
            output.matches("tail -c 1").count(),
            2 * peer_count,
            "every validator must reject public-key/hash files without a final newline"
        );
        assert_eq!(
            output
                .matches("^hash:[0-9A-F]{63}[13579BDF]#[0-9A-F]{4}$$")
                .count(),
            peer_count,
            "every validator must enforce canonical checked network-identity syntax"
        );
        for secret in [
            "- iroha_genesis_public_key",
            "- iroha_genesis_expected_hash",
        ] {
            assert_eq!(
                output.lines().filter(|line| line.trim() == secret).count(),
                peer_count,
                "every validator must receive {secret}: {output}"
            );
        }
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == "type: bind")
                .count(),
            2 * peer_count,
            "every validator must bind signed genesis and its real TOML"
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == "read_only: true")
                .count(),
            2 * peer_count,
            "genesis and per-node config must both be read-only"
        );
        assert!(
            output.contains("export GENESIS_PUBLIC_KEY GENESIS GENESIS_EXPECTED_HASH_FILE"),
            "validators must pass all approved artifacts into configuration"
        );
        for forbidden in [
            "IROHA_GENESIS_PRIVATE_KEY_FILE",
            "iroha_genesis_private_key",
            "kagami genesis sign",
            "service_completed_successfully",
            "depends_on:",
            "iroha_genesis:/genesis",
            "/config/client.toml",
            "/config/genesis.json",
        ] {
            assert!(
                !output.contains(forbidden),
                "validator-only Compose must not contain {forbidden}: {output}"
            );
        }
        let shell_content = output
            .lines()
            .filter(|line| !line.contains("${IROHA_"))
            .collect::<String>();
        let mut chars = shell_content.chars();
        while let Some(character) = chars.next() {
            if character == '$' {
                assert_eq!(
                    chars.next(),
                    Some('$'),
                    "shell dollars must be escaped from Compose interpolation: {output}"
                );
            }
        }
    }
    #[test]
    fn development_manifest_requires_existing_per_node_config() {
        let output = build_as_string(nonzero_ext::nonzero!(4u16), false, None, false, None);
        for index in 0..4 {
            assert!(output.contains(&format!("${{IROHA_PEER{index}_CONFIG_FILE:?")));
            for suffix in ["KAGEMUSHA_LOAD_KEYRING", "KAGEMUSHA_LOAD_SUBMITTER"] {
                assert!(!output.contains(&format!("IROHA_PEER{index}_{suffix}_FILE")));
            }
        }
        assert_eq!(output.matches("--config /config/peer.toml").count(), 4);
        assert_eq!(output.matches("create_host_path: false").count(), 4);
        assert_eq!(output.matches("require_private_file").count(), 8);
        assert_eq!(
            output
                .matches("require_private_file /config/peer.toml 8388608")
                .count(),
            4
        );
        assert!(output.contains("stat -c '%u:%a:%h'"));
        assert!(!output.contains("KAGEMUSHA_LOAD_AUTHORIZER_KEYRING"));
        assert!(
            !output.contains("user: "),
            "no unqualified numeric UID override"
        );
    }
    fn prepared_validator(index: u16) -> PreparedValidator {
        let (key_pair, pop) = peer::generate_bls_key_pair(
            Some(b"iroha-swarm-prepared-validator"),
            &index.to_be_bytes(),
        )
        .expect("derive prepared validator");
        let soranet_transport_key_pair = peer::generate_soranet_transport_key_pair(
            Some(b"iroha-swarm-prepared-validator"),
            &index.to_be_bytes(),
        )
        .expect("derive prepared validator SoraNet transport identity");
        PreparedValidator {
            name: format!("irohad{index}"),
            p2p_port: crate::BASE_PORT_P2P + index,
            api_port: crate::BASE_PORT_API + index,
            key_pair: iroha_crypto::KeyPair::new(
                key_pair.0,
                key_pair.1.expect("generated private key").0,
            )
            .expect("rebuild prepared validator key pair"),
            soranet_transport_public_key: soranet_transport_key_pair.0,
            pop,
            requires_sora_profile: false,
            runtime_config_path: std::path::PathBuf::from(format!("peer{index}.runtime.toml")),
            runtime_config_blake3: [u8::try_from(index).expect("test index fits u8"); 32],
            runtime_files: Vec::new(),
            secret_files: Vec::new(),
        }
    }
    #[test]
    fn minimum_committee_build_banner() {
        let output = build_as_string(
            nonzero_ext::nonzero!(4u16),
            false,
            Some("."),
            false,
            Some(&["Single-line banner"]),
        );
        assert!(output.starts_with("# Single-line banner\n\n"));
        assert!(output.contains("build: .."));
        assert!(output.contains("pull_policy: never"));
        assert_runtime_genesis_artifact_contract(&output, 4);
    }
    #[test]
    fn minimum_committee_build_banner_nocache() {
        let output = build_as_string(
            nonzero_ext::nonzero!(4u16),
            false,
            Some("."),
            true,
            Some(&["Multi-line banner 1", "Multi-line banner 2"]),
        );
        assert!(output.starts_with("# Multi-line banner 1\n# Multi-line banner 2\n\n"));
        assert!(output.contains("pull_policy: build"));
        assert_runtime_genesis_artifact_contract(&output, 4);
    }
    #[test]
    fn multiple_build_banner_nocache() {
        let output = build_as_string(
            nonzero_ext::nonzero!(7u16),
            false,
            Some("."),
            true,
            Some(&["Single-line banner"]),
        );
        assert_eq!(output.matches("pull_policy: build").count(), 1);
        assert_eq!(output.matches("pull_policy: never").count(), 6);
        assert!(output.contains("irohad0:"));
        assert_runtime_genesis_artifact_contract(&output, 7);
    }
    #[test]
    fn minimum_committee_pull_healthcheck() {
        let output = build_as_string(nonzero_ext::nonzero!(4u16), true, None, false, None);
        assert!(output.contains("pull_policy: missing"));
        assert!(output.contains("start_period: 4s"));
        assert_runtime_genesis_artifact_contract(&output, 4);
    }
    #[test]
    fn multiple_pull_healthcheck_nocache() {
        let output = build_as_string(nonzero_ext::nonzero!(4u16), true, None, true, None);
        assert_eq!(output.matches("pull_policy: always").count(), 4);
        assert_eq!(output.matches("start_period: 4s").count(), 4);
        assert_runtime_genesis_artifact_contract(&output, 4);
    }
    #[test]
    fn runtime_does_not_mount_source_manifests_or_client_credentials() {
        let temp = TempDir::new("runtime_inputs");
        let target_path = temp.path().join("deployment/docker-compose.yml");
        let output = build_with_paths(
            nonzero_ext::nonzero!(4u16),
            false,
            None,
            false,
            None,
            ComposePaths {
                target_path: &target_path,
                peer_overrides: None,
            },
        );
        assert!(
            !output.contains("genesis.json"),
            "unexpected manifest mount: {output}"
        );
        assert!(
            !output.contains("client.toml"),
            "unexpected client credential mount: {output}"
        );
    }
    #[test]
    fn peer_overrides_replace_default_names_and_ports() {
        let temp = TempDir::new("peer_overrides");
        let target_path = temp.path().join("docker-compose.yml");
        let overrides = valid_peer_overrides();
        let output = build_with_paths(
            nonzero_ext::nonzero!(4u16),
            false,
            None,
            false,
            None,
            ComposePaths {
                target_path: &target_path,
                peer_overrides: Some(overrides),
            },
        );
        assert!(
            output.contains("alpha"),
            "custom peer name missing: {output}"
        );
        assert!(
            output.contains("beta"),
            "custom peer name missing: {output}"
        );
        assert!(output.contains("2000"), "custom P2P port missing: {output}");
        assert!(output.contains("9000"), "custom API port missing: {output}");
    }
    #[test]
    fn deterministic_peer_overrides_reject_invalid_and_reused_host_ports() {
        let temp = TempDir::new("invalid_override_ports");
        let target_path = temp.path().join("docker-compose.yml");
        let mut invalid = valid_peer_overrides();
        invalid[0].p2p_port = 0;
        let result = Swarm::deterministic_dev(
            nonzero_ext::nonzero!(4u16),
            b"iroha-swarm-tests",
            false,
            IMAGE,
            None,
            false,
            &target_path,
            Some(invalid),
        );
        assert!(matches!(
            result,
            Err(crate::Error::InvalidPeerPorts { index: 0, .. })
        ));

        let mut duplicated = valid_peer_overrides();
        duplicated[1].api_port = duplicated[0].p2p_port;
        let result = Swarm::deterministic_dev(
            nonzero_ext::nonzero!(4u16),
            b"iroha-swarm-tests",
            false,
            IMAGE,
            None,
            false,
            &target_path,
            Some(duplicated),
        );
        assert!(matches!(
            result,
            Err(crate::Error::DuplicateHostPort {
                index: 1,
                port: 2000
            })
        ));
    }
    #[test]
    fn rejects_directory_target_path() {
        let temp = TempDir::new("target_directory");
        let target_dir = temp.path().join("deployment");
        std::fs::create_dir_all(&target_dir).expect("should create target directory");
        let result = Swarm::deterministic_dev(
            nonzero_ext::nonzero!(4u16),
            b"iroha-swarm-tests",
            false,
            IMAGE,
            None,
            false,
            &target_dir,
            None,
        );
        assert!(matches!(result, Err(crate::Error::TargetFileIsADirectory)));
    }
    #[test]
    fn rejects_override_count_mismatch() {
        let temp = TempDir::new("override_mismatch");
        let target_path = temp.path().join("compose.yml");
        let overrides = vec![PeerOverride {
            name: "solo".into(),
            p2p_port: 2100,
            api_port: 9100,
        }];
        let result = Swarm::deterministic_dev(
            nonzero_ext::nonzero!(4u16),
            b"iroha-swarm-tests",
            false,
            IMAGE,
            None,
            false,
            &target_path,
            Some(overrides),
        );
        assert!(matches!(
            result,
            Err(crate::Error::InvalidPeerOverrideCount {
                expected: 4,
                actual: 1
            })
        ));
    }
    #[test]
    fn deterministic_development_mode_rejects_non_committee_counts() {
        for count in [1_u16, 2, 3, 5, 32] {
            let result = Swarm::deterministic_dev(
                std::num::NonZeroU16::new(count).expect("fixture count is non-zero"),
                b"iroha-swarm-tests",
                false,
                IMAGE,
                None,
                false,
                std::path::Path::new(TARGET_PATH),
                None,
            );
            assert!(
                matches!(result, Err(crate::Error::InvalidPeerCount { actual }) if actual == count),
                "peer count {count} must be rejected"
            );
        }
    }
    #[test]
    fn deterministic_development_mode_rejects_empty_seed() {
        let result = Swarm::deterministic_dev(
            nonzero_ext::nonzero!(4u16),
            b"",
            false,
            IMAGE,
            None,
            false,
            std::path::Path::new(TARGET_PATH),
            None,
        );
        assert!(matches!(result, Err(crate::Error::EmptyDevelopmentSeed)));
    }
    #[test]
    fn deterministic_development_transport_keys_are_stable_unique_and_role_separated() {
        let first = peer::network(4, Some(b"iroha-swarm-transport-test"))
            .expect("derive deterministic network");
        let replay = peer::network(4, Some(b"iroha-swarm-transport-test"))
            .expect("rederive deterministic network");
        let mut transport_keys = std::collections::BTreeSet::new();
        for (index, peer_info) in &first {
            let replay_peer = replay.get(index).expect("replayed peer");
            let transport_private = peer_info
                .soranet_transport_key_pair
                .1
                .as_ref()
                .expect("development transport private key");
            let transport = iroha_crypto::KeyPair::new(
                peer_info.soranet_transport_key_pair.0.clone(),
                transport_private.0.clone(),
            )
            .expect("transport key pair must match");
            assert_eq!(transport.algorithm(), iroha_crypto::Algorithm::Ed25519);
            assert_ne!(peer_info.soranet_transport_key_pair.0, peer_info.key_pair.0);
            assert_eq!(
                peer_info.soranet_transport_key_pair.0,
                replay_peer.soranet_transport_key_pair.0
            );
            assert!(transport_keys.insert(peer_info.soranet_transport_key_pair.0.clone()));
        }
    }
    #[test]
    fn deterministic_development_streaming_identities_are_stable_unique_and_role_separated() {
        let first = peer::network(7, Some(b"iroha-swarm-streaming-test"))
            .expect("derive deterministic network");
        let replay = peer::network(7, Some(b"iroha-swarm-streaming-test"))
            .expect("rederive deterministic network");
        let other_identities = first
            .values()
            .flat_map(|peer_info| {
                [
                    peer_info.key_pair.0.clone(),
                    peer_info.soranet_transport_key_pair.0.clone(),
                ]
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut streaming_keys = std::collections::BTreeSet::new();
        for (index, peer_info) in &first {
            let (public_key, private_key) = peer_info
                .streaming_identity_key_pair
                .as_ref()
                .expect("development validators carry a streaming identity");
            let streaming = iroha_crypto::KeyPair::new(
                public_key.clone(),
                private_key
                    .as_ref()
                    .expect("development streaming private key")
                    .0
                    .clone(),
            )
            .expect("streaming key pair must match");
            assert_eq!(streaming.algorithm(), iroha_crypto::Algorithm::Ed25519);
            assert!(
                !other_identities.contains(public_key),
                "peer {index} streaming identity reuses a validator or SoraNet transport key"
            );
            assert_eq!(
                Some(public_key),
                replay
                    .get(index)
                    .and_then(|peer_info| peer_info.streaming_identity_key_pair.as_ref())
                    .map(|(public_key, _)| public_key),
                "peer {index} streaming identity must be reproducible from the seed"
            );
            assert!(streaming_keys.insert(public_key.clone()));
        }
    }
    #[test]
    fn deterministic_development_compose_renders_one_streaming_identity_per_validator() {
        let temp = TempDir::new("streaming_identity_overrides");
        let target_path = temp.path().join("docker-compose.yml");
        let default_output = build_as_string(nonzero_ext::nonzero!(7u16), false, None, false, None);
        let override_output = build_with_paths(
            nonzero_ext::nonzero!(4u16),
            false,
            None,
            false,
            None,
            ComposePaths {
                target_path: &target_path,
                peer_overrides: Some(valid_peer_overrides()),
            },
        );
        for (output, peer_count) in [(default_output, 7), (override_output, 4)] {
            for key in [
                "STREAMING_IDENTITY_PUBLIC_KEY: ",
                "STREAMING_IDENTITY_PRIVATE_KEY: ",
            ] {
                assert_eq!(
                    output.matches(key).count(),
                    peer_count,
                    "every development validator must render {key}: {output}"
                );
            }
        }
    }
    #[test]
    fn prepared_mode_rejects_non_committee_validator_count() {
        let result = Swarm::from_prepared(
            peer::chain(),
            vec![prepared_validator(0), prepared_validator(1)],
            PreparedGenesisArtifacts {
                signed_block: std::path::Path::new("genesis.signed.nrt"),
                public_key: std::path::Path::new("genesis.public_key"),
                expected_hash: std::path::Path::new("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            std::path::Path::new(TARGET_PATH),
        );
        assert!(matches!(
            result,
            Err(crate::Error::InvalidPeerCount { actual: 2 })
        ));
    }
    #[test]
    fn prepared_mode_rejects_wrong_algorithm_and_duplicate_transport_identities() {
        let mut wrong_algorithm = (0_u16..4).map(prepared_validator).collect::<Vec<_>>();
        wrong_algorithm[0].soranet_transport_public_key =
            wrong_algorithm[0].key_pair.public_key().clone();
        let result = Swarm::from_prepared(
            peer::chain(),
            wrong_algorithm,
            PreparedGenesisArtifacts {
                signed_block: std::path::Path::new("genesis.signed.nrt"),
                public_key: std::path::Path::new("genesis.public_key"),
                expected_hash: std::path::Path::new("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            std::path::Path::new(TARGET_PATH),
        );
        assert!(matches!(
            result,
            Err(crate::Error::InvalidPreparedTransportIdentity { index: 0, .. })
        ));
        let mut duplicate = (0_u16..4).map(prepared_validator).collect::<Vec<_>>();
        duplicate[1].soranet_transport_public_key =
            duplicate[0].soranet_transport_public_key.clone();
        let result = Swarm::from_prepared(
            peer::chain(),
            duplicate,
            PreparedGenesisArtifacts {
                signed_block: std::path::Path::new("genesis.signed.nrt"),
                public_key: std::path::Path::new("genesis.public_key"),
                expected_hash: std::path::Path::new("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            std::path::Path::new(TARGET_PATH),
        );
        assert!(matches!(
            result,
            Err(crate::Error::DuplicatePreparedTransportIdentity { index: 1 })
        ));
    }
    #[test]
    fn prepared_mode_rejects_non_normalized_runtime_targets() {
        let temp = TempDir::new("prepared_runtime_target");
        let bundle = temp.path().join("bundle");
        let deployment = temp.path().join("deployment");
        std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
        std::fs::create_dir_all(&deployment).expect("create deployment directory");
        let mut validators = (0_u16..4)
            .map(|index| {
                let mut validator = prepared_validator(index);
                validator.runtime_config_path = bundle.join(format!("peer{index}.runtime.toml"));
                validator
            })
            .collect::<Vec<_>>();
        validators[0].runtime_files.push(PreparedRuntimeFile {
            target: "/config/runtime/../peer.toml".to_owned(),
            content: b"invalid".to_vec(),
        });
        let result = Swarm::from_prepared(
            peer::chain(),
            validators,
            PreparedGenesisArtifacts {
                signed_block: &bundle.join("genesis.signed.nrt"),
                public_key: &bundle.join("genesis.public_key"),
                expected_hash: &bundle.join("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            &deployment.join("docker-compose.yml"),
        );
        assert!(matches!(
            result,
            Err(crate::Error::InvalidPreparedRuntimeTarget {
                index: 0,
                target
            }) if target == "/config/runtime/../peer.toml"
        ));
    }
    #[test]
    fn prepared_mode_rejects_duplicate_runtime_targets() {
        let temp = TempDir::new("prepared_runtime_duplicate");
        let bundle = temp.path().join("bundle");
        let deployment = temp.path().join("deployment");
        std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
        std::fs::create_dir_all(&deployment).expect("create deployment directory");
        let mut validators = (0_u16..4)
            .map(|index| {
                let mut validator = prepared_validator(index);
                validator.runtime_config_path = bundle.join(format!("peer{index}.runtime.toml"));
                validator
            })
            .collect::<Vec<_>>();
        validators[0].runtime_files.extend([
            PreparedRuntimeFile {
                target: "/config/runtime/shared.toml".to_owned(),
                content: b"first".to_vec(),
            },
            PreparedRuntimeFile {
                target: "/config/runtime/shared.toml".to_owned(),
                content: b"second".to_vec(),
            },
        ]);
        let result = Swarm::from_prepared(
            peer::chain(),
            validators,
            PreparedGenesisArtifacts {
                signed_block: &bundle.join("genesis.signed.nrt"),
                public_key: &bundle.join("genesis.public_key"),
                expected_hash: &bundle.join("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            &deployment.join("docker-compose.yml"),
        );
        assert!(matches!(
            result,
            Err(crate::Error::DuplicatePreparedRuntimeTarget {
                index: 0,
                target
            }) if target == "/config/runtime/shared.toml"
        ));
    }
    #[test]
    fn prepared_mode_rejects_ancestor_overlapping_runtime_targets_in_either_order() {
        for (case, targets) in [
            (
                "parent_first",
                [
                    "/config/runtime/policy",
                    "/config/runtime/policy/admission.nrt",
                ],
            ),
            (
                "child_first",
                [
                    "/config/runtime/policy/admission.nrt",
                    "/config/runtime/policy",
                ],
            ),
        ] {
            let temp = TempDir::new(case);
            let bundle = temp.path().join("bundle");
            let deployment = temp.path().join("deployment");
            std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
            std::fs::create_dir_all(&deployment).expect("create deployment directory");
            let mut validators = (0_u16..4)
                .map(|index| {
                    let mut validator = prepared_validator(index);
                    validator.runtime_config_path =
                        bundle.join(format!("peer{index}.runtime.toml"));
                    validator
                })
                .collect::<Vec<_>>();
            validators[0]
                .runtime_files
                .extend(targets.map(|target| PreparedRuntimeFile {
                    target: target.to_owned(),
                    content: target.as_bytes().to_vec(),
                }));
            let result = Swarm::from_prepared(
                peer::chain(),
                validators,
                PreparedGenesisArtifacts {
                    signed_block: &bundle.join("genesis.signed.nrt"),
                    public_key: &bundle.join("genesis.public_key"),
                    expected_hash: &bundle.join("genesis.expected_hash"),
                },
                false,
                IMAGE,
                None,
                false,
                &deployment.join("docker-compose.yml"),
            );
            assert!(
                matches!(
                    result,
                    Err(crate::Error::OverlappingPreparedRuntimeTarget {
                        index: 0,
                        target,
                        other,
                    }) if (target == "/config/runtime/policy"
                        && other == "/config/runtime/policy/admission.nrt")
                        || (target == "/config/runtime/policy/admission.nrt"
                            && other == "/config/runtime/policy")
                ),
                "{case} must reject an ancestor/descendant target pair"
            );
        }
    }
    #[test]
    fn prepared_mode_rejects_invalid_and_reserved_secret_targets() {
        for target in [
            "/config/runtime/private.key",
            "/run/secrets/nested/private.key",
            "/run/secrets/.",
            "/run/secrets/..",
            "/run/secrets/private$key",
            "/run/secrets/iroha_runtime_deadbeef.b64",
            "/run/secrets/iroha_genesis_public_key",
            "/run/secrets/iroha_genesis_expected_hash",
        ] {
            let temp = TempDir::new("prepared_secret_target");
            let bundle = temp.path().join("bundle");
            let deployment = temp.path().join("deployment");
            std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
            std::fs::create_dir_all(&deployment).expect("create deployment directory");
            let mut validators = (0_u16..4)
                .map(|index| {
                    let mut validator = prepared_validator(index);
                    validator.runtime_config_path =
                        bundle.join(format!("peer{index}.runtime.toml"));
                    validator
                })
                .collect::<Vec<_>>();
            validators[0].secret_files.push(PreparedSecretFile {
                target: target.to_owned(),
                source_path: bundle.join("private.key"),
            });
            let result = Swarm::from_prepared(
                peer::chain(),
                validators,
                PreparedGenesisArtifacts {
                    signed_block: &bundle.join("genesis.signed.nrt"),
                    public_key: &bundle.join("genesis.public_key"),
                    expected_hash: &bundle.join("genesis.expected_hash"),
                },
                false,
                IMAGE,
                None,
                false,
                &deployment.join("docker-compose.yml"),
            );
            assert!(
                matches!(
                    result,
                    Err(crate::Error::InvalidPreparedSecretTarget {
                        index: 0,
                        target: rejected,
                    }) if rejected == target
                ),
                "secret target {target} must be rejected"
            );
        }
    }
    #[test]
    fn prepared_mode_rejects_duplicate_secret_targets() {
        let temp = TempDir::new("prepared_secret_duplicate");
        let bundle = temp.path().join("bundle");
        let deployment = temp.path().join("deployment");
        std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
        std::fs::create_dir_all(&deployment).expect("create deployment directory");
        let mut validators = (0_u16..4)
            .map(|index| {
                let mut validator = prepared_validator(index);
                validator.runtime_config_path = bundle.join(format!("peer{index}.runtime.toml"));
                validator
            })
            .collect::<Vec<_>>();
        let target = "/run/secrets/iroha_peer0_private_key";
        validators[0].secret_files.extend([
            PreparedSecretFile {
                target: target.to_owned(),
                source_path: bundle.join("first.private"),
            },
            PreparedSecretFile {
                target: target.to_owned(),
                source_path: bundle.join("second.private"),
            },
        ]);
        let result = Swarm::from_prepared(
            peer::chain(),
            validators,
            PreparedGenesisArtifacts {
                signed_block: &bundle.join("genesis.signed.nrt"),
                public_key: &bundle.join("genesis.public_key"),
                expected_hash: &bundle.join("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            &deployment.join("docker-compose.yml"),
        );
        assert!(matches!(
            result,
            Err(crate::Error::DuplicatePreparedSecretTarget {
                index: 0,
                target: rejected,
            }) if rejected == target
        ));
    }
    #[test]
    fn prepared_mode_mounts_secret_sources_without_leaking_contents() {
        let temp = TempDir::new("prepared_secret_mount");
        let bundle = temp.path().join("bundle");
        let deployment = temp.path().join("deployment");
        std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
        std::fs::create_dir_all(&deployment).expect("create deployment directory");
        let secret_source = bundle.join("peer0.private");
        let secret_content = "secret-material-that-must-not-enter-compose";
        std::fs::write(&secret_source, secret_content).expect("write private runtime input");
        let mut validators = (0_u16..4)
            .map(|index| {
                let mut validator = prepared_validator(index);
                validator.runtime_config_path = bundle.join(format!("peer{index}.runtime.toml"));
                validator
            })
            .collect::<Vec<_>>();
        validators[0].secret_files.push(PreparedSecretFile {
            target: "/run/secrets/iroha_peer0_private_key".to_owned(),
            source_path: secret_source,
        });
        let swarm = Swarm::from_prepared(
            peer::chain(),
            validators,
            PreparedGenesisArtifacts {
                signed_block: &bundle.join("genesis.signed.nrt"),
                public_key: &bundle.join("genesis.public_key"),
                expected_hash: &bundle.join("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            &deployment.join("docker-compose.yml"),
        )
        .expect("build prepared swarm");
        let mut output = Vec::new();
        swarm
            .build()
            .write(&mut output, None)
            .expect("render prepared swarm");
        let output = String::from_utf8(output).expect("Compose output is UTF-8");
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == "irohad0_runtime_secret_0:")
                .count(),
            1,
            "the host secret source must have one top-level declaration"
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == "source: irohad0_runtime_secret_0")
                .count(),
            1,
            "only peer 0 must mount its private runtime input"
        );
        assert!(output.contains("file: ../bundle/peer0.private"));
        assert!(output.contains("target: /run/secrets/iroha_peer0_private_key"));
        assert!(
            !output.contains(secret_content),
            "Compose must reference the owner-protected source file, never inline its bytes"
        );
    }
    #[test]
    fn prepared_mode_interns_equal_runtime_content_and_deduplicates_service_mounts() {
        let temp = TempDir::new("prepared_runtime_interning");
        let bundle = temp.path().join("bundle");
        let deployment = temp.path().join("deployment");
        std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
        std::fs::create_dir_all(&deployment).expect("create deployment directory");
        let shared_content = b"\0shared binary runtime policy\xff".to_vec();
        let mut validators = (0_u16..4)
            .map(|index| {
                let mut validator = prepared_validator(index);
                validator.runtime_config_path = bundle.join(format!("peer{index}.runtime.toml"));
                validator.runtime_files.push(PreparedRuntimeFile {
                    target: format!("/config/runtime/peer{index}/shared.nrt"),
                    content: shared_content.clone(),
                });
                validator
            })
            .collect::<Vec<_>>();
        validators[0].runtime_files.push(PreparedRuntimeFile {
            target: "/config/runtime/peer0/second-copy.nrt".to_owned(),
            content: shared_content.clone(),
        });
        let swarm = Swarm::from_prepared(
            peer::chain(),
            validators,
            PreparedGenesisArtifacts {
                signed_block: &bundle.join("genesis.signed.nrt"),
                public_key: &bundle.join("genesis.public_key"),
                expected_hash: &bundle.join("genesis.expected_hash"),
            },
            false,
            IMAGE,
            None,
            false,
            &deployment.join("docker-compose.yml"),
        )
        .expect("build prepared swarm");
        let mut output = Vec::new();
        swarm
            .build()
            .write(&mut output, None)
            .expect("render prepared swarm");
        let output = String::from_utf8(output).expect("Compose output is UTF-8");
        let digest = iroha_crypto::Hash::new(&shared_content);
        let config_name = format!("runtime_file_{digest}");
        let encoded_target = format!("/run/secrets/iroha_runtime_{digest}.b64");
        let config_declaration = format!("{config_name}:");
        let config_source = format!("source: {config_name}");
        let encoded_mount_target = format!("target: {encoded_target}");
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == config_declaration.as_str())
                .count(),
            1,
            "equal byte content must have one top-level Compose config"
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == config_source.as_str())
                .count(),
            4,
            "each service must mount the shared content exactly once"
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.trim() == encoded_mount_target.as_str())
                .count(),
            4,
            "each service must use one digest-addressed encoded mount"
        );
        assert_eq!(
            output
                .matches(&base64_standard::encode(&shared_content))
                .count(),
            1,
            "the binary bytes must be encoded once at the top level"
        );
        assert!(output.contains("/config/runtime/peer0/shared.nrt"));
        assert!(output.contains("/config/runtime/peer0/second-copy.nrt"));
    }
    #[test]
    fn prepared_mode_uses_concrete_read_only_genesis_artifacts() {
        const AUTHORED_SYNC_MAX_BYTES: u32 = 555_555_555;
        let temp = TempDir::new("prepared_artifacts");
        let bundle = temp.path().join("bundle");
        let deployment = temp.path().join("deployment");
        std::fs::create_dir_all(&bundle).expect("create prepared bundle directory");
        std::fs::create_dir_all(&deployment).expect("create deployment directory");
        let signed_block = bundle.join("genesis.signed.nrt");
        let public_key = bundle.join("genesis.public_key");
        let expected_hash = bundle.join("genesis.expected_hash");
        std::fs::write(&signed_block, b"signed").expect("write signed fixture");
        std::fs::write(&public_key, b"public\n").expect("write public fixture");
        std::fs::write(
            &expected_hash,
            format!("{}\n", iroha_crypto::Hash::new(b"genesis")),
        )
        .expect("write hash fixture");
        let target = deployment.join("docker-compose.yml");
        let validators = (0_u16..4)
            .map(|index| {
                let runtime_config = bundle.join(format!("peer{index}.runtime.toml"));
                std::fs::write(
                    &runtime_config,
                    format!(
                        "chain = \"prepared\"\n# container projection for peer {index}\n\
                         [sumeragi]\n\
                         sync_max_bytes = {AUTHORED_SYNC_MAX_BYTES}\n"
                    ),
                )
                .expect("write projected runtime config fixture");
                let mut validator = prepared_validator(index);
                validator.runtime_config_path = runtime_config;
                validator.runtime_files.push(PreparedRuntimeFile {
                    target: "/config/runtime/rans_seed0.toml".to_owned(),
                    content: b"# prepared shared rANS fixture\n".to_vec(),
                });
                let runtime_secret = bundle.join(format!("peer{index}.faucet.key"));
                std::fs::write(&runtime_secret, format!("private-{index}\n"))
                    .expect("write runtime secret fixture");
                validator.secret_files.push(PreparedSecretFile {
                    target: format!("/run/secrets/iroha_peer{index}_faucet_private_key"),
                    source_path: runtime_secret,
                });
                validator
            })
            .collect();
        let swarm = Swarm::from_prepared(
            peer::chain(),
            validators,
            PreparedGenesisArtifacts {
                signed_block: &signed_block,
                public_key: &public_key,
                expected_hash: &expected_hash,
            },
            false,
            IMAGE,
            None,
            false,
            &target,
        )
        .expect("build prepared swarm");
        let mut output = Vec::new();
        swarm
            .build()
            .write(&mut output, None)
            .expect("render prepared swarm");
        let output = String::from_utf8(output).expect("Compose output is UTF-8");
        for artifact in [
            "../bundle/genesis.signed.nrt",
            "../bundle/genesis.public_key",
            "../bundle/genesis.expected_hash",
        ] {
            assert!(output.contains(artifact), "missing {artifact}: {output}");
        }
        assert!(!output.contains("${IROHA_GENESIS_"));
        assert_eq!(output.matches("read_only: true").count(), 4);
        assert_eq!(output.matches("--config /config/peer.toml").count(), 4);
        assert_eq!(output.matches("exec env -i").count(), 4);
        assert_eq!(output.matches("--config-blake3 ").count(), 4);
        assert_eq!(output.matches("target: /config/peer.toml").count(), 4);
        assert!(!output.contains("iroha_kagemusha_load"));
        assert_eq!(output.matches("create_host_path: false").count(), 0);
        assert_eq!(output.matches("require_private_file").count(), 8);
        assert_eq!(output.matches("target: /run/secrets/iroha_peer").count(), 4);
        assert!(output.contains("../bundle/peer0.faucet.key"));
        assert!(!output.contains("private-0"));
        assert_eq!(
            output
                .matches(&format!(
                    "target: /run/secrets/iroha_runtime_{}.b64",
                    iroha_crypto::Hash::new(b"# prepared shared rANS fixture\n")
                ))
                .count(),
            4
        );
        assert!(!output.contains("environment:"));
        assert!(!output.contains("PRIVATE_KEY:"));
        assert!(
            !output.contains("STREAMING_IDENTITY_"),
            "prepared validators keep their streaming identity in the admitted runtime config"
        );
        assert!(
            std::fs::read_to_string(bundle.join("peer0.runtime.toml"))
                .expect("read authored runtime config")
                .contains(&format!("sync_max_bytes = {AUTHORED_SYNC_MAX_BYTES}")),
            "building Compose must not rewrite the authored prepared runtime settings"
        );
        assert!(output.contains("../bundle/peer0.runtime.toml"));
        assert!(!output.contains("container projection for peer 0"));
        assert_eq!(
            output
                .matches(&base64_standard::encode(
                    b"# prepared shared rANS fixture\n",
                ))
                .count(),
            1,
            "equal public runtime bytes must be interned once"
        );
    }
}
