//! Docker Compose configuration generator for Iroha.

mod path;
mod peer;
mod schema;

const GENESIS_SEED: &[u8; 7] = b"genesis";
const CHAIN_ID: &str = "00000000-0000-0000-0000-000000000000";
const BASE_PORT_P2P: u16 = 1337;
const BASE_PORT_API: u16 = 8080;

/// Swarm error.
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Target file path points to a directory.
    TargetFileIsADirectory,
    /// Target directory not found.
    NoTargetDirectory,
    /// Failed to convert a path: {0}.
    PathConversion(path::Error),
}

impl std::error::Error for Error {}

/// Swarm settings.
pub struct Swarm<'a> {
    /// Peer settings.
    peer: PeerSettings,
    /// Docker image settings.
    image: ImageSettings<'a>,
    /// Absolute target path.
    target_path: path::AbsolutePath,
}

/// Iroha peer settings.
struct PeerSettings {
    /// If `true`, include a healthcheck for every service in the configuration.
    healthcheck: bool,
    /// Path to a directory with peer configuration relative to the target path.
    config_dir: path::RelativePath,
    chain: iroha_data_model::ChainId,
    genesis_key_pair: peer::ExposedKeyPair,
    network: std::collections::BTreeMap<u16, peer::PeerInfo>,
    trusted_peers: std::collections::BTreeSet<iroha_data_model::peer::PeerId>,
}

impl PeerSettings {
    fn new(
        count: std::num::NonZeroU16,
        seed: Option<&[u8]>,
        healthcheck: bool,
        config_dir: &std::path::Path,
        target_dir: &path::AbsolutePath,
    ) -> Result<Self, Error> {
        let network = peer::generate_peers(count.get(), seed);
        let trusted_peers = peer::get_trusted_peers(network.values());
        Ok(Self {
            healthcheck,
            config_dir: path::AbsolutePath::new(config_dir)?.relative_to(target_dir)?,
            chain: peer::chain(),
            genesis_key_pair: peer::generate_key_pair(seed, GENESIS_SEED),
            network,
            trusted_peers,
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
    /// Creates a new Swarm generator.
    #[allow(clippy::too_many_arguments, clippy::missing_errors_doc)]
    pub fn new(
        count: std::num::NonZeroU16,
        seed: Option<&'a [u8]>,
        healthcheck: bool,
        config_dir: &'a std::path::Path,
        image: &'a str,
        build_dir: Option<&'a std::path::Path>,
        ignore_cache: bool,
        target_path: &'a std::path::Path,
    ) -> Result<Self, Error> {
        if target_path.is_dir() {
            return Err(Error::TargetFileIsADirectory);
        }
        let target_path = path::AbsolutePath::new(target_path)?;
        let target_dir = target_path.parent().ok_or(Error::NoTargetDirectory)?;
        Ok(Self {
            peer: PeerSettings::new(count, seed, healthcheck, config_dir, &target_dir)?,
            image: ImageSettings::new(image, build_dir, ignore_cache, &target_dir)?,
            target_path,
        })
    }

    /// Builds the schema.
    #[allow(clippy::missing_errors_doc)]
    pub fn build(&self) -> schema::DockerCompose {
        schema::DockerCompose::new(&self.image, &self.peer)
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
    use crate::Swarm;

    const IMAGE: &str = "hyperledger/iroha:dev";
    const PEER_CONFIG_PATH: &str = "./configs/swarm";
    const TARGET_PATH: &str = "./configs/swarm/docker-compose.yml";

    // `serde_yaml` doesn't format YAML well – it's better to compare structurally.
    // Otherwise sample files will break tests on reformats.
    fn assert_yml_eq(expected: &str, actual: &str) {
        let expected: serde_yaml::Value =
            serde_yaml::from_str(expected).expect("should deserialize expected");
        let actual: serde_yaml::Value =
            serde_yaml::from_str(actual).expect("should deserialize actual");
        assert_eq!(expected, actual);
    }

    #[test]
    fn single_build_banner() {
        const EXPECTED: &str = include_str!("../samples/single-build-banner.yml");
        let mut buffer = Vec::new();
        Swarm::new(
            nonzero_ext::nonzero!(1u16),
            Some(&[]),
            false,
            PEER_CONFIG_PATH.as_ref(),
            IMAGE,
            Some(".".as_ref()),
            false,
            TARGET_PATH.as_ref(),
        )
        .unwrap()
        .build()
        .write(&mut buffer, Some(&["Single-line banner"]))
        .unwrap();
        let actual = std::str::from_utf8(&buffer).unwrap();
        assert_yml_eq(EXPECTED, actual);
    }

    #[test]
    fn single_build_banner_nocache() {
        const EXPECTED: &str = include_str!("../samples/single-build-banner-nocache.yml");
        let mut buffer = Vec::new();
        Swarm::new(
            nonzero_ext::nonzero!(1u16),
            Some(&[]),
            false,
            PEER_CONFIG_PATH.as_ref(),
            IMAGE,
            Some(".".as_ref()),
            true,
            TARGET_PATH.as_ref(),
        )
        .unwrap()
        .build()
        .write(
            &mut buffer,
            Some(&["Multi-line banner 1", "Multi-line banner 2"]),
        )
        .unwrap();
        let actual = std::str::from_utf8(&buffer).unwrap();
        assert_yml_eq(EXPECTED, actual);
    }

    #[test]
    fn single_pull_healthcheck() {
        const EXPECTED: &str = include_str!("../samples/single-pull-healthcheck.yml");
        let mut buffer = Vec::new();
        Swarm::new(
            nonzero_ext::nonzero!(1u16),
            Some(&[]),
            true,
            PEER_CONFIG_PATH.as_ref(),
            IMAGE,
            None,
            false,
            TARGET_PATH.as_ref(),
        )
        .unwrap()
        .build()
        .write(&mut buffer, None)
        .unwrap();
        let actual = std::str::from_utf8(&buffer).unwrap();
        assert_yml_eq(EXPECTED, actual);
    }

    #[test]
    fn multiple_pull_healthcheck_nocache() {
        const EXPECTED: &str = include_str!("../samples/multiple-pull-healthcheck-nocache.yml");
        let mut buffer = Vec::new();
        Swarm::new(
            nonzero_ext::nonzero!(4u16),
            Some(&[]),
            true,
            PEER_CONFIG_PATH.as_ref(),
            IMAGE,
            None,
            true,
            TARGET_PATH.as_ref(),
        )
        .unwrap()
        .build()
        .write(&mut buffer, None)
        .unwrap();
        let actual = std::str::from_utf8(&buffer).unwrap();
        assert_yml_eq(EXPECTED, actual);
    }
}
