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
    topology: std::collections::BTreeSet<iroha_data_model::peer::Peer>,
}

impl PeerSettings {
    fn new(
        count: std::num::NonZeroU16,
        seed: Option<&[u8]>,
        healthcheck: bool,
        config_dir: &std::path::Path,
        target_dir: &path::AbsolutePath,
    ) -> Result<Self, Error> {
        let network = peer::network(count.get(), seed);
        let topology = peer::topology(network.values());
        Ok(Self {
            healthcheck,
            config_dir: path::AbsolutePath::new(config_dir)?.relative_to(target_dir)?,
            chain: peer::chain(),
            genesis_key_pair: peer::generate_key_pair(seed, GENESIS_SEED),
            network,
            topology,
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
    #![allow(clippy::too_many_lines, clippy::needless_raw_string_hashes)]

    use crate::Swarm;

    const IMAGE: &str = "hyperledger/iroha:dev";
    const PEER_CONFIG_PATH: &str = "./defaults";
    const TARGET_PATH: &str = "./defaults/docker-compose.yml";

    fn build_as_string(
        count: std::num::NonZeroU16,
        healthcheck: bool,
        build_dir: Option<&str>,
        ignore_cache: bool,
        banner: Option<&[&str]>,
    ) -> String {
        let mut buffer = Vec::new();
        Swarm::new(
            count,
            Some(&[]),
            healthcheck,
            PEER_CONFIG_PATH.as_ref(),
            IMAGE,
            build_dir.map(str::as_ref),
            ignore_cache,
            TARGET_PATH.as_ref(),
        )
        .unwrap()
        .build()
        .write(&mut buffer, banner)
        .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn single_build_banner() {
        expect_test::expect!([r##"
            # Single-line banner

            services:
              irohad0:
                image: hyperledger/iroha:dev
                build: ..
                pull_policy: never
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA
                  PRIVATE_KEY: 802620F173D8C4913E2244715B9BF810AC0A4DBE1C9E08F595C8D9510E3E335EF964BB
                  P2P_PUBLIC_ADDRESS: irohad0:1337
                  P2P_ADDRESS: 0.0.0.0:1337
                  API_ADDRESS: 0.0.0.0:8080
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  GENESIS_PRIVATE_KEY: 802620FB8B867188E4952F1E83534B9B2E0A12D5122BD6F417CBC79D50D8A8C9C917B0
                  GENESIS: /tmp/genesis.signed.scale
                  TOPOLOGY: '["ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA"]'
                ports:
                - 1337:1337
                - 8080:8080
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                command: |-
                  /bin/sh -c "
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
                  "
        "##]).assert_eq(&build_as_string(
            nonzero_ext::nonzero!(1u16),
            false,
            Some("."),
            false,
            Some(&["Single-line banner"]),
        ));
    }

    #[test]
    fn single_build_banner_nocache() {
        expect_test::expect!([r##"
            # Multi-line banner 1
            # Multi-line banner 2

            services:
              irohad0:
                image: hyperledger/iroha:dev
                build: ..
                pull_policy: build
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA
                  PRIVATE_KEY: 802620F173D8C4913E2244715B9BF810AC0A4DBE1C9E08F595C8D9510E3E335EF964BB
                  P2P_PUBLIC_ADDRESS: irohad0:1337
                  P2P_ADDRESS: 0.0.0.0:1337
                  API_ADDRESS: 0.0.0.0:8080
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  GENESIS_PRIVATE_KEY: 802620FB8B867188E4952F1E83534B9B2E0A12D5122BD6F417CBC79D50D8A8C9C917B0
                  GENESIS: /tmp/genesis.signed.scale
                  TOPOLOGY: '["ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA"]'
                ports:
                - 1337:1337
                - 8080:8080
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                command: |-
                  /bin/sh -c "
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
                  "
        "##]).assert_eq(&build_as_string(
            nonzero_ext::nonzero!(1u16),
            false,
            Some("."),
            true,
            Some(&["Multi-line banner 1", "Multi-line banner 2"]),
        ));
    }

    #[test]
    fn multiple_build_banner_nocache() {
        expect_test::expect!([r##"
            # Single-line banner

            services:
              irohad0:
                image: hyperledger/iroha:dev
                build: ..
                pull_policy: build
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA
                  PRIVATE_KEY: 802620F173D8C4913E2244715B9BF810AC0A4DBE1C9E08F595C8D9510E3E335EF964BB
                  P2P_PUBLIC_ADDRESS: irohad0:1337
                  P2P_ADDRESS: 0.0.0.0:1337
                  API_ADDRESS: 0.0.0.0:8080
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26@irohad3:1340","ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2@irohad1:1338","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300@irohad2:1339"]'
                  GENESIS_PRIVATE_KEY: 802620FB8B867188E4952F1E83534B9B2E0A12D5122BD6F417CBC79D50D8A8C9C917B0
                  GENESIS: /tmp/genesis.signed.scale
                  TOPOLOGY: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26","ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300"]'
                ports:
                - 1337:1337
                - 8080:8080
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                command: |-
                  /bin/sh -c "
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
                  "
              irohad1:
                depends_on:
                - irohad0
                image: hyperledger/iroha:dev
                pull_policy: never
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2
                  PRIVATE_KEY: 802620FD8E2F03755AA130464ABF57A75E207BE870636B57F614D7A7B94E42318F9CA9
                  P2P_PUBLIC_ADDRESS: irohad1:1338
                  P2P_ADDRESS: 0.0.0.0:1338
                  API_ADDRESS: 0.0.0.0:8081
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26@irohad3:1340","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA@irohad0:1337","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300@irohad2:1339"]'
                ports:
                - 1338:1338
                - 8081:8081
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
              irohad2:
                depends_on:
                - irohad0
                image: hyperledger/iroha:dev
                pull_policy: never
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300
                  PRIVATE_KEY: 8026203A18FAC2654F1C8A331A84F4B142396EEC900022B38842D88D55E0DE144C8DF2
                  P2P_PUBLIC_ADDRESS: irohad2:1339
                  P2P_ADDRESS: 0.0.0.0:1339
                  API_ADDRESS: 0.0.0.0:8082
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26@irohad3:1340","ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2@irohad1:1338","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA@irohad0:1337"]'
                ports:
                - 1339:1339
                - 8082:8082
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
              irohad3:
                depends_on:
                - irohad0
                image: hyperledger/iroha:dev
                pull_policy: never
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26
                  PRIVATE_KEY: 8026209464445DBA9030D6AC4F83161D3219144F886068027F6708AF9686F85DF6C4F0
                  P2P_PUBLIC_ADDRESS: irohad3:1340
                  P2P_ADDRESS: 0.0.0.0:1340
                  API_ADDRESS: 0.0.0.0:8083
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2@irohad1:1338","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA@irohad0:1337","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300@irohad2:1339"]'
                ports:
                - 1340:1340
                - 8083:8083
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
        "##]).assert_eq(&build_as_string(
            nonzero_ext::nonzero!(4u16),
            false,
            Some("."),
            true,
            Some(&["Single-line banner"]),
        ));
    }

    #[test]
    fn single_pull_healthcheck() {
        expect_test::expect!([r#"
            services:
              irohad0:
                image: hyperledger/iroha:dev
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA
                  PRIVATE_KEY: 802620F173D8C4913E2244715B9BF810AC0A4DBE1C9E08F595C8D9510E3E335EF964BB
                  P2P_PUBLIC_ADDRESS: irohad0:1337
                  P2P_ADDRESS: 0.0.0.0:1337
                  API_ADDRESS: 0.0.0.0:8080
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  GENESIS_PRIVATE_KEY: 802620FB8B867188E4952F1E83534B9B2E0A12D5122BD6F417CBC79D50D8A8C9C917B0
                  GENESIS: /tmp/genesis.signed.scale
                  TOPOLOGY: '["ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA"]'
                ports:
                - 1337:1337
                - 8080:8080
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                healthcheck:
                  test: test $(curl -s http://127.0.0.1:8080/status/blocks) -gt 0
                  interval: 2s
                  timeout: 1s
                  retries: 30
                  start_period: 4s
                command: |-
                  /bin/sh -c "
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
                  "
        "#]).assert_eq(&build_as_string(
            nonzero_ext::nonzero!(1u16),
            true,
            None,
            false,
            None,
        ));
    }

    #[test]
    fn multiple_pull_healthcheck_nocache() {
        expect_test::expect!([r#"
            services:
              irohad0:
                image: hyperledger/iroha:dev
                pull_policy: always
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA
                  PRIVATE_KEY: 802620F173D8C4913E2244715B9BF810AC0A4DBE1C9E08F595C8D9510E3E335EF964BB
                  P2P_PUBLIC_ADDRESS: irohad0:1337
                  P2P_ADDRESS: 0.0.0.0:1337
                  API_ADDRESS: 0.0.0.0:8080
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26@irohad3:1340","ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2@irohad1:1338","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300@irohad2:1339"]'
                  GENESIS_PRIVATE_KEY: 802620FB8B867188E4952F1E83534B9B2E0A12D5122BD6F417CBC79D50D8A8C9C917B0
                  GENESIS: /tmp/genesis.signed.scale
                  TOPOLOGY: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26","ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300"]'
                ports:
                - 1337:1337
                - 8080:8080
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                healthcheck:
                  test: test $(curl -s http://127.0.0.1:8080/status/blocks) -gt 0
                  interval: 2s
                  timeout: 1s
                  retries: 30
                  start_period: 4s
                command: |-
                  /bin/sh -c "
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
                  "
              irohad1:
                image: hyperledger/iroha:dev
                pull_policy: always
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2
                  PRIVATE_KEY: 802620FD8E2F03755AA130464ABF57A75E207BE870636B57F614D7A7B94E42318F9CA9
                  P2P_PUBLIC_ADDRESS: irohad1:1338
                  P2P_ADDRESS: 0.0.0.0:1338
                  API_ADDRESS: 0.0.0.0:8081
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26@irohad3:1340","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA@irohad0:1337","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300@irohad2:1339"]'
                ports:
                - 1338:1338
                - 8081:8081
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                healthcheck:
                  test: test $(curl -s http://127.0.0.1:8081/status/blocks) -gt 0
                  interval: 2s
                  timeout: 1s
                  retries: 30
                  start_period: 4s
              irohad2:
                image: hyperledger/iroha:dev
                pull_policy: always
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300
                  PRIVATE_KEY: 8026203A18FAC2654F1C8A331A84F4B142396EEC900022B38842D88D55E0DE144C8DF2
                  P2P_PUBLIC_ADDRESS: irohad2:1339
                  P2P_ADDRESS: 0.0.0.0:1339
                  API_ADDRESS: 0.0.0.0:8082
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26@irohad3:1340","ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2@irohad1:1338","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA@irohad0:1337"]'
                ports:
                - 1339:1339
                - 8082:8082
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                healthcheck:
                  test: test $(curl -s http://127.0.0.1:8082/status/blocks) -gt 0
                  interval: 2s
                  timeout: 1s
                  retries: 30
                  start_period: 4s
              irohad3:
                image: hyperledger/iroha:dev
                pull_policy: always
                environment:
                  CHAIN: 00000000-0000-0000-0000-000000000000
                  PUBLIC_KEY: ed012063ED3DFEDEBD8A86B4941CC4379D2EF0B74BDFE61F033FC0C89867D57C882A26
                  PRIVATE_KEY: 8026209464445DBA9030D6AC4F83161D3219144F886068027F6708AF9686F85DF6C4F0
                  P2P_PUBLIC_ADDRESS: irohad3:1340
                  P2P_ADDRESS: 0.0.0.0:1340
                  API_ADDRESS: 0.0.0.0:8083
                  GENESIS_PUBLIC_KEY: ed0120F9F92758E815121F637C9704DFDA54842BA937AA721C0603018E208D6E25787E
                  TRUSTED_PEERS: '["ed012064BD9B25BF8477144D03B26FC8CF5D8A354B2F780DA310EE69933DC1E86FBCE2@irohad1:1338","ed012087FDCACF58B891947600B0C37795CADB5A2AE6DE612338FDA9489AB21CE427BA@irohad0:1337","ed01208EA177921AF051CD12FC07E3416419320908883A1104B31401B650EEB820A300@irohad2:1339"]'
                ports:
                - 1340:1340
                - 8083:8083
                volumes:
                - ./genesis.json:/config/genesis.json:ro
                - ./client.toml:/config/client.toml:ro
                init: true
                healthcheck:
                  test: test $(curl -s http://127.0.0.1:8083/status/blocks) -gt 0
                  interval: 2s
                  timeout: 1s
                  retries: 30
                  start_period: 4s
        "#]).assert_eq(&build_as_string(
            nonzero_ext::nonzero!(4u16),
            true,
            None,
            true,
            None,
        ));
    }
}
