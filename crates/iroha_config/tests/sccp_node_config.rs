//! Node-local SCCP configuration (`specs/sccp.md` §4.13.4): an empty file yields a working
//! `[sccp.keeper]` and `[sccp.light_client_keeper]`, and operator overrides are validated
//! syntactically.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use iroha_config::parameters::{
    actual::{self, Root as ActualConfig},
    defaults,
    user::Root as UserConfig,
};
use iroha_config_base::{env::MockEnv, read::ConfigReader, toml::TomlSource};

fn base_toml() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/base.toml")
}

fn base_reader() -> ConfigReader {
    ConfigReader::new()
        .without_env()
        .read_toml_with_extends(base_toml())
        .expect("base config should load")
}

fn load(extra: &str) -> Result<ActualConfig, String> {
    let table: toml::Table = extra.parse().expect("inline TOML should parse");
    base_reader()
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .map_err(|error| format!("{error:?}"))?
        .parse()
        .map_err(|error| format!("{error:?}"))
}

fn assert_rejected(extra: &str, needle: &str) {
    let error = load(extra).expect_err(extra);
    assert!(
        error.contains("Invalid SCCP node configuration"),
        "wrong error kind for {extra}: {error}"
    );
    assert!(
        error.contains(needle),
        "missing `{needle}` for {extra}: {error}"
    );
}

fn urls(list: &[url::Url]) -> Vec<&str> {
    list.iter().map(url::Url::as_str).collect()
}

#[test]
fn empty_config_yields_every_default_with_key_dir_under_kura_store_dir() {
    let config = load("").expect("an empty SCCP configuration is valid");
    let keeper = &config.sccp.keeper;
    assert!(keeper.enabled);
    assert_eq!(
        keeper.key_dir_path(),
        config
            .kura
            .store_dir
            .resolve_relative_path()
            .join("sccp")
            .join("keeper-key")
    );
    assert!(keeper.keepalive);
    assert_eq!(keeper.keepalive_stagger, Duration::from_millis(15_000));
    assert!(keeper.watch);

    let keeper = &config.sccp.light_client_keeper;
    assert!(keeper.enabled);
    assert_eq!(keeper.advance_after, None);
    assert_eq!(
        keeper.advance_after_for(1_209_600_000),
        Duration::from_millis(302_400_000)
    );
    assert_eq!(keeper.poll_interval, Duration::from_millis(60_000));
    assert_eq!(keeper.request_timeout, Duration::from_millis(10_000));
    assert_eq!(keeper.poll_budget, Duration::from_millis(120_000));
    assert_eq!(keeper.max_advance_bytes.get(), 262_144);
    assert!(keeper.secret_headers.is_empty());
    let endpoints = &keeper.endpoints;
    assert_eq!(
        endpoints,
        &actual::SccpLightClientKeeperEndpoints::compiled_defaults()
    );
    for (list, compiled) in [
        (
            &endpoints.ethereum_execution,
            defaults::sccp::endpoints::ETHEREUM_EXECUTION,
        ),
        (
            &endpoints.ethereum_beacon,
            defaults::sccp::endpoints::ETHEREUM_BEACON,
        ),
        (&endpoints.bsc, defaults::sccp::endpoints::BSC),
    ] {
        assert!(!list.is_empty());
        assert_eq!(list, &actual::compiled_http_endpoints(compiled));
    }
    assert_eq!(
        endpoints.ton_liteservers.len(),
        defaults::sccp::endpoints::TON_LITESERVERS.len()
    );
}

#[test]
fn default_key_dir_follows_kura_store_dir() {
    let config = load("[kura]\nstore_dir = \"/var/lib/iroha-sccp-test\"\n").expect("valid");
    assert_eq!(
        config.sccp.keeper.key_dir_path(),
        PathBuf::from("/var/lib/iroha-sccp-test/sccp/keeper-key")
    );
}

#[test]
fn explicit_key_dir_overrides_the_derived_default() {
    let config = load(
        "[kura]\nstore_dir = \"/var/lib/iroha-sccp-test\"\n\
         [sccp.keeper]\nkey_dir = \"/opt/iroha/keeper-key\"\n",
    )
    .expect("valid");
    assert_eq!(
        config.sccp.keeper.key_dir_path(),
        PathBuf::from("/opt/iroha/keeper-key")
    );
}

#[test]
fn explicit_keeper_values_are_kept() {
    let config = load(
        "[sccp.keeper]\n\
         enabled = false\n\
         keepalive = false\n\
         keepalive_stagger_ms = 2500\n\
         watch = false\n\
         [sccp.light_client_keeper]\n\
         enabled = false\n\
         advance_after_ms = 3600000\n\
         poll_interval_ms = 5000\n\
         request_timeout_ms = 2500\n\
         poll_budget_ms = 30000\n\
         max_advance_bytes = 65536\n",
    )
    .expect("valid");
    let keeper = &config.sccp.keeper;
    assert!(!keeper.enabled);
    assert!(!keeper.keepalive);
    assert_eq!(keeper.keepalive_stagger, Duration::from_millis(2_500));
    assert!(!keeper.watch);
    let keeper = &config.sccp.light_client_keeper;
    assert!(!keeper.enabled);
    assert_eq!(keeper.advance_after, Some(Duration::from_secs(3_600)));
    assert_eq!(keeper.advance_after_for(1), Duration::from_secs(3_600));
    assert_eq!(keeper.poll_interval, Duration::from_secs(5));
    assert_eq!(keeper.request_timeout, Duration::from_millis(2_500));
    assert_eq!(keeper.poll_budget, Duration::from_secs(30));
    assert_eq!(keeper.max_advance_bytes.get(), 65_536);
}

#[test]
fn endpoint_override_replaces_only_that_default_list() {
    let config = load(
        "[sccp.light_client_keeper.endpoints]\n\
         ethereum_execution = [\"https://eth.example.org/rpc\", \"http://localhost:8545\"]\n\
         ton_liteservers = [\"127.0.0.1:4924:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=\"]\n",
    )
    .expect("valid");
    let endpoints = &config.sccp.light_client_keeper.endpoints;
    assert_eq!(
        urls(&endpoints.ethereum_execution),
        ["https://eth.example.org/rpc", "http://localhost:8545/"]
    );
    assert_eq!(endpoints.ton_liteservers.len(), 1);
    assert_eq!(
        endpoints.ton_liteservers[0].to_string(),
        "127.0.0.1:4924:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk="
    );
    let compiled = actual::SccpLightClientKeeperEndpoints::compiled_defaults();
    assert_eq!(endpoints.ethereum_beacon, compiled.ethereum_beacon);
    assert_eq!(endpoints.bsc, compiled.bsc);
}

#[test]
fn invalid_endpoint_urls_are_rejected() {
    assert_rejected(
        "[sccp.light_client_keeper.endpoints]\nbsc = [\"http://bsc.example.org\"]\n",
        "endpoints.bsc[0]: an endpoint URL must use https",
    );
    assert_rejected(
        "[sccp.light_client_keeper.endpoints]\nethereum_execution = [\"not a url\"]\n",
        "endpoints.ethereum_execution[0]: invalid endpoint URL",
    );
    assert_rejected(
        "[sccp.light_client_keeper.endpoints]\n\
         ethereum_beacon = [\"https://key:secret@beacon.example.org\"]\n",
        "endpoints.ethereum_beacon[0]: an endpoint URL must not embed credentials",
    );
    assert_rejected(
        "[sccp.light_client_keeper.endpoints]\n\
         ethereum_execution = [\"https://a.example.org\", \"https://a.example.org/\"]\n",
        "endpoints.ethereum_execution[1] duplicates an earlier entry",
    );
}

#[test]
fn invalid_liteserver_entries_are_rejected() {
    for (entry, needle) in [
        ("1.2.3.4:4924", "a TON liteserver must be"),
        (
            "84478511:4924:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "dotted IPv4 address",
        ),
        (
            "1.2.3.4:0:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "a TON liteserver port",
        ),
        ("1.2.3.4:4924:not-base64", "a TON liteserver key"),
    ] {
        assert_rejected(
            &format!("[sccp.light_client_keeper.endpoints]\nton_liteservers = [\"{entry}\"]\n"),
            needle,
        );
    }
}

#[test]
fn zero_intervals_and_bounds_are_rejected() {
    assert_rejected(
        "[sccp.light_client_keeper]\npoll_interval_ms = 0\n",
        "sccp.light_client_keeper.poll_interval_ms must be nonzero",
    );
    assert_rejected(
        "[sccp.light_client_keeper]\nrequest_timeout_ms = 0\n",
        "sccp.light_client_keeper.request_timeout_ms must be nonzero",
    );
    assert_rejected(
        "[sccp.light_client_keeper]\npoll_budget_ms = 0\n",
        "sccp.light_client_keeper.poll_budget_ms must be nonzero",
    );
    assert_rejected(
        "[sccp.light_client_keeper]\nmax_advance_bytes = 0\n",
        "sccp.light_client_keeper.max_advance_bytes must be nonzero",
    );
    assert_rejected(
        "[sccp.keeper]\nkeepalive_stagger_ms = 0\n",
        "sccp.keeper.keepalive_stagger_ms must be nonzero",
    );
}

#[test]
fn secret_header_entries_parse() {
    let config = load(
        "[[sccp.light_client_keeper.secret_headers]]\n\
         endpoint = \"https://eth.example.org/rpc\"\n\
         header = \"X-Api-Key\"\n\
         value_file = \"/etc/iroha/eth-api-key\"\n\
         [[sccp.light_client_keeper.secret_headers]]\n\
         endpoint = \"https://eth.example.org/rpc\"\n\
         header = \"authorization\"\n\
         value_file = \"/etc/iroha/eth-bearer\"\n",
    )
    .expect("valid");
    let keeper = &config.sccp.light_client_keeper;
    let endpoint = actual::parse_sccp_http_endpoint("https://eth.example.org/rpc").expect("url");
    let headers: Vec<_> = keeper
        .secret_headers
        .iter()
        .filter(|header| header.endpoint == endpoint)
        .map(|header| (header.header.as_str(), header.value_file.clone()))
        .collect();
    assert_eq!(
        headers,
        [
            ("x-api-key", PathBuf::from("/etc/iroha/eth-api-key")),
            ("authorization", PathBuf::from("/etc/iroha/eth-bearer")),
        ]
    );
}

#[test]
fn invalid_secret_header_entries_are_rejected() {
    assert_rejected(
        "[[sccp.light_client_keeper.secret_headers]]\n\
         endpoint = \"https://eth.example.org\"\nheader = \"content-length\"\n\
         value_file = \"/k\"\n",
        "secret_headers[0].header",
    );
    assert_rejected(
        "[[sccp.light_client_keeper.secret_headers]]\n\
         endpoint = \"ftp://eth.example.org\"\nheader = \"x-api-key\"\n\
         value_file = \"/k\"\n",
        "secret_headers[0].endpoint",
    );
    let inline_secret = "[[sccp.light_client_keeper.secret_headers]]\n\
                         endpoint = \"https://eth.example.org\"\nheader = \"x-api-key\"\n\
                         value = \"inline secret\"\n";
    assert!(
        load(inline_secret).is_err(),
        "secret values must come from files, never inline"
    );
}

#[test]
fn relative_paths_resolve_against_the_config_file() {
    let dir = std::env::temp_dir().join(format!("iroha-config-sccp-{}", std::process::id()));
    fs::create_dir_all(dir.join("keys")).expect("create key dir");
    fs::create_dir_all(dir.join("secrets")).expect("create secrets dir");
    let config_path = dir.join("config.toml");
    fs::write(
        &config_path,
        format!(
            "extends = [{base:?}]\n\
             [sccp.keeper]\nkey_dir = \"keys\"\n\
             [[sccp.light_client_keeper.secret_headers]]\n\
             endpoint = \"https://eth.example.org\"\nheader = \"x-api-key\"\n\
             value_file = \"secrets\"\n",
            base = base_toml().display().to_string()
        ),
    )
    .expect("write config");
    let config = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(&config_path)
        .expect("config loads")
        .read_and_complete::<UserConfig>()
        .expect("config reads")
        .parse()
        .expect("config parses");
    let canonical = |path: &Path| fs::canonicalize(path).expect("canonical path");
    assert_eq!(
        canonical(&config.sccp.keeper.key_dir_path()),
        canonical(&dir.join("keys"))
    );
    assert_eq!(
        canonical(&config.sccp.light_client_keeper.secret_headers[0].value_file),
        canonical(&dir.join("secrets"))
    );
    fs::remove_dir_all(&dir).expect("remove temp dir");
}

#[test]
fn sccp_tables_have_no_environment_aliases() {
    let env = MockEnv::new()
        .set("SCCP_KEEPER_ENABLED", "false")
        .set("SCCP_KEEPER_KEY_DIR", "/tmp/elsewhere")
        .set("SCCP_LIGHT_CLIENT_KEEPER_ENABLED", "false");
    let config = ConfigReader::new()
        .with_env(env.clone())
        .read_toml_with_extends(base_toml())
        .expect("base config should load")
        .read_and_complete::<UserConfig>()
        .expect("config reads")
        .parse()
        .expect("config parses");
    assert!(config.sccp.keeper.enabled);
    assert!(config.sccp.light_client_keeper.enabled);
    for name in [
        "SCCP_KEEPER_ENABLED",
        "SCCP_KEEPER_KEY_DIR",
        "SCCP_LIGHT_CLIENT_KEEPER_ENABLED",
    ] {
        assert!(env.unvisited().contains(name), "{name} must not be read");
    }
}

#[test]
fn tron_endpoint_list_is_rejected() {
    for list in ["[]", "[\"https://api.trongrid.io\"]"] {
        let extra = format!("[sccp.light_client_keeper.endpoints]\ntron = {list}\n");
        let error = load(&extra).expect_err(&extra);
        assert!(
            error.contains("sccp.light_client_keeper.endpoints.tron"),
            "{error}"
        );
    }
}

#[test]
fn zk_sccp_rejects_node_local_validity_limits() {
    for key in [
        "max_secp256k1_recoveries_per_transaction",
        "max_secp256k1_recoveries_per_block",
        "max_ed25519_signature_checks_per_block",
    ] {
        let extra = format!("[zk.sccp]\n{key} = 2048\n");
        let error = load(&extra).expect_err(&extra);
        assert!(error.contains("`zk.sccp`"), "{error}");
    }
}

#[test]
fn sccp_attestor_table_is_rejected() {
    for key in [
        "enabled = true",
        "key_dir = \"/opt/iroha/bridge-keys\"",
        "auto_register = false",
        "max_entries_per_transaction = 64",
        "resubmit_after_blocks = 3",
        "max_clock_drift_ms = 3600000",
        "shutdown_grace_ms = 30000",
    ] {
        let extra = format!("[sccp.attestor]\n{key}\n");
        let error = load(&extra).expect_err(&extra);
        assert!(error.contains("sccp.attestor"), "{error}");
    }
}

#[test]
fn unknown_sccp_keys_are_rejected() {
    for extra in [
        "[sccp]\nenabled = true\n",
        "[sccp.keeper]\nkey_directory = \"/x\"\n",
        "[sccp.keeper]\nauto_register = true\n",
        "[sccp.light_client_keeper.endpoints]\nton = []\n",
    ] {
        assert!(load(extra).is_err(), "{extra} must be rejected");
    }
}
