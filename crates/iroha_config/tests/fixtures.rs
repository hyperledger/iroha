//! Test fixtures exercising `iroha_config` parameter loading and validation.
use assertables::assert_contains;
use error_stack::{Report, ResultExt};
use expect_test::expect_file;
use iroha_config::parameters::user::ParseError;
use iroha_config::parameters::{
    actual::{LaneProfile, NoritoRpcStage, Root as Config, ToriiMcpProfile},
    defaults,
    user::Root as UserConfig,
};
use iroha_config_base::{
    env::MockEnv,
    read::ConfigReader,
    toml::{TomlSource, WriteExt as _},
};
use iroha_crypto::{Algorithm, ExposedPrivateKey, Hash, KeyPair, PrivateKey, PublicKey};
use iroha_data_model::account::AccountId;
use soranet_pq::MlKemSuite;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Mutex, MutexGuard, Once},
    time::Duration,
};
use thiserror::Error;
use toml::{Table, Value as TomlValue};
use url::Url;
fn fixtures_dir() -> PathBuf {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))
            .expect("tests run relative to crate root");
    });
    PathBuf::from("tests/fixtures")
}
fn parse_env(raw: impl AsRef<str>) -> HashMap<String, String> {
    raw.as_ref()
        .lines()
        .map(|line| {
            let mut items = line.split('=');
            let key = items
                .next()
                .expect("line should be in {key}={value} format");
            let value = items
                .next()
                .expect("line should be in {key}={value} format");
            (key.to_string(), value.to_string())
        })
        .collect()
}
fn test_env_from_file(p: impl AsRef<Path>) -> MockEnv {
    let contents = fs::read_to_string(p).expect("the path should be valid");
    let map = parse_env(contents);
    MockEnv::with_map(map)
}
fn strip_ansi_codes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if matches!(chars.peek(), Some('[')) {
                chars.next();
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}
struct AddressRuntimeGuard {
    chain_discriminant: u16,
    _lock: MutexGuard<'static, ()>,
}
impl AddressRuntimeGuard {
    fn capture() -> Self {
        static ADDRESS_RUNTIME_LOCK: Mutex<()> = Mutex::new(());
        let lock = ADDRESS_RUNTIME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self {
            chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
            _lock: lock,
        }
    }
}
impl Drop for AddressRuntimeGuard {
    fn drop(&mut self) {
        iroha_data_model::account::address::set_chain_discriminant(self.chain_discriminant);
    }
}
#[derive(Error, Debug)]
#[error("failed to load config from fixtures")]
struct FixtureConfigLoadError;
// The streaming fixtures select this exact checked-in public tables artifact.
// This exact bounded source never falls back to native files.
struct BundleFixtureFiles;
impl iroha_config_base::file_source::ConfigFileSource for BundleFixtureFiles {
    fn read(
        &self,
        path: &Path,
        request: iroha_config_base::file_source::ConfigFileRequest,
    ) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
        use iroha_config_base::file_source::ConfigFileAccess;
        if request.access != ConfigFileAccess::Public
            || path != Path::new("codec/rans/tables/rans_seed0.toml")
        {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let bytes = include_bytes!("../../../codec/rans/tables/rans_seed0.toml");
        if bytes.len() > request.maximum {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(zeroize::Zeroizing::new(bytes.to_vec()))
    }
}

#[test]
fn bundle_fixture_source_keeps_the_exact_public_artifact_and_bound() {
    use iroha_config_base::file_source::{ConfigFileAccess, ConfigFileRequest, ConfigFileSource};
    let path = Path::new("codec/rans/tables/rans_seed0.toml");
    let bytes = include_bytes!("../../../codec/rans/tables/rans_seed0.toml");
    let request = ConfigFileRequest {
        access: ConfigFileAccess::Public,
        maximum: bytes.len(),
    };
    assert_eq!(
        BundleFixtureFiles.read(path, request).unwrap().as_slice(),
        bytes
    );
    for (selected, request, error) in [
        (
            path,
            ConfigFileRequest {
                maximum: bytes.len() - 1,
                ..request
            },
            std::io::ErrorKind::InvalidData,
        ),
        (
            path,
            ConfigFileRequest {
                access: ConfigFileAccess::Private,
                ..request
            },
            std::io::ErrorKind::NotFound,
        ),
        (
            Path::new("another-tables.toml"),
            request,
            std::io::ErrorKind::NotFound,
        ),
    ] {
        assert_eq!(
            BundleFixtureFiles
                .read(selected, request)
                .unwrap_err()
                .kind(),
            error
        );
    }
}

include!("fixtures/soranet_transport_identity_tests.rs");
#[path = "fixtures/snapshot_read_buffer_tests.rs"]
mod snapshot_read_buffer_tests;
fn load_config_from_fixtures(path: impl AsRef<Path>) -> Result<Config, FixtureConfigLoadError> {
    let config = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(fixtures_dir().join(path))
        .change_context(FixtureConfigLoadError)?
        .read_and_complete::<UserConfig>()
        .change_context(FixtureConfigLoadError)?
        .parse_with_file_source(&BundleFixtureFiles)
        .change_context(FixtureConfigLoadError)?;
    Ok(config)
}
#[test]
fn quic_datagram_buffers_default_to_one_mib() {
    assert_eq!(
        defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get(),
        1024 * 1024
    );
    assert_eq!(
        defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES.get(),
        1024 * 1024
    );
    assert!(
        defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get()
            >= defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES.get()
    );
    assert!(
        defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES.get()
            >= defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES.get()
    );
}
/// Assert that minimal fixture fields suffice and snapshot the redacted debug view
/// of the parsed configuration and its defaults, independent of process environment.
#[test]
#[allow(clippy::too_many_lines)]
fn minimal_config_snapshot() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("config should be valid");
    let rendered = format!("{config:#?}").replace(
        defaults::runtime_provider_broker::ENDPOINT_PATH,
        "<platform-default broker endpoint>",
    );
    expect_file!["fixtures/minimal_config_snapshot.txt"].assert_eq(&format!("{rendered}\n"));
}
/// A minimal node config inherits application-sized budgets without deployment overrides.
#[test]
#[allow(clippy::too_many_lines)]
fn minimal_config_inherits_large_application_rate_budgets() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("minimal node configuration");
    assert_eq!(config.compute.slo.max_requests_per_second.get(), 1_000_000);
    let content = &config.content.limits;
    assert_eq!(content.max_requests_per_second.get(), 1_000_000);
    assert_eq!(content.request_burst.get(), 10_000_000);
    assert_eq!(content.max_egress_bytes_per_second.get(), 256 * 1024 * 1024);
    assert_eq!(content.egress_burst_bytes.get(), 1024 * 1024 * 1024);
    let torii = config.torii;
    let gateway = &torii.sorafs_gateway.rate_limit;
    assert_eq!(
        gateway.max_requests.map(std::num::NonZeroU32::get),
        Some(60_000_000)
    );
    assert_eq!(gateway.window, Duration::from_secs(60));
    for rate in [
        torii.query_rate_per_authority_per_sec,
        torii.tx_rate_per_authority_per_sec,
        torii.deploy_rate_per_origin_per_sec,
        torii.preauth_rate_per_ip_per_sec,
        torii.soracloud_public_rate_per_ip_per_sec,
        torii.soracloud_mutation_rate_per_account_origin_per_sec,
        torii.soranet_privacy_ingest.rate_per_sec,
    ] {
        assert_eq!(rate.map(std::num::NonZeroU32::get), Some(1_000_000));
    }
    for burst in [
        torii.query_burst_per_authority,
        torii.tx_burst_per_authority,
        torii.deploy_burst_per_origin,
        torii.preauth_burst_per_ip,
        torii.soracloud_public_burst_per_ip,
        torii.soracloud_mutation_burst_per_account_origin,
        torii.proof_api.burst,
        torii.mcp.burst,
        torii.push.burst,
        torii.operator_auth.burst,
        torii.soranet_privacy_ingest.burst,
    ] {
        assert_eq!(burst.map(std::num::NonZeroU32::get), Some(10_000_000));
    }
    assert_eq!(torii.connect.ws_rate_per_ip_per_min, 60_000_000);
    assert_eq!(torii.connect.ws_per_ip_max_sessions, 10);
    assert_eq!(torii.connect.ws_max_sessions, 10_000);
    for rate in [
        torii.proof_api.rate_per_minute,
        torii.mcp.rate_per_minute,
        torii.push.rate_per_minute,
        torii.operator_auth.rate_per_minute,
    ] {
        assert_eq!(rate.map(std::num::NonZeroU32::get), Some(60_000_000));
    }
    assert_eq!(torii.recipient_lookup.requests_per_minute, 60_000_000);
    assert!(torii.kagemusha_enrollment.is_none());
    assert_eq!(
        torii
            .proof_api
            .egress_bytes_per_sec
            .map(std::num::NonZeroU64::get),
        Some(256 * 1024 * 1024)
    );
    assert_eq!(
        torii
            .proof_api
            .egress_burst_bytes
            .map(std::num::NonZeroU64::get),
        Some(1024 * 1024 * 1024)
    );

    // Raising defaults must still respect budgets deliberately chosen by the operator.
    let overrides = r#"
[torii]
tx_rate_per_authority_per_sec = 3
tx_burst_per_authority = 7
preauth_rate_per_ip_per_sec = 3
preauth_burst_per_ip = 7
[torii.operator_auth]
rate_per_minute = 5
burst = 9
[torii.recipient_lookup]
policy_id = "cbuae_aed_sbp_pkr"
requests_per_minute = 30
request_timeout_ms = 4000
routes = []
[torii.soranet_privacy_ingest]
rate_per_sec = 2
burst = 4
"#;
    let explicit = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
        .expect("minimal node fixture")
        .with_toml_source(TomlSource::inline(
            overrides.parse().expect("rate overrides"),
        ))
        .read_and_complete::<UserConfig>()
        .expect("explicit budgets")
        .parse()
        .expect("small operator-selected budgets remain valid")
        .torii;
    for (configured, expected) in [
        (explicit.tx_rate_per_authority_per_sec, 3),
        (explicit.tx_burst_per_authority, 7),
        (explicit.preauth_rate_per_ip_per_sec, 3),
        (explicit.preauth_burst_per_ip, 7),
        (explicit.operator_auth.rate_per_minute, 5),
        (explicit.operator_auth.burst, 9),
        (explicit.soranet_privacy_ingest.rate_per_sec, 2),
        (explicit.soranet_privacy_ingest.burst, 4),
    ] {
        assert_eq!(configured.map(std::num::NonZeroU32::get), Some(expected));
    }
    assert_eq!(explicit.recipient_lookup.requests_per_minute, 30);
}
#[test]
fn torii_receipt_signer_parses() {
    let config =
        load_config_from_fixtures("torii_receipt_signer.toml").expect("config should be valid");
    let signer = config
        .torii
        .receipt_signer
        .expect("receipt signer should be configured");
    let expected = PublicKey::from_str(
        "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
    )
    .expect("receipt public key");
    assert_eq!(signer.public_key(), &expected);
    assert_eq!(
        signer
            .public_key()
            .try_algorithm()
            .expect("fixture receipt public key must be well-formed"),
        Algorithm::Ed25519
    );
}
#[test]
fn torii_ram_lfe_parses() {
    let config = load_config_from_fixtures("torii_ram_lfe.toml").expect("config should be valid");
    let runtime = config
        .torii
        .ram_lfe
        .expect("RAM-LFE runtime should be configured");
    assert_eq!(runtime.programs.len(), 1);
    let program = &runtime.programs[0];
    let expected_program_id = "phone_retail".parse().expect("program id");
    assert_eq!(program.program_id, expected_program_id);
    assert_eq!(program.secret.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        program.hidden_program,
        iroha_crypto::default_bfv_programmed_hidden_program(),
        "the fixture uses the sole canonical hidden-program owner and layout"
    );
    let debug = format!("{runtime:?}");
    assert!(debug.contains("REDACTED RAM-LFE secret"));
    assert!(!debug.contains("01020304"));
    assert!(!debug.contains("4e525430"));
    assert_eq!(
        program.receipt_ttl,
        Some(Duration::from_millis(30_000)),
        "receipt ttl should parse as milliseconds"
    );
}
#[test]
fn ivm_banner_defaults_enabled() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("config should be valid");
    assert!(config.ivm.banner.show, "banner should default to on");
    assert!(config.ivm.banner.beep, "beep should default to on");
}
#[test]
fn torii_max_content_len_defaults_to_sixty_four_megabytes() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("config should be valid");
    assert_eq!(
        config.torii.max_content_len.0,
        defaults::torii::MAX_CONTENT_LEN.0,
        "minimal configs should inherit the runtime Torii body-cap default"
    );
    assert_eq!(
        config.torii.query_fanout_max_retained_bytes.get(),
        512_000_000
    );
    assert_eq!(
        config.torii.query_fanout_max_working_set_bytes.get(),
        48_000_000
    );
    assert_eq!(
        defaults::torii::app_api_routed_read_route_body_phase_bytes(
            config.torii.query_fanout_max_retained_bytes.get(),
            config.torii.query_fanout_max_working_set_bytes.get(),
            config.torii.max_content_len.get(),
        ),
        Some(2_562_487),
        "minimal configs must retain the per-query phase when aggregate concurrency increases"
    );
}
#[test]
fn sccp_history_cache_has_its_own_finite_default_and_exact_override() {
    let default = load_config_from_fixtures("minimal_with_trusted_peers.toml").unwrap();
    assert_eq!(default.torii.sccp_history_cache_max_bytes.get(), 8_000_000);
    let explicit = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
        .unwrap()
        .with_toml_source(TomlSource::inline(
            "[torii]\nsccp_history_cache_max_bytes = 4096"
                .parse()
                .unwrap(),
        ))
        .read_and_complete::<UserConfig>()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(explicit.torii.sccp_history_cache_max_bytes.get(), 4096);
    assert_eq!(
        explicit.torii.query_fanout_max_retained_bytes.get(),
        default.torii.query_fanout_max_retained_bytes.get()
    );
    assert_eq!(
        explicit.torii.query_fanout_max_working_set_bytes.get(),
        default.torii.query_fanout_max_working_set_bytes.get()
    );
}

#[test]
fn sccp_history_cache_rejects_zero_capacity() {
    let config = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
        .unwrap()
        .with_toml_source(TomlSource::inline(
            "[torii]\nsccp_history_cache_max_bytes = 0".parse().unwrap(),
        ))
        .read_and_complete::<UserConfig>()
        .unwrap();
    let error = config.parse().unwrap_err();
    assert!(
        format!("{error:?}")
            .contains("torii.sccp_history_cache_max_bytes must be greater than zero")
    );
}

#[test]
fn portable_production_capabilities_default_to_enabled() {
    let config = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("config should be valid");

    assert!(config.confidential.enabled);
    assert!(!config.confidential.assume_valid);
    assert!(config.zk.pipa_r.enabled);
    assert!(config.zk.trace.enabled);
    assert_eq!(config.zk.trace.max_batch, 16);
    assert_eq!(config.zk.max_verify_batch, 16);
    assert_eq!(config.zk.ipa_commitment.max_k, 16);
    assert_eq!(config.zk.ipa_commitment.max_transcript_label_len, 64);
    assert_eq!(config.zk.ipa_commitment.max_envelope_bytes, 256 * 1024);
    assert!(config.zk.ipa_commitment.enforce_transcript_label_ascii);
    assert!(config.zk.stark.enabled);
    assert!(config.gov.plain_voting_enabled);
    assert!(config.streaming.sync.enabled);
    assert!(config.streaming.sync.observe_only);
    assert!(config.torii.webhooks_enabled);
    assert!(config.torii.zk_attachments_enabled);
    assert!(config.torii.zk_prover_enabled);
    assert!(config.torii.transport.norito_rpc.enabled);
    assert_eq!(config.torii.transport.norito_rpc.stage, NoritoRpcStage::Ga);
    assert!(config.torii.mcp.enabled);
    assert_eq!(config.torii.mcp.profile, ToriiMcpProfile::ReadOnly);
    assert!(!config.torii.mcp.expose_operator_routes);
    assert!(!config.torii.cors.enabled);
    assert!(!config.torii.push.enabled);
    assert!(config.torii.sorafs_gateway.enforce_capabilities);
    assert_eq!(
        config
            .torii
            .sorafs_storage
            .metering_smoothing
            .gib_hours_alpha,
        Some(0.2)
    );
    assert_eq!(
        config
            .torii
            .sorafs_storage
            .metering_smoothing
            .por_success_alpha,
        Some(0.2)
    );
}
#[test]
fn ivm_banner_override_applies() {
    let config =
        load_config_from_fixtures("ivm_banner_override.toml").expect("config should be valid");
    assert!(
        !config.ivm.banner.show,
        "override should disable banner rendering"
    );
    assert!(
        !config.ivm.banner.beep,
        "override should disable beep rendering"
    );
}
#[test]
fn nexus_lane_requires_alias() {
    use iroha_config::parameters::user::{LaneDescriptor, Nexus};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("   ".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn nexus_rejects_zero_axt_slot_length() {
    use iroha_config::parameters::user::{LaneDescriptor, Nexus, NexusAxt};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("core".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        axt: NexusAxt {
            slot_length_ms: 0,
            max_clock_skew_ms:
                iroha_config::parameters::defaults::nexus::axt::CLOCK_SKEW_MS_DEFAULT,
            proof_cache_ttl_slots:
                iroha_config::parameters::defaults::nexus::axt::PROOF_CACHE_TTL_SLOTS,
            replay_retention_slots:
                iroha_config::parameters::defaults::nexus::axt::REPLAY_RETENTION_SLOTS,
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn nexus_relay_worker_requires_lane_relay_burn() {
    use iroha_config::parameters::user::{Nexus, NexusRelayWorker};
    use iroha_config_base::util::Emitter;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        relay_worker: NexusRelayWorker {
            enabled: true,
            ..NexusRelayWorker::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let error = format!("{:?}", emitter.into_result().expect_err("invalid config"));
    assert!(error.contains("nexus.relay_worker.enabled"));
}
#[test]
fn nexus_rejects_retired_lane_relay_burn_even_with_a_configured_worker() {
    use iroha_config::parameters::user::{Nexus, NexusFees, NexusRelayWorker};
    use iroha_config_base::util::Emitter;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        fees: NexusFees {
            settlement_mode: "lane_relay_burn".to_owned(),
            ..NexusFees::default()
        },
        relay_worker: NexusRelayWorker {
            enabled: true,
            max_retry_attempts: 3,
            ..NexusRelayWorker::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let error = format!("{:?}", emitter.into_result().expect_err("retired mode"));
    assert!(error.contains("nexus.fees.settlement_mode"), "{error}");
    assert!(error.contains("expected `direct`"), "{error}");
}
#[test]
fn nexus_rejects_out_of_range_axt_slot_length() {
    let result = load_config_from_fixtures("bad.nexus_axt_slot_length_too_large.toml");
    assert!(
        result.is_err(),
        "slot length above guardrail must be rejected"
    );
}
#[test]
fn nexus_rejects_negative_axt_slot_length() {
    let result = load_config_from_fixtures("bad.nexus_axt_slot_length_negative.toml");
    assert!(result.is_err(), "negative slot length must be rejected");
}
#[test]
fn nexus_rejects_axt_clock_skew_above_slot_length() {
    use iroha_config::parameters::user::{LaneDescriptor, Nexus, NexusAxt};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("core".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        axt: NexusAxt {
            slot_length_ms: 1_000,
            max_clock_skew_ms: 2_000,
            proof_cache_ttl_slots:
                iroha_config::parameters::defaults::nexus::axt::PROOF_CACHE_TTL_SLOTS,
            replay_retention_slots:
                iroha_config::parameters::defaults::nexus::axt::REPLAY_RETENTION_SLOTS,
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn nexus_rejects_zero_axt_replay_retention_slots() {
    use iroha_config::parameters::user::{LaneDescriptor, Nexus, NexusAxt};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("core".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        axt: NexusAxt {
            slot_length_ms: 1_000,
            max_clock_skew_ms: 0,
            proof_cache_ttl_slots:
                iroha_config::parameters::defaults::nexus::axt::PROOF_CACHE_TTL_SLOTS,
            replay_retention_slots: 0,
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn nexus_rejects_out_of_range_axt_replay_retention_slots() {
    let result = load_config_from_fixtures("bad.nexus_axt_replay_retention_too_large.toml");
    assert!(
        result.is_err(),
        "replay retention above guardrail must be rejected"
    );
}
#[test]
fn nexus_axt_fields_load_from_fixture() {
    let config = load_config_from_fixtures("nexus_axt_full.toml").expect("config should be valid");
    assert_eq!(config.nexus.axt.slot_length_ms.get(), 1_000);
    assert_eq!(config.nexus.axt.max_clock_skew_ms, 250);
    assert_eq!(config.nexus.axt.proof_cache_ttl_slots.get(), 8);
    assert_eq!(config.nexus.axt.replay_retention_slots.get(), 256);
}
#[test]
fn nexus_atomic_private_settlement_fields_load_from_fixture() {
    let config = load_config_from_fixtures("nexus_atomic_private_settlement_full.toml")
        .expect("private-settlement config should be valid");
    let private = &config.nexus.atomic_private_settlement;
    assert!(private.enabled);
    assert_eq!(private.activation_height, Some(100_000));
    assert_eq!(private.max_participants.get(), 16);
    assert_eq!(private.proof_profile_version.get(), 1);
    assert_eq!(private.sidecar_max_records.get(), 512);
    assert_eq!(private.sidecar_max_total_bytes.get(), 6_442_450_944);
    assert_eq!(
        private
            .capsule_padding_classes_bytes
            .iter()
            .map(|bytes| bytes.get())
            .collect::<Vec<_>>(),
        vec![4_096, 16_384, 65_536, 262_144]
    );
    assert_eq!(
        private
            .permitted_policy_versions
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![1]
    );
}
#[test]
fn nexus_atomic_private_settlement_rejects_invalid_participant_bound() {
    let result = load_config_from_fixtures("bad.nexus_atomic_private_settlement_participants.toml");
    assert!(result.is_err(), "one-leg private bundles must be rejected");
}

#[test]
fn nexus_atomic_private_settlement_rejects_sidecar_capacity_above_v1_caps() {
    use iroha_config::parameters::{
        defaults,
        user::{Nexus, NexusAtomicPrivateSettlement},
    };
    use iroha_config_base::util::Emitter;

    let mut emitter = Emitter::<ParseError>::new();
    let private = NexusAtomicPrivateSettlement {
        sidecar_max_records: defaults::nexus::atomic_private_settlement::SIDECAR_MAX_RECORDS_LIMIT
            + 1,
        sidecar_max_total_bytes:
            defaults::nexus::atomic_private_settlement::SIDECAR_MAX_TOTAL_BYTES_LIMIT + 1,
        ..NexusAtomicPrivateSettlement::default()
    };
    let nexus = Nexus {
        atomic_private_settlement: private,
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}

#[test]
fn nexus_atomic_private_settlement_requires_activation_height_and_canonical_bounds() {
    use iroha_config::parameters::user::{Nexus, NexusAtomicPrivateSettlement};
    use iroha_config_base::util::Emitter;

    let mut emitter = Emitter::<ParseError>::new();
    let private = NexusAtomicPrivateSettlement {
        enabled: true,
        activation_height: None,
        capsule_padding_classes_bytes: vec![16_384, 4_096],
        permitted_policy_versions: vec![1, 1],
        ..NexusAtomicPrivateSettlement::default()
    };
    let nexus = Nexus {
        atomic_private_settlement: private,
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}

#[test]
fn nexus_atomic_private_settlement_capsule_bound_covers_complete_default_auditor_roster() {
    use iroha_config::parameters::user::{Nexus, NexusAtomicPrivateSettlement};
    use iroha_config_base::util::Emitter;
    use iroha_data_model::nexus::private_settlement_capsule_canonical_upper_bound_v1;

    for auditors in [1_u16, 32] {
        let exact_bound =
            private_settlement_capsule_canonical_upper_bound_v1(4_096, u64::from(auditors));
        let mut valid_emitter = Emitter::<ParseError>::new();
        let valid = Nexus {
            atomic_private_settlement: NexusAtomicPrivateSettlement {
                capsule_padding_classes_bytes: vec![4_096],
                max_capsule_bytes: exact_bound,
                default_min_auditor_approvals: auditors,
                ..NexusAtomicPrivateSettlement::default()
            },
            ..Nexus::default()
        };
        assert!(valid.parse(&mut valid_emitter).is_some());
        assert!(valid_emitter.into_result().is_ok());

        let mut short_emitter = Emitter::<ParseError>::new();
        let one_byte_short = Nexus {
            atomic_private_settlement: NexusAtomicPrivateSettlement {
                capsule_padding_classes_bytes: vec![4_096],
                max_capsule_bytes: exact_bound - 1,
                default_min_auditor_approvals: auditors,
                ..NexusAtomicPrivateSettlement::default()
            },
            ..Nexus::default()
        };
        assert!(one_byte_short.parse(&mut short_emitter).is_none());
        assert!(short_emitter.into_result().is_err());
    }
}

#[test]
fn nexus_atomic_private_settlement_rejects_default_auditor_threshold_above_v1_roster() {
    use iroha_config::parameters::user::{Nexus, NexusAtomicPrivateSettlement};
    use iroha_config_base::util::Emitter;

    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        atomic_private_settlement: NexusAtomicPrivateSettlement {
            default_min_auditor_approvals: 33,
            ..NexusAtomicPrivateSettlement::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn sumeragi_rejects_each_retired_table_independently() {
    for (fixture, expected_parameter) in [
        ("bad.sumeragi_retired_collectors_table.toml", "collectors"),
        ("bad.sumeragi_retired_advanced_rbc_table.toml", "advanced"),
        ("bad.sumeragi_retired_recovery_table.toml", "recovery"),
    ] {
        let report = match load_config_from_fixtures(fixture) {
            Ok(_) => panic!("retired fixture {fixture} was accepted"),
            Err(report) => report,
        };
        let message = strip_ansi_codes(&format!("{report:?}"));
        assert!(
            message.contains(expected_parameter),
            "diagnostic for {fixture} should identify `{expected_parameter}`: {message}",
        );
    }
}
#[test]
fn sumeragi_rejects_each_retired_byzantine_rbc_debug_field_independently() {
    for fixture in [
        "bad.sumeragi_retired_debug_rbc_conflicting_ready_mask.toml",
        "bad.sumeragi_retired_debug_rbc_duplicate_inits.toml",
    ] {
        let report = match load_config_from_fixtures(fixture) {
            Ok(_) => panic!("retired debug fixture {fixture} was accepted"),
            Err(report) => report,
        };
        let message = strip_ansi_codes(&format!("{report:?}"));
        assert!(
            message.contains("sumeragi.debug") || message.contains("sumeragi.debug.rbc"),
            "diagnostic for {fixture} should identify the retired debug table: {message}",
        );
    }
}
#[test]
fn retired_plan_journal_toggle_fails_during_config_parse_before_runtime_storage() {
    let report = load_config_from_fixtures("bad.retired_plan_journal_toggle.toml")
        .expect_err("the first release must not expose a journal-disabled runtime path");
    let message = strip_ansi_codes(&format!("{report:?}"));
    assert_contains!(message, "unknown parameter: `queue.plan_journal_enabled`");
}

#[test]
fn retired_kagemusha_finality_prover_configuration_is_rejected() {
    for field in ["proving_cache", "verifier_originals", "journal_dir"] {
        let table = format!("[torii.kagemusha_load_finality]\n{field} = '/retired/finality'\n")
            .parse()
            .expect("retired finality TOML should parse");
        let error = ConfigReader::new()
            .read_toml_with_extends(fixtures_dir().join("base.toml"))
            .expect("base config should load")
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect_err("the retired finality prover must not be configurable");
        let report = strip_ansi_codes(&format!("{error:?}"));
        assert!(
            report.contains("unknown parameter: `torii.kagemusha_load_finality"),
            "{report}"
        );
    }
}
#[test]
fn nexus_storage_weights_require_full_budget() {
    use iroha_config::parameters::user::{Nexus, NexusStorage, NexusStorageWeights};
    use iroha_config_base::util::Emitter;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        storage: NexusStorage {
            disk_budget_weights: NexusStorageWeights {
                kura_blocks_bps: 9_000,
                wsv_snapshots_bps: 0,
                sorafs_bps: 0,
            },
            ..NexusStorage::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let err = emitter
        .into_result()
        .expect_err("invalid storage weights must be rejected");
    let debug = strip_ansi_codes(&format!("{err:?}"));
    assert_contains!(debug, "nexus.storage.disk_budget_weights");
}

#[test]
fn retired_kagemusha_operation_index_pool_fails_during_config_parse() {
    let report = load_config_from_fixtures("bad.retired_kagemusha_operation_index_bytes.toml")
        .expect_err("the first release has no fixed KAGEMUSHA operation-index pool");
    let message = strip_ansi_codes(&format!("{report:?}"));
    assert_contains!(
        message,
        "unknown parameter: `nexus.storage.kagemusha_operation_index_bytes`"
    );
}
#[test]
fn nexus_storage_weights_require_positive_subsystem_shares() {
    use iroha_config::parameters::user::{Nexus, NexusStorage, NexusStorageWeights};
    use iroha_config_base::util::Emitter;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        storage: NexusStorage {
            disk_budget_weights: NexusStorageWeights {
                kura_blocks_bps: 4_000,
                wsv_snapshots_bps: 6_000,
                sorafs_bps: 0,
            },
            ..NexusStorage::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let err = emitter
        .into_result()
        .expect_err("a zero subsystem storage share must be rejected");
    let debug = strip_ansi_codes(&format!("{err:?}"));
    assert_contains!(debug, "nexus.storage.disk_budget_weights");
    assert_contains!(debug, "sorafs_bps");
    assert_contains!(debug, "greater than zero");
}
#[test]
fn nexus_profile_template_enables_multilane_defaults() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("defaults/nexus/config.toml");
    let source = fs::read_to_string(&config_path).expect("read Nexus signing profile");
    let mut table: toml::Table = toml::from_str(&source).expect("parse Nexus signing profile");
    assert!(
        !table.contains_key("kagemusha_load_authorizer"),
        "ordinary Nexus profile uses finalized transactions for wallet loads"
    );

    let validator_private_key_file = table
        .remove("private_key_file")
        .expect("Nexus signing profile validator private-key file");
    assert_eq!(
        validator_private_key_file.as_str(),
        Some("/run/secrets/iroha/nexus-validator-private-key")
    );
    table.insert(
        "private_key".to_owned(),
        TomlValue::String(
            "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F".to_owned(),
        ),
    );

    let transport_private_key_file = table
        .remove("soranet_transport_private_key_file")
        .expect("Nexus signing profile SoraNet transport private-key file");
    assert_eq!(
        transport_private_key_file.as_str(),
        Some("/run/secrets/iroha/nexus-soranet-transport-private-key")
    );
    let transport_key_pair = fixture_soranet_transport_key_pair();
    table.insert(
        "soranet_transport_public_key".to_owned(),
        TomlValue::String(transport_key_pair.public_key().to_string()),
    );
    table.insert(
        "soranet_transport_private_key".to_owned(),
        TomlValue::String(ExposedPrivateKey(transport_key_pair.private_key().clone()).to_string()),
    );

    let streaming = table
        .get_mut("streaming")
        .and_then(TomlValue::as_table_mut)
        .expect("Nexus signing profile streaming table");
    let streaming_private_key_file = streaming
        .remove("identity_private_key_file")
        .expect("Nexus signing profile streaming private-key file");
    assert_eq!(
        streaming_private_key_file.as_str(),
        Some("/run/secrets/iroha/nexus-streaming-identity-private-key")
    );
    let streaming_key_pair = fixture_streaming_key_pair();
    streaming.insert(
        "identity_public_key".to_owned(),
        TomlValue::String(streaming_key_pair.public_key().to_string()),
    );
    streaming.insert(
        "identity_private_key".to_owned(),
        TomlValue::String(ExposedPrivateKey(streaming_key_pair.private_key().clone()).to_string()),
    );

    let genesis = table
        .get_mut("genesis")
        .and_then(TomlValue::as_table_mut)
        .expect("Nexus signing profile genesis table");
    let expected_hash_file = genesis
        .remove("expected_hash_file")
        .expect("Nexus signing profile expected-hash file");
    assert_eq!(
        expected_hash_file.as_str(),
        Some("/run/iroha/genesis.expected_hash")
    );
    // Substitute only inside this inspection test; the checked-in profile resolves the hash
    // from an operator-provisioned runtime file.
    genesis.insert(
        "expected_hash".to_owned(),
        TomlValue::String(norito::literal::format(
            "hash",
            &Hash::new(b"iroha-config non-runtime Nexus profile inspection")
                .to_string()
                .to_ascii_uppercase(),
        )),
    );
    let config = ConfigReader::new()
        .with_toml_source(iroha_config_base::toml::TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .change_context(FixtureConfigLoadError)
        .and_then(|user| user.parse().change_context(FixtureConfigLoadError))
        .expect("Nexus profile config should parse");
    assert_eq!(config.nexus.lane_catalog.lane_count().get(), 3);
    assert_eq!(
        config.nexus.configured_dataspace_catalog, config.nexus.dataspace_catalog,
        "parsing initializes the immutable dataspace baseline from the exact configured entries"
    );
    assert_eq!(
        config.nexus.dataspace_catalog.entries().len(),
        1,
        "logical lanes sharing one validator topology must not become dataspaces"
    );
    let lane_bindings: Vec<_> = config
        .nexus
        .lane_catalog
        .lanes()
        .iter()
        .map(|lane| (lane.alias.as_str(), lane.dataspace_id))
        .collect();
    assert_eq!(
        lane_bindings,
        [
            ("core", iroha_model_base::topology::DataSpaceId::UNIVERSAL,),
            (
                "governance",
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            ),
            ("zk", iroha_model_base::topology::DataSpaceId::UNIVERSAL),
        ]
    );
    let dataspace_aliases: Vec<_> = config
        .nexus
        .dataspace_catalog
        .entries()
        .iter()
        .map(|entry| entry.alias.as_str())
        .collect();
    assert_eq!(dataspace_aliases, ["universal"]);
    assert_eq!(config.nexus.routing_policy.rules.len(), 2);
    assert!(config.nexus.routing_policy.rules.iter().all(|rule| {
        rule.dataspace == Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL)
    }));
}
#[test]
fn minamoto_mainnet_profile_keeps_logical_lanes_in_universal() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("configs/soranexus/nexus/config.toml");

    let raw = fs::read_to_string(&config_path).expect("Minamoto mainnet config should exist");
    let doc: TomlValue = toml::from_str(&raw).expect("Minamoto config should be valid TOML");
    let nexus = doc
        .get("nexus")
        .and_then(TomlValue::as_table)
        .expect("Minamoto nexus topology should be configured");

    assert_eq!(
        nexus.get("lane_count").and_then(TomlValue::as_integer),
        Some(3)
    );
    let lane_bindings: Vec<_> = nexus
        .get("lane_catalog")
        .and_then(TomlValue::as_array)
        .expect("Minamoto lane catalog should be configured")
        .iter()
        .map(|lane| {
            (
                lane.get("alias")
                    .and_then(TomlValue::as_str)
                    .expect("every Minamoto lane should have an alias"),
                lane.get("dataspace")
                    .and_then(TomlValue::as_str)
                    .expect("every Minamoto lane should bind to a dataspace"),
            )
        })
        .collect();
    assert_eq!(
        lane_bindings,
        [
            ("core", "universal"),
            ("governance", "universal"),
            ("zk", "universal"),
        ],
        "logical governance and zk lanes must share the mainnet server topology"
    );

    let dataspace_aliases: Vec<_> = nexus
        .get("dataspace_catalog")
        .and_then(TomlValue::as_array)
        .expect("Minamoto dataspace catalog should be configured")
        .iter()
        .map(|entry| {
            entry
                .get("alias")
                .and_then(TomlValue::as_str)
                .expect("every Minamoto dataspace should have an alias")
        })
        .collect();
    assert_eq!(
        dataspace_aliases,
        ["universal"],
        "governance and zk are lane names, not physical dataspaces"
    );

    let route_bindings: Vec<_> = nexus
        .get("routing_policy")
        .and_then(TomlValue::as_table)
        .and_then(|policy| policy.get("rules"))
        .and_then(TomlValue::as_array)
        .expect("Minamoto routing rules should be configured")
        .iter()
        .map(|rule| {
            (
                rule.get("lane")
                    .and_then(TomlValue::as_integer)
                    .expect("every Minamoto route should select a lane"),
                rule.get("dataspace")
                    .and_then(TomlValue::as_str)
                    .expect("every Minamoto route should select a dataspace"),
            )
        })
        .collect();
    assert_eq!(route_bindings, [(1, "universal"), (2, "universal")]);
}

#[test]
fn lane_profile_home_applies_throttles() {
    let config = load_config_from_fixtures("home_lane_profile.toml")
        .expect("config should be valid with lane profile override");
    let expected_limits = LaneProfile::Home.derived_limits();
    let network = &config.network;
    assert_eq!(network.lane_profile, LaneProfile::Home);
    assert_eq!(network.max_incoming, expected_limits.max_incoming);
    assert_eq!(
        network.max_total_connections,
        expected_limits.max_total_connections
    );
    assert_eq!(
        network.low_priority_bytes_per_sec,
        expected_limits.low_priority_bytes_per_sec
    );
    assert_eq!(
        network.low_priority_rate_per_sec,
        expected_limits.low_priority_rate_per_sec
    );
}
#[test]
fn retired_streaming_soranet_table_is_rejected() {
    let table = r#"
[streaming.soranet]
enabled = false
exit_multiaddr = "/dns/retired.example/udp/9443/quic"
"#
    .parse()
    .expect("retired inline TOML should parse");
    let error = ConfigReader::new()
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("base config should load")
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<UserConfig>()
        .expect_err("retired streaming.soranet configuration must be unknown");
    let report = strip_ansi_codes(&format!("{error:?}"));
    assert!(
        report.contains("unknown parameter: `streaming.soranet"),
        "unexpected retired-table diagnostic: {report}"
    );
}
#[test]
fn streaming_bundled_requires_build_flag() {
    assert!(
        norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
        "Bundled rANS must be compiled in for the first release; rebuild with ENABLE_RANS_BUNDLES=1"
    );
    let result = load_config_from_fixtures("streaming_bundled.toml");
    result.expect("streaming_bundled config should load on bundled builds");
}
#[test]
fn streaming_bundle_width_above_tables_rejected() {
    assert!(
        norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
        "Bundled rANS must be compiled in for the first release; rebuild with ENABLE_RANS_BUNDLES=1"
    );
    let result = load_config_from_fixtures("bad.streaming_bundle_width.toml");
    let err = result.expect_err("bundle width above available bundled tables must be rejected");
    let debug = format!("{err:?}");
    assert!(
        debug.contains("bundle_width"),
        "error should surface the bundle_width guard (got {debug})"
    );
    assert!(
        debug.contains("1..=3"),
        "error should report the available bundled width from the tables (got {debug})"
    );
}
#[test]
fn streaming_bundle_width_below_minimum_rejected() {
    assert!(
        norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
        "Bundled rANS must be compiled in for the first release; rebuild with ENABLE_RANS_BUNDLES=1"
    );
    let result = load_config_from_fixtures("bad.streaming_bundle_width_small.toml");
    let err = result.expect_err("bundle width below minimum must be rejected");
    let debug = format!("{err:?}");
    assert!(
        debug.contains("bundle_width"),
        "error should surface the bundle_width guard (got {debug})"
    );
    assert!(
        debug.contains("at least 2"),
        "error should report the minimum bundled width requirement (got {debug})"
    );
}
#[test]
fn streaming_bundle_width_zero_rejected() {
    assert!(
        norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
        "Bundled rANS must be compiled in for the first release; rebuild with ENABLE_RANS_BUNDLES=1"
    );
    let result = load_config_from_fixtures("bad.streaming_bundle_width_zero.toml");
    let err = result.expect_err("zero bundle width must be rejected");
    let debug = format!("{err:?}");
    assert!(
        debug.contains("bundle_width"),
        "error should surface the bundle_width guard (got {debug})"
    );
    assert!(
        debug.contains("1..=3"),
        "error should report the available bundled width from the tables (got {debug})"
    );
}
#[test]
fn streaming_invalid_kyber_suite_rejected() {
    let result = load_config_from_fixtures("bad.streaming_kyber_suite.toml");
    assert!(
        result.is_err(),
        "invalid streaming.kyber_suite must be rejected"
    );
}
#[test]
fn soranet_handshake_kem_suite_override() {
    let config = load_config_from_fixtures("soranet_handshake_kem_suite_override.toml")
        .expect("config should load with handshake override");
    assert_eq!(
        config.network.soranet_handshake.kem_id,
        MlKemSuite::MlKem512.kem_id(),
        "override should downshift the KEM suite id"
    );
}
#[test]
fn soranet_handshake_invalid_kem_suite_rejected() {
    let result = load_config_from_fixtures("bad.soranet_handshake_kem_suite.toml");
    assert!(
        result.is_err(),
        "invalid network.soranet_handshake.kem_suite must be rejected"
    );
}
#[test]
fn soranet_handshake_zero_difficulty_rejected() {
    let result = load_config_from_fixtures("bad.soranet_handshake_zero_difficulty.toml");
    assert!(
        result.is_err(),
        "zero-difficulty SoraNet admission must be rejected"
    );
}
#[test]
fn routing_policy_dataspace_resolution() {
    use iroha_config::parameters::user::{
        DataSpaceDescriptor, LaneDescriptor, Nexus, RouteMatcher, RoutingPolicy, RoutingRule,
    };
    use iroha_config_base::util::Emitter;
    use iroha_model_base::topology::DataSpaceId;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(2).expect("nonzero"),
        lane_catalog: vec![
            LaneDescriptor {
                index: Some(0),
                alias: Some("primary".into()),
                dataspace: Some("universal".into()),
                description: None,
                ..LaneDescriptor::default()
            },
            LaneDescriptor {
                index: Some(1),
                alias: Some("alpha".into()),
                dataspace: Some("alpha".into()),
                description: None,
                ..LaneDescriptor::default()
            },
        ],
        dataspace_catalog: vec![
            DataSpaceDescriptor {
                alias: Some("universal".into()),
                id: Some(0),
                ..DataSpaceDescriptor::default()
            },
            DataSpaceDescriptor {
                alias: Some("alpha".into()),
                id: Some(1),
                manifest_hash: Some(
                    "0100000000000000000000000000000000000000000000000000000000000000".into(),
                ),
                description: None,
                fault_tolerance: None,
                fee_sponsor_program_id: None,
            },
        ],
        routing_policy: RoutingPolicy {
            default_lane: Some(1),
            default_dataspace: Some("alpha".into()),
            rules: vec![RoutingRule {
                lane: Some(0),
                dataspace: Some("universal".into()),
                matcher: RouteMatcher::default(),
            }],
        },
        ..Nexus::default()
    };
    let parsed = nexus
        .parse(&mut emitter)
        .expect("routing policy should parse");
    assert!(emitter.into_result().is_ok());
    assert_eq!(parsed.routing_policy.default_dataspace, DataSpaceId::new(1));
    assert_eq!(
        parsed.routing_policy.rules[0].dataspace,
        Some(DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn routing_policy_lane_dataspace_mismatch_rejected() {
    use iroha_config::parameters::user::{
        DataSpaceDescriptor, LaneDescriptor, Nexus, RoutingPolicy,
    };
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            dataspace: Some("universal".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        dataspace_catalog: vec![
            DataSpaceDescriptor {
                alias: Some("universal".into()),
                id: Some(0),
                ..DataSpaceDescriptor::default()
            },
            DataSpaceDescriptor {
                alias: Some("alpha".into()),
                id: Some(1),
                manifest_hash: Some(
                    "0100000000000000000000000000000000000000000000000000000000000000".into(),
                ),
                description: None,
                fault_tolerance: None,
                fee_sponsor_program_id: None,
            },
        ],
        routing_policy: RoutingPolicy {
            default_lane: Some(0),
            default_dataspace: Some("alpha".into()),
            rules: Vec::new(),
        },
        ..Nexus::default()
    };
    let parsed = nexus.parse(&mut emitter);
    assert!(
        parsed.is_none(),
        "mismatched default dataspace must be rejected"
    );
    let err = emitter
        .into_result()
        .expect_err("routing policy mismatch should surface parse errors");
    let debug = format!("{err:?}");
    assert!(
        debug.contains("routing default dataspace"),
        "error should mention mismatched default dataspace (got {debug})"
    );
}
#[test]
fn dataspace_fault_tolerance_zero_rejected() {
    use iroha_config::parameters::user::{DataSpaceDescriptor, LaneDescriptor, Nexus};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        dataspace_catalog: vec![DataSpaceDescriptor {
            alias: Some("alpha".into()),
            id: Some(1),
            manifest_hash: Some(
                "0100000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            description: None,
            fault_tolerance: Some(0),
            fee_sponsor_program_id: None,
        }],
        ..Nexus::default()
    };
    let parsed = nexus.parse(&mut emitter);
    assert!(parsed.is_none(), "fault_tolerance=0 must be rejected");
    let err = emitter.into_result().expect_err("parse error expected");
    let debug = strip_ansi_codes(&format!("{err:?}"));
    assert_contains!(debug, "fault_tolerance must be >= 1");
}
#[test]
fn dataspace_manifest_hash_required_for_non_universal() {
    use iroha_config::parameters::user::{DataSpaceDescriptor, Nexus};
    use iroha_config_base::util::Emitter;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        dataspace_catalog: vec![DataSpaceDescriptor {
            alias: Some("alpha".into()),
            id: Some(1),
            manifest_hash: None,
            description: None,
            fault_tolerance: None,
            fee_sponsor_program_id: None,
        }],
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let err = emitter.into_result().expect_err("parse error expected");
    let debug = strip_ansi_codes(&format!("{err:?}"));
    assert_contains!(debug, "must specify `manifest_hash`");
}
#[test]
fn dataspace_explicit_id_must_match_manifest_hash() {
    use iroha_config::parameters::user::{DataSpaceDescriptor, Nexus};
    use iroha_config_base::util::Emitter;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        dataspace_catalog: vec![DataSpaceDescriptor {
            alias: Some("alpha".into()),
            id: Some(1),
            manifest_hash: Some(
                "0200000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            description: None,
            fault_tolerance: None,
            fee_sponsor_program_id: None,
        }],
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let err = emitter.into_result().expect_err("parse error expected");
    let debug = strip_ansi_codes(&format!("{err:?}"));
    assert_contains!(debug, "does not match manifest_hash-derived id");
}
#[test]
fn dataspace_fee_sponsor_program_id_parses() {
    use iroha_config::parameters::user::{
        DataSpaceDescriptor, LaneDescriptor, Nexus, RoutingPolicy,
    };
    use iroha_config_base::util::Emitter;
    use iroha_model_base::topology::DataSpaceId;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let program_id = format!(
        "{}/default",
        defaults::nexus::fees::SPONSOR_VAULT_CUSTODY_ACCOUNT_ID
    );
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            dataspace: Some("alpha".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        dataspace_catalog: vec![DataSpaceDescriptor {
            alias: Some("alpha".into()),
            id: Some(1),
            manifest_hash: Some(
                "0100000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            description: None,
            fault_tolerance: None,
            fee_sponsor_program_id: Some(program_id.clone()),
        }],
        routing_policy: RoutingPolicy {
            default_lane: Some(0),
            default_dataspace: Some("alpha".into()),
            ..RoutingPolicy::default()
        },
        ..Nexus::default()
    };
    let parsed = nexus
        .parse(&mut emitter)
        .expect("dataspace fee sponsor should parse");
    assert!(emitter.into_result().is_ok());
    assert_eq!(
        parsed
            .dataspace_fee_sponsor_program_ids
            .get(&DataSpaceId::new(1))
            .map(ToString::to_string),
        Some(program_id)
    );
}
#[test]
fn dataspace_fee_sponsor_program_id_rejects_malformed_literal() {
    use iroha_config::parameters::user::{
        DataSpaceDescriptor, LaneDescriptor, Nexus, RoutingPolicy,
    };
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            dataspace: Some("alpha".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        dataspace_catalog: vec![DataSpaceDescriptor {
            alias: Some("alpha".into()),
            id: Some(1),
            manifest_hash: Some(
                "0100000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            description: None,
            fault_tolerance: None,
            fee_sponsor_program_id: Some("missing-program-separator".into()),
        }],
        routing_policy: RoutingPolicy {
            default_lane: Some(0),
            default_dataspace: Some("alpha".into()),
            ..RoutingPolicy::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let err = emitter.into_result().expect_err("parse error expected");
    let debug = strip_ansi_codes(&format!("{err:?}"));
    assert_contains!(debug, "fee_sponsor_program_id");
}
#[test]
fn routing_policy_unknown_dataspace_rejected() {
    use iroha_config::parameters::user::{LaneDescriptor, Nexus, RoutingPolicy};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        routing_policy: RoutingPolicy {
            default_lane: Some(0),
            default_dataspace: Some("unknown".into()),
            ..RoutingPolicy::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn lane_registry_rejects_zero_poll_interval() {
    use iroha_config::parameters::user::{LaneDescriptor, LaneRegistryConfig, Nexus};
    use iroha_config_base::util::Emitter;
    use std::{num::NonZeroU32, time::Duration};
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("core".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        registry: LaneRegistryConfig {
            poll_interval_ms: Duration::from_secs(0).into(),
            ..LaneRegistryConfig::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn governance_default_module_must_exist() {
    use iroha_config::parameters::user::{GovernanceCatalogConfig, LaneDescriptor, Nexus};
    use iroha_config_base::util::Emitter;
    use std::num::NonZeroU32;
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        governance: GovernanceCatalogConfig {
            default_module: Some("missing".into()),
            ..GovernanceCatalogConfig::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn governance_catalog_trims_and_parses_modules() {
    use iroha_config::parameters::user::{
        GovernanceCatalogConfig, GovernanceModule, LaneDescriptor, Nexus,
    };
    use iroha_config_base::util::Emitter;
    use std::{collections::BTreeMap, num::NonZeroU32};
    let mut modules = BTreeMap::new();
    modules.insert(
        " parliament ".into(),
        GovernanceModule {
            module_type: Some(" council ".into()),
            params: {
                let mut params = BTreeMap::new();
                params.insert(" quorum ".into(), " 67 ".into());
                params
            },
        },
    );
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        lane_count: NonZeroU32::new(1).expect("nonzero"),
        lane_catalog: vec![LaneDescriptor {
            index: Some(0),
            alias: Some("primary".into()),
            description: None,
            ..LaneDescriptor::default()
        }],
        governance: GovernanceCatalogConfig {
            default_module: Some("parliament".into()),
            modules,
        },
        ..Nexus::default()
    };
    let parsed = nexus.parse(&mut emitter).expect("governance should parse");
    assert!(emitter.into_result().is_ok());
    let catalog = parsed.governance;
    assert_eq!(catalog.default_module.as_deref(), Some("parliament"));
    let module = catalog
        .modules
        .get("parliament")
        .expect("module should be trimmed");
    assert_eq!(module.module_type.as_deref(), Some("council"));
    assert_eq!(module.params.get("quorum"), Some(&"67".to_string()));
}
#[test]
fn config_with_genesis() {
    let _config =
        load_config_from_fixtures("minimal_alone_with_genesis.toml").expect("should be valid");
}
#[test]
fn parse_does_not_apply_chain_discriminant_runtime_setting() {
    let _runtime_guard = AddressRuntimeGuard::capture();
    iroha_data_model::account::address::set_chain_discriminant(0x02F1);
    let config = load_config_from_fixtures("minimal_chain_discriminant.toml")
        .expect("config with chain discriminant should parse");
    assert_eq!(*config.common.chain_discriminant.value(), 777);
    assert_eq!(
        config.gov.bond_escrow_account,
        defaults::governance::bond_escrow_account_id()
    );
    assert_eq!(
        config.gov.citizenship_escrow_account,
        defaults::governance::citizenship_escrow_account_id()
    );
    assert_eq!(
        config.gov.slash_receiver_account,
        defaults::governance::slash_receiver_account_id()
    );
    assert_eq!(
        iroha_data_model::account::address::chain_discriminant(),
        0x02F1
    );
}
#[test]
fn self_is_presented_in_trusted_peers() {
    let config =
        load_config_from_fixtures("minimal_alone_with_genesis.toml").expect("valid config");
    assert!(
        config
            .common
            .trusted_peers
            .value()
            .clone()
            .into_non_empty_vec()
            .contains(config.common.peer.id())
    );
}
#[test]
fn missing_fields() {
    let error = load_config_from_fixtures("bad.missing_fields.toml")
        .expect_err("should fail without missing fields");
    let msg = strip_ansi_codes(&format!("{error:?}"));
    assert_contains!(msg, "missing parameter: `chain`");
    assert_contains!(msg, "missing parameter: `public_key`");
    assert_contains!(msg, "missing parameter: `network.address`");
}
#[test]
fn sorafs_penalty_and_telemetry_roundtrip() {
    let config = load_config_from_fixtures("sorafs_penalty_and_telemetry.toml")
        .expect("config should parse with SoraFS governance overrides");
    let penalty = config.gov.sorafs_penalty;
    assert_eq!(penalty.utilisation_floor_bps, 7600);
    assert_eq!(penalty.uptime_floor_bps, 9650);
    assert_eq!(penalty.por_success_floor_bps, 9800);
    assert_eq!(penalty.strike_threshold, 4);
    assert_eq!(penalty.penalty_bond_bps, 1800);
    assert_eq!(penalty.cooldown_windows, 3);
    assert_eq!(penalty.max_pdp_failures, 1);
    assert_eq!(penalty.max_potr_breaches, 2);
    assert_eq!(penalty.cooldown_window_secs(1_800), 5_400);
    let telemetry = &config.gov.sorafs_telemetry;
    assert!(!telemetry.require_submitter);
    assert!(telemetry.require_nonce);
    assert!(telemetry.reject_zero_capacity);
    assert_eq!(telemetry.max_window_gap, Duration::from_secs(7_200));
    let expected: Vec<_> = defaults::governance::sorafs_telemetry::submitters()
        .iter()
        .map(|id| AccountId::parse_encoded(id).expect("default submitter must parse"))
        .collect();
    assert_eq!(telemetry.submitters, expected);
}
#[test]
fn sorafs_penalty_unknown_field_rejected() {
    let error = load_config_from_fixtures("bad.sorafs_penalty_unknown.toml")
        .expect_err("unknown penalty field should be rejected");
    let msg = strip_ansi_codes(&format!("{error:?}"));
    assert_contains!(
        msg,
        "unknown parameter: `gov.sorafs_penalty.unexpected_penalty_knob`"
    );
}
#[test]
fn sorafs_telemetry_unknown_field_rejected() {
    let error = load_config_from_fixtures("bad.sorafs_telemetry_unknown.toml")
        .expect_err("unknown telemetry field should be rejected");
    let msg = strip_ansi_codes(&format!("{error:?}"));
    assert_contains!(
        msg,
        "unknown parameter: `gov.sorafs_telemetry.unknown_submitter_field`"
    );
}
#[test]
fn sorafs_site_binding_zero_entry_limit_is_rejected() {
    assert!(
        load_config_from_fixtures("bad.sorafs_site_bindings_zero_sites.toml").is_err(),
        "site binding entry limits must remain non-zero"
    );
}
/// Aims the purpose of checking that every single provided env variable is consumed and parsed
/// into a valid config.
#[test]
fn full_envs_set_is_consumed() {
    let env = test_env_from_file(fixtures_dir().join("full.env"));
    // Read, complete, and fully parse into the actual config to ensure all
    // env-backed fields (including nested sections) are queried and consumed.
    let config = ConfigReader::new()
        .with_env(env.clone())
        .read_and_complete::<UserConfig>()
        .expect("should be fine to read user view")
        .parse()
        .expect("should parse into actual config");
    assert_eq!(
        config.streaming.key_material.identity().algorithm(),
        iroha_crypto::Algorithm::Ed25519
    );
    // Ensure every provided variable was consumed by the reader.
    assert_eq!(env.unvisited(), HashSet::new());
    // NOTE: The config now includes many additional env-backed knobs with defaults
    // (e.g., `PIPELINE_*`, `NORITO_*`, `ZK_*`, etc.). The reader probes them even
    // if not present in the environment. That makes `env.unknown()` non-empty in
    // this test scenario. We intentionally no longer assert on `unknown()` here.
}
#[test]
fn config_from_file_and_env() {
    let env = test_env_from_file(fixtures_dir().join("minimal_file_and_env.env"));
    ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("minimal_file_and_env.toml"))
        .expect("files are fine")
        .read_and_complete::<UserConfig>()
        .expect("should be fine")
        .parse()
        .expect("should be fine, again");
}
#[test]
fn full_config_parses_fine() {
    let cfg = load_config_from_fixtures("full.toml").expect("should be fine");
    let sorafs = &cfg.torii.sorafs_discovery;
    println!("sorafs parsed {sorafs:?}");
    assert!(
        sorafs.discovery_enabled,
        "sorafs.discovery.discovery_enabled not parsed"
    );
    assert_eq!(
        sorafs.known_capabilities,
        vec![
            "torii_gateway".to_string(),
            "chunk_range_fetch".to_string(),
            "vendor_reserved".to_string()
        ]
    );
    assert_eq!(
        sorafs.replay_checkpoint_path,
        PathBuf::from("sorafs_discovery/test-provider-advert-replay.to")
    );
    assert_eq!(sorafs.replay_checkpoint_max_entries.get(), 4_096);
    assert!(
        sorafs.admission.is_some(),
        "native finalized admission is selected"
    );
    let alias_policy = cfg.torii.sorafs_alias_cache;
    assert_eq!(alias_policy.positive_ttl.as_secs(), 600);
    assert_eq!(alias_policy.refresh_window.as_secs(), 120);
    let site_bindings = &cfg.torii.sorafs_gateway.site_bindings;
    assert_eq!(
        site_bindings.path,
        Some(PathBuf::from("site-bindings/test.json"))
    );
    assert_eq!(site_bindings.max_bytes.get(), 4_096);
    assert_eq!(site_bindings.max_sites.get(), 7);
    let storage = &cfg.torii.sorafs_storage;
    assert!(storage.enabled, "sorafs.storage.enabled not parsed");
    assert_eq!(storage.data_dir, PathBuf::from("./storage/sorafs"));
    assert_eq!(storage.max_capacity_bytes.0, 107_374_182_400);
    assert_eq!(storage.max_parallel_fetches, 64);
    assert_eq!(storage.max_pins, 20000);
    assert_eq!(storage.por_sample_interval_secs, 900);
    assert_eq!(storage.alias.as_deref(), Some("tenant.alpha"));
    assert_eq!(
        storage.adverts.stake_pointer.as_deref(),
        Some("stake.pool.default")
    );
    assert_eq!(storage.adverts.availability, "warm");
    assert_eq!(storage.adverts.max_latency_ms, 750);
    assert_eq!(
        storage.adverts.topics,
        vec![
            "sorafs.sf1.primary:global".to_string(),
            "sorafs.sf1.backup:eu".to_string()
        ]
    );
}
#[test]
fn taira_storage_profile_matches_the_complete_preseed_budget() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("configs/soranexus/taira/config.toml");
    let raw = fs::read_to_string(config_path).expect("read Taira profile");
    let doc: TomlValue = toml::from_str(&raw).expect("parse Taira profile");
    let storage = &doc["nexus"]["storage"];
    assert_eq!(
        storage["local_budget_bytes"].as_integer(),
        Some(i64::try_from(defaults::taira::NEXUS_STORAGE_BUDGET_BYTES).unwrap())
    );
    assert_eq!(
        storage["max_wsv_memory_bytes"].as_integer(),
        Some(i64::try_from(defaults::taira::NEXUS_MAX_WSV_MEMORY_BYTES).unwrap())
    );
    for (name, expected) in [
        ("kura_blocks_bps", defaults::taira::NEXUS_KURA_BLOCKS_BPS),
        (
            "wsv_snapshots_bps",
            defaults::taira::NEXUS_WSV_SNAPSHOTS_BPS,
        ),
        ("sorafs_bps", defaults::taira::NEXUS_SORAFS_BPS),
    ] {
        assert_eq!(
            storage["disk_budget_weights"][name].as_integer(),
            Some(i64::from(expected))
        );
    }
    assert_eq!(doc["sorafs"]["storage"]["enabled"].as_bool(), Some(false));
    assert_eq!(
        doc["sorafs"]["storage"]["max_capacity_bytes"].as_integer(),
        Some(i64::try_from(defaults::taira::SORAFS_STORAGE_CAP_BYTES).unwrap())
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn taira_config_enables_untrusted_cid_hosting() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("configs/soranexus/taira/config.toml");
    let raw = fs::read_to_string(&config_path).expect("Taira config should exist");
    let doc: TomlValue = toml::from_str(&raw).expect("Taira config should be valid TOML");
    let network = doc
        .get("network")
        .and_then(TomlValue::as_table)
        .expect("Taira network config");
    let governance = doc
        .get("gov")
        .and_then(TomlValue::as_table)
        .expect("Taira governance config");
    assert_eq!(
        network
            .get("soranet_vpn")
            .and_then(TomlValue::as_table)
            .and_then(|vpn| vpn.get("operator_account_id")),
        governance.get("bond_escrow_account"),
        "the parsed disabled VPN profile must use the Taira-prefixed governance identity"
    );
    assert_eq!(
        governance.get("sorafs_pin_fee_treasury_account"),
        doc.get("nexus")
            .and_then(TomlValue::as_table)
            .and_then(|nexus| nexus.get("fees"))
            .and_then(TomlValue::as_table)
            .and_then(|fees| fees.get("fee_sink_account_id")),
        "the SoraFS pin-fee treasury must use the Taira-prefixed fee-sink identity"
    );
    assert!(
        doc.get("settlement")
            .and_then(TomlValue::as_table)
            .and_then(|settlement| settlement.get("offline"))
            .is_none(),
        "Taira must not model universal offline-wallet support as backend configuration"
    );
    let mcp = doc
        .get("torii")
        .and_then(TomlValue::as_table)
        .and_then(|torii| torii.get("mcp"))
        .and_then(TomlValue::as_table)
        .expect("torii.mcp should be configured");
    assert_eq!(
        mcp.get("enabled").and_then(TomlValue::as_bool),
        Some(true),
        "public Taira should expose MCP"
    );
    assert_eq!(
        mcp.get("profile").and_then(TomlValue::as_str),
        Some("writer"),
        "public Taira should expose the writer MCP profile"
    );
    assert_eq!(
        mcp.get("expose_operator_routes")
            .and_then(TomlValue::as_bool),
        Some(false),
        "public Taira must not expose operator MCP routes"
    );
    let allowed_tool_prefixes: Vec<_> = mcp
        .get("allow_tool_prefixes")
        .and_then(TomlValue::as_array)
        .expect("public Taira should configure MCP tool prefixes")
        .iter()
        .map(|prefix| {
            prefix
                .as_str()
                .expect("public Taira MCP tool prefixes should be strings")
        })
        .collect();
    assert_eq!(
        allowed_tool_prefixes,
        ["iroha."],
        "public Taira should expose only curated iroha.* MCP tools"
    );
    let dataspaces = doc
        .get("nexus")
        .and_then(TomlValue::as_table)
        .and_then(|nexus| nexus.get("dataspace_catalog"))
        .and_then(TomlValue::as_array)
        .expect("nexus.dataspace_catalog should be configured");
    let dataspace_aliases: Vec<_> = dataspaces
        .iter()
        .map(|entry| {
            entry
                .get("alias")
                .and_then(TomlValue::as_str)
                .expect("every Taira dataspace should have an alias")
        })
        .collect();
    assert_eq!(
        dataspace_aliases,
        ["universal", "dpn", "is2", "bpng", "cbsi", "is"],
        "only physically distinct validator/storage topologies belong in the dataspace catalog"
    );
    let universal = &dataspaces[0];
    assert_eq!(universal.get("id").and_then(TomlValue::as_integer), Some(0));
    assert!(universal.get("manifest_hash").is_none());
    for entry in &dataspaces[1..] {
        let alias = entry.get("alias").and_then(TomlValue::as_str).unwrap();
        let name_hash = iroha_data_model::sns::NameSelectorV1::new(
            iroha_data_model::sns::DATASPACE_ALIAS_SUFFIX_ID,
            alias,
        )
        .expect("canonical SNS dataspace alias")
        .name_hash();
        assert_eq!(
            entry.get("manifest_hash").and_then(TomlValue::as_str),
            Some(hex::encode(name_hash).as_str()),
            "{alias} must retain its full canonical SNS dataspace identity"
        );
        assert!(
            entry.get("id").is_none(),
            "{alias} must derive its identity from the full manifest hash"
        );
    }
    let nexus = doc
        .get("nexus")
        .and_then(TomlValue::as_table)
        .expect("nexus should be configured");
    assert_eq!(
        nexus.get("lane_count").and_then(TomlValue::as_integer),
        Some(8),
        "Taira profile should reserve one logical lane for every configured workload"
    );
    let lanes = nexus
        .get("lane_catalog")
        .and_then(TomlValue::as_array)
        .expect("nexus.lane_catalog should be configured");
    let lane_bindings: Vec<_> = lanes
        .iter()
        .map(|lane| {
            (
                lane.get("alias")
                    .and_then(TomlValue::as_str)
                    .expect("every Taira lane should have an alias"),
                lane.get("dataspace")
                    .and_then(TomlValue::as_str)
                    .expect("every Taira lane should bind to a dataspace"),
            )
        })
        .collect();
    assert_eq!(
        lane_bindings,
        [
            ("core", "universal"),
            ("governance", "universal"),
            ("zk", "universal"),
            ("dpn", "dpn"),
            ("is2", "is2"),
            ("bpng", "bpng"),
            ("cbsi", "cbsi"),
            ("is", "is"),
        ],
        "logical lanes must bind to physical dataspaces without conflating the two catalogs"
    );
    let routing_rules = nexus
        .get("routing_policy")
        .and_then(TomlValue::as_table)
        .and_then(|policy| policy.get("rules"))
        .and_then(TomlValue::as_array)
        .expect("nexus.routing_policy.rules should be configured");
    let has_instruction_route = |instruction: &str, lane: i64, dataspace: &str| {
        routing_rules.iter().any(|rule| {
            rule.get("lane").and_then(TomlValue::as_integer) == Some(lane)
                && rule.get("dataspace").and_then(TomlValue::as_str) == Some(dataspace)
                && rule
                    .get("matcher")
                    .and_then(TomlValue::as_table)
                    .and_then(|matcher| matcher.get("instruction"))
                    .and_then(TomlValue::as_str)
                    == Some(instruction)
        })
    };
    assert!(
        has_instruction_route("governance", 1, "universal"),
        "Taira should route governance instructions to its lane within universal"
    );
    assert!(
        has_instruction_route("smartcontract::deploy", 2, "universal"),
        "Taira should route smart-contract deployments to its zk lane within universal"
    );
    for retired in ["shield", "zk::zk_transfer", "unshield"] {
        assert!(
            !routing_rules.iter().any(|rule| {
                rule.get("matcher")
                    .and_then(TomlValue::as_table)
                    .and_then(|matcher| matcher.get("instruction"))
                    .and_then(TomlValue::as_str)
                    == Some(retired)
            }),
            "Taira profile must not retain retired generic confidential route {retired}"
        );
    }
    let sumeragi = doc
        .get("sumeragi")
        .and_then(TomlValue::as_table)
        .expect("Taira node-local Sumeragi configuration");
    assert_eq!(
        sumeragi.keys().map(String::as_str).collect::<Vec<_>>(),
        ["role"],
        "Taira configures only the node-local Sumeragi role; block limits come from chain parameters"
    );
    let parsed = ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(sumeragi.clone()))
        .read_and_complete::<iroha_config::parameters::user::Sumeragi>()
        .expect("Taira Sumeragi section must pass the exact current schema");
    assert!(matches!(
        parsed.role,
        iroha_config::parameters::user::NodeRole::Validator
    ));
    assert!(
        sumeragi.get("block").is_none(),
        "proposal limits belong to committed chain policy"
    );
    assert!(
        sumeragi.get("queues").is_none(),
        "retired ingress queues have no runtime owner"
    );
    let untrusted = doc
        .get("sorafs")
        .and_then(TomlValue::as_table)
        .and_then(|sorafs| sorafs.get("gateway"))
        .and_then(TomlValue::as_table)
        .and_then(|gateway| gateway.get("untrusted_hosting"))
        .and_then(TomlValue::as_table)
        .expect("sorafs.gateway.untrusted_hosting should be configured");
    assert_eq!(
        untrusted.get("enabled").and_then(TomlValue::as_bool),
        Some(true),
        "Taira profile should enable CID-host routing"
    );
    assert_eq!(
        untrusted
            .get("path_gateway_redirect")
            .and_then(TomlValue::as_bool),
        Some(true)
    );
    assert_eq!(
        untrusted
            .get("redirect_html_only")
            .and_then(TomlValue::as_bool),
        Some(true)
    );
    let suffixes = untrusted
        .get("cid_host_suffixes")
        .and_then(TomlValue::as_table)
        .expect("CID host suffixes should be configured");
    assert_eq!(
        suffixes.get("live").and_then(TomlValue::as_str),
        Some("sorafs.sora.org")
    );
    assert_eq!(
        suffixes.get("taira").and_then(TomlValue::as_str),
        Some("sorafs.taira.sora.org")
    );
    let runtime = doc
        .get("soracloud_runtime")
        .and_then(TomlValue::as_table)
        .expect("soracloud_runtime should be configured");
    assert_eq!(
        runtime.get("production_mode").and_then(TomlValue::as_bool),
        Some(true),
        "Taira profile should run the Soracloud runtime in production posture"
    );
    assert_eq!(
        runtime
            .get("hydration_concurrency")
            .and_then(TomlValue::as_integer),
        Some(i64::try_from(defaults::taira::HYDRATION_CONCURRENCY).unwrap()),
        "Taira must pin the first-release artifact hydration worker bound"
    );
    assert_eq!(
        runtime
            .get("prepared_runtime_cache_capacity")
            .and_then(TomlValue::as_integer),
        Some(i64::try_from(defaults::taira::PREPARED_RUNTIME_CACHE_CAPACITY).unwrap()),
        "Taira must pin the independent first-release prepared-runtime cache bound"
    );
    let inrou = runtime
        .get("inrou")
        .and_then(TomlValue::as_table)
        .expect("the checked Taira profile must enable PortableVM V1 hosting");
    assert_eq!(
        inrou.get("enabled").and_then(TomlValue::as_bool),
        Some(true),
        "the checked Taira profile must enable its sole first-release backend"
    );
    for (field, expected) in [
        ("portable_vm_uid", 70_000),
        ("portable_vm_gid", 70_000),
        (
            "guest_image_max_bytes",
            i64::try_from(defaults::taira::INROU_GUEST_IMAGE_MAX_BYTES).unwrap(),
        ),
        (
            "max_cpu_millis",
            i64::from(defaults::taira::INROU_MAX_CPU_MILLIS),
        ),
        (
            "max_memory_bytes",
            i64::try_from(defaults::taira::INROU_MAX_MEMORY_BYTES).unwrap(),
        ),
        (
            "max_storage_bytes",
            i64::try_from(defaults::taira::INROU_MAX_STORAGE_BYTES).unwrap(),
        ),
    ] {
        assert_eq!(
            inrou.get(field).and_then(TomlValue::as_integer),
            Some(expected),
            "Taira must pin the exact PortableVM V1 `{field}` value"
        );
    }
    for retired in [
        "backends",
        "max_concurrent_vms",
        "portable_vm_acceleration",
        "portable_vm_supplementary_gids",
    ] {
        assert!(
            !inrou.contains_key(retired),
            "Taira must not retain retired Inrou selector `{retired}`"
        );
    }
    let egress = runtime
        .get("egress")
        .and_then(TomlValue::as_table)
        .expect("Taira must configure Soracloud egress budgets");
    assert_eq!(
        egress.get("default_allow").and_then(TomlValue::as_bool),
        Some(false)
    );
    assert_eq!(
        egress
            .get("rate_per_minute")
            .and_then(TomlValue::as_integer),
        Some(600)
    );
    assert_eq!(
        egress
            .get("max_bytes_per_minute")
            .and_then(TomlValue::as_integer),
        Some(100 * 1024 * 1024)
    );
    assert_eq!(
        runtime
            .get("submission")
            .and_then(TomlValue::as_table)
            .and_then(|submission| submission.get("fee_payer"))
            .and_then(TomlValue::as_str),
        Some("sponsor"),
        "Taira Soracloud submissions should use the exact genesis sponsor program"
    );
}
#[test]
fn crypto_section_defaults_applied() {
    use iroha_crypto::Algorithm;
    let cfg = load_config_from_fixtures("minimal_with_trusted_peers.toml")
        .expect("minimal config should be valid");
    let crypto = &cfg.crypto;
    assert_eq!(
        crypto.enable_sm_openssl_preview,
        defaults::crypto::ENABLE_SM_OPENSSL_PREVIEW
    );
    assert_eq!(crypto.default_hash, defaults::crypto::DEFAULT_HASH);
    assert_eq!(
        crypto.allowed_signing,
        vec![Algorithm::Ed25519, Algorithm::Secp256k1]
    );
    assert_eq!(
        crypto.sm2_distid_default,
        defaults::crypto::SM2_DISTID_DEFAULT
    );
    assert_eq!(crypto.allowed_curve_ids, vec![1, 4]);
}
#[test]
fn crypto_section_respects_env_overrides() {
    use iroha_crypto::Algorithm;
    let (default_hash, allowed_signing_env) = if cfg!(feature = "sm") {
        ("sm3-256", "ed25519,secp256k1,sm2")
    } else {
        ("blake2b-256", "ed25519,secp256k1")
    };
    let mut env = MockEnv::new()
        .set("CRYPTO_DEFAULT_HASH", default_hash)
        .set("CRYPTO_ALLOWED_SIGNING", allowed_signing_env)
        .set("CRYPTO_SM2_DISTID_DEFAULT", "CN12345678901234")
        .set("CRYPTO_CURVES_ALLOWED_IDS", "1,4");
    env = env.set(
        "CRYPTO_SM_OPENSSL_PREVIEW",
        if cfg!(feature = "sm-ffi-openssl") {
            "true"
        } else {
            "false"
        },
    );
    let cfg = ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
        .expect("base file should be valid")
        .read_and_complete::<UserConfig>()
        .expect("user view with env overrides")
        .parse()
        .expect("actual config with env overrides");
    let crypto = &cfg.crypto;
    assert_eq!(crypto.default_hash, default_hash);
    assert_eq!(crypto.sm2_distid_default, "CN12345678901234");
    assert_eq!(
        crypto.enable_sm_openssl_preview,
        cfg!(feature = "sm-ffi-openssl")
    );
    #[cfg(feature = "sm")]
    assert_eq!(
        crypto.allowed_signing,
        vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::Sm2]
    );
    #[cfg(not(feature = "sm"))]
    assert_eq!(
        crypto.allowed_signing,
        vec![Algorithm::Ed25519, Algorithm::Secp256k1]
    );
    assert_eq!(crypto.allowed_curve_ids, vec![1, 4]);
}
#[test]
fn fraud_monitoring_config_overrides_and_defaults() {
    let cfg = load_config_from_fixtures("fraud_monitoring.toml")
        .expect("fraud monitoring config should parse");
    let fraud = &cfg.fraud_monitoring;
    assert!(!fraud.policy.enabled);
    let endpoints: Vec<&str> = fraud.service_endpoints.iter().map(Url::as_str).collect();
    assert_eq!(
        endpoints,
        vec![
            "https://fraud.local/assess",
            "https://fraud.secondary/verify"
        ],
    );
    assert_eq!(
        fraud.connect_timeout,
        defaults::fraud_monitoring::CONNECT_TIMEOUT,
    );
    assert_eq!(fraud.request_timeout, Duration::from_millis(1_800));
    assert!(!fraud.policy.missing_assessment_permitted);
    assert!(fraud.policy.required_minimum_band.is_none());
    assert!(fraud.policy.attesters.is_empty());
}
#[test]
fn fraud_monitoring_rejects_node_local_validity_policy() {
    for (field, value) in [
        ("enabled", "true"),
        ("required_minimum_band", "'high'"),
        ("missing_assessment_grace_secs", "1"),
        ("missing_assessment_permitted", "true"),
        ("attesters", "[]"),
    ] {
        let table = format!("[fraud_monitoring]\n{field} = {value}\n")
            .parse()
            .unwrap();
        let error = ConfigReader::new()
            .read_toml_with_extends(fixtures_dir().join("base.toml"))
            .unwrap()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<UserConfig>()
            .expect_err("admission policy is committed state, never node configuration");
        let report = strip_ansi_codes(&format!("{error:?}"));
        assert!(
            report.contains(&format!("unknown parameter: `fraud_monitoring.{field}`")),
            "{report}"
        );
    }
}
#[test]
fn sumeragi_explicit_schema_parses() {
    use iroha_config::parameters::actual::NodeRole;
    let cfg = load_config_from_fixtures("sumeragi.toml")
        .expect("explicit Sumeragi configuration should parse");
    assert_eq!(
        cfg.network
            .max_total_connections
            .map(std::num::NonZeroUsize::get),
        Some(32)
    );
    assert_eq!(cfg.sumeragi.role, NodeRole::Observer);
    assert_eq!(cfg.sumeragi.keys.activation_lead_blocks, 2);
    assert_eq!(cfg.sumeragi.keys.overlap_grace_blocks, 12);
    assert_eq!(cfg.sumeragi.keys.expiry_grace_blocks, 3);
    assert_eq!(cfg.sumeragi.local.t_base, Some(Duration::from_millis(400)));
    assert_eq!(cfg.sumeragi.local.sync_batch, Some(64));
    assert_eq!(cfg.sumeragi.local.max_observers, Some(16));
    assert_eq!(cfg.sumeragi.local.t_max, None);
}
#[test]
fn sumeragi_does_not_accept_retired_environment_toggles() {
    let baseline = ConfigReader::new()
        .with_env(MockEnv::new())
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("base file should be valid")
        .read_and_complete::<UserConfig>()
        .expect("read user config")
        .parse()
        .expect("parse actual config");
    let with_retired_env = ConfigReader::new()
        .with_env(
            MockEnv::new()
                .set("SUMERAGI_COLLECTORS_K", "99")
                .set("SUMERAGI_VNEXT_SUSPICION_TIMEOUT_MS", "1")
                .set("SUMERAGI_RBC_CHUNK_MAX_BYTES", "1"),
        )
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("base file should be valid")
        .read_and_complete::<UserConfig>()
        .expect("retired environment names are not schema inputs")
        .parse()
        .expect("retired environment names cannot alter the Sumeragi config");
    assert_eq!(baseline.sumeragi.role, with_retired_env.sumeragi.role);
    assert_eq!(baseline.sumeragi.local, with_retired_env.sumeragi.local);
    assert_eq!(
        baseline.sumeragi.keys.allowed_algorithms,
        with_retired_env.sumeragi.keys.allowed_algorithms
    );
}
#[cfg(feature = "gost")]
#[test]
fn gost_config_rejects_tc26_consensus_keys() {
    let error = load_config_from_fixtures("gost_with_trusted_peers.toml")
        .expect_err("gost consensus keys should be rejected");
    let message = strip_ansi_codes(&format!("{error:?}"));
    assert_contains!(
        message,
        "public_key/private_key must be BLS-normal for consensus"
    );
}
#[test]
fn pipeline_workers_env_parses() {
    use iroha_config::parameters::{actual::Root as Actual, user::Root as User};
    use iroha_config_base::env::MockEnv;
    // Default: use minimal base file so required params are satisfied,
    // then ensure workers fall back to defaults (0 = auto)
    let cfg = ConfigReader::new()
        .with_env(MockEnv::new())
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("base file should be valid")
        .read_and_complete::<User>()
        .expect("user view")
        .parse();
    assert!(cfg.is_ok());
    // Override via env
    let env = MockEnv::new().set("PIPELINE_WORKERS", "7");
    let cfg2: Actual = ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("base file should be valid")
        .read_and_complete::<User>()
        .expect("read user config with env")
        .parse()
        .expect("parse actual config with env");
    assert_eq!(cfg2.pipeline.workers, 7);
}
#[test]
fn logger_level_env_accepts_lowercase() {
    use iroha_config::{
        logger::Level,
        parameters::{actual::Root as Actual, user::Root as User},
    };
    use iroha_config_base::env::MockEnv;
    let env = MockEnv::new().set("LOG_LEVEL", "info");
    let cfg: Actual = ConfigReader::new()
        .with_env(env)
        .read_toml_with_extends(fixtures_dir().join("base.toml"))
        .expect("base file should be valid")
        .read_and_complete::<User>()
        .expect("user config with env")
        .parse()
        .expect("actual config with lowercase log level env");
    assert_eq!(cfg.logger.level, Level::INFO);
}
include!("fixtures/tls_fallback_defaults_test.rs");
include!("fixtures/trusted_proxy_defaults_test.rs");
include!("fixtures/torii_internal_api_trust_defaults_test.rs");
include!("fixtures/network_frame_defaults_test.rs");
// type alias used through fixtures for newer error-stack API
type Result<T, E> = core::result::Result<T, Report<E>>;

#[test]
fn nexus_carrier_shell_pool_preserves_zero_and_explicit_limit() {
    use iroha_config::parameters::user::{Nexus, NexusStorage};
    use iroha_config_base::util::Emitter;
    for limit in [0, 1, 16 * 1024 * 1024] {
        let mut emitter = Emitter::<ParseError>::new();
        let nexus = Nexus {
            storage: NexusStorage {
                retained_carrier_shell_bytes: limit,
                ..NexusStorage::default()
            },
            ..Nexus::default()
        };
        let actual = nexus
            .parse(&mut emitter)
            .expect("explicit finite shell pool parses");
        emitter.into_result().expect("valid shell pool");
        assert_eq!(actual.storage.retained_carrier_shell_bytes, limit);
    }
}

#[test]
fn nexus_evidence_preparation_pool_covers_all_offenders_and_local_observations() {
    use iroha_config::parameters::{
        defaults,
        user::{Nexus, NexusStorage},
    };
    use iroha_config_base::util::Emitter;

    let prune_plan = defaults::nexus::storage::CONSENSUS_EVIDENCE_PRUNE_PLAN_BYTES;
    let pending_plan = defaults::nexus::storage::CONSENSUS_EVIDENCE_PENDING_PLAN_BYTES;
    let pending_peer_keys =
        defaults::nexus::storage::CONSENSUS_EVIDENCE_PENDING_PEER_KEYS_MAX_BYTES;
    let one_plan = defaults::nexus::storage::CONSENSUS_EVIDENCE_ONE_PLAN_BYTES;
    assert_eq!(prune_plan, 3_968);
    assert_eq!(
        pending_plan,
        4 * 31
            * iroha_data_model::sumeragi_lanes::MAX_LANE_CUSTODY_SIGNERS
            * std::mem::size_of::<defaults::nexus::storage::ConsensusPenaltyPendingEntry>()
    );
    assert_eq!(
        defaults::nexus::storage::CONSENSUS_EVIDENCE_PENDING_PEER_KEY_BYTES,
        49
    );
    assert_eq!(
        pending_peer_keys,
        4 * 31
            * iroha_data_model::sumeragi_lanes::MAX_LANE_CUSTODY_SIGNERS
            * defaults::nexus::storage::CONSENSUS_EVIDENCE_PENDING_PEER_KEY_BYTES
    );
    assert_eq!(one_plan, prune_plan + pending_plan + pending_peer_keys);
    assert_eq!(
        NexusStorage::default().consensus_evidence_preparation_bytes,
        8 * one_plan + 9 * 1024 * 1024
    );
    for bytes in [one_plan, 8 * one_plan] {
        let mut emitter = Emitter::<ParseError>::new();
        let nexus = Nexus {
            storage: NexusStorage {
                consensus_evidence_preparation_bytes: bytes,
                ..NexusStorage::default()
            },
            ..Nexus::default()
        };
        let actual = nexus
            .parse(&mut emitter)
            .expect("one or more complete plans");
        emitter.into_result().expect("valid finite pool");
        assert_eq!(actual.storage.consensus_evidence_preparation_bytes, bytes);
    }

    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        storage: NexusStorage {
            consensus_evidence_preparation_bytes: one_plan - 1,
            ..NexusStorage::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let error = emitter.into_result().expect_err("partial plan must fail");
    let expected = format!(
        "nexus.storage.consensus_evidence_preparation_bytes must be at least {one_plan} bytes"
    );
    assert_contains!(strip_ansi_codes(&format!("{error:?}")), expected.as_str());
}

#[test]
fn nexus_stake_index_pool_is_finite_and_admits_one_share_group_and_account_keys() {
    use iroha_config::parameters::{
        defaults,
        user::{Nexus, NexusStorage},
    };
    use iroha_config_base::util::Emitter;

    let minimum = defaults::nexus::storage::CONSENSUS_STAKE_INDEX_MIN_BYTES;
    assert_eq!(
        NexusStorage::default().consensus_stake_index_bytes,
        defaults::nexus::storage::CONSENSUS_STAKE_INDEX_BYTES
    );
    for bytes in [
        minimum,
        defaults::nexus::storage::CONSENSUS_STAKE_INDEX_BYTES,
    ] {
        let mut emitter = Emitter::<ParseError>::new();
        let nexus = Nexus {
            storage: NexusStorage {
                consensus_stake_index_bytes: bytes,
                ..NexusStorage::default()
            },
            ..Nexus::default()
        };
        let actual = nexus
            .parse(&mut emitter)
            .expect("one share, group and three Ed25519 key copies fit");
        emitter.into_result().expect("valid finite index pool");
        assert_eq!(actual.storage.consensus_stake_index_bytes, bytes);
    }
    let mut emitter = Emitter::<ParseError>::new();
    let nexus = Nexus {
        storage: NexusStorage {
            consensus_stake_index_bytes: minimum - 1,
            ..NexusStorage::default()
        },
        ..Nexus::default()
    };
    assert!(nexus.parse(&mut emitter).is_none());
    let error = emitter
        .into_result()
        .expect_err("partial nested-and-flat backing must fail");
    let expected =
        format!("nexus.storage.consensus_stake_index_bytes must be at least {minimum} bytes");
    assert_contains!(strip_ansi_codes(&format!("{error:?}")), expected.as_str());
}

#[test]
fn sumeragi_local_overrides_parse_and_the_retired_seed_descriptor_is_unknown() {
    use iroha_config::parameters::user::Root as User;

    let read = |overrides: &str| {
        ConfigReader::new()
            .read_toml_with_extends(fixtures_dir().join("base.toml"))
            .expect("base fixture")
            .with_toml_source(TomlSource::inline(
                overrides.parse::<Table>().expect("sumeragi overrides"),
            ))
            .read_and_complete::<User>()
    };
    let config = read("[sumeragi]\nrole = \"validator\"\nview_timeout_base_ms = 250\n")
        .expect("user config")
        .parse()
        .expect("validator timing override");
    assert_eq!(
        config.sumeragi.local.t_base,
        Some(Duration::from_millis(250))
    );

    let error = read("[sumeragi]\nrole = \"validator\"\nmint_finality_seed_fd = 199\n")
        .expect_err("the retired seed descriptor is not a configuration parameter");
    assert_contains!(
        strip_ansi_codes(&format!("{error:?}")),
        "unknown parameter: `sumeragi.mint_finality_seed_fd`"
    );
}

#[test]
fn credential_registry_memory_budget_is_configured_and_nonzero() {
    let parse = |extra: &str| {
        ConfigReader::new()
            .without_env()
            .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
            .unwrap()
            .with_toml_source(TomlSource::inline(extra.parse().unwrap()))
            .read_and_complete::<UserConfig>()
            .map(UserConfig::parse)
    };
    let default = parse("").unwrap().unwrap();
    assert_eq!(
        default.runtime_provider_broker.credential_max_memory_bytes,
        defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
    );
    let explicit = parse("[runtime_provider_broker]\ncredential_max_memory_bytes = 123456\n")
        .unwrap()
        .unwrap();
    assert_eq!(
        explicit
            .runtime_provider_broker
            .credential_max_memory_bytes
            .get(),
        123_456
    );
    assert!(parse("[runtime_provider_broker]\ncredential_max_memory_bytes = 0\n").is_err());
}

#[test]
fn standalone_credential_registry_policy_matches_root_and_is_strict() {
    use iroha_config::parameters::actual::RuntimeProviderBroker;

    let parse = |table: &str| {
        RuntimeProviderBroker::from_toml_source(TomlSource::inline(table.parse().unwrap()))
    };
    let default = parse("").expect("default broker policy without a node config");
    assert_eq!(
        default.credential_max_memory_bytes,
        defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
    );
    let table = "credential_max_memory_bytes = 123456\nendpoint_path = '/tmp/runtime-provider-broker-v1.sock'\n";
    let standalone = parse(table).expect("standalone broker policy");
    let root = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
        .unwrap()
        .with_toml_source(TomlSource::inline(
            format!("[runtime_provider_broker]\n{table}")
                .parse()
                .unwrap(),
        ))
        .read_and_complete::<UserConfig>()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(standalone, root.runtime_provider_broker);
    for invalid in [
        "credential_max_memory_bytes = 0",
        "credential_max_memory_byte = 123456",
        "endpoint_path = 'relative/runtime-provider-broker-v1.sock'",
        "endpoint_path = '/tmp/wrong.sock'",
        "extends = '/missing/broker-policy.toml'",
        "private_key_file = '/missing/private-key'",
    ] {
        assert!(
            parse(invalid).is_err(),
            "accepted invalid broker table: {invalid}"
        );
    }
}

/// Node and standalone broker policies share one finite file-configured operation bound.
#[test]
fn broker_observer_operation_timeout_is_finite_and_shared_with_standalone_policy() {
    use iroha_config::parameters::actual::RuntimeProviderBroker;

    let parse = |milliseconds: Option<u64>| {
        let fields = milliseconds.map_or_else(String::new, |value| {
            format!("observer_operation_timeout_ms = {value}\n")
        });
        RuntimeProviderBroker::from_toml_source(TomlSource::inline(
            fields.parse().expect("broker policy TOML"),
        ))
    };
    assert_eq!(
        parse(None).unwrap().observer_operation_timeout,
        defaults::runtime_provider_broker::OBSERVER_OPERATION_TIMEOUT
    );
    for milliseconds in [1, 4_000, 15_000] {
        let standalone = parse(Some(milliseconds)).unwrap();
        let root = ConfigReader::new()
            .without_env()
            .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
            .unwrap()
            .with_toml_source(TomlSource::inline(
                format!(
                    "[runtime_provider_broker]\nobserver_operation_timeout_ms = {milliseconds}\n"
                )
                .parse()
                .unwrap(),
            ))
            .read_and_complete::<UserConfig>()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(standalone, root.runtime_provider_broker);
        assert_eq!(
            standalone.observer_operation_timeout,
            Duration::from_millis(milliseconds)
        );
    }
    for milliseconds in [0, 15_001, 9_223_372_036_854_775_807] {
        assert!(parse(Some(milliseconds)).is_err());
        let parsed = ConfigReader::new()
            .without_env()
            .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
            .unwrap()
            .with_toml_source(TomlSource::inline(
                format!(
                    "[runtime_provider_broker]\nobserver_operation_timeout_ms = {milliseconds}\n"
                )
                .parse()
                .unwrap(),
            ))
            .read_and_complete::<UserConfig>()
            .unwrap()
            .parse();
        assert!(
            parsed.is_err(),
            "node policy accepted invalid operation bound {milliseconds}"
        );
    }
    assert!(
        RuntimeProviderBroker::from_toml_source(TomlSource::inline(
            "observer_operation_timeout = 1".parse().unwrap(),
        ))
        .is_err()
    );
}

/// Runtime broker policy values have no environment selector or override.
#[test]
fn broker_observer_operation_timeout_ignores_environment_overrides() {
    let env = MockEnv::new()
        .set("RUNTIME_PROVIDER_BROKER_OBSERVER_OPERATION_TIMEOUT_MS", "1")
        .set("RUNTIME_PROVIDER_BROKER_ENDPOINT_PATH", "/tmp/wrong.sock")
        .set("RUNTIME_PROVIDER_BROKER_CREDENTIAL_MAX_MEMORY_BYTES", "0");
    for (table, expected) in [
        ("", 15_000),
        (
            "[runtime_provider_broker]\nobserver_operation_timeout_ms = 4000\n",
            4_000,
        ),
    ] {
        let root = ConfigReader::new()
            .with_env(env.clone())
            .read_toml_with_extends(fixtures_dir().join("minimal_with_trusted_peers.toml"))
            .unwrap()
            .with_toml_source(TomlSource::inline(table.parse().unwrap()))
            .read_and_complete::<UserConfig>()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            root.runtime_provider_broker.observer_operation_timeout,
            Duration::from_millis(expected)
        );
        assert_eq!(
            root.runtime_provider_broker.endpoint_path.as_path(),
            defaults::runtime_provider_broker::endpoint_path()
        );
        assert_eq!(
            root.runtime_provider_broker.credential_max_memory_bytes,
            defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES
        );
    }
    assert_eq!(
        env.unvisited(),
        std::collections::HashSet::from([
            "RUNTIME_PROVIDER_BROKER_OBSERVER_OPERATION_TIMEOUT_MS".to_owned(),
            "RUNTIME_PROVIDER_BROKER_ENDPOINT_PATH".to_owned(),
            "RUNTIME_PROVIDER_BROKER_CREDENTIAL_MAX_MEMORY_BYTES".to_owned(),
        ])
    );
}
