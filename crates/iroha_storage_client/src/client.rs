//! Storage orchestration layered over the protocol-only Iroha client.

use crate::da::{
    DaManifestBundle, DaManifestPersistedPaths, DaProofArtifactMetadata, DaProofConfig,
    build_car_plan_from_manifest, generate_da_proof_artifact, generate_da_proof_summary,
};
use eyre::{Result, WrapErr, eyre};
use iroha::client::Client;
use iroha_data_model::da::types::StorageTicketId;
use iroha_service_model::soranet::{AnonymityPolicy, TransportPolicy, WriteModeHint};
use norito::json::{Map as JsonMap, Value as JsonValue};
use sorafs_orchestrator::{
    OrchestratorConfig, PolicyOverride, fetch_via_gateway as orchestrator_fetch_via_gateway,
    prelude::{
        CarBuildPlan, FetchSession as SorafsFetchOutcome,
        GatewayFetchConfig as SorafsGatewayFetchConfig,
        GatewayProviderInput as SorafsGatewayProviderInput, GuardSet, RelayDirectory,
    },
};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[cfg(test)]
mod da_tests;

/// Optional tuning knobs applied when orchestrating `SoraFS` gateway fetches.
#[derive(Debug, Default, Clone)]
pub struct SorafsGatewayFetchOptions {
    /// Maximum retry attempts per chunk before aborting the session.
    pub retry_budget: Option<usize>,
    /// Hard cap on the number of providers used in a session.
    pub max_peers: Option<usize>,
    /// Override the telemetry region label emitted with orchestrator metrics.
    pub telemetry_region: Option<String>,
    /// Override the default transport policy.
    pub transport_policy: Option<TransportPolicy>,
    /// Override the staged anonymity policy applied to `SoraNet` providers.
    pub anonymity_policy: Option<AnonymityPolicy>,
    /// Optional guard cache describing pinned `SoraNet` relays.
    pub guard_set: Option<GuardSet>,
    /// Optional `SoraNet` directory describing available relays.
    pub relay_directory: Option<RelayDirectory>,
    /// Optional write-mode hint to tighten PQ requirements.
    pub write_mode_hint: Option<WriteModeHint>,
    /// Explicit transport or anonymity policy overrides.
    pub policy_override: PolicyOverride,
    /// Optional scoreboard controls used for adoption evidence.
    pub scoreboard: Option<SorafsGatewayScoreboardOptions>,
    /// Expected cache version advertised by successful gateway responses.
    pub expected_cache_version: Option<String>,
}

/// Scoreboard persistence and evaluation overrides for gateway fetches.
#[derive(Debug, Default, Clone)]
pub struct SorafsGatewayScoreboardOptions {
    /// Persist the scoreboard JSON artefact to this path.
    pub persist_path: Option<PathBuf>,
    /// Override the Unix timestamp used when evaluating adverts.
    pub now_unix_secs: Option<u64>,
    /// Optional JSON metadata persisted alongside scoreboard entries.
    pub metadata: Option<JsonValue>,
    /// Label describing the telemetry stream that produced the snapshot.
    pub telemetry_source_label: Option<String>,
}

/// Errors returned by an orchestrated `SoraFS` fetch.
#[derive(Debug, Error)]
pub enum SorafsFetchError {
    /// Gateway or orchestrator failure.
    #[error(transparent)]
    Orchestrator(#[from] sorafs_orchestrator::GatewayOrchestratorError),
}

/// Aggregated artefacts returned by [`StorageClient::prove_da_availability`].
#[derive(Debug, Clone)]
pub struct DaAvailabilityProof {
    /// Manifest and chunk-plan bundle used for verification.
    pub manifest: DaManifestBundle,
    /// Detailed orchestrator session with chunk receipts and provider telemetry.
    pub fetch_session: SorafsFetchOutcome,
    /// `PoR` summary matching the CLI output schema.
    pub proof_summary: JsonValue,
    /// Sampling configuration used to derive the proof summary.
    pub proof_config: DaProofConfig,
}

/// File-system artefacts produced for a DA availability proof.
#[derive(Debug, Clone)]
pub struct DaAvailabilityProofPersistedPaths {
    /// Paths to the manifest artefacts.
    pub manifest: DaManifestPersistedPaths,
    /// Path to the assembled gateway payload.
    pub payload_path: PathBuf,
    /// Path to the rendered proof summary.
    pub proof_summary_path: PathBuf,
    /// Path to the persisted scoreboard, when enabled.
    pub scoreboard_path: Option<PathBuf>,
}

/// Storage-specific operations layered over a borrowed Iroha protocol client.
#[derive(Clone, Copy, Debug)]
pub struct StorageClient<'client> {
    client: &'client Client,
}

impl<'client> StorageClient<'client> {
    /// Borrow an Iroha client for storage operations.
    #[must_use]
    pub const fn new(client: &'client Client) -> Self {
        Self { client }
    }

    /// Fetch and validate a DA manifest bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the manifest and chunk plan are invalid.
    pub async fn da_manifest(&self, storage_ticket: &StorageTicketId) -> Result<DaManifestBundle> {
        let response = self.client.da().manifest(storage_ticket).await?;
        DaManifestBundle::try_from(response)
    }

    /// Fetch and persist a DA manifest bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching, validation, or persistence fails.
    pub async fn fetch_da_manifest_to_dir(
        &self,
        storage_ticket: &StorageTicketId,
        output_dir: impl AsRef<Path>,
    ) -> Result<DaManifestPersistedPaths> {
        let bundle = self.da_manifest(storage_ticket).await?;
        let label = bundle.storage_ticket_hex.clone();
        bundle.persist_to_dir(output_dir, label)
    }

    /// Execute a multi-provider fetch via the `SoraFS` orchestrator.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid providers or an orchestrator failure.
    pub async fn sorafs_fetch_via_gateway(
        &self,
        plan: &CarBuildPlan,
        gateway_config: SorafsGatewayFetchConfig,
        providers: impl IntoIterator<Item = SorafsGatewayProviderInput>,
        options: SorafsGatewayFetchOptions,
    ) -> core::result::Result<SorafsFetchOutcome, SorafsFetchError> {
        let provider_inputs = providers.into_iter().collect::<Vec<_>>();
        let (mut orchestrator_config, max_peers) =
            build_sorafs_gateway_fetch_config(self.client, &options);
        if let Some(metadata) = orchestrator_config.scoreboard.persist_metadata.as_mut() {
            annotate_scoreboard_with_gateway_context(metadata, &gateway_config);
        }
        orchestrator_fetch_via_gateway(
            orchestrator_config,
            plan,
            gateway_config,
            provider_inputs,
            None,
            max_peers,
        )
        .await
        .map_err(SorafsFetchError::from)
    }

    /// Fetch a DA payload and construct its availability proof summary.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest, gateway fetch, or proof construction fails.
    pub async fn prove_da_availability(
        &self,
        storage_ticket: &StorageTicketId,
        gateway_config: SorafsGatewayFetchConfig,
        providers: impl IntoIterator<Item = SorafsGatewayProviderInput>,
        fetch_options: SorafsGatewayFetchOptions,
        proof_config: DaProofConfig,
    ) -> Result<DaAvailabilityProof> {
        let manifest = self.da_manifest(storage_ticket).await?;
        let plan = build_car_plan_from_manifest(&manifest.decode_manifest()?)?;
        let fetch_session = self
            .sorafs_fetch_via_gateway(&plan, gateway_config, providers, fetch_options)
            .await?;
        let payload = fetch_session.outcome.assemble_payload();
        let proof_summary =
            generate_da_proof_summary(&manifest.decode_manifest()?, &payload, &proof_config)?;
        Ok(DaAvailabilityProof {
            manifest,
            fetch_session,
            proof_summary,
            proof_config,
        })
    }

    /// Fetch, verify, and persist a DA availability proof bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when fetching, proof construction, or persistence fails.
    pub async fn prove_da_availability_to_dir(
        &self,
        storage_ticket: &StorageTicketId,
        gateway_config: SorafsGatewayFetchConfig,
        providers: impl IntoIterator<Item = SorafsGatewayProviderInput>,
        mut fetch_options: SorafsGatewayFetchOptions,
        proof_config: DaProofConfig,
        output_dir: impl AsRef<Path>,
    ) -> Result<(DaAvailabilityProof, DaAvailabilityProofPersistedPaths)> {
        let output_dir = output_dir.as_ref();
        if output_dir.as_os_str().is_empty() {
            return Err(eyre!("output directory must not be empty"));
        }
        std::fs::create_dir_all(output_dir).wrap_err_with(|| {
            format!(
                "failed to create DA proof output directory `{}`",
                output_dir.display()
            )
        })?;
        let configured_scoreboard = fetch_options
            .scoreboard
            .as_ref()
            .and_then(|options| options.persist_path.clone());
        let scoreboard_path =
            configured_scoreboard.unwrap_or_else(|| output_dir.join("scoreboard.json"));
        match fetch_options.scoreboard.as_mut() {
            Some(options) if options.persist_path.is_none() => {
                options.persist_path = Some(scoreboard_path.clone());
            }
            None => {
                fetch_options.scoreboard = Some(SorafsGatewayScoreboardOptions {
                    persist_path: Some(scoreboard_path.clone()),
                    ..SorafsGatewayScoreboardOptions::default()
                });
            }
            Some(_) => {}
        }
        let proof = self
            .prove_da_availability(
                storage_ticket,
                gateway_config,
                providers,
                fetch_options,
                proof_config,
            )
            .await?;
        let manifest_paths = proof
            .manifest
            .persist_to_dir(output_dir, &proof.manifest.storage_ticket_hex)?;
        let manifest_label = manifest_paths
            .manifest_raw
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_prefix("manifest_"))
            .ok_or_else(|| {
                eyre!(
                    "persisted manifest path `{}` missing expected prefix",
                    manifest_paths.manifest_raw.display()
                )
            })?;
        let payload_path = output_dir.join(format!("payload_{manifest_label}.car"));
        let payload_bytes = proof.fetch_session.outcome.assemble_payload();
        std::fs::write(&payload_path, &payload_bytes).wrap_err_with(|| {
            format!(
                "failed to write fetched payload to `{}`",
                payload_path.display()
            )
        })?;
        let proof_summary_path = output_dir.join(format!("proof_summary_{manifest_label}.json"));
        let metadata = DaProofArtifactMetadata::new(
            manifest_paths.manifest_raw.display().to_string(),
            payload_path.display().to_string(),
        );
        write_da_proof_artifact(
            &proof.manifest,
            &payload_bytes,
            &proof.proof_config,
            &metadata,
            &proof_summary_path,
            true,
        )?;
        let paths = DaAvailabilityProofPersistedPaths {
            manifest: manifest_paths,
            payload_path,
            proof_summary_path,
            scoreboard_path: Some(scoreboard_path),
        };
        Ok((proof, paths))
    }
}

/// Build a DA proof artefact from a fetched manifest bundle.
///
/// # Errors
///
/// Returns an error when the manifest or payload cannot be verified.
pub fn build_da_proof_artifact(
    bundle: &DaManifestBundle,
    payload: &[u8],
    proof: &DaProofConfig,
    metadata: &DaProofArtifactMetadata,
) -> Result<JsonValue> {
    generate_da_proof_artifact(&bundle.decode_manifest()?, payload, proof, metadata)
}

/// Write a DA proof artefact as newline-terminated JSON.
///
/// # Errors
///
/// Returns an error when proof construction, rendering, or persistence fails.
pub fn write_da_proof_artifact(
    bundle: &DaManifestBundle,
    payload: &[u8],
    proof: &DaProofConfig,
    metadata: &DaProofArtifactMetadata,
    output_path: impl AsRef<Path>,
    pretty: bool,
) -> Result<JsonValue> {
    let artifact = build_da_proof_artifact(bundle, payload, proof, metadata)?;
    let output_path = output_path.as_ref();
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).wrap_err_with(|| {
            format!(
                "failed to create DA proof artefact directory `{}`",
                parent.display()
            )
        })?;
    }
    let rendered = if pretty {
        norito::json::to_json_pretty(&artifact)
    } else {
        norito::json::to_json(&artifact)
    }
    .map_err(|error| eyre!("failed to render DA proof artefact JSON: {error}"))?;
    std::fs::write(output_path, format!("{rendered}\n")).wrap_err_with(|| {
        format!(
            "failed to write DA proof artefact to `{}`",
            output_path.display()
        )
    })?;
    Ok(artifact)
}

fn build_sorafs_gateway_fetch_config(
    client: &Client,
    options: &SorafsGatewayFetchOptions,
) -> (OrchestratorConfig, Option<usize>) {
    let telemetry_region = options
        .telemetry_region
        .clone()
        .or_else(|| Some(client.chain().to_string()));
    let mut config = OrchestratorConfig {
        telemetry_region,
        ..OrchestratorConfig::default()
    }
    .with_rollout_phase(client.rollout_phase());
    let phase_default_policy = config.anonymity_policy;
    if client.default_anonymity_policy() != phase_default_policy {
        config.anonymity_policy = client.default_anonymity_policy();
        config.anonymity_policy_override = Some(client.default_anonymity_policy());
    }
    config.write_mode = options.write_mode_hint.unwrap_or(WriteModeHint::ReadOnly);
    if let Some(budget) = options.retry_budget {
        config.fetch.per_chunk_retry_limit = (budget != 0).then_some(budget);
    }
    let max_peers = options.max_peers.filter(|value| *value != 0);
    let mut explicit_transport = options.transport_policy.is_some_and(|policy| {
        config.transport_policy = policy;
        true
    });
    let mut explicit_anonymity = options.anonymity_policy.is_some_and(|policy| {
        config.anonymity_policy = policy;
        config.anonymity_policy_override = Some(policy);
        true
    });
    config.policy_override = options.policy_override.clone();
    explicit_transport |= config.policy_override.transport_policy.is_some();
    explicit_anonymity |= config.policy_override.anonymity_policy.is_some();
    if let Some(guard_set) = options.guard_set.clone() {
        config.guard_set = Some(guard_set);
    }
    if let Some(directory) = options.relay_directory.clone() {
        config.relay_directory = Some(directory);
    }
    if let Some(scoreboard) = &options.scoreboard {
        if let Some(path) = scoreboard.persist_path.as_ref() {
            config.scoreboard.persist_path = Some(path.clone());
        }
        if let Some(now) = scoreboard.now_unix_secs {
            config.scoreboard.now_unix_secs = now;
        }
        let telemetry_label = derive_scoreboard_telemetry_label(
            scoreboard.telemetry_source_label.as_deref(),
            options,
            client.chain().as_str(),
        );
        config.scoreboard.persist_metadata = Some(ensure_scoreboard_metadata(
            scoreboard.metadata.clone(),
            Some(&telemetry_label),
            config.scoreboard.now_unix_secs,
        ));
    }
    if config.write_mode.enforces_pq_only() {
        if !explicit_anonymity {
            config.anonymity_policy = AnonymityPolicy::StrictPq;
            config.anonymity_policy_override = Some(AnonymityPolicy::StrictPq);
        }
        if !explicit_transport {
            config.transport_policy = TransportPolicy::SoranetStrict;
        }
    }
    (config, max_peers)
}

fn derive_scoreboard_telemetry_label(
    explicit: Option<&str>,
    options: &SorafsGatewayFetchOptions,
    chain_id: &str,
) -> String {
    if let Some(label) = explicit.map(str::trim).filter(|label| !label.is_empty()) {
        return label.to_owned();
    }
    if let Some(region) = options
        .telemetry_region
        .as_deref()
        .map(str::trim)
        .filter(|region| !region.is_empty())
    {
        return format!("region:{region}");
    }
    format!("chain:{chain_id}")
}

fn ensure_scoreboard_metadata(
    metadata: Option<JsonValue>,
    telemetry_label: Option<&str>,
    assume_now: u64,
) -> JsonValue {
    let mut map = match metadata {
        Some(JsonValue::Object(map)) => map,
        Some(other) => return other,
        None => JsonMap::from_iter([
            ("version".into(), JsonValue::from(env!("CARGO_PKG_VERSION"))),
            ("use_scoreboard".into(), JsonValue::from(true)),
            ("allow_implicit_metadata".into(), JsonValue::from(false)),
            ("gateway_manifest_provided".into(), JsonValue::Null),
        ]),
    };
    map.entry("assume_now".into())
        .or_insert_with(|| JsonValue::from(assume_now));
    if let Some(label) = telemetry_label.filter(|label| !label.is_empty()) {
        map.entry("telemetry_source".into())
            .or_insert_with(|| JsonValue::from(label));
    }
    JsonValue::Object(map)
}

fn annotate_scoreboard_with_gateway_context(
    metadata: &mut JsonValue,
    gateway_config: &SorafsGatewayFetchConfig,
) {
    let JsonValue::Object(map) = metadata else {
        return;
    };
    map.insert(
        "gateway_manifest_id".into(),
        JsonValue::from(gateway_config.manifest_id_hex.trim().to_ascii_lowercase()),
    );
    let manifest_cid = gateway_config
        .expected_manifest_cid_hex
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or(JsonValue::Null, |value| {
            JsonValue::from(value.to_ascii_lowercase())
        });
    map.insert("gateway_manifest_cid".into(), manifest_cid);
    map.insert(
        "gateway_manifest_provided".into(),
        JsonValue::from(gateway_config.manifest_envelope_b64.is_some()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::{
        config::{Config, DEFAULT_TORII_REQUEST_TIMEOUT},
        crypto::{Algorithm, Hash, HashOf, KeyPair},
        data_model::{NetworkId, account::AccountId, block::BlockHeader},
    };
    use iroha_model_base::chain::ChainId;
    use iroha_service_model::soranet::RolloutPhase;
    use sorafs_manifest::alias_cache::AliasCachePolicy;
    use std::time::Duration;

    #[test]
    fn gateway_fetch_config_defaults_apply_chain_region() {
        let client = test_client();
        let options = SorafsGatewayFetchOptions::default();
        let (config, max_peers) = build_sorafs_gateway_fetch_config(&client, &options);
        assert_eq!(
            config.telemetry_region.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(
            config.fetch.per_chunk_retry_limit,
            OrchestratorConfig::default().fetch.per_chunk_retry_limit
        );
        assert!(max_peers.is_none());
        assert_eq!(config.anonymity_policy, AnonymityPolicy::GuardPq);
        assert_eq!(config.write_mode, WriteModeHint::ReadOnly);
    }

    #[test]
    fn gateway_fetch_config_applies_and_sanitises_overrides() {
        let client = test_client();
        let options = SorafsGatewayFetchOptions {
            retry_budget: Some(5),
            max_peers: Some(3),
            telemetry_region: Some("sea".to_owned()),
            transport_policy: Some(TransportPolicy::DirectOnly),
            anonymity_policy: Some(AnonymityPolicy::StrictPq),
            ..SorafsGatewayFetchOptions::default()
        };
        let (config, max_peers) = build_sorafs_gateway_fetch_config(&client, &options);
        assert_eq!(config.fetch.per_chunk_retry_limit, Some(5));
        assert_eq!(config.telemetry_region.as_deref(), Some("sea"));
        assert_eq!(max_peers, Some(3));
        assert_eq!(config.transport_policy, TransportPolicy::DirectOnly);
        assert_eq!(config.anonymity_policy, AnonymityPolicy::StrictPq);

        let zero = SorafsGatewayFetchOptions {
            retry_budget: Some(0),
            max_peers: Some(0),
            ..SorafsGatewayFetchOptions::default()
        };
        let (config, max_peers) = build_sorafs_gateway_fetch_config(&client, &zero);
        assert_eq!(config.fetch.per_chunk_retry_limit, None);
        assert!(max_peers.is_none());
    }

    #[test]
    fn gateway_fetch_config_applies_write_and_policy_controls() {
        let client = test_client();
        let upload = SorafsGatewayFetchOptions {
            write_mode_hint: Some(WriteModeHint::UploadPqOnly),
            ..SorafsGatewayFetchOptions::default()
        };
        let (config, _) = build_sorafs_gateway_fetch_config(&client, &upload);
        assert_eq!(config.write_mode, WriteModeHint::UploadPqOnly);
        assert_eq!(config.transport_policy, TransportPolicy::SoranetStrict);
        assert_eq!(config.anonymity_policy, AnonymityPolicy::StrictPq);

        let explicit = SorafsGatewayFetchOptions {
            transport_policy: Some(TransportPolicy::SoranetPreferred),
            anonymity_policy: Some(AnonymityPolicy::MajorityPq),
            write_mode_hint: Some(WriteModeHint::UploadPqOnly),
            policy_override: PolicyOverride::new(
                Some(TransportPolicy::SoranetStrict),
                Some(AnonymityPolicy::StrictPq),
            ),
            ..SorafsGatewayFetchOptions::default()
        };
        let (config, _) = build_sorafs_gateway_fetch_config(&client, &explicit);
        assert_eq!(config.transport_policy, TransportPolicy::SoranetPreferred);
        assert_eq!(config.anonymity_policy, AnonymityPolicy::MajorityPq);
        assert_eq!(
            config.policy_override.transport_policy,
            Some(TransportPolicy::SoranetStrict)
        );
    }

    #[test]
    fn gateway_fetch_config_applies_scoreboard_metadata() {
        let client = test_client();
        let metadata = norito::json!({"capture_id": "unit-test"});
        let path = PathBuf::from("/tmp/sorafs_scoreboard.json");
        let options = SorafsGatewayFetchOptions {
            scoreboard: Some(SorafsGatewayScoreboardOptions {
                persist_path: Some(path.clone()),
                now_unix_secs: Some(42),
                metadata: Some(metadata),
                telemetry_source_label: None,
            }),
            ..SorafsGatewayFetchOptions::default()
        };
        let (config, _) = build_sorafs_gateway_fetch_config(&client, &options);
        assert_eq!(config.scoreboard.persist_path.as_ref(), Some(&path));
        assert_eq!(config.scoreboard.now_unix_secs, 42);
        let metadata = config.scoreboard.persist_metadata.expect("metadata");
        assert_eq!(
            metadata.get("telemetry_source").and_then(JsonValue::as_str),
            Some("chain:00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(
            metadata.get("assume_now").and_then(JsonValue::as_u64),
            Some(42)
        );
    }

    #[test]
    fn scoreboard_metadata_records_gateway_context() {
        let mut metadata = ensure_scoreboard_metadata(None, Some("region:test"), 0);
        let config = SorafsGatewayFetchConfig {
            manifest_id_hex: "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00"
                .into(),
            chunker_handle: "sorafs.sf1@1.0.0".into(),
            manifest_envelope_b64: Some("ZW52ZWxvcGU=".into()),
            client_id: Some("sdk".into()),
            expected_manifest_cid_hex: Some("C0FFEE".into()),
            blinded_cid_b64: Some("YmFzZQ".into()),
            salt_epoch: Some(7),
            expected_cache_version: None,
        };
        annotate_scoreboard_with_gateway_context(&mut metadata, &config);
        assert_eq!(
            metadata
                .get("gateway_manifest_id")
                .and_then(JsonValue::as_str),
            Some("abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00")
        );
        assert_eq!(
            metadata
                .get("gateway_manifest_cid")
                .and_then(JsonValue::as_str),
            Some("c0ffee")
        );
        assert_eq!(
            metadata
                .get("gateway_manifest_provided")
                .and_then(JsonValue::as_bool),
            Some(true)
        );
    }

    pub(super) fn test_client() -> Client {
        let key_pair = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
            .expect("deterministic client key");
        let account = AccountId::new(key_pair.public_key().clone());
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x24; 32])),
        );
        let alias_cache = AliasCachePolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        Client::builder(Config {
            chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
            network_id,
            account,
            account_chain_discriminant: 753,
            key_pair,
            basic_auth: None,
            api_token: None,
            http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
            torii_api_url: "http://127.0.0.1:8080/".parse().expect("Torii URL"),
            torii_request_timeout: DEFAULT_TORII_REQUEST_TIMEOUT,
            transaction_ttl: Duration::from_secs(5),
            transaction_status_timeout: Duration::from_secs(10),
            transaction_add_nonce: false,
            sorafs_alias_cache: alias_cache,
            sorafs_anonymity_policy: AnonymityPolicy::GuardPq,
            sorafs_rollout_phase: RolloutPhase::Canary,
        })
        .build()
        .expect("valid test client configuration")
    }
}
