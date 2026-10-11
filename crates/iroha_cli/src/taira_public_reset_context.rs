//! Current typed topology intent and native-derived reset context.
use super::*;

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in super::super) struct ResetRevisionIntentV1 {
    pub(in super::super) source_root: String,
    pub(in super::super) source_manifest_path: String,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in super::super) struct ResetArtifactIntentV1 {
    pub(in super::super) role: String,
    pub(in super::super) local_path: String,
    pub(in super::super) remote_path: String,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in super::super) struct ResetValidatorIntentV1 {
    pub(in super::super) slug: String,
    pub(in super::super) endpoint: EndpointV1,
    pub(in super::super) platform: PlatformV1,
    pub(in super::super) service_root: String,
    pub(in super::super) state_root: String,
    pub(in super::super) reset_guard: String,
    pub(in super::super) systemd_unit: String,
    pub(in super::super) artifacts: Vec<ResetArtifactIntentV1>,
    pub(in super::super) initial_state: ValidatorInitialStateV1,
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in super::super) struct ResetEdgeIntentV1 {
    pub(in super::super) slug: String,
    pub(in super::super) endpoint: EndpointV1,
    pub(in super::super) platform: PlatformV1,
    pub(in super::super) service_root: String,
    pub(in super::super) state_root: String,
    pub(in super::super) reset_guard: String,
    pub(in super::super) nginx_config: String,
    pub(in super::super) artifacts: Vec<ResetArtifactIntentV1>,
    pub(in super::super) initial_state: EdgeInitialStateV1,
}
/// Owner-selected topology, trust and authority only; generated current pins are forbidden.
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in super::super) struct ResetTopologyIntentV1 {
    pub(in super::super) schema: String,
    pub(in super::super) qualification_scope: QualificationScopeV1,
    pub(in super::super) deployment_id: String,
    pub(in super::super) previous_genesis_hash: String,
    pub(in super::super) authorization_nonce: String,
    pub(in super::super) revision: ResetRevisionIntentV1,
    pub(in super::super) hosts: host_pair::ResetHostPairV1,
    pub(in super::super) validators: Vec<ResetValidatorIntentV1>,
    pub(in super::super) validator_clients: Vec<ValidatorClientV1>,
    pub(in super::super) edge: ResetEdgeIntentV1,
    pub(in super::super) canary_onboarding_request: AccountOnboardingPlanRequestV1,
    pub(in super::super) faucet_policy: FaucetPolicyV1,
    pub(in super::super) fee_intent: FeeIntentV1,
    pub(in super::super) cleanup: CleanupV1,
    pub(in super::super) timeouts: TimeoutsV1,
}

/// Real native local inputs required before the generated beacon plan exists.
#[derive(clap::Args, Debug)]
pub(in super::super) struct ResetContextInputs {
    #[arg(long, value_name = "DIR")]
    pub(in super::super) public_inputs: PathBuf,
    #[arg(long, value_name = "PATH")]
    pub(in super::super) runtime_client_config: PathBuf,
    #[arg(long, value_name = "PATH", num_args = 4)]
    pub(in super::super) validator_client_config: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub(in super::super) onboarding_token: PathBuf,
    #[arg(long, value_name = "PATH")]
    pub(in super::super) validator_operator_key: PathBuf,
    #[arg(long, value_name = "DIR")]
    pub(in super::super) inrou_stage_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH", num_args = 4)]
    pub(in super::super) validator_unit: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub(in super::super) native_edge_capability: PathBuf,
    #[arg(long, value_name = "PATH")]
    pub(in super::super) known_hosts: PathBuf,
}

pub(in super::super) struct DerivedResetContext {
    pub(in super::super) intent: ResetTopologyIntentV1,
    pub(in super::super) revision: RevisionV1,
    pub(in super::super) validators: Vec<ValidatorV1>,
    pub(in super::super) validator_clients: Vec<ValidatorClientV1>,
    pub(in super::super) edge: EdgeV1,
    pub(in super::super) operator_public_key: String,
    pub(in super::super) public_inputs: public_inputs::PublicInputsV1,
    pub(in super::super) canary_onboarding_request: AccountOnboardingPlanRequestV1,
    pub(super) runtime: RuntimeParts,
    pins: Vec<PinnedInput>,
    public_directory: PathBuf,
}
pub(super) struct RuntimeParts {
    pub(super) runtime_client_config_sha256: String,
    pub(super) onboarding_token_sha256: String,
    pub(super) validator_client_configs_sha256: String,
    pub(super) inrou_canary: Option<InrouCanaryV1>,
    pub(super) inrou_stage_tree_sha256: Option<String>,
    stage: Option<(PathBuf, String, u64, Vec<(String, PinnedInput)>)>,
}

pub(in super::super) fn decode_reset_topology_intent(
    bytes: &[u8],
) -> Result<(ResetTopologyIntentV1, ChainDiscriminantGuard)> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(eyre!("topology intent exceeds its native bound"));
    }
    let guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    let intent: ResetTopologyIntentV1 = json::from_slice(bytes)?;
    validate_topology_intent(&intent)?;
    Ok((intent, guard))
}
pub(in super::super) fn validate_topology_intent(intent: &ResetTopologyIntentV1) -> Result<()> {
    if intent.schema != "iroha.taira.public-reset.topology-intent.v1"
        || intent.validators.len() != 4
        || intent.validator_clients.len() != 4
    {
        return Err(eyre!("current four-validator topology intent required"));
    }
    validate_timeouts(&intent.timeouts)?;
    validate_nonce(&intent.authorization_nonce)?;
    for ((validator, client), expected) in intent
        .validators
        .iter()
        .zip(&intent.validator_clients)
        .zip(VALIDATOR_SLUGS)
    {
        if validator.slug != expected || client.slug != expected {
            return Err(eyre!("topology validator roles differ"));
        }
    }
    execution_lifetime_for_host_identities(
        &intent.timeouts,
        intent
            .validators
            .iter()
            .map(|v| v.endpoint.host_identity_sha256.as_str()),
    )?;
    Ok(())
}

impl DerivedResetContext {
    pub(in super::super) fn revalidate(&self) -> Result<()> {
        for input in &self.pins {
            revalidate_pinned(input, "retained native reset context")?;
        }
        validate_source_closure(&self.revision)?;
        if let Some((directory, hash, bytes, files)) = &self.runtime.stage {
            if host::revalidate_stage_files(directory, files, None)? != (hash.clone(), *bytes) {
                return Err(eyre!("Inrou context changed before publication"));
            }
        }
        if public_inputs::load(&self.public_directory)? != self.public_inputs {
            return Err(eyre!("public genesis context changed"));
        }
        Ok(())
    }
    pub(super) fn build_inventory(
        &self,
        beacon_bootstrap: host::beacon::BeaconBootstrapPlanV1,
    ) -> Result<InventoryV1> {
        self.revalidate()?;
        let mut value = InventoryV1 {
            schema: INVENTORY_SCHEMA_V1.into(),
            qualification_scope: self.intent.qualification_scope.clone(),
            deployment_id: self.intent.deployment_id.clone(),
            chain_id: CHAIN_ID.into(),
            chain_discriminant: CHAIN_DISCRIMINANT,
            previous_genesis_hash: self.intent.previous_genesis_hash.clone(),
            next_genesis_hash: self.public_inputs.genesis_hash.clone(),
            authorization_nonce: self.intent.authorization_nonce.clone(),
            revision: self.revision.clone(),
            hosts: self.intent.hosts.clone(),
            validators: self.validators.clone(),
            validator_clients: self.validator_clients.clone(),
            operator_public_key: self.operator_public_key.clone(),
            edge: self.edge.clone(),
            inrou_canary: self.runtime.inrou_canary.clone(),
            canary_onboarding_request: self.canary_onboarding_request.clone(),
            faucet_policy: self.intent.faucet_policy.clone(),
            fee_intent: self.intent.fee_intent.clone(),
            beacon_bootstrap,
            cleanup: self.intent.cleanup.clone(),
            timeouts: self.intent.timeouts.clone(),
            artifact_closure_sha256: String::new(),
            runtime_client_config_sha256: self.runtime.runtime_client_config_sha256.clone(),
            onboarding_token_sha256: self.runtime.onboarding_token_sha256.clone(),
            validator_client_configs_sha256: self.runtime.validator_client_configs_sha256.clone(),
            inrou_stage_tree_sha256: self.runtime.inrou_stage_tree_sha256.clone(),
        };
        value.artifact_closure_sha256 = artifact_closure_sha256(&value);
        Ok(value)
    }
}

#[cfg(unix)]
pub(in super::super) fn derive_reset_context(
    intent: &ResetTopologyIntentV1,
    inputs: &ResetContextInputs,
) -> Result<DerivedResetContext> {
    use std::os::fd::AsRawFd as _;
    let _chain = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    if intent.validators.len() != 4
        || intent.validator_clients.len() != 4
        || inputs.validator_client_config.len() != 4
        || inputs.validator_unit.len() != 4
    {
        return Err(eyre!(
            "native reset context requires four exact validator inputs"
        ));
    }
    validate_topology_intent(intent)?;
    intent
        .qualification_scope
        .validate_stage_argument(inputs.inrou_stage_dir.as_deref())?;
    let public = public_inputs::load(&inputs.public_inputs)?;
    if public.canary_onboarding_request != intent.canary_onboarding_request {
        return Err(eyre!(
            "topology canary differs from actual public genesis bundle"
        ));
    }
    let operator =
        pin_owner_private_file(&inputs.validator_operator_key, "validator operator key")?;
    let pair =
        crate::operator_key::load_operator_key_pair_fd(u32::try_from(operator.file.as_raw_fd())?)?;
    let operator_public_key = pair.public_key().to_string();
    validator_operator_public_key(&operator_public_key)?;
    revalidate_pinned(&operator, "validator operator key")?;
    drop(pair);
    let release =
        super::context_release::derive_release(intent, &public, &operator_public_key, inputs)?;
    let endpoints = release
        .validators
        .iter()
        .map(|v| &v.endpoint)
        .chain(std::iter::once(&release.edge.endpoint))
        .collect::<Vec<_>>();
    let known_hosts = validate_known_host_endpoints(&endpoints, &inputs.known_hosts)?;
    let (runtime, mut pins) = derive_runtime_parts(intent, inputs, &public)?;
    let wire = pin_authenticated_genesis(inputs, &public)?;
    let wire_bytes = pinned_bytes(&wire, 64 * 1024 * 1024)?;
    deployment_profile::derive_admitted_profile(
        &public.genesis_hash,
        &public.canary_onboarding_request,
        &release.validators,
        &intent.validator_clients,
        &public,
        &wire_bytes,
    )?;
    pins.extend(release.pins);
    pins.extend([operator, wire, known_hosts]);
    let context = DerivedResetContext {
        intent: intent.clone(),
        revision: release.revision,
        validators: release.validators,
        validator_clients: intent.validator_clients.clone(),
        edge: release.edge,
        operator_public_key,
        canary_onboarding_request: public.canary_onboarding_request.clone(),
        public_inputs: public,
        runtime,
        pins,
        public_directory: inputs.public_inputs.clone(),
    };
    context.revalidate()?;
    Ok(context)
}
#[cfg(not(unix))]
pub(in super::super) fn derive_reset_context(
    _: &ResetTopologyIntentV1,
    _: &ResetContextInputs,
) -> Result<DerivedResetContext> {
    Err(eyre!("native reset context requires Unix"))
}

/// Pin and authenticate both native genesis representations before deriving trust.
fn pin_authenticated_genesis(
    inputs: &ResetContextInputs,
    public: &public_inputs::PublicInputsV1,
) -> Result<PinnedInput> {
    let manifest_path = inputs.public_inputs.join("genesis.json");
    let (manifest, manifest_bytes) = read_json::<iroha_genesis::RawGenesisTransaction>(
        &manifest_path,
        "authenticated genesis manifest",
    )?;
    let path = inputs.public_inputs.join("genesis.signed.nrt");
    let (file, snapshot) = open_pinned_regular(&path, "authenticated signed genesis")?;
    let wire = PinnedInput {
        path,
        file,
        snapshot,
    };
    let wire_bytes = pinned_bytes(&wire, 64 * 1024 * 1024)?;
    if sha256_hex(&manifest_bytes) != public.raw_manifest_sha256
        || sha256_hex(&wire_bytes) != public.signed_genesis_sha256
    {
        return Err(eyre!("signed genesis differs from authenticated bundle"));
    }
    iroha_genesis::validate_prepared_genesis_bundle(
        &wire_bytes,
        &manifest,
        &public.genesis_public_key,
        public.network_id.into_genesis_hash(),
    )?;
    revalidate_pinned(&wire, "authenticated signed genesis")?;
    Ok(wire)
}

fn derive_runtime_parts(
    intent: &ResetTopologyIntentV1,
    inputs: &ResetContextInputs,
    public: &public_inputs::PublicInputsV1,
) -> Result<(RuntimeParts, Vec<PinnedInput>)> {
    intent
        .qualification_scope
        .validate_stage_argument(inputs.inrou_stage_dir.as_deref())?;
    let runtime = pin_owner_private_file(&inputs.runtime_client_config, "runtime client config")?;
    let token = pin_owner_private_file(&inputs.onboarding_token, "onboarding token")?;
    let clients = inputs
        .validator_client_config
        .iter()
        .map(|p| pin_owner_private_file(p, "validator client config"))
        .collect::<Result<Vec<_>>>()?;
    for (input, expected) in clients.iter().zip(&intent.validator_clients) {
        let config = host::load_client_config_for_reset_genesis(
            input,
            "validator client config",
            &public.genesis_hash,
        )?;
        let account = AccountId::parse_encoded(&expected.account_id)?;
        if config.account != account || config.torii_api_url.as_str() != expected.torii_origin {
            return Err(eyre!(
                "validator client config does not match selected account and Torii origin"
            ));
        }
    }
    let config = host::load_client_config_for_reset_genesis(
        &runtime,
        "runtime client config",
        &public.genesis_hash,
    )?;
    if config.torii_api_url.as_str() != format!("{PUBLIC_ROOT}/")
        || config.account.to_string() != public.canary_onboarding_request.account_id
    {
        return Err(eyre!(
            "runtime client config does not bind the explicit public Taira canary"
        ));
    }
    let runtime_client_config_sha256 = host::hash_pinned_input(&runtime, "runtime config", None)?;
    let onboarding_token_sha256 = host::hash_pinned_input(&token, "onboarding token", None)?;
    let validator_client_configs_sha256 = host::validator_config_closure_sha256(&clients, None)?;
    let mut pins = clients;
    pins.extend([runtime, token]);
    let mut parts = RuntimeParts {
        runtime_client_config_sha256,
        onboarding_token_sha256,
        validator_client_configs_sha256,
        inrou_canary: None,
        inrou_stage_tree_sha256: None,
        stage: None,
    };
    let Some(stage_dir) = inputs.inrou_stage_dir.as_deref() else {
        return Ok((parts, pins));
    };
    let (stage_hash, stage_bytes, files, fixed) = host::pin_stage_tree(stage_dir, None)?;
    let identity = crate::soracloud::load_taira_inrou_stage_identity(
        &config,
        stage_dir,
        crate::taira::InrouCanaryMode::Deploy,
    )?;
    if host::revalidate_stage_files(stage_dir, &files, None)? != (stage_hash.clone(), stage_bytes) {
        return Err(eyre!("Inrou stage changed during inventory assembly"));
    }

    parts.inrou_stage_tree_sha256 = Some(stage_hash.clone());
    parts.stage = Some((
        stage_dir.to_path_buf(),
        stage_hash.clone(),
        stage_bytes,
        files,
    ));
    let file_hash = |path: &str| {
        fixed
            .get(path)
            .cloned()
            .ok_or_else(|| eyre!("Inrou stage omits a mandatory fixed file"))
    };
    parts.inrou_canary = Some(InrouCanaryV1 {
        public_root: PUBLIC_ROOT.to_owned(),
        replicas: 4,
        service_name: identity.service_name,
        service_version: identity.service_version,
        route_host: identity.route_host,
        route_path_prefix: identity.route_path_prefix,
        healthcheck_path: identity.healthcheck_path,
        bundle_hash: identity.bundle_hash,
        bundle_content_cid: identity.bundle_content_cid,
        bundle_manifest_digest_hex: identity.bundle_manifest_digest_hex,
        guest_content_cid: identity.guest_content_cid,
        guest_manifest_digest_hex: identity.guest_manifest_digest_hex,
        discovery_payload_dir: identity.discovery_payload_dir,
        discovery_manifest_file: "manifests/discovery.to".to_owned(),
        discovery_document_hash: identity.discovery_document_hash,
        discovery_content_cid: identity.discovery_content_cid,
        discovery_manifest_digest_hex: identity.discovery_manifest_digest_hex,
        public_discovery_url: identity.public_discovery_url,
        public_discovery_cid_host_url: identity.public_discovery_cid_host_url,
        deployment_bundle_hash: identity.deployment_bundle_hash,
        container_manifest_hash: identity.container_manifest_hash,
        service_manifest_hash: identity.service_manifest_hash,
        placement_targets: identity.placement_targets,
        stage_tree_sha256: stage_hash,
        stage_bytes,
        receipt_sha256: file_hash("receipt.json")?,
        container_sha256: file_hash("container.json")?,
        service_sha256: file_hash("service.json")?,
        bundle_payload_sha256: file_hash("payloads/bundle.bin")?,
        bundle_manifest_sha256: file_hash("manifests/bundle.to")?,
        guest_manifest_sha256: file_hash("manifests/aarch64.to")?,
        discovery_document_sha256: file_hash("payloads/discovery/index.json")?,
        discovery_manifest_sha256: file_hash("manifests/discovery.to")?,
    });
    Ok((parts, pins))
}

impl From<&LocalInputs> for ResetContextInputs {
    fn from(input: &LocalInputs) -> Self {
        Self {
            public_inputs: input.public_inputs.clone(),
            runtime_client_config: input.runtime_client_config.clone(),
            validator_client_config: input.validator_client_config.clone(),
            onboarding_token: input.onboarding_token.clone(),
            validator_operator_key: input.validator_operator_key.clone(),
            inrou_stage_dir: input.inrou_stage_dir.clone(),
            validator_unit: input.validator_unit.clone(),
            native_edge_capability: input.native_edge_capability.clone(),
            known_hosts: input.known_hosts.clone(),
        }
    }
}
impl<Beacon> From<&InventoryRecordV1<Beacon>> for ResetTopologyIntentV1 {
    fn from(value: &InventoryRecordV1<Beacon>) -> Self {
        let artifact = |a: &ArtifactV1| ResetArtifactIntentV1 {
            role: a.role.clone(),
            local_path: a.local_path.clone(),
            remote_path: a.remote_path.clone(),
        };
        Self {
            schema: "iroha.taira.public-reset.topology-intent.v1".into(),
            qualification_scope: value.qualification_scope,
            deployment_id: value.deployment_id.clone(),
            previous_genesis_hash: value.previous_genesis_hash.clone(),
            authorization_nonce: value.authorization_nonce.clone(),
            revision: ResetRevisionIntentV1 {
                source_root: value.revision.source_root.clone(),
                source_manifest_path: value.revision.source_manifest_path.clone(),
            },
            hosts: value.hosts.clone(),
            validators: value
                .validators
                .iter()
                .map(|v| ResetValidatorIntentV1 {
                    slug: v.slug.clone(),
                    endpoint: v.endpoint.clone(),
                    platform: v.platform.clone(),
                    service_root: v.service_root.clone(),
                    state_root: v.state_root.clone(),
                    reset_guard: v.reset_guard.clone(),
                    systemd_unit: v.systemd_unit.clone(),
                    artifacts: v.artifacts.iter().map(&artifact).collect(),
                    initial_state: v.initial_state.clone(),
                })
                .collect(),
            validator_clients: value.validator_clients.clone(),
            edge: ResetEdgeIntentV1 {
                slug: value.edge.slug.clone(),
                endpoint: value.edge.endpoint.clone(),
                platform: value.edge.platform.clone(),
                service_root: value.edge.service_root.clone(),
                state_root: value.edge.state_root.clone(),
                reset_guard: value.edge.reset_guard.clone(),
                nginx_config: value.edge.nginx_config.clone(),
                artifacts: value.edge.artifacts.iter().map(&artifact).collect(),
                initial_state: value.edge.initial_state.clone(),
            },
            canary_onboarding_request: value.canary_onboarding_request.clone(),
            faucet_policy: value.faucet_policy.clone(),
            fee_intent: value.fee_intent.clone(),
            cleanup: value.cleanup.clone(),
            timeouts: value.timeouts.clone(),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
impl history::TerminalInventory {
    /// Copy historical topology only after independently validating current physical custody.
    pub(in super::super) fn topology_intent(
        &self,
        hosts: &host_pair::ResetHostPairV1,
    ) -> Result<ResetTopologyIntentV1> {
        self.validate_physical_binding(hosts)?;
        let value = self;
        let artifact = |a: &ArtifactV1| ResetArtifactIntentV1 {
            role: a.role.clone(),
            local_path: a.local_path.clone(),
            remote_path: a.remote_path.clone(),
        };
        Ok(ResetTopologyIntentV1 {
            schema: "iroha.taira.public-reset.topology-intent.v1".into(),
            qualification_scope: value.qualification_scope,
            deployment_id: value.deployment_id.clone(),
            previous_genesis_hash: value.previous_genesis_hash.clone(),
            authorization_nonce: value.authorization_nonce.clone(),
            revision: ResetRevisionIntentV1 {
                source_root: value.revision.source_root.clone(),
                source_manifest_path: value.revision.source_manifest_path.clone(),
            },
            hosts: hosts.clone(),
            validators: value
                .validators
                .iter()
                .map(|v| ResetValidatorIntentV1 {
                    slug: v.slug.clone(),
                    endpoint: v.endpoint.clone(),
                    platform: v.platform.clone(),
                    service_root: v.service_root.clone(),
                    state_root: v.state_root.clone(),
                    reset_guard: v.reset_guard.clone(),
                    systemd_unit: v.systemd_unit.clone(),
                    artifacts: v.artifacts.iter().map(&artifact).collect(),
                    initial_state: v.initial_state.clone(),
                })
                .collect(),
            validator_clients: value.validator_clients.clone(),
            edge: ResetEdgeIntentV1 {
                slug: value.edge.slug.clone(),
                endpoint: value.edge.endpoint.clone(),
                platform: value.edge.platform.clone(),
                service_root: value.edge.service_root.clone(),
                state_root: value.edge.state_root.clone(),
                reset_guard: value.edge.reset_guard.clone(),
                nginx_config: value.edge.nginx_config.clone(),
                artifacts: value.edge.artifacts.iter().map(&artifact).collect(),
                initial_state: value.edge.initial_state.clone(),
            },
            canary_onboarding_request: value.canary_onboarding_request.clone(),
            faucet_policy: value.faucet_policy.clone(),
            fee_intent: value.fee_intent.clone(),
            cleanup: value.cleanup.clone(),
            timeouts: value.timeouts.clone(),
        })
    }
}
