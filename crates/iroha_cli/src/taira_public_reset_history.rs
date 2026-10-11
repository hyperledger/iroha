//! Immutable custody of a historical inventory, never executable input.
//!
//! Original bytes and signatures cover the complete inventory. Only immutable
//! topology, identities and ordered artifact pins are interpreted here; retired
//! host execution, beacon and native-edge capabilities remain opaque. They cannot
//! be converted into a current inventory or executed by the successor.

#[cfg(any(target_os = "linux", test))]
use super::*;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields, no_fast_from_json)]
pub(super) struct TerminalInventory {
    pub(super) schema: String,
    pub(super) qualification_scope: QualificationScopeV1,
    pub(super) deployment_id: String,
    pub(super) chain_id: String,
    pub(super) chain_discriminant: u16,
    pub(super) previous_genesis_hash: String,
    pub(super) next_genesis_hash: String,
    pub(super) authorization_nonce: String,
    pub(super) revision: RevisionV1,
    /// Original host document, interpreted only through immutable physical custody.
    pub(super) hosts: Value,
    pub(super) validators: Vec<ValidatorV1>,
    pub(super) validator_clients: Vec<ValidatorClientV1>,
    /// Dedicated public operator identity accepted by every candidate validator.
    pub(super) operator_public_key: String,
    pub(super) edge: TerminalEdge,
    #[norito(required)]
    pub(super) inrou_canary: Option<InrouCanaryV1>,
    pub(super) canary_onboarding_request: AccountOnboardingPlanRequestV1,
    pub(super) faucet_policy: FaucetPolicyV1,
    pub(super) fee_intent: FeeIntentV1,
    /// Original beacon execution data, authenticated but never replayed.
    pub(super) beacon_bootstrap: Value,
    pub(super) cleanup: CleanupV1,
    pub(super) timeouts: TimeoutsV1,
    pub(super) artifact_closure_sha256: String,
    pub(super) runtime_client_config_sha256: String,
    pub(super) onboarding_token_sha256: String,
    pub(super) validator_client_configs_sha256: String,
    #[norito(required)]
    pub(super) inrou_stage_tree_sha256: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields, no_fast_from_json)]
pub(super) struct TerminalEdge {
    pub(super) slug: String,
    pub(super) endpoint: EndpointV1,
    pub(super) platform: PlatformV1,
    pub(super) service_root: String,
    pub(super) state_root: String,
    pub(super) reset_guard: String,
    pub(super) nginx_config: String,
    pub(super) artifacts: Vec<ArtifactV1>,
    pub(super) native_capability: Value,
    pub(super) initial_state: EdgeInitialStateV1,
}

#[cfg(any(target_os = "linux", test))]
impl TerminalInventory {
    fn validate_inrou_scope(&self) -> Result<()> {
        match (
            self.qualification_scope,
            &self.inrou_canary,
            &self.inrou_stage_tree_sha256,
        ) {
            (QualificationScopeV1::CoreTestnet, None, None) => Ok(()),
            (QualificationScopeV1::FullInrou, Some(canary), Some(hash)) => {
                validate_lower_hex("Inrou stage closure SHA-256", hash, 64)?;
                if hash != &canary.stage_tree_sha256 {
                    return Err(eyre!(
                        "full_inrou stage hash differs from the complete canary closure"
                    ));
                }
                validate_inrou(canary)
            }
            _ => Err(eyre!(
                "core_testnet requires null Inrou fields; full_inrou requires the complete Inrou closure"
            )),
        }
    }

    fn validate_host_custody(&self) -> Result<()> {
        let (guest, edge) = self.physical_hosts()?;
        for validator in &self.validators {
            guest.bind_role(&validator.endpoint, &validator.platform)?;
        }
        edge.bind_role(&self.edge.endpoint, &self.edge.platform)?;
        if self.edge.service_root != format!("{}/.local/share/iroha/taira/edge", edge.owner_home)
            || self.edge.reset_guard != format!("{}/taira-edge", edge.custody_root)
        {
            return Err(eyre!(
                "historical edge roots differ from its physical custodian"
            ));
        }
        Ok(())
    }

    fn physical_hosts(&self) -> Result<(PhysicalHost, PhysicalHost)> {
        let hosts = self
            .hosts
            .as_object()
            .ok_or_else(|| eyre!("historical hosts must be an object"))?;
        if hosts.get("schema").and_then(Value::as_str)
            != Some("iroha.taira.public-reset.host-pair.v1")
            || hosts.get("provider").and_then(Value::as_str) != Some("macstadium-dublin")
        {
            return Err(eyre!(
                "historical hosts do not bind the approved physical provider"
            ));
        }
        let project = |name: &str| -> Result<PhysicalHost> {
            let value = hosts
                .get(name)
                .ok_or_else(|| eyre!("historical physical host absent"))?;
            json::from_value(value.clone())
                .map_err(|_| eyre!("historical physical host identity is invalid"))
        };
        Ok((project("validator_guest")?, project("native_edge")?))
    }

    /// Bind only immutable physical identity; current execution capabilities validate separately.
    pub(super) fn validate_physical_binding(
        &self,
        current: &host_pair::ResetHostPairV1,
    ) -> Result<()> {
        current.validate()?;
        let (guest, edge) = self.physical_hosts()?;
        guest.bind_current(&current.validator_guest)?;
        edge.bind_current(&current.native_edge)
    }
}

/// This projection deliberately has no executable or interpreter capability field.
#[cfg(any(target_os = "linux", test))]
#[derive(JsonDeserialize)]
struct PhysicalHost {
    endpoint: host_pair::HostSshRouteV1,
    platform: PlatformV1,
    owner_uid: u32,
    owner_gid: u32,
    owner_home: String,
    custody_root: String,
    dispatcher_path: String,
    capture_public_key: String,
}

#[cfg(any(target_os = "linux", test))]
impl PhysicalHost {
    fn bind_role(&self, endpoint: &EndpointV1, platform: &PlatformV1) -> Result<()> {
        if endpoint.hostname != self.endpoint.hostname
            || endpoint.port != self.endpoint.port
            || endpoint.user != self.endpoint.user
            || endpoint.known_host_line_sha256 != self.endpoint.known_host_line_sha256
            || endpoint.host_identity_sha256 != self.endpoint.host_identity_sha256
            || json::to_vec(platform)? != json::to_vec(&self.platform)?
        {
            return Err(eyre!(
                "historical role differs from its signed physical host"
            ));
        }
        Ok(())
    }

    fn bind_current(&self, current: &host_pair::ResetHostV1) -> Result<()> {
        if json::to_vec(&self.endpoint)? != json::to_vec(&current.endpoint)?
            || json::to_vec(&self.platform)? != json::to_vec(&current.platform)?
            || self.owner_uid != current.owner_uid
            || self.owner_gid != current.owner_gid
            || self.owner_home != current.owner_home
            || self.custody_root != current.custody_root
            || self.dispatcher_path != current.dispatcher_path
            || self.capture_public_key != current.capture_public_key
        {
            return Err(eyre!(
                "historical inventory changes immutable physical host custody"
            ));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
impl TerminalEdge {
    pub(super) fn admitted_release(&self) -> Result<&EdgeAdmittedReleaseV1> {
        match &self.initial_state {
            EdgeInitialStateV1::AdmittedRelease(release) => Ok(release),
            EdgeInitialStateV1::Vacant => {
                Err(eyre!("vacant historical edge has no admitted release"))
            }
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn validate_edge_custody(edge: &TerminalEdge, revision: &RevisionV1) -> Result<()> {
    if edge.slug != "taira-edge"
        || edge.state_root != format!("{}/state", edge.service_root)
        || edge.platform.os != "macos"
        || edge.platform.arch != "aarch64"
        || edge.platform.kvm_api_version != 0
    {
        return Err(eyre!("historical edge role or platform differs"));
    }
    validate_absolute_normal_path(Path::new(&edge.nginx_config), "historical edge publication")?;
    if let EdgeInitialStateV1::AdmittedRelease(release) = &edge.initial_state {
        validate_lower_hex("historical edge release commit", &release.commit, 40)?;
        validate_lower_hex("historical edge rollback CLI", &release.cli_sha256, 64)?;
        validate_lower_hex(
            "historical edge rollback config",
            &release.config_sha256,
            64,
        )?;
        if release.commit == revision.commit
            || release.release_root != format!("{}/releases/{}", edge.service_root, release.commit)
        {
            return Err(eyre!("historical edge predecessor release differs"));
        }
    }
    validate_artifacts(
        &edge.artifacts,
        &EDGE_ARTIFACT_ROLES,
        &edge.service_root,
        revision,
        host_pair::NATIVE_EDGE_TARGET,
    )?;
    let release = format!("{}/releases/{}", edge.service_root, revision.commit);
    require_remote_artifact(
        &edge.artifacts,
        "iroha_cli",
        &format!("{release}/bin/iroha"),
    )?;
    require_remote_artifact(
        &edge.artifacts,
        "edge_config",
        &format!("{release}/taira.conf"),
    )?;
    if edge.endpoint.remote_cli != format!("{release}/bin/iroha") {
        return Err(eyre!("historical edge CLI differs from its signed release"));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn validate_inventory_custody(inventory: &TerminalInventory) -> Result<()> {
    if inventory.schema != INVENTORY_SCHEMA_V1 {
        return Err(eyre!("inventory schema must be `{INVENTORY_SCHEMA_V1}`"));
    }
    validator_operator_public_key(&inventory.operator_public_key)?;
    if inventory.chain_id != CHAIN_ID || inventory.chain_discriminant != CHAIN_DISCRIMINANT {
        return Err(eyre!(
            "historical inventory must bind the canonical Taira chain identity"
        ));
    }
    validate_slug("deployment_id", &inventory.deployment_id)?;
    for (label, value) in [
        (
            "runtime client-config SHA-256",
            inventory.runtime_client_config_sha256.as_str(),
        ),
        (
            "onboarding-token SHA-256",
            inventory.onboarding_token_sha256.as_str(),
        ),
        (
            "validator client-config closure SHA-256",
            inventory.validator_client_configs_sha256.as_str(),
        ),
    ] {
        validate_lower_hex(label, value, 64)?;
    }
    inventory.validate_inrou_scope()?;
    for (label, value) in [
        (
            "previous genesis hash",
            inventory.previous_genesis_hash.as_str(),
        ),
        ("next genesis hash", inventory.next_genesis_hash.as_str()),
    ] {
        validate_canonical_iroha_hash(label, value)?;
    }
    if inventory.previous_genesis_hash == inventory.next_genesis_hash {
        return Err(eyre!(
            "public reset must bind distinct previous and next genesis hashes"
        ));
    }
    validate_nonce(&inventory.authorization_nonce)?;
    validate_revision_source_fields(&inventory.revision)?;
    validate_revision_build_fields(&inventory.revision)?;
    validate_timeouts(&inventory.timeouts)?;
    validate_canary_onboarding_request(&inventory.canary_onboarding_request)?;
    validate_faucet_policy(&inventory.faucet_policy)?;
    validate_fee_intent(&inventory.fee_intent)?;
    validate_cleanup(&inventory.cleanup)?;
    if inventory.validators.len() != VALIDATOR_SLUGS.len() {
        return Err(eyre!("inventory must contain exactly four validators"));
    }
    if inventory.validator_clients.len() != VALIDATOR_SLUGS.len() {
        return Err(eyre!(
            "inventory must bind exactly four ordered validator client identities"
        ));
    }

    let mut node_fingerprints = BTreeSet::new();
    let mut build_fingerprint = None;
    let mut config_fingerprint = None;
    for (validator, expected_slug) in inventory.validators.iter().zip(VALIDATOR_SLUGS) {
        validate_validator(
            validator,
            expected_slug,
            &inventory.revision,
            inventory.qualification_scope,
        )?;
        if !node_fingerprints.insert(validator.node_fingerprint.clone()) {
            return Err(eyre!("validator node fingerprints must be distinct"));
        }
        match &build_fingerprint {
            None => build_fingerprint = Some(validator.build_fingerprint.clone()),
            Some(expected) if expected == &validator.build_fingerprint => {}
            Some(_) => return Err(eyre!("validators must report one signed build fingerprint")),
        }
        match &config_fingerprint {
            None => config_fingerprint = Some(validator.config_fingerprint.clone()),
            Some(expected) if expected == &validator.config_fingerprint => {}
            Some(_) => {
                return Err(eyre!(
                    "validators must report one signed consensus-config fingerprint"
                ));
            }
        }
    }
    let mut client_accounts = BTreeSet::new();
    let mut client_peers = BTreeSet::new();
    let mut probe_origins = BTreeSet::new();
    let mut client_placement_targets = BTreeSet::new();
    for (client, expected_slug) in inventory.validator_clients.iter().zip(VALIDATOR_SLUGS) {
        validate_validator_public_origin(&client.torii_origin)?;
        // Historical public routes are signed custody, never candidate routing.
        // A predecessor may have exposed all four clients through its single root.
        validate_candidate_probe_origin(&client.probe_origin)?;
        if !probe_origins.insert(&client.probe_origin) {
            return Err(eyre!(
                "candidate Torii origins must bind four distinct sockets"
            ));
        }
        if client.slug != expected_slug
            || client.account_id.is_empty()
            || client.peer_id.is_empty()
            || !client_accounts.insert(client.account_id.clone())
            || !client_peers.insert(client.peer_id.clone())
        {
            return Err(eyre!(
                "validator client identities must bind four distinct ordered account/peer pairs and Torii origins"
            ));
        }
        let account = AccountId::parse_encoded(&client.account_id)
            .wrap_err("validator client account identity is not canonical")?;
        if account.to_string() != client.account_id {
            return Err(eyre!(
                "validator client account identity is not canonical I105"
            ));
        }
        let peer = client
            .peer_id
            .parse::<PeerId>()
            .wrap_err("validator client peer identity is not canonical")?;
        if peer.to_string() != client.peer_id {
            return Err(eyre!("validator client peer identity is not canonical"));
        }
        let target = SoraInrouPlacementTargetV1 {
            peer_id: client.peer_id.clone(),
            validator_account_id: account,
        };
        target.validate()?;
        client_placement_targets.insert(target);
    }
    if let Some(canary) = &inventory.inrou_canary
        && canary.placement_targets != client_placement_targets
    {
        return Err(eyre!(
            "Inrou canary placement targets must equal the exact four validator client identities"
        ));
    }
    inventory.validate_host_custody()?;
    validate_edge_custody(&inventory.edge, &inventory.revision)?;
    validate_lower_hex(
        "artifact closure SHA-256",
        &inventory.artifact_closure_sha256,
        64,
    )?;
    let computed = artifact_closure_sha256(inventory);
    if computed != inventory.artifact_closure_sha256 {
        return Err(eyre!(
            "artifact closure SHA-256 mismatch: inventory `{}`, computed `{computed}`",
            inventory.artifact_closure_sha256
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn artifact_closure_sha256(inventory: &TerminalInventory) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iroha:taira:public-reset:artifact-closure:v1\0");
    for value in [
        inventory.revision.commit.as_str(),
        inventory.revision.branch.as_str(),
        inventory.revision.tree.as_str(),
        inventory.revision.cargo_lock_sha256.as_str(),
        inventory.revision.source_manifest_sha256.as_str(),
        inventory.revision.source_closure_sha256.as_str(),
        inventory.revision.target.as_str(),
        inventory.revision.profile.as_str(),
        inventory.previous_genesis_hash.as_str(),
        inventory.next_genesis_hash.as_str(),
    ] {
        update_framed(&mut digest, value.as_bytes());
    }
    for artifact in inventory
        .validators
        .iter()
        .flat_map(|validator| validator.artifacts.iter())
        .chain(inventory.edge.artifacts.iter())
    {
        for value in [
            artifact.role.as_str(),
            artifact.remote_path.as_str(),
            artifact.sha256.as_str(),
        ] {
            update_framed(&mut digest, value.as_bytes());
        }
        update_framed(&mut digest, &artifact.size.to_be_bytes());
        update_framed(&mut digest, &artifact.mode.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

#[cfg(any(target_os = "linux", test))]
fn verify_authorization_claims(
    inventory: &TerminalInventory,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
) -> Result<()> {
    if envelope.schema != AUTHORIZATION_SCHEMA_V1 {
        return Err(eyre!(
            "authorization schema must be `{AUTHORIZATION_SCHEMA_V1}`"
        ));
    }
    if trusted.schema != TRUSTED_KEY_SCHEMA_V1 || trusted.algorithm != "ed25519" {
        return Err(eyre!(
            "trusted key must use schema `{TRUSTED_KEY_SCHEMA_V1}` and algorithm `ed25519`"
        ));
    }
    let claims = &envelope.claims;
    if claims.action != "reset_and_deploy"
        || claims.qualification_scope != inventory.qualification_scope
        || claims.deployment_id != inventory.deployment_id
        || claims.inventory_sha256 != inventory_sha256
        || claims.artifact_closure_sha256 != inventory.artifact_closure_sha256
        || claims.runtime_client_config_sha256 != inventory.runtime_client_config_sha256
        || claims.onboarding_token_sha256 != inventory.onboarding_token_sha256
        || claims.validator_client_configs_sha256 != inventory.validator_client_configs_sha256
        || claims.inrou_stage_tree_sha256 != inventory.inrou_stage_tree_sha256
        || claims.faucet_policy != inventory.faucet_policy
        || claims.fee_intent != inventory.fee_intent
        || claims.authorization_nonce != inventory.authorization_nonce
    {
        return Err(eyre!(
            "authorization claims do not exactly bind this reset inventory"
        ));
    }
    validate_lower_hex(
        "authorization inventory SHA-256",
        &claims.inventory_sha256,
        64,
    )?;
    for (label, value) in [
        (
            "runtime client-config SHA-256",
            claims.runtime_client_config_sha256.as_str(),
        ),
        (
            "onboarding-token SHA-256",
            claims.onboarding_token_sha256.as_str(),
        ),
        (
            "validator client-config closure SHA-256",
            claims.validator_client_configs_sha256.as_str(),
        ),
    ] {
        validate_lower_hex(label, value, 64)?;
    }
    inventory.validate_inrou_scope()?;
    if claims.not_before_unix_ms < claims.issued_at_unix_ms
        || claims.expires_at_unix_ms <= claims.not_before_unix_ms
        || claims.expires_at_unix_ms - claims.issued_at_unix_ms > MAX_AUTHORIZATION_LIFETIME_MS
    {
        return Err(eyre!(
            "authorization time window is invalid or exceeds 15 minutes"
        ));
    }
    if claims.execution_expires_at_unix_ms < claims.expires_at_unix_ms
        || claims.execution_expires_at_unix_ms - claims.issued_at_unix_ms
            > MAX_EXECUTION_LIFETIME_MS
    {
        return Err(eyre!(
            "authorization execution lease does not cover admission within its finite bound"
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn decode(
    bytes: &[u8],
    label: &str,
) -> Result<(TerminalInventory, ChainDiscriminantGuard)> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(eyre!(
            "{label} is empty or exceeds the inventory custody bound"
        ));
    }
    let guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    let inventory: TerminalInventory = json::from_slice(bytes)
        .map_err(|_| eyre!("{label} is not exact inventory custody JSON"))?;
    validate_inventory_custody(&inventory)?;
    Ok((inventory, guard))
}

/// Authenticate the original historical bytes, not a re-encoded projection.
/// Its finite signed lease was admitted by its executor. A successor does not
/// recalculate that lease using a different execution plan or authorize a replay.
#[cfg(any(target_os = "linux", test))]
pub(super) fn verify_authorization(
    inventory: &TerminalInventory,
    inventory_sha256: &str,
    envelope: &AuthorizationEnvelopeV1,
    trusted: &TrustedKeyV1,
) -> Result<()> {
    verify_authorization_claims(inventory, inventory_sha256, envelope, trusted)?;
    verify_authorization_signature(envelope, trusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{KeyPair, Signature};

    fn opaque_inventory_bytes() -> Vec<u8> {
        let inventory = sample_inventory_fixture();
        let mut value: Value =
            json::from_slice(&canonical_inventory_bytes(&inventory).unwrap()).unwrap();
        value.as_object_mut().unwrap().insert(
            "beacon_bootstrap".into(),
            norito::json!({"uninterpreted_execution": {"round": 17}}),
        );
        json::to_vec(&value).unwrap()
    }

    fn sign(
        inventory: &TerminalInventory,
        bytes: &[u8],
    ) -> (AuthorizationEnvelopeV1, TrustedKeyV1) {
        let key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).unwrap();
        let issued = 990_000;
        let claims = AuthorizationClaimsV1 {
            action: "reset_and_deploy".into(),
            qualification_scope: inventory.qualification_scope,
            deployment_id: inventory.deployment_id.clone(),
            inventory_sha256: sha256_hex(bytes),
            artifact_closure_sha256: inventory.artifact_closure_sha256.clone(),
            runtime_client_config_sha256: inventory.runtime_client_config_sha256.clone(),
            onboarding_token_sha256: inventory.onboarding_token_sha256.clone(),
            validator_client_configs_sha256: inventory.validator_client_configs_sha256.clone(),
            inrou_stage_tree_sha256: inventory.inrou_stage_tree_sha256.clone(),
            faucet_policy: inventory.faucet_policy.clone(),
            fee_intent: inventory.fee_intent.clone(),
            authorization_nonce: inventory.authorization_nonce.clone(),
            issued_at_unix_ms: issued,
            not_before_unix_ms: issued,
            expires_at_unix_ms: issued + MAX_AUTHORIZATION_LIFETIME_MS,
            // Historical custody does not imply the current executor's action count.
            execution_expires_at_unix_ms: issued + 2 * MAX_AUTHORIZATION_LIFETIME_MS,
        };
        let signature =
            Signature::try_new(key.private_key(), &authorization_message(&claims).unwrap())
                .unwrap();
        (
            AuthorizationEnvelopeV1 {
                schema: AUTHORIZATION_SCHEMA_V1.into(),
                claims,
                signature_hex: hex::encode(signature.payload()),
            },
            TrustedKeyV1 {
                schema: TRUSTED_KEY_SCHEMA_V1.into(),
                algorithm: "ed25519".into(),
                public_key: key.public_key().to_string(),
            },
        )
    }

    #[test]
    fn terminal_custody_does_not_admit_an_opaque_execution_payload() {
        let bytes = opaque_inventory_bytes();
        let (inventory, _guard) = decode(&bytes, "terminal").unwrap();
        let current = sample_inventory_fixture().hosts;
        let intent = inventory.topology_intent(&current).unwrap();
        inputs::validate_topology_intent(&intent).unwrap();
        assert!(decode_inventory(&bytes, "candidate").is_err());
        let (authorization, trusted) = sign(&inventory, &bytes);
        verify_authorization(&inventory, &sha256_hex(&bytes), &authorization, &trusted).unwrap();
    }

    #[test]
    fn terminal_custody_still_binds_exact_raw_bytes_claims_and_signer() {
        let bytes = opaque_inventory_bytes();
        let (inventory, _guard) = decode(&bytes, "terminal").unwrap();
        let (authorization, trusted) = sign(&inventory, &bytes);
        let mut reformatted = bytes.clone();
        reformatted.push(b'\n');
        assert!(
            verify_authorization(
                &inventory,
                &sha256_hex(&reformatted),
                &authorization,
                &trusted
            )
            .is_err()
        );
        let mut changed: Value = json::from_slice(&bytes).unwrap();
        changed
            .as_object_mut()
            .unwrap()
            .insert("beacon_bootstrap".into(), Value::Null);
        let changed = json::to_vec(&changed).unwrap();
        let (changed_inventory, _changed_guard) = decode(&changed, "terminal").unwrap();
        assert!(
            verify_authorization(
                &changed_inventory,
                &sha256_hex(&changed),
                &authorization,
                &trusted
            )
            .is_err()
        );
        let mut altered = inventory.clone();
        altered.authorization_nonce = "9".repeat(32);
        assert!(
            verify_authorization(&altered, &sha256_hex(&bytes), &authorization, &trusted).is_err()
        );
        let mut wrong_signer = trusted.clone();
        wrong_signer.public_key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_string();
        assert!(
            verify_authorization(
                &inventory,
                &sha256_hex(&bytes),
                &authorization,
                &wrong_signer
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_custody_accepts_opaque_retired_capabilities_and_shared_public_routes() {
        let fixture = sample_inventory_fixture();
        let mut value: Value =
            json::from_slice(&canonical_inventory_bytes(&fixture).unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        let hosts = object.get_mut("hosts").unwrap().as_object_mut().unwrap();
        let old_python = hosts
            .get_mut("native_edge")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("native_python")
            .unwrap();
        hosts
            .get_mut("validator_guest")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("native_python");
        hosts.insert("native_python".into(), old_python);
        object
            .get_mut("edge")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "native_capability".into(),
                norito::json!({"retired_owner_execution": [1, 2, 3]}),
            );
        object.insert(
            "beacon_bootstrap".into(),
            norito::json!({"retired_beacon_execution": true}),
        );
        for client in object
            .get_mut("validator_clients")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            client.as_object_mut().unwrap().insert(
                "torii_origin".into(),
                Value::from("https://taira.sora.org/"),
            );
        }
        let bytes = json::to_vec(&value).unwrap();
        let (inventory, _guard) = decode(&bytes, "historical").unwrap();
        inventory.validate_physical_binding(&fixture.hosts).unwrap();
        let intent = inventory.topology_intent(&fixture.hosts).unwrap();
        assert_eq!(
            intent.validator_clients[0].torii_origin,
            "https://taira.sora.org/"
        );
        assert_eq!(
            intent.validator_clients[3].torii_origin,
            "https://taira.sora.org/"
        );
        let (authorization, trusted) = sign(&inventory, &bytes);
        verify_authorization(&inventory, &sha256_hex(&bytes), &authorization, &trusted).unwrap();
        assert!(decode_inventory(&bytes, "candidate").is_err());
        let mut current = fixture;
        for client in &mut current.validator_clients {
            client.torii_origin = "https://taira.sora.org/".into();
        }
        assert!(validate_inventory_custody_with_revision(&current, |_| Ok(())).is_err());
    }

    #[test]
    fn terminal_custody_binds_physical_identity_without_replaying_old_programs() {
        let fixture = sample_inventory_fixture();
        let bytes = canonical_inventory_bytes(&fixture).unwrap();
        let (inventory, _guard) = decode(&bytes, "historical").unwrap();
        let mut current = fixture.hosts.clone();
        current.validator_guest.dispatcher_sha256 = "9".repeat(64);
        current.native_edge.guard_sha256 = "8".repeat(64);
        inventory.validate_physical_binding(&current).unwrap();
        for index in 0..8 {
            let mut changed = current.clone();
            match index {
                0 => changed.validator_guest.endpoint.hostname = "other-guest.example.org".into(),
                1 => changed.native_edge.endpoint.known_host_line_sha256 = "3".repeat(64),
                2 => changed.validator_guest.endpoint.host_identity_sha256 = "4".repeat(64),
                3 => changed.native_edge.owner_gid += 1,
                4 => {
                    changed.native_edge.capture_public_key =
                        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
                            .unwrap()
                            .public_key()
                            .to_string()
                }
                5 => changed.validator_guest.custody_root.push_str("-other"),
                6 => changed.native_edge.dispatcher_path.push_str("-other"),
                7 => changed.provider = "other".into(),
                _ => unreachable!(),
            }
            assert!(
                inventory.validate_physical_binding(&changed).is_err(),
                "case {index}"
            );
            assert!(inventory.topology_intent(&changed).is_err(), "case {index}");
        }
        let mut value: Value = json::from_slice(&bytes).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .get_mut("hosts")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("validator_guest")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("endpoint")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("hostname".into(), Value::from("other-guest.example.org"));
        assert!(decode(&json::to_vec(&value).unwrap(), "historical").is_err());
    }

    #[test]
    fn terminal_custody_rejects_reordered_signed_artifacts() {
        let fixture = sample_inventory_fixture();
        let bytes = canonical_inventory_bytes(&fixture).unwrap();
        let (mut inventory, _guard) = decode(&bytes, "historical").unwrap();
        inventory.validators[0].artifacts.swap(0, 1);
        assert!(validate_inventory_custody(&inventory).is_err());
        let (mut inventory, _guard) = decode(&bytes, "historical").unwrap();
        inventory.edge.artifacts.swap(0, 1);
        assert!(validate_inventory_custody(&inventory).is_err());
        let (mut inventory, _guard) = decode(&bytes, "historical").unwrap();
        inventory.edge.artifacts[0].sha256 = "3".repeat(64);
        assert!(validate_inventory_custody(&inventory).is_err());
    }

    #[test]
    fn terminal_custody_rejects_wrong_chain_roles_artifacts_and_unknown_metadata() {
        let bytes = opaque_inventory_bytes();
        for (field, replacement) in [
            ("chain_id", Value::from("wrong-chain")),
            ("chain_discriminant", Value::from(753_u16)),
            ("authorization_nonce", Value::from("bad")),
            ("artifact_closure_sha256", Value::from("0".repeat(64))),
            ("validators", Value::Array(Vec::new())),
            ("unrecognized_metadata", Value::Null),
        ] {
            let mut value: Value = json::from_slice(&bytes).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), replacement);
            assert!(
                decode(&json::to_vec(&value).unwrap(), "terminal").is_err(),
                "{field}"
            );
        }
    }
}
