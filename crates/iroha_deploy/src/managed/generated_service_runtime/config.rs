//! Fixed generated configuration projection; ordinary config parsing remains authoritative.
use super::*;
use crate::localnet::service_authorities::{
    NetworkServiceAuthorityRole as NetworkRole, RetainedGatewayCompliancePlan,
    RetainedProviderServicePlan, StreamTokenAuthorityRole as Role,
};
use crate::managed::service_policies::GeneratedProviderPolicies;
use iroha_config::{
    node_config::{NodeConfigOptions, NodeFile, open_node_config},
    parameters::{actual, defaults::sorafs::gateway::compliance as compliance_defaults},
    sora_profile::SoraProfileSelection,
};
use sorafs_manifest::signer::custody::SignerCustodyAuthorityV1;
use std::time::Duration;
use toml::{Table, Value};
use zeroize::Zeroizing;

fn section<'a>(table: &'a mut Table, path: &[&str]) -> Result<&'a mut Table> {
    let mut cursor = table;
    for name in path {
        cursor = cursor
            .entry((*name).to_owned())
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .ok_or_else(|| invalid("generated runtime config section differs"))?;
    }
    Ok(cursor)
}
fn text(table: &mut Table, key: &str, value: impl Into<String>) {
    crate::secret_toml::insert(table, key.into(), Value::String(value.into()));
}
fn number(table: &mut Table, key: &str, value: u64) -> Result<()> {
    table.insert(
        key.into(),
        Value::Integer(
            i64::try_from(value)
                .map_err(|_| invalid("generated runtime integer exceeds TOML bound"))?,
        ),
    );
    Ok(())
}
fn duration(table: &mut Table, key: &str, value: Duration) -> Result<()> {
    let mut encoded = Table::new();
    number(&mut encoded, "secs", value.as_secs())?;
    number(&mut encoded, "nanos", u64::from(value.subsec_nanos()))?;
    table.insert(key.into(), Value::Table(encoded));
    Ok(())
}
fn flag(table: &mut Table, key: &str, value: bool) {
    table.insert(key.into(), Value::Boolean(value));
}
fn path(table: &mut Table, key: &str, value: &Path) -> Result<()> {
    text(
        table,
        key,
        value
            .to_str()
            .ok_or_else(|| invalid("generated runtime path is not UTF-8"))?,
    );
    Ok(())
}
fn raw_public(key: &iroha_crypto::PublicKey) -> Result<String> {
    if key.try_algorithm().ok() != Some(iroha_crypto::Algorithm::Ed25519) {
        return Err(invalid("generated runtime role is not Ed25519"));
    }
    Ok(hex::encode(key.to_bytes().1))
}
fn role_key(
    authority: &ServiceAuthority,
    provider: ProviderId,
    role: Role,
) -> Result<&iroha_crypto::PublicKey> {
    authority
        .provider_inventory(provider)?
        .authority(role)?
        .account
        .try_signatory()
        .ok_or_else(|| invalid("generated runtime role is not a direct key"))
}
fn role_path(root: &Path, slot: u8, role: Role) -> PathBuf {
    root.join("runtime")
        .join("stream-token-authorities")
        .join("providers")
        .join(slot.to_string())
        .join(role.credential_filename())
}
fn network_role_path(root: &Path, role: NetworkRole) -> PathBuf {
    root.join("runtime")
        .join("stream-token-authorities")
        .join("network")
        .join(role.credential_filename())
}

pub(super) fn parse(table: Table, source: &Path, sora: bool) -> Result<actual::Root> {
    if table.contains_key("extends") || table.contains_key("profile") {
        return Err(invalid(
            "generated runtime requires its original flat configuration",
        ));
    }
    let _chain = table
        .get("chain_discriminant")
        .and_then(Value::as_integer)
        .and_then(|value| u16::try_from(value).ok())
        .map(ChainDiscriminantGuard::enter);
    let selection = SoraProfileSelection::from_table(&table);
    let reader = open_node_config(
        NodeFile::Verified {
            path: source.to_owned(),
            table,
        },
        NodeConfigOptions::default(),
    )
    .map_err(|_| invalid("invalid generated runtime node layout"))?;
    let (user, _) = reader
        .read()
        .map_err(|_| invalid("invalid generated runtime node configuration"))?;
    let mut actual = user
        .parse()
        .map_err(|_| invalid("invalid generated runtime configuration"))?;
    if sora {
        selection.apply(&mut actual);
    }
    Ok(actual)
}

/// Original input and destination custody for one generated peer configuration.
#[derive(Clone, Copy)]
pub(super) struct RenderTarget<'a> {
    pub index: usize,
    pub original: &'a [u8],
    pub destination: &'a Path,
    pub material: &'a PrivateDirectory,
    pub provider_material: Option<&'a PrivateDirectory>,
}

/// A new sibling retains every existing source-relative path and the original generation cwd.
pub(super) fn render(
    authority: &ServiceAuthority,
    selection: &RuntimeSelection,
    intent: &Intent,
    components: Option<&[Arc<ProviderComponent>; 3]>,
    target: RenderTarget<'_>,
) -> Result<Zeroizing<String>> {
    let RenderTarget {
        index,
        original,
        destination,
        material,
        provider_material,
    } = target;
    let policies = &selection.policies;
    if index >= 4 || (index < 3) != provider_material.is_some() {
        return Err(invalid(
            "generated runtime provider directory selection differs",
        ));
    }
    if *Hash::new(encode(policies, MAX_POLICY_BYTES)?).as_ref() != intent.policies {
        return Err(invalid(
            "generated runtime differs from its original selected policies",
        ));
    }
    let text_source =
        std::str::from_utf8(original).map_err(|_| invalid("invalid original peer TOML"))?;
    let mut table = crate::secret_toml::Table::new(
        crate::secret_toml::parse_table(text_source, "generated runtime original")
            .map_err(|_| invalid("invalid original peer TOML"))?,
    );
    let before = parse(
        table.clone(),
        &authority.prepared.peers[index].config_path,
        false,
    )?;
    if before.musubi_publication.installation.is_some() {
        return Err(invalid(
            "original peer already contains a publication installation",
        ));
    }
    let signed_fees = iroha_genesis::signed_genesis_root_fee_policy(&authority.genesis.genesis)
        .map_err(|_| invalid("invalid original signed fee policy"))?;
    let expected =
        crate::localnet::service_authorities::configured_execution_policy(&before, &signed_fees)
            .map_err(|_| invalid("invalid original execution policy"))?;
    let nexus = section(&mut table, &["nexus"])?;
    // An omitted catalog has a precise default meaning in this sole config owner. Preserve it
    // explicitly rather than reconstructing model catalogs in a second TOML serializer.
    nexus
        .entry("lane_count")
        .or_insert(Value::Integer(i64::from(
            before.nexus.lane_catalog.lane_count().get(),
        )));
    nexus
        .entry("lane_catalog")
        .or_insert_with(|| Value::Array(Vec::new()));
    nexus
        .entry("dataspace_catalog")
        .or_insert_with(|| Value::Array(Vec::new()));
    nexus
        .entry("routing_policy")
        .or_insert_with(|| Value::Table(Table::new()));
    let discovery = section(&mut table, &["sorafs", "discovery"])?;
    flag(discovery, "discovery_enabled", true);
    path(
        discovery,
        "replay_checkpoint_path",
        &material
            .path()
            .join(format!("peer{index}-advert-replay.nrt")),
    )?;
    let storage = section(&mut table, &["sorafs", "storage"])?;
    flag(storage, "enabled", index < 3);
    flag(
        section(storage, &["provider_ingest_runtime"])?,
        "enabled",
        false,
    );
    // These are fresh generated workers; disabled generators do not disable durable replay.
    flag(
        section(&mut table, &["sorafs", "repair"])?,
        "enabled",
        false,
    );
    flag(section(&mut table, &["sorafs", "por"])?, "enabled", false);
    flag(
        section(&mut table, &["sorafs", "storage", "reserve_worker"])?,
        "enabled",
        false,
    );
    flag(
        section(&mut table, &["sorafs", "storage", "orderbook_worker"])?,
        "enabled",
        false,
    );
    if index < 3 {
        let plan = &selection.plans[index];
        let compliance = &selection.compliance[index];
        let provider_material =
            provider_material.ok_or_else(|| invalid("generated provider directory absent"))?;
        let storage = section(&mut table, &["sorafs", "storage"])?;
        text(
            storage,
            "provider_id_hex",
            hex::encode(plan.provider_id().as_bytes()),
        );
        let capacity = plan
            .declaration()
            .committed_capacity_gib
            .checked_mul(1_u64 << 30)
            .ok_or_else(|| invalid("generated provider capacity overflows bytes"))?;
        number(storage, "max_capacity_bytes", capacity)?;
        native_signers(&mut table, authority, policies, plan)?;
        configure_compliance(&mut table, compliance, provider_material)?;
        if intent.stage == GeneratedRuntimeStage::StreamTokens {
            let component = &components.ok_or_else(|| invalid("token components absent"))?[index];
            if component.directory().path() != provider_material.path() {
                return Err(invalid(
                    "token component directory differs from selected provider",
                ));
            }
            configure_tokens(&mut table, authority, policies, plan, component)?;
            configure_ingest(&mut table, authority, policies, plan, &selection.plans)?;
        }
    }
    let installs_publication = intent.stage == GeneratedRuntimeStage::StreamTokens
        && index == selection.publication.peer_index();
    if installs_publication {
        table.insert(
            "musubi_publication".into(),
            Value::Table(selection.publication.configuration_table()?),
        );
    }
    let after = parse(table.clone(), destination, true)?;
    let expected_publication = if installs_publication {
        selection.publication.installation_config()
    } else {
        before.musubi_publication.clone()
    };
    if after.nexus.lane_catalog != before.nexus.lane_catalog
        || after.nexus.dataspace_catalog != before.nexus.dataspace_catalog
        || crate::localnet::service_authorities::configured_execution_policy(&after, &signed_fees)
            .map_err(|_| invalid("invalid derived execution policy"))?
            != expected
        || after.genesis.expected_hash != before.genesis.expected_hash
        || after.kura.store_dir.resolve_relative_path()
            != before.kura.store_dir.resolve_relative_path()
        || after.common.key_pair.public_key() != before.common.key_pair.public_key()
        || after.torii.sorafs_storage.data_dir != before.torii.sorafs_storage.data_dir
        || !after.torii.sorafs_discovery.discovery_enabled
        || after.torii.sorafs_discovery.admission.is_none()
        || after.torii.sorafs_storage.enabled != (index < 3)
        || after.torii.sorafs_storage.stream_tokens.enabled
            != (index < 3 && intent.stage == GeneratedRuntimeStage::StreamTokens)
        || after.torii.sorafs_storage.provider_ingest_runtime.is_some()
            != (index < 3 && intent.stage == GeneratedRuntimeStage::StreamTokens)
        || after.torii.sorafs_gateway.compliance.is_some() != (index < 3)
        || after.musubi_publication != expected_publication
    {
        return Err(invalid(
            "derived service configuration changed its original identity or policy",
        ));
    }
    let rendered = Zeroizing::new(
        toml::to_string(&*table)
            .map_err(|_| invalid("cannot encode generated runtime configuration"))?,
    );
    if rendered.len() > MAX_CONFIG_BYTES {
        return Err(invalid("generated runtime configuration exceeds bound"));
    }
    Ok(rendered)
}

fn native_signers(
    table: &mut Table,
    authority: &ServiceAuthority,
    policies: &GeneratedServicePolicies,
    plan: &RetainedProviderServicePlan,
) -> Result<()> {
    let inventory = authority.provider_inventory(plan.provider_id())?;
    let policy = encode(policies, MAX_POLICY_BYTES)?;
    let root = generation_path(&authority.prepared)?;
    let mut bindings = Vec::with_capacity(4);
    for (label, role) in [
        ("proof_outcome", Role::ProofOutcome),
        ("repair", Role::Repair),
        ("orderbook", Role::OrderbookMatcher),
    ] {
        bindings.push((
            label,
            &inventory.authority(role)?.account,
            role_path(root, plan.slot(), role),
        ));
    }
    bindings.push((
        "reserve",
        authority.network_role(NetworkRole::ReserveOperations)?,
        network_role_path(root, NetworkRole::ReserveOperations),
    ));
    for (label, account, credential) in bindings {
        let key = account
            .try_signatory()
            .ok_or_else(|| invalid("native runtime role is not a direct key"))?;
        let digest = Hash::new_from_chunks(&[
            b"iroha:generated-native-software-binding:v1\0",
            authority.config.network_id.as_bytes(),
            plan.provider_id().as_bytes(),
            label.as_bytes(),
            key.to_bytes().1,
            &policy,
        ]);
        let binding = section(
            table,
            &["sorafs", "storage", "native_transaction_signers", label],
        )?;
        path(binding, "software_credential", &credential)?;
        text(binding, "handle", format!("software://managed/{label}"));
        text(binding, "authority", account.to_string());
        text(binding, "algorithm", "ed25519");
        text(binding, "public_key_hex", raw_public(key)?);
        number(binding, "revision", 1)?;
        text(binding, "policy_digest_hex", hex::encode(digest.as_ref()));
    }
    Ok(())
}

fn configure_compliance(
    table: &mut Table,
    plan: &RetainedGatewayCompliancePlan,
    material: &PrivateDirectory,
) -> Result<()> {
    let config = section(table, &["sorafs", "gateway", "compliance"])?;
    let trust = plan.trust_policy();
    flag(config, "enabled", true);
    text(
        config,
        "feed_transport_provider_handle",
        compliance_defaults::GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1,
    );
    number(
        config,
        "feed_transport_provider_revision",
        compliance_defaults::GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
    )?;
    text(
        config,
        "feed_transport_provider_policy_digest_hex",
        hex::encode(plan.empty_feed_transport_digest()),
    );
    path(
        config,
        "checkpoint_path",
        &material.path().join("gateway-compliance.nrt"),
    )?;
    text(config, "policy_id_hex", hex::encode(trust.policy_id));
    text(config, "region_id", "local");
    text(config, "gateway_id", plan.gateway_label());
    number(
        config,
        "catalog_threshold",
        u64::from(trust.catalog_threshold),
    )?;
    number(
        config,
        "gateway_ack_threshold",
        u64::from(trust.gateway_ack_threshold),
    )?;
    for (name, signers) in [
        ("catalog_signers", &trust.catalog_signers),
        ("gateway_signers", &trust.gateway_signers),
    ] {
        config.insert(
            name.into(),
            Value::Array(
                signers
                    .iter()
                    .map(|signer| {
                        Value::Table(Table::from_iter([
                            ("signer_id".into(), Value::String(signer.signer_id.clone())),
                            (
                                "public_key_hex".into(),
                                Value::String(hex::encode(signer.public_key)),
                            ),
                        ]))
                    })
                    .collect(),
            ),
        );
    }
    for name in [
        "feeds",
        "revoked_catalog_signer_ids",
        "revoked_gateway_signer_ids",
    ] {
        config.insert(name.into(), Value::Array(Vec::new()));
    }
    duration(
        config,
        "max_catalog_validity",
        Duration::from_secs(crate::localnet::service_authorities::RetainedGatewayCompliancePlan::catalog_validity_seconds()),
    )?;
    Ok(())
}
fn public_authority(
    table: &mut Table,
    selected: &SignerCustodyAuthorityV1,
    key: &iroha_crypto::PublicKey,
    policies: &GeneratedProviderPolicies,
) -> Result<()> {
    text(table, "service_id", selected.service_id.clone());
    text(table, "administrator_id", selected.administrator_id.clone());
    text(table, "public_key_hex", raw_public(key)?);
    number(table, "key_revision", selected.key_revision)?;
    number(table, "policy_revision", selected.policy_revision)?;
    text(
        table,
        "policy_digest_hex",
        hex::encode(selected.policy_digest),
    );
    number(
        table,
        "active_from_unix_ms",
        policies.custody.active_from_unix_ms,
    )?;
    number(
        table,
        "active_until_unix_ms",
        policies.custody.active_until_unix_ms,
    )?;
    Ok(())
}
fn configure_tokens(
    table: &mut Table,
    authority: &ServiceAuthority,
    aggregate: &GeneratedServicePolicies,
    plan: &RetainedProviderServicePlan,
    component: &ProviderComponent,
) -> Result<()> {
    let policies = aggregate.provider(plan.provider_id())?;
    let material = component.directory();
    let root = generation_path(&authority.prepared)?;
    let tokens = section(table, &["sorafs", "storage", "stream_tokens"])?;
    flag(tokens, "enabled", true);
    let gateway = &policies.gateway.qualification;
    text(
        tokens,
        "admission_provider_handle",
        "software://managed/stream-token-gateway",
    );
    number(tokens, "admission_provider_revision", gateway.revision)?;
    text(
        tokens,
        "admission_provider_policy_digest_hex",
        hex::encode(gateway.policy_digest),
    );
    number(
        tokens,
        "admission_max_pending",
        u64::from(gateway.max_pending),
    )?;
    number(
        tokens,
        "admission_max_tracked_tokens",
        u64::from(gateway.max_tracked_tokens),
    )?;
    number(tokens, "admission_lease_ttl_ms", gateway.lease_ttl_ms)?;
    let binding = &policies.custody.binding;
    let signer = section(tokens, &["signer"])?;
    number(signer, "clock_uncertainty_ms", 250)?;
    text(signer, "runtime_handle", binding.runtime_handle.clone());
    text(signer, "key_handle", binding.key_handle.clone());
    text(signer, "service_id", binding.service_id.clone());
    text(signer, "administrator_id", binding.administrator_id.clone());
    text(signer, "public_key_hex", raw_public(&binding.public_key)?);
    number(signer, "key_revision", binding.key_revision)?;
    number(signer, "policy_revision", binding.policy_revision)?;
    text(
        signer,
        "policy_digest_hex",
        hex::encode(binding.policy_digest),
    );
    let attester = section(signer, &["attester"])?;
    public_authority(
        attester,
        &policies.custody.attester_authority,
        &policies.custody.attester_public_key,
        policies,
    )?;
    number(
        attester,
        "max_validity_ms",
        policies.custody.max_validity_ms,
    )?;
    number(
        attester,
        "max_anchor_age_ms",
        policies.custody.max_anchor_age_ms,
    )?;
    let observer = section(signer, &["observer"])?;
    public_authority(
        observer,
        &policies.observer_authority,
        role_key(authority, plan.provider_id(), Role::IssuerObserver)?,
        policies,
    )?;
    text(
        observer,
        "runtime_handle",
        "software://managed/state-observer",
    );
    number(observer, "max_state_age_ms", 30_000)?;
    let native = section(signer, &["native"])?;
    path(
        native,
        "signer_credential",
        &role_path(root, plan.slot(), Role::TokenSigner),
    )?;
    let record = component.selection().bytes_digest;
    path(
        native,
        "custody_record",
        &material.path().join(custody_name(record)),
    )?;
    path(
        native,
        "receipt_journal",
        &material.path().join("stream-token-receipts"),
    )?;
    text(
        native,
        "operator",
        authority
            .provider_inventory(plan.provider_id())?
            .authority(Role::IssuerOperator)?
            .account
            .to_string(),
    );
    path(
        native,
        "operator_credential",
        &role_path(root, plan.slot(), Role::IssuerOperator),
    )?;
    path(
        native,
        "observer_credential",
        &role_path(root, plan.slot(), Role::IssuerObserver),
    )?;
    let fees = norito::json::to_json(&aggregate.network.runtime_fee_payment)
        .map_err(|_| invalid("invalid original runtime fee policy"))?;
    text(native, "fee_payment_json", fees.clone());
    number(native, "timeout_ms", 30_000)?;
    let admission = section(tokens, &["admission_native"])?;
    for (name, role) in [
        ("operator", Role::GatewayOperator),
        ("observer", Role::GatewayObserver),
    ] {
        text(
            admission,
            name,
            authority
                .provider_inventory(plan.provider_id())?
                .authority(role)?
                .account
                .to_string(),
        );
        path(
            admission,
            &format!("{name}_credential"),
            &role_path(root, plan.slot(), role),
        )?;
    }
    text(
        admission,
        "reputation_recorder",
        authority
            .network_role(NetworkRole::ReputationRecorder)?
            .to_string(),
    );
    path(
        admission,
        "reputation_recorder_credential",
        &network_role_path(root, NetworkRole::ReputationRecorder),
    )?;
    text(admission, "fee_payment_json", fees);
    number(admission, "clock_uncertainty_ms", 250)?;
    Ok(())
}

/// Project only the original public binding. Native State remains the per-use authority.
fn configure_ingest(
    table: &mut Table,
    authority: &ServiceAuthority,
    policies: &GeneratedServicePolicies,
    plan: &RetainedProviderServicePlan,
    plans: &[RetainedProviderServicePlan; 3],
) -> Result<()> {
    let selected = &policies.provider(plan.provider_id())?.provider_ingest;
    let inventory = authority.provider_inventory(plan.provider_id())?;
    let owner = &inventory.authority(Role::IssuerOperator)?.account;
    let signer = &inventory.authority(Role::ProviderIngest)?.account;
    let key = role_key(authority, plan.provider_id(), Role::ProviderIngest)?;
    if !selected.is_valid()
        || &selected.provider_owner != owner
        || &selected.completion_signer != signer
        || owner == signer
        || selected.completion_signer.try_signatory() != Some(key)
        || plan.network_id() != authority.config.network_id
    {
        return Err(invalid(
            "generated provider ingest authority differs from its fixed roles",
        ));
    }
    let root = generation_path(&authority.prepared)?;
    let config = section(table, &["sorafs", "storage", "provider_ingest_runtime"])?;
    flag(config, "enabled", true);
    path(
        config,
        "native_completion_credential",
        &role_path(root, plan.slot(), Role::ProviderIngest),
    )?;
    // Only the other two original management peers may supply assignment-authorized bytes.
    // The native source adapter still owns request signatures, current permission and content checks.
    let mut origins = Table::new();
    for other in plans {
        if other.provider_id() == plan.provider_id() {
            continue;
        }
        let peer = authority
            .prepared
            .peers
            .get(other.peer_index())
            .ok_or_else(|| invalid("original source peer absent"))?;
        let origin: url::Url = peer
            .torii_url
            .parse()
            .map_err(|_| invalid("original source origin invalid"))?;
        if origin.scheme() != "http"
            || origin.host_str() != Some("127.0.0.1")
            || origin.port().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(invalid(
                "original source origin is not its fixed management peer",
            ));
        }
        origins.insert(
            hex::encode(other.provider_id().as_bytes()),
            Value::String(origin.to_string()),
        );
    }
    if origins.len() != 2 {
        return Err(invalid("generated native source inventory differs"));
    }
    config.insert("native_source_origins".into(), Value::Table(origins));
    let policy_bytes = encode(policies, MAX_POLICY_BYTES)?;
    for (field, purpose, handle) in [
        (
            "authenticated_source_fetch",
            b"source".as_slice(),
            "software://managed/provider-ingest/source",
        ),
        (
            "completion_signer_resolver",
            b"resolver".as_slice(),
            "software://managed/provider-ingest/resolver",
        ),
        (
            "checkpoint_store",
            b"checkpoint".as_slice(),
            "software://managed/provider-ingest/checkpoint",
        ),
    ] {
        let digest = Hash::new_from_chunks(&[
            b"iroha:generated-provider-ingest-runtime-binding:v1\0",
            authority.config.network_id.as_bytes(),
            plan.provider_id().as_bytes(),
            purpose,
            &policy_bytes,
        ]);
        text(config, &format!("{field}_handle"), handle);
        number(config, &format!("{field}_revision"), 1)?;
        text(
            config,
            &format!("{field}_policy_digest_hex"),
            hex::encode(digest.as_ref()),
        );
    }
    text(
        config,
        "completion_signer_handle",
        "software://managed/provider-ingest/completion",
    );
    number(config, "completion_signer_adapter_revision", 1)?;
    let policy = selected.signer_policy;
    text(
        config,
        "completion_signer_policy_id_hex",
        hex::encode(policy.policy_id),
    );
    number(config, "completion_signer_policy_revision", policy.revision)?;
    if let Some(predecessor) = policy.predecessor_digest {
        text(
            config,
            "completion_signer_policy_predecessor_digest_hex",
            hex::encode(predecessor),
        );
    } else {
        config.remove("completion_signer_policy_predecessor_digest_hex");
    }
    text(
        config,
        "completion_signer_policy_digest_hex",
        hex::encode(policy.policy_digest),
    );
    text(config, "completion_signer_algorithm", "ed25519");
    text(config, "completion_signer_public_key_hex", raw_public(key)?);
    // Software checkpoint custody lives below the unchanged storage data directory. The native
    // owner opens it; the renderer neither initializes nor repairs retained execution history.
    let archive = section(config, &["finalized_archive"])?;
    text(
        archive,
        "relative_root",
        "provider-ingest-finalized-archive-v1",
    );
    flag(archive, "retention_enabled", false);
    // This projection is reachable only for the carrier-gated StreamTokens revision. It never
    // creates history: fresh generation owns initialization and the daemon owns ordinary open.
    configure_attestation_journal(section(config, &["provider_attestation_journal"])?, signer)?;
    Ok(())
}

fn configure_attestation_journal(
    table: &mut Table,
    completion_signer: &iroha_data_model::account::AccountId,
) -> Result<()> {
    use sorafs_node::{
        provider_attestation_journal::musubi_provider_attestation_controller_policy_digest_v1,
        provider_attestation_native::{
            NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1,
            NATIVE_PROVIDER_ATTESTATION_CLOCK_HANDLE_V1,
            NATIVE_PROVIDER_ATTESTATION_INVENTORY_HANDLE_V1,
        },
    };
    let policy = crate::localnet::service_authorities::RetainedProviderServicePlan::attestation_journal_policy();
    let digest = policy
        .digest()
        .map_err(|_| invalid("original attestation journal policy differs"))?;
    let controller = musubi_provider_attestation_controller_policy_digest_v1(completion_signer)
        .map_err(|_| invalid("original completion signer controller differs"))?;
    flag(table, "enabled", true);
    for (prefix, handle, selected) in [
        ("clock", NATIVE_PROVIDER_ATTESTATION_CLOCK_HANDLE_V1, digest),
        (
            "inventory",
            NATIVE_PROVIDER_ATTESTATION_INVENTORY_HANDLE_V1,
            digest,
        ),
        (
            "approval_signer",
            NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1,
            controller,
        ),
    ] {
        text(table, &format!("{prefix}_handle"), handle);
        number(table, &format!("{prefix}_revision"), 1)?;
        text(
            table,
            &format!("{prefix}_policy_digest_hex"),
            hex::encode(selected),
        );
    }
    for (field, value) in [
        (
            "max_entries",
            u64::try_from(policy.max_entries)
                .map_err(|_| invalid("attestation entry bound differs"))?,
        ),
        ("max_attempts", u64::from(policy.max_attempts)),
        ("lease_ttl_ms", policy.lease_ttl_ms),
        ("approval_timeout_ms", policy.approval_timeout_ms),
        ("handoff_timeout_ms", policy.handoff_timeout_ms),
        ("retry_delay_ms", policy.retry_delay_ms),
        (
            "checkpoint_max_bytes",
            u64::try_from(policy.checkpoint_max_bytes)
                .map_err(|_| invalid("attestation byte bound differs"))?,
        ),
        ("max_cas_retries", u64::from(policy.max_cas_retries)),
    ] {
        number(table, field, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Generated duration fields use the canonical configuration reader's exact representation.

    use super::*;
    use iroha_config_base::{read::ConfigReader, toml::TomlSource};

    #[test]
    fn duration_projection_preserves_canonical_seconds_and_nanoseconds() {
        for expected in [Duration::from_secs(300), Duration::new(3, 123_456_789)] {
            let mut table = Table::new();
            duration(&mut table, "max_catalog_validity", expected).unwrap();
            let rendered = toml::to_string(&table).unwrap();
            let mut reader =
                ConfigReader::new().with_toml_source(TomlSource::inline(rendered.parse().unwrap()));
            let parsed = reader
                .read_parameter::<Duration>(["max_catalog_validity"])
                .value_required()
                .finish();
            reader.into_result().unwrap();
            assert_eq!(parsed.unwrap(), expected);
        }
        let mut table = Table::new();
        assert!(
            duration(
                &mut table,
                "max_catalog_validity",
                Duration::from_secs(1_u64 << 63),
            )
            .is_err()
        );
        assert!(table.is_empty());
    }
}
