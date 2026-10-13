//! Exact generated publication client image and developer-owned namespace intent.
//!
//! Native genesis staging proves original policy and ownership only. First-use paid namespace
//! binding and every current publication authorization remain with their normal runtime owners.

use super::*;
use iroha::config::MusubiPublicationConfig;
use iroha_core::state::WorldReadOnly as _;
use iroha_data_model::musubi::{
    MusubiNamespaceBindingV1, MusubiNamespaceV1, MusubiPackageScopeV1,
    MusubiRegistryAdmissionModeV1, MusubiRegistryPolicyV1,
};

const NAMESPACE: &str = "dev.universal";
const TEMPORARY_ROLE: &str = "generated_publication_domain_bootstrap";
const NAMESPACE_JOURNAL_DIRECTORY: &str = "publication-namespace";
const PUBLICATION_CLIENT_DIRECTORY: &str = "publication-client";
const PUBLICATION_OPERATIONS_DIRECTORY: &str = "operations";
const REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_CLIENT_BYTES: usize = 1024 * 1024;

/// Original public publication configuration authenticated with the complete generated profile.
///
/// This cannot be decoded or constructed by callers. The namespace/policy describe original
/// genesis; neither is current authority or proof that the paid namespace binding exists.
pub struct RetainedPublicationClientConfig {
    namespace_journal_root: PathBuf,
    client_path: PathBuf,
    client_image: Zeroizing<Vec<u8>>,
    configuration: MusubiPublicationConfig,
    service: RetainedPublicationServicePlan,
    binding: MusubiNamespaceBindingV1,
    policy: MusubiRegistryPolicyV1,
    publisher: AccountId,
}
impl std::fmt::Debug for RetainedPublicationClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedPublicationClientConfig")
            .field("validated", &true)
            .finish_non_exhaustive()
    }
}
impl RetainedPublicationClientConfig {
    /// Anchored original client path for the consumer's existing provenance checks.
    #[must_use]
    pub fn client_config_path(&self) -> &Path {
        &self.client_path
    }
    /// Exact bounded original client image, including runtime signing material.
    ///
    /// Borrow only for the existing configuration/provenance owner; never log or persist it.
    #[must_use]
    pub fn client_config_image(&self) -> &[u8] {
        &self.client_image
    }
    /// Fixed original namespace-parent custody, separate from daemon seed/pin custody.
    ///
    /// The wallet opens this preinitialized parent; this accessor never locks or repairs it.
    #[must_use]
    pub fn namespace_journal_root(&self) -> &Path {
        &self.namespace_journal_root
    }
    /// Fixed generation-bound publication engine root shared by managed frontends.
    /// This derives original private storage intent only; it creates no directory or journal.
    #[must_use]
    pub fn publication_state_root(&self) -> PathBuf {
        self.namespace_journal_root
            .with_file_name(PUBLICATION_CLIENT_DIRECTORY)
            .join(PUBLICATION_OPERATIONS_DIRECTORY)
    }
    /// Fixed generation-bound resolver/archive cache shared by managed frontends.
    /// This never selects a user cache or opens namespace, service or registry custody.
    #[must_use]
    pub fn publication_cache_root(&self) -> PathBuf {
        self.namespace_journal_root
            .with_file_name(PUBLICATION_CLIENT_DIRECTORY)
            .join("cache")
    }

    /// Purpose-bound TLS selection from the authenticated original profile; no raw HTTP override.
    /// # Errors
    /// Refuses invalid original TLS material or publication origin.
    pub fn publication_transport(
        &self,
    ) -> crate::managed::Result<iroha_musubi_service::GeneratedLocalPublicationTransportV1> {
        self.service.publication_transport()
    }

    /// Original signed-profile fee ceiling for one ordinary developer-paid namespace transaction.
    ///
    /// Reuses the original fee asset/per-transaction bound, never the daemon pin authority or
    /// aggregate session budget. Native charging and the wallet's exact quote remain authoritative.
    #[must_use]
    pub fn namespace_fee_payment(&self) -> iroha_data_model::transaction::FeePaymentIntent {
        self.service.publication_client_fee_payment()
    }

    /// Exact public SDK configuration admitted from the original complete client image.
    #[must_use]
    pub fn configuration(&self) -> &MusubiPublicationConfig {
        &self.configuration
    }
    /// Retained singleton transport and service intent, without installing or enabling it.
    #[must_use]
    pub fn service_plan(&self) -> &RetainedPublicationServicePlan {
        &self.service
    }
    /// Namespace an explicit generated scaffold caller may select; arbitrary manifests keep theirs.
    #[must_use]
    pub fn publication_namespace(&self) -> &MusubiNamespaceV1 {
        &self.binding.namespace
    }
    /// Original domain/owner-generation selection for a later normal paid binding operation.
    #[must_use]
    pub fn namespace_binding(&self) -> &MusubiNamespaceBindingV1 {
        &self.binding
    }
    /// Actual native registry policy from the authenticated original genesis World.
    #[must_use]
    pub fn registry_policy(&self) -> &MusubiRegistryPolicyV1 {
        &self.policy
    }
    /// Developer client that owns the generated domain; never the seed broker or validator key.
    #[must_use]
    pub fn publisher(&self) -> &AccountId {
        &self.publisher
    }
}

impl PreparedLocalnet {
    /// Validate the entire original client image and return its public publication companion.
    ///
    /// Performs one native signed-genesis projection at this complete handoff. Unrelated profile
    /// getters do not restage genesis. No HTTP, binding transaction or live custody is performed.
    /// Standard/private profiles return `None` only when no publication subtree is present.
    /// # Errors
    /// Refuses original profile, native namespace/policy, client bytes, endpoint, provider order,
    /// signer, network or TLS substitutions. Current eligibility requires fresh runtime evidence.
    pub fn publication_client_config(
        &self,
    ) -> crate::managed::Result<Option<RetainedPublicationClientConfig>> {
        let invalid = || Error::Invalid("original generated publication client differs".into());
        let manifest = validate_retained(self)?;
        let root = self.context.client_config.parent().ok_or_else(invalid)?;
        let directory = iroha_fs::PrivateDirectory::open_exact(root)?;
        let bytes = directory.read("client.toml", MAX_CLIENT_BYTES)?;
        let (client, configuration) = iroha::config::Config::load_bytes_with_musubi_publication(
            &self.context.client_config,
            &bytes,
        )
        .map_err(|_| invalid())?;
        let table = crate::secret_toml::parse_table(
            std::str::from_utf8(&bytes).map_err(|_| invalid())?,
            "generated publication client",
        )
        .map_err(|_| invalid())?;
        let Some(manifest) = manifest else {
            if table
                .get("musubi")
                .and_then(toml::Value::as_table)
                .is_some_and(|musubi| musubi.contains_key("publication"))
            {
                return Err(invalid());
            }
            return Ok(None);
        };
        let manifest_bytes = directory.read(
            "genesis.json",
            iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
        )?;
        iroha_genesis::validate_genesis_manifest_json(&manifest_bytes).map_err(|_| invalid())?;
        let raw = RawGenesisTransaction::from_json_slice_at_path(
            &manifest_bytes,
            root.join("genesis.json"),
        )
        .map_err(|_| invalid())?;
        let signed = directory.read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)?;
        let peer_bytes = directory.read("peer0.toml", MAX_CLIENT_BYTES)?;
        let peer = parse_localnet_peer_config(
            std::str::from_utf8(&peer_bytes).map_err(|_| invalid())?,
            Some(&self.peers[0].config_path),
        )
        .map_err(|_| invalid())?;
        // Every management origin names its exact retained validator listener, in slot order.
        for (index, selected) in self.peers.iter().enumerate() {
            let config_bytes = directory.read(format!("peer{index}.toml"), MAX_CLIENT_BYTES)?;
            let actual = parse_localnet_peer_config(
                std::str::from_utf8(&config_bytes).map_err(|_| invalid())?,
                Some(&selected.config_path),
            )
            .map_err(|_| invalid())?;
            let listener: std::net::SocketAddr = actual
                .torii
                .address
                .value()
                .to_string()
                .parse()
                .map_err(|_| invalid())?;
            if listener.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
                || loopback_port(&selected.torii_url).map_err(|_| invalid())? != listener.port()
                || actual.genesis.expected_hash != peer.genesis.expected_hash
            {
                return Err(invalid());
            }
        }
        let (policy, binding) =
            native_original(&raw, &signed, &peer, &manifest.manager).map_err(|_| invalid())?;
        if client.chain != *raw.chain_id()
            || client.account_chain_discriminant != raw.chain_discriminant()
            || client.network_id != manifest.network_id
            || client.account != manifest.manager
        {
            return Err(invalid());
        }
        let service = publication_material::retained_from_parts(
            &manifest,
            client.chain.as_ref(),
            client.account_chain_discriminant,
            root,
        )
        .map_err(|_| invalid())?;
        let urls: [String; PROVIDER_COUNT] =
            std::array::from_fn(|index| self.peers[index].torii_url.clone());
        let _address = ChainDiscriminantGuard::enter(raw.chain_discriminant());
        let public =
            configuration_table(&service, &manifest, &policy, &urls).map_err(|_| invalid())?;
        let port = loopback_port(&urls[0]).map_err(|_| invalid())?;
        // Reconstruct through the sole generator. This checks every byte, including the existing
        // signing/network fields; no generic TOML reserialization of secrets is used.
        let identity = LocalnetClientIdentity {
            account_id: client.account.clone(),
            public_key: client.key_pair.public_key().clone(),
            private_key: Zeroizing::new(
                ExposedPrivateKey(client.key_pair.private_key().clone()).to_string(),
            ),
        };
        let expected = render_client_config(
            port,
            &CanonicalHost::parse("127.0.0.1", "generated Torii host").map_err(|_| invalid())?,
            client.chain.as_ref(),
            resolve_localnet_chain_discriminant(
                client.chain.as_ref(),
                Some(client.account_chain_discriminant),
            )
            .map_err(|_| invalid())?,
            &identity,
            Some(&public),
        )
        .map_err(|_| invalid())?;
        if bytes.as_slice() != expected.as_bytes() {
            return Err(invalid());
        }
        directory.revalidate()?;
        // Catch a replacement during native staging/profile validation before exporting intent.
        if directory.read("client.toml", MAX_CLIENT_BYTES)?.as_slice() != bytes.as_slice() {
            return Err(invalid());
        }
        Ok(Some(RetainedPublicationClientConfig {
            namespace_journal_root: root
                .join(LOCALNET_RUNTIME_DIRECTORY)
                .join(NAMESPACE_JOURNAL_DIRECTORY),
            client_path: self.context.client_config.clone(),
            client_image: bytes,
            configuration,
            service,
            binding,
            policy,
            publisher: manifest.manager,
        }))
    }
}

pub(in crate::localnet) fn append_namespace(
    genesis: RawGenesisTransaction,
    genesis_authority: &AccountId,
    developer: &AccountId,
) -> Result<RawGenesisTransaction> {
    let domain = DomainId::parse_fully_qualified(NAMESPACE)?;
    let role: RoleId = TEMPORARY_ROLE.parse()?;
    ensure!(
        !genesis.instructions().any(|instruction| {
            instruction.as_any().downcast_ref::<RegisterBox>().is_some_and(|register| {
            matches!(register, RegisterBox::Role(register) if register.object().inner().id == role)
        })
        }),
        "generated publication bootstrap role already exists"
    );
    let permission = Permission::from(CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Domain(domain.clone()),
    });
    let ensure = EnsureAlias::new(
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain, DataSpaceId::UNIVERSAL),
            owner: developer.clone(),
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: LOCALNET_ALIAS_SETUP_POLICY_VERSION,
            expected_payment_asset: localnet_xor_asset_definition_id(),
            max_amount: Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
            valid_until_ms: u64::MAX,
        },
    );
    genesis
        .into_builder()
        .next_transaction()
        .append_instruction(Register::role(
            Role::new(role.clone(), genesis_authority.clone()).add_permission(permission),
        ))
        .append_instruction(ensure)
        .append_instruction(Unregister::role(role))
        .build_raw()
}

fn native_original(
    raw: &RawGenesisTransaction,
    signed: &[u8],
    config: &iroha_config::parameters::actual::Root,
    developer: &AccountId,
) -> Result<(MusubiRegistryPolicyV1, MusubiNamespaceBindingV1)> {
    let (_, original) = crate::genesis::staging::staged_signed_native_genesis_with_projection(
        raw,
        signed,
        config,
        |genesis, staged| {
            let world = staged.world();
            let now_ms = u64::try_from(genesis.0.header().creation_time().as_millis())?;
            let domain = DomainId::parse_fully_qualified(NAMESPACE)?;
            ensure!(
                world.domain(&domain)?.owned_by() == developer,
                "generated namespace domain owner differs"
            );
            ensure!(
                iroha_core::sns::active_domain_owner(world, &domain, now_ms)
                    .map_err(|_| eyre!("generated namespace SNS lookup failed"))?
                    .as_ref()
                    == Some(developer),
                "generated namespace has no active original SNS owner"
            );
            let genesis_owner = AccountId::new(config.genesis.public_key.clone());
            let home = iroha_core::sns::resolve_active_dataspace_id_by_alias(
                world,
                &config.nexus.dataspace_catalog,
                "universal",
                now_ms,
            )
            .map_err(|_| eyre!("generated namespace dataspace differs"))?;
            ensure!(
                home == DataSpaceId::UNIVERSAL
                    && iroha_core::sns::active_dataspace_owner_by_alias(world, "universal", now_ms)
                        .map_err(|_| eyre!("original Universal owner lookup failed"))?
                        .as_ref()
                        == Some(&genesis_owner)
                    && world
                        .domain(&DomainId::parse_fully_qualified(CLIENT_ACCOUNT_DOMAIN)?)?
                        .owned_by()
                        == &genesis_owner,
                "generated publication changed existing admin ownership"
            );
            let temporary: RoleId = TEMPORARY_ROLE.parse()?;
            ensure!(
                world.role(&temporary).is_err()
                    && !world
                        .account_roles_iter(&genesis_owner)
                        .any(|role| role == &temporary),
                "generated publication left its temporary role"
            );
            let policy = world.musubi_registry_policy().clone();
            policy.validate()?;
            ensure!(
                matches!(policy.mode, MusubiRegistryAdmissionModeV1::Open),
                "generated public publication policy is not open"
            );
            let binding = MusubiNamespaceBindingV1 {
                namespace: NAMESPACE.parse()?,
                home_dataspace: home,
                scope: MusubiPackageScopeV1::Domain("dev".parse()?),
                generation: world.musubi_domain_ownership_generation(&domain),
            };
            binding.validate()?;
            Ok((policy, binding))
        },
    )?;
    Ok(original)
}

fn loopback_port(origin: &str) -> Result<u16> {
    let url = url::Url::parse(origin)?;
    let port = url
        .port()
        .ok_or_else(|| eyre!("generated management port is absent"))?;
    ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && port != 0
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && origin == format!("http://127.0.0.1:{port}/"),
        "generated management origin differs"
    );
    Ok(port)
}

fn configuration_table(
    service: &RetainedPublicationServicePlan,
    manifest: &StreamTokenAuthorityManifest,
    policy: &MusubiRegistryPolicyV1,
    origins: &[String; PROVIDER_COUNT],
) -> Result<toml::Table> {
    let base = loopback_port(&origins[0])?;
    for (index, origin) in origins.iter().enumerate() {
        ensure!(
            loopback_port(origin)?
                == base
                    .checked_add(u16::try_from(index)?)
                    .ok_or_else(|| eyre!("generated management port overflow"))?,
            "original management topology differs"
        );
    }
    let root = format!("{}/", service.https_origin());
    let mut table = toml::Table::new();
    for (key, value) in [
        ("seed_ingress_url", root.clone()),
        ("storage_coordinator_url", root.clone()),
        ("ingress_broker", service.ingress_broker().to_string()),
        (
            "seed_provider",
            hex::encode(service.seed_provider().as_bytes()),
        ),
    ] {
        table.insert(key.into(), toml::Value::String(value));
    }
    table.insert(
        "expected_policy_revision".into(),
        toml::Value::Integer(i64::try_from(policy.revision)?),
    );
    table.insert(
        "request_timeout_ms".into(),
        toml::Value::Integer(i64::try_from(REQUEST_TIMEOUT_MS)?),
    );
    let providers = manifest
        .providers
        .iter()
        .enumerate()
        .map(|(index, provider)| {
            ensure!(
                usize::from(provider.slot) == index,
                "generated provider order differs"
            );
            Ok(toml::Value::Table(toml::Table::from_iter([
                (
                    "provider_id".into(),
                    toml::Value::String(hex::encode(provider.provider_id.as_bytes())),
                ),
                ("url".into(), toml::Value::String(root.clone())),
                (
                    "attestation_url".into(),
                    toml::Value::String(origins[index].clone()),
                ),
            ])))
        })
        .collect::<Result<Vec<_>>>()?;
    table.insert("provider_gateways".into(), toml::Value::Array(providers));
    Ok(table)
}

impl GeneratedAuthorities {
    pub(in crate::localnet) fn publication_client_selection(
        &self,
        raw: &RawGenesisTransaction,
        signed: &[u8],
        config: &iroha_config::parameters::actual::Root,
        generation: &Path,
        developer: &AccountId,
        base_api_port: u16,
    ) -> Result<GeneratedPublicationClient> {
        let _address = ChainDiscriminantGuard::enter(raw.chain_discriminant());
        let manifest = self.manifest(
            NetworkId::from_genesis_hash(config.genesis.expected_hash),
            developer,
        )?;
        let service = publication_material::retained_from_parts(
            &manifest,
            raw.chain_id().as_ref(),
            raw.chain_discriminant(),
            generation,
        )?;
        let (policy, binding) = native_original(raw, signed, config, developer)?;
        let ports = [0u16, 1, 2].map(|index| base_api_port.checked_add(index));
        ensure!(
            ports.iter().all(Option::is_some),
            "generated management port overflow"
        );
        let origins =
            ports.map(|port| format!("http://127.0.0.1:{}/", port.expect("checked ports")));
        let table = configuration_table(&service, &manifest, &policy, &origins)?;
        Ok(GeneratedPublicationClient {
            table,
            selection: iroha_wallet::operations::MusubiNamespaceBindingSelection {
                chain_id: raw.chain_id().to_string(),
                network_id: manifest.network_id,
                owner: developer.clone(),
                binding,
                expected_policy_revision: policy.revision,
            },
            fee: service.publication_client_fee_payment(),
        })
    }
}

/// One unpublished-generation selection. Never returned as current native authority.
pub(in crate::localnet) struct GeneratedPublicationClient {
    pub(in crate::localnet) table: toml::Table,
    selection: iroha_wallet::operations::MusubiNamespaceBindingSelection,
    fee: iroha_data_model::transaction::FeePaymentIntent,
}
impl GeneratedPublicationClient {
    pub(in crate::localnet) fn initialize_namespace_parent(&self, generation: &Path) -> Result<()> {
        let directory = iroha_fs::PrivateDirectory::open_exact(generation)?;
        let path = generation.join("client.toml");
        let bytes = directory.read("client.toml", MAX_CLIENT_BYTES)?;
        let (client, _) = iroha::config::Config::load_bytes_with_musubi_publication(&path, &bytes)
            .map_err(|_| eyre!("generated namespace wallet configuration differs"))?;
        ensure!(
            client.chain.as_str() == self.selection.chain_id
                && client.network_id == self.selection.network_id
                && client.account == self.selection.owner,
            "generated namespace wallet identity differs"
        );
        let wallet = iroha_wallet::operations::AccountService::new(client)
            .map_err(|_| eyre!("cannot open generated namespace wallet"))?;
        wallet
            .initialize_musubi_namespace_binding_parent(
                &generation
                    .join(LOCALNET_RUNTIME_DIRECTORY)
                    .join(NAMESPACE_JOURNAL_DIRECTORY),
                &self.selection,
                &self.fee,
            )
            .map_err(|_| eyre!("cannot initialize original namespace parent"))?;
        // Only the unpublished-generation producer initializes the complete client-history
        // directory. Consumers open its original inner and outer custody without repair.
        let runtime = directory.open_child(LOCALNET_RUNTIME_DIRECTORY)?;
        let publication = runtime.create_child(PUBLICATION_CLIENT_DIRECTORY)?;
        let operations = publication.create_child(PUBLICATION_OPERATIONS_DIRECTORY)?;
        let journal =
            iroha_musubi_service::publication_client_journal::initialize(operations.path())?;
        journal.revalidate()?;
        operations.sync()?;
        publication.sync()?;
        runtime.sync()?;
        directory.revalidate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
