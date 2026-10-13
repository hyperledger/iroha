//! Original singleton publication intent and explicit unpublished-generation provisioning.
//!
//! This owner selects public material and initializes existing lower custody exactly once. It
//! does not create current native authority, send a transaction, or install a serving backend.

use super::*;
use iroha_config::parameters::{actual, defaults::musubi_publication as defaults};
use iroha_data_model::sorafs::pin_registry::StorageClass;
use iroha_musubi_service::{
    DurableMusubiPublicationServiceClockV1, DurableMusubiPublicationServiceJournalLimitsV1,
    DurableMusubiPublicationServiceJournalV1, MusubiPublicationServiceConfigurationV1,
    MusubiPublicationServiceJournalBindingV1, MusubiSeedStagingBackendV1, NativeMusubiPinSessionV1,
};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};

const SELECTED_SLOT: u8 = 0;
const MAX_PLAN_BYTES: usize = 16 * 1024;
const PLAN_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    MAX_PLAN_BYTES,
    MAX_PLAN_BYTES,
    MAX_PLAN_BYTES * 2,
    256 * 1024,
    24,
);

#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::PublicationPlanV1")]
struct PublicationPlanV1 {
    slot: u8,
    seed_provider: ProviderId,
    ingress_broker: AccountId,
    pin_authority: AccountId,
    session_id: [u8; 32],
    https_port: u16,
    max_inflight_requests: u16,
    journal_limits: DurableMusubiPublicationServiceJournalLimitsV1,
    max_seed_records: u32,
    max_seed_bytes: u64,
    max_future_clock_skew_ms: u64,
    receipt_lifetime_ms: u64,
    pin_storage_class: StorageClass,
    pin_retention_horizon_secs: u64,
    readback_request_timeout_ms: u64,
    pin_authorization_window_ms: u64,
    pin_max_check_rounds: u16,
    pin_fee_asset: iroha_data_model::asset::AssetDefinitionId,
    pin_per_transaction_fee_limit: Quantity,
    pin_total_fee_limit: Quantity,
}

/// Complete original publication selection authenticated by the retained signed profile.
///
/// The public constructor is deliberately absent. This is immutable generation intent, not a
/// fresh provider proof, archive-manager permission, native pin receipt or serving capability.
#[derive(Debug)]
pub struct RetainedPublicationServicePlan {
    plan: PublicationPlanV1,
    provider: RetainedProviderServicePlan,
    chain: String,
    address_discriminant: u16,
    generation: PathBuf,
    origin: String,
}
impl RetainedPublicationServicePlan {
    pub(super) fn publication_client_fee_payment(
        &self,
    ) -> iroha_data_model::transaction::FeePaymentIntent {
        use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent};
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                self.plan.pin_fee_asset.clone(),
                self.plan.pin_per_transaction_fee_limit.clone(),
            )],
            None,
        )
    }

    /// Exact original genesis-derived network.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.provider.network_id()
    }
    /// Original chain label; never sufficient to establish the network by itself.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain
    }
    /// Explicit original daemon host, presently provider slot zero.
    #[must_use]
    pub fn peer_index(&self) -> usize {
        usize::from(self.plan.slot)
    }
    /// Exact provider whose existing owner signs ingress receipts.
    #[must_use]
    pub fn seed_provider(&self) -> ProviderId {
        self.plan.seed_provider
    }
    /// Original provider owner/IssuerOperator; distinct from the publishing user's manager.
    #[must_use]
    pub fn ingress_broker(&self) -> &AccountId {
        &self.plan.ingress_broker
    }
    /// Independent ordinary-funded paid pin and publisher-source transaction account.
    #[must_use]
    pub fn pin_authority(&self) -> &AccountId {
        &self.plan.pin_authority
    }
    /// Original authority-wide pin session, never regenerated on restart.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.plan.session_id
    }
    /// Original private publication origin, with its separately retained listener port.
    #[must_use]
    pub fn https_origin(&self) -> &str {
        &self.origin
    }
    /// Original nonzero listener port; no inferred remapping to the account-read listener.
    #[must_use]
    pub fn https_port(&self) -> u16 {
        self.plan.https_port
    }
    /// Exact original provider TLS/admission material, authenticated with the whole profile.
    #[must_use]
    pub fn provider_admission_material(
        &self,
    ) -> &sorafs_manifest::provider_admission::ProviderAdmissionGenesisMaterialV1 {
        self.provider.admission_material()
    }
    /// Project only this retained public intent and fixed credential paths into typed config.
    ///
    /// Calling this does not enable a listener or initialize any custody. The completed native
    /// backend and managed runtime still own activation and current native authorization.
    #[must_use]
    pub fn installation_config(&self) -> actual::MusubiPublication {
        self.plan
            .configuration(&self.generation, self.network_id(), &self.provider)
    }

    /// Select the sole generated-local private publication transport from original intent.
    ///
    /// This retains exact normal TLS trust/name/leaf and the original loopback port. It does
    /// not establish current provider eligibility or confer the publishing user's authority.
    /// # Errors
    /// Refuses a malformed or mismatched original endpoint selection.
    pub fn publication_transport(
        &self,
    ) -> crate::managed::Result<iroha_musubi_service::GeneratedLocalPublicationTransportV1> {
        iroha_musubi_service::GeneratedLocalPublicationTransportV1::select(
            self.network_id(),
            self.chain_id(),
            self.seed_provider(),
            self.ingress_broker(),
            self.provider_admission_material(),
            self.https_port(),
        )
        .map_err(|_| Error::Invalid("original publication transport differs".into()))
    }

    /// Render the exact `[musubi_publication]` section for the original selected peer.
    ///
    /// This creates public configuration material only. A runtime must still qualify its
    /// backend before selecting this section for a launch; other peers keep installation absent.
    /// # Errors
    /// Refuses unrepresentable original paths or bounded values outside TOML's integer range.
    pub fn configuration_table(&self) -> crate::managed::Result<toml::Table> {
        let _address = ChainDiscriminantGuard::enter(self.address_discriminant);
        let config = self.installation_config();
        let selected = config
            .installation
            .as_ref()
            .ok_or_else(|| Error::Invalid("original publication selection is absent".into()))?;
        let invalid = || Error::Invalid("original publication config is unrepresentable".into());
        let path = |value: &Path| value.to_str().map(str::to_owned).ok_or_else(invalid);
        let mut table = toml::Table::new();
        table.insert(
            "custody_root".into(),
            toml::Value::String(path(&config.custody_root)?),
        );
        table.insert(
            "private_tls_bind".into(),
            toml::Value::String(config.private_tls_bind.to_string()),
        );
        for (key, value) in [
            (
                "max_inflight_requests",
                u64::from(config.max_inflight_requests),
            ),
            (
                "journal_max_operations",
                u64::from(config.journal_max_operations),
            ),
            (
                "journal_max_authorizations",
                u64::from(config.journal_max_authorizations),
            ),
            (
                "journal_max_total_response_bytes",
                config.journal_max_total_response_bytes,
            ),
            (
                "journal_max_snapshot_bytes",
                config.journal_max_snapshot_bytes,
            ),
            ("max_seed_records", u64::from(config.max_seed_records)),
            ("max_seed_bytes", config.max_seed_bytes),
            ("max_future_clock_skew_ms", config.max_future_clock_skew_ms),
            ("receipt_lifetime_ms", config.receipt_lifetime_ms),
            (
                "pin_retention_horizon_secs",
                config.pin_retention_horizon_secs,
            ),
        ] {
            table.insert(
                key.into(),
                toml::Value::Integer(i64::try_from(value).map_err(|_| invalid())?),
            );
        }
        table.insert(
            "pin_storage_class".into(),
            toml::Value::String(
                match config.pin_storage_class {
                    StorageClass::Hot => "hot",
                    StorageClass::Warm => "warm",
                    StorageClass::Cold => "cold",
                }
                .into(),
            ),
        );
        table.insert(
            "pin_transaction_authority".into(),
            toml::Value::String(self.plan.pin_authority.to_string()),
        );
        let mut install = toml::Table::new();
        for (key, value) in [
            ("network_id", selected.network_id.to_string()),
            (
                "seed_provider_hex",
                hex::encode(selected.seed_provider.as_bytes()),
            ),
            ("ingress_broker", selected.ingress_broker.to_string()),
            ("pin_session_hex", hex::encode(selected.pin_session)),
            ("broker_key_file", path(&selected.broker_key_file)?),
            ("pin_key_file", path(&selected.pin_key_file)?),
            ("tls_server_name", selected.tls_server_name.clone()),
            (
                "tls_certificate_file",
                path(&selected.tls_certificate_file)?,
            ),
            (
                "tls_private_key_file",
                path(&selected.tls_private_key_file)?,
            ),
            (
                "tls_root_certificate_file",
                path(&selected.tls_root_certificate_file)?,
            ),
            ("pin_fee_asset", selected.pin_fee_asset.to_string()),
            (
                "pin_per_transaction_fee_limit",
                selected.pin_per_transaction_fee_limit.to_string(),
            ),
            (
                "pin_total_fee_limit",
                selected.pin_total_fee_limit.to_string(),
            ),
        ] {
            install.insert(key.into(), toml::Value::String(value));
        }
        install.insert(
            "readback_request_timeout_ms".into(),
            toml::Value::Integer(
                i64::try_from(selected.readback_request_timeout_ms).map_err(|_| invalid())?,
            ),
        );
        install.insert(
            "pin_authorization_window_ms".into(),
            toml::Value::Integer(
                i64::try_from(selected.pin_authorization_window_ms).map_err(|_| invalid())?,
            ),
        );
        install.insert(
            "pin_max_check_rounds".into(),
            toml::Value::Integer(i64::from(selected.pin_max_check_rounds)),
        );
        table.insert("installation".into(), toml::Value::Table(install));
        Ok(table)
    }
}

pub(super) struct GeneratedPublication {
    plan: PublicationPlanV1,
    _port: TcpListener,
}

fn session_id(
    creation_time_ms: u64,
    provider: ProviderId,
    broker: &AccountId,
    pin: &AccountId,
) -> Result<[u8; 32]> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let broker = norito::core::to_bytes_bounded(broker, MAX_PLAN_BYTES)?;
    let pin = norito::core::to_bytes_bounded(pin, MAX_PLAN_BYTES)?;
    Ok(*Hash::new_from_chunks(&[
        b"iroha.localnet.musubi-publication-session.v1\0",
        &creation_time_ms.to_be_bytes(),
        provider.as_bytes(),
        &(broker.len() as u64).to_be_bytes(),
        &broker,
        &(pin.len() as u64).to_be_bytes(),
        &pin,
    ])
    .as_ref())
}
fn encode(plan: &PublicationPlanV1) -> Result<Vec<u8>> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::to_bytes_bounded(plan, MAX_PLAN_BYTES).map_err(Into::into)
}
fn decode(bytes: &[u8]) -> Result<PublicationPlanV1> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PLAN_BYTES,
        "publication plan exceeds bound"
    );
    norito::decode_canonical_with_limits(bytes, PLAN_LIMITS).map_err(Into::into)
}
impl PublicationPlanV1 {
    fn selected(
        creation_time_ms: u64,
        provider: ProviderId,
        broker: AccountId,
        pin: AccountId,
        port: u16,
    ) -> Result<Self> {
        ensure!(
            port != 0 && broker != pin,
            "publication port or role differs"
        );
        Ok(Self {
            slot: SELECTED_SLOT,
            seed_provider: provider,
            session_id: session_id(creation_time_ms, provider, &broker, &pin)?,
            ingress_broker: broker,
            pin_authority: pin,
            https_port: port,
            max_inflight_requests: defaults::MAX_INFLIGHT_REQUESTS,
            journal_limits: DurableMusubiPublicationServiceJournalLimitsV1::new(
                defaults::JOURNAL_MAX_OPERATIONS,
                defaults::JOURNAL_MAX_AUTHORIZATIONS,
                defaults::JOURNAL_MAX_TOTAL_RESPONSE_BYTES,
                defaults::JOURNAL_MAX_SNAPSHOT_BYTES,
            )
            .map_err(|_| eyre!("invalid generated publication journal limits"))?,
            max_seed_records: defaults::MAX_SEED_RECORDS,
            max_seed_bytes: defaults::MAX_SEED_BYTES,
            max_future_clock_skew_ms: defaults::MAX_FUTURE_CLOCK_SKEW_MS,
            receipt_lifetime_ms: defaults::RECEIPT_LIFETIME_MS,
            pin_storage_class: StorageClass::Hot,
            pin_retention_horizon_secs: defaults::PIN_RETENTION_HORIZON_SECS,
            readback_request_timeout_ms: defaults::READBACK_REQUEST_TIMEOUT_MS,
            pin_authorization_window_ms: 600_000,
            pin_max_check_rounds: 16,
            pin_fee_asset: localnet_xor_asset_definition_id(),
            pin_per_transaction_fee_limit: Quantity::from(1u64),
            pin_total_fee_limit: Quantity::from(64u64),
        })
    }
    fn configuration(
        &self,
        generation: &Path,
        network_id: NetworkId,
        provider: &RetainedProviderServicePlan,
    ) -> actual::MusubiPublication {
        // slot has already been authenticated against the entire original inventory.
        let provider_root = generation
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(DIRECTORY)
            .join(PROVIDERS_DIRECTORY)
            .join(self.slot.to_string());
        let network_root = generation
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(DIRECTORY)
            .join(NETWORK_DIRECTORY);
        actual::MusubiPublication {
            installation: Some(actual::MusubiPublicationInstallation {
                network_id,
                seed_provider: self.seed_provider,
                ingress_broker: self.ingress_broker.clone(),
                pin_session: self.session_id,
                broker_key_file: provider_root
                    .join(StreamTokenAuthorityRole::IssuerOperator.credential_filename()),
                pin_key_file: network_root
                    .join(NetworkServiceAuthorityRole::MusubiPin.credential_filename()),
                tls_server_name: provider.admission_material().proposal.endpoints[0]
                    .endpoint
                    .host_pattern
                    .clone(),
                tls_certificate_file: provider_root.join("provider-tls.der"),
                tls_private_key_file: provider_root.join("provider-tls.key.der"),
                tls_root_certificate_file: provider_root.join("provider-ca.der"),
                readback_request_timeout_ms: self.readback_request_timeout_ms,
                pin_authorization_window_ms: self.pin_authorization_window_ms,
                pin_max_check_rounds: self.pin_max_check_rounds,
                pin_fee_asset: self.pin_fee_asset.clone(),
                pin_per_transaction_fee_limit: self.pin_per_transaction_fee_limit.clone(),
                pin_total_fee_limit: self.pin_total_fee_limit.clone(),
            }),
            custody_root: generation
                .join("state")
                .join(format!("peer{}", self.slot))
                .join("musubi-publication"),
            private_tls_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, self.https_port)),
            max_inflight_requests: self.max_inflight_requests,
            journal_max_operations: self.journal_limits.max_operations(),
            journal_max_authorizations: self.journal_limits.max_authorizations(),
            journal_max_total_response_bytes: self.journal_limits.max_total_response_bytes(),
            journal_max_snapshot_bytes: self.journal_limits.max_snapshot_bytes(),
            max_seed_records: self.max_seed_records,
            max_seed_bytes: self.max_seed_bytes,
            max_future_clock_skew_ms: self.max_future_clock_skew_ms,
            receipt_lifetime_ms: self.receipt_lifetime_ms,
            pin_storage_class: self.pin_storage_class,
            pin_retention_horizon_secs: self.pin_retention_horizon_secs,
            pin_transaction_authority: actual::MusubiPinTransactionAuthority::Account(
                self.pin_authority.clone(),
            ),
        }
    }
}

impl GeneratedPublication {
    pub(super) fn generate(
        network: &[(NetworkServiceAuthorityRole, LocalnetClientIdentity)],
        providers: &[GeneratedProviderAuthorities; PROVIDER_COUNT],
        creation_time_ms: u64,
    ) -> Result<Self> {
        let selected = providers
            .iter()
            .find(|provider| provider.slot == SELECTED_SLOT)
            .ok_or_else(|| eyre!("original publication provider slot is absent"))?;
        let broker = selected
            .authorities
            .iter()
            .find(|(role, _)| *role == StreamTokenAuthorityRole::IssuerOperator)
            .ok_or_else(|| eyre!("original publication owner is absent"))?;
        let pin = network
            .iter()
            .find(|(role, _)| *role == NetworkServiceAuthorityRole::MusubiPin)
            .ok_or_else(|| eyre!("original publication pin role is absent"))?;
        // Existing peer and provider sockets remain reserved during this selection.
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let plan = PublicationPlanV1::selected(
            creation_time_ms,
            selected.provider_id,
            broker.1.account_id.clone(),
            pin.1.account_id.clone(),
            port.local_addr()?.port(),
        )?;
        ensure!(
            plan.session_id != [0; 32],
            "generated publication session is zero"
        );
        Ok(Self { plan, _port: port })
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        encode(&self.plan)
    }
}

pub(super) fn validate_retained(
    manifest: &StreamTokenAuthorityManifest,
    network: &network_material::NetworkServicePlanV1,
) -> Result<()> {
    let plan = decode(&manifest.network.publication_plan)?;
    let provider = manifest
        .providers
        .iter()
        .find(|provider| provider.slot == SELECTED_SLOT)
        .ok_or_else(|| eyre!("original publication provider slot is absent"))?;
    let expected = PublicationPlanV1::selected(
        network.creation_time_ms,
        provider.provider_id,
        provider
            .authority(StreamTokenAuthorityRole::IssuerOperator)?
            .account
            .clone(),
        manifest
            .network
            .authority(NetworkServiceAuthorityRole::MusubiPin)?
            .account
            .clone(),
        plan.https_port,
    )?;
    ensure!(
        plan == expected && plan.session_id != [0; 32],
        "original publication selection differs"
    );
    for entry in &manifest.providers {
        let provider = provider_material::retained(manifest, entry.provider_id)?;
        let url = url::Url::parse(provider.https_origin())?;
        ensure!(
            url.port_or_known_default() != Some(plan.https_port),
            "publication port collides with provider origin"
        );
    }
    Ok(())
}

pub(super) fn retained(
    prepared: &PreparedLocalnet,
    manifest: &StreamTokenAuthorityManifest,
) -> Result<RetainedPublicationServicePlan> {
    let client = prepared.context.load_client_config()?;
    retained_from_parts(
        manifest,
        client.chain.as_ref(),
        client.account_chain_discriminant,
        prepared
            .context
            .client_config
            .parent()
            .ok_or_else(|| eyre!("original generation is absent"))?,
    )
}

pub(super) fn retained_from_parts(
    manifest: &StreamTokenAuthorityManifest,
    chain: &str,
    address_discriminant: u16,
    generation: &Path,
) -> Result<RetainedPublicationServicePlan> {
    let plan = decode(&manifest.network.publication_plan)?;
    let provider = provider_material::retained(manifest, plan.seed_provider)?;
    ensure!(
        provider.slot() == plan.slot,
        "publication provider scope differs"
    );
    let name = &provider.admission_material().proposal.endpoints[0]
        .endpoint
        .host_pattern;
    let origin = if plan.https_port == 443 {
        format!("https://{name}")
    } else {
        format!("https://{name}:{}", plan.https_port)
    };
    Ok(RetainedPublicationServicePlan {
        plan,
        provider,
        chain: chain.to_owned(),
        address_discriminant,
        generation: generation.to_owned(),
        origin,
    })
}

impl GeneratedAuthorities {
    /// Sole fresh provisioning call while the complete generation is still unpublished.
    pub(in crate::localnet) fn initialize_publication(
        &self,
        generation: &Path,
        genesis: HashOf<BlockHeader>,
        manager: &AccountId,
    ) -> Result<()> {
        let network_id = NetworkId::from_genesis_hash(genesis);
        let manifest = self.manifest(network_id, manager)?;
        validate_retained(&manifest, &self.network)?;
        let provider = provider_material::retained(&manifest, self.publication.plan.seed_provider)?;
        let config = self
            .publication
            .plan
            .configuration(generation, network_id, &provider);
        custody::prepare_empty_private_directory(&config.custody_root)?;
        let root = iroha_fs::PrivateDirectory::open_exact(&config.custody_root)?;
        let service = MusubiPublicationServiceConfigurationV1 {
            network_id,
            ingress_broker: self.publication.plan.ingress_broker.clone(),
            seed_provider: self.publication.plan.seed_provider,
            max_future_clock_skew_ms: config.max_future_clock_skew_ms,
            receipt_lifetime_ms: config.receipt_lifetime_ms,
        };
        let journal = root.create_child("journal")?;
        drop(
            DurableMusubiPublicationServiceJournalV1::initialize(
                journal.path(),
                MusubiPublicationServiceJournalBindingV1::from_configuration(&service),
                self.publication.plan.journal_limits,
            )
            .map_err(|_| eyre!("cannot initialize original publication journal"))?,
        );
        let seed = root.create_child("seed")?;
        drop(
            MusubiSeedStagingBackendV1::initialize(
                seed.path(),
                service.seed_provider,
                config.max_seed_records,
                config.max_seed_bytes,
            )
            .map_err(|_| eyre!("cannot initialize original publication seed custody"))?,
        );
        let clock = root.create_child("clock")?;
        drop(
            DurableMusubiPublicationServiceClockV1::initialize_system(clock.path())
                .map_err(|_| eyre!("cannot initialize original publication clock"))?,
        );
        drop(
            NativeMusubiPinSessionV1::new(
                network_id,
                self.publication.plan.pin_authority.clone(),
                self.publication.plan.session_id,
                self.publication.plan.pin_storage_class,
                self.publication.plan.pin_retention_horizon_secs,
            )
            .map_err(|_| eyre!("invalid original publication pin selection"))?
            .initialize_private_journal(&root.path().join("pin"))
            .map_err(|_| eyre!("cannot initialize original publication pin custody"))?,
        );
        root.revalidate()?;
        root.sync()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
