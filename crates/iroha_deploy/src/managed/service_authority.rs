//! Original generated service authority, signed genesis and private operation custody.

use super::{
    PreparedLocalnet, Result,
    native_operation::{invalid, read_selected_peers},
};
use crate::{
    localnet::service_authorities::{
        NetworkServiceAuthorityRole, ProviderServiceInventory, RetainedGatewayCompliancePlan,
        RetainedProviderServicePlan, RetainedServiceProfile, StreamTokenAuthorityManifest,
        StreamTokenAuthorityRole, ValidatedServiceProfile, capture_retained,
    },
    verify::finality::{FinalityVerifier, GenesisAnchor},
};
use iroha::{client::Client, config::Config};
#[cfg(test)]
use iroha_data_model::NetworkId;
use iroha_data_model::{
    account::{AccountId, address::ChainDiscriminantGuard},
    sorafs::{
        capacity::ProviderId,
        reserve::{ReserveAuthorityPolicyV1, account_proof::VerifiedReserveAccountStateV1},
    },
};
use iroha_fs::PrivateDirectory;
use iroha_model_base::peer::PeerId;
use std::{fs::File, sync::Arc, time::Instant};

#[path = "service_authority/certificate_seed.rs"]
mod certificate_seed;

#[path = "service_authority/checkpoint_cache.rs"]
mod checkpoint_cache;
pub(in crate::managed) use checkpoint_cache::{CheckpointImportScope, CheckpointImports};

#[path = "service_authority/inventory.rs"]
mod inventory;
pub(super) use inventory::ServiceChildInventory;

pub(super) enum NetworkPurpose {
    BuildRegistry,
    ServiceObservation,
    InitialReservePolicy,
    InitialReputationPolicy,
    ServiceBootstrap,
    GeneratedRuntime,
}
impl NetworkPurpose {
    fn directory_name(self) -> &'static str {
        match self {
            Self::BuildRegistry => "build-registry",
            Self::ServiceObservation => "service-observation",
            Self::InitialReservePolicy => "initial-reserve-policy",
            Self::InitialReputationPolicy => "initial-reputation-policy",
            Self::ServiceBootstrap => "service-bootstrap",
            Self::GeneratedRuntime => "generated-service-runtime",
        }
    }
}

pub(super) enum ProviderPurpose {
    ProviderAdvertisement,
    Custody,
    ReserveAccountRegistration,
    ReserveTopUpRequest,
    ReserveTopUpApproval,
    InitialProviderCredit,
    ProviderCapacityDeclaration,
    ProviderFundingBootstrap,
    GatewayCompliance,
    InitialGatewaySetup,
    InitialProviderIngestAuthority,
}
impl ProviderPurpose {
    fn directory_name(self) -> &'static str {
        match self {
            Self::ProviderAdvertisement => "provider-advertisement",
            Self::Custody => "stream-token-custody",
            Self::ReserveAccountRegistration => "reserve-account-registration",
            Self::ReserveTopUpRequest => "reserve-top-up-request",
            Self::ReserveTopUpApproval => "reserve-top-up-approval",
            Self::InitialProviderCredit => "initial-provider-credit",
            Self::ProviderCapacityDeclaration => "provider-capacity-declaration",
            Self::ProviderFundingBootstrap => "provider-funding-bootstrap",
            Self::GatewayCompliance => "gateway-compliance",
            Self::InitialGatewaySetup => "initial-gateway-setup",
            Self::InitialProviderIngestAuthority => "initial-provider-ingest-authority",
        }
    }
}

#[derive(Clone, Copy)]
enum Scope {
    Network,
    Provider { provider: ProviderId, slot: u8 },
}

// Active caller admission retains the original moved-output recipe. Otherwise the immutable
// validated constructor bundle can be borrowed by graph/census and authorized creating owners while each child opens
// its own operation directory/lock and rechecks the complete captured byte/native image.
#[expect(
    clippy::large_enum_variant,
    reason = "Active decode admission must retain the original inline moved profile without another allocation"
)]
enum AuthorityProfile {
    Owned(RetainedServiceProfile),
    Shared(Arc<ValidatedServiceProfile>),
}
impl std::ops::Deref for AuthorityProfile {
    type Target = RetainedServiceProfile;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(profile) => profile,
            Self::Shared(profile) => &profile.retained,
        }
    }
}

pub(super) struct ServiceAuthority {
    scope: Scope,
    profile: AuthorityProfile,
    // Immutable original client: only its transport is inherited by freshly built contexts.
    // Keep it separate from mutable diagnostic/configuration projections.
    transport_seed: Client,
    checkpoint_cache: checkpoint_cache::CheckpointCache,
    checkpoint_import_scope: Option<CheckpointImportScope>,
    certificate_scope: certificate_seed::Scope,
    pub(super) prepared: PreparedLocalnet,
    pub(super) directory: PrivateDirectory,
    pub(super) _lock: File,
    pub(super) manifest: StreamTokenAuthorityManifest,
    pub(super) config: Config,
    pub(super) genesis: GenesisAnchor,
    pub(super) peers: Vec<(PeerId, Client)>,
}

/// Borrowed original public intent inside one synchronous projection scope.
///
/// This is neither current native state nor a signing capability. The sole projection owner
/// must consume the view with `finish` before returning its result. The closed owned-gateway
/// pair performs that same first full exit directly to retain an immutable borrow for its
/// second projection; the enclosing aggregate still closes its full image unconditionally.
/// No view or plan leaves that pair. Any interleaved native reads retain their ordinary
/// independent authority checks; this view grants only immutable projections and cannot
/// authorize a child read or action.
#[must_use = "finish the original-intent view before returning its projection"]
pub(super) struct OriginalServiceIntent<'a> {
    authority: &'a ServiceAuthority,
}

/// Immutable constructor input borrowed only within one closed RuntimeSelection read.
/// Child locks and all mutable reads remain independently owned. This scope cannot create
/// a purpose, authorize a wallet or carry a current-state result beyond the enclosing read.
pub(super) struct RuntimeOriginalRead<'a> {
    authority: &'a ServiceAuthority,
}
impl RuntimeOriginalRead<'_> {
    pub(super) fn eligible(&self, authority: &ServiceAuthority) -> Result<bool> {
        if norito::core::decode_limits_active()
            || matches!(&authority.profile, AuthorityProfile::Owned(_))
        {
            return Ok(false);
        }
        self.require_image(&authority.profile, &authority.prepared, &authority.manifest)?;
        Ok(true)
    }

    fn require_image(
        &self,
        profile: &AuthorityProfile,
        prepared: &PreparedLocalnet,
        manifest: &StreamTokenAuthorityManifest,
    ) -> Result<()> {
        if !matches!((&self.authority.profile, profile),
            (AuthorityProfile::Shared(original), AuthorityProfile::Shared(selected))
                if Arc::ptr_eq(original, selected))
            || prepared != &self.authority.prepared
            || manifest != &self.authority.manifest
        {
            return Err(invalid(
                "runtime constructor belongs to another original image",
            ));
        }
        Ok(())
    }

    fn validate_profile(&self, authority: &ServiceAuthority) -> Result<()> {
        if norito::core::decode_limits_active()
            || matches!(&authority.profile, AuthorityProfile::Owned(_))
        {
            return authority.validate_profile();
        }
        authority.validate_operation_custody()?;
        self.require_image(&authority.profile, &authority.prepared, &authority.manifest)?;
        if let Scope::Provider { provider, slot } = authority.scope
            && authority.manifest.provider(provider)?.slot != slot
        {
            return Err(invalid("original provider operation scope changed"));
        }
        authority.validate_operation_custody()
    }
}

impl OriginalServiceIntent<'_> {
    /// Lend only this still-live original read's constructor image to temporary children.
    pub(super) fn runtime_read(&self) -> Option<RuntimeOriginalRead<'_>> {
        if norito::core::decode_limits_active()
            || matches!(&self.authority.profile, AuthorityProfile::Owned(_))
        {
            return None;
        }
        #[cfg(test)]
        if profile_validation_test_support::runtime_original_recipe() {
            return None;
        }
        Some(RuntimeOriginalRead {
            authority: self.authority,
        })
    }

    pub(super) fn finish_in_runtime(self, read: &RuntimeOriginalRead<'_>) -> Result<()> {
        read.validate_profile(self.authority)
    }

    pub(super) fn provider_plans(&self) -> Result<&[RetainedProviderServicePlan; 3]> {
        if matches!(self.authority.scope, Scope::Provider { .. }) {
            return Err(invalid("provider service cannot select all network plans"));
        }
        Ok(self.authority.profile.original_plans())
    }

    pub(super) fn provider_plan(
        &self,
        provider: ProviderId,
    ) -> Result<RetainedProviderServicePlan> {
        if matches!(self.authority.scope, Scope::Provider { .. }) {
            return Err(invalid("provider service cannot select all network plans"));
        }
        self.authority.profile.original_plan(provider)
    }

    pub(super) fn manifest(&self) -> &StreamTokenAuthorityManifest {
        &self.authority.manifest
    }

    pub(super) fn network_id(&self) -> iroha_data_model::NetworkId {
        self.authority.config.network_id
    }

    pub(super) fn chain_id(&self) -> &str {
        self.authority.config.chain.as_str()
    }

    pub(super) fn manager_account(&self) -> &AccountId {
        &self.authority.config.account
    }

    pub(super) fn genesis_hash(&self) -> [u8; 32] {
        *self.authority.genesis.genesis.hash().as_ref()
    }

    pub(super) fn network_role(&self, role: NetworkServiceAuthorityRole) -> Result<&AccountId> {
        self.authority.network_role(role)
    }

    pub(super) fn gateway_compliance_plan(
        &self,
        provider: ProviderId,
    ) -> Result<RetainedGatewayCompliancePlan> {
        self.authority.provider_inventory(provider)?;
        // The original bounded canonical decode remains real in every enclosing resource scope.
        self.authority.profile.original_compliance_plan(provider)
    }

    pub(super) fn publication_plan(
        &self,
    ) -> Result<crate::localnet::service_authorities::RetainedPublicationServicePlan> {
        if matches!(self.authority.scope, Scope::Provider { .. }) {
            return Err(invalid(
                "provider service cannot select network publication intent",
            ));
        }
        self.authority.profile.original_publication_plan()
    }

    /// Compare policies against this exact immutable original before the owner closes it.
    /// Active physical admission and owned originals keep the standalone validation recipe.
    pub(super) fn validate_policies(
        &self,
        policies: &super::service_policies::GeneratedServicePolicies,
    ) -> Result<()> {
        if norito::core::decode_limits_active()
            || matches!(&self.authority.profile, AuthorityProfile::Owned(_))
        {
            return policies.validate(self.authority);
        }
        policies.validate_projection(self)
    }

    // Exact lock/scope observations from validate_profile, without another image traversal.
    // This private projection is enclosed by the original intent's full entry and finish.
    pub(super) fn validate_policy_custody(&self) -> Result<()> {
        self.authority.validate_operation_custody()?;
        if let Scope::Provider { provider, slot } = self.authority.scope
            && self.authority.manifest.provider(provider)?.slot != slot
        {
            return Err(invalid("original provider operation scope changed"));
        }
        self.authority.validate_operation_custody()
    }

    pub(super) fn finish(self) -> Result<()> {
        self.authority.validate_profile()
    }
}

fn operation_directory(
    runtime: &PrivateDirectory,
    scope: Scope,
    purpose: &str,
    create: bool,
) -> Result<Option<PrivateDirectory>> {
    let child = |parent: &PrivateDirectory, name: &str| -> Result<Option<PrivateDirectory>> {
        if create {
            return parent.ensure_child(name).map(Some).map_err(Into::into);
        }
        parent.open_child_optional(name).map_err(Into::into)
    };
    let Some(operations) = child(runtime, "service-operations")? else {
        return Ok(None);
    };
    let selected = match scope {
        Scope::Network => child(&operations, "network")?,
        Scope::Provider { slot, .. } => {
            let Some(providers) = child(&operations, "providers")? else {
                return Ok(None);
            };
            child(&providers, &slot.to_string())?
        }
    };
    let Some(selected) = selected else {
        return Ok(None);
    };
    child(&selected, purpose)
}

impl ServiceAuthority {
    /// Enter a pure original-intent projection after fresh whole-image and operation-lock checks.
    /// The returned view must finish with the same checks before its projection is returned.
    pub(super) fn original_intent(&self) -> Result<OriginalServiceIntent<'_>> {
        self.validate_profile()?;
        Ok(OriginalServiceIntent { authority: self })
    }

    /// Borrow immutable constructor intent only outside active physical decode admission.
    /// Owned originals and active callers must use their original standalone producer.
    pub(super) fn original_intent_if_shared(&self) -> Result<Option<OriginalServiceIntent<'_>>> {
        if norito::core::decode_limits_active()
            || matches!(&self.profile, AuthorityProfile::Owned(_))
        {
            return Ok(None);
        }
        self.original_intent().map(Some)
    }

    pub(super) fn open_network(
        prepared: &PreparedLocalnet,
        purpose: NetworkPurpose,
    ) -> Result<Self> {
        Self::open(prepared, None, purpose.directory_name(), true)?
            .ok_or_else(|| invalid("new native operation custody was not created"))
    }

    /// Create or retain one network purpose from the parent's immutable original bundle.
    /// This supplies no signing authority; the selected child obtains its own native lock.
    /// Active decode admission and an owned parent retain the full standalone capture recipe.
    pub(super) fn open_network_from_original(
        parent: &Self,
        purpose: NetworkPurpose,
    ) -> Result<Self> {
        Self::open_from_original(parent, None, purpose.directory_name(), true, None)?
            .ok_or_else(|| invalid("new native operation custody was not created"))
    }

    pub(super) fn open_provider(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        purpose: ProviderPurpose,
    ) -> Result<Self> {
        Self::open(prepared, Some(provider), purpose.directory_name(), true)?
            .ok_or_else(|| invalid("new native operation custody was not created"))
    }

    /// Create or retain one provider purpose from the parent's immutable original bundle.
    /// The selected child takes its own native lock; this grants no current or signing authority.
    /// Active decode admission and an owned parent retain the full standalone capture recipe.
    pub(super) fn open_provider_from_original(
        parent: &Self,
        provider: ProviderId,
        purpose: ProviderPurpose,
    ) -> Result<Self> {
        Self::open_from_original(parent, Some(provider), purpose.directory_name(), true, None)?
            .ok_or_else(|| invalid("new native operation custody was not created"))
    }

    /// Observe the actual creating-child return before its original parent exit check.
    /// This delegates the existing one-shot test hook and restores it when the guard drops.
    #[cfg(test)]
    pub(super) fn test_on_creating_child_exit(action: impl FnOnce() + 'static) -> impl Drop {
        creating_original_tests::install(action)
    }

    pub(super) fn open_network_existing(
        prepared: &PreparedLocalnet,
        purpose: NetworkPurpose,
    ) -> Result<Option<Self>> {
        Self::open(prepared, None, purpose.directory_name(), false)
    }

    pub(super) fn open_provider_existing(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        purpose: ProviderPurpose,
    ) -> Result<Option<Self>> {
        Self::open(prepared, Some(provider), purpose.directory_name(), false)
    }

    /// Open a fresh existing network purpose from the parent's immutable original bundle.
    /// Active decode admission and an owned parent retain the full standalone capture recipe.
    /// An optional lexical scope reuses only exact immutable checkpoint imports.
    pub(super) fn open_network_existing_from_original(
        parent: &Self,
        purpose: NetworkPurpose,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Self::open_existing_from_original(parent, None, purpose.directory_name(), scope)
    }

    /// Open a fresh existing provider purpose from the parent's immutable original bundle.
    /// The selected child retains its own native directory, lock and complete profile checks.
    /// An optional lexical scope reuses only exact immutable checkpoint imports.
    pub(super) fn open_provider_existing_from_original(
        parent: &Self,
        provider: ProviderId,
        purpose: ProviderPurpose,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Self::open_existing_from_original(parent, Some(provider), purpose.directory_name(), scope)
    }

    /// Existing-only child construction inside the exact enclosing original read.
    pub(super) fn open_network_existing_in_runtime(
        parent: &Self,
        purpose: NetworkPurpose,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<Option<Self>> {
        Self::open_existing_in_runtime(parent, None, purpose.directory_name(), None, read)
    }

    pub(super) fn open_provider_existing_in_runtime(
        parent: &Self,
        provider: ProviderId,
        purpose: ProviderPurpose,
        imports: Option<&CheckpointImportScope>,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<Option<Self>> {
        Self::open_existing_in_runtime(
            parent,
            Some(provider),
            purpose.directory_name(),
            imports,
            read,
        )
    }

    fn open_existing_in_runtime(
        parent: &Self,
        provider: Option<ProviderId>,
        purpose: &'static str,
        imports: Option<&CheckpointImportScope>,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<Option<Self>> {
        if !read.eligible(parent)? {
            return Self::open_existing_from_original(parent, provider, purpose, imports);
        }
        if !std::ptr::eq(parent, read.authority) {
            return Err(invalid(
                "runtime constructor belongs to another original owner",
            ));
        }
        Self::open_from_original_with_read(parent, provider, purpose, false, imports, Some(read))
    }

    fn open(
        prepared: &PreparedLocalnet,
        provider: Option<ProviderId>,
        purpose: &'static str,
        create: bool,
    ) -> Result<Option<Self>> {
        #[cfg(test)]
        inventory::record_authority_open();
        let captured = capture_retained(prepared)?.ok_or_else(|| {
            invalid("managed native operation requires its original StreamTokenAuthorities profile")
        })?;
        let (profile, config, genesis, peer_ids) = if norito::core::decode_limits_active() {
            // Do not introduce a new Arc or clone a decoded genesis inside caller admission.
            (
                AuthorityProfile::Owned(captured.retained),
                captured.config,
                captured.genesis,
                captured.peer_ids,
            )
        } else {
            let captured = Arc::new(captured);
            (
                AuthorityProfile::Shared(Arc::clone(&captured)),
                captured.config.clone(),
                captured.genesis.clone(),
                captured.peer_ids.clone(),
            )
        };
        Self::open_profile(
            prepared, provider, purpose, create, profile, config, genesis, peer_ids, None, None,
        )
    }

    fn open_existing_from_original(
        parent: &Self,
        provider: Option<ProviderId>,
        purpose: &'static str,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Self::open_from_original(parent, provider, purpose, false, scope)
    }

    // The same immutable bundle and native tail serve existing readers and the authorized
    // typed creators. Active callers and owned parents keep the original full capture.
    fn open_from_original(
        parent: &Self,
        provider: Option<ProviderId>,
        purpose: &'static str,
        create: bool,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Self::open_from_original_with_read(parent, provider, purpose, create, scope, None)
    }

    fn open_from_original_with_read(
        parent: &Self,
        provider: Option<ProviderId>,
        purpose: &'static str,
        create: bool,
        scope: Option<&CheckpointImportScope>,
        read: Option<&RuntimeOriginalRead<'_>>,
    ) -> Result<Option<Self>> {
        if norito::core::decode_limits_active() {
            return Self::open(&parent.prepared, provider, purpose, create);
        }
        let AuthorityProfile::Shared(captured) = &parent.profile else {
            return Self::open(&parent.prepared, provider, purpose, create);
        };
        #[cfg(test)]
        inventory::record_authority_open();
        parent.validate_profile_with_runtime(read)?;
        let mut result = Self::open_profile(
            &parent.prepared,
            provider,
            purpose,
            create,
            AuthorityProfile::Shared(Arc::clone(captured)),
            captured.config.clone(),
            captured.genesis.clone(),
            captured.peer_ids.clone(),
            Some(&parent.transport_seed),
            read,
        );
        if let Ok(Some(owner)) = &mut result {
            // Eligible construction is outside active admission and from the shared profile.
            // Default/profile-only callers supply None and retain their original local memo.
            owner.checkpoint_import_scope = scope.cloned();
            if let Err(error) = owner.certificate_scope.inherit(&parent.certificate_scope) {
                result = Err(error);
            }
        }
        #[cfg(test)]
        if create {
            creating_original_tests::after_child();
        } else {
            profile_validation_test_support::after_existing_child(&result);
        }
        // Close the retained parent on every ordinary child result while a successful child's
        // native directory and lock remain live. Parent custody failure supersedes that result.
        parent.validate_profile_with_runtime(read)?;
        result
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Share one native constructor tail across moved and immutable original outputs"
    )]
    fn open_profile(
        prepared: &PreparedLocalnet,
        provider: Option<ProviderId>,
        purpose: &'static str,
        create: bool,
        profile: AuthorityProfile,
        config: Config,
        genesis: GenesisAnchor,
        peer_ids: [PeerId; 4],
        transport_seed: Option<&Client>,
        read: Option<&RuntimeOriginalRead<'_>>,
    ) -> Result<Option<Self>> {
        let manifest = profile.manifest().clone();
        // Resolve the original provider before any operation directory or lock is created.
        let scope = match provider {
            Some(provider) => Scope::Provider {
                slot: manifest.provider(provider)?.slot,
                provider,
            },
            None => Scope::Network,
        };
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let peers = service_peers(prepared, peer_ids, &config, transport_seed)?;
        let transport_seed = peers
            .first()
            .ok_or_else(|| invalid("original service committee is empty"))?
            .1
            .clone();
        let Some(directory) = operation_directory(profile.runtime(), scope, purpose, create)?
        else {
            return Ok(None);
        };
        let lock = if create {
            directory.open_lock("operation.lock")?
        } else {
            match directory.open_existing_lock("operation.lock") {
                Ok(lock) => lock,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A crash before lock publication can leave only this exact empty directory.
                    super::native_operation::require_empty(&directory)?;
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        };
        lock.try_lock()
            .map_err(|_| invalid("another managed native operation holds this generation"))?;
        directory.revalidate()?;
        match read {
            Some(read) if !norito::core::decode_limits_active() => {
                read.require_image(&profile, prepared, &manifest)?;
            }
            _ => profile.revalidate(prepared, &manifest)?,
        }
        Ok(Some(Self {
            scope,
            profile,
            transport_seed,
            checkpoint_cache: checkpoint_cache::CheckpointCache::default(),
            checkpoint_import_scope: None,
            certificate_scope: certificate_seed::Scope::default(),
            prepared: prepared.clone(),
            directory,
            _lock: lock,
            manifest,
            config,
            genesis,
            peers,
        }))
    }

    /// Select authenticated public intent without acquiring another live child lock.
    pub(super) fn provider_inventory(
        &self,
        provider: ProviderId,
    ) -> Result<&ProviderServiceInventory> {
        if let Scope::Provider {
            provider: selected, ..
        } = self.scope
            && provider != selected
        {
            return Err(invalid("provider differs from selected service scope"));
        }
        self.manifest.provider(provider)
    }

    pub(super) fn provider_id(&self) -> Result<ProviderId> {
        match self.scope {
            Scope::Provider { provider, .. } => Ok(provider),
            Scope::Network => Err(invalid("network service has no selected provider")),
        }
    }

    pub(super) fn provider_role(&self, role: StreamTokenAuthorityRole) -> Result<&AccountId> {
        Ok(&self
            .provider_inventory(self.provider_id()?)?
            .authority(role)?
            .account)
    }

    pub(super) fn network_role(&self, role: NetworkServiceAuthorityRole) -> Result<&AccountId> {
        Ok(&self.manifest.network.authority(role)?.account)
    }

    /// Borrow the complete original network selection after rechecking every captured input.
    /// This conveys neither a current provider permission nor a live service eligibility claim.
    pub(super) fn provider_plans(&self) -> Result<&[RetainedProviderServicePlan; 3]> {
        self.validate_profile()?;
        if matches!(self.scope, Scope::Provider { .. }) {
            return Err(invalid("provider service cannot select all network plans"));
        }
        Ok(self.profile.original_plans())
    }

    /// Project original compliance intent within this operation's authenticated provider scope.
    pub(super) fn gateway_compliance_plan(
        &self,
        provider: ProviderId,
    ) -> Result<RetainedGatewayCompliancePlan> {
        self.validate_profile()?;
        self.provider_inventory(provider)?;
        self.profile.original_compliance_plan(provider)
    }

    /// Project singleton publication intent from the original parsed client and manifest.
    /// The network operation retains full-image custody; this grants no current eligibility.
    pub(super) fn publication_plan(
        &self,
    ) -> Result<crate::localnet::service_authorities::RetainedPublicationServicePlan> {
        self.validate_profile()?;
        if matches!(self.scope, Scope::Provider { .. }) {
            return Err(invalid(
                "provider service cannot select network publication intent",
            ));
        }
        self.profile.original_publication_plan()
    }

    /// Sign through the sole generated catalog owner, retaining full source and lock custody.
    pub(super) fn sign_gateway_compliance_catalog(
        &self,
        previous: Option<&sorafs_manifest::gateway_compliance::GatewayComplianceCatalogV1>,
        now_seconds: u64,
    ) -> Result<sorafs_manifest::gateway_compliance::GatewayComplianceCatalogV1> {
        self.validate_profile()?;
        let catalog = self.profile.sign_gateway_compliance_catalog(
            self.provider_id()?,
            previous,
            now_seconds,
        )?;
        self.validate_profile()?;
        Ok(catalog)
    }

    /// Verify original catalog history; this grants no current freshness or serving authority.
    pub(super) fn validate_generated_gateway_catalog(
        &self,
        catalog: &sorafs_manifest::gateway_compliance::GatewayComplianceCatalogV1,
    ) -> Result<()> {
        self.validate_profile()?;
        self.profile
            .validate_generated_gateway_catalog(self.provider_id()?, catalog)?;
        self.validate_profile()
    }

    /// Sign only the exact observed catalog with the original gateway key and current clock.
    pub(super) fn sign_observed_gateway_catalog(
        &self,
        observation: &super::gateway_compliance::ObservedGatewayCatalog,
        catalog: &sorafs_manifest::gateway_compliance::GatewayComplianceCatalogV1,
    ) -> Result<sorafs_manifest::gateway_compliance::GatewayComplianceAcknowledgementV1> {
        self.validate_profile()?;
        let acknowledgement = self.profile.sign_observed_gateway_catalog(
            self.provider_id()?,
            observation,
            catalog,
        )?;
        self.validate_profile()?;
        Ok(acknowledgement)
    }

    pub(super) fn provider_plan(&self) -> Result<RetainedProviderServicePlan> {
        self.validate_profile()?;
        self.profile.original_plan(self.provider_id()?)
    }

    /// Select only the original generated issuer operator after authenticating the whole profile.
    /// The manager and independently selected finality peers stay unchanged. This is a local
    /// signing configuration, not evidence of current native permission, registration or funds.
    pub(super) fn issuer_operator_config(&self) -> Result<Config> {
        self.validate_profile()
            .map_err(|_| invalid("invalid original issuer-operator profile"))?;
        let key = crate::localnet::service_authorities::issuer_operator_key(
            &self.prepared,
            &self.manifest,
            self.provider_id()?,
        )?;
        let mut config = self.config.clone();
        config.account = self
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)?
            .clone();
        config.key_pair = key;
        Ok(config)
    }

    /// Select the original shared reserve operator, preserving manager finality clients.
    pub(super) fn reserve_operations_config(&self) -> Result<Config> {
        self.validate_profile()
            .map_err(|_| invalid("invalid original reserve-operations profile"))?;
        let key = crate::localnet::service_authorities::reserve_operations_key(
            &self.prepared,
            &self.manifest,
        )?;
        let mut config = self.config.clone();
        config.account = self
            .network_role(NetworkServiceAuthorityRole::ReserveOperations)?
            .clone();
        config.key_pair = key;
        Ok(config)
    }

    fn validate_operation_custody(&self) -> Result<()> {
        #[cfg(test)]
        profile_validation_test_support::record_operation_custody();
        #[cfg(test)]
        profile_validation_test_support::record_operation_path(self.directory.path());
        self.directory.revalidate()?;
        if iroha_fs::FileIdentity::of(&self.directory.open_read("operation.lock")?)?
            != iroha_fs::FileIdentity::of(&self._lock)?
        {
            return Err(invalid("managed native operation lock was replaced"));
        }
        Ok(())
    }

    pub(super) fn validate_profile_with_runtime(
        &self,
        read: Option<&RuntimeOriginalRead<'_>>,
    ) -> Result<()> {
        match read {
            Some(read) => read.validate_profile(self),
            None => self.validate_profile(),
        }
    }

    pub(super) fn original_intent_in_runtime(
        &self,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<OriginalServiceIntent<'_>> {
        read.validate_profile(self)?;
        Ok(OriginalServiceIntent { authority: self })
    }

    pub(super) fn provider_plans_in_runtime(
        &self,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<&[RetainedProviderServicePlan; 3]> {
        read.validate_profile(self)?;
        if matches!(self.scope, Scope::Provider { .. }) {
            return Err(invalid("provider service cannot select all network plans"));
        }
        Ok(self.profile.original_plans())
    }

    pub(super) fn validate_profile(&self) -> Result<()> {
        #[cfg(test)]
        profile_validation_test_support::record();
        self.validate_operation_custody()?;
        self.profile.revalidate(&self.prepared, &self.manifest)?;
        if let Scope::Provider { provider, slot } = self.scope
            && self.manifest.provider(provider)?.slot != slot
        {
            return Err(invalid("original provider operation scope changed"));
        }
        self.validate_operation_custody()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

// The original registration reader is shared without a parallel transport or proof verifier.
impl ServiceAuthority {
    pub(super) fn read_reserve_account(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        verifier: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedReserveAccountStateV1> {
        let block = verifier
            .verified_tip()
            .map_err(|_| invalid("invalid certified reserve tip"))?;
        let schema = iroha_core::state::State::native_world_schema_hash_v1()
            .map_err(|_| invalid("native reserve schema unavailable"))?;
        // Keep the original manager clients intact for finality. Rebind only the account
        // signer of each independently selected original committee endpoint for this purpose.
        let operator = self.reserve_operations_config()?;
        let provider = self.provider_id()?;
        let owner = self.provider_role(StreamTokenAuthorityRole::IssuerOperator)?;
        read_selected_peers(&self.peers, deadline, |client, deadline| {
            let mut builder = client.to_builder();
            builder.account = operator.account.clone();
            builder.key_pair = operator.key_pair.clone();
            let client = builder
                .build()
                .map_err(|_| invalid("invalid reserve operator client"))?;
            client
                .with_request_deadline(deadline)
                .get_reserve_account_state(
                    &policy.operations_authority,
                    provider,
                    owner,
                    policy,
                    schema,
                    &block,
                )
                .map_err(|_| invalid("native reserve provider candidate unavailable or invalid"))
        })
    }
}

#[cfg(test)]
#[path = "service_authority/capture_tests.rs"]
mod capture_tests;

#[cfg(test)]
pub(super) mod profile_validation_test_support;

#[cfg(test)]
#[path = "service_authority/original_intent_tests.rs"]
mod original_intent_tests;

#[cfg(test)]
#[path = "service_authority/creating_original_tests.rs"]
mod creating_original_tests;

#[cfg(test)]
#[path = "service_authority/creating_custody_tests.rs"]
mod creating_custody_tests;

// The seed is private original constructor state, never a mutable account/peer projection.
// Rebuilding resets all compatibility/probe state while retaining only transport owners.
fn service_peers(
    prepared: &PreparedLocalnet,
    peer_ids: [PeerId; 4],
    config: &Config,
    seed: Option<&Client>,
) -> Result<Vec<(PeerId, Client)>> {
    let mut peers: Vec<(PeerId, Client)> = Vec::with_capacity(4);
    for (peer, id) in prepared.peers.iter().zip(peer_ids) {
        let original = seed.or_else(|| peers.first().map(|(_, client)| client));
        let mut builder =
            original.map_or_else(|| Client::builder(config.clone()), Client::to_builder);
        builder.torii_url = peer
            .torii_url
            .parse()
            .map_err(|_| invalid("invalid service peer endpoint"))?;
        let client = builder
            .build()
            .map_err(|_| invalid("cannot construct service peer client"))?;
        peers.push((id, client));
    }
    Ok(peers)
}

#[cfg(test)]
#[path = "service_authority/transport_tests.rs"]
mod transport_tests;
