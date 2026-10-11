//! Original generated service authority, signed genesis and private operation custody.

use super::{
    PreparedLocalnet, Result,
    native_operation::{invalid, read_selected_peers},
};
use crate::{
    localnet::service_authorities::{
        NetworkServiceAuthorityRole, ProviderServiceInventory, RetainedGatewayCompliancePlan,
        RetainedProviderServicePlan, RetainedServiceProfile, StreamTokenAuthorityManifest,
        StreamTokenAuthorityRole, capture_retained,
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
use std::{fs::File, time::Instant};

#[path = "service_authority/checkpoint_cache.rs"]
mod checkpoint_cache;

#[path = "service_authority/inventory.rs"]
mod inventory;
pub(super) use inventory::ServiceChildInventory;

pub(super) enum NetworkPurpose {
    BuildRegistry,
    InitialReservePolicy,
    InitialReputationPolicy,
    ServiceBootstrap,
    GeneratedRuntime,
}
impl NetworkPurpose {
    fn directory_name(self) -> &'static str {
        match self {
            Self::BuildRegistry => "build-registry",
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

pub(super) struct ServiceAuthority {
    scope: Scope,
    profile: RetainedServiceProfile,
    checkpoint_cache: checkpoint_cache::CheckpointCache,
    pub(super) prepared: PreparedLocalnet,
    pub(super) directory: PrivateDirectory,
    pub(super) _lock: File,
    pub(super) manifest: StreamTokenAuthorityManifest,
    pub(super) config: Config,
    pub(super) genesis: GenesisAnchor,
    pub(super) peers: Vec<(PeerId, Client)>,
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
        match parent.open_child(name) {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                parent.revalidate()?;
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
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
    pub(super) fn open_network(
        prepared: &PreparedLocalnet,
        purpose: NetworkPurpose,
    ) -> Result<Self> {
        Self::open(prepared, None, purpose.directory_name(), true)?
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
        let manifest = captured.retained.manifest().clone();
        // Resolve the original provider before any operation directory or lock is created.
        let scope = match provider {
            Some(provider) => Scope::Provider {
                slot: manifest.provider(provider)?.slot,
                provider,
            },
            None => Scope::Network,
        };
        let config = captured.config;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let mut peers = Vec::with_capacity(4);
        for (peer, id) in prepared.peers.iter().zip(captured.peer_ids) {
            let mut selected = config.clone();
            selected.torii_api_url = peer
                .torii_url
                .parse()
                .map_err(|_| invalid("invalid service peer endpoint"))?;
            let client = Client::builder(selected)
                .build()
                .map_err(|_| invalid("cannot construct service peer client"))?;
            peers.push((id, client));
        }
        let Some(directory) =
            operation_directory(captured.retained.runtime(), scope, purpose, create)?
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
        captured.retained.revalidate(prepared, &manifest)?;
        Ok(Some(Self {
            scope,
            profile: captured.retained,
            checkpoint_cache: checkpoint_cache::CheckpointCache::default(),
            prepared: prepared.clone(),
            directory,
            _lock: lock,
            manifest,
            config,
            genesis: captured.genesis,
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
        self.directory.revalidate()?;
        if iroha_fs::FileIdentity::of(&self.directory.open_read("operation.lock")?)?
            != iroha_fs::FileIdentity::of(&self._lock)?
        {
            return Err(invalid("managed native operation lock was replaced"));
        }
        Ok(())
    }

    pub(super) fn validate_profile(&self) -> Result<()> {
        #[cfg(test)]
        let _timing = crate::custody_timing::Span::enter(crate::custody_timing::Category::Profile);
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
