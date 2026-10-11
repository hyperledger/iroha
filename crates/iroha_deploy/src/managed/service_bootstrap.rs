//! Original generated service setup, composed through the sole native child journals.
//!
//! The parent retains all public policies and bounded fee authorization before paid work.
//! Historical completion never grants current service eligibility or enables a daemon.

use super::{
    ManagedInitialGatewaySetup, ManagedInitialProviderIngestAuthority,
    ManagedInitialReputationPolicy, ManagedInitialReservePolicy, ManagedReserveAccountRegistration,
    ManagedStreamTokenCustody, PreparedLocalnet, Result,
    native_operation::{
        Fees, ManagedTransactionFinality, attempts::Purpose, encode, invalid, read_optional,
        require_deadline, require_empty,
    },
    provider_funding::{ProviderFundingBootstrap, ProviderFundingProgress},
    service_authority::{NetworkPurpose, RuntimeOriginalRead, ServiceAuthority},
    service_policies::GeneratedServicePolicies,
};
use iroha_data_model::sorafs::{capacity::ProviderId, reserve::ReserveProviderTermsV1};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_wallet::operations::{BoundedTransactionOptions, OperationStatus};
use std::time::Instant;

const MAX_ORIGINAL_BYTES: usize = 512 * 1024;
const MAX_CARRIERS: usize = 29;

#[path = "service_bootstrap/authorization.rs"]
pub(super) mod authorization;
pub(super) use authorization::GeneratedBootstrapAuthorization;
#[path = "service_bootstrap/inventory.rs"]
mod inventory;
#[path = "service_bootstrap/phases.rs"]
mod phases;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::service_bootstrap::Original")]
struct Original {
    network: iroha_data_model::NetworkId,
    genesis: [u8; 32],
    profile: [u8; 32],
    policies: GeneratedServicePolicies,
    underwriting: [ReserveProviderTermsV1; 3],
    fees: Fees,
}

impl Original {
    fn select(authority: &ServiceAuthority, fees: Fees) -> Result<Self> {
        let policies = GeneratedServicePolicies::select(authority)?;
        let plans = authority.provider_plans()?;
        let original = Self {
            network: authority.config.network_id,
            genesis: *authority.genesis.genesis.hash().as_ref(),
            profile: *plans[0].original_profile_commitment().as_ref(),
            policies,
            underwriting: plans.each_ref().map(|plan| plan.reserve_terms().clone()),
            fees,
        };
        original.validate(authority)?;
        Ok(original)
    }
    fn validate(&self, authority: &ServiceAuthority) -> Result<()> {
        self.validate_with_runtime(authority, None)
    }
    fn validate_with_runtime(
        &self,
        authority: &ServiceAuthority,
        read: Option<&RuntimeOriginalRead<'_>>,
    ) -> Result<()> {
        encode(self, MAX_ORIGINAL_BYTES)?;
        self.fees.validate()?;
        match read {
            Some(read) => self.policies.validate_in_runtime(authority, read)?,
            None => self.policies.validate(authority)?,
        }
        let plans = match read {
            Some(read) => authority.provider_plans_in_runtime(read)?,
            None => authority.provider_plans()?,
        };
        if self.network != authority.config.network_id
            || self.genesis != *authority.genesis.genesis.hash().as_ref()
        {
            return Err(invalid("bootstrap original network or genesis changed"));
        }
        for (slot, plan) in plans.iter().enumerate() {
            if self.policies.providers[slot].provider_id != plan.provider_id()
                || &self.underwriting[slot] != plan.reserve_terms()
                || self.profile != *plan.original_profile_commitment().as_ref()
            {
                return Err(invalid(
                    "original service policy, profile or underwriting changed",
                ));
            }
        }
        Ok(())
    }
    fn digest(&self) -> Result<[u8; 32]> {
        Ok(*iroha_crypto::Hash::new(encode(self, MAX_ORIGINAL_BYTES)?).as_ref())
    }
}

fn read_original(
    directory: &PrivateDirectory,
    authority: &ServiceAuthority,
) -> Result<Option<Original>> {
    read_original_with_runtime(directory, authority, None)
}

fn read_original_with_runtime(
    directory: &PrivateDirectory,
    authority: &ServiceAuthority,
    read: Option<&RuntimeOriginalRead<'_>>,
) -> Result<Option<Original>> {
    let Some(bytes) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? else {
        require_empty(directory)?;
        return Ok(None);
    };
    let original: Original = norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES * 8,
            48,
        ),
    )
    .map_err(|_| invalid("invalid original service bootstrap intent"))?;
    original.validate_with_runtime(authority, read)?;
    Ok(Some(original))
}

/// Exact next purpose and original provider scope; never a dispatch capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ServiceBootstrapStep {
    ReservePolicy,
    CustodyPolicy { provider_id: ProviderId },
    CustodyEnrollment { provider_id: ProviderId },
    ReserveAccount { provider_id: ProviderId },
    ProviderFunding { provider_id: ProviderId },
    ProviderIngest { provider_id: ProviderId },
    Gateway { provider_id: ProviderId },
    Reputation,
}

/// Fresh traversal frontiers, not decoded completion or dispatch authority. A completed
/// reserve precedes three independent provider chains; `None` means that branch was fully
/// recovered by its native owners in this traversal.
#[derive(Debug)]
struct DependencyFrontiers {
    reserve_complete: bool,
    reputation_complete: bool,
    providers: [Option<ServiceBootstrapStep>; 3],
}
impl DependencyFrontiers {
    fn before_reserve(policies: &GeneratedServicePolicies) -> Self {
        Self {
            reserve_complete: false,
            reputation_complete: false,
            providers: std::array::from_fn(|slot| {
                Some(ServiceBootstrapStep::CustodyPolicy {
                    provider_id: policies.providers[slot].provider_id,
                })
            }),
        }
    }
}

/// One traversal's exact report and independently authenticated provider frontiers. Only
/// the phase producer creates successful histories; the census uses frontiers solely to refuse
/// out-of-order material and never turns presence into completion.
#[derive(Debug)]
struct RunOutcome {
    progress: ServiceBootstrapProgress,
    dependencies: DependencyFrontiers,
}

/// Only original completed funding facts enter the opaque parent history. The unfinished
/// reports and their optional current-state graphs stay with the separate progress branch.
#[derive(Debug)]
struct CompletedFunding {
    request: Option<super::ManagedHistoricalReserveTopUp>,
    approval: Option<super::ManagedHistoricalReserveTopUpApproval>,
    credit: ManagedTransactionFinality,
    capacity: ManagedTransactionFinality,
}
impl CompletedFunding {
    // Called after the sole funding phase's existing completion and prerequisite checks,
    // after releasing its native child owner. This moves facts and creates no evidence.
    #[inline(never)]
    fn from_progress(progress: ProviderFundingProgress) -> Result<Self> {
        match progress {
            ProviderFundingProgress::Complete {
                request,
                approval,
                credit,
                capacity,
            } => Ok(Self {
                request,
                approval,
                credit,
                capacity,
            }),
            _ => Err(invalid("bootstrap funding history is not complete")),
        }
    }
}

/// Privately produced from each exact original child, not a public completion DTO.
#[derive(Debug)]
pub(super) struct HistoricalProviderBootstrap {
    provider_id: ProviderId,
    custody_policy: ManagedTransactionFinality,
    custody_enrollment: ManagedTransactionFinality,
    reserve_account: ManagedTransactionFinality,
    funding: CompletedFunding,
    provider_ingest: ManagedTransactionFinality,
    gateway: ManagedTransactionFinality,
}
impl HistoricalProviderBootstrap {
    pub(super) fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
    pub(super) fn custody_enrollment(&self) -> ManagedTransactionFinality {
        self.custody_enrollment
    }
}

/// Opaque complete original history. No decoded/caller-constructed report mints completion.
#[derive(Debug)]
pub(super) struct HistoricalServiceBootstrap {
    reserve_policy: ManagedTransactionFinality,
    providers: [HistoricalProviderBootstrap; 3],
    reputation: ManagedTransactionFinality,
}
impl HistoricalServiceBootstrap {
    pub(super) fn reputation(&self) -> ManagedTransactionFinality {
        self.reputation
    }
    pub(super) fn provider(&self, provider: ProviderId) -> Result<&HistoricalProviderBootstrap> {
        self.providers
            .iter()
            .find(|history| history.provider_id == provider)
            .ok_or_else(|| invalid("provider is absent from original bootstrap history"))
    }
    /// Every original carrier in stable height order, retaining canonical provider/purpose
    /// order for equal heights. At most29; no max-height projection.
    /// Optional funding Request/Approval are both absent only when original economics needed none.
    pub(super) fn ordered_carriers(&self) -> Result<Vec<ManagedTransactionFinality>> {
        for (slot, provider) in self.providers.iter().enumerate() {
            if self.providers[..slot]
                .iter()
                .any(|earlier| earlier.provider_id == provider.provider_id)
            {
                return Err(invalid("bootstrap history repeats a provider"));
            }
        }
        let mut carriers = Vec::with_capacity(MAX_CARRIERS);
        carriers.push(self.reserve_policy);
        let mut maximum_gateway_height = self.reserve_policy.height;
        for provider in &self.providers {
            let provider_start = carriers.len();
            carriers.extend([
                provider.custody_policy,
                provider.custody_enrollment,
                provider.reserve_account,
            ]);
            let CompletedFunding {
                request,
                approval,
                credit,
                capacity,
            } = &provider.funding;
            match (request, approval) {
                (Some(request), Some(approval)) => {
                    if request.movement_id() != approval.request().movement_id()
                        || request.amount() != approval.request().amount()
                    {
                        return Err(invalid("bootstrap funding histories differ"));
                    }
                    carriers.extend([*request.original(), *approval.original()]);
                }
                (None, None) => {}
                _ => return Err(invalid("bootstrap funding history omits one original")),
            }
            carriers.extend([
                *credit,
                *capacity,
                provider.provider_ingest,
                provider.gateway,
            ]);
            require_after(&provider.custody_policy, self.reserve_policy.height)?;
            for pair in carriers[provider_start..].windows(2) {
                require_after(&pair[1], pair[0].height)?;
            }
            maximum_gateway_height = maximum_gateway_height.max(provider.gateway.height);
        }
        require_after(&self.reputation, maximum_gateway_height)?;
        carriers.push(self.reputation);
        if carriers.len() > MAX_CARRIERS {
            return Err(invalid("bootstrap carrier count exceeds bound"));
        }
        for (index, carrier) in carriers.iter().enumerate() {
            if carriers[..index]
                .iter()
                .any(|earlier| earlier.transaction_hash == carrier.transaction_hash)
            {
                return Err(invalid("bootstrap history repeats an original transaction"));
            }
        }
        // Different providers may share a certified block. Stable ordering retains every
        // exact original; it neither replaces per-provider prerequisites nor authenticates a DTO.
        carriers.sort_by_key(|carrier| carrier.height);
        Ok(carriers)
    }
}

#[derive(Debug)]
pub(super) enum ServiceBootstrapProgress {
    Pending {
        step: ServiceBootstrapStep,
        status: OperationStatus,
    },
    Funding {
        provider_id: ProviderId,
        progress: ProviderFundingProgress,
    },
    Complete(HistoricalServiceBootstrap),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Advance,
    Recover,
    Local,
}

/// The private initial bootstrap does not accept caller-selected policy families or key roles.
pub(super) struct ManagedServiceBootstrap {
    authority: ServiceAuthority,
}

impl ManagedServiceBootstrap {
    pub(super) fn open(prepared: &PreparedLocalnet) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_network(prepared, NetworkPurpose::ServiceBootstrap)?,
        })
    }

    /// Open only an existing bootstrap purpose through the parent's original profile.
    /// This retains fresh profile, native directory and lock admission; active decode budgets
    /// and owned profiles still use the complete standalone capture recipe.
    pub(super) fn open_existing_from_original(parent: &ServiceAuthority) -> Result<Option<Self>> {
        ServiceAuthority::open_network_existing_from_original(
            parent,
            NetworkPurpose::ServiceBootstrap,
            None,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    pub(super) fn open_existing_in_runtime(
        parent: &ServiceAuthority,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_network_existing_in_runtime(
            parent,
            NetworkPurpose::ServiceBootstrap,
            read,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    /// A newly created worker alone calls this finite authorization producer. Existing worker
    /// polling, recovery, maintenance and owned daemon restart have no path to this method.
    pub(super) fn authorize_generated_startup(
        &mut self,
        deadline: Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<GeneratedBootstrapAuthorization>> {
        self.authorize_startup(generated_fees(deadline)?, deadline, cancelled)
    }

    #[cfg(test)]
    pub(in crate::managed) fn authorize_test_startup(
        &mut self,
        options: &BoundedTransactionOptions,
    ) -> Result<Option<GeneratedBootstrapAuthorization>> {
        self.authorize_startup(
            Fees::from_options(options)?,
            options.deadline,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }

    fn authorize_startup(
        &mut self,
        fees: Fees,
        deadline: Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<GeneratedBootstrapAuthorization>> {
        authorization::require_active(&cancelled)?;
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let existing = match self.authority.directory.open_child_optional("initial")? {
            Some(directory) => {
                read_original(&directory, &self.authority)?.map(|original| (directory, original))
            }
            None => None,
        };
        let (directory, original) = match existing {
            Some((directory, original)) => {
                if original.fees != fees {
                    return Err(invalid("original bootstrap fee authorization changed"));
                }
                (directory, original)
            }
            None => {
                let original = Original::select(&self.authority, fees)?;
                // Missing parent custody cannot be reconstructed around retained child work.
                // Inspect every exact child purpose before creating even the initial directory.
                self.validate_child_inventory(&original.policies, None)?;
                #[cfg(test)]
                tests::after_read(tests::ReadStage::OriginalInventory);
                authorization::require_active(&cancelled)?;
                require_deadline(deadline)?;
                let directory = self.authority.directory.ensure_child("initial")?;
                require_empty(&directory)?;
                let bytes = encode(&original, MAX_ORIGINAL_BYTES)?;
                #[cfg(test)]
                tests::after_read(tests::ReadStage::OriginalEncoding);
                authorization::require_active(&cancelled)?;
                require_deadline(deadline)?;
                directory.write_atomic("original.nrt", &bytes, PublishMode::CreateNew)?;
                (directory, original)
            }
        };
        authorization::validate_inventory(&directory, &original)?;
        #[cfg(test)]
        let mut stage_started = Instant::now();
        #[cfg(test)]
        eprintln!("bootstrap timing: action=authorize_startup stage=graph begin");
        let progress = self.run(deadline, Mode::Local, None);
        #[cfg(test)]
        eprintln!(
            "bootstrap timing: action=authorize_startup stage=graph end elapsed_ms={} remaining_ms={} ok={}",
            stage_started.elapsed().as_millis(),
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            progress.is_ok(),
        );
        let progress = progress?;
        #[cfg(test)]
        {
            stage_started = Instant::now();
            eprintln!("bootstrap timing: action=authorize_startup stage=census begin");
        }
        let census = self.validate_dependency_inventory(&progress.dependencies);
        #[cfg(test)]
        eprintln!(
            "bootstrap timing: action=authorize_startup stage=census end elapsed_ms={} remaining_ms={} ok={}",
            stage_started.elapsed().as_millis(),
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            census.is_ok(),
        );
        census?;
        #[cfg(test)]
        tests::after_read(tests::ReadStage::AuthorizationCensus);
        authorization::require_active(&cancelled)?;
        require_deadline(deadline)?;
        if matches!(progress.progress, ServiceBootstrapProgress::Complete(_)) {
            return Ok(None);
        }
        let authorization =
            GeneratedBootstrapAuthorization::issue(&self.authority, original, deadline, cancelled)?;
        #[cfg(test)]
        tests::after_read(tests::ReadStage::AuthorizationIssued);
        authorization.validate(&self.authority, deadline)?;
        Ok(Some(authorization))
    }

    pub(super) fn advance(
        &mut self,
        authorization: &GeneratedBootstrapAuthorization,
        deadline: Instant,
    ) -> Result<ServiceBootstrapProgress> {
        let deadline = authorization.validate(&self.authority, deadline)?;
        #[cfg(test)]
        let mut stage_started = Instant::now();
        #[cfg(test)]
        eprintln!("bootstrap timing: action=advance stage=graph begin");
        let progress = self.run(deadline, Mode::Local, None);
        #[cfg(test)]
        eprintln!(
            "bootstrap timing: action=advance stage=graph end elapsed_ms={} remaining_ms={} ok={}",
            stage_started.elapsed().as_millis(),
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            progress.is_ok(),
        );
        let progress = progress?;
        #[cfg(test)]
        {
            stage_started = Instant::now();
            eprintln!("bootstrap timing: action=advance stage=census begin");
        }
        let census = self.validate_dependency_inventory(&progress.dependencies);
        #[cfg(test)]
        eprintln!(
            "bootstrap timing: action=advance stage=census end elapsed_ms={} remaining_ms={} ok={}",
            stage_started.elapsed().as_millis(),
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            census.is_ok(),
        );
        census?;
        if matches!(&progress.progress, ServiceBootstrapProgress::Complete(_)) {
            // This call freshly authenticated every original child and the full dependency
            // census. Completion needs no dispatch pass; keep its live authorization exit.
            authorization.validate(&self.authority, deadline)?;
            return Ok(progress.progress);
        }
        let progress = self.run(deadline, Mode::Advance, Some(authorization))?;
        self.validate_dependency_inventory(&progress.dependencies)?;
        authorization.validate(&self.authority, deadline)?;
        Ok(progress.progress)
    }

    /// Observe exact original children without minting an epoch or creating missing custody.
    pub(super) fn recover(&mut self, deadline: Instant) -> Result<ServiceBootstrapProgress> {
        #[cfg(test)]
        let mut stage_started = Instant::now();
        #[cfg(test)]
        eprintln!("bootstrap timing: action=recover stage=graph begin");
        let progress = self.run(deadline, Mode::Recover, None);
        #[cfg(test)]
        eprintln!(
            "bootstrap timing: action=recover stage=graph end elapsed_ms={} remaining_ms={} ok={}",
            stage_started.elapsed().as_millis(),
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            progress.is_ok(),
        );
        let progress = progress?;
        #[cfg(test)]
        {
            stage_started = Instant::now();
            eprintln!("bootstrap timing: action=recover stage=census begin");
        }
        let census = self.validate_dependency_inventory(&progress.dependencies);
        #[cfg(test)]
        eprintln!(
            "bootstrap timing: action=recover stage=census end elapsed_ms={} remaining_ms={} ok={}",
            stage_started.elapsed().as_millis(),
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            census.is_ok(),
        );
        census?;
        #[cfg(test)]
        tests::after_read(tests::ReadStage::RecoveryCensus);
        require_deadline(deadline)?;
        Ok(progress.progress)
    }

    /// A closed original census selects scheduling only, never execution or readiness.
    pub(super) fn gateway_catalog_purposes_absent(&self) -> Result<bool> {
        super::service_authority::ServiceChildInventory::begin(&self.authority)?
            .gateway_catalog_purposes_absent()
    }

    /// Recover the same retained public intent for later runtime configuration.
    /// This accessor supplies no evidence of transaction execution or current eligibility.
    pub(super) fn selected_policies(&self) -> Result<GeneratedServicePolicies> {
        self.authority.validate_profile()?;
        let directory = self.authority.directory.open_child("initial")?;
        read_original(&directory, &self.authority)?
            .map(|original| original.policies)
            .ok_or_else(|| invalid("original service bootstrap intent is absent"))
    }

    pub(super) fn selected_policies_in_runtime(
        &self,
        read: &RuntimeOriginalRead<'_>,
    ) -> Result<GeneratedServicePolicies> {
        if !read.eligible(&self.authority)? {
            return self.selected_policies();
        }
        self.authority.validate_profile_with_runtime(Some(read))?;
        let directory = self.authority.directory.open_child("initial")?;
        read_original_with_runtime(&directory, &self.authority, Some(read))?
            .map(|original| original.policies)
            .ok_or_else(|| invalid("original service bootstrap intent is absent"))
    }

    fn run(
        &mut self,
        deadline: Instant,
        mode: Mode,
        authorization: Option<&GeneratedBootstrapAuthorization>,
    ) -> Result<RunOutcome> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let directory = self.authority.directory.open_child("initial")?;
        let original = read_original(&directory, &self.authority)?
            .ok_or_else(|| invalid("original service bootstrap intent is absent"))?;
        authorization::validate_inventory(&directory, &original)?;
        // Keep the original directory and intent alive across every joined native child owner.
        phases::run(&self.authority, &original, deadline, mode, authorization)
    }
}

fn incomplete<T>(result: Result<Option<T>>) -> Result<Option<T>> {
    match result {
        Err(super::Error::Bootstrap(super::ManagedBootstrapFailure::TransitionPending)) => Ok(None),
        other => other,
    }
}
fn generated_fees(deadline: Instant) -> Result<Fees> {
    let asset = iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .map_err(|_| invalid("invalid original bootstrap fee asset"))?;
    Fees::from_options(&BoundedTransactionOptions {
        fee_payment: iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: std::collections::BTreeMap::from([(
            asset,
            iroha_primitives::numeric::Quantity::from(1_u64),
        )]),
        deadline,
    })
}

fn require_after(finalized: &ManagedTransactionFinality, prior_height: u64) -> Result<()> {
    if finalized.height <= prior_height {
        return Err(invalid(
            "original service child carrier predates its prerequisite",
        ));
    }
    Ok(())
}

// Native current-use checks, catalog promotion and launch revision selection remain their sole
// owners. This aggregate supplies exact history only; no serving or automatic epoch is implied.

#[cfg(test)]
#[path = "service_bootstrap/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_bootstrap/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "service_bootstrap/inventory_tests.rs"]
mod inventory_tests;

#[cfg(test)]
#[path = "service_bootstrap/provider_dag_tests.rs"]
mod provider_dag_tests;
