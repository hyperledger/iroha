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
    service_authority::{NetworkPurpose, ServiceAuthority},
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
        encode(self, MAX_ORIGINAL_BYTES)?;
        self.fees.validate()?;
        self.policies.validate(authority)?;
        let plans = authority.provider_plans()?;
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
    original.validate(authority)?;
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

/// Privately produced from each exact original child, not a public completion DTO.
#[derive(Debug)]
pub(super) struct HistoricalProviderBootstrap {
    provider_id: ProviderId,
    custody_policy: ManagedTransactionFinality,
    custody_enrollment: ManagedTransactionFinality,
    reserve_account: ManagedTransactionFinality,
    funding: ProviderFundingProgress,
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
    /// Every original carrier in dependency order. At most29; no max-height projection.
    /// Optional funding Request/Approval are both absent only when original economics needed none.
    pub(super) fn ordered_carriers(&self) -> Result<Vec<ManagedTransactionFinality>> {
        let mut carriers = Vec::with_capacity(MAX_CARRIERS);
        carriers.push(self.reserve_policy);
        for provider in &self.providers {
            carriers.extend([
                provider.custody_policy,
                provider.custody_enrollment,
                provider.reserve_account,
            ]);
            let ProviderFundingProgress::Complete {
                request,
                approval,
                credit,
                capacity,
            } = &provider.funding
            else {
                return Err(invalid("bootstrap funding history is not complete"));
            };
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
        }
        carriers.push(self.reputation);
        if carriers.len() > MAX_CARRIERS {
            return Err(invalid("bootstrap carrier count exceeds bound"));
        }
        for pair in carriers.windows(2) {
            require_after(&pair[1], pair[0].height)?;
        }
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
        let existing = match self.authority.directory.open_child("initial") {
            Ok(directory) => {
                read_original(&directory, &self.authority)?.map(|original| (directory, original))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
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
                authorization::require_active(&cancelled)?;
                let directory = self.authority.directory.ensure_child("initial")?;
                require_empty(&directory)?;
                directory.write_atomic(
                    "original.nrt",
                    &encode(&original, MAX_ORIGINAL_BYTES)?,
                    PublishMode::CreateNew,
                )?;
                (directory, original)
            }
        };
        authorization::validate_inventory(&directory, &original)?;
        let progress = self.run(deadline, Mode::Local, None)?;
        self.validate_dependency_inventory(&progress)?;
        if matches!(progress, ServiceBootstrapProgress::Complete(_)) {
            return Ok(None);
        }
        GeneratedBootstrapAuthorization::issue(&self.authority, original, deadline, cancelled)
            .map(Some)
    }

    pub(super) fn advance(
        &mut self,
        authorization: &GeneratedBootstrapAuthorization,
        deadline: Instant,
    ) -> Result<ServiceBootstrapProgress> {
        let deadline = authorization.validate(&self.authority, deadline)?;
        let progress = self.run(deadline, Mode::Local, None)?;
        self.validate_dependency_inventory(&progress)?;
        self.run(deadline, Mode::Advance, Some(authorization))
    }

    /// Observe exact original children without minting an epoch or creating missing custody.
    pub(super) fn recover(&mut self, deadline: Instant) -> Result<ServiceBootstrapProgress> {
        let progress = self.run(deadline, Mode::Recover, None)?;
        self.validate_dependency_inventory(&progress)?;
        Ok(progress)
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

    fn run(
        &mut self,
        deadline: Instant,
        mode: Mode,
        authorization: Option<&GeneratedBootstrapAuthorization>,
    ) -> Result<ServiceBootstrapProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let directory = self.authority.directory.open_child("initial")?;
        let original = read_original(&directory, &self.authority)?
            .ok_or_else(|| invalid("original service bootstrap intent is absent"))?;
        authorization::validate_inventory(&directory, &original)?;
        let policies = &original.policies;
        let fees = &original.fees;
        let may_submit = || -> Result<bool> {
            if mode != Mode::Advance {
                return Ok(false);
            }
            authorization
                .ok_or_else(|| invalid("bootstrap advance requires its live worker authorization"))?
                .validate(&self.authority, deadline)?;
            Ok(true)
        };
        let absent = |step| -> Result<ServiceBootstrapProgress> {
            Ok(ServiceBootstrapProgress::Pending {
                step,
                status: OperationStatus::Absent,
            })
        };
        // Open-existing paths authenticate without creating directories or lock files. Only the
        // live startup branch can create a genuinely missing purpose after its prerequisites.
        macro_rules! open_child {
            ($owner:ty, $step:expr $(, $provider:expr)?) => {{
                match <$owner>::open_existing(&self.authority.prepared $(, $provider)?)? {
                    Some(owner) => owner,
                    None if may_submit()? => <$owner>::open(&self.authority.prepared $(, $provider)?)?,
                    None => return absent($step),
                }
            }};
        }
        let mut reserve = open_child!(
            ManagedInitialReservePolicy,
            ServiceBootstrapStep::ReservePolicy
        );
        let mut result = incomplete(if mode == Mode::Local {
            reserve.recover_local_selected_if_present(&policies.network.reserve, fees, deadline)
        } else {
            reserve.recover_selected_if_present(&policies.network.reserve, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && may_submit()?
        {
            result = Some(
                reserve.advance_selected(
                    &policies.network.reserve,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::ReservePolicy)?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::ReservePolicy);
        };
        let Some(reserve_policy) = result.finalized else {
            return Ok(ServiceBootstrapProgress::Pending {
                step: ServiceBootstrapStep::ReservePolicy,
                status: result.transaction_status,
            });
        };
        drop(reserve);

        let mut histories = Vec::with_capacity(3);
        let mut prior_height = reserve_policy.height;
        for (slot, selected) in policies.providers.iter().enumerate() {
            let provider_id = selected.provider_id;
            let mut custody = open_child!(
                ManagedStreamTokenCustody,
                ServiceBootstrapStep::CustodyPolicy { provider_id },
                provider_id
            );
            let mut result = incomplete(if mode == Mode::Local {
                custody.recover_configure_local_selected_if_present(
                    &selected.custody,
                    fees,
                    deadline,
                )
            } else {
                custody.recover_configure_selected_if_present(&selected.custody, fees, deadline)
            })?;
            if result
                .as_ref()
                .is_none_or(|value| value.finalized.is_none())
                && may_submit()?
            {
                result = Some(
                    custody.advance_configure_selected(
                        &selected.custody,
                        &authorization
                            .ok_or_else(|| {
                                invalid("bootstrap advance requires its live worker authorization")
                            })?
                            .child(Purpose::CustodyConfigure(provider_id))?,
                        deadline,
                    )?,
                );
            }
            let Some(result) = result else {
                return absent(ServiceBootstrapStep::CustodyPolicy { provider_id });
            };
            let Some(custody_policy) = result.finalized else {
                return Ok(ServiceBootstrapProgress::Pending {
                    step: ServiceBootstrapStep::CustodyPolicy { provider_id },
                    status: result.transaction_status,
                });
            };

            require_after(&custody_policy, prior_height)?;
            let mut result = incomplete(if mode == Mode::Local {
                custody.recover_enroll_local_selected_if_present(&selected.custody, fees, deadline)
            } else {
                custody.recover_enroll_selected_if_present(&selected.custody, fees, deadline)
            })?;
            if result
                .as_ref()
                .is_none_or(|value| value.finalized.is_none())
                && may_submit()?
            {
                result = Some(
                    custody.advance_enroll_selected(
                        &selected.custody,
                        &authorization
                            .ok_or_else(|| {
                                invalid("bootstrap advance requires its live worker authorization")
                            })?
                            .child(Purpose::CustodyEnroll(provider_id))?,
                        deadline,
                    )?,
                );
            }
            let Some(result) = result else {
                return absent(ServiceBootstrapStep::CustodyEnrollment { provider_id });
            };
            let Some(custody_enrollment) = result.finalized else {
                return Ok(ServiceBootstrapProgress::Pending {
                    step: ServiceBootstrapStep::CustodyEnrollment { provider_id },
                    status: result.transaction_status,
                });
            };
            require_after(&custody_enrollment, custody_policy.height)?;
            drop(custody);

            let mut account = open_child!(
                ManagedReserveAccountRegistration,
                ServiceBootstrapStep::ReserveAccount { provider_id },
                provider_id
            );
            let mut result = incomplete(if mode == Mode::Local {
                account.recover_local_selected_if_present(
                    &policies.network.reserve,
                    &original.underwriting[slot],
                    fees,
                    deadline,
                )
            } else {
                account.recover_selected_if_present(
                    &policies.network.reserve,
                    &original.underwriting[slot],
                    fees,
                    deadline,
                )
            })?;
            if result
                .as_ref()
                .is_none_or(|value| value.finalized.is_none())
                && may_submit()?
            {
                result = Some(
                    account.advance_selected(
                        &policies.network.reserve,
                        &original.underwriting[slot],
                        &authorization
                            .ok_or_else(|| {
                                invalid("bootstrap advance requires its live worker authorization")
                            })?
                            .child(Purpose::ReserveAccount(provider_id))?,
                        deadline,
                    )?,
                );
            }
            let Some(result) = result else {
                return absent(ServiceBootstrapStep::ReserveAccount { provider_id });
            };
            let Some(reserve_account) = result.finalized else {
                return Ok(ServiceBootstrapProgress::Pending {
                    step: ServiceBootstrapStep::ReserveAccount { provider_id },
                    status: result.transaction_status,
                });
            };
            require_after(&reserve_account, custody_enrollment.height)?;
            drop(account);

            let mut funding = open_child!(
                ProviderFundingBootstrap,
                ServiceBootstrapStep::ProviderFunding { provider_id },
                provider_id
            );
            let mut result = incomplete(if mode == Mode::Local {
                funding.recover_local_selected_if_present(&policies.network.reserve, fees, deadline)
            } else {
                funding.recover_selected_if_present(&policies.network.reserve, fees, deadline)
            })?;
            if result
                .as_ref()
                .is_none_or(|value| !matches!(value, ProviderFundingProgress::Complete { .. }))
                && may_submit()?
            {
                result = Some(
                    funding.advance_selected(
                        &policies.network.reserve,
                        &authorization
                            .ok_or_else(|| {
                                invalid("bootstrap advance requires its live worker authorization")
                            })?
                            .funding(provider_id)?,
                        deadline,
                    )?,
                );
            }
            let Some(funding_result) = result else {
                return absent(ServiceBootstrapStep::ProviderFunding { provider_id });
            };
            let ProviderFundingProgress::Complete {
                credit, capacity, ..
            } = &funding_result
            else {
                return Ok(ServiceBootstrapProgress::Funding {
                    provider_id,
                    progress: funding_result,
                });
            };
            require_after(credit, reserve_account.height)?;
            require_after(capacity, credit.height)?;
            let funding_height = capacity.height;
            drop(funding);

            let mut ingest = open_child!(
                ManagedInitialProviderIngestAuthority,
                ServiceBootstrapStep::ProviderIngest { provider_id },
                provider_id
            );
            let mut result = incomplete(if mode == Mode::Local {
                ingest.recover_local_selected_if_present(&selected.provider_ingest, fees, deadline)
            } else {
                ingest.recover_selected_if_present(&selected.provider_ingest, fees, deadline)
            })?;
            if result
                .as_ref()
                .is_none_or(|value| value.finalized.is_none())
                && may_submit()?
            {
                result = Some(
                    ingest.advance_selected(
                        &selected.provider_ingest,
                        &authorization
                            .ok_or_else(|| {
                                invalid("bootstrap advance requires its live worker authorization")
                            })?
                            .child(Purpose::ProviderIngest(provider_id))?,
                        deadline,
                    )?,
                );
            }
            let Some(result) = result else {
                return absent(ServiceBootstrapStep::ProviderIngest { provider_id });
            };
            let Some(ingest_finality) = result.finalized else {
                return Ok(ServiceBootstrapProgress::Pending {
                    step: ServiceBootstrapStep::ProviderIngest { provider_id },
                    status: result.transaction_status,
                });
            };
            require_after(&ingest_finality, funding_height)?;
            drop(ingest);

            let mut gateway = open_child!(
                ManagedInitialGatewaySetup,
                ServiceBootstrapStep::Gateway { provider_id },
                provider_id
            );
            let mut result = incomplete(if mode == Mode::Local {
                gateway.recover_local_selected_if_present(&selected.gateway, fees, deadline)
            } else {
                gateway.recover_selected_if_present(&selected.gateway, fees, deadline)
            })?;
            if result
                .as_ref()
                .is_none_or(|value| value.finalized.is_none())
                && may_submit()?
            {
                result = Some(
                    gateway.advance_selected(
                        &selected.gateway,
                        &authorization
                            .ok_or_else(|| {
                                invalid("bootstrap advance requires its live worker authorization")
                            })?
                            .child(Purpose::Gateway(provider_id))?,
                        deadline,
                    )?,
                );
            }
            let Some(result) = result else {
                return absent(ServiceBootstrapStep::Gateway { provider_id });
            };
            let Some(gateway_finality) = result.finalized else {
                return Ok(ServiceBootstrapProgress::Pending {
                    step: ServiceBootstrapStep::Gateway { provider_id },
                    status: result.transaction_status,
                });
            };
            require_after(&gateway_finality, ingest_finality.height)?;
            drop(gateway);

            prior_height = gateway_finality.height;
            histories.push(HistoricalProviderBootstrap {
                provider_id,
                custody_policy,
                custody_enrollment,
                reserve_account,
                funding: funding_result,
                provider_ingest: ingest_finality,
                gateway: gateway_finality,
            });
        }
        let mut reputation = open_child!(
            ManagedInitialReputationPolicy,
            ServiceBootstrapStep::Reputation
        );
        let labels = policies.gateway_labels();
        let mut result = incomplete(if mode == Mode::Local {
            reputation.recover_local_selected_if_present(
                &labels,
                &policies.network.reputation,
                fees,
                deadline,
            )
        } else {
            reputation.recover_selected_if_present(
                &labels,
                &policies.network.reputation,
                fees,
                deadline,
            )
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && may_submit()?
        {
            result = Some(
                reputation.advance_selected(
                    &labels,
                    &policies.network.reputation,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::Reputation)?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::Reputation);
        };
        let Some(reputation_finality) = result.finalized else {
            return Ok(ServiceBootstrapProgress::Pending {
                step: ServiceBootstrapStep::Reputation,
                status: result.transaction_status,
            });
        };
        require_after(&reputation_finality, prior_height)?;
        let providers = histories
            .try_into()
            .map_err(|_| invalid("bootstrap provider history count differs"))?;
        let history = HistoricalServiceBootstrap {
            reserve_policy,
            providers,
            reputation: reputation_finality,
        };
        history.ordered_carriers()?;
        Ok(ServiceBootstrapProgress::Complete(history))
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
