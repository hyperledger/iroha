//! Generated provider capacity replacement through the sole owner wallet journal.
//! Original successful inclusion and fresh capacity/pricing facts remain separate.
//! No principal transfer, atomic capacity CAS, admission or service activation is synthesized.

use super::{
    PreparedLocalnet, Result,
    native_operation::{
        MAX_CHECKPOINT_BYTES, ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid,
        now_ms, read_optional, require_deadline, require_empty,
    },
    provider_economics,
    service_authority::{CheckpointImportScope, ProviderPurpose, ServiceAuthority},
};
use crate::{
    localnet::service_authorities::{RetainedProviderServicePlan, StreamTokenAuthorityRole},
    verify::finality::FinalityVerifier,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    sorafs::pricing::ProviderCreditRecord,
    sorafs::reserve::{
        ReserveAuthorityPolicyV1, ReserveProviderAccountV1,
        account_proof::VerifiedReserveAccountStateV1,
    },
    transaction::SignedTransaction,
};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, OperationStatus,
    ProviderCapacityDeclarationSelection,
};
use sorafs_manifest::capacity::CapacityDeclarationV1;
use std::time::Instant;

#[path = "provider_capacity/journal.rs"]
mod journal;
use super::{
    native_operation::{
        Fees,
        attempts::{self, Observation, Purpose, Selected},
    },
    service_bootstrap::authorization::BootstrapChildAuthorization,
};
use journal::Original;

#[cfg(test)]
#[path = "provider_capacity/native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "provider_capacity/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "provider_capacity/transport_tests.rs"]
mod transport_tests;

/// Node observation, original native execution and independently proved current facts.
/// This public report grants no collateral, capacity, admission or service activation authority.
#[derive(Debug)]
pub struct ManagedProviderCapacityProgress {
    /// Replaceable node status, not independently authenticated transaction inclusion.
    pub transaction_status: OperationStatus,
    /// Successful exact original declaration carrier, independent of later row changes.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh selected policy, partition, credit, pricing and capacity facts; None means evidence unavailable.
    pub current: Option<VerifiedReserveAccountStateV1>,
}

// Fixed borrowed parent intent, not a caller eligibility callback or decoded authority.
struct FundingSelection<'a> {
    partition: &'a ReserveProviderAccountV1,
    credit: &'a ProviderCreditRecord,
    minimum_height: u64,
}
impl FundingSelection<'_> {
    fn validate(
        &self,
        partition: &ReserveProviderAccountV1,
        credit: &ProviderCreditRecord,
        capacity_present: bool,
        height: u64,
    ) -> Result<()> {
        if height < self.minimum_height
            || partition != self.partition
            || credit != self.credit
            || capacity_present
        {
            return Err(invalid(
                "capacity original differs from automatic funding selection",
            ));
        }
        Ok(())
    }
}

/// Purpose-closed declaration of the original generated provider plan.
/// The generated provider owner signs and pays fees only. Native execution owns actual backing,
/// allocation checks and replacement semantics; this owner does not activate any service.
pub struct ManagedProviderCapacity {
    authority: ServiceAuthority,
}
impl ManagedProviderCapacity {
    /// Authenticate the original profile/genesis and hold the exclusive capacity purpose.
    /// # Errors
    /// Rejects altered generation, unsafe retained custody or another holder. Performs no HTTP.
    pub fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        let owner = Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::ProviderCapacityDeclaration,
            )?,
        };
        owner.plan()?;
        Ok(owner)
    }

    /// Preserve the plan postcondition while admitting this provider's own purpose lock.
    /// Active decode admission and owned parents retain the full standalone capture recipe.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        let owner = Self {
            authority: ServiceAuthority::open_provider_from_original(
                parent,
                provider,
                ProviderPurpose::ProviderCapacityDeclaration,
            )?,
        };
        owner.plan()?;
        Ok(owner)
    }

    /// Retain the generated declaration against fresh native economic and predecessor facts.
    /// Bootstrap selects policy from its prior owner; users supply no declaration or amount.
    /// Native declaration registration is a replacement, without atomic capacity CAS.
    pub(crate) fn declare(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedProviderCapacityProgress> {
        self.declare_original(policy, deadline_unix_ms, options, None)
    }

    #[cfg(test)]
    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Option<Self>> {
        Self::from_existing_authority(ServiceAuthority::open_provider_existing(
            prepared,
            provider,
            ProviderPurpose::ProviderCapacityDeclaration,
        )?)
    }

    /// Preserve the existing plan postcondition while borrowing the original read-only profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Self::from_existing_authority(ServiceAuthority::open_provider_existing_from_original(
            parent,
            provider,
            ProviderPurpose::ProviderCapacityDeclaration,
            scope,
        )?)
    }

    fn from_existing_authority(authority: Option<ServiceAuthority>) -> Result<Option<Self>> {
        let Some(authority) = authority else {
            return Ok(None);
        };
        let owner = Self { authority };
        owner.plan()?;
        Ok(Some(owner))
    }

    fn declare_original(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
        funding: Option<FundingSelection<'_>>,
    ) -> Result<ManagedProviderCapacityProgress> {
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let directory = self.authority.directory.ensure_child("declare")?;
        let original = self.select_intent(&directory, policy, funding, options.deadline)?;
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open capacity wallet"))?;
        journal::explicit(&directory, &original, utc, options, &account)?;
        self.advance(options.deadline)
    }

    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        policy: &ReserveAuthorityPolicyV1,
        funding: Option<FundingSelection<'_>>,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            self.validate_original(&original)?;
            original.matches_intent(policy)?;
            if let Some(funding) = funding {
                let verifier = self.authority.decode_checkpoint(&original.checkpoint)?;
                funding.validate(
                    &original.partition,
                    &original.credit,
                    original.previous_capacity.is_some(),
                    verifier.checkpoint().height(),
                )?;
            }
            return Ok(original);
        }
        require_empty(directory)?;
        let (verifier, current) = self.observe(policy, deadline)?;
        self.retain_observed_original(policy, &current, &verifier, funding)
    }

    pub(super) fn advance_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        partition: &ReserveProviderAccountV1,
        credit: &ProviderCreditRecord,
        minimum_height: u64,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedProviderCapacityProgress> {
        let purpose = Purpose::FundingCapacity(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        if policy != &authorization.policies().network.reserve {
            return Err(invalid(
                "capacity policy differs from startup authorization",
            ));
        }
        self.validate_policy(policy)?;
        journal::admit_selection_inputs(partition, credit, self.plan()?.declaration())?;
        let funding = FundingSelection {
            partition,
            credit,
            minimum_height,
        };
        let directory = self.authority.directory.ensure_child("declare")?;
        let original = self.select_intent(&directory, policy, Some(funding), deadline)?;
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open capacity wallet"))?;
        let account = authorization.bind_account(account)?;
        attempts::generated(
            &directory,
            purpose,
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
            authorization,
            deadline,
            None,
            |attempt| {
                account
                    .inspect_provider_capacity_declaration_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("capacity attempt differs from exact wallet request"))
            },
            |attempt| {
                account
                    .retire_provider_capacity_declaration_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("capacity unsigned request could not retire"))
            },
            |attempt, _, deadline| {
                account
                    .retain_provider_capacity_declaration_request(
                        &original.request(attempt.terms(), deadline),
                        &attempt.wallet_path(),
                    )
                    .map_err(|_| invalid("cannot retain exact unsigned capacity request"))
            },
            |_, deadline| {
                let (_, current) = self.observe(policy, deadline)?;
                if !matches_predecessor(&current, &original) || current.height() < minimum_height {
                    return Err(invalid("fresh capacity predecessor unavailable"));
                }
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )?;
        authorization.validate(&self.authority, purpose, deadline)?;
        self.advance_original(deadline, Advance::SubmitAuthorized(authorization), false)
    }

    // One owner selects and publishes both generic replacements and the closed funding child.
    // Opaque evidence is produced by the existing reader; retained claim rows cannot call this.
    fn retain_observed_original(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        current: &VerifiedReserveAccountStateV1,
        verifier: &FinalityVerifier,
        funding: Option<FundingSelection<'_>>,
    ) -> Result<Original> {
        let plan = self.plan()?;
        let tip = verifier
            .verified_tip_ref()
            .map_err(|_| invalid("capacity requires selected certified state"))?;
        if current.height() != tip.height()
            || current.context_id() != tip.context_id()
            || current.block_time_ms() != tip.header().creation_time_ms
            || &current.policy().policy != policy
        {
            return Err(invalid(
                "capacity current cut differs from selected checkpoint",
            ));
        }
        let partition = current
            .current()
            .ok_or_else(|| invalid("capacity requires a native reserve partition"))?;
        let credit = current
            .credit()
            .ok_or_else(|| invalid("capacity requires a native credit projection"))?;
        journal::admit(
            policy,
            partition,
            credit,
            plan.declaration(),
            current.pricing(),
            current.capacity(),
        )?;
        if let Some(funding) = funding {
            funding.validate(
                partition,
                credit,
                current.capacity().is_some(),
                current.height(),
            )?;
        }
        let amounts = provider_economics::derive(&plan, current)?;
        if !amounts.top_up.is_zero() {
            return Err(invalid(
                "generated capacity still requires owner-funded reserve",
            ));
        }
        let original = Original {
            selection: self.selection(policy, partition, credit, plan.declaration())?,
            policy: policy.clone(),
            partition: partition.clone(),
            credit: credit.clone(),
            declaration: plan.declaration().clone(),
            pricing: current.pricing().clone(),
            previous_capacity: current.capacity().cloned(),
            observed_block_time_ms: current.block_time_ms(),
            economics: amounts,
            checkpoint: checkpoint_bytes(verifier)?,
        };
        self.validate_original(&original)?;
        let directory = self.authority.directory.ensure_child("declare")?;
        journal::publish_intent(&directory, &original)?;
        Ok(original)
    }

    /// Prepare or dispatch the exact retained capacity declaration at most once, then observe it.
    /// # Errors
    /// Rejects missing/changed originals, changed native preflight or journal/evidence failures.
    /// A fresh I/O deadline never renews the original UTC authorization or signed envelope.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedProviderCapacityProgress> {
        self.advance_original(deadline, Advance::SubmitOriginal, true)
    }

    /// Observe the exact original intent and wallet transaction without preparing or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or invalid retained evidence. This may retain verified
    /// finality progress, but never creates a wallet transaction, quotes fees, signs or sends it.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedProviderCapacityProgress> {
        self.advance_original(deadline, Advance::ObserveOnly, true)
    }

    // Closed parent recovery: authenticate exact retained claims before any HTTP. Missing
    // original is reported only for a genuinely absent or empty child; orphan/corrupt work fails.
    // Successful original carrier recovery skips optional current observation so a peer outage
    // cannot consume the parent deadline before its later original children are recovered.
    pub(super) fn recover_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        partition: &ReserveProviderAccountV1,
        credit: &ProviderCreditRecord,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedProviderCapacityProgress>> {
        self.recover_selected(
            policy,
            partition,
            credit,
            fees,
            deadline,
            Advance::ObserveOnly,
        )
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        partition: &ReserveProviderAccountV1,
        credit: &ProviderCreditRecord,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedProviderCapacityProgress>> {
        self.recover_selected(
            policy,
            partition,
            credit,
            fees,
            deadline,
            Advance::ObserveLocal,
        )
    }
    fn recover_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        partition: &ReserveProviderAccountV1,
        credit: &ProviderCreditRecord,
        fees: &Fees,
        deadline: Instant,
        mode: Advance<'_>,
    ) -> Result<Option<ManagedProviderCapacityProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        journal::admit_selection_inputs(partition, credit, self.plan()?.declaration())?;
        let Some(directory) = self.authority.directory.open_child_optional("declare")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            require_empty(&directory)?;
            return Ok(None);
        };
        self.validate_original(&original)?;
        original.matches_intent(policy)?;
        let history = attempts::History::read(
            &directory,
            Purpose::FundingCapacity(original.selection.provider_id),
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )?;
        history.require_fees(fees)?;
        if original.partition != *partition
            || original.credit != *credit
            || original.previous_capacity.is_some()
        {
            return Err(invalid(
                "capacity original differs from automatic funding selection",
            ));
        }
        self.advance_original(deadline, mode, false).map(Some)
    }

    fn advance_original(
        &mut self,
        deadline: Instant,
        mode: Advance<'_>,
        observe_current: bool,
    ) -> Result<ManagedProviderCapacityProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let operation = self.authority.directory.open_child("declare")?;
        let original = journal::required_original(&operation)?;
        let directory = original.directory();
        self.validate_original(&original)?;
        let path = directory.path().join("transaction");
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open provider capacity declaration wallet"))?;
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                account
                    .inspect_provider_capacity_declaration_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &intent.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("retained capacity attempt history changed"))
            })
        };
        verify_custody()?;
        let preparation = account
            .inspect_provider_capacity_declaration_preparation_in_parent(
                directory,
                std::ffi::OsStr::new("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| invalid("wallet preparation differs from the exact original request"))?;
        let unprepared_expired = preparation.unprepared_status() == Some(OperationStatus::Expired);
        let retained = match preparation.phase() {
            iroha_wallet::operations::NativePreparationPhase::Missing
            | iroha_wallet::operations::NativePreparationPhase::RequestOnly
            | iroha_wallet::operations::NativePreparationPhase::PayloadRetained => None,
            iroha_wallet::operations::NativePreparationPhase::Signed => {
                Some(preparation.into_signed_transaction().map_err(|_| {
                    invalid("retained wallet preparation has no signed transaction")
                })?)
            }
            iroha_wallet::operations::NativePreparationPhase::Retired => {
                return Err(invalid("original wallet request was retired"));
            }
        };
        let needs_prepare = retained.is_none();
        if let Some(transaction) = &retained
            && let Some(finalized) = self.authority.retained_finality(&directory, transaction)?
        {
            self.validate_carrier(&original, &finalized)?;
            let current = if observe_current {
                self.observe(&original.policy, deadline)
                    .ok()
                    .map(|(_, state)| state)
            } else {
                None
            };
            verify_custody()?;
            return Ok(progress(OperationStatus::Applied, Some(finalized), current));
        }
        if matches!(mode, Advance::ObserveLocal) {
            verify_custody()?;
            return Ok(progress(
                if needs_prepare {
                    if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                        OperationStatus::Expired
                    } else {
                        OperationStatus::Absent
                    }
                } else {
                    OperationStatus::Pending
                },
                None,
                None,
            ));
        }
        if needs_prepare
            && (matches!(mode, Advance::ObserveOnly)
                || (now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired))
        {
            // Read-only recovery of an unprepared intent does not perform HTTP or create a child.
            let status =
                if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                    OperationStatus::Expired
                } else {
                    OperationStatus::Absent
                };
            return Ok(progress(status, None, None));
        }
        // Existing signed work remains observable during a current-state/quorum outage.
        let observed = self.authority.observe_finality(deadline).ok();
        let current = observed
            .as_ref()
            .and_then(|verifier| self.read_current(&original.policy, verifier, deadline).ok());
        let predecessor = current
            .as_ref()
            .is_some_and(|state| matches_predecessor(state, &original));
        if needs_prepare {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                return Ok(progress(OperationStatus::Expired, None, current));
            }
            if !predecessor {
                return Err(invalid(
                    "fresh capacity declaration predecessor unavailable; retain original intent",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(
                Purpose::FundingCapacity(original.selection.provider_id),
                deadline,
            )?;
            account
                .prepare_provider_capacity_declaration(
                    &original.request(original.terms.signing_deadline(deadline)?),
                    &path,
                )
                .map_err(|_| {
                    invalid(
                        "provider capacity declaration preparation failed; retain original intent and journal",
                    )
                })?;
        }
        let transaction = match retained {
            Some(transaction) => transaction,
            None => self.verify_wallet(&directory, &original, deadline)?,
        };
        let request = original.request(deadline);
        let mut report = account
            .resume_provider_capacity_declaration(&path, &request)
            .map_err(|_| {
                invalid("provider capacity declaration transaction unresolved; recover its original journal")
            })?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if predecessor {
                verify_custody()?;
                mode.check_dispatch(
                    Purpose::FundingCapacity(original.selection.provider_id),
                    deadline,
                )?;
                report = account
                    .submit_provider_capacity_declaration(&path, &request)
                    .map_err(|_| {
                        invalid(
                            "provider capacity declaration transaction unresolved; recover its original journal",
                        )
                    })?;
            }
        }
        if matches!(mode, Advance::SubmitAuthorized(_)) && report.status == OperationStatus::Expired
        {
            return Err(super::ManagedBootstrapFailure::SignedUnresolved.into());
        }
        // Refresh after possible dispatch. A node status is a replaceable hint for replay only.
        let observed = self.authority.observe_finality(deadline).ok();
        let finalized = if report.status == OperationStatus::Applied {
            if let Some(observed) = &observed {
                self.authority.advance_carrier(
                    &directory,
                    &original.checkpoint,
                    &transaction,
                    &report,
                    observed,
                    deadline,
                )?
            } else {
                None
            }
        } else {
            None
        };
        if let Some(finalized) = &finalized {
            self.validate_carrier(&original, finalized)?;
        }
        let current = super::native_operation::optional_current(
            observe_current,
            observed.as_ref(),
            |verifier| self.read_current(&original.policy, verifier, deadline),
        );
        verify_custody()?;
        Ok(progress(report.status, finalized, current))
    }

    fn plan(&self) -> Result<RetainedProviderServicePlan> {
        self.authority.provider_plan()
    }

    fn validate_policy(&self, policy: &ReserveAuthorityPolicyV1) -> Result<()> {
        encode(policy, provider_economics::MAX_POLICY_BYTES)?;
        policy
            .validate()
            .map_err(|_| invalid("invalid selected capacity reserve policy"))?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated reserve asset"))?;
        let operator = self.authority.network_role(
            crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations,
        )?;
        if policy.asset_definition != asset
            || policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &policy.operations_authority != operator
            || policy.decision_authority != self.authority.config.account
        {
            return Err(invalid(
                "capacity policy differs from original generated roles",
            ));
        }
        Ok(())
    }

    fn selection(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        partition: &ReserveProviderAccountV1,
        credit: &ProviderCreditRecord,
        declaration: &CapacityDeclarationV1,
    ) -> Result<ProviderCapacityDeclarationSelection> {
        self.validate_policy(policy)?;
        journal::admit_selection_inputs(partition, credit, declaration)?;
        Ok(ProviderCapacityDeclarationSelection {
            chain_id: self.authority.config.chain.to_string(),
            network_id: self.authority.config.network_id,
            provider_id: self.authority.provider_id()?,
            provider_account: self
                .authority
                .provider_role(StreamTokenAuthorityRole::IssuerOperator)?
                .clone(),
            declaration_hash: iroha_crypto::HashOf::try_new(declaration)
                .map_err(std::io::Error::other)?,
            credit_hash: iroha_crypto::HashOf::try_new(credit).map_err(std::io::Error::other)?,
            partition_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy
                .digest()
                .map_err(|_| invalid("invalid reserve policy digest"))?,
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            operations_authority: policy.operations_authority.clone(),
            decision_authority: policy.decision_authority.clone(),
        })
    }

    fn validate_original(&self, original: &Original) -> Result<()> {
        original.validate()?;
        self.validate_policy(&original.policy)?;
        let plan = self.plan()?;
        if original.declaration != *plan.declaration()
            || original.partition.terms != *plan.reserve_terms()
            || original.economics
                != provider_economics::derive_retained(
                    &plan,
                    &original.policy,
                    &original.partition,
                    Some(&original.credit),
                    &original.pricing,
                    original.observed_block_time_ms,
                )?
            || encode(&original.selection, journal::MAX_SELECTION_BYTES)?
                != encode(
                    &self.selection(
                        &original.policy,
                        &original.partition,
                        &original.credit,
                        &original.declaration,
                    )?,
                    journal::MAX_SELECTION_BYTES,
                )?
        {
            return Err(invalid(
                "original capacity intent differs from authenticated generation",
            ));
        }
        let checkpoint = self.authority.decode_checkpoint(&original.checkpoint)?;
        let tip = checkpoint
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original capacity checkpoint"))?;
        tip.verify_global_scope(
            self.authority.config.network_id,
            &self.authority.config.chain.to_string(),
        )
        .map_err(|_| invalid("original capacity checkpoint is not selected Global root"))?;
        if tip.header().creation_time_ms != original.observed_block_time_ms {
            return Err(invalid(
                "original capacity economics time differs from its native checkpoint",
            ));
        }
        Ok(())
    }

    fn validate_carrier(
        &self,
        original: &Original,
        finalized: &ManagedTransactionFinality,
    ) -> Result<()> {
        if finalized.height
            <= self
                .authority
                .decode_checkpoint(&original.checkpoint)?
                .checkpoint()
                .height()
        {
            return Err(invalid(
                "provider capacity declaration carrier predates the original intent",
            ));
        }
        Ok(())
    }
    fn verify_wallet(
        &self,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open provider capacity declaration wallet"))?
            .verify_provider_capacity_declaration_journal(
                &directory.path().join("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| {
                invalid(
                    "provider capacity declaration wallet differs from the exact original request",
                )
            })
    }
    fn observe(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedReserveAccountStateV1)> {
        let verifier = self.authority.observe_finality(deadline)?;
        let state = self.read_current(policy, &verifier, deadline)?;
        Ok((verifier, state))
    }
    fn read_current(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        verifier: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedReserveAccountStateV1> {
        self.authority
            .read_reserve_account(policy, verifier, deadline)
    }
}

#[derive(Clone, Copy)]
enum Advance<'a> {
    SubmitOriginal,
    SubmitAuthorized(&'a BootstrapChildAuthorization<'a>),
    ObserveOnly,
    ObserveLocal,
}
impl Advance<'_> {
    fn submits(self) -> bool {
        matches!(self, Self::SubmitOriginal | Self::SubmitAuthorized(_))
    }
    fn bind_account(self, account: AccountService) -> Result<AccountService> {
        match self {
            Self::SubmitAuthorized(authorization) => authorization.bind_account(account),
            _ => Ok(account),
        }
    }
    fn check_dispatch(self, purpose: Purpose, deadline: Instant) -> Result<()> {
        if let Self::SubmitAuthorized(authorization) = self {
            authorization.check(purpose, deadline)?;
        }
        Ok(())
    }
}

fn progress(
    status: OperationStatus,
    finalized: Option<ManagedTransactionFinality>,
    current: Option<VerifiedReserveAccountStateV1>,
) -> ManagedProviderCapacityProgress {
    // A current cut preceding this original carrier cannot report post-declaration facts.
    let current = current.filter(|state| {
        finalized
            .as_ref()
            .is_none_or(|carrier| state.height() >= carrier.height)
    });
    ManagedProviderCapacityProgress {
        transaction_status: status,
        finalized,
        current,
    }
}

// Only called with a fresh independently verified same-cut state. Native capacity writes have
// replacement semantics; this preflight comparison is not an atomic compare-and-set guarantee.
fn matches_predecessor(state: &VerifiedReserveAccountStateV1, original: &Original) -> bool {
    state.current() == Some(&original.partition)
        && state.credit() == Some(&original.credit)
        && state.pricing() == &original.pricing
        && state.capacity() == original.previous_capacity.as_ref()
}

#[cfg(test)]
#[path = "provider_capacity/funding_test_support.rs"]
mod funding_test_support;
