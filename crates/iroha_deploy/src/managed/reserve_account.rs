//! Provider reserve account registration using the sole wallet journal and native evidence.
//!
//! Partition absence is only a collision preflight. Successful execution of the exact original
//! native registration establishes historical completion; fresh provider facts remain separate.
//! This coordinator neither enables services nor funds collateral, credit or provider capacity.

use super::{
    PreparedLocalnet, Result,
    native_operation::{
        ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid, now_ms,
        read_optional, require_deadline, require_empty,
    },
    service_authority::{CheckpointImportScope, ProviderPurpose, ServiceAuthority},
};
use crate::{
    localnet::service_authorities::StreamTokenAuthorityRole, verify::finality::FinalityVerifier,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    sorafs::reserve::{
        ReserveAuthorityPolicyV1, ReserveProviderTermsV1,
        account_proof::VerifiedReserveAccountStateV1,
    },
    transaction::SignedTransaction,
};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, OperationStatus, ReserveAccountRegistrationSelection,
};
use std::time::Instant;

#[path = "reserve_account/journal.rs"]
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
#[path = "reserve_account/native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "reserve_account/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "reserve_account/transport_tests.rs"]
mod transport_tests;

/// Separate wallet observation, exact original execution and fresh provider facts.
///
/// Successful original registration survives later movement, policy rotation and read outages.
/// Registration creates no funded collateral, provider credit, admission or service readiness.
#[derive(Debug)]
pub struct ManagedReserveAccountProgress {
    /// Node status is a replaceable observation, not independent transaction inclusion.
    pub transaction_status: OperationStatus,
    /// Exact independently authenticated successful original registration carrier.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh exact provider and policy facts; absence of evidence is not partition absence.
    pub current: Option<VerifiedReserveAccountStateV1>,
}

/// Purpose-closed registration of the original generated provider's first reserve partition.
///
/// The original shared reserve operator signs and pays for the native registration. The manager
/// context remains the independent finality reader. Any active policy revision with the original
/// generated roles is supported; the selected policy is immutable once the intent is retained.
pub struct ManagedReserveAccountRegistration {
    authority: ServiceAuthority,
}
impl ManagedReserveAccountRegistration {
    /// Authenticate the original service profile/genesis and exclusively hold its reserve intent.
    /// # Errors
    /// Rejects substituted profiles, genesis, committee, private custody, or another coordinator.
    /// This performs no network operation and signs no transaction.
    pub fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::ReserveAccountRegistration,
            )?,
        })
    }

    /// Admit this provider's fixed reserve-registration purpose from immutable original intent.
    /// The child retains its own native lock; active/owned callers keep full capture.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider_from_original(
                parent,
                provider,
                ProviderPurpose::ReserveAccountRegistration,
            )?,
        })
    }

    // The real standalone producer remains the test baseline for physical admission parity.
    #[cfg(test)]
    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_provider_existing(
            prepared,
            provider,
            ProviderPurpose::ReserveAccountRegistration,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    /// Retain fresh purpose custody using the immutable original read-only parent profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_provider_existing_from_original(
            parent,
            provider,
            ProviderPurpose::ReserveAccountRegistration,
            scope,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    /// Retain the selected policy, underwriting and original bounded authorization, then advance.
    /// # Errors
    /// Rejects changed original inputs, unavailable native prerequisites or unsafe wallet custody.
    pub fn register(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedReserveAccountProgress> {
        self.authority.validate_profile()?;
        self.validate_registration(policy, underwriting)?;
        let directory = self.authority.directory.ensure_child("register")?;
        let original = self.select_intent(&directory, policy, underwriting, options.deadline)?;
        let account = AccountService::new(self.authority.reserve_operations_config()?)
            .map_err(|_| invalid("cannot open reserve registration wallet"))?;
        journal::explicit(&directory, &original, utc, options, &account)?;
        self.advance(options.deadline)
    }

    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_intent(policy, underwriting)?;
            self.validate_original(&original)?;
            return Ok(original);
        }
        require_empty(directory)?;
        let (verifier, current) = self.observe(policy, deadline)?;
        if current.current().is_some() {
            return Err(invalid("reserve provider partition already exists"));
        }
        let original = Original {
            selection: self.selection(policy, underwriting)?,
            underwriting: underwriting.clone(),
            policy: policy.clone(),
            checkpoint: checkpoint_bytes(&verifier)?,
        };
        self.validate_original(&original)?;
        journal::publish_intent(directory, &original)?;
        Ok(original)
    }

    pub(super) fn advance_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedReserveAccountProgress> {
        let purpose = Purpose::ReserveAccount(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        if policy != &authorization.policies().network.reserve
            || underwriting != self.authority.provider_plan()?.reserve_terms()
        {
            return Err(invalid(
                "reserve registration differs from authorized policy or underwriting",
            ));
        }
        self.validate_registration(policy, underwriting)?;
        let directory = self.authority.directory.ensure_child("register")?;
        let original = self.select_intent(&directory, policy, underwriting, deadline)?;
        let account = AccountService::new(self.authority.reserve_operations_config()?)
            .map_err(|_| invalid("cannot open reserve registration wallet"))?;
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
                    .inspect_reserve_account_registration_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| {
                        invalid("reserve registration attempt differs from its exact request")
                    })
            },
            |attempt| {
                account
                    .retire_reserve_account_registration_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("reserve registration unsigned request could not retire"))
            },
            |attempt, _, deadline| {
                account
                    .retain_reserve_account_registration_request(
                        &original.request(attempt.terms(), deadline),
                        &attempt.wallet_path(),
                    )
                    .map_err(|_| invalid("cannot retain exact unsigned reserve registration"))
            },
            |_, deadline| {
                let (_, current) = self.observe(policy, deadline)?;
                if current.current().is_some() {
                    return Err(invalid("reserve provider partition already exists"));
                }
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )?;
        authorization.validate(&self.authority, purpose, deadline)?;
        self.advance_original(deadline, Advance::SubmitAuthorized(authorization), false)
    }

    /// Prepare or dispatch the exact retained registration at most once, then observe it.
    /// # Errors
    /// Rejects missing/changed originals, changed native preflight or journal/evidence failures.
    /// A fresh I/O deadline never renews the original UTC authorization or signed envelope.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedReserveAccountProgress> {
        self.advance_original(deadline, Advance::SubmitOriginal, true)
    }

    /// Observe the exact original intent and wallet transaction without preparing or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or invalid retained evidence. This may retain verified
    /// finality progress, but never creates a wallet transaction, quotes fees, signs or sends it.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedReserveAccountProgress> {
        self.advance_original(deadline, Advance::ObserveOnly, true)
    }

    /// Recover exact semantic selection and full original fee constraints without new signing.
    pub(super) fn recover_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReserveAccountProgress>> {
        self.recover_selected(policy, underwriting, fees, deadline, Advance::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReserveAccountProgress>> {
        self.recover_selected(policy, underwriting, fees, deadline, Advance::ObserveLocal)
    }
    fn recover_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        fees: &Fees,
        deadline: Instant,
        mode: Advance<'_>,
    ) -> Result<Option<ManagedReserveAccountProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_registration(policy, underwriting)?;
        let Some(directory) = self.authority.directory.open_child_optional("register")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            return Ok(None);
        };
        self.validate_original(&original)?;
        original.matches_intent(policy, underwriting)?;
        let history = attempts::History::read(
            &directory,
            Purpose::ReserveAccount(self.authority.provider_id()?),
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )?;
        history.require_fees(fees)?;
        self.advance_original(deadline, mode, false).map(Some)
    }

    fn advance_original(
        &mut self,
        deadline: Instant,
        mode: Advance<'_>,
        observe_current: bool,
    ) -> Result<ManagedReserveAccountProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let operation = self.authority.directory.open_child("register")?;
        let original = journal::required_original(&operation)?;
        self.validate_original(&original)?;
        let directory = original.directory();
        let path = directory.path().join("transaction");
        let account = AccountService::new(self.authority.reserve_operations_config()?)
            .map_err(|_| invalid("cannot open reserve registration wallet"))?;
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                account
                    .inspect_reserve_account_registration_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &intent.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("reserve registration retained attempt history changed"))
            })
        };
        verify_custody()?;
        let preparation = account
            .inspect_reserve_account_registration_preparation_in_parent(
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
            let current = observe_current
                .then(|| self.observe(&original.policy, deadline).ok())
                .flatten()
                .map(|(_, state)| state);
            verify_custody()?;
            return Ok(progress(OperationStatus::Applied, Some(finalized), current));
        }
        if matches!(mode, Advance::ObserveLocal) {
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
        let absent = current
            .as_ref()
            .is_some_and(|state| state.current().is_none());
        if needs_prepare {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                return Ok(progress(OperationStatus::Expired, None, current));
            }
            if !absent {
                return Err(invalid(
                    "fresh reserve provider absence unavailable; retain original intent",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(
                Purpose::ReserveAccount(self.authority.provider_id()?),
                deadline,
            )?;
            account
                .prepare_reserve_account_registration(
                    &original.request(original.terms.signing_deadline(deadline)?),
                    &path,
                )
                .map_err(|_| {
                    invalid("reserve preparation failed; retain original intent and journal")
                })?;
        }
        verify_custody()?;
        let transaction = match retained {
            Some(transaction) => transaction,
            None => self.verify_wallet(&directory, &original, deadline)?,
        };
        let request = original.request(deadline);
        let mut report = account
            .resume_reserve_account_registration(&path, &request)
            .map_err(|_| invalid("reserve transaction unresolved; recover its original journal"))?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if absent {
                verify_custody()?;
                mode.check_dispatch(
                    Purpose::ReserveAccount(self.authority.provider_id()?),
                    deadline,
                )?;
                report = account
                    .submit_reserve_account_registration(&path, &request)
                    .map_err(|_| {
                        invalid("reserve transaction unresolved; recover its original journal")
                    })?;
            }
        }
        if matches!(mode, Advance::SubmitAuthorized(_)) && report.status == OperationStatus::Expired
        {
            return Err(super::ManagedBootstrapFailure::SignedUnresolved.into());
        }
        verify_custody()?;
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

    fn validate_registration(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
    ) -> Result<()> {
        encode(policy, journal::MAX_POLICY_BYTES)?;
        encode(underwriting, journal::MAX_UNDERWRITING_BYTES)?;
        policy
            .validate()
            .map_err(|_| invalid("invalid selected reserve policy"))?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated reserve asset"))?;
        let owner = self
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)?;
        if policy.asset_definition != asset
            || policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &policy.operations_authority != self.authority.network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)?
            || policy.decision_authority != self.authority.config.account
            || underwriting.provider_id != self.authority.provider_id()?
            || &underwriting.provider_account != owner
        {
            return Err(invalid(
                "reserve registration differs from original generated provider or roles",
            ));
        }
        policy
            .economics
            .quote(
                underwriting.storage_class,
                underwriting.capacity_gib,
                underwriting.duration,
                underwriting.tier,
                sorafs_manifest::deal::XorQuantity::zero(),
            )
            .map_err(|_| invalid("invalid original reserve underwriting"))?;
        Ok(())
    }

    fn selection(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
    ) -> Result<ReserveAccountRegistrationSelection> {
        self.validate_registration(policy, underwriting)?;
        Ok(ReserveAccountRegistrationSelection {
            chain_id: self.authority.config.chain.to_string(),
            network_id: self.authority.config.network_id,
            operations_authority: policy.operations_authority.clone(),
            provider_id: underwriting.provider_id,
            provider_account: underwriting.provider_account.clone(),
            policy_digest: policy
                .digest()
                .map_err(|_| invalid("invalid reserve policy digest"))?,
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            decision_authority: policy.decision_authority.clone(),
        })
    }

    fn validate_original(&self, original: &Original) -> Result<()> {
        original.validate()?;
        self.validate_registration(&original.policy, &original.underwriting)?;
        if encode(&original.selection, journal::MAX_SELECTION_BYTES)?
            != encode(
                &self.selection(&original.policy, &original.underwriting)?,
                journal::MAX_SELECTION_BYTES,
            )?
        {
            return Err(invalid(
                "original reserve registration differs from authenticated generation",
            ));
        }
        self.authority
            .decode_checkpoint(&original.checkpoint)?
            .verified_tip()
            .map_err(|_| invalid("invalid original reserve registration checkpoint"))?
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("original reserve checkpoint is not the selected Global root"))?;
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
            return Err(invalid("reserve carrier predates the original intent"));
        }
        Ok(())
    }
    fn verify_wallet(
        &self,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        AccountService::new(self.authority.reserve_operations_config()?)
            .map_err(|_| invalid("cannot open reserve registration wallet"))?
            .verify_reserve_account_registration_journal(
                &directory.path().join("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| invalid("reserve wallet differs from the exact original request"))
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
    ObserveLocal,
    SubmitOriginal,
    SubmitAuthorized(&'a BootstrapChildAuthorization<'a>),
    ObserveOnly,
}
impl Advance<'_> {
    fn bind_account(self, account: AccountService) -> Result<AccountService> {
        match self {
            Self::SubmitAuthorized(authorization) => authorization.bind_account(account),
            _ => Ok(account),
        }
    }

    fn submits(self) -> bool {
        matches!(self, Self::SubmitOriginal | Self::SubmitAuthorized(_))
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
) -> ManagedReserveAccountProgress {
    ManagedReserveAccountProgress {
        transaction_status: status,
        finalized,
        current,
    }
}

#[cfg(test)]
#[path = "reserve_account/bootstrap_test_support.rs"]
mod bootstrap_test_support;
