//! Initial generated provider credit through the sole wallet journal and native absence CAS.
//! Policy/partition observations remain separate from exact original successful execution.
//! No borrowing, principal transfer, capacity, admission or service activation is synthesized.

use super::{
    PreparedLocalnet, Result,
    native_operation::{
        MAX_CHECKPOINT_BYTES, ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid,
        now_ms, read_optional, require_deadline, require_empty,
    },
    service_authority::{CheckpointImportScope, ProviderPurpose, ServiceAuthority},
};
use crate::{
    localnet::service_authorities::StreamTokenAuthorityRole, verify::finality::FinalityVerifier,
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
    AccountService, BoundedTransactionOptions, OperationStatus, ProviderCreditUpsertSelection,
};
use std::time::Instant;

#[path = "provider_credit/journal.rs"]
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
#[path = "provider_credit/native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "provider_credit/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "provider_credit/transport_tests.rs"]
mod transport_tests;

/// Complete selected claims for installing the generated provider's first credit projection.
/// Native Upsert compares only credit absence; policy/partition selections are not native CAS.
#[derive(Clone, Debug)]
pub struct ManagedInitialProviderCreditIntent {
    /// Exact selected active reserve policy, including all original generated roles.
    pub policy: ReserveAuthorityPolicyV1,
    /// Exact selected partition, including its possibly lagging policy digest.
    pub partition: ReserveProviderAccountV1,
    /// Complete desired record; no amount, epoch or pricing field is silently synthesized.
    pub record: ProviderCreditRecord,
}

/// Node observation, original native execution and independently proved current facts.
/// This public report grants no collateral, capacity, admission or service activation authority.
#[derive(Debug)]
pub struct ManagedInitialProviderCreditProgress {
    /// Replaceable node status, not independently authenticated transaction inclusion.
    pub transaction_status: OperationStatus,
    /// Successful exact original initial Upsert carrier, independent of later row changes.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh selected policy, partition and credit facts; None means evidence unavailable.
    pub current: Option<VerifiedReserveAccountStateV1>,
}

/// Purpose-closed initial credit projection for the original generated provider.
/// The generated manager signs and pays fees only. Native execution owns actual permission,
/// aggregate backing and atomic credit absence. A collision never becomes a replacement upsert.
pub struct ManagedInitialProviderCredit {
    authority: ServiceAuthority,
}
impl ManagedInitialProviderCredit {
    /// Authenticate the original profile/genesis and hold the exclusive initial-credit purpose.
    /// # Errors
    /// Rejects altered generation, unsafe retained custody or another holder. Performs no HTTP.
    pub fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::InitialProviderCredit,
            )?,
        })
    }

    /// Borrow the immutable original profile while admitting this provider's own purpose lock.
    /// Active decode admission and owned parents retain the full standalone capture recipe.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider_from_original(
                parent,
                provider,
                ProviderPurpose::InitialProviderCredit,
            )?,
        })
    }

    /// Retain one exact initial projection after fresh native absence/predecessor proof.
    /// # Errors
    /// Refuses changed intent, roles, fees or UTC terms, unavailable proof, or existing credit.
    /// The preflight is informational; the original native None guard owns atomic absence.
    pub fn install(
        &mut self,
        intent: &ManagedInitialProviderCreditIntent,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedInitialProviderCreditProgress> {
        self.authority.validate_profile()?;
        self.validate_intent(intent)?;
        let directory = self.authority.directory.ensure_child("install")?;
        let original = self.select_intent(&directory, intent, options.deadline)?;
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open funding wallet"))?;
        journal::explicit(&directory, &original, deadline_unix_ms, options, &account)?;
        self.advance(options.deadline)
    }

    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        intent: &ManagedInitialProviderCreditIntent,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_intent(intent)?;
            self.validate_original(&original)?;
            return Ok(original);
        }
        require_empty(&directory)?;
        let (verifier, current) = self.observe(&intent.policy, deadline)?;
        if !matches_predecessor(current.current(), current.credit(), &intent.partition) {
            return Err(invalid(
                "fresh initial credit predecessor differs or credit already exists",
            ));
        }
        let original = Original {
            selection: self.selection(intent)?,
            policy: intent.policy.clone(),
            partition: intent.partition.clone(),
            record: intent.record.clone(),
            checkpoint: checkpoint_bytes(&verifier)?,
        };
        self.validate_original(&original)?;
        journal::publish_intent(directory, &original)?;
        Ok(original)
    }

    #[cfg(test)]
    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_provider_existing(
            prepared,
            provider,
            ProviderPurpose::InitialProviderCredit,
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
            ProviderPurpose::InitialProviderCredit,
            scope,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    pub(super) fn advance_selected(
        &mut self,
        intent: &ManagedInitialProviderCreditIntent,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedInitialProviderCreditProgress> {
        let purpose = Purpose::FundingCredit(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        if intent.policy != authorization.policies().network.reserve {
            return Err(invalid("funding policy differs from startup authorization"));
        }
        self.validate_intent(intent)?;
        let directory = self.authority.directory.ensure_child("install")?;
        let original = self.select_intent(&directory, intent, deadline)?;
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open funding wallet"))?;
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
                    .inspect_provider_credit_upsert_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("funding attempt differs from exact wallet request"))
            },
            |attempt| {
                account
                    .retire_provider_credit_upsert_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("funding unsigned request could not retire"))
            },
            |attempt, _, deadline| {
                account
                    .retain_provider_credit_upsert_request(
                        &original.request(attempt.terms(), deadline),
                        &attempt.wallet_path(),
                    )
                    .map_err(|_| invalid("cannot retain exact unsigned funding request"))
            },
            |_, deadline| {
                let (_, current) = self.observe(&intent.policy, deadline)?;
                if !matches_predecessor(current.current(), current.credit(), &original.partition) {
                    return Err(invalid("fresh exact funding predecessor unavailable"));
                }
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )?;
        authorization.validate(&self.authority, purpose, deadline)?;
        self.advance_original(deadline, Advance::SubmitAuthorized(authorization), false)
    }

    /// Prepare or dispatch the exact retained initial credit at most once, then observe it.
    /// # Errors
    /// Rejects missing/changed originals, changed native preflight or journal/evidence failures.
    /// A fresh I/O deadline never renews the original UTC authorization or signed envelope.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedInitialProviderCreditProgress> {
        self.advance_original(deadline, Advance::SubmitOriginal, true)
    }

    /// Observe the exact original intent and wallet transaction without preparing or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or invalid retained evidence. This may retain verified
    /// finality progress, but never creates a wallet transaction, quotes fees, signs or sends it.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedInitialProviderCreditProgress> {
        self.advance_original(deadline, Advance::ObserveOnly, true)
    }

    // Closed parent recovery: authenticate exact retained claims before any HTTP. Missing
    // original is reported only for a genuinely absent or empty child; orphan/corrupt work fails.
    // Successful original carrier recovery skips optional current observation so a peer outage
    // cannot consume the parent deadline before its later original children are recovered.
    pub(super) fn recover_selected_if_present(
        &mut self,
        intent: &ManagedInitialProviderCreditIntent,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialProviderCreditProgress>> {
        self.recover_selected(intent, fees, deadline, Advance::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        intent: &ManagedInitialProviderCreditIntent,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialProviderCreditProgress>> {
        self.recover_selected(intent, fees, deadline, Advance::ObserveLocal)
    }
    fn recover_selected(
        &mut self,
        intent: &ManagedInitialProviderCreditIntent,
        fees: &Fees,
        deadline: Instant,
        mode: Advance<'_>,
    ) -> Result<Option<ManagedInitialProviderCreditProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_intent(intent)?;
        let Some(directory) = self.authority.directory.open_child_optional("install")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            require_empty(&directory)?;
            return Ok(None);
        };
        self.validate_original(&original)?;
        original.matches_intent(intent)?;
        let attempts = attempts::History::read(
            &directory,
            Purpose::FundingCredit(original.selection.provider_id),
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )?;
        attempts.require_fees(fees)?;
        self.advance_original(deadline, mode, false).map(Some)
    }

    fn advance_original(
        &mut self,
        deadline: Instant,
        mode: Advance<'_>,
        observe_current: bool,
    ) -> Result<ManagedInitialProviderCreditProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let operation = self.authority.directory.open_child("install")?;
        let original = journal::required_original(&operation)?;
        let directory = original.directory();
        self.validate_original(&original)?;
        let path = directory.path().join("transaction");
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open initial provider credit wallet"))?;
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                account
                    .inspect_provider_credit_upsert_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &intent.request(attempt.terms(), deadline),
                    )
                    .map_err(|_error| {
                        #[cfg(test)]
                        {
                            use std::io::Write as _;
                            let mut output = std::io::stderr().lock();
                            for (index, cause) in _error.chain().enumerate() {
                                let _ = writeln!(
                                    output,
                                    "retained funding wallet inspection: purpose=FundingCredit; cause[{index}]={cause}",
                                );
                            }
                        }
                        invalid("retained funding attempt history changed")
                    })
            })
        };
        verify_custody()?;
        let preparation = account
            .inspect_provider_credit_upsert_preparation_in_parent(
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
        let predecessor = current.as_ref().is_some_and(|state| {
            matches_predecessor(state.current(), state.credit(), &original.partition)
        });
        if needs_prepare {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                return Ok(progress(OperationStatus::Expired, None, current));
            }
            if !predecessor {
                return Err(invalid(
                    "fresh initial credit absence/predecessor unavailable; retain original intent",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(
                Purpose::FundingCredit(original.selection.provider_id),
                deadline,
            )?;
            account
                .prepare_provider_credit_upsert(
                    &original.request(original.terms.signing_deadline(deadline)?),
                    &path,
                )
                .map_err(|_| {
                    invalid(
                        "provider credit preparation failed; retain original intent and journal",
                    )
                })?;
        }
        let transaction = match retained {
            Some(transaction) => transaction,
            None => self.verify_wallet(&directory, &original, deadline)?,
        };
        let request = original.request(deadline);
        let mut report = account
            .resume_provider_credit_upsert(&path, &request)
            .map_err(|_| {
                invalid("provider credit transaction unresolved; recover its original journal")
            })?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if predecessor {
                verify_custody()?;
                mode.check_dispatch(
                    Purpose::FundingCredit(original.selection.provider_id),
                    deadline,
                )?;
                report = account
                    .submit_provider_credit_upsert(&path, &request)
                    .map_err(|_| {
                        invalid(
                            "provider credit transaction unresolved; recover its original journal",
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

    fn validate_intent(&self, intent: &ManagedInitialProviderCreditIntent) -> Result<()> {
        journal::validate_intent(&intent.policy, &intent.partition, &intent.record)?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated reserve asset"))?;
        let operator = self
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)?;
        if intent.policy.asset_definition != asset
            || intent.policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || intent.policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &intent.policy.operations_authority != self.authority.network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)?
            || intent.policy.decision_authority != self.authority.config.account
            || intent.partition.terms.provider_id != self.authority.provider_id()?
            || &intent.partition.terms.provider_account != operator
        {
            return Err(invalid(
                "initial credit differs from original generated provider or roles",
            ));
        }
        Ok(())
    }

    fn selection(
        &self,
        intent: &ManagedInitialProviderCreditIntent,
    ) -> Result<ProviderCreditUpsertSelection> {
        self.validate_intent(intent)?;
        let policy = &intent.policy;
        let partition = &intent.partition;
        Ok(ProviderCreditUpsertSelection {
            chain_id: self.authority.config.chain.to_string(),
            network_id: self.authority.config.network_id,
            credit_authority: self.authority.config.account.clone(),
            provider_id: self.authority.provider_id()?,
            provider_account: partition.terms.provider_account.clone(),
            expected_current: None,
            desired_record_hash: iroha_crypto::HashOf::try_new(&intent.record)
                .map_err(std::io::Error::other)?,
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
        let intent = original.intent();
        self.validate_intent(&intent)?;
        if encode(&original.selection, journal::MAX_SELECTION_BYTES)?
            != encode(&self.selection(&intent)?, journal::MAX_SELECTION_BYTES)?
        {
            return Err(invalid(
                "original initial provider credit differs from authenticated generation",
            ));
        }
        self.authority
            .decode_checkpoint(&original.checkpoint)?
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original initial provider credit checkpoint"))?
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| {
                invalid("original initial credit checkpoint is not the selected Global root")
            })?;
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
                "provider credit carrier predates the original intent",
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
        AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open initial provider credit wallet"))?
            .verify_provider_credit_upsert_journal(
                &directory.path().join("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| invalid("provider credit wallet differs from the exact original request"))
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
) -> ManagedInitialProviderCreditProgress {
    // A current cut preceding this original carrier cannot report post-installation facts.
    let current = current.filter(|state| {
        finalized
            .as_ref()
            .is_none_or(|carrier| state.height() >= carrier.height)
    });
    ManagedInitialProviderCreditProgress {
        transaction_status: status,
        finalized,
        current,
    }
}

// This comparison only operates after the shared reader authenticates one fresh Global cut.
// Exposing selected claims to a unit test does not manufacture a verified state owner.
fn matches_predecessor(
    partition: Option<&ReserveProviderAccountV1>,
    credit: Option<&ProviderCreditRecord>,
    selected: &ReserveProviderAccountV1,
) -> bool {
    partition == Some(selected) && credit.is_none()
}

#[cfg(test)]
#[path = "provider_credit/funding_test_support.rs"]
mod funding_test_support;
