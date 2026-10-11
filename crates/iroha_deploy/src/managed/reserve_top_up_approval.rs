//! Managed approval of a proven original provider TopUp, using the sole decision wallet journal.
//!
//! Every call requires the original private request evidence again. Journal fields are retained
//! claims, never an alternate decoder or constructor for that evidence. Native Decide owns Pending
//! status and the atomic provider-to-custody transfer; current funding remains a separate fact.

use super::{
    ManagedHistoricalReserveTopUp, PreparedLocalnet, Result,
    native_operation::{
        MAX_CHECKPOINT_BYTES, ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid,
        now_ms, read_optional, require_deadline, require_empty, verify_carrier,
    },
    service_authority::{CheckpointImportScope, ProviderPurpose, ServiceAuthority},
};
use crate::{
    localnet::service_authorities::StreamTokenAuthorityRole, verify::finality::FinalityVerifier,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::sorafs::DecideSorafsReserveMovement,
    sorafs::reserve::{
        RESERVE_MAX_REASON_BYTES_V1, ReserveAuthorityPolicyV1, ReserveProviderAccountV1,
        account_proof::VerifiedReserveAccountStateV1, history::validate_provider_record,
    },
    transaction::{Executable, SignedTransaction},
};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, OperationStatus, ReserveMovementDecisionSelection,
};
use sorafs_manifest::deal::XorQuantity;
use std::time::Instant;

#[path = "reserve_top_up_approval/journal.rs"]
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
#[path = "reserve_top_up_approval/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "reserve_top_up_approval/tests.rs"]
mod tests;

/// Immutable selected policy, exact provider predecessor and manager explanation.
/// These are caller claims until the current native account proof independently verifies them.
#[derive(Clone, Debug)]
pub struct ManagedReserveTopUpApprovalIntent {
    /// Complete selected active policy; it may have rotated since the original TopUp request.
    pub policy: ReserveAuthorityPolicyV1,
    /// Complete current predecessor partition, including its possibly lagged policy digest.
    pub partition: ReserveProviderAccountV1,
    /// Independently requested current provider CAS, not the original request's CAS.
    pub expected_provider_revision: u64,
    /// Exact nonempty bounded explanation included in the signed decision.
    pub rationale: String,
}

/// Historical native approval of one authenticated original TopUp request.
///
/// Private construction joins both exact original envelopes to independently certified successful
/// execution. It proves the native approval and its historical transfer, never current reserve
/// balance, credit, service activation or a reusable permission to transfer funds.
#[derive(Clone, Debug)]
pub struct ManagedHistoricalReserveTopUpApproval {
    original: ManagedTransactionFinality,
    request: ManagedHistoricalReserveTopUp,
    requested_provider_revision: u64,
    policy_digest: [u8; 32],
    rationale: String,
}
impl ManagedHistoricalReserveTopUpApproval {
    /// Exact successful original decision carrier.
    #[must_use]
    pub fn original(&self) -> &ManagedTransactionFinality {
        &self.original
    }
    /// Independently authenticated original TopUp whose unique movement id was decided.
    #[must_use]
    pub fn request(&self) -> &ManagedHistoricalReserveTopUp {
        &self.request
    }
    /// CAS consumed by the decision, not a current provider revision.
    #[must_use]
    pub fn requested_provider_revision(&self) -> u64 {
        self.requested_provider_revision
    }
    /// Active policy digest selected by the original decision.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    /// Exact original signed approval rationale.
    #[must_use]
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// Replaceable node observation, private historical approval and separate current account facts.
#[derive(Debug)]
pub struct ManagedReserveTopUpApprovalProgress {
    /// Node status alone cannot establish successful native approval.
    pub transaction_status: OperationStatus,
    /// Public reporting of certified inclusion; replacing it cannot mint historical authority.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh selected account facts; None means unavailable, not unfunded or absent.
    pub current: Option<VerifiedReserveAccountStateV1>,
    historical: Option<ManagedHistoricalReserveTopUpApproval>,
}
impl ManagedReserveTopUpApprovalProgress {
    /// Exact historical native approval, independently bound to the original request.
    #[must_use]
    pub fn historical(&self) -> Option<&ManagedHistoricalReserveTopUpApproval> {
        self.historical.as_ref()
    }
}

/// Closed manager approval owner for the generated provider's proven original TopUp.
///
/// The manager signs and pays decision fees. Native execution alone resolves the Pending movement,
/// transfers provider principal and updates the reserve ledger atomically. Every call requires the
/// authentic request capability recovered through its original request owner.
pub struct ManagedReserveTopUpApproval {
    authority: ServiceAuthority,
}
impl ManagedReserveTopUpApproval {
    /// Authenticate the original generation and hold its exclusive approval journal lock.
    /// # Errors
    /// Refuses altered profiles, unsafe custody or another holder of the same purpose lock.
    pub fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::ReserveTopUpApproval,
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
                ProviderPurpose::ReserveTopUpApproval,
            )?,
        })
    }

    /// Retain one exact approval after fresh predecessor proof, then advance once-only work.
    /// # Errors
    /// Refuses substituted history, original intent/UTC/fees, stale predecessors or custody faults.
    pub fn approve(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedReserveTopUpApprovalProgress> {
        self.authority.validate_profile()?;
        self.validate_history(history)?;
        self.validate_intent(history, intent)?;
        let directory = self.authority.directory.ensure_child("approval")?;
        let original = self.select_intent(&directory, history, intent, options.deadline)?;
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open funding wallet"))?;
        journal::explicit(&directory, &original, deadline_unix_ms, options, &account)?;
        self.advance(history, options.deadline)
    }

    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_intent(intent)?;
            self.validate_original(history, &original)?;
            return Ok(original);
        }
        require_empty(&directory)?;
        let (verifier, current) = self.observe(&intent.policy, deadline)?;
        if current.height() < history.original().height
            || current.current() != Some(&intent.partition)
        {
            return Err(invalid(
                "fresh reserve approval predecessor differs or predates original request",
            ));
        }
        let original = Original {
            history: journal::HistoryClaim::from_history(history)?,
            selection: self.selection(history, intent)?,
            policy: intent.policy.clone(),
            partition: intent.partition.clone(),
            rationale: intent.rationale.clone(),
            checkpoint: checkpoint_bytes(&verifier)?,
        };
        self.validate_original(history, &original)?;
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
            ProviderPurpose::ReserveTopUpApproval,
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
            ProviderPurpose::ReserveTopUpApproval,
            scope,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    pub(super) fn advance_selected(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedReserveTopUpApprovalProgress> {
        let purpose = Purpose::FundingApproval(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        if intent.policy != authorization.policies().network.reserve {
            return Err(invalid("funding policy differs from startup authorization"));
        }
        self.validate_history(history)?;
        self.validate_intent(history, intent)?;
        let directory = self.authority.directory.ensure_child("approval")?;
        let original = self.select_intent(&directory, history, intent, deadline)?;
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
                    .inspect_reserve_movement_decision_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("funding attempt differs from exact wallet request"))
            },
            |attempt| {
                account
                    .retire_reserve_movement_decision_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("funding unsigned request could not retire"))
            },
            |attempt, _, deadline| {
                account
                    .retain_reserve_movement_decision_request(
                        &original.request(attempt.terms(), deadline),
                        &attempt.wallet_path(),
                    )
                    .map_err(|_| invalid("cannot retain exact unsigned funding request"))
            },
            |_, deadline| {
                let (_, current) = self.observe(&intent.policy, deadline)?;
                if !original.matches_current(&current) {
                    return Err(invalid("fresh exact funding predecessor unavailable"));
                }
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )?;
        authorization.validate(&self.authority, purpose, deadline)?;
        self.advance_original(
            history,
            deadline,
            Advance::SubmitAuthorized(authorization),
            false,
        )
    }

    /// Prepare or submit only the retained exact decision, then authenticate its outcome.
    /// # Errors
    /// Refuses missing/changed history, original terms, stale preflight or unsafe custody.
    /// A new I/O deadline never renews original authorization or creates a replacement envelope.
    pub fn advance(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        deadline: Instant,
    ) -> Result<ManagedReserveTopUpApprovalProgress> {
        self.advance_original(history, deadline, Advance::SubmitOriginal, true)
    }
    /// Recover original work without preparing, quoting, signing or dispatching a transaction.
    /// # Errors
    /// Refuses substituted history or invalid journals. Unprepared recovery performs no HTTP.
    pub fn recover(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        deadline: Instant,
    ) -> Result<ManagedReserveTopUpApprovalProgress> {
        self.advance_original(history, deadline, Advance::ObserveOnly, true)
    }
    // Closed parent recovery: authenticate exact retained claims before any HTTP. Missing
    // original is reported only for a genuinely absent or empty child; orphan/corrupt work fails.
    // Successful original carrier recovery skips optional current observation so a peer outage
    // cannot consume the parent deadline before its later original children are recovered.
    pub(super) fn recover_selected_if_present(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReserveTopUpApprovalProgress>> {
        self.recover_selected(history, intent, fees, deadline, Advance::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReserveTopUpApprovalProgress>> {
        self.recover_selected(history, intent, fees, deadline, Advance::ObserveLocal)
    }
    fn recover_selected(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
        fees: &Fees,
        deadline: Instant,
        mode: Advance<'_>,
    ) -> Result<Option<ManagedReserveTopUpApprovalProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_history(history)?;
        self.validate_intent(history, intent)?;
        let Some(directory) = self.authority.directory.open_child_optional("approval")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            require_empty(&directory)?;
            return Ok(None);
        };
        self.validate_original(history, &original)?;
        original.matches_intent(intent)?;
        let attempts = attempts::History::read(
            &directory,
            Purpose::FundingApproval(original.selection.provider_id),
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )?;
        attempts.require_fees(fees)?;
        self.advance_original(history, deadline, mode, false)
            .map(Some)
    }

    fn advance_original(
        &mut self,
        history: &ManagedHistoricalReserveTopUp,
        deadline: Instant,
        mode: Advance<'_>,
        observe_current: bool,
    ) -> Result<ManagedReserveTopUpApprovalProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_history(history)?;
        let operation = self.authority.directory.open_child("approval")?;
        let original = journal::required_original(&operation)?;
        let directory = original.directory();
        self.validate_original(history, &original)?;
        let path = directory.path().join("transaction");
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open reserve top-up approval wallet"))?;
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                account
                    .inspect_reserve_movement_decision_preparation_in_parent(
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
                                    "retained funding wallet inspection: purpose=FundingApproval; cause[{index}]={cause}",
                                );
                            }
                        }
                        invalid("retained funding attempt history changed")
                    })
            })
        };
        verify_custody()?;
        let preparation = account
            .inspect_reserve_movement_decision_preparation_in_parent(
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
            && let Some(historical) =
                self.retained_historical(history, &directory, &original, transaction)?
        {
            let current = if observe_current {
                self.observe(&original.policy, deadline)
                    .ok()
                    .map(|(_, state)| state)
            } else {
                None
            };
            verify_custody()?;
            return Ok(progress(
                OperationStatus::Applied,
                Some(historical),
                current,
            ));
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
        let predecessor_matches = current
            .as_ref()
            .is_some_and(|state| original.matches_current(state));
        if needs_prepare {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                return Ok(progress(OperationStatus::Expired, None, current));
            }
            if !predecessor_matches {
                return Err(invalid(
                    "fresh exact reserve predecessor unavailable; retain original top-up approval intent",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(
                Purpose::FundingApproval(original.selection.provider_id),
                deadline,
            )?;
            account
                .prepare_reserve_movement_decision(
                    &original.request(original.terms.signing_deadline(deadline)?),
                    &path,
                )
                .map_err(|_| {
                    invalid("reserve preparation failed; retain original intent and journal")
                })?;
        }
        let transaction = match retained {
            Some(transaction) => transaction,
            None => self.verify_wallet(&directory, &original, deadline)?,
        };
        let request = original.request(deadline);
        let mut report = account
            .resume_reserve_movement_decision(&path, &request)
            .map_err(|_| invalid("reserve transaction unresolved; recover its original journal"))?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if predecessor_matches {
                verify_custody()?;
                mode.check_dispatch(
                    Purpose::FundingApproval(original.selection.provider_id),
                    deadline,
                )?;
                report = account
                    .submit_reserve_movement_decision(&path, &request)
                    .map_err(|_| {
                        invalid("reserve transaction unresolved; recover its original journal")
                    })?;
            }
        }
        if matches!(mode, Advance::SubmitAuthorized(_)) && report.status == OperationStatus::Expired
        {
            return Err(super::ManagedBootstrapFailure::SignedUnresolved.into());
        }
        // Refresh after possible dispatch. A node status is a replaceable hint for replay only.
        let observed = self.authority.observe_finality(deadline).ok();
        if report.status == OperationStatus::Applied
            && let Some(observed) = &observed
        {
            self.authority.advance_carrier(
                &directory,
                &original.checkpoint,
                &transaction,
                &report,
                observed,
                deadline,
            )?;
        }
        // A public status/finality report never mints historical authority. Reopen the retained
        // independently authenticated carrier and bind its exact single signed instruction.
        let historical = self.retained_historical(history, &directory, &original, &transaction)?;
        let current = super::native_operation::optional_current(
            observe_current,
            observed.as_ref(),
            |verifier| self.read_current(&original.policy, verifier, deadline),
        );
        verify_custody()?;
        Ok(progress(report.status, historical, current))
    }

    fn validate_history(&self, history: &ManagedHistoricalReserveTopUp) -> Result<()> {
        // The argument has no public constructor or decoder. These checks bind its already
        // authenticated Global carrier to this exact original generated provider, not caller DTOs.
        encode(history.amount(), journal::MAX_AMOUNT_BYTES)?;
        if history.network_id() != self.authority.config.network_id
            || history.provider_id() != self.authority.provider_id()?
            || history.provider_account()
                != self
                    .authority
                    .provider_role(StreamTokenAuthorityRole::IssuerOperator)?
            || history.movement_id() == [0; 32]
            || history.amount().is_zero()
            || history.original().height < 2
            || history.original().block_time_ms == 0
            || history.requested_provider_revision() == u64::MAX
        {
            return Err(invalid(
                "top-up history differs from original generated network or provider",
            ));
        }
        Ok(())
    }
    fn validate_intent(
        &self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
    ) -> Result<()> {
        journal::validate_intent(intent)?;
        self.validate_history(history)?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated reserve asset"))?;
        let policy = &intent.policy;
        if policy.asset_definition != asset
            || policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &policy.operations_authority != self.authority.network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)?
            || policy.decision_authority != self.authority.config.account
            || intent.partition.terms.provider_id != history.provider_id()
            || &intent.partition.terms.provider_account != history.provider_account()
            || intent.expected_provider_revision <= history.requested_provider_revision()
        {
            return Err(invalid(
                "approval differs from original generated roles or post-request provider CAS",
            ));
        }
        Ok(())
    }
    fn selection(
        &self,
        history: &ManagedHistoricalReserveTopUp,
        intent: &ManagedReserveTopUpApprovalIntent,
    ) -> Result<ReserveMovementDecisionSelection> {
        self.validate_intent(history, intent)?;
        let policy = &intent.policy;
        Ok(ReserveMovementDecisionSelection {
            chain_id: self.authority.config.chain.to_string(),
            network_id: self.authority.config.network_id,
            provider_id: history.provider_id(),
            provider_account: history.provider_account().clone(),
            expected_provider_revision: intent.expected_provider_revision,
            partition_policy_digest: intent.partition.policy_digest,
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
    fn validate_original(
        &self,
        history: &ManagedHistoricalReserveTopUp,
        original: &Original,
    ) -> Result<()> {
        original.validate()?;
        self.validate_history(history)?;
        original.history.matches(history)?;
        if encode(&original.selection, journal::MAX_SELECTION_BYTES)?
            != encode(
                &self.selection(history, &original.intent())?,
                journal::MAX_SELECTION_BYTES,
            )?
        {
            return Err(invalid(
                "original approval differs from authenticated generation",
            ));
        }
        let verifier = self.authority.decode_checkpoint(&original.checkpoint)?;
        let block = verifier
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original approval checkpoint"))?;
        block
            .verify_global_scope(
                self.authority.config.network_id,
                self.authority.config.chain.as_str(),
            )
            .map_err(|_| invalid("original approval checkpoint is not selected Global root"))?;
        if block.height() < history.original().height {
            return Err(invalid(
                "original approval checkpoint predates authenticated request",
            ));
        }
        Ok(())
    }
    fn historical_binding(
        &self,
        history: &ManagedHistoricalReserveTopUp,
        original: &Original,
        transaction: &SignedTransaction,
        verifier: &FinalityVerifier,
    ) -> Result<ManagedHistoricalReserveTopUpApproval> {
        self.validate_original(history, original)?;
        let block = verifier
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original approval carrier"))?;
        block
            .verify_global_scope(
                self.authority.config.network_id,
                self.authority.config.chain.as_str(),
            )
            .map_err(|_| invalid("approval carrier differs from selected Global root"))?;
        let finalized = verify_carrier(verifier, transaction)?;
        if finalized.height
            <= self
                .authority
                .decode_checkpoint(&original.checkpoint)?
                .checkpoint()
                .height()
        {
            return Err(invalid(
                "approval carrier predates original approval intent",
            ));
        }
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(invalid(
                "historical approval is not a direct native decision",
            ));
        };
        if instructions.len() != 1
            || transaction.attachments().is_some()
            || transaction.multisig_signatures().is_some()
            || transaction.metadata() != &iroha_model_base::metadata::Metadata::default()
            || transaction.authority() != &original.selection.decision_authority
            || transaction.network_id() != Some(&original.selection.network_id)
        {
            return Err(invalid(
                "historical approval differs from original manager signature profile",
            ));
        }
        let decision = instructions[0]
            .as_any()
            .downcast_ref::<DecideSorafsReserveMovement>()
            .ok_or_else(|| invalid("historical approval has a different native purpose"))?;
        if !decision.approve
            || decision.movement_id != history.movement_id()
            || decision.expected_provider_revision != original.selection.expected_provider_revision
            || decision.policy_digest != original.selection.policy_digest
            || decision.rationale != original.rationale
        {
            return Err(invalid(
                "historical decision differs from original top-up approval",
            ));
        }
        Ok(ManagedHistoricalReserveTopUpApproval {
            original: finalized,
            request: history.clone(),
            requested_provider_revision: decision.expected_provider_revision,
            policy_digest: decision.policy_digest,
            rationale: decision.rationale.clone(),
        })
    }
    fn retained_historical(
        &self,
        history: &ManagedHistoricalReserveTopUp,
        directory: &PrivateDirectory,
        original: &Original,
        transaction: &SignedTransaction,
    ) -> Result<Option<ManagedHistoricalReserveTopUpApproval>> {
        let Some(bytes) = read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)? else {
            return Ok(None);
        };
        let verifier = self.authority.decode_checkpoint(&bytes)?;
        self.historical_binding(history, original, transaction, &verifier)
            .map(Some)
    }
    fn verify_wallet(
        &self,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open reserve top-up approval wallet"))?
            .verify_reserve_movement_decision_journal(
                &directory.path().join("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| invalid("reserve wallet differs from exact original top-up approval"))
    }
    fn observe(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedReserveAccountStateV1)> {
        let verifier = self.authority.observe_finality(deadline)?;
        let current = self.read_current(policy, &verifier, deadline)?;
        Ok((verifier, current))
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
    historical: Option<ManagedHistoricalReserveTopUpApproval>,
    current: Option<VerifiedReserveAccountStateV1>,
) -> ManagedReserveTopUpApprovalProgress {
    let current = current.filter(|state| {
        historical.as_ref().is_none_or(|binding| {
            state.network_id() == binding.request().network_id()
                && state.height() >= binding.original().height
        })
    });
    ManagedReserveTopUpApprovalProgress {
        transaction_status: status,
        finalized: historical.as_ref().map(|value| *value.original()),
        current,
        historical,
    }
}

#[cfg(test)]
#[path = "reserve_top_up_approval/funding_test_support.rs"]
mod funding_test_support;
