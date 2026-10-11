//! Managed original provider top-up requests and independently authenticated historical facts.
//!
//! Current account evidence is a separate observation, never movement Pending status, approval,
//! collateral or service readiness. The sole wallet journal owns signing and once-only dispatch.

use super::{
    PreparedLocalnet, Result,
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
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    isi::sorafs::RequestSorafsReserveMovement,
    sorafs::{
        capacity::ProviderId,
        reserve::{
            ReserveAuthorityPolicyV1, ReserveMovementKindV1, ReserveProviderAccountV1,
            account_proof::VerifiedReserveAccountStateV1, history::validate_provider_record,
        },
    },
    transaction::{Executable, SignedTransaction},
};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, OperationStatus, ReserveTopUpSelection,
};
use sorafs_manifest::deal::XorQuantity;
use std::time::Instant;

#[path = "reserve_top_up/journal.rs"]
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
#[path = "reserve_top_up/native_tests.rs"]
pub(in crate::managed) mod native_tests;
#[cfg(test)]
#[path = "reserve_top_up/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "reserve_top_up/transport_tests.rs"]
mod transport_tests;

/// Immutable caller intent checked against original generated roles and fresh native evidence.
///
/// These fields are claims, not a native proof. The current revision is selected independently
/// of the supplied partition; its last projected policy digest may legitimately lag governance.
#[derive(Clone, Debug)]
pub struct ManagedReserveTopUpIntent {
    /// Complete selected active policy, including all original generated roles.
    pub policy: ReserveAuthorityPolicyV1,
    /// Complete selected original provider partition, retained without normalization.
    pub partition: ReserveProviderAccountV1,
    /// Independently requested current provider CAS.
    pub expected_provider_revision: u64,
    /// Exact nonzero movement identifier; native execution owns uniqueness.
    pub movement_id: [u8; 32],
    /// Positive requested amount; request execution does not transfer it.
    pub amount: XorQuantity,
}

/// Historical successful execution of one exact original native RequestTopUp.
///
/// Only this coordinator can construct the binding after independently authenticating its
/// original signed wallet envelope and execution carrier. It has no public decoder or constructor.
/// The fields do not assert current Pending status, approval, funding or service readiness.
#[derive(Clone, Debug)]
pub struct ManagedHistoricalReserveTopUp {
    original: ManagedTransactionFinality,
    network_id: NetworkId,
    provider_id: ProviderId,
    provider_account: AccountId,
    movement_id: [u8; 32],
    amount: XorQuantity,
    requested_provider_revision: u64,
    policy_digest: [u8; 32],
}
impl ManagedHistoricalReserveTopUp {
    /// Independently verified original carrier; this returned report is not a constructor.
    #[must_use]
    pub fn original(&self) -> &ManagedTransactionFinality {
        &self.original
    }
    /// Original selected Global network.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Provider derived from the exact successful RequestTopUp.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
    /// Original request signer, matching the independently selected provider owner.
    #[must_use]
    pub fn provider_account(&self) -> &AccountId {
        &self.provider_account
    }
    /// Immutable native movement identifier derived from that request.
    #[must_use]
    pub fn movement_id(&self) -> [u8; 32] {
        self.movement_id
    }
    /// Immutable amount requested; no transfer or current reserve balance is inferred.
    #[must_use]
    pub fn amount(&self) -> &XorQuantity {
        &self.amount
    }
    /// CAS consumed by the original request, not a current decision CAS.
    #[must_use]
    pub fn requested_provider_revision(&self) -> u64 {
        self.requested_provider_revision
    }
    /// Active policy digest selected by the original request, not necessarily current governance.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
}

/// Separate node status, original historical binding and optional current provider facts.
#[derive(Debug)]
pub struct ManagedReserveTopUpProgress {
    /// Replaceable node observation; `Applied` alone establishes no historical binding.
    pub transaction_status: OperationStatus,
    /// Public reporting of original inclusion. Mutating this field cannot create a binding.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh selected provider/policy evidence; None means unavailable, not provider absence.
    pub current: Option<VerifiedReserveAccountStateV1>,
    historical: Option<ManagedHistoricalReserveTopUp>,
}
impl ManagedReserveTopUpProgress {
    /// Historical immutable request facts, independently verified even across current-state outage.
    #[must_use]
    pub fn historical(&self) -> Option<&ManagedHistoricalReserveTopUp> {
        self.historical.as_ref()
    }
}

/// Closed request/evidence owner for the original generated issuer's provider reserve partition.
///
/// Original manager clients retain finality ownership; the issuer signs the request and account
/// reads. This owner never approves a movement, enables services or transfers reserve principal.
pub struct ManagedReserveTopUpRequest {
    authority: ServiceAuthority,
}
impl ManagedReserveTopUpRequest {
    /// Authenticate the original generated profile/genesis and exclusively hold its top-up intent.
    /// # Errors
    /// Substituted generation, non-Global/Standard profile, unsafe custody or concurrent owner.
    pub fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::ReserveTopUpRequest,
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
                ProviderPurpose::ReserveTopUpRequest,
            )?,
        })
    }

    /// Retain one exact request after fresh predecessor verification, then advance once-only work.
    /// # Errors
    /// Changed original intent/UTC/fees, invalid generated bindings, unavailable/stale predecessor
    /// or unsafe journal custody. Caller fields never select the finality trust anchor.
    pub fn request(
        &mut self,
        intent: &ManagedReserveTopUpIntent,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedReserveTopUpProgress> {
        self.authority.validate_profile()?;
        self.validate_intent(intent)?;
        let directory = self.authority.directory.ensure_child("request")?;
        let original = self.select_intent(&directory, intent, options.deadline)?;
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open funding wallet"))?;
        journal::explicit(&directory, &original, deadline_unix_ms, options, &account)?;
        self.advance(options.deadline)
    }

    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        intent: &ManagedReserveTopUpIntent,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_intent(intent)?;
            self.validate_original(&original)?;
            return Ok(original);
        }
        require_empty(&directory)?;
        let (verifier, current) = self.observe(&intent.policy, deadline)?;
        if current.current() != Some(&intent.partition) {
            return Err(invalid(
                "fresh reserve partition differs from selected original top-up predecessor",
            ));
        }
        let original = Original {
            selection: self.selection(intent)?,
            policy: intent.policy.clone(),
            partition: intent.partition.clone(),
            movement_id: intent.movement_id,
            amount: intent.amount.clone(),
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
            ProviderPurpose::ReserveTopUpRequest,
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
            ProviderPurpose::ReserveTopUpRequest,
            scope,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    pub(super) fn advance_selected(
        &mut self,
        intent: &ManagedReserveTopUpIntent,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedReserveTopUpProgress> {
        let purpose = Purpose::FundingRequest(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        if intent.policy != authorization.policies().network.reserve {
            return Err(invalid("funding policy differs from startup authorization"));
        }
        self.validate_intent(intent)?;
        let directory = self.authority.directory.ensure_child("request")?;
        let original = self.select_intent(&directory, intent, deadline)?;
        let account = AccountService::new(self.authority.issuer_operator_config()?)
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
                    .inspect_reserve_top_up_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("funding attempt differs from exact wallet request"))
            },
            |attempt| {
                account
                    .retire_reserve_top_up_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("funding unsigned request could not retire"))
            },
            |attempt, _, deadline| {
                account
                    .retain_reserve_top_up_request(
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
        self.advance_original(deadline, Advance::SubmitAuthorized(authorization), false)
    }

    /// Prepare or dispatch the exact retained top-up request at most once, then observe it.
    /// # Errors
    /// Rejects missing/changed originals, changed native preflight or journal/evidence failures.
    /// A fresh I/O deadline never renews the original UTC authorization or signed envelope.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedReserveTopUpProgress> {
        self.advance_original(deadline, Advance::SubmitOriginal, true)
    }

    /// Observe the exact original intent and wallet transaction without preparing or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or invalid retained evidence. This may retain verified
    /// finality progress, but never creates a wallet transaction, quotes fees, signs or sends it.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedReserveTopUpProgress> {
        self.advance_original(deadline, Advance::ObserveOnly, true)
    }

    // Closed parent recovery: authenticate exact retained claims before any HTTP. Missing
    // original is reported only for a genuinely absent or empty child; orphan/corrupt work fails.
    // Successful original carrier recovery skips optional current observation so a peer outage
    // cannot consume the parent deadline before its later original children are recovered.
    pub(super) fn recover_selected_if_present(
        &mut self,
        intent: &ManagedReserveTopUpIntent,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReserveTopUpProgress>> {
        self.recover_selected(intent, fees, deadline, Advance::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        intent: &ManagedReserveTopUpIntent,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReserveTopUpProgress>> {
        self.recover_selected(intent, fees, deadline, Advance::ObserveLocal)
    }
    fn recover_selected(
        &mut self,
        intent: &ManagedReserveTopUpIntent,
        fees: &Fees,
        deadline: Instant,
        mode: Advance<'_>,
    ) -> Result<Option<ManagedReserveTopUpProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_intent(intent)?;
        let Some(directory) = self.authority.directory.open_child_optional("request")? else {
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
            Purpose::FundingRequest(original.selection.provider_id),
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
    ) -> Result<ManagedReserveTopUpProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let operation = self.authority.directory.open_child("request")?;
        let original = journal::required_original(&operation)?;
        let directory = original.directory();
        self.validate_original(&original)?;
        let path = directory.path().join("transaction");
        let account = AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open reserve top-up request wallet"))?;
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                account
                    .inspect_reserve_top_up_preparation_in_parent(
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
                                    "retained funding wallet inspection: purpose=FundingRequest; cause[{index}]={cause}",
                                );
                            }
                        }
                        invalid("retained funding attempt history changed")
                    })
            })
        };
        verify_custody()?;
        let preparation = account
            .inspect_reserve_top_up_preparation_in_parent(
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
                self.retained_historical(&directory, &original, transaction)?
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
                    "fresh exact reserve predecessor unavailable; retain original top-up intent",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(
                Purpose::FundingRequest(original.selection.provider_id),
                deadline,
            )?;
            account
                .prepare_reserve_top_up(
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
            .resume_reserve_top_up(&path, &request)
            .map_err(|_| invalid("reserve transaction unresolved; recover its original journal"))?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if predecessor_matches {
                verify_custody()?;
                mode.check_dispatch(
                    Purpose::FundingRequest(original.selection.provider_id),
                    deadline,
                )?;
                report = account
                    .submit_reserve_top_up(&path, &request)
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
        let historical = self.retained_historical(&directory, &original, &transaction)?;
        let current = super::native_operation::optional_current(
            observe_current,
            observed.as_ref(),
            |verifier| self.read_current(&original.policy, verifier, deadline),
        );
        verify_custody()?;
        Ok(progress(report.status, historical, current))
    }

    fn validate_intent(&self, intent: &ManagedReserveTopUpIntent) -> Result<()> {
        journal::validate_intent(intent)?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated reserve asset"))?;
        let operator = self
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)?;
        let policy = &intent.policy;
        if policy.asset_definition != asset
            || policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &policy.operations_authority != self.authority.network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)?
            || policy.decision_authority != self.authority.config.account
            || intent.partition.terms.provider_id != self.authority.provider_id()?
            || &intent.partition.terms.provider_account != operator
        {
            return Err(invalid(
                "reserve top-up differs from original generated provider or roles",
            ));
        }
        Ok(())
    }

    fn selection(&self, intent: &ManagedReserveTopUpIntent) -> Result<ReserveTopUpSelection> {
        self.validate_intent(intent)?;
        let policy = &intent.policy;
        Ok(ReserveTopUpSelection {
            chain_id: self.authority.config.chain.to_string(),
            network_id: self.authority.config.network_id,
            provider_id: intent.partition.terms.provider_id,
            provider_account: intent.partition.terms.provider_account.clone(),
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

    fn validate_original(&self, original: &Original) -> Result<()> {
        original.validate()?;
        self.validate_original_selection(original)?;
        self.authority
            .decode_checkpoint(&original.checkpoint)?
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original reserve top-up checkpoint"))?
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("original reserve checkpoint is not the selected Global root"))?;
        Ok(())
    }

    // Complete the original canonical claim comparison in its own lexical frame. The
    // policy/partition/amount clone and both selection encodes drop before native import;
    // the authenticated original and its directory remain held by the caller unchanged.
    #[inline(never)]
    fn validate_original_selection(&self, original: &Original) -> Result<()> {
        let intent = original.intent();
        if encode(&original.selection, journal::MAX_SELECTION_BYTES)?
            != encode(&self.selection(&intent)?, journal::MAX_SELECTION_BYTES)?
        {
            return Err(invalid(
                "original reserve top-up differs from authenticated generation",
            ));
        }
        Ok(())
    }

    fn historical_binding(
        &self,
        original: &Original,
        transaction: &SignedTransaction,
        verifier: &FinalityVerifier,
    ) -> Result<ManagedHistoricalReserveTopUp> {
        self.validate_original(original)?;
        let block = verifier
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original top-up carrier"))?;
        block
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("top-up carrier differs from selected Global root"))?;
        let finalized = verify_carrier(verifier, transaction)?;
        if finalized.height
            <= self
                .authority
                .decode_checkpoint(&original.checkpoint)?
                .checkpoint()
                .height()
        {
            return Err(invalid("top-up carrier predates original intent"));
        }
        // The historical binding is minted from the actual envelope, not caller claims or the
        // public reporting DTO. The native carrier owner above authenticates success and wire.
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(invalid("historical top-up is not a direct native request"));
        };
        if instructions.len() != 1
            || transaction.attachments().is_some()
            || transaction.multisig_signatures().is_some()
            || transaction.metadata() != &iroha_model_base::metadata::Metadata::default()
            || transaction.authority() != &original.selection.provider_account
            || transaction.network_id() != Some(&original.selection.network_id)
        {
            return Err(invalid(
                "historical top-up differs from sole original signature profile",
            ));
        }
        let request = instructions[0]
            .as_any()
            .downcast_ref::<RequestSorafsReserveMovement>()
            .ok_or_else(|| invalid("historical top-up has a different native purpose"))?;
        if request.kind != ReserveMovementKindV1::TopUp
            || request.movement_id != original.movement_id
            || request.provider_id != original.selection.provider_id
            || request.amount != original.amount
            || request.expected_provider_revision != original.selection.expected_provider_revision
            || request.policy_digest != original.selection.policy_digest
        {
            return Err(invalid(
                "historical request differs from original top-up intent",
            ));
        }
        Ok(ManagedHistoricalReserveTopUp {
            original: finalized,
            network_id: original.selection.network_id,
            provider_id: request.provider_id,
            provider_account: transaction.authority().clone(),
            movement_id: request.movement_id,
            amount: request.amount.clone(),
            requested_provider_revision: request.expected_provider_revision,
            policy_digest: request.policy_digest,
        })
    }

    fn retained_historical(
        &self,
        directory: &PrivateDirectory,
        original: &Original,
        transaction: &SignedTransaction,
    ) -> Result<Option<ManagedHistoricalReserveTopUp>> {
        let Some(bytes) = read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)? else {
            return Ok(None);
        };
        let verifier = self.authority.decode_checkpoint(&bytes)?;
        self.historical_binding(original, transaction, &verifier)
            .map(Some)
    }

    fn verify_wallet(
        &self,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        AccountService::new(self.authority.issuer_operator_config()?)
            .map_err(|_| invalid("cannot open reserve top-up wallet"))?
            .verify_reserve_top_up_journal(
                &directory.path().join("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| invalid("reserve wallet differs from exact original top-up request"))
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
    historical: Option<ManagedHistoricalReserveTopUp>,
    current: Option<VerifiedReserveAccountStateV1>,
) -> ManagedReserveTopUpProgress {
    let current = current.filter(|state| {
        historical.as_ref().is_none_or(|binding| {
            state.network_id() == binding.network_id()
                && state.height() >= binding.original().height
        })
    });
    ManagedReserveTopUpProgress {
        transaction_status: status,
        finalized: historical.as_ref().map(|value| *value.original()),
        current,
        historical,
    }
}

#[cfg(test)]
#[path = "reserve_top_up/funding_test_support.rs"]
mod funding_test_support;
