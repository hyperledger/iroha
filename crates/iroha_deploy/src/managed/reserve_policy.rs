//! Initial reserve policy provisioning using the sole wallet journal and native evidence.
//!
//! Singleton absence is only a collision preflight. Successful execution of the exact original
//! native Set instruction establishes activation; fresh policy evidence remains separate.
//! This coordinator neither enables services nor funds collateral, credit or provider capacity.

use super::{
    PreparedLocalnet, Result,
    native_operation::{
        ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid, now_ms,
        read_optional, read_selected_peers, require_deadline, require_empty,
    },
    service_authority::{CheckpointImportScope, NetworkPurpose, ServiceAuthority},
};
use crate::verify::finality::FinalityVerifier;
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    asset::AssetDefinitionId,
    sorafs::reserve::{
        ReserveAuthorityPolicyRecordV1, ReserveAuthorityPolicyV1,
        proof::VerifiedReservePolicyStateV1,
    },
    transaction::SignedTransaction,
};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, InitialReservePolicySelection, OperationStatus,
};
use std::time::Instant;

#[path = "reserve_policy/journal.rs"]
mod journal;
use super::{
    native_operation::attempts::{self, Observation, Purpose, Selected},
    service_bootstrap::authorization::BootstrapChildAuthorization,
};
use journal::Original;

/// Exact original activation joined to fresh native evidence at a separately observed cut.
///
/// Only this coordinator can construct this fact. It grants no service, funding or capacity
/// authority, and carries no claim that the reserve namespace was empty before native execution.
#[derive(Clone, Copy, Debug)]
pub struct ManagedReservePolicyActivation {
    original: ManagedTransactionFinality,
    policy_digest: [u8; 32],
    network_id: NetworkId,
    current_height: u64,
    current_context: Hash,
}
impl ManagedReservePolicyActivation {
    /// Independently authenticated successful execution of the exact original wallet envelope.
    #[must_use]
    pub fn original(&self) -> &ManagedTransactionFinality {
        &self.original
    }
    /// Canonical digest of the exact original and freshly authenticated current policy.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    /// Original selected Global network, independently checked by both evidence owners.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Height of the fresh policy proof, at or after original activation.
    #[must_use]
    pub fn current_height(&self) -> u64 {
        self.current_height
    }
    /// Certified consensus context of the fresh policy proof.
    #[must_use]
    pub fn current_context(&self) -> Hash {
        self.current_context
    }
}

/// Separate wallet observation, exact original execution and fresh selected policy evidence.
#[derive(Debug)]
pub struct ManagedReservePolicyProgress {
    /// Wallet/node status; `Applied` alone is never independent successful inclusion.
    pub transaction_status: OperationStatus,
    /// Exact independently authenticated original carrier, including during a current outage.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh independently verified selected policy. `None` is unavailable, not absence.
    pub current: Option<VerifiedReservePolicyStateV1>,
    activation: Option<ManagedReservePolicyActivation>,
}
impl ManagedReservePolicyProgress {
    /// Exact original successful Set joined to fresh exact policy/provenance, when available.
    #[must_use]
    pub fn activation(&self) -> Option<&ManagedReservePolicyActivation> {
        self.activation.as_ref()
    }
}

/// Private, purpose-closed initial reserve provisioning for a generated service-authority root.
///
/// The manager signs governance, the existing issuer operator operates the reserve, and the
/// manager owns decisions. Original non-signing custody and treasury accounts receive no funds
/// here. Ordinary Standard profiles and private roots are not accepted or changed.
pub struct ManagedInitialReservePolicy {
    authority: ServiceAuthority,
}
impl ManagedInitialReservePolicy {
    /// Authenticate the original service profile/genesis and exclusively hold its reserve intent.
    /// # Errors
    /// Rejects substituted profiles, genesis, committee, private custody, or another coordinator.
    /// This performs no network operation and signs no transaction.
    pub fn open(prepared: &PreparedLocalnet) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_network(
                prepared,
                NetworkPurpose::InitialReservePolicy,
            )?,
        })
    }

    /// Create original reserve custody from a freshly checked parent without recapturing intent.
    /// The caller still supplies its ordinary live authorization before requesting creation.
    pub(super) fn open_from_original(parent: &ServiceAuthority) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_network_from_original(
                parent,
                NetworkPurpose::InitialReservePolicy,
            )?,
        })
    }

    pub(super) fn open_existing(prepared: &PreparedLocalnet) -> Result<Option<Self>> {
        ServiceAuthority::open_network_existing(prepared, NetworkPurpose::InitialReservePolicy)
            .map(|authority| authority.map(|authority| Self { authority }))
    }

    /// Retain fresh purpose custody using the immutable original read-only parent profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_network_existing_from_original(
            parent,
            NetworkPurpose::InitialReservePolicy,
            scope,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    /// Retain the initial policy and explicit original authorization, then advance that intent.
    /// # Errors
    /// Rejects changed original inputs, unsafe custody, or unavailable native prerequisites.
    pub fn set_initial(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedReservePolicyProgress> {
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let directory = self.authority.directory.ensure_child("set")?;
        let original = self.select_intent(&directory, policy, options.deadline)?;
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open initial reserve wallet"))?;
        journal::explicit(&directory, &original, utc, options, &account)?;
        self.advance(options.deadline)
    }

    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        policy: &ReserveAuthorityPolicyV1,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_policy(policy)?;
            self.validate_original(&original)?;
            return Ok(original);
        }
        require_empty(directory)?;
        let (verifier, current) = self.observe(policy, deadline)?;
        if current.current().is_some() {
            return Err(invalid("initial reserve policy already exists"));
        }
        let original = Original {
            selection: self.selection(policy)?,
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
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedReservePolicyProgress> {
        let deadline = authorization.validate(&self.authority, Purpose::ReservePolicy, deadline)?;
        if policy != &authorization.policies().network.reserve {
            return Err(invalid(
                "reserve policy differs from authorized original policy",
            ));
        }
        self.validate_policy(policy)?;
        let directory = self.authority.directory.ensure_child("set")?;
        let original = self.select_intent(&directory, policy, deadline)?;
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open initial reserve wallet"))?;
        let account = authorization.bind_account(account)?;
        attempts::generated(
            &directory,
            Purpose::ReservePolicy,
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
            authorization,
            deadline,
            None,
            |attempt| {
                account
                    .inspect_initial_reserve_policy_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("reserve attempt differs from exact wallet request"))
            },
            |attempt| {
                account
                    .retire_initial_reserve_policy_unprepared(
                        &attempt.wallet_path(),
                        &original.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("reserve unsigned request could not retire"))
            },
            |attempt, _, deadline| {
                account
                    .retain_initial_reserve_policy_request(
                        &original.request(attempt.terms(), deadline),
                        &attempt.wallet_path(),
                    )
                    .map_err(|_| invalid("cannot retain exact unsigned reserve request"))
            },
            |_, deadline| {
                let (_, current) = self.observe(policy, deadline)?;
                if current.current().is_some() {
                    return Err(invalid("initial reserve policy already exists"));
                }
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )?;
        authorization.validate(&self.authority, Purpose::ReservePolicy, deadline)?;
        self.advance_original(
            deadline,
            Advance::SubmitAuthorized(authorization),
            false,
            Some(account),
        )
    }

    /// Prepare or dispatch the exact retained initial policy at most once, then observe it.
    /// # Errors
    /// Rejects missing/changed originals, changed native preflight or journal/evidence failures.
    /// A fresh I/O deadline never renews the original UTC authorization or signed envelope.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedReservePolicyProgress> {
        self.advance_original(deadline, Advance::SubmitOriginal, true, None)
    }

    /// Observe the exact original intent and wallet transaction without preparing or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or invalid retained evidence. This may retain verified
    /// finality progress, but never creates a wallet transaction, quotes fees, signs or sends it.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedReservePolicyProgress> {
        self.advance_original(deadline, Advance::ObserveOnly, true, None)
    }

    /// Recover the semantic original using its selected immutable dispatch authorization.
    pub(super) fn recover_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &super::native_operation::Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReservePolicyProgress>> {
        self.recover_selected(policy, fees, deadline, Advance::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &super::native_operation::Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedReservePolicyProgress>> {
        self.recover_selected(policy, fees, deadline, Advance::ObserveLocal)
    }
    fn recover_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &super::native_operation::Fees,
        deadline: Instant,
        mode: Advance<'_>,
    ) -> Result<Option<ManagedReservePolicyProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let Some(directory) = self.authority.directory.open_child_optional("set")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            require_empty(&directory)?;
            return Ok(None);
        };
        self.validate_original(&original)?;
        original.matches_policy(policy)?;
        let history = attempts::History::read(
            &directory,
            Purpose::ReservePolicy,
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )?;
        history.require_fees(fees)?;
        self.advance_original(deadline, mode, false, None).map(Some)
    }

    fn advance_original(
        &mut self,
        deadline: Instant,
        mode: Advance<'_>,
        observe_current: bool,
        retained_account: Option<AccountService>,
    ) -> Result<ManagedReservePolicyProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let operation = self.authority.directory.open_child("set")?;
        let original = journal::required_original(&operation)?;
        self.validate_original(&original)?;
        let directory = original.directory();
        let path = directory.path().join("transaction");
        // The generated caller closes its original authorization before moving the account
        // used for request retention here. Standalone and recovery calls construct their own.
        let account = match retained_account {
            Some(account) => account,
            None => AccountService::new(self.authority.config.clone())
                .map_err(|_| invalid("cannot open initial reserve wallet"))?,
        };
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                account
                    .inspect_initial_reserve_policy_preparation_in_parent(
                        attempt.directory(),
                        std::ffi::OsStr::new("transaction"),
                        &intent.request(attempt.terms(), deadline),
                    )
                    .map_err(|_| invalid("reserve retained attempt history changed"))
            })
        };
        verify_custody()?;
        let preparation = account
            .inspect_initial_reserve_policy_preparation_in_parent(
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
            return Ok(progress(
                &original,
                OperationStatus::Applied,
                Some(finalized),
                current,
            ));
        }
        if matches!(mode, Advance::ObserveLocal) {
            return Ok(progress(
                &original,
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
            return Ok(progress(&original, status, None, None));
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
                return Ok(progress(&original, OperationStatus::Expired, None, current));
            }
            if !absent {
                return Err(invalid(
                    "fresh reserve singleton absence unavailable; retain original intent",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(Purpose::ReservePolicy, deadline)?;
            account
                .prepare_initial_reserve_policy(
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
            None => Self::verify_wallet(&account, &directory, &original, deadline)?,
        };
        let request = original.request(deadline);
        let mut report = account
            .resume_initial_reserve_policy(&path, &request)
            .map_err(|_| invalid("reserve transaction unresolved; recover its original journal"))?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if absent {
                verify_custody()?;
                mode.check_dispatch(Purpose::ReservePolicy, deadline)?;
                report = account
                    .submit_initial_reserve_policy(&path, &request)
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
        Ok(progress(&original, report.status, finalized, current))
    }

    fn validate_policy(&self, policy: &ReserveAuthorityPolicyV1) -> Result<()> {
        encode(policy, journal::MAX_POLICY_BYTES)?;
        policy
            .validate()
            .map_err(|_| invalid("invalid initial reserve policy"))?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated reserve asset"))?;
        if policy.revision != 1
            || policy.predecessor_policy_digest.is_some()
            || policy.asset_definition != asset
            || policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &policy.operations_authority
                != self
                    .authority
                    .network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)?
            || policy.decision_authority != self.authority.config.account
        {
            return Err(invalid(
                "initial reserve policy differs from the original generated roles or asset",
            ));
        }
        Ok(())
    }
    fn selection(
        &self,
        policy: &ReserveAuthorityPolicyV1,
    ) -> Result<InitialReservePolicySelection> {
        self.validate_policy(policy)?;
        Ok(InitialReservePolicySelection {
            chain_id: self.authority.config.chain.to_string(),
            network_id: self.authority.config.network_id,
            manager: self.authority.config.account.clone(),
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
        self.validate_original_selection(original)?;
        self.authority
            .decode_checkpoint(&original.checkpoint)?
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original reserve checkpoint"))?
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("original reserve checkpoint is not the selected Global root"))?;
        Ok(())
    }
    // Finish all original selection scratch before cold checkpoint authentication begins.
    #[inline(never)]
    fn validate_original_selection(&self, original: &Original) -> Result<()> {
        original.validate()?;
        self.validate_policy(&original.policy)?;
        if encode(&original.selection, journal::MAX_SELECTION_BYTES)?
            != encode(
                &self.selection(&original.policy)?,
                journal::MAX_SELECTION_BYTES,
            )?
        {
            return Err(invalid(
                "original reserve selection differs from the authenticated generation",
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
            return Err(invalid("reserve carrier predates the original intent"));
        }
        Ok(())
    }
    // Inspect through this call's already-bound account; the exact journal producer still
    // reopens and verifies every record. No HTTP context or new signing authority is created.
    fn verify_wallet(
        account: &AccountService,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        account
            .verify_initial_reserve_policy_journal(
                &directory.path().join("transaction"),
                &original.request(deadline),
            )
            .map_err(|_| invalid("reserve wallet differs from the exact original request"))
    }
    fn observe(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedReservePolicyStateV1)> {
        let verifier = self.authority.observe_finality(deadline)?;
        let state = self.read_current(policy, &verifier, deadline)?;
        Ok((verifier, state))
    }
    fn read_current(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        verifier: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedReservePolicyStateV1> {
        let block = verifier
            .verified_tip()
            .map_err(|_| invalid("invalid certified reserve tip"))?;
        let schema = iroha_core::state::State::native_world_schema_hash_v1()
            .map_err(|_| invalid("native reserve schema unavailable"))?;
        read_selected_peers(&self.authority.peers, deadline, |client, deadline| {
            client
                .with_request_deadline(deadline)
                .get_reserve_policy_state(&self.authority.config.account, policy, schema, &block)
                .map_err(|_| invalid("native reserve candidate unavailable or invalid"))
        })
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

// Called only after original-wallet verification and independent carrier verification. Public
// finality report fields are not accepted as capabilities by any coordinator API.
fn progress(
    original: &Original,
    status: OperationStatus,
    finalized: Option<ManagedTransactionFinality>,
    current: Option<VerifiedReservePolicyStateV1>,
) -> ManagedReservePolicyProgress {
    let activation = finalized
        .as_ref()
        .zip(current.as_ref())
        .and_then(|(finalized, state)| {
            let record = state.current()?;
            if state.network_id() != original.selection.network_id
                || state.manager() != &original.selection.manager
                || state.height() < finalized.height
                || !matches_activation_record(original, finalized, record)
            {
                return None;
            }
            Some(ManagedReservePolicyActivation {
                original: *finalized,
                policy_digest: original.selection.policy_digest,
                network_id: state.network_id(),
                current_height: state.height(),
                current_context: state.context_id(),
            })
        });
    ManagedReservePolicyProgress {
        transaction_status: status,
        finalized,
        current,
        activation,
    }
}

// Pure exact-provenance comparison, not a proof constructor or an eligibility predicate.
fn matches_activation_record(
    original: &Original,
    finalized: &ManagedTransactionFinality,
    record: &ReserveAuthorityPolicyRecordV1,
) -> bool {
    record.policy == original.policy
        && record.policy_digest == original.selection.policy_digest
        && record.activated_by == original.selection.manager
        && record.activated_at_unix == finalized.block_time_ms / 1_000
}

#[cfg(test)]
#[path = "reserve_policy/native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "reserve_policy/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "reserve_policy/transport_tests.rs"]
mod transport_tests;

#[cfg(test)]
#[path = "reserve_policy/bootstrap_test_support.rs"]
mod bootstrap_test_support;

#[cfg(test)]
#[path = "reserve_policy/epoch_test_support.rs"]
mod epoch_test_support;
