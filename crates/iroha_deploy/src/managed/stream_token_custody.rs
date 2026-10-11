//! Managed signer custody: immutable initial and renewal intents with native evidence.
//!
//! Configure and Enroll (including bounded generated renewal) are the only writable purposes.
//! Exact transaction finality and fresh
//! custody state are separate observations; neither enables services or establishes admission,
//! capacity, current signing eligibility, or hardware custody guarantees.

use super::{
    PreparedLocalnet, Result,
    native_operation::{
        MAX_CHECKPOINT_BYTES, ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid,
        now_ms, read_optional, read_selected_peers, require_deadline, require_empty,
    },
    service_authority::{
        CheckpointImportScope, CheckpointImports, ProviderPurpose, ServiceAuthority,
    },
};
use crate::{
    localnet::service_authorities::StreamTokenAuthorityRole, verify::finality::FinalityVerifier,
};
use iroha_crypto::{Hash, Signature};
use iroha_data_model::{
    sorafs::stream_token_custody::proof::VerifiedStreamTokenCustodyStateV1,
    sumeragi_finality::{EpochValidationScope, VerifiedSumeragiBlock},
    transaction::SignedTransaction,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, OperationStatus, StreamTokenCustodyConfigureRequest,
    StreamTokenCustodyEnrollRequest, StreamTokenCustodySelection,
};
use sorafs_manifest::signer::{
    custody::{
        SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyBindingV1,
        SignerCustodyRecordV1, SignerCustodyStatementV1,
    },
    custody_control::SignerCustodyPolicyV1,
};
use std::time::Instant;
#[cfg(test)]
use std::{num::NonZeroU64, time::Duration};

#[path = "stream_token_custody/body_history.rs"]
pub(in crate::managed) mod body_history;
#[path = "stream_token_custody/identity.rs"]
mod identity;
#[path = "stream_token_custody/journal.rs"]
mod journal;
use super::{
    ManagedBootstrapFailure,
    native_operation::{
        Fees,
        attempts::{self, HistoryScope, Observation, Purpose, Selected},
        authorization::DispatchAuthorization,
    },
    service_bootstrap::authorization::BootstrapChildAuthorization,
};
use body_history::{BodyHistory, SigningTurn};
use journal::{Action, Original};
#[path = "stream_token_custody/enrollment.rs"]
mod enrollment;
#[path = "stream_token_custody/renewal.rs"]
pub(super) mod renewal;
pub use enrollment::RetainedCustodyEnrollment;

/// Separate node observation, exact original inclusion and freshly proved current custody.
#[derive(Debug)]
pub struct ManagedCustodyProgress {
    /// Exact wallet/node observation; `Applied` alone is not independent finality.
    pub transaction_status: OperationStatus,
    /// Independently authenticated original transaction carrier, when replay has reached it.
    pub finalized: Option<ManagedTransactionFinality>,
    /// Fresh native state at the separately observed quorum tip, not a signing eligibility claim.
    /// `None` means unavailable, including a changed binding; only a verified state's absent
    /// current record is authenticated absence. Historical inclusion remains independently valid.
    pub current: Option<VerifiedStreamTokenCustodyStateV1>,
}

/// An original caller-selected enrollment interval and exclusive submission deadline.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_deploy::managed::ManagedCustodyEnrollmentInterval")]
pub struct ManagedCustodyEnrollmentInterval {
    /// Inclusive original beginning of the attester's authorization, in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive original end of that authorization, in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Exclusive original transaction deadline; cannot exceed the enrollment expiry.
    pub deadline_unix_ms: u64,
}

/// Held native private custody for one generated Global network's Configure and Enroll.
///
/// The generated manager, role signer and attester remain distinct. Opening authenticates the
/// original signed genesis and retained authority profile. Fixed journals support initial
/// provisioning. Renewals have separate bounded sequence journals; no original is reset.
pub struct ManagedStreamTokenCustody {
    authority: ServiceAuthority,
}

#[derive(Clone, Copy)]
enum Mode<'a> {
    ObserveLocal,
    SubmitOriginal,
    SubmitAuthorized(&'a dyn DispatchAuthorization),
    ObserveOnly,
}
impl Mode<'_> {
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

/// Closed directory/purpose selection; a renewal never substitutes the initial journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CustodyPurpose {
    Configure,
    InitialEnroll,
    Renewal(u64),
}
impl CustodyPurpose {
    #[cfg(test)]
    fn initial(action: &Action) -> Self {
        match action {
            Action::Configure(_) => Self::Configure,
            Action::Enroll { .. } => Self::InitialEnroll,
        }
    }
    fn directory_name(self) -> Result<String> {
        match self {
            Self::Configure => Ok("configure".into()),
            Self::InitialEnroll => Ok("enroll".into()),
            Self::Renewal(sequence) => renewal::directory_name(sequence),
        }
    }
}

impl ManagedStreamTokenCustody {
    /// Authenticate a retained generated authority profile and exclusively open its coordinator.
    /// # Errors
    /// Rejects a Standard/private root, substituted genesis/roles/configuration, unsafe custody
    /// or another active coordinator. No network operation or transaction occurs here.
    pub fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::Custody,
            )?,
        })
    }

    /// Create or retain this provider's Custody purpose from an authenticated original parent.
    /// Fresh native admission and the parent's ordinary exit checks remain mandatory.
    /// This creates no Configure/Enroll original or signing authorization.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_provider_from_original(
                parent,
                provider,
                ProviderPurpose::Custody,
            )?,
        })
    }

    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_provider_existing(prepared, provider, ProviderPurpose::Custody)
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
            ProviderPurpose::Custody,
            scope,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }
    pub(super) fn open_existing_in_runtime(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        scope: Option<&CheckpointImportScope>,
        read: &super::service_authority::RuntimeOriginalRead<'_>,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_provider_existing_in_runtime(
            parent,
            provider,
            ProviderPurpose::Custody,
            scope,
            read,
        )
        .map(|authority| authority.map(|authority| Self { authority }))
    }

    fn wallet(&self) -> Result<AccountService> {
        #[cfg(test)]
        tests::record_wallet_construction();
        AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open custody wallet"))
    }

    /// Retain the exact first configuration and finite dispatch authorization, then advance once.
    /// # Errors
    /// Rejects changed policy, terms, generated roles, native prerequisite or private custody.
    pub fn configure(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedCustodyProgress> {
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let directory = self.authority.directory.ensure_child("configure")?;
        let original = self.select_configuration(&directory, policy, options.deadline)?;
        journal::explicit(
            &directory,
            &original,
            utc,
            options,
            &self.wallet()?,
            &HistoryScope::FixedBody,
        )?;
        self.advance_configure(options.deadline)
    }
    fn select_configuration(
        &mut self,
        directory: &PrivateDirectory,
        policy: &SignerCustodyPolicyV1,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_configuration(policy)?;
            self.validate_original(&original, CustodyPurpose::Configure)?;
            return Ok(original);
        }
        require_empty(directory)?;
        let (verifier, current) = self.observe(&policy.binding, deadline)?;
        if current.current().is_some() {
            return Err(invalid("initial custody configuration already exists"));
        }
        let original = Original {
            selection: self.selection(&policy.binding, &current)?,
            action: Action::Configure(policy.clone()),
            checkpoint: checkpoint_bytes(&verifier)?,
        };
        self.validate_original(&original, CustodyPurpose::Configure)?;
        journal::publish_intent(directory, &original)?;
        Ok(original)
    }

    /// Retain an independently attested first body after exact native Configure inclusion.
    /// # Errors
    /// Rejects changed original interval, fees, native predecessor, role custody or body expiry.
    pub fn enroll(
        &mut self,
        interval: ManagedCustodyEnrollmentInterval,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedCustodyProgress> {
        self.authority.validate_profile()?;
        let (policy, finalized) = self.retained_configuration(options.deadline)?;
        let existing = BodyHistory::open(self, CustodyPurpose::InitialEnroll)?;
        if let Some(history) = &existing {
            history.matches_policy(&policy)?;
            history.matches_interval(interval)?;
            if *history.fees() != Fees::from_options(options)? {
                return Err(invalid("explicit enrollment changed original fees"));
            }
        }
        let history = if existing
            .as_ref()
            .is_some_and(|h| h.original().is_ok_and(|o| o.is_some()) && !h.has_pending())
        {
            existing.ok_or_else(|| invalid("selected enrollment absent"))?
        } else {
            let terms = Terms::new(interval.deadline_unix_ms, options)?;
            let (unsigned, current) =
                self.select_initial_unsigned(&policy, &finalized, interval, options.deadline)?;
            let turn = SigningTurn::Explicit(&terms);
            let history = match existing {
                Some(history) => history,
                None => BodyHistory::initialize(
                    self,
                    CustodyPurpose::InitialEnroll,
                    unsigned,
                    &terms.fees,
                    &turn,
                    options.deadline,
                )?,
            };
            history.finish_pending(self, &current, &turn, options.deadline)?
        };
        let (directory, original, scope) = history.dispatch()?;
        journal::explicit(
            directory,
            original,
            interval.deadline_unix_ms,
            options,
            &self.wallet()?,
            scope,
        )?;
        let selected = history.into_reparsed_selected(self)?;
        self.advance_selected(
            CustodyPurpose::InitialEnroll,
            selected,
            options.deadline,
            Mode::SubmitOriginal,
            true,
        )
    }
    fn select_initial_unsigned(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        finalized: &ManagedTransactionFinality,
        interval: ManagedCustodyEnrollmentInterval,
        deadline: Instant,
    ) -> Result<(
        body_history::UnsignedEnrollment,
        VerifiedStreamTokenCustodyStateV1,
    )> {
        let (verifier, current) = self.observe(&policy.binding, deadline)?;
        let selected = current
            .current()
            .ok_or_else(|| invalid("custody policy absent"))?;
        if selected.control().policy != *policy
            || selected.control().signer_revoked
            || selected.control().attester_revoked
            || selected.control().active_head.is_some()
            || selected.record().revision != 1
            || selected.record().execution_height != finalized.height
            || selected.record().authority != self.authority.config.account
        {
            return Err(invalid(
                "initial configured custody changed before enrollment",
            ));
        }
        let observed = now_ms()?;
        validate_interval(interval, observed)?;
        let unsigned = self.unsigned_enrollment(policy, &current, &verifier, interval, observed)?;
        self.authority.validate_profile()?;
        require_deadline(deadline)?;
        Ok((unsigned, current))
    }
    pub(super) fn advance_configure_selected(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedCustodyProgress> {
        let purpose = Purpose::CustodyConfigure(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        if policy
            != &authorization
                .policies()
                .provider(self.authority.provider_id()?)?
                .custody
        {
            return Err(invalid(
                "custody configuration differs from authorized policy",
            ));
        }
        self.validate_policy(policy)?;
        let directory = self.authority.directory.ensure_child("configure")?;
        let original = self.select_configuration(&directory, policy, deadline)?;
        self.select_generated_attempt(
            &directory,
            &original,
            &HistoryScope::FixedBody,
            authorization,
            deadline,
        )?;
        self.advance(
            CustodyPurpose::Configure,
            deadline,
            Mode::SubmitAuthorized(authorization),
            false,
        )
    }
    pub(super) fn advance_enroll_selected(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedCustodyProgress> {
        let purpose = Purpose::CustodyEnroll(self.authority.provider_id()?);
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        let provider_policies = authorization
            .policies()
            .provider(self.authority.provider_id()?)?;
        if policy != &provider_policies.custody {
            return Err(invalid("custody enrollment differs from authorized policy"));
        }
        self.validate_policy(policy)?;
        let (configured, finalized) = self.retained_configuration(deadline)?;
        if configured != *policy {
            return Err(invalid("original Configure policy differs from enrollment"));
        }
        let existing = BodyHistory::open(self, CustodyPurpose::InitialEnroll)?;
        if let Some(history) = &existing {
            history.matches_policy(policy)?;
            if history.fees() != authorization.fees() {
                return Err(invalid("generated enrollment fees changed"));
            }
        }
        let preserve = existing
            .as_ref()
            .map(|history| -> Result<bool> {
                Ok(!history.has_pending()
                    && history.original()?.is_some()
                    && (history.preserve_paid_body(self)? || !history.body_expired()?))
            })
            .transpose()?
            .unwrap_or(false);
        let history = if preserve {
            existing.ok_or_else(|| invalid("selected enrollment absent"))?
        } else {
            let terms = authorization.terms(deadline, Some(policy.active_until_unix_ms))?;
            let interval = provider_policies
                .initial_enrollment(now_ms()?, terms.requested_deadline_unix_ms)?;
            let (unsigned, current) =
                self.select_initial_unsigned(policy, &finalized, interval, deadline)?;
            let turn = SigningTurn::Generated(authorization);
            let history = match existing {
                None => BodyHistory::initialize(
                    self,
                    CustodyPurpose::InitialEnroll,
                    unsigned.clone(),
                    authorization.fees(),
                    &turn,
                    deadline,
                )?,
                Some(history) => history,
            }
            .finish_pending(self, &current, &turn, deadline)?;
            if history.body_expired()? {
                history
                    .reserve_successor(self, unsigned, &current, authorization, deadline)?
                    .finish_pending(self, &current, &turn, deadline)?
            } else {
                history
            }
        };
        authorization.validate(&self.authority, purpose, deadline)?;
        let (directory, original, scope) = history.dispatch()?;
        self.select_generated_attempt(directory, original, scope, authorization, deadline)?;
        let selected = history.into_reparsed_selected(self)?;
        self.advance_selected(
            CustodyPurpose::InitialEnroll,
            selected,
            deadline,
            Mode::SubmitAuthorized(authorization),
            false,
        )
    }
    fn select_generated_attempt(
        &mut self,
        directory: &PrivateDirectory,
        original: &Original,
        scope: &HistoryScope,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
    ) -> Result<()> {
        let purpose = original.dispatch_purpose()?;
        let account = self.wallet()?;
        let body_expiry = match &original.action {
            Action::Configure(_) => None,
            Action::Enroll { validity, .. } => Some(validity.expires_at_unix_ms),
        };
        let account = authorization.bind_account(account)?;
        attempts::generated(
            directory,
            purpose,
            original.digest()?,
            scope,
            authorization,
            deadline,
            body_expiry,
            |attempt| {
                original
                    .request(attempt.terms(), attempt.observation()?, deadline)?
                    .inspect_in_parent(&account, attempt.directory())
            },
            |attempt| {
                original
                    .request(attempt.terms(), attempt.observation()?, deadline)?
                    .retire(&account, &attempt.wallet_path())
            },
            |attempt, observation, deadline| {
                original
                    .request(attempt.terms(), observation, deadline)?
                    .retain(&account, &attempt.wallet_path())
            },
            |_, deadline| self.fresh_original_predecessor(original, deadline),
            |attempt| match &original.action {
                Action::Configure(_) => Ok(true),
                Action::Enroll { validity, .. } => {
                    let now = now_ms()?;
                    if now >= validity.expires_at_unix_ms {
                        return Err(ManagedBootstrapFailure::EnrollmentExpired.into());
                    }
                    let observed = attempt
                        .observation()?
                        .enrollment_observed_at_unix_ms
                        .ok_or_else(|| invalid("enrollment observation absent"))?;
                    Ok(observed <= now
                        && now - observed <= original.control()?.policy.max_anchor_age_ms)
                }
            },
        )?;
        authorization.check(purpose, deadline)?;
        self.authority.validate_profile()?;
        Ok(())
    }
    /// A fresh paid observation is admitted only after the original certified anchor and the
    /// current native record independently agree. This never selects another attester body.
    fn fresh_original_predecessor(
        &mut self,
        original: &Original,
        deadline: Instant,
    ) -> Result<Observation> {
        self.authority.validate_profile()?;
        let checkpoint = self.authority.decode_checkpoint(&original.checkpoint)?;
        let historical = self.read_current(&original.selection.binding, &checkpoint, deadline)?;
        let (_, current) = self.observe(&original.selection.binding, deadline)?;
        self.fresh_predecessor_observation(original, &historical, &current, deadline)
    }

    // Both inputs are opaque native proofs. This owns the exact predecessor/body predicate;
    // transport and genuine native component fixtures supply proofs through the same verifier.
    fn fresh_predecessor_observation(
        &self,
        original: &Original,
        historical: &VerifiedStreamTokenCustodyStateV1,
        current: &VerifiedStreamTokenCustodyStateV1,
        deadline: Instant,
    ) -> Result<Observation> {
        self.authority.validate_profile()?;
        let checkpoint = self.authority.decode_checkpoint(&original.checkpoint)?;
        let tip = checkpoint
            .verified_tip_ref()
            .map_err(|_| invalid("invalid custody checkpoint"))?;
        if historical.height() != checkpoint.checkpoint().height()
            || historical.context_id() != tip.context_id()
            || !matches_predecessor(
                &original.selection,
                historical.current().map(|record| record.record()),
            )
        {
            return Err(ManagedBootstrapFailure::EnrollmentPredecessorChanged.into());
        }
        if !matches_predecessor(
            &original.selection,
            current.current().map(|record| record.record()),
        ) {
            return Err(ManagedBootstrapFailure::EnrollmentPredecessorChanged.into());
        }
        let observed = now_ms()?;
        let observation = match &original.action {
            Action::Configure(_) => Observation::ordinary(),
            Action::Enroll {
                validity,
                anchor,
                enrollment,
                ..
            } => {
                if observed >= validity.expires_at_unix_ms {
                    return Err(ManagedBootstrapFailure::EnrollmentExpired.into());
                }
                let control = original.control()?;
                sorafs_manifest::signer::custody::verify_signer_custody_enrollment_v1(
                    enrollment,
                    &original.selection.binding,
                    &control.policy.custody_trust(),
                    &sorafs_manifest::signer::custody::SignerCustodyEnrollmentContextV1 {
                        now_unix_ms: observed,
                        anchor_observed_at_unix_ms: observed,
                        current_anchor: *anchor,
                        next_sequence: control.next_sequence,
                        predecessor_digest: control.predecessor_digest,
                        signer_revoked: control.signer_revoked,
                        attester_revoked: control.attester_revoked,
                    },
                )
                .map_err(|_| invalid("original attester body no longer admits this dispatch"))?;
                Observation {
                    enrollment_observed_at_unix_ms: Some(observed),
                }
            }
        };
        self.authority.validate_profile()?;
        require_deadline(deadline)?;
        Ok(observation)
    }

    /// Recover and advance only the original Configure, with a fresh finite I/O deadline.
    /// # Errors
    /// Rejects changed custody/context, wallet evidence or native finality. This cannot renew UTC
    /// authorization; the wallet's retained pre-dispatch marker permits at most one send.
    pub fn advance_configure(&mut self, deadline: Instant) -> Result<ManagedCustodyProgress> {
        self.advance(
            CustodyPurpose::Configure,
            deadline,
            Mode::SubmitOriginal,
            true,
        )
    }

    /// Recover and advance only the original Enroll without replacing its signed interval.
    /// # Errors
    /// Rejects changed custody/context, wallet evidence or native finality. Current proof is
    /// separate from original inclusion and can show custody changed after that transaction.
    pub fn advance_enroll(&mut self, deadline: Instant) -> Result<ManagedCustodyProgress> {
        self.advance(
            CustodyPurpose::InitialEnroll,
            deadline,
            Mode::SubmitOriginal,
            true,
        )
    }

    pub(super) fn recover_configure_selected_if_present(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedCustodyProgress>> {
        self.recover_selected(
            policy,
            fees,
            deadline,
            CustodyPurpose::Configure,
            Mode::ObserveOnly,
        )
    }
    pub(super) fn recover_configure_local_selected_if_present(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedCustodyProgress>> {
        self.recover_selected(
            policy,
            fees,
            deadline,
            CustodyPurpose::Configure,
            Mode::ObserveLocal,
        )
    }
    pub(super) fn recover_enroll_selected_if_present(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedCustodyProgress>> {
        self.recover_selected(
            policy,
            fees,
            deadline,
            CustodyPurpose::InitialEnroll,
            Mode::ObserveOnly,
        )
    }
    pub(super) fn recover_enroll_local_selected_if_present(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedCustodyProgress>> {
        self.recover_selected(
            policy,
            fees,
            deadline,
            CustodyPurpose::InitialEnroll,
            Mode::ObserveLocal,
        )
    }
    fn recover_selected(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        fees: &Fees,
        deadline: Instant,
        purpose: CustodyPurpose,
        mode: Mode<'_>,
    ) -> Result<Option<ManagedCustodyProgress>> {
        // One recovery may reuse only the existing two exact, validated epoch contexts.
        // Every original source, wallet, carrier and active decode admission remains fresh.
        let mut validation = EpochValidationScope::new();
        let result = self.recover_selected_with_validation(
            policy,
            fees,
            deadline,
            purpose,
            mode,
            Some(&mut validation),
        );
        drop(validation);
        result
    }

    fn recover_selected_with_validation(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        fees: &Fees,
        deadline: Instant,
        purpose: CustodyPurpose,
        mode: Mode<'_>,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<Option<ManagedCustodyProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        if purpose != CustodyPurpose::Configure {
            if purpose != CustodyPurpose::InitialEnroll {
                return Err(invalid("bootstrap cannot recover renewal as initial"));
            }
            let Some(history) = BodyHistory::open_with_imports(
                self,
                purpose,
                &mut CheckpointImports::new(&self.authority, validation.as_deref_mut()),
            )?
            else {
                return Ok(None);
            };
            history.matches_policy(policy)?;
            if history.fees() != fees {
                return Err(invalid("enrollment recovery fees changed"));
            }
            let expired = history.body_expired()?;
            match history.into_selected() {
                Ok(selected) => {
                    return self
                        .advance_selected_with_validation(
                            purpose, selected, deadline, mode, false, validation,
                        )
                        .map(Some);
                }
                Err(super::Error::Bootstrap(ManagedBootstrapFailure::TransitionPending)) => {
                    return Ok(Some(ManagedCustodyProgress {
                        transaction_status: if expired {
                            OperationStatus::Expired
                        } else {
                            OperationStatus::Absent
                        },
                        finalized: None,
                        current: None,
                    }));
                }
                Err(error) => return Err(error),
            }
        }
        let Some(directory) = self.authority.directory.open_child_optional("configure")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            return Ok(None);
        };
        self.validate_original_with_imports(
            &original,
            purpose,
            &mut CheckpointImports::new(&self.authority, validation.as_deref_mut()),
        )?;
        original.matches_configuration(policy)?;
        let history = attempts::History::read(
            &directory,
            original.dispatch_purpose()?,
            original.digest()?,
            &HistoryScope::FixedBody,
        )?;
        history.require_fees(fees)?;
        let selected = Selected::from_history(original, history)?;
        self.advance_selected_with_validation(purpose, selected, deadline, mode, false, validation)
            .map(Some)
    }

    fn advance(
        &mut self,
        purpose: CustodyPurpose,
        deadline: Instant,
        mode: Mode<'_>,
        observe_current: bool,
    ) -> Result<ManagedCustodyProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let original = if purpose == CustodyPurpose::Configure {
            let operation = self.authority.directory.open_child("configure")?;
            journal::required_original(&operation)?
        } else {
            self.required_enrollment(purpose)?
        };
        self.advance_selected_validated(purpose, original, deadline, mode, observe_current)
    }

    // All loaders and consuming enrollment transitions join this one advance implementation.
    // A selection owns its original native graph; no second enrollment root is opened here.
    fn advance_selected(
        &mut self,
        purpose: CustodyPurpose,
        original: Selected<Original>,
        deadline: Instant,
        mode: Mode<'_>,
        observe_current: bool,
    ) -> Result<ManagedCustodyProgress> {
        self.advance_selected_with_validation(
            purpose,
            original,
            deadline,
            mode,
            observe_current,
            None,
        )
    }

    fn advance_selected_with_validation(
        &mut self,
        purpose: CustodyPurpose,
        original: Selected<Original>,
        deadline: Instant,
        mode: Mode<'_>,
        observe_current: bool,
        validation: Option<&mut EpochValidationScope>,
    ) -> Result<ManagedCustodyProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.advance_selected_validated_with_validation(
            purpose,
            original,
            deadline,
            mode,
            observe_current,
            validation,
        )
    }

    fn advance_selected_validated(
        &mut self,
        purpose: CustodyPurpose,
        original: Selected<Original>,
        deadline: Instant,
        mode: Mode<'_>,
        observe_current: bool,
    ) -> Result<ManagedCustodyProgress> {
        self.advance_selected_validated_with_validation(
            purpose,
            original,
            deadline,
            mode,
            observe_current,
            None,
        )
    }

    fn advance_selected_validated_with_validation(
        &mut self,
        purpose: CustodyPurpose,
        original: Selected<Original>,
        deadline: Instant,
        mode: Mode<'_>,
        observe_current: bool,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<ManagedCustodyProgress> {
        let directory = original.directory();
        self.validate_original_with_imports(
            &original,
            purpose,
            &mut CheckpointImports::new(&self.authority, validation.as_deref_mut()),
        )?;
        if matches!(purpose, CustodyPurpose::Renewal(_)) {
            self.validate_renewal_context(&original, deadline)?;
        }
        let journal_path = directory.path().join("transaction");
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open custody wallet"))?;
        let account = mode.bind_account(account)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                intent
                    .request(attempt.terms(), attempt.observation()?, deadline)?
                    .inspect_in_parent(&account, attempt.directory())
            })
        };
        verify_custody()?;
        let preparation = original
            .request(deadline)?
            .inspect_in_parent(&account, directory)?;
        let unprepared_expired = preparation.unprepared_status() == Some(OperationStatus::Expired);
        let retained_transaction = match preparation.phase() {
            iroha_wallet::operations::NativePreparationPhase::Missing
            | iroha_wallet::operations::NativePreparationPhase::RequestOnly
            | iroha_wallet::operations::NativePreparationPhase::PayloadRetained => None,
            iroha_wallet::operations::NativePreparationPhase::Signed => {
                Some(preparation.into_signed_transaction().map_err(|_| {
                    invalid("retained custody preparation has no signed transaction")
                })?)
            }
            iroha_wallet::operations::NativePreparationPhase::Retired => {
                return Err(invalid("original custody wallet request was retired"));
            }
        };
        let needs_prepare = retained_transaction.is_none();
        if let Some(transaction) = &retained_transaction
            && let Some(finalized) = {
                let mut imports =
                    CheckpointImports::new(&self.authority, validation.as_deref_mut());
                imports.retained_finality(&directory, transaction)?
            }
        {
            // Immutable original inclusion survives a current peer/quorum outage. Freshness
            // remains a separate best-effort observation and cannot renew that historical fact.
            let current = observe_current
                .then(|| self.observe(&original.selection.binding, deadline).ok())
                .flatten()
                .map(|(_, current)| current);
            verify_custody()?;
            return Ok(ManagedCustodyProgress {
                transaction_status: OperationStatus::Applied,
                finalized: Some(finalized),
                current,
            });
        }
        if matches!(mode, Mode::ObserveLocal) {
            return Ok(ManagedCustodyProgress {
                transaction_status: if needs_prepare {
                    if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                        OperationStatus::Expired
                    } else {
                        OperationStatus::Absent
                    }
                } else {
                    OperationStatus::Pending
                },
                finalized: None,
                current: None,
            });
        }
        if needs_prepare && matches!(mode, Mode::ObserveOnly) {
            // Parent recovery cannot create a wallet, quote fees, sign, or refresh current state.
            return Ok(ManagedCustodyProgress {
                transaction_status: if now_ms()? >= original.terms.signing_deadline_unix_ms
                    || unprepared_expired
                {
                    OperationStatus::Expired
                } else {
                    OperationStatus::Absent
                },
                finalized: None,
                current: None,
            });
        }
        if needs_prepare
            && (now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired)
        {
            let current = observe_current
                .then(|| self.observe(&original.selection.binding, deadline).ok())
                .flatten()
                .map(|(_, current)| current);
            return Ok(ManagedCustodyProgress {
                transaction_status: OperationStatus::Expired,
                finalized: None,
                current,
            });
        }
        let observed = self.authority.observe_finality(deadline)?;
        let current = self
            .read_current(&original.selection.binding, &observed, deadline)
            .ok();
        let unchanged = current.as_ref().is_some_and(|state| {
            matches_predecessor(
                &original.selection,
                state.current().map(|current| current.record()),
            )
        });
        if needs_prepare {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                return Ok(ManagedCustodyProgress {
                    transaction_status: OperationStatus::Expired,
                    finalized: None,
                    current,
                });
            }
            if !unchanged {
                return Err(invalid(
                    "fresh custody predecessor differs; original request cannot be re-signed",
                ));
            }
            verify_custody()?;
            mode.check_dispatch(original.dispatch_purpose()?, deadline)?;
            let signing_deadline = original.terms.signing_deadline(deadline)?;
            match original.request(signing_deadline)? {
                journal::Request::Configure(request) => {
                    account.prepare_stream_token_custody_configure(&request, &journal_path)
                }
                journal::Request::Enroll(request) => {
                    account.prepare_stream_token_custody_enroll(&request, &journal_path)
                }
            }
            .map_err(|_| {
                invalid("custody preparation failed; retain original request and journal")
            })?;
        }
        verify_custody()?;
        let transaction = match retained_transaction {
            Some(transaction) => transaction,
            None => self.verify_wallet(&directory, &original, deadline)?,
        };
        let mut report = match original.request(deadline)? {
            journal::Request::Configure(request) => {
                account.resume_stream_token_custody_configure(&journal_path, &request)
            }
            journal::Request::Enroll(request) => {
                account.resume_stream_token_custody_enroll(&journal_path, &request)
            }
        }
        .map_err(|_| invalid("custody transaction unresolved; recover its original journal"))?;
        if report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if mode.submits() && unchanged {
                verify_custody()?;
                mode.check_dispatch(original.dispatch_purpose()?, deadline)?;
                report = match original.request(deadline)? {
                    journal::Request::Configure(request) => {
                        account.submit_stream_token_custody_configure(&journal_path, &request)
                    }
                    journal::Request::Enroll(request) => {
                        account.submit_stream_token_custody_enroll(&journal_path, &request)
                    }
                }
                .map_err(|_| {
                    invalid("custody transaction unresolved; recover its original journal")
                })?;
            }
        }
        if matches!(mode, Mode::SubmitAuthorized(_)) && report.status == OperationStatus::Expired {
            return Err(super::ManagedBootstrapFailure::SignedUnresolved.into());
        }
        verify_custody()?;
        let finalized = if let Some(retained) = {
            let mut imports = CheckpointImports::new(&self.authority, validation.as_deref_mut());
            imports.retained_finality(&directory, &transaction)?
        } {
            Some(retained)
        } else {
            applied_carrier(
                &mut self.authority,
                report.status,
                deadline,
                ServiceAuthority::observe_finality,
                |authority, observed, deadline| {
                    authority.advance_carrier(
                        &directory,
                        &original.checkpoint,
                        &transaction,
                        &report,
                        observed,
                        deadline,
                    )
                },
            )?
        };
        // Refresh separately after any dispatch/replay; an old original inclusion never becomes
        // a claim that today's policy, revocation or enrollment head still agrees.
        let current = if observe_current {
            let observed = self.authority.observe_finality(deadline)?;
            self.read_current(&original.selection.binding, &observed, deadline)
                .ok()
        } else {
            None
        };
        verify_custody()?;
        Ok(ManagedCustodyProgress {
            transaction_status: report.status,
            finalized,
            current,
        })
    }

    fn observe(
        &mut self,
        binding: &SignerCustodyBindingV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedStreamTokenCustodyStateV1)> {
        let verifier = self.authority.observe_finality(deadline)?;
        let current = self.read_current(binding, &verifier, deadline)?;
        Ok((verifier, current))
    }

    fn read_current(
        &self,
        binding: &SignerCustodyBindingV1,
        verifier: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        let block = verifier
            .verified_tip_ref()
            .map_err(|_| invalid("invalid certified custody tip"))?;
        self.read_current_at(binding, block, deadline)
    }

    fn read_current_at(
        &self,
        binding: &SignerCustodyBindingV1,
        block: &VerifiedSumeragiBlock,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        require_deadline(deadline)?;
        block
            .verify_global_scope(
                self.authority.config.network_id,
                self.authority.config.chain.as_str(),
            )
            .map_err(|_| invalid("current custody cut differs from original Global scope"))?;
        let owner = self
            .authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)?;
        let schema = iroha_core::state::State::native_world_schema_hash_v1()
            .map_err(|_| invalid("native custody schema is unavailable"))?;
        read_selected_peers(&self.authority.peers, deadline, |client, deadline| {
            client
                .with_request_deadline(deadline)
                .get_stream_token_custody_state(
                    self.authority.provider_id()?,
                    owner,
                    binding,
                    schema,
                    block,
                )
                .map_err(|_| invalid("native custody candidate is unavailable or invalid"))
        })
    }

    fn verify_wallet(
        &self,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        let account = AccountService::new(self.authority.config.clone())
            .map_err(|_| invalid("cannot open custody wallet"))?;
        original.verify_wallets(|intent, attempt| {
            intent
                .request(attempt.terms(), attempt.observation()?, deadline)?
                .inspect_in_parent(&account, attempt.directory())
        })?;
        let path = directory.path().join("transaction");
        match original.request(deadline)? {
            journal::Request::Configure(request) => {
                account.verify_stream_token_custody_configure_journal(&path, &request)
            }
            journal::Request::Enroll(request) => {
                account.verify_stream_token_custody_enroll_journal(&path, &request)
            }
        }
        .map_err(|_error| {
            #[cfg(test)]
            crate::managed::native_operation::deadline_diagnostics::wallet_error(
                "wallet signed journal verification",
                &_error,
            );
            invalid("custody wallet differs from original request")
        })
    }
}

/// Reuse the held purpose lock for a complete read-only enrollment reference census.
///
/// Outside active decode limits, two fresh bounded namespace observations select only slots
/// with a body or selection reference. Every selected slot uses the original full body reader.
/// The same names, retained directory, operation lock and complete profile close every ordinary
/// outcome. This consolidates absence observations; it is not an atomic snapshot. Material
/// appearing and disappearing between both observations is not observed. Closing custody or
/// namespace errors can supersede an earlier body error. Active limits retain the original
/// ordered 64-slot reader, including its allocation and error order.
pub(in crate::managed) fn validate_enrollment_inventory(authority: ServiceAuthority) -> Result<()> {
    let owner = ManagedStreamTokenCustody { authority };
    validate_enrollment_slots(&owner, |owner, purpose| {
        BodyHistory::open(owner, purpose).map(|_| ())
    })
}

fn validate_enrollment_slots(
    owner: &ManagedStreamTokenCustody,
    mut inspect: impl FnMut(&ManagedStreamTokenCustody, CustodyPurpose) -> Result<()>,
) -> Result<()> {
    if norito::core::decode_limits_active() {
        inspect(owner, CustodyPurpose::InitialEnroll)?;
        for sequence in 2..=64 {
            inspect(owner, CustodyPurpose::Renewal(sequence))?;
        }
        return Ok(());
    }

    // The outer bootstrap census still owns unknown-name and dependency-order admission.
    // This independent fresh census shares only joint absence, never present-body validation.
    let result = owner.authority.directory.read_scope(|scope| {
        let names = scope.entries(131)?;
        let result = (|| {
            for purpose in std::iter::once(CustodyPurpose::InitialEnroll)
                .chain((2..=64).map(CustodyPurpose::Renewal))
            {
                let body = purpose.directory_name()?;
                let reference = format!("{body}-selection.nrt");
                if names
                    .binary_search_by(|name| name.as_os_str().cmp(std::ffi::OsStr::new(&body)))
                    .is_ok()
                    || names
                        .binary_search_by(|name| {
                            name.as_os_str().cmp(std::ffi::OsStr::new(&reference))
                        })
                        .is_ok()
                {
                    inspect(owner, purpose)?;
                }
            }
            Ok(())
        })();
        if scope.entries(131)? != names {
            return Err(invalid(
                "custody enrollment census changed during inspection",
            ));
        }
        result
    });
    owner.authority.validate_profile()?;
    result
}

// Submission can commit above the predecessor observed before dispatch. As for Reserve,
// refresh independently authenticated finality before selecting the exact native carrier.
// These callbacks use the same observation/replay owners in production and native fixtures;
// they confer no signing authority and always receive the unchanged operation deadline.
fn applied_carrier(
    authority: &mut ServiceAuthority,
    status: OperationStatus,
    deadline: Instant,
    observe: impl FnOnce(&mut ServiceAuthority, Instant) -> Result<FinalityVerifier>,
    replay: impl FnOnce(
        &ServiceAuthority,
        &FinalityVerifier,
        Instant,
    ) -> Result<Option<ManagedTransactionFinality>>,
) -> Result<Option<ManagedTransactionFinality>> {
    if status != OperationStatus::Applied {
        return Ok(None);
    }
    // An unavailable fresh observation leaves the original Applied wallet recoverable.
    let Ok(observed) = observe(authority, deadline) else {
        return Ok(None);
    };
    replay(authority, &observed, deadline)
}

fn matches_predecessor(
    selection: &StreamTokenCustodySelection,
    current: Option<
        &iroha_data_model::sorafs::stream_token_custody::StreamTokenCustodyControlRecordV1,
    >,
) -> bool {
    match current {
        None => {
            selection.current.is_none()
                && selection.expected_revision == 0
                && selection.expected_digest == [0; 32]
        }
        Some(current) => {
            selection.current.as_ref() == Some(current)
                && selection.expected_revision == current.revision
                && current
                    .canonical_digest()
                    .is_ok_and(|digest| digest == selection.expected_digest)
        }
    }
}

fn validate_interval(interval: ManagedCustodyEnrollmentInterval, now: u64) -> Result<()> {
    if interval.issued_at_unix_ms == 0
        || interval.issued_at_unix_ms > now
        || interval.expires_at_unix_ms <= now
        || interval.expires_at_unix_ms == u64::MAX
        || interval.deadline_unix_ms <= now
        || interval.deadline_unix_ms > interval.expires_at_unix_ms
    {
        return Err(invalid(
            "enrollment requires its original finite UTC interval",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "stream_token_custody/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stream_token_custody/transport_tests.rs"]
mod transport_tests;

#[cfg(test)]
#[path = "stream_token_custody/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "stream_token_custody/bootstrap_test_support.rs"]
mod bootstrap_test_support;

#[cfg(test)]
#[path = "stream_token_custody/renewal_tests.rs"]
mod renewal_tests;

#[cfg(test)]
#[path = "stream_token_custody/epoch_test_support.rs"]
mod epoch_test_support;

#[cfg(test)]
#[path = "stream_token_custody/recovery_scope_tests.rs"]
mod recovery_scope_tests;

#[cfg(test)]
#[path = "stream_token_custody/borrowed_tip_tests.rs"]
mod borrowed_tip_tests;

#[cfg(test)]
#[path = "stream_token_custody/enrollment_inventory_tests.rs"]
mod enrollment_inventory_tests;
