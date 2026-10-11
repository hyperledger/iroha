//! Bounded generated renewal using the same Enroll instruction, codec and wallet owner.

use super::*;
use crate::localnet::service_authorities::RetainedProviderServicePlan;
use iroha_data_model::sorafs::stream_token_custody::StreamTokenCustodyControlRecordV1;
use sorafs_manifest::signer::custody_control::SignerCustodyControlStateV1;
use std::borrow::Borrow;

#[path = "renewal/generated.rs"]
mod generated;
pub(in crate::managed) use generated::{
    GeneratedRenewalAuthorization, GeneratedRenewalTurn, Reconciliation,
};

#[cfg(test)]
pub(in crate::managed::stream_token_custody) use generated::RenewalReads;

// Local generated-profile bound, not a native protocol revision or sequence limit.
const MAX_GENERATED_SEQUENCE: u64 = 64;

pub(in crate::managed) fn directory_name(sequence: u64) -> Result<String> {
    if !(2..=MAX_GENERATED_SEQUENCE).contains(&sequence) {
        return Err(invalid(
            "generated custody renewal sequence must be between 2 and 64",
        ));
    }
    Ok(format!("renew-{sequence:016x}"))
}

impl ManagedStreamTokenCustody {
    /// Select a new finite generated renewal from a fresh independent native head, then advance.
    ///
    /// The claimed sequence must equal native `next_sequence` in 2..=64. Selection is allowed
    /// only in the latter half of the previous signed interval, and must extend its expiry.
    /// Existing originals retain their original interval, fee caps and signing deadline.
    /// # Errors
    /// Rejects premature/exhausted renewal, changed policy, head/CAS, revoked identities,
    /// missing initial finality, provider expiry or substituted original terms/evidence.
    pub fn renew(
        &mut self,
        sequence: u64,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedCustodyProgress> {
        directory_name(sequence)?;
        require_deadline(options.deadline)?;
        self.authority.validate_profile()?;
        let purpose = CustodyPurpose::Renewal(sequence);
        let existing = BodyHistory::open(self, purpose)?;
        let history = if existing.as_ref().is_some_and(|history| {
            history.original().is_ok_and(|original| original.is_some()) && !history.has_pending()
        }) {
            existing.ok_or_else(|| invalid("renewal body absent"))?
        } else {
            let terms = Terms::new(deadline_unix_ms, options)?;
            let (policy, _) = self.retained_configuration(options.deadline)?;
            let (verifier, current) = self.observe(&policy.binding, options.deadline)?;
            let unsigned = self.select_renewal_unsigned(
                sequence,
                &policy,
                &current,
                &verifier,
                &terms,
                options.deadline,
            )?;
            let turn = SigningTurn::Explicit(&terms);
            let history = match existing {
                Some(history) => history,
                None => BodyHistory::initialize(
                    self,
                    purpose,
                    unsigned,
                    &terms.fees,
                    &turn,
                    options.deadline,
                )?,
            };
            history.finish_pending(self, &current, &turn, options.deadline)?
        };
        if history.fees() != &Fees::from_options(options)? {
            return Err(invalid("renewal original fee selection changed"));
        }
        let (directory, original, scope) = history.dispatch()?;
        journal::explicit(
            directory,
            original,
            deadline_unix_ms,
            options,
            &self.wallet()?,
            scope,
        )?;
        let selected = history.into_reparsed_selected(self)?;
        self.advance_selected(
            purpose,
            selected,
            options.deadline,
            Mode::SubmitOriginal,
            true,
        )
    }

    /// Advance only this immutable renewal, with no new interval or wallet resend permission.
    /// # Errors
    /// Rejects changed original evidence or current predecessor and expired I/O deadlines.
    pub fn advance_renewal(
        &mut self,
        sequence: u64,
        deadline: Instant,
    ) -> Result<ManagedCustodyProgress> {
        self.advance(
            CustodyPurpose::Renewal(sequence),
            deadline,
            Mode::SubmitOriginal,
            true,
        )
    }

    /// Recover one explicitly selected renewal without creating a wallet or sending.
    ///
    /// An absent renewal root returns `None` only when its selection reference is absent too.
    /// Existing empty or lost anchored material refuses without HTTP or filesystem publication.
    /// Exact retained successful carriers remain recoverable without current peer availability.
    /// # Errors
    /// Rejects unsafe custody or substituted profile/original/wallet/native carrier evidence.
    pub fn recover_renewal(
        &mut self,
        sequence: u64,
        deadline: Instant,
    ) -> Result<Option<ManagedCustodyProgress>> {
        directory_name(sequence)?;
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let Some(history) = BodyHistory::open(self, CustodyPurpose::Renewal(sequence))? else {
            return Ok(None);
        };
        let expired = history.body_expired()?;
        match history.into_selected() {
            Ok(_) => {}
            Err(super::super::Error::Bootstrap(ManagedBootstrapFailure::TransitionPending)) => {
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
        self.advance(
            CustodyPurpose::Renewal(sequence),
            deadline,
            Mode::ObserveOnly,
            false,
        )
        .map(Some)
    }

    pub(super) fn select_renewal_unsigned(
        &self,
        sequence: u64,
        policy: &SignerCustodyPolicyV1,
        current: &VerifiedStreamTokenCustodyStateV1,
        verifier: &FinalityVerifier,
        terms: &Terms,
        deadline: Instant,
    ) -> Result<body_history::UnsignedEnrollment> {
        directory_name(sequence)?;
        self.validate_policy(policy)?;
        let selected = current
            .current()
            .ok_or_else(|| invalid("renewal requires native custody head"))?;
        let tip = verifier
            .verified_tip()
            .map_err(|_| invalid("invalid renewal checkpoint"))?;
        if current.height() != verifier.checkpoint().height()
            || current.context_id() != tip.context_id()
            || selected.control().policy != *policy
        {
            return Err(invalid("renewal policy or certified cut differs"));
        }
        let now = now_ms()?;
        let interval = self.renewal_interval(
            selected.record(),
            selected.control(),
            sequence,
            now,
            terms.requested_deadline_unix_ms,
        )?;
        let unsigned = self.unsigned_enrollment(policy, current, verifier, interval, now)?;
        unsigned.validate_with_checkpoint(
            self,
            CustodyPurpose::Renewal(sequence),
            verifier,
            || self.authority.provider_plan(),
        )?;
        self.validate_unsigned_renewal_context_at(&unsigned, verifier, deadline)?;
        Ok(unsigned)
    }

    pub(super) fn validate_unsigned_renewal_context_at(
        &self,
        unsigned: &body_history::UnsignedEnrollment,
        verifier: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<()> {
        self.validate_unsigned_renewal_context_with(
            unsigned,
            deadline,
            || self.retained_initial_prerequisite(deadline),
            || unsigned.matching_checkpoint(self, verifier),
        )
    }

    pub(super) fn validate_unsigned_renewal_context_using(
        &self,
        unsigned: &body_history::UnsignedEnrollment,
        deadline: Instant,
        prerequisite: impl FnOnce() -> Result<enrollment::RetainedInitialPrerequisite>,
    ) -> Result<()> {
        self.validate_unsigned_renewal_context_with(unsigned, deadline, prerequisite, || {
            self.authority.decode_checkpoint(&unsigned.checkpoint)
        })
    }

    pub(super) fn validate_unsigned_renewal_context_with_imports(
        &self,
        unsigned: &body_history::UnsignedEnrollment,
        deadline: Instant,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
    ) -> Result<()> {
        let prerequisite = self.retained_initial_prerequisite_with_imports(deadline, imports)?;
        let policy = prerequisite.policy;
        let initial = prerequisite.enrollment;
        let checkpoint = imports.decode(&unsigned.checkpoint)?;
        self.require_unsigned_renewal_prerequisite(
            unsigned,
            &policy,
            &initial,
            &checkpoint,
            deadline,
        )
    }

    fn validate_unsigned_renewal_context_with<V: Borrow<FinalityVerifier>>(
        &self,
        unsigned: &body_history::UnsignedEnrollment,
        deadline: Instant,
        prerequisite: impl FnOnce() -> Result<enrollment::RetainedInitialPrerequisite>,
        checkpoint: impl FnOnce() -> Result<V>,
    ) -> Result<()> {
        let prerequisite = prerequisite()?;
        let policy = prerequisite.policy;
        let initial = prerequisite.enrollment;
        let checkpoint = checkpoint()?;
        let checkpoint = checkpoint.borrow();
        self.require_unsigned_renewal_prerequisite(
            unsigned, &policy, &initial, checkpoint, deadline,
        )
    }

    fn require_unsigned_renewal_prerequisite(
        &self,
        unsigned: &body_history::UnsignedEnrollment,
        policy: &SignerCustodyPolicyV1,
        initial: &RetainedCustodyEnrollment,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<()> {
        let selected = body_history::selected_policy(&unsigned.selection)?;
        if selected != *policy || checkpoint.checkpoint().height() < initial.finalized().height {
            return Err(invalid(
                "renewal predecessor differs from original initial enrollment",
            ));
        }
        self.authority.validate_profile()?;
        require_deadline(deadline)
    }
    pub(super) fn validate_renewal_context(
        &self,
        original: &Original,
        deadline: Instant,
    ) -> Result<()> {
        let prerequisite = self.retained_initial_prerequisite(deadline)?;
        let policy = prerequisite.policy;
        let initial = prerequisite.enrollment;
        original.matches_enrollment_policy(&policy)?;
        let checkpoint = self.authority.decode_checkpoint(&original.checkpoint)?;
        if checkpoint.checkpoint().height() < initial.finalized().height {
            return Err(invalid("renewal predecessor predates initial enrollment"));
        }
        self.authority.validate_profile()?;
        require_deadline(deadline)
    }

    pub(super) fn validate_renewal_original<P: Borrow<RetainedProviderServicePlan>>(
        &self,
        original: &Original,
        control: &SignerCustodyControlStateV1,
        sequence: u64,
        provider_plan: impl FnOnce() -> Result<P>,
    ) -> Result<()> {
        let Action::Enroll {
            validity,
            selected_at_unix_ms,
            ..
        } = &original.action
        else {
            return Err(invalid("renewal journal has another purpose"));
        };
        let current = original
            .selection
            .current
            .as_ref()
            .ok_or_else(|| invalid("renewal predecessor absent"))?;
        let expected = validate_renewal_validity(
            current,
            control,
            sequence,
            *selected_at_unix_ms,
            provider_plan,
        )?;
        if *validity != expected {
            return Err(invalid("renewal differs from original finite interval"));
        }
        Ok(())
    }

    fn renewal_interval(
        &self,
        current: &StreamTokenCustodyControlRecordV1,
        control: &SignerCustodyControlStateV1,
        sequence: u64,
        observed: u64,
        deadline: u64,
    ) -> Result<ManagedCustodyEnrollmentInterval> {
        let validity = self.renewal_validity(current, control, sequence, observed)?;
        let interval = validity.interval(deadline);
        validate_interval(interval, observed)?;
        Ok(interval)
    }
    pub(super) fn renewal_validity(
        &self,
        current: &StreamTokenCustodyControlRecordV1,
        control: &SignerCustodyControlStateV1,
        sequence: u64,
        observed: u64,
    ) -> Result<journal::EnrollmentValidity> {
        validate_renewal_validity(current, control, sequence, observed, || {
            self.authority.provider_plan()
        })
    }
}

// A caller may share its freshly validated immutable provider plan only within the same
// local validation bundle. Native control, evidence and live clocks remain independently checked.
pub(super) fn validate_renewal_validity<P: Borrow<RetainedProviderServicePlan>>(
    current: &StreamTokenCustodyControlRecordV1,
    control: &SignerCustodyControlStateV1,
    sequence: u64,
    observed: u64,
    provider_plan: impl FnOnce() -> Result<P>,
) -> Result<journal::EnrollmentValidity> {
    directory_name(sequence)?;
    control
        .validate()
        .map_err(|_| invalid("invalid governed renewal control"))?;
    if control.signer_revoked || control.attester_revoked || control.next_sequence != sequence {
        return Err(invalid("renewal requires exact unrevoked native sequence"));
    }
    current
        .validate_active_enrollment(control)
        .map_err(|_| invalid("renewal active enrollment differs from native head"))?;
    let previous = enrollment::decode_enrollment(
        current
            .active_enrollment
            .as_deref()
            .ok_or_else(|| invalid("renewal requires original active enrollment"))?,
    )?;
    // Ordinary callers acquire here, preserving the native validation/error order; a body
    // parser supplies only its own already-validated plan for this pure comparison bundle.
    let plan = provider_plan()?;
    let plan = plan.borrow();
    let provider_end = plan
        .admission_material()
        .retention_epoch
        .checked_mul(1_000)
        .ok_or_else(|| invalid("provider expiry overflows milliseconds"))?;
    let provider_start = plan
        .admission_material()
        .issued_at
        .checked_mul(1_000)
        .ok_or_else(|| invalid("provider beginning overflows milliseconds"))?;
    if observed < provider_start {
        return Err(invalid("renewal predates original provider interval"));
    }
    renewal_validity(&previous.statement, &control.policy, observed, provider_end)
}

pub(super) fn renewal_interval(
    previous: &SignerCustodyStatementV1,
    policy: &SignerCustodyPolicyV1,
    observed: u64,
    provider_end: u64,
    deadline: u64,
) -> Result<ManagedCustodyEnrollmentInterval> {
    let validity = renewal_validity(previous, policy, observed, provider_end)?;
    let interval = validity.interval(deadline);
    validate_interval(interval, observed)?;
    Ok(interval)
}
fn renewal_validity(
    previous: &SignerCustodyStatementV1,
    policy: &SignerCustodyPolicyV1,
    observed: u64,
    provider_end: u64,
) -> Result<journal::EnrollmentValidity> {
    let duration = previous
        .expires_at_unix_ms
        .checked_sub(previous.issued_at_unix_ms)
        .filter(|duration| *duration > 0)
        .ok_or_else(|| invalid("previous custody interval is invalid"))?;
    let midpoint = previous
        .issued_at_unix_ms
        .checked_add(duration.div_ceil(2))
        .ok_or_else(|| invalid("previous custody midpoint overflows"))?;
    if observed < midpoint || observed < policy.active_from_unix_ms {
        return Err(invalid("generated custody renewal is premature"));
    }
    let expires = observed
        .checked_add(policy.max_validity_ms)
        .ok_or_else(|| invalid("renewal interval overflows"))?
        .min(policy.active_until_unix_ms)
        .min(provider_end);
    if expires <= previous.expires_at_unix_ms {
        return Err(invalid(
            "original custody/provider interval cannot be extended",
        ));
    }
    if observed == 0 || expires <= observed || expires == u64::MAX {
        return Err(invalid(
            "enrollment requires its original finite UTC interval",
        ));
    }
    Ok(journal::EnrollmentValidity {
        issued_at_unix_ms: observed,
        expires_at_unix_ms: expires,
    })
}
