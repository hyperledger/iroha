//! Closed generated renewal reconciliation, sharing the one native attempt and wallet owners.
use super::*;
use crate::managed::native_operation::{
    Fees,
    authorization::{self, DispatchAuthorization, Lease, Scope},
    require_retained_material,
};
use crate::managed::service_authority::CheckpointImports;
use iroha_data_model::sorafs::stream_token_custody::proof::VerifiedStreamTokenCustodyRecordV1;
use iroha_data_model::sumeragi_finality::EpochValidationScope;
use std::sync::{Arc, atomic::AtomicBool};

/// Closed I/O boundary only; successful inputs still come from the sole native proof owners.
/// Production always uses NativeReads. Genuine component fixtures supply the existing native
/// FinalitySource without installing a runtime override or a parallel proof verifier.
pub(in crate::managed::stream_token_custody) trait RenewalReads {
    fn observe(
        &self,
        owner: &mut ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedStreamTokenCustodyStateV1)>;
    fn retain_carrier(
        &self,
        authority: &ServiceAuthority,
        directory: &PrivateDirectory,
        checkpoint: &[u8],
        transaction: &SignedTransaction,
        height: u64,
        observed_height: u64,
        deadline: Instant,
    ) -> Result<()>;
}
struct NativeReads;
impl RenewalReads for NativeReads {
    fn observe(
        &self,
        owner: &mut ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedStreamTokenCustodyStateV1)> {
        owner.observe(&policy.binding, deadline)
    }
    fn retain_carrier(
        &self,
        authority: &ServiceAuthority,
        directory: &PrivateDirectory,
        checkpoint: &[u8],
        transaction: &SignedTransaction,
        height: u64,
        observed_height: u64,
        deadline: Instant,
    ) -> Result<()> {
        authority.advance_carrier_at(
            directory,
            checkpoint,
            transaction,
            height,
            observed_height,
            deadline,
        )?;
        Ok(())
    }
}

/// One fresh finite generated turn. Polling keeps this exact value; records cannot construct it.
pub(in crate::managed) struct GeneratedRenewalTurn {
    prepared: PreparedLocalnet,
    provider: iroha_data_model::sorafs::capacity::ProviderId,
    policy: SignerCustodyPolicyV1,
    fees: Fees,
    floor: ManagedTransactionFinality,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    authorization: Option<GeneratedRenewalAuthorization>,
    issuance_consumed: bool,
}
/// Purpose-closed scope around the shared epoch owner. It is not current custody evidence.
pub(in crate::managed) struct GeneratedRenewalAuthorization {
    lease: Lease,
    purpose: Purpose,
}
impl DispatchAuthorization for GeneratedRenewalAuthorization {
    fn lease(&self) -> &Lease {
        &self.lease
    }
    fn purpose(&self) -> Purpose {
        self.purpose
    }
}
/// Current means the exact original head passed the existing current-use verifier at this cut.
/// It remains an observation; the renderer and daemon must independently requalify their use.
pub(in crate::managed) enum Reconciliation {
    Current(RetainedCustodyEnrollment),
    Pending(ManagedCustodyProgress),
}
// Sequential local phases borrow the same authenticated cut and move the same body graph.
// This is control flow within one call, not a new authorization or retained observation.
enum RenewalMaterial<'a> {
    Current(RetainedCustodyEnrollment),
    Pending(PendingRenewal<'a>),
}
struct PendingRenewal<'a> {
    selected: &'a VerifiedStreamTokenCustodyRecordV1,
    control: &'a SignerCustodyControlStateV1,
    next: u64,
    existing: Option<BodyHistory>,
    _retained: RetainedCustodyEnrollment,
}
impl GeneratedRenewalTurn {
    pub(in crate::managed) fn begin(
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        fees: Fees,
        floor: ManagedTransactionFinality,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut validation = EpochValidationScope::new();
        let mut imports = CheckpointImports::new(&owner.authority, Some(&mut validation));
        let result = Self::begin_with_imports(
            owner,
            policy,
            fees,
            floor,
            deadline,
            cancelled,
            &mut imports,
        );
        drop(imports);
        drop(validation);
        result
    }

    fn begin_with_imports(
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        fees: Fees,
        floor: ManagedTransactionFinality,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<Self> {
        #[cfg(test)]
        crate::managed::native_operation::deadline_diagnostics::begin_phase(
            crate::managed::native_operation::deadline_diagnostics::BeginPhase::Entry,
        );
        authorization::require_active(&cancelled)?;
        require_deadline(deadline)?;
        owner.authority.validate_profile()?;
        owner.validate_policy(policy)?;
        #[cfg(test)]
        crate::managed::native_operation::deadline_diagnostics::begin_phase(
            crate::managed::native_operation::deadline_diagnostics::BeginPhase::Configure,
        );
        let (configured, _) = owner.retained_configuration_with_imports(deadline, imports)?;
        if configured != *policy || floor.height < 2 || *floor.block_hash.as_ref() == [0; 32] {
            return Err(invalid(
                "renewal turn differs from original configured policy or carrier",
            ));
        }
        fees.validate()?;
        #[cfg(test)]
        crate::managed::native_operation::deadline_diagnostics::begin_phase(
            crate::managed::native_operation::deadline_diagnostics::BeginPhase::Inventory,
        );
        require_retained_material(
            owner.validate_renewal_selection_inventory_with_imports(&fees, deadline, imports),
        )?;
        Ok(Self {
            prepared: owner.authority.prepared.clone(),
            provider: owner.authority.provider_id()?,
            policy: policy.clone(),
            fees,
            floor,
            deadline,
            cancelled,
            authorization: None,
            issuance_consumed: false,
        })
    }
    fn check<'a>(
        &self,
        owner: &'a ManagedStreamTokenCustody,
        deadline: Instant,
    ) -> Result<(Instant, enrollment::RetainedConfiguration<'a>)> {
        authorization::require_active(&self.cancelled)?;
        let deadline = deadline.min(self.deadline);
        require_deadline(deadline)?;
        owner.authority.validate_profile()?;
        if self.prepared != owner.authority.prepared
            || self.provider != owner.authority.provider_id()?
        {
            return Err(invalid("renewal turn changed original profile or provider"));
        }
        let configured = owner.read_configuration(deadline)?;
        if configured.policy() != &self.policy {
            return Err(invalid("renewal turn changed original full custody policy"));
        }
        Ok((deadline, configured))
    }
    pub(in crate::managed::stream_token_custody) fn check_selection(
        &self,
        purpose: Purpose,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<()> {
        authorization::require_active(&self.cancelled)?;
        require_deadline(deadline.min(self.deadline))?;
        if !matches!(purpose, Purpose::CustodyRenewal { provider, sequence: 2..=64 } if provider == self.provider)
            || fees != &self.fees
        {
            return Err(invalid(
                "renewal selection differs from live original scope",
            ));
        }
        Ok(())
    }
    /// The sole finite issuer binds stable outer selection, never whichever body is active.
    pub(in crate::managed::stream_token_custody) fn authorize_retained(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        history: &BodyHistory,
        deadline: Instant,
    ) -> Result<&GeneratedRenewalAuthorization> {
        let (deadline, configured) = self.check(owner, deadline)?;
        let purpose = history.purpose();
        let Purpose::CustodyRenewal { provider, sequence } = purpose else {
            return Err(invalid("renewal issuer selected another purpose"));
        };
        self.check_selection(purpose, history.fees(), deadline)?;
        history.matches_policy(&self.policy)?;
        history.validate_renewal_context(owner, deadline, || {
            configured.into_initial_prerequisite(deadline)
        })?;
        if self.authorization.is_none() {
            if self.issuance_consumed {
                return Err(ManagedBootstrapFailure::TransitionPending.into());
            }
            self.issuance_consumed = true;
            let plan = owner.authority.provider_plan()?;
            let expires = self.policy.active_until_unix_ms.min(
                plan.admission_material()
                    .retention_epoch
                    .checked_mul(1000)
                    .ok_or_else(|| invalid("provider interval overflow"))?,
            );
            #[cfg(test)]
            begin_scope_tests::before_lease_root_selection();
            let lease = Lease::issue(
                history.root().retain()?,
                history.outer_bytes()?,
                &self.fees,
                Scope::Renewal { provider, sequence },
                expires,
                deadline,
                Arc::clone(&self.cancelled),
            )?;
            self.authorization = Some(GeneratedRenewalAuthorization { lease, purpose });
        }
        let authorization = self
            .authorization
            .as_ref()
            .ok_or_else(|| invalid("renewal authorization absent"))?;
        authorization.check(purpose, deadline)?;
        Ok(authorization)
    }
}
impl ManagedStreamTokenCustody {
    fn validate_renewal_selection_inventory_with_imports(
        &self,
        fees: &Fees,
        deadline: Instant,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<()> {
        // Bounded full reference census, never a native sequence selector.
        for sequence in 2..=64 {
            #[cfg(test)]
            crate::managed::native_operation::deadline_diagnostics::inventory(
                sequence,
                crate::managed::native_operation::deadline_diagnostics::InventoryPhase::Guard,
            );
            require_deadline(deadline)?;
            #[cfg(test)]
            crate::managed::native_operation::deadline_diagnostics::inventory(
                sequence,
                crate::managed::native_operation::deadline_diagnostics::InventoryPhase::Open,
            );
            if let Some(history) =
                BodyHistory::open_with_imports(self, CustodyPurpose::Renewal(sequence), imports)?
            {
                if history.fees() != fees {
                    return Err(invalid("renewal original fees changed"));
                }
                #[cfg(test)]
                crate::managed::native_operation::deadline_diagnostics::inventory(
                    sequence,
                    crate::managed::native_operation::deadline_diagnostics::InventoryPhase::Context,
                );
                history.validate_renewal_context_with_imports(self, deadline, imports)?;
            }
        }
        Ok(())
    }
    pub(in crate::managed::stream_token_custody) fn original_renewal_if_present(
        &self,
        sequence: u64,
    ) -> Result<Option<Selected<Original>>> {
        let Some(history) = BodyHistory::open(self, CustodyPurpose::Renewal(sequence))? else {
            return Ok(None);
        };
        match history.into_selected() {
            Ok(selected) => Ok(Some(selected)),
            Err(super::super::super::Error::Bootstrap(
                ManagedBootstrapFailure::TransitionPending,
            )) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn recover_native_renewal_carrier(
        &self,
        sequence: u64,
        original: &Original,
        current: &VerifiedStreamTokenCustodyStateV1,
        deadline: Instant,
        reads: &impl RenewalReads,
    ) -> Result<()> {
        let selected =
            require_retained_material(self.required_enrollment(CustodyPurpose::Renewal(sequence)))?;
        let transaction = require_retained_material(self.verify_wallet(
            selected.directory(),
            &selected,
            deadline,
        ))?;
        if require_retained_material(
            self.authority
                .retained_finality(selected.directory(), &transaction),
        )?
        .is_none()
        {
            let native = current
                .current()
                .ok_or_else(|| invalid("native renewal head absent"))?;
            // Its height is only a replay hint; the shared owner checks exact successful wire.
            reads.retain_carrier(
                &self.authority,
                selected.directory(),
                &original.checkpoint,
                &transaction,
                native.record().execution_height,
                current.height(),
                deadline,
            )?;
        }
        Ok(())
    }

    /// Material-only current head for Catalog preflight. Expiry cannot create a launch capability.
    pub(in crate::managed) fn retained_native_head_material(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        initial: ManagedCustodyEnrollmentInterval,
        minimum: ManagedTransactionFinality,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let (_, current) = self.observe(&policy.binding, deadline)?;
        let native = current
            .current()
            .ok_or_else(|| invalid("native custody head absent"))?;
        if native.control().policy != *policy
            || native.control().signer_revoked
            || native.control().attester_revoked
        {
            return Err(invalid(
                "native custody material policy or revocation changed",
            ));
        }
        let sequence = native
            .control()
            .active_head
            .ok_or_else(|| invalid("native custody active head absent"))?
            .sequence;
        if sequence > 1 {
            let original = self
                .original_renewal_if_present(sequence)?
                .ok_or(ManagedBootstrapFailure::RetainedMaterial)?;
            self.recover_native_renewal_carrier(
                sequence,
                &original,
                &current,
                deadline,
                &NativeReads,
            )?;
        }
        self.retained_head_material_at(
            policy,
            initial,
            minimum.height,
            *minimum.block_hash.as_ref(),
            &current,
            deadline,
        )
    }

    /// Reconcile under a caller-owned finite turn while Catalog (or the exact old launch) lives.
    /// Neither local directory ordering nor current native bytes can mint historical inclusion.
    pub(in crate::managed) fn reconcile_generated_renewal(
        &mut self,
        turn: &mut GeneratedRenewalTurn,
        deadline: Instant,
    ) -> Result<Reconciliation> {
        self.reconcile_generated_with_reads(turn, deadline, &NativeReads)
    }

    pub(in crate::managed::stream_token_custody) fn reconcile_generated_with_reads(
        &mut self,
        turn: &mut GeneratedRenewalTurn,
        deadline: Instant,
        reads: &impl RenewalReads,
    ) -> Result<Reconciliation> {
        let (deadline, _) = turn.check(self, deadline)?;
        let initial_interval = self.inspect_local_initial_interval(&turn.policy)?;
        let (verifier, current) = reads.observe(self, &turn.policy, deadline)?;
        match self.reconcile_generated_material(
            turn,
            initial_interval,
            &current,
            deadline,
            reads,
        )? {
            RenewalMaterial::Current(retained) => Ok(Reconciliation::Current(retained)),
            RenewalMaterial::Pending(pending) => {
                self.reconcile_pending_renewal(turn, &verifier, &current, pending, deadline)
            }
        }
    }

    // Authenticate retained material before allocating the pending dispatch working values.
    #[inline(never)]
    fn reconcile_generated_material<'a>(
        &self,
        turn: &GeneratedRenewalTurn,
        initial_interval: ManagedCustodyEnrollmentInterval,
        current: &'a VerifiedStreamTokenCustodyStateV1,
        deadline: Instant,
        reads: &impl RenewalReads,
    ) -> Result<RenewalMaterial<'a>> {
        let selected = current
            .current()
            .ok_or_else(|| invalid("generated native custody head absent"))?;
        let control = selected.control();
        if control.policy != turn.policy || control.signer_revoked || control.attester_revoked {
            return Err(invalid(
                "generated native custody policy or revocation changed",
            ));
        }
        selected
            .record()
            .validate_active_enrollment(control)
            .map_err(|_| invalid("generated native custody head differs"))?;
        let head = control
            .active_head
            .ok_or_else(|| invalid("generated custody has no active head"))?;
        if !(1..=64).contains(&head.sequence)
            || control.next_sequence
                != head
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("custody sequence overflow"))?
        {
            return Err(invalid("generated custody native sequence exceeds bound"));
        }
        if current.height() < turn.floor.height
            || current.height() == turn.floor.height
                && selected.anchor().block_hash != *turn.floor.block_hash.as_ref()
        {
            return Err(invalid("generated custody cut predates original carrier"));
        }
        if head.sequence > 1 {
            let original = self
                .original_renewal_if_present(head.sequence)?
                .ok_or(ManagedBootstrapFailure::RetainedMaterial)?;
            if original.terms.fees != turn.fees {
                return Err(invalid("renewal original fees changed"));
            }
            self.recover_native_renewal_carrier(
                head.sequence,
                &original,
                current,
                deadline,
                reads,
            )?;
        }
        let retained = self.retained_head_material_at(
            &turn.policy,
            initial_interval,
            turn.floor.height,
            *turn.floor.block_hash.as_ref(),
            current,
            deadline,
        )?;
        let now = now_ms()?;
        if now < retained.statement().issued_at_unix_ms {
            return Err(invalid(
                "current custody predates its original issued interval",
            ));
        }
        let usable = now < retained.statement().expires_at_unix_ms;
        if usable {
            self.match_current_enrollment(
                &retained,
                &turn.policy,
                turn.floor.height.max(retained.finalized().height),
                if retained.finalized().height > turn.floor.height {
                    *retained.finalized().block_hash.as_ref()
                } else {
                    *turn.floor.block_hash.as_ref()
                },
                current,
                now,
            )?;
        }
        if let Some(authorization) = &turn.authorization {
            if matches!(authorization.purpose, Purpose::CustodyRenewal { sequence, .. } if head.sequence == sequence)
            {
                if !usable {
                    return Err(ManagedBootstrapFailure::EnrollmentExpired.into());
                }
                return Ok(RenewalMaterial::Current(retained));
            }
        }
        if head.sequence == 64 {
            return if usable {
                Ok(RenewalMaterial::Current(retained))
            } else {
                Err(ManagedBootstrapFailure::EpochLimit.into())
            };
        }
        let next = control.next_sequence;
        let existing = BodyHistory::open(self, CustodyPurpose::Renewal(next))?;
        let statement = retained.statement();
        let midpoint = statement
            .issued_at_unix_ms
            .checked_add((statement.expires_at_unix_ms - statement.issued_at_unix_ms).div_ceil(2))
            .ok_or_else(|| invalid("custody midpoint overflow"))?;
        if usable && now < midpoint && existing.is_none() {
            return Ok(RenewalMaterial::Current(retained));
        }
        Ok(RenewalMaterial::Pending(PendingRenewal {
            selected,
            control,
            next,
            existing,
            _retained: retained,
        }))
    }

    // Consume the same opened body only after material reconciliation has returned.
    #[inline(never)]
    fn reconcile_pending_renewal(
        &mut self,
        turn: &mut GeneratedRenewalTurn,
        verifier: &FinalityVerifier,
        current: &VerifiedStreamTokenCustodyStateV1,
        pending: PendingRenewal<'_>,
        deadline: Instant,
    ) -> Result<Reconciliation> {
        let PendingRenewal {
            _retained,
            selected,
            control,
            next,
            existing,
        } = pending;
        // Construct fresh attester selections only when a genuinely unsigned body needs one.
        // Paid originals retain their exact recovery path even after no later interval can exist.
        let select_fresh = |owner: &Self, fees: &Fees| -> Result<_> {
            let now = now_ms()?;
            let remaining = u64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .map_err(|_| invalid("renewal turn duration exceeds bound"))?;
            let utc = now
                .checked_add(remaining)
                .ok_or_else(|| invalid("renewal turn UTC overflow"))?
                .min(
                    owner
                        .renewal_validity(selected.record(), control, next, now)?
                        .expires_at_unix_ms,
                );
            let terms = Terms::new(utc, &fees.options(deadline))?;
            owner.select_renewal_unsigned(
                next,
                &control.policy,
                current,
                verifier,
                &terms,
                deadline,
            )
        };
        let history = match existing {
            Some(history) => history,
            None => {
                let unsigned = select_fresh(self, &turn.fees)?;
                turn.check(self, deadline)?;
                BodyHistory::initialize(
                    self,
                    CustodyPurpose::Renewal(next),
                    unsigned,
                    &turn.fees,
                    &SigningTurn::RenewalSelection(turn),
                    deadline,
                )?
            }
        };
        let authorization = turn.authorize_retained(self, &history, deadline)?;
        let history = if history.preserve_paid_body(self)? {
            history
        } else {
            let history = history.finish_pending(
                self,
                current,
                &SigningTurn::Generated(authorization),
                deadline,
            )?;
            let history = if history.body_expired()? {
                let unsigned = select_fresh(self, authorization.fees())?;
                history
                    .reserve_successor(self, unsigned, current, authorization, deadline)?
                    .finish_pending(
                        self,
                        current,
                        &SigningTurn::Generated(authorization),
                        deadline,
                    )?
            } else {
                history
            };
            history
        };
        let (operation, original, scope) = history.dispatch()?;
        self.select_generated_attempt(operation, original, scope, authorization, deadline)?;
        let selected = history.into_reparsed_selected(self)?;
        let result = self.advance_selected(
            CustodyPurpose::Renewal(next),
            selected,
            deadline,
            Mode::SubmitAuthorized(authorization),
            false,
        )?;
        turn.check(self, deadline)?;
        Ok(Reconciliation::Pending(result))
    }
}

#[cfg(test)]
#[path = "generated_begin_scope_tests.rs"]
mod begin_scope_tests;
