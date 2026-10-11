//! Sole original enrollment signer and historical enrollment extraction.

use super::*;
use crate::managed::service_authority::CheckpointImports;
use iroha_data_model::sumeragi_finality::EpochValidationScope;

/// Exact original enrollment with independently authenticated successful wallet inclusion.
///
/// This is historical evidence only. Native current custody, revocation, time and signer
/// qualification must be checked separately before use. It has no public decoder/constructor.
pub struct RetainedCustodyEnrollment {
    bytes: Vec<u8>,
    statement: SignerCustodyStatementV1,
    record_digest: [u8; 32],
    finalized: ManagedTransactionFinality,
}
impl RetainedCustodyEnrollment {
    /// Original canonical enrollment bytes, without re-signing or updating its interval.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact statement from those original signed bytes.
    #[must_use]
    pub fn statement(&self) -> &SignerCustodyStatementV1 {
        &self.statement
    }
    /// Exact canonical enrollment record commitment, to compare with a fresh native head.
    #[must_use]
    pub fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
    /// Independent successful inclusion of this exact original wallet envelope.
    #[must_use]
    pub fn finalized(&self) -> &ManagedTransactionFinality {
        &self.finalized
    }
}
impl std::fmt::Debug for RetainedCustodyEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedCustodyEnrollment")
            .finish_non_exhaustive()
    }
}

/// One call's fully verified original initial enrollment and its exact Configure policy.
/// This historical prerequisite grants no current authority and is never cached across calls.
pub(super) struct RetainedInitialPrerequisite {
    pub(super) policy: SignerCustodyPolicyV1,
    pub(super) enrollment: RetainedCustodyEnrollment,
}

/// One call's authenticated Configure input. The exact original native owners and carrier
/// bytes stay held until reuse; this is never a current-state or cross-call cache.
pub(super) struct RetainedConfiguration<'a> {
    owner: &'a ManagedStreamTokenCustody,
    original: Selected<Original>,
    signed: SignedTransaction,
    carrier: Vec<u8>,
    policy: SignerCustodyPolicyV1,
    finalized: ManagedTransactionFinality,
}
impl RetainedConfiguration<'_> {
    pub(super) fn policy(&self) -> &SignerCustodyPolicyV1 {
        &self.policy
    }
    fn require_carrier(&self) -> Result<()> {
        let directory = self.original.directory();
        directory.revalidate()?;
        if read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)?.as_deref()
            != Some(self.carrier.as_slice())
        {
            return Err(invalid("retained Configure carrier changed during handoff"));
        }
        directory.revalidate()?;
        Ok(())
    }
    pub(super) fn into_initial_prerequisite(
        self,
        deadline: Instant,
    ) -> Result<RetainedInitialPrerequisite> {
        let owner = self.owner;
        require_deadline(deadline)?;
        owner.authority.validate_profile()?;
        self.require_carrier()?;
        // The selected graph rechecks original identities, all records and canonical wallets.
        // Only the immutable native proof import is reused; wallet verification remains fresh.
        let signed = owner.verify_wallet(self.original.directory(), &self.original, deadline)?;
        if signed
            .encode_wire_v1()
            .map_err(|_| invalid("invalid retained Configure transaction wire"))?
            != self
                .signed
                .encode_wire_v1()
                .map_err(|_| invalid("invalid retained Configure transaction wire"))?
        {
            return Err(invalid("retained Configure wallet changed during handoff"));
        }
        self.require_carrier()?;
        require_deadline(deadline)?;
        drop(signed);
        let Self {
            owner: _,
            original,
            signed,
            carrier,
            policy,
            finalized,
        } = self;
        drop((original, signed, carrier));
        // End the Configure graph before the initial BodyHistory opens. The historical result
        // reaches the same verifier at the same boundary as an ordinary Configure read.
        owner.initial_prerequisite_after_configuration(policy, finalized, deadline)
    }
}

impl ManagedStreamTokenCustody {
    /// Recover the exact initial enrollment for an independently selected original policy/interval.
    ///
    /// Reads only retained originals, wallet and native carrier; it never queries peers, signs,
    /// sends or selects a later sequence. A renderer must separately qualify current native use.
    /// # Errors
    /// Rejects missing or changed profile, original terms, policy, interval, wallet or carrier.
    pub fn retained_initial_enrollment(
        &self,
        policy: &SignerCustodyPolicyV1,
        interval: ManagedCustodyEnrollmentInterval,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        self.retained_enrollment(
            CustodyPurpose::InitialEnroll,
            policy,
            Some(interval),
            deadline,
        )
    }

    /// Recover one explicitly selected renewal; sequence ordering grants no current authority.
    /// # Errors
    /// Rejects a sequence outside the generated bound or changed original evidence.
    pub fn retained_renewed_enrollment(
        &self,
        sequence: u64,
        policy: &SignerCustodyPolicyV1,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        self.retained_enrollment(CustodyPurpose::Renewal(sequence), policy, None, deadline)
    }

    /// Recover exactly the original enrollment named by a fresh independent native head.
    /// No journal directory ordering or retained response claim can select the sequence.
    pub(crate) fn retained_current_enrollment(
        &mut self,
        policy: &SignerCustodyPolicyV1,
        initial_interval: ManagedCustodyEnrollmentInterval,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let (_, current) = self.observe(&policy.binding, deadline)?;
        self.select_retained_current_enrollment(
            policy,
            initial_interval,
            minimum_height,
            minimum_block_hash,
            &current,
            now_ms()?,
            deadline,
        )
    }

    pub(super) fn select_retained_current_enrollment(
        &self,
        policy: &SignerCustodyPolicyV1,
        initial_interval: ManagedCustodyEnrollmentInterval,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        current: &VerifiedStreamTokenCustodyStateV1,
        observed_at_unix_ms: u64,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        let retained = self.retained_head_material_at(
            policy,
            initial_interval,
            minimum_height,
            minimum_block_hash,
            current,
            deadline,
        )?;
        let (height, hash) = if retained.finalized().height > minimum_height {
            (
                retained.finalized().height,
                *retained.finalized().block_hash.as_ref(),
            )
        } else {
            (minimum_height, minimum_block_hash)
        };
        self.verify_enrollment_at(
            &retained,
            policy,
            height,
            hash,
            current,
            observed_at_unix_ms,
            deadline,
        )?;
        Ok(retained)
    }

    /// Historical material join only. Expired bytes can be a renewal predecessor, never a launch.
    pub(super) fn retained_head_material_at(
        &self,
        policy: &SignerCustodyPolicyV1,
        initial_interval: ManagedCustodyEnrollmentInterval,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        current: &VerifiedStreamTokenCustodyStateV1,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        if minimum_height < 2 || minimum_block_hash == [0; 32] {
            return Err(invalid("original runtime carrier floor is invalid"));
        }
        let sequence = current
            .current()
            .and_then(|value| value.control().active_head)
            .map(|head| head.sequence)
            .filter(|sequence| (1..=64).contains(sequence))
            .ok_or_else(|| invalid("current generated custody head is absent or outside bound"))?;
        let retained = if sequence == 1 {
            crate::managed::native_operation::require_retained_material(
                self.retained_initial_enrollment(policy, initial_interval, deadline),
            )?
        } else {
            crate::managed::native_operation::require_retained_material(
                self.retained_renewed_enrollment(sequence, policy, deadline),
            )?
        };
        // Floor may precede a renewed enrollment, but never its selected successful carrier.
        let (height, hash) = if retained.finalized().height > minimum_height {
            (
                retained.finalized().height,
                *retained.finalized().block_hash.as_ref(),
            )
        } else {
            (minimum_height, minimum_block_hash)
        };
        self.match_current_enrollment_material(&retained, policy, height, hash, current)?;
        Ok(retained)
    }

    /// Read and qualify the selected original enrollment at the caller's independently verified
    /// Global block, allowing discovery and custody to share the exact same native cut.
    pub(crate) fn verify_current_enrollment_at(
        &self,
        enrollment: &RetainedCustodyEnrollment,
        policy: &SignerCustodyPolicyV1,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        block: &VerifiedSumeragiBlock,
        deadline: Instant,
    ) -> Result<()> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let current = self.read_current_at(&policy.binding, block, deadline)?;
        self.verify_enrollment_at(
            enrollment,
            policy,
            minimum_height,
            minimum_block_hash,
            &current,
            now_ms()?,
            deadline,
        )
    }

    /// Check historical enrollment against a separately authenticated same-cut current proof.
    /// The proof's sole native verifier owns provenance; this method adds exact original-profile,
    /// enrollment and floor checks, with no signing, HTTP or durable state publication.
    pub(crate) fn verify_enrollment_at(
        &self,
        enrollment: &RetainedCustodyEnrollment,
        policy: &SignerCustodyPolicyV1,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        current: &VerifiedStreamTokenCustodyStateV1,
        observed_at_unix_ms: u64,
        deadline: Instant,
    ) -> Result<()> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.match_current_enrollment(
            enrollment,
            policy,
            minimum_height,
            minimum_block_hash,
            current,
            observed_at_unix_ms,
        )?;
        self.authority.validate_profile()?;
        require_deadline(deadline)
    }

    /// Select one retained renewal only after a fresh independent head names its exact bytes.
    /// This is a render-time check, not a durable current-use capability; the daemon requalifies
    /// native custody on startup and each use. The supplied floor is a caller-selected original
    /// successful carrier, not a checkpoint or source of finality authority.
    pub(crate) fn verify_current_enrollment(
        &mut self,
        enrollment: &RetainedCustodyEnrollment,
        policy: &SignerCustodyPolicyV1,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        deadline: Instant,
    ) -> Result<()> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let (_, current) = self.observe(&policy.binding, deadline)?;
        self.verify_enrollment_at(
            enrollment,
            policy,
            minimum_height,
            minimum_block_hash,
            &current,
            now_ms()?,
            deadline,
        )?;
        self.authority.validate_profile()?;
        require_deadline(deadline)?;
        Ok(())
    }

    pub(super) fn match_current_enrollment(
        &self,
        enrollment: &RetainedCustodyEnrollment,
        policy: &SignerCustodyPolicyV1,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        current: &VerifiedStreamTokenCustodyStateV1,
        observed_at_unix_ms: u64,
    ) -> Result<()> {
        use sorafs_manifest::signer::custody::{
            SignerCustodyUseContextV1, verify_signer_custody_use_v1,
        };
        self.match_current_enrollment_material(
            enrollment,
            policy,
            minimum_height,
            minimum_block_hash,
            current,
        )?;
        let selected = current
            .current()
            .ok_or_else(|| invalid("renewed runtime custody is absent"))?;
        let control = selected.control();
        let anchor = selected.anchor();
        let verified = verify_signer_custody_use_v1(
            enrollment.bytes(),
            &policy.binding,
            &policy.custody_trust(),
            &SignerCustodyUseContextV1 {
                now_unix_ms: observed_at_unix_ms,
                anchor_observed_at_unix_ms: observed_at_unix_ms,
                current_anchor: anchor,
                active_head: control
                    .active_head
                    .ok_or_else(|| invalid("renewed custody head absent"))?,
                signer_revoked: control.signer_revoked,
                attester_revoked: control.attester_revoked,
            },
        )
        .map_err(|_| invalid("renewed runtime custody is not currently usable"))?;
        if verified.record_digest() != enrollment.record_digest()
            || verified.statement() != enrollment.statement()
        {
            return Err(invalid("renewed runtime custody record changed"));
        }
        Ok(())
    }

    fn match_current_enrollment_material(
        &self,
        enrollment: &RetainedCustodyEnrollment,
        policy: &SignerCustodyPolicyV1,
        minimum_height: u64,
        minimum_block_hash: [u8; 32],
        current: &VerifiedStreamTokenCustodyStateV1,
    ) -> Result<()> {
        self.validate_policy(policy)?;
        let selected = current
            .current()
            .ok_or_else(|| invalid("renewed runtime custody is absent"))?;
        let control = selected.control();
        let anchor = selected.anchor();
        if minimum_height < enrollment.finalized().height
            || minimum_block_hash == [0; 32]
            || current.height() < minimum_height
            || current.height() == minimum_height && anchor.block_hash != minimum_block_hash
            || current.network_id() != self.authority.config.network_id
            || current.provider_id() != self.authority.provider_id()?
            || current.owner()
                != self
                    .authority
                    .provider_role(StreamTokenAuthorityRole::IssuerOperator)?
            || control.policy != *policy
            || selected.record().active_enrollment.as_deref() != Some(enrollment.bytes())
        {
            return Err(invalid(
                "renewed runtime custody differs from its native head or floor",
            ));
        }
        let head = control
            .active_head
            .ok_or_else(|| invalid("retained native enrollment head absent"))?;
        if head.sequence != enrollment.statement().sequence
            || head.record_digest != enrollment.record_digest()
            || control.signer_revoked
            || control.attester_revoked
        {
            return Err(invalid(
                "retained enrollment differs from unrevoked native head",
            ));
        }
        Ok(())
    }

    fn retained_enrollment(
        &self,
        purpose: CustodyPurpose,
        policy: &SignerCustodyPolicyV1,
        interval: Option<ManagedCustodyEnrollmentInterval>,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        // Keep only the existing two pure epoch contexts across these independently read
        // original phases. Current source custody and active decode admission stay fresh.
        let mut validation = EpochValidationScope::new();
        let mut imports = CheckpointImports::new(&self.authority, Some(&mut validation));
        let (configured_policy, configured) =
            self.retained_configuration_with_imports(deadline, &mut imports)?;
        if configured_policy != *policy {
            return Err(invalid("retained enrollment policy differs"));
        }
        let original = self.required_enrollment_with_imports(purpose, &mut imports)?;
        let result = self.verify_retained_enrollment_with_imports(
            purpose,
            policy,
            interval,
            &configured,
            original,
            deadline,
            &mut imports,
        );
        drop(imports);
        drop(validation);
        result
    }

    /// Consume one canonical initial selection after verifying Configure once. The same owned
    /// History that supplied its interval reaches wallet verification; no pathname reopen or
    /// second complete history graph is needed between these read-only stages.
    pub(super) fn retained_initial_prerequisite(
        &self,
        deadline: Instant,
    ) -> Result<RetainedInitialPrerequisite> {
        let mut validation = EpochValidationScope::new();
        let mut imports = CheckpointImports::new(&self.authority, Some(&mut validation));
        let result = self.retained_initial_prerequisite_with_imports(deadline, &mut imports);
        drop(imports);
        drop(validation);
        result
    }

    pub(super) fn retained_initial_prerequisite_with_imports(
        &self,
        deadline: Instant,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<RetainedInitialPrerequisite> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let (policy, configured) = self.retained_configuration_with_imports(deadline, imports)?;
        // Each Configure source graph ends at the original phase boundary. Only the caller's
        // bounded pure epoch workspace may remain live through the initial prerequisite.
        self.initial_prerequisite_after_configuration_with_imports(
            policy, configured, deadline, imports,
        )
    }

    fn initial_prerequisite_after_configuration(
        &self,
        policy: SignerCustodyPolicyV1,
        configured: ManagedTransactionFinality,
        deadline: Instant,
    ) -> Result<RetainedInitialPrerequisite> {
        // Configure's source graph has already ended at the original handoff boundary.
        // The initial body and its carrier share pure work only until this call returns.
        let mut validation = EpochValidationScope::new();
        let mut imports = CheckpointImports::new(&self.authority, Some(&mut validation));
        let result = self.initial_prerequisite_after_configuration_with_imports(
            policy,
            configured,
            deadline,
            &mut imports,
        );
        drop(imports);
        drop(validation);
        result
    }

    fn initial_prerequisite_after_configuration_with_imports(
        &self,
        policy: SignerCustodyPolicyV1,
        configured: ManagedTransactionFinality,
        deadline: Instant,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<RetainedInitialPrerequisite> {
        let (original, interval) = self
            .inspect_initial_selection_with_imports(&policy, imports)?
            .ok_or_else(|| invalid("original initial enrollment dispatch is not selected"))?;
        let enrollment = self.verify_retained_enrollment_with_imports(
            CustodyPurpose::InitialEnroll,
            &policy,
            Some(interval),
            &configured,
            original,
            deadline,
            imports,
        )?;
        Ok(RetainedInitialPrerequisite { policy, enrollment })
    }

    #[cfg(test)]
    fn verify_retained_enrollment(
        &self,
        purpose: CustodyPurpose,
        policy: &SignerCustodyPolicyV1,
        interval: Option<ManagedCustodyEnrollmentInterval>,
        configured: &ManagedTransactionFinality,
        original: Selected<Original>,
        deadline: Instant,
    ) -> Result<RetainedCustodyEnrollment> {
        self.verify_retained_enrollment_with_imports(
            purpose,
            policy,
            interval,
            configured,
            original,
            deadline,
            &mut CheckpointImports::new(&self.authority, None),
        )
    }

    fn verify_retained_enrollment_with_imports(
        &self,
        purpose: CustodyPurpose,
        policy: &SignerCustodyPolicyV1,
        interval: Option<ManagedCustodyEnrollmentInterval>,
        configured: &ManagedTransactionFinality,
        original: Selected<Original>,
        deadline: Instant,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<RetainedCustodyEnrollment> {
        let directory = original.directory();
        self.validate_original_with_imports(&original, purpose, imports)?;
        let Action::Enroll { enrollment, .. } = &original.action else {
            return Err(invalid("retained enrollment has another purpose"));
        };
        original.matches_selected_enrollment(
            policy,
            interval.unwrap_or(original.interval()?),
            &original.terms.options(deadline),
        )?;
        if matches!(purpose, CustodyPurpose::Renewal(_)) {
            self.validate_renewal_context(&original, deadline)?;
        }
        if purpose == CustodyPurpose::InitialEnroll {
            let predecessor = original
                .selection
                .current
                .as_ref()
                .ok_or_else(|| invalid("initial predecessor absent"))?;
            if predecessor.execution_height != configured.height
                || predecessor.authority != self.authority.config.account
            {
                return Err(invalid(
                    "initial enrollment differs from original Configure execution",
                ));
            }
        }
        let transaction = self.verify_wallet(&directory, &original, deadline)?;
        let finalized = imports
            .retained_finality(&directory, &transaction)?
            .ok_or_else(|| invalid("enrollment requires independent original inclusion"))?;
        if finalized.height <= configured.height {
            return Err(invalid("enrollment carrier predates original Configure"));
        }
        let record = decode_enrollment(enrollment)?;
        let digest = record
            .canonical_digest()
            .map_err(|_| invalid("invalid retained enrollment digest"))?;
        let bytes = enrollment.clone();
        self.authority.validate_profile()?;
        require_deadline(deadline)?;
        Ok(RetainedCustodyEnrollment {
            bytes,
            statement: record.statement,
            record_digest: digest,
            finalized,
        })
    }

    /// Read the exact selected initial body and its selected dispatch deadline without creating
    /// custody or querying current state. Full native inclusion is checked by retained enrollment.
    pub(in crate::managed) fn inspect_local_initial_interval(
        &self,
        policy: &SignerCustodyPolicyV1,
    ) -> Result<ManagedCustodyEnrollmentInterval> {
        self.inspect_local_initial_interval_if_present(policy)?
            .ok_or_else(|| invalid("original initial enrollment dispatch is not selected"))
    }
    /// Inspect an optional local selection for the managed runtime without creating a dispatch.
    pub(in crate::managed) fn inspect_local_initial_interval_if_present(
        &self,
        policy: &SignerCustodyPolicyV1,
    ) -> Result<Option<ManagedCustodyEnrollmentInterval>> {
        Ok(self
            .inspect_initial_selection(policy)?
            .map(|(_, interval)| interval))
    }

    fn inspect_initial_selection(
        &self,
        policy: &SignerCustodyPolicyV1,
    ) -> Result<Option<(Selected<Original>, ManagedCustodyEnrollmentInterval)>> {
        self.inspect_initial_selection_with_imports(
            policy,
            &mut CheckpointImports::new(&self.authority, None),
        )
    }

    fn inspect_initial_selection_with_imports(
        &self,
        policy: &SignerCustodyPolicyV1,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<Option<(Selected<Original>, ManagedCustodyEnrollmentInterval)>> {
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let Some(history) = body_history::BodyHistory::open_with_imports(
            self,
            CustodyPurpose::InitialEnroll,
            imports,
        )?
        else {
            return Ok(None);
        };
        history.matches_policy(policy)?;
        let original = match history.into_selected() {
            Ok(original) => original,
            Err(super::super::Error::Bootstrap(ManagedBootstrapFailure::TransitionPending)) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let selected = original.interval()?;
        self.authority.validate_profile()?;
        Ok(Some((original, selected)))
    }

    pub(super) fn retained_configuration(
        &self,
        deadline: Instant,
    ) -> Result<(SignerCustodyPolicyV1, ManagedTransactionFinality)> {
        self.retained_configuration_with_imports(
            deadline,
            &mut CheckpointImports::new(&self.authority, None),
        )
    }

    pub(super) fn retained_configuration_with_imports(
        &self,
        deadline: Instant,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<(SignerCustodyPolicyV1, ManagedTransactionFinality)> {
        let retained = self.read_configuration_with_imports(deadline, imports)?;
        Ok((retained.policy, retained.finalized))
    }

    pub(super) fn read_configuration(
        &self,
        deadline: Instant,
    ) -> Result<RetainedConfiguration<'_>> {
        self.read_configuration_with_imports(
            deadline,
            &mut CheckpointImports::new(&self.authority, None),
        )
    }

    fn read_configuration_with_imports(
        &self,
        deadline: Instant,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<RetainedConfiguration<'_>> {
        #[cfg(test)]
        prerequisite_tests::record_configuration_read();
        require_deadline(deadline)?;
        let operation = self.authority.directory.open_child("configure")?;
        let original = journal::required_original(&operation)?;
        let directory = original.directory();
        self.validate_original_with_imports(&original, CustodyPurpose::Configure, imports)?;
        let signed = self.verify_wallet(&directory, &original, deadline)?;
        // Retain the same bytes fed to the sole native decoder, never a later path reread.
        let carrier = read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)?
            .ok_or_else(|| invalid("configuration requires independent original inclusion"))?;
        let verifier = imports.decode(&carrier)?;
        let finalized = crate::managed::native_operation::verify_carrier(&verifier, &signed)?;
        let Action::Configure(policy) = &original.action else {
            return Err(invalid("configuration journal has another purpose"));
        };
        let policy = policy.clone();
        Ok(RetainedConfiguration {
            owner: self,
            original,
            signed,
            carrier,
            policy,
            finalized,
        })
    }

    pub(super) fn unsigned_enrollment(
        &self,
        policy: &SignerCustodyPolicyV1,
        current: &VerifiedStreamTokenCustodyStateV1,
        verifier: &FinalityVerifier,
        interval: ManagedCustodyEnrollmentInterval,
        observed: u64,
    ) -> Result<body_history::UnsignedEnrollment> {
        let selected = current
            .current()
            .ok_or_else(|| invalid("custody policy absent"))?;
        let tip = verifier
            .verified_tip()
            .map_err(|_| invalid("unsigned enrollment cut invalid"))?;
        if current.height() != verifier.checkpoint().height()
            || current.context_id() != tip.context_id()
            || selected.control().policy != *policy
        {
            return Err(invalid(
                "unsigned enrollment differs from selected native cut",
            ));
        }
        let checkpoint = checkpoint_bytes(verifier)?;
        let selection = self.selection(&policy.binding, current)?;
        let statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: policy.binding.clone(),
            authority: policy.attester_authority.clone(),
            anchor: selected.anchor(),
            sequence: selected.control().next_sequence,
            predecessor_digest: selected.control().predecessor_digest,
            issued_at_unix_ms: interval.issued_at_unix_ms,
            expires_at_unix_ms: interval.expires_at_unix_ms,
            evidence_digest: self.evidence_digest(policy, &selection, &checkpoint)?,
            revoked: false,
        };
        statement
            .signing_payload()
            .map_err(|_| invalid("invalid enrollment statement"))?;
        Ok(body_history::UnsignedEnrollment {
            selection,
            statement,
            selected_at_unix_ms: observed,
            checkpoint,
        })
    }
}

pub(super) fn decode_enrollment(bytes: &[u8]) -> Result<SignerCustodyRecordV1> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(invalid("enrollment exceeds bound"));
    }
    norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 1024 * 1024, 32),
    )
    .map_err(|_| invalid("invalid retained enrollment statement"))
}

#[cfg(test)]
mod local_inspection_tests {
    //! Optional inspection preserves absence and refuses changed retained material.

    use super::*;

    #[test]
    fn optional_initial_inspection_preserves_absence_and_rejects_changed_material() {
        let _guard = crate::managed::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "custody-local-inspection",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let owner = ManagedStreamTokenCustody::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let policy = super::super::transport_tests::policy(&owner);
        let entries = owner.authority.directory.entries(32).unwrap();
        assert_eq!(
            owner
                .inspect_local_initial_interval_if_present(&policy)
                .unwrap(),
            None
        );
        assert!(owner.inspect_local_initial_interval(&policy).is_err());
        assert_eq!(owner.authority.directory.entries(32).unwrap(), entries);
        let mut changed = policy.clone();
        changed.binding.network_id = [0x55; 32];
        assert!(
            owner
                .inspect_local_initial_interval_if_present(&changed)
                .is_err()
        );
        let enrollment = owner.authority.directory.ensure_child("enroll").unwrap();
        assert!(matches!(
            owner.inspect_local_initial_interval_if_present(&policy),
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::RetainedMaterial
            ))
        ));
        assert!(enrollment.entries(3).unwrap().is_empty());
        enrollment
            .write_atomic("original.nrt", &[0xff], PublishMode::CreateNew)
            .unwrap();
        assert!(
            owner
                .inspect_local_initial_interval_if_present(&policy)
                .is_err()
        );
        assert_eq!(
            enrollment.read("original.nrt", 1).unwrap().as_slice(),
            &[0xff]
        );
    }
}

#[cfg(test)]
#[path = "enrollment/prerequisite_tests.rs"]
mod prerequisite_tests;

#[cfg(test)]
#[path = "enrollment/route_scope_tests.rs"]
mod route_scope_tests;
