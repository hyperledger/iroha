//! Closed custody planning over the shared wallet journal and canonical signer-control owners.
//!
//! Supplied records and anchors are caller claims, never authenticated evidence. The coordinator
//! must authenticate them independently; native execution checks provider ownership, the exact
//! `CanManageSorafsStreamTokenCustody` permission, finality, revocation and predecessor CAS.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::MutateSorafsStreamTokenCustody,
    sorafs::{
        capacity::ProviderId,
        stream_token_custody::{
            STREAM_TOKEN_CUSTODY_MAX_RECORD_BYTES_V1, STREAM_TOKEN_CUSTODY_NORMAL_REVISIONS_V1,
            SorafsStreamTokenCustodyActionV1, StreamTokenCustodyControlRecordV1,
        },
    },
};
use sorafs_manifest::signer::{
    custody::{
        SIGNER_CUSTODY_MAX_BYTES_V1, SignerCustodyAnchorV1, SignerCustodyBindingV1,
        SignerCustodyEnrollmentContextV1, verify_signer_custody_enrollment_v1,
    },
    custody_control::{
        SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1, SignerCustodyControlStateV1, SignerCustodyPolicyV1,
        configure_signer_custody_policy_v1,
    },
    protocol::{SignerPurposeBindingV1, SignerRoleV1},
};

const MAX_PLAN_BYTES: usize = 128 * 1024;

/// Independently selected custody target and exact predecessor, supplied by the coordinator.
///
/// This is an untrusted request value. Constructing it proves neither native execution nor
/// current finality. The caller must authenticate the current record before preparing an action.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::StreamTokenCustodySelection")]
pub struct StreamTokenCustodySelection {
    /// Exact governed provider.
    pub provider_id: ProviderId,
    /// Expected signer identity, supplied independently of an enrollment candidate.
    pub binding: SignerCustodyBindingV1,
    /// Exact native CAS revision; zero only when no control has been configured.
    pub expected_revision: u64,
    /// Exact native record digest; zero only when no control has been configured.
    pub expected_digest: [u8; 32],
    /// Original native predecessor record; absent only for first configuration.
    pub current: Option<StreamTokenCustodyControlRecordV1>,
}

/// One requested policy configuration with immutable UTC and spending authorization.
#[derive(Clone, Debug)]
pub struct StreamTokenCustodyConfigureRequest {
    /// Independently selected target and predecessor CAS.
    pub selection: StreamTokenCustodySelection,
    /// Exact proposed canonical policy; signer binding must equal `selection.binding`.
    pub policy: SignerCustodyPolicyV1,
    /// Original exclusive transaction deadline in Unix milliseconds; never renewed on retry.
    pub deadline_unix_ms: u64,
    /// Explicit aggregate fee limits and a monotonic budget for this call's I/O.
    pub options: BoundedTransactionOptions,
}

/// One signed enrollment, checked against an independently selected policy and native predecessor.
#[derive(Clone, Debug)]
pub struct StreamTokenCustodyEnrollRequest {
    /// Exact configured target and native predecessor CAS.
    pub selection: StreamTokenCustodySelection,
    /// Independently selected finalized block and exact current native record digest.
    pub anchor: SignerCustodyAnchorV1,
    /// Original time at which the coordinator observed that anchor.
    pub anchor_observed_at_unix_ms: u64,
    /// Exact requested signed interval beginning, independent of the candidate statement.
    pub issued_at_unix_ms: u64,
    /// Exact requested signed interval end, independent of the candidate statement.
    pub expires_at_unix_ms: u64,
    /// Complete canonical signed Manifest custody record; no keys or signer handles are opened.
    pub enrollment: Vec<u8>,
    /// Original exclusive transaction deadline, no later than the enrollment's expiry.
    pub deadline_unix_ms: u64,
    /// Explicit aggregate fee limits and a monotonic budget for this call's I/O.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::stream_token_custody::Action")]
enum Action {
    Configure(SignerCustodyPolicyV1),
    Enroll {
        anchor: SignerCustodyAnchorV1,
        anchor_observed_at_unix_ms: u64,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        enrollment: Vec<u8>,
    },
}
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::stream_token_custody::Plan")]
struct Plan {
    selection: StreamTokenCustodySelection,
    action: Action,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl StreamTokenCustodySelection {
    fn validate(&self, config: &Config) -> Result<Option<SignerCustodyControlStateV1>> {
        self.binding.validate()?;
        eyre::ensure!(
            self.binding.chain_id == config.chain.to_string()
                && self.binding.network_id == *config.network_id.as_bytes()
                && self.binding.role == SignerRoleV1::StreamToken
                && self.binding.purpose
                    == SignerPurposeBindingV1::StreamToken {
                        provider_id: *self.provider_id.as_bytes()
                    }
                && self.expected_revision < STREAM_TOKEN_CUSTODY_NORMAL_REVISIONS_V1,
            "custody target differs from the selected network, provider, role or revision bound"
        );
        match &self.current {
            None => {
                eyre::ensure!(
                    self.expected_revision == 0 && self.expected_digest == [0; 32],
                    "initial custody configuration requires the absent predecessor CAS"
                );
                Ok(None)
            }
            Some(record) => {
                eyre::ensure!(
                    record.provider_id == self.provider_id
                        && record.revision > 0
                        && record.revision == self.expected_revision
                        && (record.revision == 1) == (record.predecessor_digest == [0; 32])
                        && record.request_digest != [0; 32]
                        && record.execution_height > 0
                        && record.recorded_at_unix_ms > 0
                        && record.recorded_at_unix_ms != u64::MAX,
                    "custody predecessor has inconsistent native provenance"
                );
                eyre::ensure!(
                    record.canonical_digest()? == self.expected_digest,
                    "custody predecessor differs from the independently selected digest"
                );
                let state: SignerCustodyControlStateV1 =
                    decode_bounded(&record.control_state, SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1)?;
                state.validate()?;
                record.validate_active_enrollment(&state)?;
                // Configuration may rotate keys, but can never replace the immutable role scope.
                let old = &state.policy.binding;
                eyre::ensure!(
                    old.chain_id == self.binding.chain_id
                        && old.network_id == self.binding.network_id
                        && old.role == self.binding.role
                        && old.purpose == self.binding.purpose,
                    "custody predecessor belongs to another role scope"
                );
                Ok(Some(state))
            }
        }
    }
    fn admit(&self) -> Result<()> {
        if let Some(record) = &self.current {
            eyre::ensure!(
                record.control_state.len() <= SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1
                    && record
                        .active_enrollment
                        .as_ref()
                        .is_none_or(|bytes| bytes.len() <= SIGNER_CUSTODY_MAX_BYTES_V1)
                    && norito::canonical_frame_len(record)?
                        <= STREAM_TOKEN_CUSTODY_MAX_RECORD_BYTES_V1,
                "custody predecessor exceeds its native record bound"
            );
        }
        eyre::ensure!(
            norito::canonical_frame_len(&self.binding)? <= SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1,
            "custody binding exceeds its byte bound"
        );
        Ok(())
    }
}

impl Plan {
    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        self.selection.admit()?;
        let current = self.selection.validate(config)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms != u64::MAX
                && self.deadline_unix_ms > self.validated_at_unix_ms,
            "custody operation has no original finite UTC interval"
        );
        let policy = match &self.action {
            Action::Configure(policy) => policy,
            Action::Enroll { .. } => {
                &current
                    .as_ref()
                    .ok_or_else(|| eyre!("missing custody predecessor"))?
                    .policy
            }
        };
        eyre::ensure!(
            config.key_pair.public_key() != &policy.binding.public_key
                && config.key_pair.public_key() != &policy.attester_public_key,
            "custody manager must be independent of signer and attester keys"
        );
        let action = match &self.action {
            Action::Configure(policy) => {
                let policy_bytes = encode_bounded(policy, SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1)?;
                eyre::ensure!(
                    policy.binding == self.selection.binding,
                    "custody policy differs from selected signer"
                );
                configure_signer_custody_policy_v1(current.as_ref(), policy.clone())?;
                SorafsStreamTokenCustodyActionV1::Configure(policy_bytes)
            }
            Action::Enroll {
                anchor,
                anchor_observed_at_unix_ms,
                issued_at_unix_ms,
                expires_at_unix_ms,
                enrollment,
            } => {
                let current = current
                    .ok_or_else(|| eyre!("custody enrollment requires a configured predecessor"))?;
                let predecessor = self
                    .selection
                    .current
                    .as_ref()
                    .ok_or_else(|| eyre!("missing custody predecessor"))?;
                eyre::ensure!(
                    current.policy.binding == self.selection.binding
                        && anchor.state_digest == self.selection.expected_digest
                        && anchor.height >= predecessor.execution_height
                        && self.deadline_unix_ms <= *expires_at_unix_ms,
                    "custody enrollment differs from selected current state or original expiry"
                );
                let verified = verify_signer_custody_enrollment_v1(
                    enrollment,
                    &self.selection.binding,
                    &current.policy.custody_trust(),
                    &SignerCustodyEnrollmentContextV1 {
                        now_unix_ms: self.validated_at_unix_ms,
                        anchor_observed_at_unix_ms: *anchor_observed_at_unix_ms,
                        current_anchor: *anchor,
                        next_sequence: current.next_sequence,
                        predecessor_digest: current.predecessor_digest,
                        signer_revoked: current.signer_revoked,
                        attester_revoked: current.attester_revoked,
                    },
                )?;
                eyre::ensure!(
                    verified.statement().issued_at_unix_ms == *issued_at_unix_ms
                        && verified.statement().expires_at_unix_ms == *expires_at_unix_ms,
                    "custody enrollment differs from the independently requested UTC interval"
                );
                SorafsStreamTokenCustodyActionV1::Enroll(enrollment.clone())
            }
        };
        Ok(MutateSorafsStreamTokenCustody {
            provider_id: self.selection.provider_id,
            expected_revision: self.selection.expected_revision,
            expected_digest: self.selection.expected_digest,
            action,
        }
        .into())
    }
}

pub(super) fn instructions(
    config: &Config,
    bytes: &[u8],
    kind: NativeOperationKind,
    deadline_ms: u64,
) -> Result<Vec<InstructionBox>> {
    let plan: Plan = decode_bounded(bytes, MAX_PLAN_BYTES)?;
    eyre::ensure!(
        matches!(
            (&plan.action, kind),
            (
                Action::Configure(_),
                NativeOperationKind::StreamTokenCustodyConfigure
            ) | (
                Action::Enroll { .. },
                NativeOperationKind::StreamTokenCustodyEnroll
            )
        ) && deadline_ms <= plan.deadline_unix_ms
            && deadline_ms > plan.validated_at_unix_ms,
        "custody journal changed its purpose or original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

#[derive(Clone, Copy)]
pub(super) enum CustodyExpectation<'a> {
    Configure(&'a StreamTokenCustodyConfigureRequest),
    Enroll(&'a StreamTokenCustodyEnrollRequest),
}
impl CustodyExpectation<'_> {
    fn options(&self) -> &BoundedTransactionOptions {
        match self {
            Self::Configure(request) => &request.options,
            Self::Enroll(request) => &request.options,
        }
    }
    fn plan(&self, validated_at_unix_ms: u64) -> Result<Plan> {
        validate_options(self.options())?;
        let (selection, action, deadline_unix_ms) = match self {
            Self::Configure(request) => {
                request.selection.admit()?;
                encode_bounded(&request.policy, SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1)?;
                (
                    &request.selection,
                    Action::Configure(request.policy.clone()),
                    request.deadline_unix_ms,
                )
            }
            Self::Enroll(request) => {
                request.selection.admit()?;
                eyre::ensure!(
                    !request.enrollment.is_empty()
                        && request.enrollment.len() <= SIGNER_CUSTODY_MAX_BYTES_V1,
                    "custody enrollment exceeds its canonical record bound"
                );
                (
                    &request.selection,
                    Action::Enroll {
                        anchor: request.anchor,
                        anchor_observed_at_unix_ms: request.anchor_observed_at_unix_ms,
                        issued_at_unix_ms: request.issued_at_unix_ms,
                        expires_at_unix_ms: request.expires_at_unix_ms,
                        enrollment: request.enrollment.clone(),
                    },
                    request.deadline_unix_ms,
                )
            }
        };
        Ok(Plan {
            selection: selection.clone(),
            action,
            validated_at_unix_ms,
            deadline_unix_ms,
        })
    }
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let bytes = match (self, record.operation) {
            (Self::Configure(_), NativeOperation::StreamTokenCustodyConfigure { plan, .. })
            | (Self::Enroll(_), NativeOperation::StreamTokenCustodyEnroll { plan, .. }) => plan,
            _ => eyre::bail!("custody journal differs from the selected operation purpose"),
        };
        let retained: Plan = decode_bounded(bytes, MAX_PLAN_BYTES)?;
        let expected = self.plan(retained.validated_at_unix_ms)?;
        let terms = record
            .operation
            .bounded_terms()
            .ok_or_else(|| eyre!("missing custody fee terms"))?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *bytes
                && *record.requested_fee == self.options().fee_payment
                && terms.matches_options(self.options())?,
            "custody journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the immutable custody request and preparation stages without signing or network I/O.
    /// # Errors
    /// Rejects changed selected custody request, fee limits or unsafe native custody.
    pub fn inspect_stream_token_custody_enroll_preparation(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::StreamTokenCustodyEnroll,
            Some(OperationExpectation::Custody(CustodyExpectation::Enroll(
                expected,
            ))),
        )
    }

    /// Inspect the exact preparation under an already retained private parent without signing or network I/O.
    ///
    /// Fresh child, lock, native ancestry and record checks remain mandatory. Only the original
    /// parent ancestry owners are shared; initial child absence creates no journal.
    /// # Errors
    /// Rejects invalid names, changed parent custody, unsafe journals or changed request and fee terms.
    pub fn inspect_stream_token_custody_enroll_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::StreamTokenCustodyEnroll,
            Some(OperationExpectation::Custody(CustodyExpectation::Enroll(
                expected,
            ))),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_stream_token_custody_enroll_unprepared(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::StreamTokenCustodyEnroll,
            OperationExpectation::Custody(CustodyExpectation::Enroll(expected)),
        )
    }

    /// Inspect the immutable custody request and preparation stages without signing or network I/O.
    /// # Errors
    /// Rejects changed selected custody request, fee limits or unsafe native custody.
    pub fn inspect_stream_token_custody_configure_preparation(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::StreamTokenCustodyConfigure,
            Some(OperationExpectation::Custody(
                CustodyExpectation::Configure(expected),
            )),
        )
    }

    /// Inspect the exact preparation under an already retained private parent without signing or network I/O.
    ///
    /// Fresh child, lock, native ancestry and record checks remain mandatory. Only the original
    /// parent ancestry owners are shared; initial child absence creates no journal.
    /// # Errors
    /// Rejects invalid names, changed parent custody, unsafe journals or changed request and fee terms.
    pub fn inspect_stream_token_custody_configure_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::StreamTokenCustodyConfigure,
            Some(OperationExpectation::Custody(
                CustodyExpectation::Configure(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_stream_token_custody_configure_unprepared(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::StreamTokenCustodyConfigure,
            OperationExpectation::Custody(CustodyExpectation::Configure(expected)),
        )
    }

    fn prepare_custody(
        &self,
        expected: CustodyExpectation<'_>,
        journal: &Path,
    ) -> Result<OperationReport> {
        let kind = match &expected {
            CustodyExpectation::Configure(_) => NativeOperationKind::StreamTokenCustodyConfigure,
            CustodyExpectation::Enroll(_) => NativeOperationKind::StreamTokenCustodyEnroll,
        };
        let bounded = self.with_deadline(expected.options().deadline)?;
        let choice = match &expected {
            CustodyExpectation::Configure(value) => CustodyExpectation::Configure(value),
            CustodyExpectation::Enroll(value) => CustodyExpectation::Enroll(value),
        };
        if let Some(report) = bounded.finish_existing_preparation(
            journal,
            kind,
            Some(OperationExpectation::Custody(choice)),
        )? {
            return Ok(report);
        }

        self.retain_custody_request(expected, journal)?;
        bounded
            .finish_existing_preparation(
                journal,
                kind,
                Some(OperationExpectation::Custody(expected)),
            )?
            .ok_or_else(|| eyre!("retained custody request disappeared before preparation"))
    }
    fn retain_custody_request(
        &self,
        expected: CustodyExpectation<'_>,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        let kind = match &expected {
            CustodyExpectation::Configure(_) => NativeOperationKind::StreamTokenCustodyConfigure,
            CustodyExpectation::Enroll(_) => NativeOperationKind::StreamTokenCustodyEnroll,
        };
        let bounded = self.with_deadline(expected.options().deadline)?;
        let choice = match &expected {
            CustodyExpectation::Configure(value) => CustodyExpectation::Configure(value),
            CustodyExpectation::Enroll(value) => CustodyExpectation::Enroll(value),
        };
        if let Some(report) = bounded.inspect_existing_preparation(
            journal,
            kind,
            Some(OperationExpectation::Custody(choice)),
        )? {
            return Ok(report);
        }

        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let plan = expected.plan(current_unix_ms()?)?;
        plan.instruction(&self.config)?;
        let options = expected.options();
        let mut terms = BoundedTerms::new(options)?;
        terms.deadline_ms = terms.deadline_ms.min(plan.deadline_unix_ms);
        let bytes = encode_bounded(&plan, MAX_PLAN_BYTES)?;
        let operation = match plan.action {
            Action::Configure(_) => {
                NativeOperation::StreamTokenCustodyConfigure { plan: bytes, terms }
            }
            Action::Enroll { .. } => {
                NativeOperation::StreamTokenCustodyEnroll { plan: bytes, terms }
            }
        };
        operation.instructions(&self.config)?;
        self.with_deadline(options.deadline)?.retain_native_request(
            operation,
            options.fee_payment.clone(),
            journal,
        )
    }
    fn verify_custody_journal(
        &self,
        journal: &Path,
        expected: CustodyExpectation<'_>,
    ) -> Result<SignedTransaction> {
        let kind = match &expected {
            CustodyExpectation::Configure(_) => NativeOperationKind::StreamTokenCustodyConfigure,
            CustodyExpectation::Enroll(_) => NativeOperationKind::StreamTokenCustodyEnroll,
        };
        self.inspect_preparation(journal, kind, Some(OperationExpectation::Custody(expected)))?
            .into_signed_transaction()
    }
    fn run_custody(
        &self,
        journal: &Path,
        expected: CustodyExpectation<'_>,
        submit: bool,
    ) -> Result<OperationReport> {
        let kind = match expected {
            CustodyExpectation::Configure(_) => NativeOperationKind::StreamTokenCustodyConfigure,
            CustodyExpectation::Enroll(_) => NativeOperationKind::StreamTokenCustodyEnroll,
        };
        self.with_deadline(expected.options().deadline)?
            .run_transaction_with_expectation(
                journal,
                kind,
                submit,
                Some(OperationExpectation::Custody(expected)),
            )
    }

    /// Retain or inspect the exact Configure request without HTTP, quote, payload or signature.
    /// Existing later phases remain unchanged; this cannot renew their authorization.
    /// # Errors
    /// Rejects changed policy/CAS, fees, deadline, malformed records or unsafe custody.
    pub fn retain_stream_token_custody_configure_request(
        &self,
        request: &StreamTokenCustodyConfigureRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        self.retain_custody_request(CustodyExpectation::Configure(request), journal)
    }
    /// Retain or inspect the exact already-attested Enroll request without HTTP, quote or signing.
    /// The original attester body, interval and native predecessor are preserved in every phase.
    /// # Errors
    /// Rejects changed body, policy/CAS, original bounds, fees or unsafe custody.
    pub fn retain_stream_token_custody_enroll_request(
        &self,
        request: &StreamTokenCustodyEnrollRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        self.retain_custody_request(CustodyExpectation::Enroll(request), journal)
    }
    /// Quote, sign and retain one exact Configure without submitting it.
    /// # Errors
    /// Rejects malformed policy/CAS, changed role, fees, deadline, unsafe custody or failed I/O.
    pub fn prepare_stream_token_custody_configure(
        &self,
        request: &StreamTokenCustodyConfigureRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        self.prepare_custody(CustodyExpectation::Configure(request), journal)
    }
    /// Quote, sign and retain one exactly attested Enroll without submitting it.
    /// # Errors
    /// Rejects wrong policy, signature, CAS, original interval, revocation, fees or unsafe custody.
    pub fn prepare_stream_token_custody_enroll(
        &self,
        request: &StreamTokenCustodyEnrollRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        self.prepare_custody(CustodyExpectation::Enroll(request), journal)
    }
    /// Inspect an original Configure journal, including after its UTC deadline, without I/O to a node.
    /// Returns its exact validated signed envelope for independent native inclusion verification.
    /// # Errors
    /// Rejects substituted request, signed wire, network, fees or local custody.
    pub fn verify_stream_token_custody_configure_journal(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<SignedTransaction> {
        self.verify_custody_journal(journal, CustodyExpectation::Configure(expected))
    }
    /// Inspect an original Enroll journal without renewing its attestation or transaction lifetime.
    /// Returns its exact validated signed envelope, never a freshly signed replacement.
    /// # Errors
    /// Rejects substituted request, signed wire, original interval, fees or local custody.
    pub fn verify_stream_token_custody_enroll_journal(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<SignedTransaction> {
        self.verify_custody_journal(journal, CustodyExpectation::Enroll(expected))
    }
    /// Submit the original Configure at most once, comparing its request while holding the journal.
    /// # Errors
    /// Rejects substituted authorization, expired I/O budget or unsafe evidence before dispatch.
    pub fn submit_stream_token_custody_configure(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<OperationReport> {
        self.run_custody(journal, CustodyExpectation::Configure(expected), true)
    }
    /// Submit the original Enroll at most once; ambiguous attempts are only reconciled by hash.
    /// # Errors
    /// Rejects substituted authorization, expired I/O budget or unsafe evidence before dispatch.
    pub fn submit_stream_token_custody_enroll(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<OperationReport> {
        self.run_custody(journal, CustodyExpectation::Enroll(expected), true)
    }
    /// Reconcile the original Configure without signing or submitting another transaction.
    /// # Errors
    /// Rejects changed request, expired read budget, unsafe custody or invalid node observations.
    pub fn resume_stream_token_custody_configure(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<OperationReport> {
        self.run_custody(journal, CustodyExpectation::Configure(expected), false)
    }
    /// Reconcile the original Enroll while preserving its original interval and signed transaction.
    /// # Errors
    /// Rejects changed request, expired read budget, unsafe custody or invalid node observations.
    pub fn resume_stream_token_custody_enroll(
        &self,
        journal: &Path,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<OperationReport> {
        self.run_custody(journal, CustodyExpectation::Enroll(expected), false)
    }
}

#[cfg(test)]
#[path = "operations_stream_token_custody_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "operations_stream_token_custody_request_tests.rs"]
mod request_tests;
