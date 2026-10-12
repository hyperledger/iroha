//! Closed immutable Musubi namespace registration through the sole wallet preparation journal.
//!
//! The selection is structural intent, not native ownership, policy or absence evidence. Native
//! Register authenticates the actual current domain/SNS owner and generation; exact replay still
//! requires that owner. This operation pays execution fees only and never creates a domain/lease.
use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::musubi::RegisterMusubiNamespaceBindingV1, musubi::MusubiNamespaceBindingV1,
};

const MAX_CHAIN_BYTES: usize = 1024;
const MAX_SELECTION_BYTES: usize = 4096;
const MAX_PLAN_BYTES: usize = 8192;

/// Independently selected complete immutable namespace intent; no current-state authority.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::MusubiNamespaceBindingSelection")]
pub struct MusubiNamespaceBindingSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured native network.
    pub network_id: NetworkId,
    /// Exact configured signer; native execution establishes current namespace ownership.
    pub owner: AccountId,
    /// Complete immutable namespace, home dataspace, scope and ownership generation.
    pub binding: MusubiNamespaceBindingV1,
    /// Exact original registry policy revision selected for native admission.
    pub expected_policy_revision: u64,
}
/// One namespace registration with immutable UTC and fee authorization.
#[derive(Clone, Debug)]
pub struct MusubiNamespaceBindingRequest {
    /// Complete independently selected original binding and signer.
    pub selection: MusubiNamespaceBindingSelection,
    /// Finite exclusive UTC deadline retained before any quotation or signature.
    pub deadline_unix_ms: u64,
    /// Original fee ceilings and this call's finite monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::musubi_namespace::Plan")]
struct Plan {
    selection: MusubiNamespaceBindingSelection,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}
impl Plan {
    fn new(request: &MusubiNamespaceBindingRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        eyre::ensure!(
            request.selection.chain_id.len() <= MAX_CHAIN_BYTES,
            "selected chain exceeds bound"
        );
        encode_bounded(&request.selection, MAX_SELECTION_BYTES)?;
        Ok(Self {
            selection: request.selection.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }
    fn instructions(&self, config: &Config) -> Result<Vec<InstructionBox>> {
        eyre::ensure!(
            self.selection.chain_id.len() <= MAX_CHAIN_BYTES,
            "retained chain exceeds bound"
        );
        encode_bounded(&self.selection, MAX_SELECTION_BYTES)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "namespace binding requires original finite UTC authorization"
        );
        eyre::ensure!(
            self.selection.chain_id == config.chain.as_str()
                && self.selection.network_id == config.network_id
                && self.selection.owner == config.account
                && self.selection.expected_policy_revision > 0,
            "namespace binding differs from selected chain, network, signer or policy"
        );
        self.selection.binding.validate()?;
        Ok(vec![
            RegisterMusubiNamespaceBindingV1::new(
                self.selection.binding.clone(),
                self.selection.expected_policy_revision,
            )
            .into(),
        ])
    }
}
pub(super) fn instructions(
    config: &Config,
    bytes: &[u8],
    deadline_ms: u64,
) -> Result<Vec<InstructionBox>> {
    let plan: Plan = decode_bounded(bytes, MAX_PLAN_BYTES)?;
    eyre::ensure!(
        deadline_ms <= plan.deadline_unix_ms && deadline_ms > plan.validated_at_unix_ms,
        "namespace binding journal changed original UTC authorization"
    );
    plan.instructions(config)
}
#[derive(Clone, Copy)]
pub(super) struct MusubiNamespaceExpectation<'a>(pub(super) &'a MusubiNamespaceBindingRequest);
impl MusubiNamespaceExpectation<'_> {
    pub(super) fn verify(self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::MusubiNamespaceBinding { plan, terms } = record.operation else {
            eyre::bail!("journal differs from selected initial namespace binding purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "namespace binding journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Recover the original finite request and its complete local phase without HTTP or signing.
    /// Only the current monotonic observation deadline comes from `options`; selected intent and
    /// fees must agree exactly. A parent must authenticate the stable journal namespace/census.
    /// Missing custody is an error, never a reason to create a fresh request or UTC window.
    /// # Errors
    /// Refuses absent, changed, malformed or unsafe custody and substituted selection/fee claims.
    pub fn recover_musubi_namespace_binding_request(
        &self,
        journal: &Path,
        selection: &MusubiNamespaceBindingSelection,
        options: &BoundedTransactionOptions,
    ) -> Result<(MusubiNamespaceBindingRequest, VerifiedNativePreparation)> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        validate_options(options)?;
        let expected = encode_bounded(selection, MAX_SELECTION_BYTES)?;
        norito::with_decode_limits_scope(preparation::LIMITS, || {
            let held = Journal::open(journal)?;
            let retained = preparation::Retained::read(&held, &self.config)?;
            let selected = retained.selection();
            let NativeOperation::MusubiNamespaceBinding { plan, .. } = selected.operation else {
                eyre::bail!("journal differs from namespace binding purpose");
            };
            let original: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
            eyre::ensure!(
                encode_bounded(&original.selection, MAX_SELECTION_BYTES)? == expected,
                "retained namespace selection differs"
            );
            let request = MusubiNamespaceBindingRequest {
                selection: original.selection,
                deadline_unix_ms: original.deadline_unix_ms,
                options: options.clone(),
            };
            retained.verify_selection(
                NativeOperationKind::MusubiNamespaceBinding,
                Some(&OperationExpectation::MusubiNamespace(
                    MusubiNamespaceExpectation(&request),
                )),
            )?;
            Ok((request, retained.into_inspection()?))
        })
    }

    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_musubi_namespace_binding_preparation(
        &self,
        journal: &Path,
        expected: &MusubiNamespaceBindingRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::MusubiNamespaceBinding,
            Some(OperationExpectation::MusubiNamespace(
                MusubiNamespaceExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_musubi_namespace_binding_unprepared(
        &self,
        journal: &Path,
        expected: &MusubiNamespaceBindingRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::MusubiNamespaceBinding,
            OperationExpectation::MusubiNamespace(MusubiNamespaceExpectation(expected)),
        )
    }

    /// Quote, sign and retain the sole owner-signed namespace Register without submitting.
    ///
    /// The caller supplies structural intent; native permission and state are not authenticated here.
    /// # Errors
    /// Rejects malformed binding, substituted identities, fees, UTC bounds or unsafe journal.
    pub fn prepare_musubi_namespace_binding(
        &self,
        request: &MusubiNamespaceBindingRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::MusubiNamespaceBinding,
                Some(OperationExpectation::MusubiNamespace(
                    MusubiNamespaceExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_musubi_namespace_binding_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::MusubiNamespaceBinding,
                Some(OperationExpectation::MusubiNamespace(
                    MusubiNamespaceExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        Err(eyre!(
            "retained native request disappeared before preparation"
        ))
    }

    /// Retain or inspect this exact request without HTTP, fee quotes, payload creation or signing.
    /// Existing payloads and signed envelopes are returned unchanged; no lifetime is renewed.
    /// # Errors
    /// Rejects changed identity, intent, fee limits, deadline, malformed records or unsafe custody.
    pub fn retain_musubi_namespace_binding_request(
        &self,
        request: &MusubiNamespaceBindingRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::MusubiNamespaceBinding,
                Some(OperationExpectation::MusubiNamespace(
                    MusubiNamespaceExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let plan = Plan::new(request, current_unix_ms()?)?;
        plan.instructions(&self.config)?;
        let mut terms = BoundedTerms::new(&request.options)?;
        terms.deadline_ms = terms.deadline_ms.min(plan.deadline_unix_ms);
        let operation = NativeOperation::MusubiNamespaceBinding {
            plan: encode_bounded(&plan, MAX_PLAN_BYTES)?,
            terms,
        };
        operation.instructions(&self.config)?;
        self.with_deadline(request.options.deadline)?
            .retain_native_request(operation, request.options.fee_payment.clone(), journal)
    }

    /// Inspect the exact retained signed envelope, including after its original UTC deadline.
    ///
    /// The returned transaction is available for independent inclusion verification; this method
    /// makes no node request and grants no current-state or current owner or signer authority.
    /// # Errors
    /// Rejects substituted request, signature, wire profile, network, fees or unsafe journal custody.
    pub fn verify_musubi_namespace_binding_journal(
        &self,
        journal: &Path,
        expected: &MusubiNamespaceBindingRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_musubi_namespace_binding_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_musubi_namespace_binding(
        &self,
        journal: &Path,
        expected: &MusubiNamespaceBindingRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::MusubiNamespaceBinding,
                submit,
                Some(OperationExpectation::MusubiNamespace(
                    MusubiNamespaceExpectation(expected),
                )),
            )
    }

    /// Submit the original initial namespace binding transaction at most once under the held journal.
    ///
    /// Submission does not establish native inclusion, finality or current eligibility.
    /// # Errors
    /// Rejects changed request, authorization, I/O deadline, unsafe custody or invalid node observations.
    pub fn submit_musubi_namespace_binding(
        &self,
        journal: &Path,
        expected: &MusubiNamespaceBindingRequest,
    ) -> Result<OperationReport> {
        self.run_musubi_namespace_binding(journal, expected, true)
    }

    /// Reconcile the exact original transaction without signing, renewing UTC or dispatching.
    /// # Errors
    /// Rejects changed request, spending authorization, unsafe custody or invalid node observations.
    pub fn resume_musubi_namespace_binding(
        &self,
        journal: &Path,
        expected: &MusubiNamespaceBindingRequest,
    ) -> Result<OperationReport> {
        self.run_musubi_namespace_binding(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_musubi_namespace_tests.rs"]
mod tests;

#[path = "operations_musubi_namespace_parent.rs"]
mod parent;
pub use parent::MusubiNamespaceBindingParent;
