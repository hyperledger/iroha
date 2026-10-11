//! Closed initial native reputation recorder policy through the original wallet journal.
//! Selection is caller intent, never native state proof. The manager pays fees only; native
//! permission, policy history and execution own authority. Historical inclusion and current
//! daemon Qualification/Pending/Serving remain separate. Recovery never renews or re-signs.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::SetSorafsReputationJournalAuthorityPolicy,
    sorafs::reputation::{
        ReputationJournalAuthorityPolicyV1, derive_stream_token_gateway_id_v1,
        stream_token_delivery::STREAM_TOKEN_REPUTATION_MAX_GATEWAYS_V1,
    },
};

// Local planning bounds, not an alternative native policy or wire format.
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_PLAN_BYTES: usize = 64 * 1024;

/// Explicit original selection for one sole initial native recorder policy.
/// The full policy and role fields are claims, not evidence of native absence or current authority.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::InitialReputationPolicySelection")]
pub struct InitialReputationPolicySelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Exact manager signing and paying for this policy transaction.
    pub manager: AccountId,
    /// Exact canonical labels, in strictly increasing corresponding gateway-ID order.
    pub compliance_gateway_ids: Vec<String>,
    /// Nonempty exact network-derived delivery set; one entry per selected label, at most16.
    pub gateway_ids: Vec<[u8; 32]>,
    /// Exact canonical digest of the full initial policy, including delivery fees and lifetime.
    pub policy_digest: [u8; 32],
    /// Exact policy PoR recorder; no new distinctness rule is imposed on recorder roles.
    pub por_recorder: AccountId,
    /// Exact policy capacity-dispute recorder.
    pub dispute_recorder: AccountId,
    /// Exact policy stream-token recorder.
    pub token_recorder: AccountId,
}

impl InitialReputationPolicySelection {
    /// Validate the complete bounded label/ID selection without authenticating native state.
    /// # Errors
    /// Rejects empty, oversized, repeated, unordered or incorrectly network-derived identities.
    pub fn validate_gateway_selection(&self) -> Result<()> {
        eyre::ensure!(
            !self.gateway_ids.is_empty()
                && self.gateway_ids.len() <= STREAM_TOKEN_REPUTATION_MAX_GATEWAYS_V1
                && self.compliance_gateway_ids.len() == self.gateway_ids.len(),
            "recorder gateway selection has invalid cardinality"
        );
        encode_bounded(self, MAX_SELECTION_BYTES)?;
        eyre::ensure!(
            self.gateway_ids.windows(2).all(|pair| pair[0] < pair[1]),
            "recorder gateway selection must be strictly ordered"
        );
        for (label, expected) in self.compliance_gateway_ids.iter().zip(&self.gateway_ids) {
            eyre::ensure!(
                derive_stream_token_gateway_id_v1(&self.network_id, label)? == *expected,
                "recorder gateway selection differs from its network-derived identity"
            );
        }
        Ok(())
    }
}

/// One initial revision-one recorder policy with original UTC and fee authorization.
#[derive(Clone, Debug)]
pub struct InitialReputationPolicyRequest {
    /// Explicit target and role binding; never a native state proof.
    pub selection: InitialReputationPolicySelection,
    /// Complete original revision-one policy; native execution remains authoritative.
    pub policy: ReputationJournalAuthorityPolicyV1,
    /// Original finite exclusive Unix-millisecond deadline; never renewed on recovery.
    pub deadline_unix_ms: u64,
    /// Immutable spending authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::reputation_policy::Plan")]
struct Plan {
    selection: InitialReputationPolicySelection,
    policy: ReputationJournalAuthorityPolicyV1,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl Plan {
    fn new(request: &InitialReputationPolicyRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        // Admit cardinality and both public components before cloning caller-owned graphs.
        request.selection.validate_gateway_selection()?;
        encode_bounded(&request.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&request.policy, MAX_POLICY_BYTES)?;
        Ok(Self {
            selection: request.selection.clone(),
            policy: request.policy.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn instructions(&self, config: &Config) -> Result<Vec<InstructionBox>> {
        encode_bounded(&self.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&self.policy, MAX_POLICY_BYTES)?;
        self.policy.validate()?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "setup requires its original finite UTC authorization"
        );
        let selected = &self.selection;
        selected.validate_gateway_selection()?;
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.manager == config.account,
            "setup differs from selected network, manager or derived gateway"
        );
        eyre::ensure!(
            self.policy.revision == 1
                && self.policy.predecessor_policy_digest.is_none()
                && self.policy.canonical_digest()? == selected.policy_digest
                && self.policy.por_recorder_authority == selected.por_recorder
                && self.policy.dispute_recorder_authority == selected.dispute_recorder
                && self.policy.token_recorder_authority == selected.token_recorder
                && self
                    .policy
                    .stream_token_delivery
                    .allowed_gateways
                    .as_slice()
                    == selected.gateway_ids.as_slice(),
            "initial recorder policy differs from exact revision, recorder roles or active gateway template"
        );
        // The native Network origin requires this Set to be the sole instruction.
        Ok(vec![
            SetSorafsReputationJournalAuthorityPolicy::new(self.policy.clone()).into(),
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
        "setup journal changed its original UTC deadline"
    );
    plan.instructions(config)
}

pub(super) struct ReputationPolicyExpectation<'a>(pub(super) &'a InitialReputationPolicyRequest);
impl ReputationPolicyExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::InitialReputationPolicy { plan, terms } = record.operation else {
            eyre::bail!("setup journal differs from selected setup purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "setup journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_initial_reputation_policy_preparation(
        &self,
        journal: &Path,
        expected: &InitialReputationPolicyRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::InitialReputationPolicy,
            Some(OperationExpectation::ReputationPolicy(
                ReputationPolicyExpectation(expected),
            )),
        )
    }

    /// Inspect the exact preparation under an already retained private parent without signing or network I/O.
    ///
    /// Fresh child, lock, native ancestry and record checks remain mandatory. Only the original
    /// parent ancestry owners are shared; initial child absence creates no journal.
    /// # Errors
    /// Rejects invalid names, changed parent custody, unsafe journals or changed request and fee terms.
    pub fn inspect_initial_reputation_policy_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &InitialReputationPolicyRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::InitialReputationPolicy,
            Some(OperationExpectation::ReputationPolicy(
                ReputationPolicyExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_initial_reputation_policy_unprepared(
        &self,
        journal: &Path,
        expected: &InitialReputationPolicyRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::InitialReputationPolicy,
            OperationExpectation::ReputationPolicy(ReputationPolicyExpectation(expected)),
        )
    }

    /// Quote, sign and retain one initial setup without submitting it.
    ///
    /// The caller supplies structural intent; native permission and state are not authenticated here.
    /// # Errors
    /// Rejects noninitial or malformed policy, substituted identities, fees, UTC bounds or unsafe journal.
    pub fn prepare_initial_reputation_policy(
        &self,
        request: &InitialReputationPolicyRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialReputationPolicy,
                Some(OperationExpectation::ReputationPolicy(
                    ReputationPolicyExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_initial_reputation_policy_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialReputationPolicy,
                Some(OperationExpectation::ReputationPolicy(
                    ReputationPolicyExpectation(request),
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
    pub fn retain_initial_reputation_policy_request(
        &self,
        request: &InitialReputationPolicyRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::InitialReputationPolicy,
                Some(OperationExpectation::ReputationPolicy(
                    ReputationPolicyExpectation(request),
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
        let operation = NativeOperation::InitialReputationPolicy {
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
    /// makes no node request and grants no current-state or manager-permission authority.
    /// # Errors
    /// Rejects substituted request, signature, wire profile, network, fees or unsafe journal custody.
    pub fn verify_initial_reputation_policy_journal(
        &self,
        journal: &Path,
        expected: &InitialReputationPolicyRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_initial_reputation_policy_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_initial_reputation_policy(
        &self,
        journal: &Path,
        expected: &InitialReputationPolicyRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::InitialReputationPolicy,
                submit,
                Some(OperationExpectation::ReputationPolicy(
                    ReputationPolicyExpectation(expected),
                )),
            )
    }

    /// Submit the original initial setup transaction at most once under the held journal.
    ///
    /// Submission does not establish native inclusion, finality or current eligibility.
    /// # Errors
    /// Rejects changed request, authorization, I/O deadline, unsafe custody or invalid node observations.
    pub fn submit_initial_reputation_policy(
        &self,
        journal: &Path,
        expected: &InitialReputationPolicyRequest,
    ) -> Result<OperationReport> {
        self.run_initial_reputation_policy(journal, expected, true)
    }

    /// Reconcile the exact original transaction without signing, renewing UTC or dispatching.
    /// # Errors
    /// Rejects changed request, spending authorization, unsafe custody or invalid node observations.
    pub fn resume_initial_reputation_policy(
        &self,
        journal: &Path,
        expected: &InitialReputationPolicyRequest,
    ) -> Result<OperationReport> {
        self.run_initial_reputation_policy(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_reputation_policy_tests.rs"]
mod tests;
