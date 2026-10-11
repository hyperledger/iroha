//! Closed initial gateway policy plus ordered exact role grants through the original wallet journal.
//! Selection is caller intent, never native state proof. The manager pays fees only; native
//! permission, policy history and execution own authority. Historical inclusion and current
//! daemon Qualification/Pending/Serving remain separate. Recovery never renews or re-signs.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::{Grant, sorafs::MutateSorafsStreamTokenGateway},
    sorafs::{
        reputation::derive_stream_token_gateway_id_v1,
        stream_token_gateway::native::{
            StreamTokenGatewayActionV1, StreamTokenGatewayPolicyV1, StreamTokenGatewayRequestV1,
        },
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsStreamTokenGateway, CanOperateSorafsStreamTokenGateway,
};

// Local planning bounds, not an alternative native policy or wire format.
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 16 * 1024;
const MAX_PLAN_BYTES: usize = 64 * 1024;

/// Explicit original selection for one initial gateway policy and its two exact grants.
/// All fields are claims. Native Configure owns absence/CAS, and native Grant owns delegation.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::InitialGatewaySetupSelection")]
pub struct InitialGatewaySetupSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Exact manager signing and paying for setup.
    pub manager: AccountId,
    /// Canonical compliance gateway label selected independently from the policy.
    pub compliance_gateway_id: String,
    /// Exact network-derived gateway identifier, never a wildcard.
    pub gateway_id: [u8; 32],
    /// Exact native canonical digest of the complete initial policy.
    pub policy_digest: [u8; 32],
    /// Sole policy operator and exact destination of the Operate grant.
    pub operator: AccountId,
    /// Sole policy observer and exact destination of the Check grant.
    pub observer: AccountId,
}

/// Complete original gateway setup policy and exact role grants with UTC and fee authorization.
#[derive(Clone, Debug)]
pub struct InitialGatewaySetupRequest {
    /// Explicit target and role binding; never a native state proof.
    pub selection: InitialGatewaySetupSelection,
    /// Complete original revision-one policy; native execution remains authoritative.
    pub policy: StreamTokenGatewayPolicyV1,
    /// Original finite exclusive Unix-millisecond deadline; never renewed on recovery.
    pub deadline_unix_ms: u64,
    /// Immutable spending authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::gateway_setup::Plan")]
struct Plan {
    selection: InitialGatewaySetupSelection,
    policy: StreamTokenGatewayPolicyV1,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl Plan {
    fn new(request: &InitialGatewaySetupRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        // Admit both public components before cloning caller-owned graphs.
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
        let gateway_id = derive_stream_token_gateway_id_v1(
            &selected.network_id,
            &selected.compliance_gateway_id,
        )?;
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.manager == config.account
                && selected.gateway_id == gateway_id,
            "setup differs from selected network, manager or derived gateway"
        );
        eyre::ensure!(
            self.policy.qualification.revision == 1
                && self.policy.network_id == selected.network_id
                && self.policy.compliance_gateway_id == selected.compliance_gateway_id
                && self.policy.qualification.gateway_id == selected.gateway_id
                && self.policy.qualification.policy_digest == selected.policy_digest
                && self.policy.operators.len() == 1
                && self.policy.operators.contains(&selected.operator)
                && self.policy.observers.len() == 1
                && self.policy.observers.contains(&selected.observer),
            "initial gateway setup differs from exact revision-one policy and role grants"
        );
        let request = StreamTokenGatewayRequestV1 {
            network_id: selected.network_id,
            gateway_id: selected.gateway_id,
            expected_policy_revision: 0,
            expected_policy_digest: [0; 32],
            action: StreamTokenGatewayActionV1::Configure(self.policy.clone()),
        };
        request.validate()?;
        // Initial executor delegation requires the configured exact native policy. The complete
        // ordered sequence is reconstructed and compared by TransactionJournal::verify.
        Ok(vec![
            MutateSorafsStreamTokenGateway { request }.into(),
            Grant::account_permission(
                CanOperateSorafsStreamTokenGateway { gateway_id },
                selected.operator.clone(),
            )
            .into(),
            Grant::account_permission(
                CanCheckSorafsStreamTokenGateway { gateway_id },
                selected.observer.clone(),
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
        "setup journal changed its original UTC deadline"
    );
    plan.instructions(config)
}

pub(super) struct GatewaySetupExpectation<'a>(pub(super) &'a InitialGatewaySetupRequest);
impl GatewaySetupExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::InitialGatewaySetup { plan, terms } = record.operation else {
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
    pub fn inspect_initial_gateway_setup_preparation(
        &self,
        journal: &Path,
        expected: &InitialGatewaySetupRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::InitialGatewaySetup,
            Some(OperationExpectation::GatewaySetup(GatewaySetupExpectation(
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
    pub fn inspect_initial_gateway_setup_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &InitialGatewaySetupRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::InitialGatewaySetup,
            Some(OperationExpectation::GatewaySetup(GatewaySetupExpectation(
                expected,
            ))),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_initial_gateway_setup_unprepared(
        &self,
        journal: &Path,
        expected: &InitialGatewaySetupRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::InitialGatewaySetup,
            OperationExpectation::GatewaySetup(GatewaySetupExpectation(expected)),
        )
    }

    /// Quote, sign and retain Configure then exact Operate and Check grants without submitting.
    ///
    /// The caller supplies structural intent; native permission and state are not authenticated here.
    /// # Errors
    /// Rejects noninitial or malformed policy, substituted identities, fees, UTC bounds or unsafe journal.
    pub fn prepare_initial_gateway_setup(
        &self,
        request: &InitialGatewaySetupRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialGatewaySetup,
                Some(OperationExpectation::GatewaySetup(GatewaySetupExpectation(
                    request,
                ))),
            )?
        {
            return Ok(report);
        }
        self.retain_initial_gateway_setup_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialGatewaySetup,
                Some(OperationExpectation::GatewaySetup(GatewaySetupExpectation(
                    request,
                ))),
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
    pub fn retain_initial_gateway_setup_request(
        &self,
        request: &InitialGatewaySetupRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::InitialGatewaySetup,
                Some(OperationExpectation::GatewaySetup(GatewaySetupExpectation(
                    request,
                ))),
            )?
        {
            return Ok(report);
        }
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let plan = Plan::new(request, current_unix_ms()?)?;
        plan.instructions(&self.config)?;
        let mut terms = BoundedTerms::new(&request.options)?;
        terms.deadline_ms = terms.deadline_ms.min(plan.deadline_unix_ms);
        let operation = NativeOperation::InitialGatewaySetup {
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
    pub fn verify_initial_gateway_setup_journal(
        &self,
        journal: &Path,
        expected: &InitialGatewaySetupRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_initial_gateway_setup_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_initial_gateway_setup(
        &self,
        journal: &Path,
        expected: &InitialGatewaySetupRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::InitialGatewaySetup,
                submit,
                Some(OperationExpectation::GatewaySetup(GatewaySetupExpectation(
                    expected,
                ))),
            )
    }

    /// Submit the original initial setup transaction at most once under the held journal.
    ///
    /// Submission does not establish native inclusion, finality or current eligibility.
    /// # Errors
    /// Rejects changed request, authorization, I/O deadline, unsafe custody or invalid node observations.
    pub fn submit_initial_gateway_setup(
        &self,
        journal: &Path,
        expected: &InitialGatewaySetupRequest,
    ) -> Result<OperationReport> {
        self.run_initial_gateway_setup(journal, expected, true)
    }

    /// Reconcile the exact original transaction without signing, renewing UTC or dispatching.
    /// # Errors
    /// Rejects changed request, spending authorization, unsafe custody or invalid node observations.
    pub fn resume_initial_gateway_setup(
        &self,
        journal: &Path,
        expected: &InitialGatewaySetupRequest,
    ) -> Result<OperationReport> {
        self.run_initial_gateway_setup(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_gateway_setup_tests.rs"]
mod tests;
