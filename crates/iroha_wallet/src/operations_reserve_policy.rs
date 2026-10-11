//! Closed initial reserve-policy planning over the native policy and durable wallet journal.
//!
//! Selection fields are explicit caller intent, not authenticated state. This planner proves
//! neither policy absence nor manager permission, funding, current eligibility or finality.
//! Native execution owns `CanSetSorafsReservePolicy`, entity existence and revision checks.
//! `iroha_deploy::managed::ManagedInitialReservePolicy` owns independently authenticated state
//! preflight and exact original inclusion. This planner does not activate a runtime or rewrite profiles.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::SetSorafsReservePolicy, sorafs::reserve::ReserveAuthorityPolicyV1,
};

// Local planning bounds, not an alternative native policy or wire format.
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_PLAN_BYTES: usize = 64 * 1024;

/// Explicit immutable target for an initial reserve-policy request.
///
/// These public identities and digest are claims. Constructing this value does not establish
/// on-chain policy absence, manager authority or independent inclusion/current-state evidence.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::InitialReservePolicySelection")]
pub struct InitialReservePolicySelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Account signing and paying for this governance request.
    pub manager: AccountId,
    /// Native domain-separated digest of the exact proposed policy.
    pub policy_digest: [u8; 32],
    /// Reserve custody, rent and credit asset.
    pub asset_definition: AssetDefinitionId,
    /// Exact pooled reserve custody account.
    pub custody_account: AccountId,
    /// Exact treasury receiving rent and credit repayments.
    pub treasury_account: AccountId,
    /// Exact reserve service operations authority.
    pub operations_authority: AccountId,
    /// Exact reserve movement and appeal decision authority.
    pub decision_authority: AccountId,
}

/// One initial revision-one reserve policy with original UTC and fee authorization.
#[derive(Clone, Debug)]
pub struct InitialReservePolicyRequest {
    /// Explicit target and role binding; never a native state proof.
    pub selection: InitialReservePolicySelection,
    /// Exact canonical policy; only revision one without a predecessor is accepted.
    pub policy: ReserveAuthorityPolicyV1,
    /// Original finite exclusive Unix-millisecond deadline; never renewed on recovery.
    pub deadline_unix_ms: u64,
    /// Immutable spending authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::reserve_policy::Plan")]
struct Plan {
    selection: InitialReservePolicySelection,
    policy: ReserveAuthorityPolicyV1,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl Plan {
    fn new(request: &InitialReservePolicyRequest, validated_at_unix_ms: u64) -> Result<Self> {
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

    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        // Recovery admits the tighter component bounds before constructing the owned instruction.
        encode_bounded(&self.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&self.policy, MAX_POLICY_BYTES)?;
        self.policy.validate()?;
        eyre::ensure!(
            self.policy.revision == 1 && self.policy.predecessor_policy_digest.is_none(),
            "initial reserve policy requires revision one without a predecessor"
        );
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "initial reserve policy requires its original finite UTC authorization"
        );
        let selected = &self.selection;
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.manager == config.account
                && selected.policy_digest == self.policy.digest()?
                && selected.asset_definition == self.policy.asset_definition
                && selected.custody_account == self.policy.custody_account
                && selected.treasury_account == self.policy.treasury_account
                && selected.operations_authority == self.policy.operations_authority
                && selected.decision_authority == self.policy.decision_authority,
            "initial reserve policy differs from selected network, manager, policy or roles"
        );
        Ok(SetSorafsReservePolicy {
            policy: self.policy.clone(),
        }
        .into())
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
        "reserve journal changed its original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

pub(super) struct ReservePolicyExpectation<'a>(pub(super) &'a InitialReservePolicyRequest);
impl ReservePolicyExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::InitialReservePolicy { plan, terms } = record.operation else {
            eyre::bail!("reserve journal differs from selected initial-policy purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "reserve journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_initial_reserve_policy_preparation(
        &self,
        journal: &Path,
        expected: &InitialReservePolicyRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::InitialReservePolicy,
            Some(OperationExpectation::ReservePolicy(
                ReservePolicyExpectation(expected),
            )),
        )
    }
    /// Inspect this exact request beneath its original retained native parent.
    ///
    /// Shares native ancestor custody while freshly admitting the named journal, its original
    /// lock and every bounded preparation record; this does not submit or grant authority.
    /// # Errors
    /// Rejects a missing or replaced parent, unsafe child or lock, changed request, fees,
    /// malformed durable stages and signature/UTC violations exactly as the path inspector.
    pub fn inspect_initial_reserve_policy_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &InitialReservePolicyRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::InitialReservePolicy,
            Some(OperationExpectation::ReservePolicy(
                ReservePolicyExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_initial_reserve_policy_unprepared(
        &self,
        journal: &Path,
        expected: &InitialReservePolicyRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::InitialReservePolicy,
            OperationExpectation::ReservePolicy(ReservePolicyExpectation(expected)),
        )
    }

    /// Quote, sign and retain one initial policy without submitting it.
    ///
    /// The caller supplies structural intent; native permission and state are not authenticated here.
    /// # Errors
    /// Rejects noninitial or malformed policy, substituted identities, fees, UTC bounds or unsafe journal.
    pub fn prepare_initial_reserve_policy(
        &self,
        request: &InitialReservePolicyRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialReservePolicy,
                Some(OperationExpectation::ReservePolicy(
                    ReservePolicyExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_initial_reserve_policy_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialReservePolicy,
                Some(OperationExpectation::ReservePolicy(
                    ReservePolicyExpectation(request),
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
    pub fn retain_initial_reserve_policy_request(
        &self,
        request: &InitialReservePolicyRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::InitialReservePolicy,
                Some(OperationExpectation::ReservePolicy(
                    ReservePolicyExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let plan = Plan::new(request, current_unix_ms()?)?;
        plan.instruction(&self.config)?;
        let mut terms = BoundedTerms::new(&request.options)?;
        terms.deadline_ms = terms.deadline_ms.min(plan.deadline_unix_ms);
        let operation = NativeOperation::InitialReservePolicy {
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
    pub fn verify_initial_reserve_policy_journal(
        &self,
        journal: &Path,
        expected: &InitialReservePolicyRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_initial_reserve_policy_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_initial_reserve_policy(
        &self,
        journal: &Path,
        expected: &InitialReservePolicyRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::InitialReservePolicy,
                submit,
                Some(OperationExpectation::ReservePolicy(
                    ReservePolicyExpectation(expected),
                )),
            )
    }

    /// Submit the original initial-policy transaction at most once under the held journal.
    ///
    /// Submission does not establish native inclusion, finality or current eligibility.
    /// # Errors
    /// Rejects changed request, authorization, I/O deadline, unsafe custody or invalid node observations.
    pub fn submit_initial_reserve_policy(
        &self,
        journal: &Path,
        expected: &InitialReservePolicyRequest,
    ) -> Result<OperationReport> {
        self.run_initial_reserve_policy(journal, expected, true)
    }

    /// Reconcile the exact original transaction without signing, renewing UTC or dispatching.
    /// # Errors
    /// Rejects changed request, spending authorization, unsafe custody or invalid node observations.
    pub fn resume_initial_reserve_policy(
        &self,
        journal: &Path,
        expected: &InitialReservePolicyRequest,
    ) -> Result<OperationReport> {
        self.run_initial_reserve_policy(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_reserve_policy_tests.rs"]
mod tests;
