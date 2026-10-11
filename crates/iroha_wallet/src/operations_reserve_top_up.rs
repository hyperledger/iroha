//! Closed provider top-up requests using the canonical native movement instruction and wallet journal.
//!
//! Policy, partition and selection fields are immutable caller claims, never authenticated state.
//! Native execution checks the current policy, provider owner, partition revision, pending ceiling
//! and movement-id uniqueness. This purpose creates only a Pending TopUp request: manager approval
//! and its asset transfer are separate native operations. It grants no collateral or service readiness.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::RequestSorafsReserveMovement,
    sorafs::{
        capacity::ProviderId,
        reserve::{
            ReserveAuthorityPolicyV1, ReserveMovementKindV1, ReserveProviderAccountV1,
            history::validate_provider_record,
        },
    },
};
use sorafs_manifest::deal::XorQuantity;

// Local intent bounds; native policy, partition structure and economics keep their sole owners.
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_PARTITION_BYTES: usize = 32 * 1024;
const MAX_AMOUNT_BYTES: usize = 1024;
const MAX_PLAN_BYTES: usize = 96 * 1024;

/// Explicit immutable selection for one provider-owned reserve top-up request.
///
/// Selection expresses intent; it proves no active policy, partition inclusion, current authority,
/// free movement id, reserve backing or service eligibility.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::ReserveTopUpSelection")]
pub struct ReserveTopUpSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Nonzero provider identifier selected independently of the supplied partition.
    pub provider_id: ProviderId,
    /// Exact provider owner signing and paying for this request; not the operations role.
    pub provider_account: AccountId,
    /// Independently requested current partition CAS, never inferred from a candidate row.
    pub expected_provider_revision: u64,
    /// Exact selected partition's projection digest; it may lag the selected active policy.
    pub partition_policy_digest: [u8; 32],
    /// Canonical digest of the full selected active policy.
    pub policy_digest: [u8; 32],
    /// Exact asset selected for the later manager-approved movement.
    pub asset_definition: AssetDefinitionId,
    /// Exact pooled reserve custody account selected for later approval.
    pub custody_account: AccountId,
    /// Exact treasury receiving rent and credit repayments.
    pub treasury_account: AccountId,
    /// Exact operations authority; no signature or authority from this role is substituted.
    pub operations_authority: AccountId,
    /// Exact manager authorized to decide the movement later.
    pub decision_authority: AccountId,
}

/// One request-only top-up with original policy, partition, movement and fee authorization.
#[derive(Clone, Debug)]
pub struct ReserveTopUpRequest {
    /// Explicit independently selected identities and CAS; never a native proof.
    pub selection: ReserveTopUpSelection,
    /// Full claimed active policy, retained even though the instruction carries only its digest.
    pub policy: ReserveAuthorityPolicyV1,
    /// Full selected partition, retained without projecting its potentially lagging policy digest.
    pub partition: ReserveProviderAccountV1,
    /// Exact nonzero globally unique intent id; native execution checks its absence.
    pub movement_id: [u8; 32],
    /// Exact positive amount requested for later manager approval, not an immediate asset debit.
    pub amount: XorQuantity,
    /// Original finite exclusive Unix-millisecond deadline, never renewed on recovery.
    pub deadline_unix_ms: u64,
    /// Original fee authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::reserve_top_up::Plan")]
struct Plan {
    selection: ReserveTopUpSelection,
    policy: ReserveAuthorityPolicyV1,
    partition: ReserveProviderAccountV1,
    movement_id: [u8; 32],
    amount: XorQuantity,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl Plan {
    fn new(request: &ReserveTopUpRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        // Admit every component before cloning any caller-owned graph or amount.
        encode_bounded(&request.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&request.policy, MAX_POLICY_BYTES)?;
        encode_bounded(&request.partition, MAX_PARTITION_BYTES)?;
        encode_bounded(&request.amount, MAX_AMOUNT_BYTES)?;
        Ok(Self {
            selection: request.selection.clone(),
            policy: request.policy.clone(),
            partition: request.partition.clone(),
            movement_id: request.movement_id,
            amount: request.amount.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        // Recovered plans pass the same tighter component bounds before instruction cloning.
        encode_bounded(&self.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&self.policy, MAX_POLICY_BYTES)?;
        encode_bounded(&self.partition, MAX_PARTITION_BYTES)?;
        encode_bounded(&self.amount, MAX_AMOUNT_BYTES)?;
        self.policy.validate()?;
        let selected = &self.selection;
        validate_provider_record(&self.partition, selected.provider_id)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "reserve top-up requires its original finite UTC authorization"
        );
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.provider_id != ProviderId::default()
                && selected.provider_account == config.account
                && selected.provider_account == self.partition.terms.provider_account
                && selected.expected_provider_revision == self.partition.revision
                && selected.expected_provider_revision < u64::MAX
                && selected.partition_policy_digest == self.partition.policy_digest
                && selected.policy_digest == self.policy.digest()?
                && selected.asset_definition == self.policy.asset_definition
                && selected.custody_account == self.policy.custody_account
                && selected.treasury_account == self.policy.treasury_account
                && selected.operations_authority == self.policy.operations_authority
                && selected.decision_authority == self.policy.decision_authority,
            "reserve top-up differs from selected network, provider owner, partition CAS or policy roles"
        );
        eyre::ensure!(
            self.movement_id != [0; 32]
                && !self.amount.is_zero()
                && self.partition.pending_movements
                    < self.policy.max_pending_movements_per_provider,
            "reserve top-up requires a nonzero id and amount within the selected pending ceiling"
        );
        // Native provider_for_policy owns lazy projection. Validate terms with its selected-policy
        // economics owner without rewriting the original partition or requiring digest equality.
        let terms = &self.partition.terms;
        self.policy.economics.quote(
            terms.storage_class,
            terms.capacity_gib,
            terms.duration,
            terms.tier,
            XorQuantity::zero(),
        )?;
        Ok(RequestSorafsReserveMovement::new(
            self.movement_id,
            selected.provider_id,
            ReserveMovementKindV1::TopUp,
            self.amount.clone(),
            selected.expected_provider_revision,
            selected.policy_digest,
        )
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
        "reserve top-up request journal changed its original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

pub(super) struct ReserveTopUpExpectation<'a>(pub(super) &'a ReserveTopUpRequest);
impl ReserveTopUpExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::ReserveTopUpRequest { plan, terms } = record.operation else {
            eyre::bail!("reserve journal differs from selected top-up-request purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "reserve top-up request journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_reserve_top_up_preparation(
        &self,
        journal: &Path,
        expected: &ReserveTopUpRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::ReserveTopUpRequest,
            Some(OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(
                expected,
            ))),
        )
    }
    /// Inspect this exact request beneath its original retained native parent.
    ///
    /// The child and original lock receive fresh admission; only ancestor descriptors are shared.
    /// Every record, signature, request and fee check uses the same canonical inspector as the
    /// absolute-path entry. This neither reuses an earlier verdict nor grants dispatch authority.
    /// # Errors
    /// Refuses invalid names, missing or replaced parents, unsafe custody and changed preparation.
    pub fn inspect_reserve_top_up_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &ReserveTopUpRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::ReserveTopUpRequest,
            Some(OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(
                expected,
            ))),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_reserve_top_up_unprepared(
        &self,
        journal: &Path,
        expected: &ReserveTopUpRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::ReserveTopUpRequest,
            OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(expected)),
        )
    }

    /// Quote, sign and retain one provider reserve top-up request without submitting it.
    ///
    /// Inputs are structural intent; native execution owns current policy, provider authority,
    /// revision and movement-id uniqueness. Approval and asset transfer are separate operations.
    /// # Errors
    /// Rejects malformed partition or policy, substituted identities, fees, UTC bounds or custody.
    pub fn prepare_reserve_top_up(
        &self,
        request: &ReserveTopUpRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ReserveTopUpRequest,
                Some(OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(
                    request,
                ))),
            )?
        {
            return Ok(report);
        }
        self.retain_reserve_top_up_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ReserveTopUpRequest,
                Some(OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(
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
    pub fn retain_reserve_top_up_request(
        &self,
        request: &ReserveTopUpRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::ReserveTopUpRequest,
                Some(OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(
                    request,
                ))),
            )?
        {
            return Ok(report);
        }
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let plan = Plan::new(request, current_unix_ms()?)?;
        plan.instruction(&self.config)?;
        let mut terms = BoundedTerms::new(&request.options)?;
        terms.deadline_ms = terms.deadline_ms.min(plan.deadline_unix_ms);
        let operation = NativeOperation::ReserveTopUpRequest {
            plan: encode_bounded(&plan, MAX_PLAN_BYTES)?,
            terms,
        };
        operation.instructions(&self.config)?;
        self.with_deadline(request.options.deadline)?
            .retain_native_request(operation, request.options.fee_payment.clone(), journal)
    }

    /// Inspect the exact original signed envelope, including after its UTC authorization expires.
    ///
    /// This makes no HTTP request and grants no inclusion, policy, owner, movement or
    /// readiness authority.
    /// # Errors
    /// Rejects changed request, signature, wire profile, network, fee terms or unsafe journal custody.
    pub fn verify_reserve_top_up_journal(
        &self,
        journal: &Path,
        expected: &ReserveTopUpRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_reserve_top_up_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_reserve_top_up(
        &self,
        journal: &Path,
        expected: &ReserveTopUpRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::ReserveTopUpRequest,
                submit,
                Some(OperationExpectation::ReserveTopUp(ReserveTopUpExpectation(
                    expected,
                ))),
            )
    }

    /// Dispatch the original reserve top-up request at most once under the held wallet journal.
    ///
    /// Submission does not prove native inclusion, current reserve state or service readiness.
    /// # Errors
    /// Rejects changed request, spending terms, I/O deadline, journal custody or node observations.
    pub fn submit_reserve_top_up(
        &self,
        journal: &Path,
        expected: &ReserveTopUpRequest,
    ) -> Result<OperationReport> {
        self.run_reserve_top_up(journal, expected, true)
    }

    /// Reconcile the original top-up request without preparing, quoting, signing or dispatching.
    /// # Errors
    /// Rejects changed request, spending terms, I/O deadline, journal custody or node observations.
    pub fn resume_reserve_top_up(
        &self,
        journal: &Path,
        expected: &ReserveTopUpRequest,
    ) -> Result<OperationReport> {
        self.run_reserve_top_up(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_reserve_top_up_tests.rs"]
mod tests;
