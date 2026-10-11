//! Closed native reserve movement decisions with immutable caller selection and sole wallet custody.
//!
//! Decide carries a movement id, current CAS/policy digest, decision and rationale. It carries no
//! provider, kind or amount: the selected provider partition remains a caller claim and does not
//! prove that the movement belongs to it. A managed owner must join authenticated original request
//! history and fresh state before offering a purpose-specific approval. Native execution alone
//! resolves the movement, checks Pending status and atomically applies its transfer. The manager
//! pays execution fees; this wallet does not debit manager principal or establish funding/readiness.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::DecideSorafsReserveMovement,
    sorafs::{
        capacity::ProviderId,
        reserve::{
            RESERVE_MAX_REASON_BYTES_V1, ReserveAuthorityPolicyV1, ReserveProviderAccountV1,
            history::validate_provider_record,
        },
    },
};
use sorafs_manifest::deal::XorQuantity;

// Local intent bounds; native policy, partition structure and economics keep their sole owners.
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_PARTITION_BYTES: usize = 32 * 1024;
const MAX_PLAN_BYTES: usize = 96 * 1024;

/// Explicit immutable caller selection for one manager-signed native movement decision.
///
/// Selection expresses intent; it proves no current state or movement-id-to-provider relation.
/// No movement kind, amount, Pending status, reserve backing or service eligibility is inferred.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::ReserveMovementDecisionSelection")]
pub struct ReserveMovementDecisionSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Nonzero provider identifier selected independently of the supplied partition.
    pub provider_id: ProviderId,
    /// Selected provider owner; the decision wire cannot prove the id resolves to this owner.
    pub provider_account: AccountId,
    /// Independently requested current partition CAS, never inferred from a candidate row.
    pub expected_provider_revision: u64,
    /// Exact selected partition's projection digest; it may lag the selected active policy.
    pub partition_policy_digest: [u8; 32],
    /// Canonical digest of the full selected active policy.
    pub policy_digest: [u8; 32],
    /// Exact selected reserve policy asset; native execution resolves any transfer.
    pub asset_definition: AssetDefinitionId,
    /// Exact selected pooled reserve custody account.
    pub custody_account: AccountId,
    /// Exact treasury receiving rent and credit repayments.
    pub treasury_account: AccountId,
    /// Exact operations authority; no signature or authority from this role is substituted.
    pub operations_authority: AccountId,
    /// Exact configured manager signing and paying fees for the native decision.
    pub decision_authority: AccountId,
}

/// One native decision with exact original policy, claimed partition, id, rationale and fees.
#[derive(Clone, Debug)]
pub struct ReserveMovementDecisionRequest {
    /// Explicit independently selected identities and CAS; never a native proof.
    pub selection: ReserveMovementDecisionSelection,
    /// Full claimed active policy, retained even though the instruction carries only its digest.
    pub policy: ReserveAuthorityPolicyV1,
    /// Full selected partition, retained without projecting its potentially lagging policy digest.
    pub partition: ReserveProviderAccountV1,
    /// Exact existing movement id; no provider, kind, amount or Pending evidence is supplied here.
    pub movement_id: [u8; 32],
    /// Exact terminal decision. Approval may transfer provider/custody assets during native execution.
    pub approve: bool,
    /// Exact nonempty UTF-8 rationale, retained without normalization.
    pub rationale: String,
    /// Original finite exclusive Unix-millisecond deadline, never renewed on recovery.
    pub deadline_unix_ms: u64,
    /// Original fee authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

fn validate_rationale(rationale: &str) -> Result<()> {
    eyre::ensure!(
        !rationale.is_empty() && rationale.len() <= RESERVE_MAX_REASON_BYTES_V1,
        "reserve movement rationale is empty or oversized"
    );
    Ok(())
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::reserve_movement_decision::Plan")]
struct Plan {
    selection: ReserveMovementDecisionSelection,
    policy: ReserveAuthorityPolicyV1,
    partition: ReserveProviderAccountV1,
    movement_id: [u8; 32],
    approve: bool,
    rationale: String,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl Plan {
    fn new(request: &ReserveMovementDecisionRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        // Admit every component before cloning any caller-owned graph or rationale.
        encode_bounded(&request.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&request.policy, MAX_POLICY_BYTES)?;
        encode_bounded(&request.partition, MAX_PARTITION_BYTES)?;
        validate_rationale(&request.rationale)?;
        Ok(Self {
            selection: request.selection.clone(),
            policy: request.policy.clone(),
            partition: request.partition.clone(),
            movement_id: request.movement_id,
            approve: request.approve,
            rationale: request.rationale.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        // Recovered plans pass the same tighter component bounds before instruction cloning.
        encode_bounded(&self.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&self.policy, MAX_POLICY_BYTES)?;
        encode_bounded(&self.partition, MAX_PARTITION_BYTES)?;
        validate_rationale(&self.rationale)?;
        self.policy.validate()?;
        let selected = &self.selection;
        validate_provider_record(&self.partition, selected.provider_id)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "reserve movement decision requires its original finite UTC authorization"
        );
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.provider_id != ProviderId::default()
                && selected.decision_authority == config.account
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
            "reserve movement decision differs from selected network, manager, claimed partition CAS or policy roles"
        );
        eyre::ensure!(
            self.movement_id != [0; 32],
            "reserve decision requires a nonzero movement id"
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
        Ok(DecideSorafsReserveMovement::new(
            self.movement_id,
            selected.expected_provider_revision,
            selected.policy_digest,
            self.approve,
            self.rationale.clone(),
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
        "reserve movement decision journal changed its original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

pub(super) struct ReserveMovementDecisionExpectation<'a>(
    pub(super) &'a ReserveMovementDecisionRequest,
);
impl ReserveMovementDecisionExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::ReserveMovementDecision { plan, terms } = record.operation else {
            eyre::bail!("reserve journal differs from selected movement-decision purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "reserve movement decision journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_reserve_movement_decision_preparation(
        &self,
        journal: &Path,
        expected: &ReserveMovementDecisionRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::ReserveMovementDecision,
            Some(OperationExpectation::ReserveMovementDecision(
                ReserveMovementDecisionExpectation(expected),
            )),
        )
    }
    /// Inspect this exact request beneath its original retained native parent.
    ///
    /// The child and original lock receive fresh admission; only ancestor descriptors are shared.
    /// Every record, signature, request and fee check uses the same canonical inspector as the
    /// absolute-path entry. This neither reuses an earlier verdict nor grants dispatch authority.
    /// # Errors
    /// Refuses invalid names, missing or replaced parents, unsafe custody and changed preparation.
    pub fn inspect_reserve_movement_decision_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &ReserveMovementDecisionRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::ReserveMovementDecision,
            Some(OperationExpectation::ReserveMovementDecision(
                ReserveMovementDecisionExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_reserve_movement_decision_unprepared(
        &self,
        journal: &Path,
        expected: &ReserveMovementDecisionRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::ReserveMovementDecision,
            OperationExpectation::ReserveMovementDecision(ReserveMovementDecisionExpectation(
                expected,
            )),
        )
    }

    /// Quote, sign and retain one manager-signed movement decision without submitting it.
    ///
    /// Inputs are structural claims; the wire cannot bind a movement id to the selected provider,
    /// kind or amount. Native execution resolves the movement and owns its status and transfer.
    /// Only the manager's execution fees are checked as this transaction's own funding.
    /// # Errors
    /// Rejects malformed partition or policy, substituted identities, fees, UTC bounds or custody.
    pub fn prepare_reserve_movement_decision(
        &self,
        request: &ReserveMovementDecisionRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ReserveMovementDecision,
                Some(OperationExpectation::ReserveMovementDecision(
                    ReserveMovementDecisionExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_reserve_movement_decision_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ReserveMovementDecision,
                Some(OperationExpectation::ReserveMovementDecision(
                    ReserveMovementDecisionExpectation(request),
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
    pub fn retain_reserve_movement_decision_request(
        &self,
        request: &ReserveMovementDecisionRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::ReserveMovementDecision,
                Some(OperationExpectation::ReserveMovementDecision(
                    ReserveMovementDecisionExpectation(request),
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
        let operation = NativeOperation::ReserveMovementDecision {
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
    pub fn verify_reserve_movement_decision_journal(
        &self,
        journal: &Path,
        expected: &ReserveMovementDecisionRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_reserve_movement_decision_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_reserve_movement_decision(
        &self,
        journal: &Path,
        expected: &ReserveMovementDecisionRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::ReserveMovementDecision,
                submit,
                Some(OperationExpectation::ReserveMovementDecision(
                    ReserveMovementDecisionExpectation(expected),
                )),
            )
    }

    /// Dispatch the original native decision at most once under the held wallet journal.
    ///
    /// Submission does not prove native inclusion, movement kind/amount/status, funding or readiness.
    /// # Errors
    /// Rejects changed request, spending terms, I/O deadline, journal custody or node observations.
    pub fn submit_reserve_movement_decision(
        &self,
        journal: &Path,
        expected: &ReserveMovementDecisionRequest,
    ) -> Result<OperationReport> {
        self.run_reserve_movement_decision(journal, expected, true)
    }

    /// Reconcile the original decision without preparing, quoting, signing or dispatching.
    /// # Errors
    /// Rejects changed request, spending terms, I/O deadline, journal custody or node observations.
    pub fn resume_reserve_movement_decision(
        &self,
        journal: &Path,
        expected: &ReserveMovementDecisionRequest,
    ) -> Result<OperationReport> {
        self.run_reserve_movement_decision(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_reserve_movement_decision_tests.rs"]
mod tests;
