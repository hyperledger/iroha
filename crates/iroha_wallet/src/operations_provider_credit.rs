//! Closed governed credit upserts with explicit native row CAS and sole wallet signing custody.
//!
//! The complete policy, reserve partition and current credit are caller claims. Only the credit
//! row's explicit absence/hash comparison travels in Upsert; the wire has no policy/partition CAS.
//! Native execution owns permission, registered ownership, aggregate custody and exact backed
//! bond/slash checks. The selected credit authority pays fees only. No principal transfer, reserve
//! credit borrowing, current funding, capacity or service readiness is inferred by this planner.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    isi::sorafs::UpsertProviderCredit,
    sorafs::{
        capacity::ProviderId,
        pricing::ProviderCreditRecord,
        reserve::{
            ReserveAuthorityPolicyV1, ReserveProviderAccountV1, history::validate_provider_record,
        },
    },
};

const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_PARTITION_BYTES: usize = 32 * 1024;
const MAX_CREDIT_BYTES: usize = 64 * 1024;
const MAX_PLAN_BYTES: usize = 224 * 1024;

/// Independently selected immutable identities and explicit native credit CAS.
///
/// Fields are caller intent, never proof of permission, policy, reserve backing or current state.
/// The credit authority is independent of reserve policy roles; native CanUpsert permission owns
/// admission. No omitted/default expectation or inference from a candidate row authorizes signing.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::ProviderCreditUpsertSelection")]
pub struct ProviderCreditUpsertSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Exact configured signer and fee payer; native permission remains independently required.
    pub credit_authority: AccountId,
    /// Independently selected nonzero provider identifier.
    pub provider_id: ProviderId,
    /// Exact selected governed provider owner, independently of the claimed partition.
    pub provider_account: AccountId,
    /// Explicit None requires native absence; Some requires this exact original typed row hash.
    pub expected_current: Option<HashOf<ProviderCreditRecord>>,
    /// Independently selected canonical hash of the complete desired replacement record.
    pub desired_record_hash: HashOf<ProviderCreditRecord>,
    /// Exact claimed partition revision; not a native Upsert precondition.
    pub partition_revision: u64,
    /// Exact claimed partition projection digest; it may lag the selected active policy.
    pub partition_policy_digest: [u8; 32],
    /// Canonical digest of the complete selected reserve policy; not a native Upsert precondition.
    pub policy_digest: [u8; 32],
    /// Exact selected reserve asset.
    pub asset_definition: AssetDefinitionId,
    /// Exact selected pooled reserve custody account.
    pub custody_account: AccountId,
    /// Exact selected treasury account.
    pub treasury_account: AccountId,
    /// Exact policy operations role, without substituting its authority for the signer.
    pub operations_authority: AccountId,
    /// Exact policy decision role, independently of the selected credit authority.
    pub decision_authority: AccountId,
}

/// One exact governed credit replacement with original claims, UTC and fee authorization.
#[derive(Clone, Debug)]
pub struct ProviderCreditUpsertRequest {
    /// Explicit identities, desired record hash and required native absence/current hash selection.
    pub selection: ProviderCreditUpsertSelection,
    /// Complete selected reserve policy, retained as intent rather than native CAS or proof.
    pub policy: ReserveAuthorityPolicyV1,
    /// Complete claimed reserve partition, retained without projecting its policy digest.
    pub partition: ReserveProviderAccountV1,
    /// Complete claimed existing credit row, or explicit absence; must match expected_current.
    pub current_credit: Option<ProviderCreditRecord>,
    /// Complete exact desired native record, with no inferred or silently merged fields.
    pub record: ProviderCreditRecord,
    /// Original finite exclusive Unix-millisecond authorization, never renewed by recovery.
    pub deadline_unix_ms: u64,
    /// Original fee authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::provider_credit::Plan")]
struct Plan {
    selection: ProviderCreditUpsertSelection,
    policy: ReserveAuthorityPolicyV1,
    partition: ReserveProviderAccountV1,
    current_credit: Option<ProviderCreditRecord>,
    record: ProviderCreditRecord,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

fn admit_components(
    selection: &ProviderCreditUpsertSelection,
    policy: &ReserveAuthorityPolicyV1,
    partition: &ReserveProviderAccountV1,
    current: Option<&ProviderCreditRecord>,
    record: &ProviderCreditRecord,
) -> Result<()> {
    encode_bounded(selection, MAX_SELECTION_BYTES)?;
    encode_bounded(policy, MAX_POLICY_BYTES)?;
    encode_bounded(partition, MAX_PARTITION_BYTES)?;
    if let Some(current) = current {
        encode_bounded(current, MAX_CREDIT_BYTES)?;
    }
    encode_bounded(record, MAX_CREDIT_BYTES)?;
    Ok(())
}

impl Plan {
    fn new(request: &ProviderCreditUpsertRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        // Admit all caller graphs before cloning any policy, metadata or credit record.
        admit_components(
            &request.selection,
            &request.policy,
            &request.partition,
            request.current_credit.as_ref(),
            &request.record,
        )?;
        Ok(Self {
            selection: request.selection.clone(),
            policy: request.policy.clone(),
            partition: request.partition.clone(),
            current_credit: request.current_credit.clone(),
            record: request.record.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        admit_components(
            &self.selection,
            &self.policy,
            &self.partition,
            self.current_credit.as_ref(),
            &self.record,
        )?;
        self.policy.validate()?;
        let selected = &self.selection;
        validate_provider_record(&self.partition, selected.provider_id)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "provider credit requires its original finite UTC authorization"
        );
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.credit_authority == config.account
                && selected.provider_id != ProviderId::default()
                && selected.provider_id == self.record.provider_id
                && selected.provider_account == self.partition.terms.provider_account
                && selected.partition_revision == self.partition.revision
                && selected.partition_policy_digest == self.partition.policy_digest
                && selected.policy_digest == self.policy.digest()?
                && selected.asset_definition == self.policy.asset_definition
                && selected.custody_account == self.policy.custody_account
                && selected.treasury_account == self.policy.treasury_account
                && selected.operations_authority == self.policy.operations_authority
                && selected.decision_authority == self.policy.decision_authority,
            "provider credit differs from selected network, authority, provider, claimed partition or policy"
        );
        // Canonical streaming typed hashes use the sole native domain and inherit any active
        // resource owner. Propagate typed codec/allocation refusal; never replace it with a CAS
        // mismatch, invent a new hashing scope or infer the expected hash from the candidate.
        eyre::ensure!(
            selected.desired_record_hash == HashOf::try_new(&self.record)?,
            "provider credit desired record differs from independently selected hash"
        );
        match (&selected.expected_current, &self.current_credit) {
            (None, None) => eyre::ensure!(
                self.record.slashed.is_zero() && self.record.last_penalty_epoch.is_none(),
                "initial provider credit cannot author slash history"
            ),
            (Some(expected), Some(current)) => {
                eyre::ensure!(
                    current.provider_id == selected.provider_id,
                    "provider credit current claim has a different provider"
                );
                let actual = HashOf::try_new(current)?;
                eyre::ensure!(
                    *expected == actual,
                    "provider credit current claim differs from explicit native CAS"
                );
                eyre::ensure!(
                    self.record.slashed == current.slashed
                        && self.record.last_penalty_epoch == current.last_penalty_epoch,
                    "provider credit replacement cannot reset its claimed slash lien or penalty epoch"
                );
            }
            _ => eyre::bail!(
                "provider credit requires an explicit matching absence or full current record hash"
            ),
        }
        // This mirrors native bond equality for the supplied claims only. It cannot establish
        // actual aggregate custody, active policy, capacity or registered ownership.
        let claimed_bond = self
            .partition
            .reserve_balance
            .checked_sub(&self.partition.debt_principal)?;
        let desired_locked = self.record.bonded.checked_add(&self.record.slashed)?;
        eyre::ensure!(
            &desired_locked == claimed_bond.as_quantity(),
            "provider credit replacement differs from claimed owner-funded reserve"
        );
        Ok(UpsertProviderCredit::new(selected.expected_current, self.record.clone()).into())
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
        "provider credit journal changed its original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

pub(super) struct ProviderCreditExpectation<'a>(pub(super) &'a ProviderCreditUpsertRequest);
impl ProviderCreditExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::ProviderCreditUpsert { plan, terms } = record.operation else {
            eyre::bail!("provider credit journal differs from selected upsert purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "provider credit journal differs from original full records, claims or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_provider_credit_upsert_preparation(
        &self,
        journal: &Path,
        expected: &ProviderCreditUpsertRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::ProviderCreditUpsert,
            Some(OperationExpectation::ProviderCredit(
                ProviderCreditExpectation(expected),
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
    pub fn inspect_provider_credit_upsert_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &ProviderCreditUpsertRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::ProviderCreditUpsert,
            Some(OperationExpectation::ProviderCredit(
                ProviderCreditExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_provider_credit_upsert_unprepared(
        &self,
        journal: &Path,
        expected: &ProviderCreditUpsertRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::ProviderCreditUpsert,
            OperationExpectation::ProviderCredit(ProviderCreditExpectation(expected)),
        )
    }

    /// Quote, sign and retain one native credit upsert without submitting it.
    ///
    /// Only explicit credit row absence/hash is a native CAS. Policy/partition inputs remain
    /// claims; native execution owns actual permission, backing and slash-history preservation.
    /// # Errors
    /// Refuses inconsistent identities, hashes, claims, component bounds, fees or finite UTC terms.
    pub fn prepare_provider_credit_upsert(
        &self,
        request: &ProviderCreditUpsertRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ProviderCreditUpsert,
                Some(OperationExpectation::ProviderCredit(
                    ProviderCreditExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_provider_credit_upsert_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ProviderCreditUpsert,
                Some(OperationExpectation::ProviderCredit(
                    ProviderCreditExpectation(request),
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
    pub fn retain_provider_credit_upsert_request(
        &self,
        request: &ProviderCreditUpsertRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::ProviderCreditUpsert,
                Some(OperationExpectation::ProviderCredit(
                    ProviderCreditExpectation(request),
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
        let operation = NativeOperation::ProviderCreditUpsert {
            plan: encode_bounded(&plan, MAX_PLAN_BYTES)?,
            terms,
        };
        operation.instructions(&self.config)?;
        self.with_deadline(request.options.deadline)?
            .retain_native_request(operation, request.options.fee_payment.clone(), journal)
    }

    /// Verify the unchanged sole original signed envelope offline, including after its UTC expiry.
    /// # Errors
    /// Refuses changed original records, expectations, signature profile, authority, network or fees.
    pub fn verify_provider_credit_upsert_journal(
        &self,
        journal: &Path,
        expected: &ProviderCreditUpsertRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_provider_credit_upsert_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_provider_credit_upsert(
        &self,
        journal: &Path,
        expected: &ProviderCreditUpsertRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::ProviderCreditUpsert,
                submit,
                Some(OperationExpectation::ProviderCredit(
                    ProviderCreditExpectation(expected),
                )),
            )
    }

    /// Dispatch the exact original native upsert at most once under the held durable journal.
    /// # Errors
    /// Refuses changed full records/expectations, fee or UTC terms, unsafe custody or observations.
    pub fn submit_provider_credit_upsert(
        &self,
        journal: &Path,
        expected: &ProviderCreditUpsertRequest,
    ) -> Result<OperationReport> {
        self.run_provider_credit_upsert(journal, expected, true)
    }

    /// Reconcile original work without preparing, quoting, signing or dispatching another upsert.
    /// # Errors
    /// Refuses changed records, native CAS, immutable claims, fees, journal custody or observations.
    pub fn resume_provider_credit_upsert(
        &self,
        journal: &Path,
        expected: &ProviderCreditUpsertRequest,
    ) -> Result<OperationReport> {
        self.run_provider_credit_upsert(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_provider_credit_tests.rs"]
mod tests;
