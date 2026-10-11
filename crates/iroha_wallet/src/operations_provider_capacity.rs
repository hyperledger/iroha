//! Closed provider capacity declarations through the sole wallet journal.
//!
//! Selected policy, partition and credit rows are immutable caller claims, not proofs or native
//! compare-and-set conditions. Native RegisterCapacityDeclaration replaces a provider declaration
//! after authenticating its owner, actual backing and active allocations. The owner pays fees only;
//! a stake pointer is not a principal transfer, provider admission or service readiness claim.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    isi::sorafs::RegisterCapacityDeclaration,
    sorafs::{
        capacity::ProviderId,
        pricing::ProviderCreditRecord,
        reserve::{
            ReserveAuthorityPolicyV1, ReserveProviderAccountV1, history::validate_provider_record,
        },
    },
};
use iroha_model_base::name::Name;
use sorafs_manifest::capacity::CapacityDeclarationV1;

const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_PARTITION_BYTES: usize = 32 * 1024;
const MAX_CREDIT_BYTES: usize = 64 * 1024;
// Match the current native declaration reader's finite payload ceiling; no codec fallback.
const MAX_DECLARATION_BYTES: usize = 256 * 1024;
const MAX_PLAN_BYTES: usize = 416 * 1024;
const OWNER_METADATA: &str = "sorafs.owner_account_id";
const STORAGE_CLASS_METADATA: &str = "sorafs.storage_class";

/// Independently selected immutable declaration and supporting claims.
/// These fields cannot prove registered ownership, backing, current capacity or admission.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::ProviderCapacityDeclarationSelection")]
pub struct ProviderCapacityDeclarationSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Independently selected nonzero provider identifier.
    pub provider_id: ProviderId,
    /// Exact configured provider-owner signer and fee payer.
    pub provider_account: AccountId,
    /// Canonical typed hash of the complete desired declaration, including every metadata field.
    pub declaration_hash: HashOf<CapacityDeclarationV1>,
    /// Canonical typed hash of the complete selected credit projection; not a native CAS.
    pub credit_hash: HashOf<ProviderCreditRecord>,
    /// Exact selected partition revision; not a native capacity precondition.
    pub partition_revision: u64,
    /// Exact claimed partition digest, which may lag the selected active policy.
    pub partition_policy_digest: [u8; 32],
    /// Digest of the full selected policy; not a native capacity precondition.
    pub policy_digest: [u8; 32],
    /// Exact claimed reserve asset.
    pub asset_definition: AssetDefinitionId,
    /// Exact claimed reserve custody account.
    pub custody_account: AccountId,
    /// Exact claimed treasury account.
    pub treasury_account: AccountId,
    /// Exact claimed operations role, distinct from registered provider-owner authority.
    pub operations_authority: AccountId,
    /// Exact claimed decision role, distinct from provider-owner authority.
    pub decision_authority: AccountId,
}

/// Complete capacity replacement intent with original UTC and fee authorization.
#[derive(Clone, Debug)]
pub struct ProviderCapacityDeclarationRequest {
    /// Explicit selected hashes, network, owner and supporting claim identities.
    pub selection: ProviderCapacityDeclarationSelection,
    /// Complete selected policy, retained without conferring current-state authority.
    pub policy: ReserveAuthorityPolicyV1,
    /// Complete selected partition, with its original possibly lagging policy digest.
    pub partition: ReserveProviderAccountV1,
    /// Complete selected credit record, including slash history and required bond.
    pub credit: ProviderCreditRecord,
    /// Complete desired native declaration, canonically encoded without rewriting fields.
    pub declaration: CapacityDeclarationV1,
    /// Finite original exclusive Unix-millisecond authorization; recovery never renews it.
    pub deadline_unix_ms: u64,
    /// Original owner-paid fee authorization and current monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::provider_capacity::Plan")]
struct Plan {
    selection: ProviderCapacityDeclarationSelection,
    policy: ReserveAuthorityPolicyV1,
    partition: ReserveProviderAccountV1,
    credit: ProviderCreditRecord,
    // Typed storage avoids treating the canonical payload's bytes as a short collection.
    declaration: CapacityDeclarationV1,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

fn admit_components(
    selection: &ProviderCapacityDeclarationSelection,
    policy: &ReserveAuthorityPolicyV1,
    partition: &ReserveProviderAccountV1,
    credit: &ProviderCreditRecord,
    declaration: &CapacityDeclarationV1,
) -> Result<()> {
    encode_bounded(selection, MAX_SELECTION_BYTES)?;
    encode_bounded(policy, MAX_POLICY_BYTES)?;
    encode_bounded(partition, MAX_PARTITION_BYTES)?;
    encode_bounded(credit, MAX_CREDIT_BYTES)?;
    encode_bounded(declaration, MAX_DECLARATION_BYTES)?;
    Ok(())
}

impl Plan {
    fn new(
        request: &ProviderCapacityDeclarationRequest,
        validated_at_unix_ms: u64,
    ) -> Result<Self> {
        validate_options(&request.options)?;
        admit_components(
            &request.selection,
            &request.policy,
            &request.partition,
            &request.credit,
            &request.declaration,
        )?;
        Ok(Self {
            selection: request.selection.clone(),
            policy: request.policy.clone(),
            partition: request.partition.clone(),
            credit: request.credit.clone(),
            declaration: request.declaration.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        admit_components(
            &self.selection,
            &self.policy,
            &self.partition,
            &self.credit,
            &self.declaration,
        )?;
        self.policy.validate()?;
        self.declaration.validate()?;
        let selected = &self.selection;
        validate_provider_record(&self.partition, selected.provider_id)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "provider capacity requires its original finite UTC authorization"
        );
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.provider_account == config.account
                && selected.provider_id != ProviderId::default()
                && selected.provider_id.as_bytes() == &self.declaration.provider_id
                && selected.provider_id == self.credit.provider_id
                && selected.provider_account == self.partition.terms.provider_account
                && selected.partition_revision == self.partition.revision
                && selected.partition_policy_digest == self.partition.policy_digest
                && selected.policy_digest == self.policy.digest()?
                && selected.asset_definition == self.policy.asset_definition
                && selected.custody_account == self.policy.custody_account
                && selected.treasury_account == self.policy.treasury_account
                && selected.operations_authority == self.policy.operations_authority
                && selected.decision_authority == self.policy.decision_authority,
            "provider capacity differs from selected network, owner, provider, partition or policy"
        );
        // The sole typed hash owner preserves actual resource errors; neither selected hash is
        // transmitted as native CAS or inferred from an unproved candidate during submission.
        eyre::ensure!(
            selected.declaration_hash == HashOf::try_new(&self.declaration)?
                && selected.credit_hash == HashOf::try_new(&self.credit)?,
            "provider capacity differs from selected complete declaration or credit hash"
        );
        for entry in &self.declaration.metadata {
            let _: Name = entry.key.parse()?;
        }
        eyre::ensure!(
            self.declaration.metadata.iter().any(|entry| {
                entry.key == OWNER_METADATA && entry.value == selected.provider_account.to_string()
            }),
            "provider capacity requires exact canonical owner metadata"
        );
        eyre::ensure!(
            self.declaration.metadata.iter().any(|entry| {
                entry.key == STORAGE_CLASS_METADATA
                    && matches!(entry.value.as_str(), "hot" | "warm" | "cold")
            }),
            "provider capacity requires explicit lowercase storage-class metadata"
        );
        eyre::ensure!(
            self.declaration.valid_until >= self.validated_at_unix_ms / 1_000,
            "provider capacity declaration expired before original authorization"
        );
        let claimed_bond = self
            .partition
            .reserve_balance
            .checked_sub(&self.partition.debt_principal)?;
        let locked = self.credit.bonded.checked_add(&self.credit.slashed)?;
        eyre::ensure!(
            self.partition.terms.capacity_gib >= self.declaration.committed_capacity_gib
                && &locked == claimed_bond.as_quantity()
                && !self.credit.bonded.is_zero()
                && &self.credit.bonded >= self.declaration.stake.stake_amount.as_quantity()
                && self.credit.bonded >= self.credit.required_bond,
            "provider capacity exceeds selected reserve capacity or unslashed backed bond"
        );
        // Available credit, optional pricing and future valid_from are not invented admission
        // rules. Native execution independently checks current backing and active allocations.
        Ok(RegisterCapacityDeclaration::new(encode_bounded(
            &self.declaration,
            MAX_DECLARATION_BYTES,
        )?)
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
        "provider capacity journal changed its original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

pub(super) struct ProviderCapacityExpectation<'a>(
    pub(super) &'a ProviderCapacityDeclarationRequest,
);
impl ProviderCapacityExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::ProviderCapacityDeclaration { plan, terms } = record.operation else {
            eyre::bail!(
                "provider capacity journal differs from selected capacity declaration purpose"
            );
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "provider capacity journal differs from original full records, claims or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_provider_capacity_declaration_preparation(
        &self,
        journal: &Path,
        expected: &ProviderCapacityDeclarationRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::ProviderCapacityDeclaration,
            Some(OperationExpectation::ProviderCapacity(
                ProviderCapacityExpectation(expected),
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
    pub fn inspect_provider_capacity_declaration_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &ProviderCapacityDeclarationRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::ProviderCapacityDeclaration,
            Some(OperationExpectation::ProviderCapacity(
                ProviderCapacityExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_provider_capacity_declaration_unprepared(
        &self,
        journal: &Path,
        expected: &ProviderCapacityDeclarationRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::ProviderCapacityDeclaration,
            OperationExpectation::ProviderCapacity(ProviderCapacityExpectation(expected)),
        )
    }

    /// Quote, sign and retain one exact native capacity declaration without submitting it.
    ///
    /// Native registration can replace an existing declaration and carries no selected-state CAS.
    /// Policy, partition and credit remain claims; native execution owns owner/backing checks.
    /// # Errors
    /// Refuses inconsistent identities, hashes, claims, component bounds, fees or finite UTC terms.
    pub fn prepare_provider_capacity_declaration(
        &self,
        request: &ProviderCapacityDeclarationRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ProviderCapacityDeclaration,
                Some(OperationExpectation::ProviderCapacity(
                    ProviderCapacityExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_provider_capacity_declaration_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ProviderCapacityDeclaration,
                Some(OperationExpectation::ProviderCapacity(
                    ProviderCapacityExpectation(request),
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
    pub fn retain_provider_capacity_declaration_request(
        &self,
        request: &ProviderCapacityDeclarationRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::ProviderCapacityDeclaration,
                Some(OperationExpectation::ProviderCapacity(
                    ProviderCapacityExpectation(request),
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
        let operation = NativeOperation::ProviderCapacityDeclaration {
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
    pub fn verify_provider_capacity_declaration_journal(
        &self,
        journal: &Path,
        expected: &ProviderCapacityDeclarationRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_provider_capacity_declaration_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_provider_capacity_declaration(
        &self,
        journal: &Path,
        expected: &ProviderCapacityDeclarationRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::ProviderCapacityDeclaration,
                submit,
                Some(OperationExpectation::ProviderCapacity(
                    ProviderCapacityExpectation(expected),
                )),
            )
    }

    /// Dispatch the exact original native capacity declaration at most once under the held durable journal.
    /// # Errors
    /// Refuses changed full records/expectations, fee or UTC terms, unsafe custody or observations.
    pub fn submit_provider_capacity_declaration(
        &self,
        journal: &Path,
        expected: &ProviderCapacityDeclarationRequest,
    ) -> Result<OperationReport> {
        self.run_provider_capacity_declaration(journal, expected, true)
    }

    /// Reconcile original work without preparing, quoting, signing or dispatching another declaration.
    /// # Errors
    /// Refuses changed records, declaration, immutable claims, fees, journal custody or observations.
    pub fn resume_provider_capacity_declaration(
        &self,
        journal: &Path,
        expected: &ProviderCapacityDeclarationRequest,
    ) -> Result<OperationReport> {
        self.run_provider_capacity_declaration(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_provider_capacity_tests.rs"]
mod tests;
