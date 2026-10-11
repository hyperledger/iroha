//! Closed reserve-partition registration using the canonical native instruction and wallet journal.
//!
//! The selected policy, owner and underwriting terms are caller claims, not authenticated state.
//! Native execution checks the active policy, exact operations authority, registered provider owner
//! and partition absence. Registration starts at revision one with zero reserve, debt and interest
//! in the Warning lifecycle; it does not fund collateral, grant credit or establish service readiness.

use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::RegisterSorafsReserveAccount,
    sorafs::{
        capacity::ProviderId,
        reserve::{ReserveAuthorityPolicyV1, ReserveProviderTermsV1},
    },
};
use sorafs_manifest::deal::XorQuantity;

// Local planning bounds; the native instruction and economics remain their canonical owners.
const MAX_SELECTION_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_UNDERWRITING_BYTES: usize = 16 * 1024;
const MAX_PLAN_BYTES: usize = 80 * 1024;

/// Explicit immutable identities for one provider's first reserve-partition registration.
///
/// These fields express intent. They do not prove current policy, provider ownership, partition
/// absence, signer authority, independent inclusion or current reserve eligibility.
#[derive(Clone, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::ReserveAccountRegistrationSelection")]
pub struct ReserveAccountRegistrationSelection {
    /// Exact configured chain.
    pub chain_id: String,
    /// Exact configured network.
    pub network_id: NetworkId,
    /// Exact policy operations account, signing and paying for registration.
    pub operations_authority: AccountId,
    /// Nonzero provider identifier selected independently of the supplied terms.
    pub provider_id: ProviderId,
    /// Exact selected provider owner, independently of the supplied terms.
    pub provider_account: AccountId,
    /// Canonical digest of the exact selected policy.
    pub policy_digest: [u8; 32],
    /// Exact reserve custody, rent and credit asset.
    pub asset_definition: AssetDefinitionId,
    /// Exact pooled reserve custody account.
    pub custody_account: AccountId,
    /// Exact treasury receiving rent and credit repayments.
    pub treasury_account: AccountId,
    /// Exact reserve movement and appeal decision authority.
    pub decision_authority: AccountId,
}

/// One reserve-partition registration with original policy, underwriting and spending terms.
#[derive(Clone, Debug)]
pub struct ReserveAccountRegistrationRequest {
    /// Explicit identities and policy digest; never a native state proof.
    pub selection: ReserveAccountRegistrationSelection,
    /// Exact claimed active policy, retained even though the instruction carries only its digest.
    pub policy: ReserveAuthorityPolicyV1,
    /// Exact immutable provider terms submitted to native registration.
    pub underwriting: ReserveProviderTermsV1,
    /// Original finite exclusive Unix-millisecond deadline, never renewed on recovery.
    pub deadline_unix_ms: u64,
    /// Original fee authorization and this call's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::reserve_account::Plan")]
struct Plan {
    selection: ReserveAccountRegistrationSelection,
    policy: ReserveAuthorityPolicyV1,
    underwriting: ReserveProviderTermsV1,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}

impl Plan {
    fn new(request: &ReserveAccountRegistrationRequest, validated_at_unix_ms: u64) -> Result<Self> {
        validate_options(&request.options)?;
        // Admit every component before cloning the caller-owned graphs.
        encode_bounded(&request.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&request.policy, MAX_POLICY_BYTES)?;
        encode_bounded(&request.underwriting, MAX_UNDERWRITING_BYTES)?;
        Ok(Self {
            selection: request.selection.clone(),
            policy: request.policy.clone(),
            underwriting: request.underwriting.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn instruction(&self, config: &Config) -> Result<InstructionBox> {
        // Recovered plans pass the tighter component caps before constructing an instruction.
        encode_bounded(&self.selection, MAX_SELECTION_BYTES)?;
        encode_bounded(&self.policy, MAX_POLICY_BYTES)?;
        encode_bounded(&self.underwriting, MAX_UNDERWRITING_BYTES)?;
        self.policy.validate()?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "reserve registration requires its original finite UTC authorization"
        );
        let selected = &self.selection;
        eyre::ensure!(
            selected.chain_id == config.chain.to_string()
                && selected.network_id == config.network_id
                && selected.operations_authority == config.account
                && selected.operations_authority == self.policy.operations_authority
                && selected.provider_id != ProviderId::default()
                && selected.provider_id == self.underwriting.provider_id
                && selected.provider_account == self.underwriting.provider_account
                && selected.provider_account != self.policy.custody_account
                && selected.policy_digest == self.policy.digest()?
                && selected.asset_definition == self.policy.asset_definition
                && selected.custody_account == self.policy.custody_account
                && selected.treasury_account == self.policy.treasury_account
                && selected.decision_authority == self.policy.decision_authority,
            "reserve registration differs from selected network, operator, provider, policy or roles"
        );
        // The native economics owner validates capacity, selected class/tier and arithmetic.
        // This quote checks only structural terms; it does not authenticate an active policy.
        self.policy.economics.quote(
            self.underwriting.storage_class,
            self.underwriting.capacity_gib,
            self.underwriting.duration,
            self.underwriting.tier,
            XorQuantity::zero(),
        )?;
        Ok(
            RegisterSorafsReserveAccount::new(self.underwriting.clone(), selected.policy_digest)
                .into(),
        )
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
        "reserve registration journal changed its original UTC deadline"
    );
    Ok(vec![plan.instruction(config)?])
}

pub(super) struct ReserveAccountExpectation<'a>(pub(super) &'a ReserveAccountRegistrationRequest);
impl ReserveAccountExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::ReserveAccountRegistration { plan, terms } = record.operation else {
            eyre::bail!("reserve journal differs from selected account-registration purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "reserve registration journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_reserve_account_registration_preparation(
        &self,
        journal: &Path,
        expected: &ReserveAccountRegistrationRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::ReserveAccountRegistration,
            Some(OperationExpectation::ReserveAccount(
                ReserveAccountExpectation(expected),
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
    pub fn inspect_reserve_account_registration_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &ReserveAccountRegistrationRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::ReserveAccountRegistration,
            Some(OperationExpectation::ReserveAccount(
                ReserveAccountExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_reserve_account_registration_unprepared(
        &self,
        journal: &Path,
        expected: &ReserveAccountRegistrationRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::ReserveAccountRegistration,
            OperationExpectation::ReserveAccount(ReserveAccountExpectation(expected)),
        )
    }

    /// Quote, sign and retain one provider reserve registration without submitting it.
    ///
    /// Inputs are structural intent; native execution owns current authority and partition absence.
    /// # Errors
    /// Rejects malformed underwriting or policy, substituted identities, fees, UTC bounds or custody.
    pub fn prepare_reserve_account_registration(
        &self,
        request: &ReserveAccountRegistrationRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ReserveAccountRegistration,
                Some(OperationExpectation::ReserveAccount(
                    ReserveAccountExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_reserve_account_registration_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::ReserveAccountRegistration,
                Some(OperationExpectation::ReserveAccount(
                    ReserveAccountExpectation(request),
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
    pub fn retain_reserve_account_registration_request(
        &self,
        request: &ReserveAccountRegistrationRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::ReserveAccountRegistration,
                Some(OperationExpectation::ReserveAccount(
                    ReserveAccountExpectation(request),
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
        let operation = NativeOperation::ReserveAccountRegistration {
            plan: encode_bounded(&plan, MAX_PLAN_BYTES)?,
            terms,
        };
        operation.instructions(&self.config)?;
        self.with_deadline(request.options.deadline)?
            .retain_native_request(operation, request.options.fee_payment.clone(), journal)
    }

    /// Inspect the exact original signed envelope, including after its UTC authorization expires.
    ///
    /// This makes no HTTP request and grants no inclusion, policy, owner or readiness authority.
    /// # Errors
    /// Rejects changed request, signature, wire profile, network, fee terms or unsafe journal custody.
    pub fn verify_reserve_account_registration_journal(
        &self,
        journal: &Path,
        expected: &ReserveAccountRegistrationRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_reserve_account_registration_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_reserve_account_registration(
        &self,
        journal: &Path,
        expected: &ReserveAccountRegistrationRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::ReserveAccountRegistration,
                submit,
                Some(OperationExpectation::ReserveAccount(
                    ReserveAccountExpectation(expected),
                )),
            )
    }

    /// Dispatch the original reserve registration at most once under the held wallet journal.
    ///
    /// Submission does not prove native inclusion, current reserve state or service readiness.
    /// # Errors
    /// Rejects changed request, spending terms, I/O deadline, journal custody or node observations.
    pub fn submit_reserve_account_registration(
        &self,
        journal: &Path,
        expected: &ReserveAccountRegistrationRequest,
    ) -> Result<OperationReport> {
        self.run_reserve_account_registration(journal, expected, true)
    }

    /// Reconcile the original registration without preparing, quoting, signing or dispatching.
    /// # Errors
    /// Rejects changed request, spending terms, I/O deadline, journal custody or node observations.
    pub fn resume_reserve_account_registration(
        &self,
        journal: &Path,
        expected: &ReserveAccountRegistrationRequest,
    ) -> Result<OperationReport> {
        self.run_reserve_account_registration(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_reserve_account_tests.rs"]
mod tests;
