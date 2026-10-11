//! Initial owner-signed native ingest authority with immutable bounded wallet recovery.
//!
//! Inputs are structural claims, not current registry, permission, signer custody or absence
//! evidence. Native Set owns its exact absence CAS and idempotent replay. This operation funds
//! only the owner's execution fees and neither transfers principal nor makes serving claims.
use super::{
    bounded::{decode_bounded, encode_bounded, validate_options},
    *,
};
use iroha_data_model::{
    isi::sorafs::SetProviderIngestCompletionAuthority,
    sorafs::{capacity::ProviderId, pin_registry::ProviderIngestCompletionAuthorityV1},
};

const MAX_CHAIN_BYTES: usize = 4096;
const MAX_AUTHORITY_BYTES: usize = 16 * 1024;
const MAX_PLAN_BYTES: usize = 32 * 1024;

/// Complete immutable structural intent for one initial provider-ingest authority.
#[derive(Clone, Debug)]
pub struct InitialProviderIngestAuthorityRequest {
    /// Exact configured chain identity.
    pub chain_id: String,
    /// Exact configured network identity.
    pub network_id: NetworkId,
    /// Exact nonzero native provider identity.
    pub provider_id: ProviderId,
    /// Complete owner, completion signer and revision-one policy binding.
    pub authority: ProviderIngestCompletionAuthorityV1,
    /// Original finite exclusive Unix-millisecond authorization deadline.
    pub deadline_unix_ms: u64,
    /// Original spending authorization and this observation's monotonic I/O deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::provider_ingest::Plan")]
struct Plan {
    chain_id: String,
    network_id: NetworkId,
    provider_id: ProviderId,
    authority: ProviderIngestCompletionAuthorityV1,
    validated_at_unix_ms: u64,
    deadline_unix_ms: u64,
}
impl Plan {
    fn new(
        request: &InitialProviderIngestAuthorityRequest,
        validated_at_unix_ms: u64,
    ) -> Result<Self> {
        validate_options(&request.options)?;
        eyre::ensure!(
            request.chain_id.len() <= MAX_CHAIN_BYTES,
            "selected chain exceeds bound"
        );
        encode_bounded(&request.authority, MAX_AUTHORITY_BYTES)?;
        Ok(Self {
            chain_id: request.chain_id.clone(),
            network_id: request.network_id,
            provider_id: request.provider_id,
            authority: request.authority.clone(),
            validated_at_unix_ms,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }
    fn instructions(&self, config: &Config) -> Result<Vec<InstructionBox>> {
        eyre::ensure!(
            self.chain_id.len() <= MAX_CHAIN_BYTES,
            "retained chain exceeds bound"
        );
        encode_bounded(&self.authority, MAX_AUTHORITY_BYTES)?;
        eyre::ensure!(
            self.validated_at_unix_ms > 0
                && self.deadline_unix_ms > self.validated_at_unix_ms
                && self.deadline_unix_ms != u64::MAX,
            "initial ingest authority requires its original finite UTC authorization"
        );
        eyre::ensure!(
            self.chain_id == config.chain.to_string()
                && self.network_id == config.network_id
                && self.authority.provider_owner == config.account
                && self.provider_id.as_bytes() != &[0; 32],
            "initial ingest authority differs from selected chain, network, provider or owner"
        );
        eyre::ensure!(
            self.authority.is_valid()
                && self.authority.signer_policy.revision == 1
                && self.authority.signer_policy.predecessor_digest.is_none(),
            "initial ingest authority requires a canonical revision-one policy without predecessor"
        );
        Ok(vec![
            SetProviderIngestCompletionAuthority::new(
                self.provider_id,
                None,
                self.authority.clone(),
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
        "ingest authority journal changed original UTC authorization"
    );
    plan.instructions(config)
}
pub(super) struct ProviderIngestExpectation<'a>(
    pub(super) &'a InitialProviderIngestAuthorityRequest,
);
impl ProviderIngestExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let NativeOperation::InitialProviderIngestAuthority { plan, terms } = record.operation
        else {
            eyre::bail!("journal differs from selected initial ingest authority purpose");
        };
        let retained: Plan = decode_bounded(plan, MAX_PLAN_BYTES)?;
        let expected = Plan::new(self.0, retained.validated_at_unix_ms)?;
        eyre::ensure!(
            encode_bounded(&expected, MAX_PLAN_BYTES)? == *plan
                && *record.requested_fee == self.0.options.fee_payment
                && terms.matches_options(&self.0.options)?,
            "ingest authority journal differs from original request or fee authorization"
        );
        Ok(())
    }
}

impl AccountService {
    /// Inspect the exact original request and every durable preparation stage without network I/O.
    /// # Errors
    /// Rejects changed identity, request, fees, malformed stages or unsafe journal custody.
    pub fn inspect_initial_provider_ingest_authority_preparation(
        &self,
        journal: &Path,
        expected: &InitialProviderIngestAuthorityRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::InitialProviderIngestAuthority,
            Some(OperationExpectation::ProviderIngest(
                ProviderIngestExpectation(expected),
            )),
        )
    }

    /// Inspect the exact preparation under an already retained private parent without signing or network I/O.
    ///
    /// Fresh child, lock, native ancestry and record checks remain mandatory. Only the original
    /// parent ancestry owners are shared; initial child absence creates no journal.
    /// # Errors
    /// Rejects invalid names, changed parent custody, unsafe journals or changed request and fee terms.
    pub fn inspect_initial_provider_ingest_authority_preparation_in_parent(
        &self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &InitialProviderIngestAuthorityRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation_in_parent(
            parent,
            name,
            NativeOperationKind::InitialProviderIngestAuthority,
            Some(OperationExpectation::ProviderIngest(
                ProviderIngestExpectation(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_initial_provider_ingest_authority_unprepared(
        &self,
        journal: &Path,
        expected: &InitialProviderIngestAuthorityRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::InitialProviderIngestAuthority,
            OperationExpectation::ProviderIngest(ProviderIngestExpectation(expected)),
        )
    }

    /// Quote, sign and retain the sole owner-signed native Set with absence CAS without submitting.
    ///
    /// The caller supplies structural intent; native permission and state are not authenticated here.
    /// # Errors
    /// Rejects noninitial or malformed policy, substituted identities, fees, UTC bounds or unsafe journal.
    pub fn prepare_initial_provider_ingest_authority(
        &self,
        request: &InitialProviderIngestAuthorityRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialProviderIngestAuthority,
                Some(OperationExpectation::ProviderIngest(
                    ProviderIngestExpectation(request),
                )),
            )?
        {
            return Ok(report);
        }
        self.retain_initial_provider_ingest_authority_request(request, journal)?;
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::InitialProviderIngestAuthority,
                Some(OperationExpectation::ProviderIngest(
                    ProviderIngestExpectation(request),
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
    pub fn retain_initial_provider_ingest_authority_request(
        &self,
        request: &InitialProviderIngestAuthorityRequest,
        journal: &Path,
    ) -> Result<VerifiedNativePreparation> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .inspect_existing_preparation(
                journal,
                NativeOperationKind::InitialProviderIngestAuthority,
                Some(OperationExpectation::ProviderIngest(
                    ProviderIngestExpectation(request),
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
        let operation = NativeOperation::InitialProviderIngestAuthority {
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
    pub fn verify_initial_provider_ingest_authority_journal(
        &self,
        journal: &Path,
        expected: &InitialProviderIngestAuthorityRequest,
    ) -> Result<SignedTransaction> {
        self.inspect_initial_provider_ingest_authority_preparation(journal, expected)?
            .into_signed_transaction()
    }

    fn run_initial_provider_ingest_authority(
        &self,
        journal: &Path,
        expected: &InitialProviderIngestAuthorityRequest,
        submit: bool,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction_with_expectation(
                journal,
                NativeOperationKind::InitialProviderIngestAuthority,
                submit,
                Some(OperationExpectation::ProviderIngest(
                    ProviderIngestExpectation(expected),
                )),
            )
    }

    /// Submit the original initial ingest authority transaction at most once under the held journal.
    ///
    /// Submission does not establish native inclusion, finality or current eligibility.
    /// # Errors
    /// Rejects changed request, authorization, I/O deadline, unsafe custody or invalid node observations.
    pub fn submit_initial_provider_ingest_authority(
        &self,
        journal: &Path,
        expected: &InitialProviderIngestAuthorityRequest,
    ) -> Result<OperationReport> {
        self.run_initial_provider_ingest_authority(journal, expected, true)
    }

    /// Reconcile the exact original transaction without signing, renewing UTC or dispatching.
    /// # Errors
    /// Rejects changed request, spending authorization, unsafe custody or invalid node observations.
    pub fn resume_initial_provider_ingest_authority(
        &self,
        journal: &Path,
        expected: &InitialProviderIngestAuthorityRequest,
    ) -> Result<OperationReport> {
        self.run_initial_provider_ingest_authority(journal, expected, false)
    }
}

#[cfg(test)]
#[path = "operations_provider_ingest_tests.rs"]
mod tests;
