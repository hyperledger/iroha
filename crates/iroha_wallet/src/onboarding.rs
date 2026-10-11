//! Shared trusted onboarding and faucet preparation, submission and exact recovery.
use crate::faucet_pow::solve_account_faucet_claim;
use crate::operations::{OperationReport, OperationStatus, current_unix_ms, validate_config};
use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    client::{
        AccountFaucetClaimV1, AccountFaucetPolicyV1, AccountFaucetPreparedTransactionV1,
        AccountOnboardingCurrentStateV1, AccountOnboardingPlanReceiptV1,
        AccountOnboardingPlanRequestV1, AccountOnboardingPrepareResponseV1,
        AccountOnboardingPreparedTransactionV1, AccountOnboardingProofRequiredPrepareResponseV1,
        Client as IrohaClient, PreparedOperationBindingV1,
        verify_account_faucet_prepared_transaction_v1,
        verify_account_onboarding_prepared_transaction_v1,
        verify_account_onboarding_proof_required_result_v1,
    },
    config::Config,
    data_model::{
        NetworkId,
        account::{AccountId, address::ChainDiscriminantGuard},
        alias_setup::AccountAliasName,
        asset::AssetDefinitionId,
        prelude::SignedTransaction,
        transaction::FeePaymentIntent,
    },
};
use iroha_operation_journal::Journal;
use iroha_primitives::numeric::Quantity;
use norito::json::{self, JsonDeserialize, JsonSerialize, Value};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const JOURNAL_SCHEMA: &str = "iroha.wallet.account-operation.v1";

/// Bounded options for one public prepared-operation binding.
#[derive(Clone, Debug)]
pub struct PreparationOptions {
    /// Optional canonical 32-byte lowercase hexadecimal request identity; otherwise random.
    pub request_id: Option<String>,
    /// Requested lifetime in seconds, restricted to 1 through 3600.
    pub expires_in_secs: u64,
    /// Maximum request and proof-of-work duration, restricted to 1 through 300 seconds.
    pub timeout_secs: u64,
}
impl Default for PreparationOptions {
    fn default() -> Self {
        Self {
            request_id: None,
            expires_in_secs: 120,
            timeout_secs: 30,
        }
    }
}
/// Independently authorized account and alias onboarding request.
#[derive(Clone, Debug)]
pub struct OnboardingRequest {
    /// Exact account alias to bind.
    pub alias: String,
    /// Independently trusted single-signatory onboarding issuer.
    pub issuer: AccountId,
    /// Exact unscoped permissions requested from the operator.
    pub permissions: Vec<String>,
    /// Explicit authority or sponsor fee policy, bound to the prepared envelope.
    pub fee_payment: FeePaymentIntent,
}
/// Independently trusted faucet policy and explicit preparation fee intent.
#[derive(Clone, Debug)]
pub struct FaucetRequest {
    /// Independently trusted faucet issuer.
    pub issuer: AccountId,
    /// Exact native asset definition issued by the faucet.
    pub asset_definition: AssetDefinitionId,
    /// Exact positive quantity authorized for one claim.
    pub amount: Quantity,
    /// Explicit payer and gas intent retained by the signed prepared envelope.
    pub fee_payment: FeePaymentIntent,
}
/// Shared account bootstrap lifecycle; no CLI, custody or presentation dependency.
pub struct OnboardingService {
    config: Config,
    deadline: Option<Instant>,
    cancellation: Option<Arc<AtomicBool>>,
}
impl OnboardingService {
    /// Bind one native wallet identity and safe public endpoint.
    ///
    /// # Errors
    /// Rejects endpoint credentials or a mismatched native signer.
    pub fn new(config: Config) -> Result<Self> {
        validate_config(&config)?;
        Ok(Self {
            config,
            deadline: None,
            cancellation: None,
        })
    }
    /// Bind a caller-owned cancellation signal to new preparation and dispatch.
    ///
    /// Set this signal once when cancelling; callers must never reset it. Shorter deadline
    /// views retain the same signal. Cancellation does not prevent exact read-only recovery
    /// of retained signed envelopes or a previously recorded submission attempt.
    ///
    /// # Errors
    /// Refuses replacing an existing cancellation binding with a different signal.
    pub fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Result<Self> {
        eyre::ensure!(
            self.cancellation
                .as_ref()
                .is_none_or(|original| Arc::ptr_eq(original, &cancellation)),
            "account bootstrap cancellation signal cannot be replaced"
        );
        self.cancellation = Some(cancellation);
        Ok(self)
    }
    /// Retain one absolute I/O budget across preparation, proof-of-work and exact recovery.
    /// Applying another deadline can only shorten this context's remaining budget.
    ///
    /// # Errors
    /// The requested deadline has elapsed.
    pub fn with_deadline(mut self, deadline: Instant) -> Result<Self> {
        let deadline = self.deadline.map_or(deadline, |held| held.min(deadline));
        if deadline <= Instant::now() {
            eyre::bail!("account bootstrap deadline elapsed");
        }
        self.deadline = Some(deadline);
        Ok(self)
    }
    /// Verify a trusted receipt and privately retain its exact prepared transaction without submitting.
    /// The borrowed runtime token is never retained in operation evidence.
    ///
    /// # Errors
    /// Returns policy, token, native SDK, binding, or journal errors.
    pub fn prepare_onboarding(
        &self,
        request: &OnboardingRequest,
        token: &str,
        options: &PreparationOptions,
        journal: &Path,
    ) -> Result<OperationReport> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        prepare_onboarding(
            &self.config,
            request,
            token,
            options,
            journal,
            MutationBudget {
                deadline: operation_deadline(options.timeout_secs, self.deadline)?,
                cancellation: self.cancellation.as_deref(),
            },
        )
    }
    /// Solve the bounded native puzzle and persist a trusted faucet-signed envelope before submission.
    ///
    /// # Errors
    /// Returns wrong-network puzzle, work-budget, fee/policy, SDK or journal errors.
    pub fn prepare_faucet(
        &self,
        request: &FaucetRequest,
        options: &PreparationOptions,
        journal: &Path,
    ) -> Result<OperationReport> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        prepare_faucet(
            &self.config,
            request,
            options,
            journal,
            MutationBudget {
                deadline: operation_deadline(options.timeout_secs, self.deadline)?,
                cancellation: self.cancellation.as_deref(),
            },
        )
    }
    /// Submit a saved onboarding envelope at most once, then wait within the configured timeout.
    /// The runtime token is borrowed and no waiting or recovery step repeats the submission.
    ///
    /// # Errors
    /// Returns identity, journal or authenticated observation failures; uncertainty is Pending.
    pub fn submit_onboarding(
        &self,
        journal: &Path,
        token: &str,
        timeout_secs: u64,
    ) -> Result<OperationReport> {
        self.run(journal, "onboarding", true, Some(token), timeout_secs)
    }
    /// Read-only exact onboarding transaction or account-and-alias proof reconciliation.
    ///
    /// # Errors
    /// Returns changed identity, unsafe journal or untrusted observation errors.
    pub fn resume_onboarding(&self, journal: &Path, timeout_secs: u64) -> Result<OperationReport> {
        self.run(journal, "onboarding", false, None, timeout_secs)
    }
    /// Submit a saved faucet envelope at most once, then wait within the configured timeout.
    /// No token or private issuer key is needed; waiting only reads the exact saved hash.
    ///
    /// # Errors
    /// Returns identity, journal or authenticated observation failures; uncertainty is Pending.
    pub fn submit_faucet(&self, journal: &Path, timeout_secs: u64) -> Result<OperationReport> {
        self.run(journal, "faucet", true, None, timeout_secs)
    }
    /// Read-only reconciliation of a saved faucet transaction.
    ///
    /// # Errors
    /// Returns changed identity, unsafe journal or untrusted observation errors.
    pub fn resume_faucet(&self, journal: &Path, timeout_secs: u64) -> Result<OperationReport> {
        self.run(journal, "faucet", false, None, timeout_secs)
    }
    /// Verify saved faucet bytes against the independently selected issuer, allowance and fee intent.
    /// No HTTP request or dispatch occurs; expired signed bytes remain valid recovery evidence.
    ///
    /// # Errors
    /// Unsafe custody or a different original request, wallet identity or signed envelope.
    pub fn verify_faucet_journal(&self, journal: &Path, request: &FaucetRequest) -> Result<()> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal)?;
        let operation: OperationJournalV1 = journal.read_operation()?;
        operation.verify_faucet_request(request)?;
        operation.verify(&self.config, "faucet")?;
        Ok(())
    }
    /// Submit at most once while holding the journal lock and binding its original trusted request.
    ///
    /// # Errors
    /// Changed request/configuration, unsafe journal or failed authenticated observation.
    pub fn submit_faucet_with_request(
        &self,
        journal: &Path,
        request: &FaucetRequest,
        timeout_secs: u64,
    ) -> Result<OperationReport> {
        self.run_faucet_with_request(journal, request, timeout_secs, true)
    }
    /// Reconcile only the saved faucet transaction, requiring the exact original trusted request.
    ///
    /// # Errors
    /// Changed request/configuration, unsafe journal or failed authenticated observation.
    pub fn resume_faucet_with_request(
        &self,
        journal: &Path,
        request: &FaucetRequest,
        timeout_secs: u64,
    ) -> Result<OperationReport> {
        self.run_faucet_with_request(journal, request, timeout_secs, false)
    }
    fn run_faucet_with_request(
        &self,
        journal: &Path,
        request: &FaucetRequest,
        timeout_secs: u64,
        submit: bool,
    ) -> Result<OperationReport> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        run_saved_operation(
            &self.config,
            journal,
            timeout_secs,
            operation_deadline(timeout_secs, self.deadline)?,
            SavedAction {
                kind: "faucet",
                submit,
                token: None,
                expected_faucet: Some(request),
                cancellation: self.cancellation.as_deref(),
            },
        )
    }
    fn run(
        &self,
        journal: &Path,
        kind: &'static str,
        submit: bool,
        token: Option<&str>,
        timeout_secs: u64,
    ) -> Result<OperationReport> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        run_saved_operation(
            &self.config,
            journal,
            timeout_secs,
            operation_deadline(timeout_secs, self.deadline)?,
            SavedAction {
                kind,
                submit,
                token,
                expected_faucet: None,
                cancellation: self.cancellation.as_deref(),
            },
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OperationJournalV1 {
    schema: String,
    torii_url: String,
    chain_id: String,
    network_id: NetworkId,
    chain_discriminant: u16,
    account_id: String,
    binding: PreparedOperationBindingV1,
    fee_payment: FeePaymentIntent,
    operation: OperationV1,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OperationV1 {
    Onboarding(Box<OnboardingV1>),
    Faucet(Box<FaucetV1>),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OnboardingV1 {
    issuer: AccountId,
    request: AccountOnboardingPlanRequestV1,
    receipt: AccountOnboardingPlanReceiptV1,
    response: OnboardingResponseV1,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OnboardingResponseV1 {
    Prepared(Box<AccountOnboardingPreparedTransactionV1>),
    ProofRequired(Box<AccountOnboardingProofRequiredPrepareResponseV1>),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FaucetV1 {
    requested_fee: FeePaymentIntent,
    issuer: AccountId,
    asset_definition: AssetDefinitionId,
    amount: Quantity,
    claim: AccountFaucetClaimV1,
    prepared: AccountFaucetPreparedTransactionV1,
}

impl FaucetV1 {
    fn policy(&self) -> Result<AccountFaucetPolicyV1> {
        AccountFaucetPolicyV1::try_new(
            self.issuer.clone(),
            self.asset_definition.clone(),
            self.amount.clone(),
        )
    }
}

impl PreparationOptions {
    fn identity(&self, now_ms: u64) -> Result<(String, u64)> {
        let request_id = self
            .request_id
            .clone()
            .unwrap_or_else(|| hex::encode(rand::random::<[u8; 32]>()));
        validate_request_id(&request_id).map_err(|error| eyre!(error))?;
        if !(1..=3600).contains(&self.expires_in_secs) {
            eyre::bail!("envelope lifetime must be between 1 and 3600 seconds");
        }
        let expires_at = self
            .expires_in_secs
            .checked_mul(1000)
            .and_then(|duration| now_ms.checked_add(duration))
            .ok_or_else(|| eyre!("envelope deadline overflow"))?;
        Ok((request_id, expires_at))
    }
}

/// Validate the optional public prepared-operation identity.
///
/// # Errors
/// Rejects identities that are not exactly 64 lowercase hexadecimal characters.
pub fn validate_request_id(value: &str) -> Result<String, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("must be exactly 64 lowercase hexadecimal characters".to_owned());
    }
    Ok(value.to_owned())
}

fn operation_deadline(timeout_secs: u64, held: Option<Instant>) -> Result<Instant> {
    if !(1..=300).contains(&timeout_secs) {
        eyre::bail!("request timeout must be between 1 and 300 seconds");
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(timeout_secs))
        .ok_or_else(|| eyre!("account bootstrap deadline overflow"))?;
    let deadline = held.map_or(deadline, |held| held.min(deadline));
    if deadline <= Instant::now() {
        eyre::bail!("account bootstrap deadline elapsed");
    }
    Ok(deadline)
}

fn operation_client(config: &Config, timeout_secs: u64, deadline: Instant) -> Result<IrohaClient> {
    let deadline = operation_deadline(timeout_secs, Some(deadline))?;
    let mut config = config.clone();
    config.torii_request_timeout =
        Duration::from_secs(timeout_secs).min(config.torii_request_timeout);
    Ok(IrohaClient::builder(config)
        .build()?
        .with_request_deadline(deadline))
}

#[derive(Clone, Copy)]
struct MutationBudget<'a> {
    deadline: Instant,
    cancellation: Option<&'a AtomicBool>,
}
impl MutationBudget<'_> {
    fn ensure_active(self) -> Result<()> {
        if self
            .cancellation
            .is_some_and(|signal| signal.load(Ordering::Acquire))
        {
            eyre::bail!("account bootstrap operation cancelled");
        }
        if Instant::now() >= self.deadline {
            eyre::bail!("account bootstrap deadline elapsed");
        }
        Ok(())
    }
}

fn prepare_onboarding(
    config: &Config,
    args: &OnboardingRequest,
    token: &str,
    options: &PreparationOptions,
    path: &Path,
    budget: MutationBudget<'_>,
) -> Result<OperationReport> {
    budget.ensure_active()?;
    let issuer = args.issuer.clone();
    if issuer.try_signatory().is_none() {
        eyre::bail!("onboarding issuer must be single-signatory");
    }
    let request = AccountOnboardingPlanRequestV1::try_new(
        args.alias.clone(),
        &config.account,
        args.permissions.clone(),
    )?;
    let requested_fee = args.fee_payment.clone();
    requested_fee.validate()?;
    let (request_id, deadline) = options.identity(current_unix_ms()?)?;
    let client = operation_client(config, options.timeout_secs, budget.deadline)?;
    budget.ensure_active()?;
    let receipt = client.plan_account_onboarding(&request, token)?;
    budget.ensure_active()?;
    verify_trusted_issuer(&receipt, &issuer)?;
    let binding = PreparedOperationBindingV1::onboarding(
        &receipt,
        request_id,
        deadline.min(receipt.body.valid_until_ms),
    )?;
    budget.ensure_active()?;
    let response = client.prepare_account_onboarding_transaction(
        &request,
        &receipt,
        &binding,
        &requested_fee,
        token,
    )?;
    let (response, fee_payment) = match response {
        AccountOnboardingPrepareResponseV1::Prepared(prepared) => {
            let fee = prepared.fee_payment.clone();
            (OnboardingResponseV1::Prepared(prepared), fee)
        }
        AccountOnboardingPrepareResponseV1::ProofRequired(proof) => {
            (OnboardingResponseV1::ProofRequired(proof), requested_fee)
        }
    };
    let operation = new_operation(
        config,
        binding,
        fee_payment,
        OperationV1::Onboarding(Box::new(OnboardingV1 {
            issuer,
            request,
            receipt,
            response,
        })),
    );
    let transaction = operation.verify(config, "onboarding")?;
    // Planning and preparation do not dispatch a transaction. Establish durable operation
    // custody only once the verified envelope exists, so an offline preparation can retry
    // without leaving an empty journal that could be mistaken for submitted work.
    budget.ensure_active()?;
    let journal = Journal::create_prepared(path, &operation)?;
    report(
        &journal,
        &operation,
        if transaction.is_some() {
            "Prepared"
        } else {
            "ProofRequired"
        },
        None,
    )
}

fn prepare_faucet(
    config: &Config,
    args: &FaucetRequest,
    options: &PreparationOptions,
    path: &Path,
    budget: MutationBudget<'_>,
) -> Result<OperationReport> {
    budget.ensure_active()?;
    let issuer = args.issuer.clone();
    let asset_definition = args.asset_definition.clone();
    let amount = args.amount.clone();
    let policy =
        AccountFaucetPolicyV1::try_new(issuer.clone(), asset_definition.clone(), amount.clone())?;
    let requested_fee = args.fee_payment.clone();
    requested_fee.validate()?;
    let (request_id, expires_at) = options.identity(current_unix_ms()?)?;
    let client = operation_client(config, options.timeout_secs, budget.deadline)?;
    let deadline = observation_deadline(options.timeout_secs, expires_at)?.min(budget.deadline);
    budget.ensure_active()?;
    let claim = solve_account_faucet_claim(
        config.torii_api_url.as_str(),
        &config.account,
        &config.network_id,
        config.account_chain_discriminant,
        deadline,
    )?;
    budget.ensure_active()?;
    let binding = PreparedOperationBindingV1::faucet(&claim, request_id, expires_at)?;
    budget.ensure_active()?;
    let prepared =
        client.prepare_account_faucet_transaction(&claim, &binding, &requested_fee, &policy)?;
    let operation = new_operation(
        config,
        binding,
        prepared.fee_payment.clone(),
        OperationV1::Faucet(Box::new(FaucetV1 {
            requested_fee,
            issuer,
            asset_definition,
            amount,
            claim,
            prepared,
        })),
    );
    operation.verify(config, "faucet")?;
    budget.ensure_active()?;
    let journal = Journal::create_prepared(path, &operation)?;
    report(&journal, &operation, "Prepared", None)
}

fn new_operation(
    config: &Config,
    binding: PreparedOperationBindingV1,
    fee_payment: FeePaymentIntent,
    operation: OperationV1,
) -> OperationJournalV1 {
    OperationJournalV1 {
        schema: JOURNAL_SCHEMA.to_owned(),
        torii_url: config.torii_api_url.to_string(),
        chain_id: config.chain.to_string(),
        network_id: config.network_id,
        chain_discriminant: config.account_chain_discriminant,
        account_id: config.account.to_string(),
        binding,
        fee_payment,
        operation,
    }
}

fn verify_trusted_issuer(
    receipt: &AccountOnboardingPlanReceiptV1,
    issuer: &AccountId,
) -> Result<()> {
    if &receipt.body.authority != issuer || !receipt.verify() {
        eyre::bail!("onboarding receipt is not signed by the independently trusted issuer");
    }
    Ok(())
}

impl OperationJournalV1 {
    fn verify_faucet_request(&self, request: &FaucetRequest) -> Result<()> {
        let OperationV1::Faucet(faucet) = &self.operation else {
            eyre::bail!("saved operation is not a faucet claim");
        };
        if faucet.issuer != request.issuer
            || faucet.asset_definition != request.asset_definition
            || faucet.amount != request.amount
            || faucet.requested_fee != request.fee_payment
        {
            eyre::bail!("saved faucet differs from the exact trusted request");
        }
        crate::operations::verify_fee_intent_limits(&request.fee_payment, &self.fee_payment)
    }
    fn kind(&self) -> &'static str {
        match self.operation {
            OperationV1::Onboarding(_) => "onboarding",
            OperationV1::Faucet(_) => "faucet",
        }
    }

    fn verify(&self, config: &Config, expected_kind: &str) -> Result<Option<SignedTransaction>> {
        if self.schema != JOURNAL_SCHEMA
            || self.kind() != expected_kind
            || self.torii_url != config.torii_api_url.as_str()
            || self.chain_id != config.chain.to_string()
            || self.network_id != config.network_id
            || self.chain_discriminant != config.account_chain_discriminant
            || self.account_id != config.account.to_string()
        {
            eyre::bail!(
                "operation journal differs from the configured endpoint, network, profile, account, or operation"
            );
        }
        match &self.operation {
            OperationV1::Onboarding(operation) => {
                verify_trusted_issuer(&operation.receipt, &operation.issuer)?;
                if operation.request.account_id != self.account_id {
                    eyre::bail!("onboarding journal targets another account");
                }
                match &operation.response {
                    OnboardingResponseV1::Prepared(prepared) => {
                        if prepared.fee_payment != self.fee_payment {
                            eyre::bail!("journal fee intent differs from its signed transaction");
                        }
                        verify_account_onboarding_prepared_transaction_v1(
                            self.network_id,
                            &operation.request,
                            prepared,
                            &operation.receipt,
                            &self.binding,
                            &self.fee_payment,
                        )
                        .map(Some)
                    }
                    OnboardingResponseV1::ProofRequired(proof) => {
                        verify_account_onboarding_proof_required_result_v1(
                            self.network_id,
                            &operation.request,
                            proof,
                            &operation.receipt,
                            &self.binding,
                        )?;
                        Ok(None)
                    }
                }
            }
            OperationV1::Faucet(operation) => {
                crate::operations::verify_fee_intent_limits(
                    &operation.requested_fee,
                    &self.fee_payment,
                )?;
                if operation.claim.account_id != self.account_id
                    || operation.prepared.fee_payment != self.fee_payment
                {
                    eyre::bail!("faucet journal targets another account or fee intent");
                }
                verify_account_faucet_prepared_transaction_v1(
                    self.network_id,
                    &operation.prepared,
                    &operation.claim,
                    &self.binding,
                    &self.fee_payment,
                    &operation.policy()?,
                )
                .map(Some)
            }
        }
    }
}

struct SavedAction<'a> {
    kind: &'static str,
    submit: bool,
    token: Option<&'a str>,
    expected_faucet: Option<&'a FaucetRequest>,
    cancellation: Option<&'a AtomicBool>,
}

fn run_saved_operation(
    config: &Config,
    path: &Path,
    timeout_secs: u64,
    deadline: Instant,
    action: SavedAction<'_>,
) -> Result<OperationReport> {
    run_saved_operation_with_client(config, path, timeout_secs, deadline, action, || {
        operation_client(config, timeout_secs, deadline)
    })
}

fn run_saved_operation_with_client(
    config: &Config,
    path: &Path,
    timeout_secs: u64,
    deadline: Instant,
    action: SavedAction<'_>,
    make_client: impl FnOnce() -> Result<IrohaClient>,
) -> Result<OperationReport> {
    let journal = Journal::open(path)?;
    let operation: OperationJournalV1 = journal.read_operation()?;
    if let Some(request) = action.expected_faucet {
        operation.verify_faucet_request(request)?;
    }
    let transaction = operation.verify(config, action.kind)?;
    let client = make_client()?;
    let mut before = observe(&client, &operation, transaction.as_ref())?;
    if before.status == "Absent" {
        if journal.submission_recorded(&operation)? {
            // A dispatch may have succeeded even after its acknowledgement was lost.
            before.status = "Pending";
        } else if current_unix_ms()? >= operation.binding.execution_expires_at_unix_ms {
            before.status = "Expired";
        }
    }
    if !action.submit || before.status != "Absent" {
        return report(
            &journal,
            &operation,
            before.status,
            before.evidence.as_ref(),
        );
    }
    if current_unix_ms()? >= operation.binding.execution_expires_at_unix_ms {
        return report(&journal, &operation, "Expired", None);
    }
    let budget = MutationBudget {
        deadline,
        cancellation: action.cancellation,
    };
    // An exact preflight read can finish after the caller cancels. Preserve its signed
    // operation, but refuse any fresh dispatch marker or server mutation.
    budget.ensure_active()?;
    // This durable marker is installed before the only mutation call. A failed response is
    // ambiguous; the immutable transaction remains the sole object accepted on every retry.
    if !journal.record_submission(&operation)? {
        return report(&journal, &operation, "Pending", None);
    }
    // Cancellation while the durable marker is being published remains an ambiguous
    // retained attempt. Recovery never clears it or grants a replacement submission.
    budget.ensure_active()?;
    let _submission = match &operation.operation {
        OperationV1::Onboarding(onboarding) => match &onboarding.response {
            OnboardingResponseV1::Prepared(prepared) => {
                let token = action
                    .token
                    .ok_or_else(|| eyre!("onboarding submission requires a private token"))?;
                client.submit_prepared_account_onboarding_transaction(
                    &onboarding.request,
                    prepared,
                    &operation.fee_payment,
                    token,
                )
            }
            OnboardingResponseV1::ProofRequired(_) => {
                eyre::bail!("proof-required onboarding has no transaction to submit")
            }
        },
        OperationV1::Faucet(faucet) => client.submit_prepared_account_faucet_transaction(
            &faucet.prepared,
            &operation.fee_payment,
            &faucet.policy()?,
        ),
    };
    let after = observe_after_submission(
        &client,
        &operation,
        transaction.as_ref(),
        iroha::client::TransactionWaitOptions {
            timeout: Duration::from_secs(timeout_secs)
                .min(config.transaction_status_timeout)
                .min(deadline.saturating_duration_since(Instant::now())),
            ..Default::default()
        },
    );
    match after {
        Ok(observation) if observation.status != "Absent" => report(
            &journal,
            &operation,
            observation.status,
            observation.evidence.as_ref(),
        ),
        _ => report(&journal, &operation, "Pending", None),
    }
}

fn observe_after_submission(
    client: &IrohaClient,
    operation: &OperationJournalV1,
    transaction: Option<&SignedTransaction>,
    options: iroha::client::TransactionWaitOptions,
) -> Result<Observation> {
    let deadline = std::time::Instant::now()
        .checked_add(options.timeout)
        .ok_or_else(|| eyre!("account-operation wait deadline overflow"))?;
    let client = client.with_request_deadline(deadline);
    if let Some(transaction) = transaction {
        // The canonical SDK waiter reads only the saved hash. Its terminal hint is not
        // enough for success: exact committed-wire readback shares the same deadline.
        let _wait = client.wait_for_transaction_applied(transaction.hash(), options);
    }
    if std::time::Instant::now() >= deadline {
        return Ok(Observation {
            status: "Pending",
            evidence: None,
        });
    }
    observe(&client, operation, transaction)
}

struct Observation {
    status: &'static str,
    evidence: Option<Value>,
}

fn observe(
    client: &IrohaClient,
    operation: &OperationJournalV1,
    transaction: Option<&SignedTransaction>,
) -> Result<Observation> {
    let Some(transaction) = transaction else {
        let OperationV1::Onboarding(onboarding) = &operation.operation else {
            eyre::bail!("faucet journal omitted its transaction");
        };
        let account = AccountId::parse_encoded(&operation.account_id)?;
        let alias = onboarding.request.alias.parse::<AccountAliasName>()?;
        return Ok(
            match client.prove_account_onboarding_current_state(&account, &alias)? {
                AccountOnboardingCurrentStateV1::Applied {
                    block_height,
                    block_hash,
                } => Observation {
                    status: "AlreadyPresent",
                    evidence: Some(norito::json!({
                        "kind": "account_alias_current_state",
                        "block_height": (block_height.get()),
                        "block_hash": (block_hash.to_string())
                    })),
                },
                AccountOnboardingCurrentStateV1::AliasAbsent { .. } => Observation {
                    status: "ProofRequired",
                    evidence: None,
                },
                AccountOnboardingCurrentStateV1::AliasConflict { .. } => Observation {
                    status: "AliasConflict",
                    evidence: None,
                },
            },
        );
    };
    let observation = crate::operations::observe_transaction(client, transaction)?;
    Ok(Observation {
        status: observation.status.as_str(),
        evidence: observation.evidence,
    })
}

fn report(
    journal: &Journal,
    operation: &OperationJournalV1,
    status: &str,
    evidence: Option<&Value>,
) -> Result<OperationReport> {
    let transaction_hash = match &operation.operation {
        OperationV1::Onboarding(onboarding) => match &onboarding.response {
            OnboardingResponseV1::Prepared(prepared) => {
                Some(prepared.transaction_hash_hex.as_str())
            }
            OnboardingResponseV1::ProofRequired(_) => None,
        },
        OperationV1::Faucet(faucet) => Some(faucet.prepared.transaction_hash_hex.as_str()),
    };
    let mut value = norito::json!({
        "schema": "iroha.wallet.account-operation-result.v1",
        "operation": (operation.kind()),
        "status": status,
        "account_id": (operation.account_id),
        "network_id": (operation.network_id.to_string()),
        "chain_discriminant": (operation.chain_discriminant),
        "request_id": (operation.binding.request_id),
        "expires_at_unix_ms": (operation.binding.execution_expires_at_unix_ms),
        "fee_payment": (operation.fee_payment),
        "transaction_hash": transaction_hash,
        "journal": (journal.path().to_string_lossy().to_string()),
        "evidence": evidence
    });
    if let Value::Object(fields) = &mut value {
        match &operation.operation {
            OperationV1::Onboarding(onboarding) => {
                fields.insert(
                    "issuer".to_owned(),
                    Value::String(onboarding.issuer.to_string()),
                );
                fields.insert(
                    "alias".to_owned(),
                    Value::String(onboarding.request.alias.clone()),
                );
                fields.insert(
                    "permissions_requested".to_owned(),
                    json::to_value(&onboarding.request.permissions)?,
                );
                fields.insert(
                    "owner_auto_renew_follow_up".to_owned(),
                    Value::Bool(
                        onboarding
                            .receipt
                            .body
                            .owner_auto_renew_instruction
                            .is_some(),
                    ),
                );
            }
            OperationV1::Faucet(faucet) => {
                fields.insert(
                    "issuer".to_owned(),
                    Value::String(faucet.issuer.to_string()),
                );
                fields.insert(
                    "asset_definition".to_owned(),
                    Value::String(faucet.asset_definition.to_string()),
                );
                fields.insert(
                    "amount".to_owned(),
                    Value::String(faucet.amount.to_string()),
                );
            }
        }
    }
    let status = match status {
        "Prepared" => OperationStatus::Prepared,
        "ProofRequired" => OperationStatus::ProofRequired,
        "Applied" => OperationStatus::Applied,
        "AlreadyPresent" => OperationStatus::AlreadyPresent,
        "Absent" => OperationStatus::Absent,
        "Pending" => OperationStatus::Pending,
        "Rejected" => OperationStatus::Rejected,
        "Expired" => OperationStatus::Expired,
        "AliasConflict" => OperationStatus::AliasConflict,
        _ => eyre::bail!("invalid internal operation status"),
    };
    Ok(OperationReport {
        status,
        data: value,
    })
}

fn observation_deadline(timeout_secs: u64, expires_at: u64) -> Result<Instant> {
    if !(1..=300).contains(&timeout_secs) {
        eyre::bail!("request timeout must be between 1 and 300 seconds");
    }
    let budget = Duration::from_secs(timeout_secs).min(Duration::from_millis(
        expires_at.saturating_sub(current_unix_ms()?),
    ));
    Instant::now()
        .checked_add(budget)
        .ok_or_else(|| eyre!("operation deadline overflow"))
}
#[cfg(test)]
#[path = "onboarding_tests.rs"]
mod tests;

/// Parse an independently trusted exact single-signatory issuer identity.
///
/// # Errors
/// Rejects aliases, noncanonical spellings and multisignature identities.
pub fn canonical_issuer(value: &str) -> Result<AccountId> {
    let issuer =
        AccountId::parse_encoded(value).wrap_err("issuer must be a canonical account ID")?;
    if issuer.to_string() != value || issuer.try_signatory().is_none() {
        eyre::bail!("issuer must be an exact canonical single-signatory account ID");
    }
    Ok(issuer)
}
