//! Exact, locally authorized contract calls using the native deployment journal store.
use super::*;
use iroha::client::ContractCallDraftIntent;
use iroha::data_model::{
    smart_contract::manifest::{
        ContractPermissionScopeV1, EntryPointKind, EntrypointAuthorizationV1,
    },
    transaction::Executable,
};
use iroha_crypto::Signature;
use iroha_executor_data_model::permission::smart_contract::{
    CanInvokeContractEntrypoint, CanUseContractPermission,
};
use norito::json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
const ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_CALL_PLAN_BYTES: usize = 2 * MAX_DEPLOYMENT_ARTIFACT_BYTES + 6 * 1024 * 1024;
const ARGUMENT_LIMITS: norito::DecodeLimits =
    norito::DecodeLimits::new(8192, ARGUMENT_BYTES, 8192, 2 * 1024 * 1024, 128);

/// Largest signature-bound VM gas budget a mutable call may request.
pub const MAX_CALL_GAS_LIMIT: u64 = 10_000_000;
/// Gas budget used when simulation cannot run before the call's own self-grant is Applied.
pub const UNSIMULATED_CALL_GAS_LIMIT: u64 = 1_500_000;
/// Fixed gas margin added to every simulated budget.
const GAS_HEADROOM_MARGIN: u64 = 10_000;

/// Signature-bound gas budget for a call whose simulation consumed `gas_used`.
///
/// Adds half the simulated gas plus a fixed margin, so ordinary state drift between simulation and
/// execution does not exhaust the budget, and caps the result at [`MAX_CALL_GAS_LIMIT`].
#[must_use]
pub fn gas_limit_with_headroom(gas_used: u64) -> u64 {
    gas_used
        .saturating_add(gas_used / 2)
        .saturating_add(GAS_HEADROOM_MARGIN)
        .min(MAX_CALL_GAS_LIMIT)
}

/// Result of executing a mutable call on current state without signing or submitting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallSimulation {
    /// The node executed the call successfully.
    Executed {
        /// Gas the simulated execution consumed.
        gas_used: u64,
    },
    /// The node rejected the call; nothing was signed or submitted.
    Rejected {
        /// Node-reported rejection, including any VM diagnostic.
        message: String,
        /// Gas consumed before the rejection.
        gas_used: u64,
    },
    /// The caller does not hold the scoped entrypoint permission yet. The call grants it first, so
    /// the node cannot execute the call until that self-grant is Applied.
    RequiresSelfGrant,
}

/// Interpret one `/v1/contracts/call/simulate` response for the exact verified intent.
///
/// # Errors
/// Rejects responses bound to another contract code hash or entrypoint, or without gas usage.
pub fn interpret_call_simulation(
    response: &Value,
    intent: &ContractCallDraftIntent,
) -> Result<CallSimulation> {
    let expected_code_hash = hex::encode(intent.invocation.expected_code_hash.as_ref());
    if response.get("code_hash_hex").and_then(Value::as_str) != Some(expected_code_hash.as_str())
        || response.get("entrypoint").and_then(Value::as_str)
            != Some(intent.invocation.entrypoint.as_str())
    {
        return Err(eyre!(
            "call simulation answered for a different contract code or entrypoint"
        ));
    }
    let gas_used = response
        .get("gas_used")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("call simulation omitted its gas usage"))?;
    match response.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(CallSimulation::Executed { gas_used }),
        Some(false) => {
            let mut message = response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the node rejected the simulated call")
                .to_owned();
            if let Some(diagnostic) = response
                .get("vm_diagnostic")
                .filter(|value| !value.is_null())
            {
                message.push_str("; VM diagnostic: ");
                message.push_str(&norito::json::to_string(diagnostic)?);
            }
            Ok(CallSimulation::Rejected { message, gas_used })
        }
        None => Err(eyre!("call simulation omitted its outcome")),
    }
}

/// Admit bounded ergonomic JSON before allocating a native contract argument value.
///
/// # Errors
/// Rejects raw, lexical, native allocation, depth or syntax limits before materialization.
pub fn parse_contract_arguments(input: &str) -> Result<Value> {
    norito::json::preflight_slice(
        input.as_bytes(),
        norito::json::JsonPreflightLimits::from_decode_limits(ARGUMENT_BYTES, ARGUMENT_LIMITS),
    )?;
    norito::with_decode_limits_scope(ARGUMENT_LIMITS, || norito::json::from_str(input))
        .map_err(Into::into)
}

/// Admit a pre-existing argument value before any cloning or intent materialization.
///
/// # Errors
/// Rejects serialized size, aggregate entries, depth and native resource limits.
pub fn admit_arguments(value: &Value) -> Result<()> {
    let encoded = norito::with_decode_limits_scope(ARGUMENT_LIMITS, || {
        norito::json::to_json_bounded(value, ARGUMENT_BYTES)
    })?;
    norito::json::preflight_slice(
        encoded.as_bytes(),
        norito::json::JsonPreflightLimits::from_decode_limits(ARGUMENT_BYTES, ARGUMENT_LIMITS),
    )?;
    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn check_component_limits(requested: &FeePaymentIntent, actual: &FeePaymentIntent) -> Result<()> {
    if !requested.has_same_payer_and_gas_bound(actual) {
        return Err(eyre!("call quote changed its original payer or gas bound"));
    }
    if !requested.charge_limits().is_empty() {
        for quoted in actual.charge_limits() {
            let original = requested
                .charge_limits()
                .iter()
                .find(|limit| {
                    limit.kind() == quoted.kind()
                        && limit.asset_definition_id() == quoted.asset_definition_id()
                })
                .ok_or_else(|| eyre!("call quote added a component outside its original limits"))?;
            if quoted.max_amount() > original.max_amount() {
                return Err(eyre!("call quote increased an original component maximum"));
            }
        }
    }
    Ok(())
}
fn read_call_plan(journal: &Journal) -> Result<PreparedContractCall> {
    const MAX_BYTES: usize = MAX_CALL_PLAN_BYTES;
    journal.read_limited(
        "plan.json",
        MAX_BYTES,
        norito::DecodeLimits::new(8192, MAX_BYTES, 16384, 4 * MAX_BYTES, 128),
    )
}

/// Finite original authorization for all transactions in one mutable call.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct CallAuthorization {
    /// Fixed Unix millisecond boundary after which no new transaction may be signed.
    pub signing_deadline_unix_ms: u64,
    /// Positive aggregate maxima across the optional exact self-grant and mutable call.
    pub max_total_fees: BTreeMap<AssetDefinitionId, Quantity>,
}
impl CallAuthorization {
    fn validate(&self) -> Result<()> {
        if self.signing_deadline_unix_ms == 0
            || self.signing_deadline_unix_ms == u64::MAX
            || self.max_total_fees.is_empty()
            || self.max_total_fees.len() > 16
            || self.max_total_fees.values().any(Quantity::is_zero)
        {
            return Err(eyre!(
                "call requires a fixed deadline and positive finite fee maxima"
            ));
        }
        Ok(())
    }
    fn require_signing(&self) -> Result<()> {
        self.validate()?;
        let now = now_ms()?;
        if now >= self.signing_deadline_unix_ms {
            return Err(eyre!(
                "original call signing authorization expired; no unsigned stage can be prepared"
            ));
        }
        Ok(())
    }
    fn ttl_ms(&self, creation_time_ms: u64, original_ttl_ms: u64) -> Result<u64> {
        if original_ttl_ms == 0 {
            return Err(eyre!("call original transaction TTL must be positive"));
        }
        self.signing_deadline_unix_ms
            .checked_sub(creation_time_ms)
            .filter(|remaining| *remaining > 0)
            .map(|remaining| remaining.min(original_ttl_ms))
            .ok_or_else(|| eyre!("original call signing authorization expired"))
    }
    fn check_fees(
        &self,
        intents: impl IntoIterator<Item = impl std::borrow::Borrow<FeePaymentIntent>>,
    ) -> Result<()> {
        self.validate()?;
        let mut totals = BTreeMap::<AssetDefinitionId, Quantity>::new();
        for intent in intents {
            let intent = intent.borrow();
            intent.validate()?;
            for component in intent.charge_limits() {
                let total = totals
                    .entry(component.asset_definition_id().clone())
                    .or_default();
                *total = total
                    .checked_add(component.max_amount())
                    .map_err(|_| eyre!("call fee total overflow"))?;
            }
        }
        for (asset, amount) in totals {
            let cap = self
                .max_total_fees
                .get(&asset)
                .ok_or_else(|| eyre!("call quote added an unauthorized fee asset"))?;
            if amount > *cap {
                return Err(eyre!(
                    "aggregate call quote exceeds its original fee authorization"
                ));
            }
        }
        Ok(())
    }
}

/// Canonical argument record and retained JSON payload of one checked entrypoint invocation.
type CheckedArguments = (
    Option<iroha::data_model::transaction::executable::ContractArgumentRecord>,
    Option<Value>,
);

/// Check named arguments against one entrypoint of admission-verified local code.
///
/// This is the argument half of [`trusted_contract_intent`]; it needs no contract address, so a
/// deployment can reject activation arguments before anything is signed.
///
/// # Errors
/// Rejects unknown or wrong-kind entrypoints, malformed arguments and oversized payloads, naming
/// the rejected argument path and its expected IVM type.
pub fn check_contract_arguments(
    artifact: &[u8],
    entrypoint: &str,
    payload: &Value,
    view: bool,
) -> Result<()> {
    let verified = verified_call_artifact(artifact, payload)?;
    entrypoint_arguments(&verified, entrypoint, payload.clone(), view).map(|_| ())
}

/// Admit the bounded artifact and argument JSON, then verify the artifact.
fn verified_call_artifact(
    artifact: &[u8],
    payload: &Value,
) -> Result<ivm_artifact_admission::VerifiedContractArtifact> {
    if artifact.is_empty() || artifact.len() > MAX_DEPLOYMENT_ARTIFACT_BYTES {
        return Err(eyre!(
            "contract intent exceeds fixed artifact or argument bounds"
        ));
    }
    admit_arguments(payload)?;
    Ok(ivm_artifact_admission::verify_contract_artifact(artifact)?)
}

/// Encode named arguments for one entrypoint of verified code.
fn entrypoint_arguments(
    verified: &ivm_artifact_admission::VerifiedContractArtifact,
    entrypoint: &str,
    payload: Value,
    view: bool,
) -> Result<CheckedArguments> {
    let descriptor = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == entrypoint)
        .ok_or_else(|| eyre!("entrypoint is absent from the verified local artifact"))?;
    if (descriptor.kind == EntryPointKind::View) != view {
        return Err(eyre!(
            "entrypoint kind differs from the requested view or mutable call"
        ));
    }
    Ok(match &descriptor.argument_schema {
        Some(schema) => {
            let canonical = Json::from_norito_value_ref(&payload)?;
            // The detailed form names the rejected argument path and its expected IVM type.
            let bytes =
                ivm_abi::arguments::encode_argument_record_from_json_detailed(schema, &canonical)
                    .map_err(|error| {
                    eyre!("arguments do not match the verified entrypoint schema: {error}")
                })?;
            (
                Some(
                    iroha::data_model::transaction::executable::ContractArgumentRecord::try_new(
                        bytes,
                    )?,
                ),
                Some(payload),
            )
        }
        None if descriptor.params.is_empty()
            && payload.as_object().is_some_and(norito::json::Map::is_empty) =>
        {
            (None, None)
        }
        None => {
            return Err(eyre!(
                "zero-parameter entrypoints accept only omitted arguments or {{}}"
            ));
        }
    })
}

/// Build an exact native intent from admission-verified local code and its argument schema.
///
/// # Errors
/// Rejects unknown or wrong-kind entrypoints, malformed arguments and oversized payloads.
pub fn trusted_contract_intent(
    artifact: &[u8],
    address: ContractAddress,
    entrypoint: &str,
    payload: Value,
    view: bool,
) -> Result<(ContractCallDraftIntent, Option<Value>)> {
    let verified = verified_call_artifact(artifact, &payload)?;
    let (arguments, payload) = entrypoint_arguments(&verified, entrypoint, payload, view)?;
    let mut metadata = Metadata::default();
    for (key, value) in [
        ("contract_address", address.to_string()),
        ("contract_code_hash", verified.code_hash.to_string()),
        ("contract_entrypoint", entrypoint.to_owned()),
    ] {
        metadata.insert(key.parse::<Name>()?, Json::new(value));
    }
    if let Some(payload) = &payload {
        metadata.insert(
            "contract_payload".parse::<Name>()?,
            Json::from_norito_value_ref(payload)?,
        );
    }
    Ok((
        ContractCallDraftIntent {
            invocation: iroha::data_model::transaction::executable::ContractInvocation {
                contract_address: address,
                expected_code_hash: verified.code_hash,
                entrypoint: entrypoint.to_owned(),
                arguments,
            },
            metadata,
        },
        payload,
    ))
}

fn validate_trusted_intent(
    artifact: &[u8],
    intent: &ContractCallDraftIntent,
    payload: &Option<Value>,
    allow_operation_tag: bool,
) -> Result<()> {
    if let Some(value) = payload {
        admit_arguments(value)?;
    }
    let (expected, canonical_payload) = trusted_contract_intent(
        artifact,
        intent.invocation.contract_address.clone(),
        &intent.invocation.entrypoint,
        payload
            .clone()
            .unwrap_or_else(|| Value::Object(norito::json::Map::new())),
        false,
    )?;
    let key = operation_metadata_key();
    if intent.invocation != expected.invocation
        || &canonical_payload != payload
        || (!allow_operation_tag && intent.metadata.get(&key).is_some())
        || !intent
            .metadata
            .iter()
            .filter(|(name, _)| *name != &key)
            .eq(expected.metadata.iter())
    {
        return Err(eyre!(
            "call intent differs from its verified local interface and canonical arguments"
        ));
    }
    Ok(())
}

/// Local artifact and invocation selected by the package-aware caller.
#[derive(Clone, Debug)]
pub struct ContractCallRequest {
    /// Complete verified local compiled artifact.
    pub artifact: Vec<u8>,
    /// Human-readable configured alias, resolved to the exact invocation address before signing.
    pub alias: ContractAlias,
    /// Canonical named arguments; absent for a zero-parameter entrypoint.
    pub payload: Option<Value>,
    /// Exact executable and metadata derived locally from the artifact and arguments.
    pub intent: ContractCallDraftIntent,
    /// Explicit payer, sponsor revision and gas bound.
    pub fee_payment: FeePaymentIntent,
    /// Original finite signing interval and aggregate quote caps.
    pub authorization: CallAuthorization,
}
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CallPlan {
    version: u8,
    network_id: NetworkId,
    chain_id: String,
    authority: AccountId,
    chain_discriminant: u16,
    created_at_ns: u64,
    artifact_hex: String,
    alias: ContractAlias,
    payload: Option<Value>,
    intent: ContractCallDraftIntent,
    requested_fee: FeePaymentIntent,
    authorization: CallAuthorization,
    transaction_ttl_ms: u64,
    grant: Option<TransactionRecord>,
    call: TransactionRecord,
}

#[derive(norito::derive::JsonSerialize)]
struct CallOperationBinding<'a> {
    version: u8,
    network_id: NetworkId,
    chain_id: &'a str,
    authority: &'a AccountId,
    chain_discriminant: u16,
    created_at_ns: u64,
    artifact_hex: &'a str,
    alias: &'a ContractAlias,
    payload: Option<&'a Value>,
    invocation: &'a iroha::data_model::transaction::executable::ContractInvocation,
    metadata: Vec<CallMetadataEntry<'a>>,
    requested_fee: &'a FeePaymentIntent,
    authorization: &'a CallAuthorization,
    transaction_ttl_ms: u64,
    grant: Option<&'a TransactionRecord>,
}

#[derive(norito::derive::JsonSerialize)]
struct CallMetadataEntry<'a> {
    name: &'a Name,
    value: BorrowedJson<'a>,
}

struct BorrowedJson<'a>(&'a Json);
impl norito::json::JsonSerialize for BorrowedJson<'_> {
    fn json_serialize(&self, output: &mut String) {
        norito::json::JsonSerialize::json_serialize(self.0, output);
    }
    fn json_serialize_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> std::result::Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(self.0, output)
    }
}

impl<'a> CallOperationBinding<'a> {
    fn from_plan(plan: &'a CallPlan) -> Self {
        Self {
            version: plan.version,
            network_id: plan.network_id,
            chain_id: &plan.chain_id,
            authority: &plan.authority,
            chain_discriminant: plan.chain_discriminant,
            created_at_ns: plan.created_at_ns,
            artifact_hex: &plan.artifact_hex,
            alias: &plan.alias,
            payload: plan.payload.as_ref(),
            invocation: &plan.intent.invocation,
            metadata: operation_metadata_entries(&plan.intent.metadata),
            requested_fee: &plan.requested_fee,
            authorization: &plan.authorization,
            transaction_ttl_ms: plan.transaction_ttl_ms,
            grant: plan.grant.as_ref(),
        }
    }
}
/// Immutable signed local operation; contains no private key.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PreparedContractCall {
    plan: CallPlan,
    signature_hex: String,
}
impl PreparedContractCall {
    /// Stable journal identifier derived from the complete locally signed operation.
    /// # Errors
    /// Returns the canonical JSON encoding error.
    pub fn operation_id(&self) -> Result<String> {
        let _profile = ChainDiscriminantGuard::enter(self.plan.chain_discriminant);
        Ok(hex::encode(
            Hash::new(plan_signing_bytes(&self.plan)?).as_ref(),
        ))
    }
    /// Exact contract address selected by the caller.
    pub fn contract_address(&self) -> &ContractAddress {
        &self.plan.intent.invocation.contract_address
    }
    /// Exact public entrypoint selected by the caller.
    pub fn entrypoint(&self) -> &str {
        &self.plan.intent.invocation.entrypoint
    }
    /// Exact alias retained before the original operation was signed.
    pub fn contract_alias(&self) -> &ContractAlias {
        &self.plan.alias
    }
    /// Exact complete artifact retained by the signature-bound operation.
    ///
    /// # Errors
    /// Returns the hex decoding error for a corrupted retained artifact.
    pub fn artifact(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.plan.artifact_hex)?)
    }
    /// Whether this operation includes an exact permission grant to the calling account.
    pub fn grants_entrypoint_to_self(&self) -> bool {
        self.plan.grant.is_some()
    }
}
/// Receipt emitted only after the exact retained call reaches the configured root's Applied.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ContractCallReceipt {
    /// Stable locally signed operation identifier.
    pub operation_id: String,
    /// Exact network identity.
    pub network_id: NetworkId,
    /// Transaction authority.
    pub authority: AccountId,
    /// Configured alias observed before preparation.
    pub contract_alias: ContractAlias,
    /// Exact signature-bound invocation address.
    pub contract_address: ContractAddress,
    /// Exact signature-bound selector.
    pub entrypoint: String,
    /// Optional preceding exact self-grant's Applied evidence.
    pub grant: Option<AppliedEvidence>,
    /// Exact mutable call's Applied evidence.
    pub call: AppliedEvidence,
}
/// Retained disposition used to prevent a fresh operation from replacing unresolved work.
pub enum ContractCallDisposition {
    /// An unattempted stage or an unresolved exact hash requires resume.
    Pending,
    /// The complete operation was cancelled before any transaction attempt.
    Cancelled,
    /// The exact operation reached Applied and was rechecked against the configured network.
    Applied(Box<ContractCallReceipt>),
    /// The exact attempted transaction is authoritatively rejected or expired.
    Failed(TransactionFinalityFailure),
}
/// An attempted transaction is unresolved; retry only the retained journal.
#[derive(Debug, thiserror::Error)]
#[error("contract call stage `{stage}` hash {hash} is unresolved; resume its journal: {source}")]
pub struct ContractCallPending {
    /// Exact stage name.
    pub stage: String,
    /// Exact signed hash recorded before dispatch.
    pub hash: String,
    /// Original transport/finality diagnostic.
    #[source]
    pub source: eyre::Report,
}
/// Package contract call preparation and exact-hash recovery using one immutable signer context.
pub struct ContractCallService {
    config: Config,
    client: Client,
}
impl ContractCallService {
    /// Construct the service without network or filesystem effects.
    /// # Errors
    /// Rejects invalid client context or a zero finality timeout.
    pub fn new(config: Config) -> Result<Self> {
        if config.transaction_status_timeout.is_zero() {
            return Err(eyre!("call finality timeout must be nonzero"));
        }
        let client = Client::new(config.clone())?;
        Ok(Self { config, client })
    }
    /// Resolve the configured alias through the authenticated native deployment-state read.
    /// # Errors
    /// Rejects missing aliases or inconsistent network/account response bindings.
    pub fn resolve_address(&self, alias: &ContractAlias) -> Result<ContractAddress> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        self.client.refresh_capabilities()?;
        read_contract_deployment_state(
            &self.client,
            &self.config.account,
            alias,
            self.config.account_chain_discriminant,
        )?
        .previous_contract_address
        .ok_or_else(|| eyre!("contract alias `{alias}` is not deployed"))
    }
    /// Execute the exact verified call on current state without signing or submitting it.
    ///
    /// Calls that first grant their own scoped entrypoint permission cannot run before that grant
    /// is Applied and report [`CallSimulation::RequiresSelfGrant`].
    /// # Errors
    /// Rejects artifact/intent mismatches, permission reads, transport failures and responses bound
    /// to different code.
    pub fn simulate(
        &self,
        artifact: &[u8],
        intent: &ContractCallDraftIntent,
        payload: Option<&Value>,
    ) -> Result<CallSimulation> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        if artifact.is_empty() || artifact.len() > MAX_DEPLOYMENT_ARTIFACT_BYTES {
            return Err(eyre!("call artifact exceeds fixed bounds"));
        }
        if let Some(payload) = payload {
            admit_arguments(payload)?;
        }
        let verified = ivm_artifact_admission::verify_contract_artifact(artifact)?;
        if let Some(permission) = required_permission(&verified, intent)?
            && !authorization::read_effective_permissions(&self.client, &self.config.account)?
                .contains(&permission)
        {
            if permission.name() == "CanInvokeContractEntrypoint" {
                return Ok(CallSimulation::RequiresSelfGrant);
            }
            return Err(missing_call_permission(&permission, &self.config.account));
        }
        let response = self.client.client().post_contract_call_simulate_json(
            &self.config.account,
            Some(&intent.invocation.contract_address),
            None,
            &intent.invocation.entrypoint,
            payload,
            MAX_CALL_GAS_LIMIT,
        )?;
        interpret_call_simulation(&response, intent)
    }
    /// Prepare a locally signed immutable call intent and any required exact self-grant.
    /// No transaction is submitted or journal written.
    /// # Errors
    /// Rejects artifact, alias, argument, permission-read, fee, or signing failures.
    pub fn prepare(&self, mut request: ContractCallRequest) -> Result<PreparedContractCall> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        request.authorization.require_signing()?;
        if request.artifact.is_empty() || request.artifact.len() > MAX_DEPLOYMENT_ARTIFACT_BYTES {
            return Err(eyre!("call artifact exceeds fixed bounds"));
        }
        if let Some(payload) = &request.payload {
            admit_arguments(payload)?;
        }
        validate_trusted_intent(&request.artifact, &request.intent, &request.payload, false)?;
        let verified = ivm_artifact_admission::verify_contract_artifact(&request.artifact)?;
        let permission = required_permission(&verified, &request.intent)?;
        request.fee_payment.validate()?;
        if request.fee_payment.gas_limit().is_none() {
            return Err(eyre!("call requires an explicit gas bound"));
        }
        if self.resolve_address(&request.alias)? != request.intent.invocation.contract_address {
            return Err(eyre!("contract alias changed before call preparation"));
        }
        let mut grant = None;
        let mut fee_quotes = Vec::new();
        let transaction_ttl_ms = u64::try_from(self.config.transaction_ttl.as_millis())?;
        if transaction_ttl_ms == 0 {
            return Err(eyre!("call original transaction TTL must be positive"));
        }
        if let Some(permission) = permission {
            let held =
                authorization::read_effective_permissions(&self.client, &self.config.account)?;
            if !held.contains(&permission) {
                if permission.name() != "CanInvokeContractEntrypoint" {
                    return Err(missing_call_permission(&permission, &self.config.account));
                }
                let metadata = Metadata::default();
                request.authorization.require_signing()?;
                let creation_time_ms = now_ms()?;
                let ttl_ms = request
                    .authorization
                    .ttl_ms(creation_time_ms, transaction_ttl_ms)?;
                let mut builder = TransactionBuilder::new(
                    self.config.network_id,
                    self.config.account.clone(),
                    request.fee_payment.clone(),
                );
                builder.set_creation_time(Duration::from_millis(creation_time_ms));
                builder.set_ttl(Duration::from_millis(ttl_ms));
                let draft = builder
                    .with_metadata(metadata)
                    .with_instructions([InstructionBox::from(Grant::account_permission(
                        permission,
                        self.config.account.clone(),
                    ))])
                    .try_sign(self.config.key_pair.private_key())?;
                let (signed, quote) = quote_and_resign_transaction_reviewed(
                    &self.client,
                    &draft,
                    &request.fee_payment,
                    &mut |quote| {
                        validate_quote_route(
                            quote,
                            request.intent.invocation.contract_address.dataspace_id()?,
                        )?;
                        request.authorization.check_fees([&quote.intent])?;
                        check_component_limits(&request.fee_payment, &quote.intent)?;
                        request.authorization.require_signing()
                    },
                )?;
                fee_quotes.push(quote);
                grant = Some(transaction_record("entrypoint-grant", &signed));
            }
        }
        let chain_id = self.config.chain.to_string();
        let created_at_ns =
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        let artifact_hex = hex::encode(request.artifact);
        let tag = operation_tag(&CallOperationBinding {
            version: 1,
            network_id: self.config.network_id,
            chain_id: &chain_id,
            authority: &self.config.account,
            chain_discriminant: self.config.account_chain_discriminant,
            created_at_ns,
            artifact_hex: &artifact_hex,
            alias: &request.alias,
            payload: request.payload.as_ref(),
            invocation: &request.intent.invocation,
            metadata: operation_metadata_entries(&request.intent.metadata),
            requested_fee: &request.fee_payment,
            authorization: &request.authorization,
            transaction_ttl_ms,
            grant: grant.as_ref(),
        })?;
        request
            .intent
            .metadata
            .insert(operation_metadata_key(), Json::new(tag));
        request.authorization.require_signing()?;
        let creation_time_ms = now_ms()?;
        let ttl_ms = request
            .authorization
            .ttl_ms(creation_time_ms, transaction_ttl_ms)?;
        let mut builder = TransactionBuilder::new(
            self.config.network_id,
            self.config.account.clone(),
            request.fee_payment.clone(),
        );
        builder.set_creation_time(Duration::from_millis(creation_time_ms));
        builder.set_ttl(Duration::from_millis(ttl_ms));
        let draft = builder
            .with_metadata(request.intent.metadata.clone())
            .with_executable(Executable::ContractCall(request.intent.invocation.clone()))
            .try_sign(self.config.key_pair.private_key())?;
        let grant_transaction = grant.as_ref().map(decode_transaction).transpose()?;
        let (signed, quote) = quote_and_resign_transaction_reviewed(
            &self.client,
            &draft,
            &request.fee_payment,
            &mut |quote| {
                validate_quote_route(
                    quote,
                    request.intent.invocation.contract_address.dataspace_id()?,
                )?;
                request.authorization.check_fees(
                    grant_transaction
                        .iter()
                        .map(SignedTransaction::fee_payment_intent)
                        .chain(std::iter::once(&quote.intent)),
                )?;
                check_component_limits(&request.fee_payment, &quote.intent)?;
                request.authorization.require_signing()
            },
        )?;
        fee_quotes.push(quote);
        self.client
            .check_funding(&BTreeMap::default(), &fee_quotes)?;
        request.authorization.require_signing()?;
        let plan = CallPlan {
            version: 1,
            network_id: self.config.network_id,
            chain_id,
            authority: self.config.account.clone(),
            chain_discriminant: self.config.account_chain_discriminant,
            created_at_ns,
            artifact_hex,
            alias: request.alias,
            payload: request.payload,
            intent: request.intent,
            requested_fee: request.fee_payment,
            authorization: request.authorization,
            transaction_ttl_ms,
            grant,
            call: transaction_record("contract-call", &signed),
        };
        let signature = Signature::try_new(
            self.config.key_pair.private_key(),
            &plan_signing_bytes(&plan)?,
        )?;
        let prepared = PreparedContractCall {
            plan,
            signature_hex: hex::encode(signature.payload()),
        };
        validate_plan(&prepared, &self.config)?;
        Ok(prepared)
    }
    /// Persist the operation before either the grant or call can be dispatched.
    /// # Errors
    /// Rejects substituted plans or unsafe/busy journal storage.
    pub fn persist(&self, prepared: &PreparedContractCall, path: &Path) -> Result<()> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        validate_plan(prepared, &self.config)?;
        Journal::open(path, true)?.put_exact_limited("plan.json", prepared, MAX_CALL_PLAN_BYTES)
    }
    /// Read and authenticate the original immutable operation without renewing authorization.
    ///
    /// # Errors
    /// Rejects unsafe custody, malformed plans or another network, authority or signing key.
    pub fn retained_call(&self, path: &Path) -> Result<PreparedContractCall> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(path, false)?;
        let prepared = read_call_plan(&journal)?;
        validate_plan(&prepared, &self.config)?;
        validate_stage_layout(&journal, &prepared.plan)?;
        Ok(prepared)
    }
    /// Cancel a fully unattempted local operation without submitting any transaction.
    /// # Errors
    /// Rejects unsafe custody or any retained attempt or unknown execution evidence.
    pub fn cancel(&self, path: &Path) -> Result<String> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(path, false)?;
        let prepared = read_call_plan(&journal)?;
        validate_plan(&prepared, &self.config)?;
        journal.require_unattempted()?;
        let operation_id = prepared.operation_id()?;
        journal.put_exact("cancelled.json", &operation_id)?;
        Ok(operation_id)
    }
    /// Execute an unattempted operation or recover its exact attempted hashes.
    /// # Errors
    /// Returns exact-hash pending, authoritative failure, or journal errors.
    pub fn resume(&self, path: &Path) -> Result<ContractCallReceipt> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(path, false)?;
        let prepared = read_call_plan(&journal)?;
        validate_plan(&prepared, &self.config)?;
        validate_stage_layout(&journal, &prepared.plan)?;
        if is_cancelled(&journal, &prepared)? {
            return Err(eyre!(
                "this call was cancelled before submission; create a new operation"
            ));
        }
        self.client.refresh_capabilities()?;
        let transport = CallTransport { service: self };
        let grant = prepared
            .plan
            .grant
            .as_ref()
            .map(|grant| execute_step(&journal, grant, 0, &transport))
            .transpose()?;
        let step = &prepared.plan.call;
        validate_call_transaction(&prepared.plan, step)?;
        let call = execute_step(&journal, step, 1, &transport)?;
        let receipt = ContractCallReceipt {
            operation_id: prepared.operation_id()?,
            network_id: prepared.plan.network_id,
            authority: prepared.plan.authority.clone(),
            contract_alias: prepared.plan.alias.clone(),
            contract_address: prepared.plan.intent.invocation.contract_address.clone(),
            entrypoint: prepared.plan.intent.invocation.entrypoint.clone(),
            grant,
            call,
        };
        journal.put_exact(RECEIPT_FILE_NAME, &receipt)?;
        Ok(receipt)
    }
    /// Inspect a retained operation without preparing, signing, or submitting any transaction.
    /// # Errors
    /// Returns journal/substitution errors; unavailable evidence remains pending.
    pub fn inspect(&self, path: &Path) -> Result<ContractCallDisposition> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(path, false)?;
        let prepared = read_call_plan(&journal)?;
        validate_plan(&prepared, &self.config)?;
        validate_stage_layout(&journal, &prepared.plan)?;
        if is_cancelled(&journal, &prepared)? {
            return Ok(ContractCallDisposition::Cancelled);
        }
        let mut grant = None;
        for (index, step) in [
            (0, prepared.plan.grant.clone()),
            (1, Some(prepared.plan.call.clone())),
        ] {
            let Some(step) = step else {
                if index == 1 {
                    return Ok(ContractCallDisposition::Pending);
                }
                continue;
            };
            if index == 1 {
                validate_call_transaction(&prepared.plan, &step)?;
            }
            if !journal.exists(&format!("attempt-{index:04}.json"))? {
                return Ok(ContractCallDisposition::Pending);
            }
            validate_attempt(&journal, &step, index)?;
            match (CallTransport { service: self }).wait(decode_transaction(&step)?.hash()) {
                Ok(applied) => {
                    validate_applied(decode_transaction(&step)?.hash(), &applied)?;
                    let applied = reconcile_retained_evidence(&journal, index, applied)?;
                    if index == 0 {
                        grant = Some(applied);
                    } else {
                        let receipt = ContractCallReceipt {
                            operation_id: prepared.operation_id()?,
                            network_id: prepared.plan.network_id,
                            authority: prepared.plan.authority.clone(),
                            contract_alias: prepared.plan.alias.clone(),
                            contract_address: prepared
                                .plan
                                .intent
                                .invocation
                                .contract_address
                                .clone(),
                            entrypoint: prepared.plan.intent.invocation.entrypoint.clone(),
                            grant,
                            call: applied,
                        };
                        if journal.exists(RECEIPT_FILE_NAME)? {
                            let retained: ContractCallReceipt = journal.read(RECEIPT_FILE_NAME)?;
                            if norito::json::to_vec(&retained)? != norito::json::to_vec(&receipt)? {
                                return Err(eyre!(
                                    "retained call receipt disagrees with exact current Applied evidence"
                                ));
                            }
                        }
                        return Ok(ContractCallDisposition::Applied(Box::new(receipt)));
                    }
                }
                Err(error) => {
                    if let Some(proof) = finality_failure(&error) {
                        validate_retained_failure(
                            &journal,
                            index,
                            decode_transaction(&step)?.hash(),
                            &proof,
                        )?;
                        return Ok(ContractCallDisposition::Failed(proof));
                    }
                    return Ok(ContractCallDisposition::Pending);
                }
            }
        }
        Ok(ContractCallDisposition::Pending)
    }
}
fn plan_signing_bytes(plan: &CallPlan) -> Result<Vec<u8>> {
    let mut bytes = b"iroha.contract-call-operation.v1\0".to_vec();
    bytes.extend(norito::json::to_json_bounded(plan, MAX_CALL_PLAN_BYTES)?.as_bytes());
    Ok(bytes)
}
fn operation_metadata_key() -> Name {
    "musubi_call_operation"
        .parse()
        .expect("static operation metadata key")
}
fn operation_metadata_entries(metadata: &Metadata) -> Vec<CallMetadataEntry<'_>> {
    let key = operation_metadata_key();
    metadata
        .iter()
        .filter(|(name, _)| *name != &key)
        .map(|(name, value)| CallMetadataEntry {
            name,
            value: BorrowedJson(value),
        })
        .collect()
}
fn operation_tag(binding: &CallOperationBinding<'_>) -> Result<String> {
    let mut bytes = b"iroha.contract-call-binding.v1\0".to_vec();
    bytes.extend(norito::json::to_json_bounded(binding, MAX_CALL_PLAN_BYTES)?.as_bytes());
    Ok(hex::encode(Hash::new(bytes).as_ref()))
}
#[cfg(test)]
fn bind_operation_metadata(plan: &mut CallPlan) -> Result<()> {
    let tag = operation_tag(&CallOperationBinding::from_plan(plan))?;
    plan.intent
        .metadata
        .insert(operation_metadata_key(), Json::new(tag));
    Ok(())
}
fn operation_metadata(plan: &CallPlan) -> Result<Metadata> {
    let tag = Json::new(operation_tag(&CallOperationBinding::from_plan(plan))?);
    if plan.intent.metadata.get(&operation_metadata_key()) != Some(&tag) {
        return Err(eyre!(
            "call metadata does not bind its exact immutable operation"
        ));
    }
    let mut metadata = Metadata::default();
    metadata.insert(operation_metadata_key(), tag);
    Ok(metadata)
}
fn transaction_record(name: &str, signed: &SignedTransaction) -> TransactionRecord {
    TransactionRecord {
        name: name.to_owned(),
        hash: signed.hash().to_string(),
        norito_hex: hex::encode(signed.encode_versioned()),
    }
}
fn missing_call_permission(permission: &Permission, account: &AccountId) -> eyre::Report {
    match norito::json::to_string(permission) {
        Ok(token) => eyre!(
            "caller lacks the exact required permission {token}; have an authorized owner or token holder submit this JSON with `iroha account permission grant --id {account}` before calling"
        ),
        Err(error) => eyre!("failed to render the required permission: {error}"),
    }
}

fn required_permission(
    artifact: &ivm_artifact_admission::VerifiedContractArtifact,
    intent: &ContractCallDraftIntent,
) -> Result<Option<Permission>> {
    if artifact.code_hash != intent.invocation.expected_code_hash {
        return Err(eyre!(
            "call code identity differs from the verified local artifact"
        ));
    }
    let descriptor = artifact
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == intent.invocation.entrypoint)
        .ok_or_else(|| eyre!("entrypoint is absent from the verified local artifact"))?;
    if descriptor.kind == EntryPointKind::View {
        return Err(eyre!("read-only entrypoints use `musubi view`"));
    }
    Ok(match &descriptor.authorization {
        EntrypointAuthorizationV1::Anyone => None,
        EntrypointAuthorizationV1::RuntimeLifecycle => Some(
            CanInvokeContractEntrypoint {
                contract: intent.invocation.contract_address.clone(),
                entrypoint: intent.invocation.entrypoint.clone(),
            }
            .into(),
        ),
        EntrypointAuthorizationV1::Permission(name) => {
            let declaration = artifact
                .contract_interface
                .permissions
                .iter()
                .find(|declaration| declaration.name == *name)
                .ok_or_else(|| eyre!("entrypoint refers to undeclared permission `{name}`"))?;
            Some(match &declaration.scope {
                ContractPermissionScopeV1::Instance => CanUseContractPermission {
                    contract: intent.invocation.contract_address.clone(),
                    permission: name.clone(),
                }
                .into(),
                ContractPermissionScopeV1::Chain { permission_name } => {
                    Permission::new(permission_name.to_string(), Json::new(()))
                }
            })
        }
    })
}
fn validate_plan(prepared: &PreparedContractCall, config: &Config) -> Result<()> {
    let plan = &prepared.plan;
    if plan.version != 1
        || plan.network_id != config.network_id
        || plan.chain_id != config.chain.to_string()
        || plan.chain_discriminant != config.account_chain_discriminant
        || plan.authority != config.account
        || plan.authority.try_signatory() != Some(config.key_pair.public_key())
        || plan.created_at_ns == 0
    {
        return Err(eyre!(
            "call journal belongs to a different network, authority, or address profile"
        ));
    }
    if plan.artifact_hex.is_empty()
        || plan.artifact_hex.len() > 2 * MAX_DEPLOYMENT_ARTIFACT_BYTES
        || prepared.signature_hex.len() > 64 * 1024
    {
        return Err(eyre!(
            "call journal exceeds fixed artifact/signature bounds"
        ));
    }
    let signature = hex::decode(&prepared.signature_hex)?;
    if hex::encode(&signature) != prepared.signature_hex {
        return Err(eyre!("call plan signature is not canonical hex"));
    }
    Signature::from_bytes(&signature)
        .verify(config.key_pair.public_key(), &plan_signing_bytes(plan)?)?;
    let artifact = hex::decode(&plan.artifact_hex)?;
    if hex::encode(&artifact) != plan.artifact_hex {
        return Err(eyre!("call artifact is not canonical hex"));
    }
    let verified = ivm_artifact_admission::verify_contract_artifact(&artifact)?;
    validate_trusted_intent(&artifact, &plan.intent, &plan.payload, true)?;
    let permission = required_permission(&verified, &plan.intent)?;
    operation_metadata(plan)?;
    plan.requested_fee.validate()?;
    plan.authorization.validate()?;
    validate_call_transaction(plan, &plan.call)?;
    if let Some(payload) = &plan.payload {
        admit_arguments(payload)?;
    }
    if plan.requested_fee.gas_limit().is_none()
        || plan.transaction_ttl_ms == 0
        || plan.payload.is_some() != plan.intent.invocation.arguments.is_some()
    {
        return Err(eyre!(
            "call journal requires bounded arguments and an explicit gas limit"
        ));
    }
    if let Some(grant) = &plan.grant {
        if grant.norito_hex.len() > 2 * 1024 * 1024 {
            return Err(eyre!("retained self-grant exceeds fixed byte bound"));
        }
        let signed = decode_transaction(grant)?;
        check_component_limits(&plan.requested_fee, signed.fee_payment_intent())?;
        validate_transaction_expiry(plan, &signed)?;
        plan.authorization
            .check_fees([signed.fee_payment_intent()])?;
        let permission =
            permission.ok_or_else(|| eyre!("unguarded call must not create a grant"))?;
        if permission.name() != "CanInvokeContractEntrypoint" {
            return Err(eyre!(
                "call may grant only its exact entrypoint invocation permission"
            ));
        }
        let expected = Executable::Instructions(
            vec![InstructionBox::from(Grant::account_permission(
                permission,
                plan.authority.clone(),
            ))]
            .into(),
        );
        if grant.name != "entrypoint-grant"
            || signed.network_id() != Some(&plan.network_id)
            || signed.authority() != &plan.authority
            || signed.instructions() != &expected
            || !signed.metadata().is_empty()
            || !plan
                .requested_fee
                .has_same_payer_and_gas_bound(&signed.payload().fee_payment)
        {
            return Err(eyre!(
                "call self-grant differs from the exact owned entrypoint and authority"
            ));
        }
    }
    Ok(())
}
fn validate_call_transaction(plan: &CallPlan, step: &TransactionRecord) -> Result<()> {
    if plan.call.hash != step.hash
        || plan.call.norito_hex != step.norito_hex
        || plan.call.name != step.name
    {
        return Err(eyre!(
            "call transaction differs from the exact originally signed stage"
        ));
    }
    if step.norito_hex.len() > 2 * 1024 * 1024 {
        return Err(eyre!("retained call transaction exceeds fixed bound"));
    }
    let signed = decode_transaction(step)?;
    check_component_limits(&plan.requested_fee, signed.fee_payment_intent())?;
    validate_transaction_expiry(plan, &signed)?;
    let grant = plan.grant.as_ref().map(decode_transaction).transpose()?;
    plan.authorization.check_fees(
        grant
            .iter()
            .map(SignedTransaction::fee_payment_intent)
            .chain(std::iter::once(signed.fee_payment_intent())),
    )?;
    if step.name != "contract-call"
        || signed.network_id() != Some(&plan.network_id)
        || signed.authority() != &plan.authority
        || signed.instructions() != &Executable::ContractCall(plan.intent.invocation.clone())
        || signed.metadata() != &plan.intent.metadata
        || !plan
            .requested_fee
            .has_same_payer_and_gas_bound(&signed.payload().fee_payment)
    {
        return Err(eyre!(
            "retained call transaction differs from the locally signed operation"
        ));
    }
    Ok(())
}
fn validate_transaction_expiry(plan: &CallPlan, signed: &SignedTransaction) -> Result<()> {
    let created = u64::try_from(signed.creation_time().as_millis())?;
    let ttl = signed
        .time_to_live()
        .ok_or_else(|| eyre!("call transaction omitted its original bounded TTL"))?;
    if created == 0
        || u64::try_from(ttl.as_millis())?
            != plan
                .authorization
                .ttl_ms(created, plan.transaction_ttl_ms)?
    {
        return Err(eyre!(
            "call transaction lifetime differs from its original authorization"
        ));
    }
    Ok(())
}
struct CallTransport<'a> {
    service: &'a ContractCallService,
}
impl DeploymentTransport for CallTransport<'_> {
    fn submit(&self, signed: &SignedTransaction) -> Result<()> {
        self.service
            .client
            .submit_transaction_and_wait(signed)
            .map(|_| ())
    }
    fn wait(&self, hash: HashOf<SignedTransaction>) -> Result<AppliedEvidence> {
        let outcome = self.service.client.wait_for_transaction_applied(
            hash,
            TransactionWaitOptions {
                timeout: self.service.config.transaction_status_timeout,
                ..TransactionWaitOptions::default()
            },
        )?;
        let charge = read_applied_charge(&self.service.client, hash);
        applied_evidence(hash, outcome, charge)
    }
}
fn is_cancelled(journal: &Journal, prepared: &PreparedContractCall) -> Result<bool> {
    if !journal.exists("cancelled.json")? {
        return Ok(false);
    }
    journal.require_unattempted()?;
    if journal.read::<String>("cancelled.json")? != prepared.operation_id()? {
        return Err(eyre!(
            "cancellation names a different immutable call operation"
        ));
    }
    Ok(true)
}
fn validate_stage_layout(journal: &Journal, plan: &CallPlan) -> Result<()> {
    if journal.exists("call.json")? {
        return Err(eyre!("retired separate call payload is not supported"));
    }
    for index in 0..2 {
        let attempted = journal.exists(&format!("attempt-{index:04}.json"))?;
        let applied = journal.exists(&format!("applied-{index:04}.json"))?;
        let failed = journal.exists(&format!("failed-{index:04}.json"))?;
        if (applied || failed) && !attempted || applied && failed {
            return Err(eyre!(
                "call stage has missing or conflicting durable attempt evidence"
            ));
        }
        if index == 0 && plan.grant.is_none() && attempted {
            return Err(eyre!("call has an unexpected permission-grant attempt"));
        }
    }
    if plan.grant.is_some()
        && journal.exists("attempt-0001.json")?
        && !journal.exists("applied-0000.json")?
    {
        return Err(eyre!(
            "call was attempted before its permission grant reached Applied"
        ));
    }
    if journal.exists(RECEIPT_FILE_NAME)? && !journal.exists("applied-0001.json")? {
        return Err(eyre!(
            "call receipt lacks its durable signed and Applied stage"
        ));
    }
    Ok(())
}
/// Reconcile current Applied evidence of step `index` with the journal without writing.
///
/// Rejects a retained failure, and returns the retained Applied evidence (same finality, its
/// first-read charge) in place of the current observation when one exists.
fn reconcile_retained_evidence(
    journal: &Journal,
    index: usize,
    evidence: AppliedEvidence,
) -> Result<AppliedEvidence> {
    if journal.exists(&format!("failed-{index:04}.json"))? {
        return Err(eyre!(
            "retained failure conflicts with current Applied evidence"
        ));
    }
    retained_applied_evidence(journal, index, evidence)
}
fn validate_retained_failure(
    journal: &Journal,
    index: usize,
    hash: HashOf<SignedTransaction>,
    proof: &TransactionFinalityFailure,
) -> Result<()> {
    proof.validate_for_hash(hash)?;
    if journal.exists(&format!("applied-{index:04}.json"))? {
        return Err(eyre!(
            "retained Applied evidence conflicts with current failure"
        ));
    }
    let path = format!("failed-{index:04}.json");
    if journal.exists(&path)? {
        let retained: TransactionFinalityFailure = journal.read(&path)?;
        retained.validate_for_hash(hash)?;
        if norito::json::to_vec(&retained)? != norito::json::to_vec(proof)? {
            return Err(eyre!(
                "retained failure differs from current exact-hash evidence"
            ));
        }
    }
    Ok(())
}
fn validate_attempt(journal: &Journal, step: &TransactionRecord, index: usize) -> Result<()> {
    let marker: TransactionAttempt = journal.read(&format!("attempt-{index:04}.json"))?;
    if marker.name != step.name || marker.hash != step.hash {
        return Err(eyre!(
            "call attempt differs from its exact signed transaction"
        ));
    }
    Ok(())
}
fn finality_failure(error: &eyre::Report) -> Option<TransactionFinalityFailure> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<TransactionFinalityFailure>())
        .cloned()
}
fn execute_step<T: DeploymentTransport>(
    journal: &Journal,
    step: &TransactionRecord,
    index: usize,
    transport: &T,
) -> Result<AppliedEvidence> {
    let signed = decode_transaction(step)?;
    let attempt = format!("attempt-{index:04}.json");
    let result = (|| {
        if journal.exists(&attempt)? {
            validate_attempt(journal, step, index)?;
        } else {
            journal.put_exact(
                &attempt,
                &TransactionAttempt {
                    name: step.name.clone(),
                    hash: step.hash.clone(),
                },
            )?;
            transport.submit(&signed)?;
        }
        let evidence = transport.wait(signed.hash())?;
        validate_applied(signed.hash(), &evidence)?;
        let evidence = reconcile_retained_evidence(journal, index, evidence)?;
        journal.put_exact(&format!("applied-{index:04}.json"), &evidence)?;
        Ok(evidence)
    })();
    result.map_err(|error: eyre::Report| {
        if let Some(proof) = finality_failure(&error) {
            let recorded = (|| {
                validate_retained_failure(journal, index, signed.hash(), &proof)?;
                journal.put_exact(&format!("failed-{index:04}.json"), &proof)
            })();
            if let Err(journal_error) = recorded {
                return journal_error;
            }
            return error;
        }
        eyre::Report::new(ContractCallPending {
            stage: step.name.clone(),
            hash: step.hash.clone(),
            source: error,
        })
    })
}
#[cfg(test)]
#[path = "call_tests.rs"]
mod tests;
