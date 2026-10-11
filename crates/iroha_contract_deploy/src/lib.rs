//! Durable native contract deployment using canonical Iroha SDK primitives.
//!
//! The service verifies immutable artifacts, quotes and signs exact native instructions, and
//! journals every attempted hash before dispatch. Recovery polls that exact hash without replay.
//! The Rust SDK remains the owner of transport, signing, fee quotes, and `Applied` finality.
use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    blocking::Client,
    client::{
        FeeQuoteRequest, TransactionFinalityFailure, TransactionWaitOptions, TransactionWaitOutcome,
    },
    config::Config,
    data_model::{
        account::address::ChainDiscriminantGuard,
        isi::smart_contract_code::{
            CommitContractDeployment, FinalizeSmartContractCodeUpload, RegisterSmartContractCode,
            SMART_CONTRACT_CODE_CHUNK_BYTES, UploadSmartContractCodeChunk,
        },
        prelude::*,
        smart_contract::{ContractAddress, ContractAlias, ContractArtifactId},
        transaction::{FeePaymentIntent, TransactionBuilder},
    },
};
#[cfg(test)]
use iroha_crypto::KeyPair;
use iroha_crypto::{Hash, HashOf, PrivateKey};
use iroha_model_base::{metadata::Metadata, name::Name, topology::DataSpaceId};
use iroha_primitives::json::Json;
use iroha_torii_shared::FeeQuoteResponse;
use iroha_version::codec::{DecodeVersioned, EncodeVersioned};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
mod authorization;
pub mod call;
pub use authorization::DeploymentAuthorization;
mod journal;
mod lifecycle;
pub use lifecycle::{DeploymentLifecycleGuidance, LifecycleHook, LifecycleParameter};
mod manifest_encoding;
mod native;
mod progress;
pub use progress::{DeploymentProgress, DeploymentStage};
mod validation;
use journal::Journal;
use manifest_encoding::ManifestEncodingBudget;
use native::*;
use validation::{DeploymentReadContext, validate_plan, validate_read_plan};

/// Final public receipt filename beneath the caller-selected deployment journal.
pub const RECEIPT_FILE_NAME: &str = "receipt.json";
/// Maximum immutable artifact bytes accepted by this service.
pub const MAX_DEPLOYMENT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
/// Existing retained native transaction ceiling, before canonical hex decoding.
const MAX_DEPLOYMENT_TRANSACTION_BYTES: usize = 1024 * 1024;
/// A completed deployment and its exact retained, admission-verified artifact.
///
/// Only the native service constructs this value after authenticated current alias, artifact,
/// and state-resolved Applied readback; callers cannot substitute endpoint-selected code.
#[derive(Debug)]
pub struct CompletedContract {
    receipt: DeploymentReceipt,
    artifact: Vec<u8>,
}
impl CompletedContract {
    /// Original verified deployment receipt.
    pub fn receipt(&self) -> &DeploymentReceipt {
        &self.receipt
    }
    /// Complete exact compiled bytes retained by the signed deployment plan.
    pub fn artifact(&self) -> &[u8] {
        &self.artifact
    }
}
/// Categorized deployment failure, retaining underlying SDK diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    /// Artifact bytes fail canonical admission or the fixed service bound.
    #[error("invalid deployment artifact: {0}")]
    Artifact(String),
    /// Exact client, alias, fee, or signed-plan bindings are invalid.
    #[error("invalid deployment request: {0}")]
    InvalidRequest(String),
    /// A read, compatibility probe, fee quote, or signature failed before submission.
    #[error("deployment {operation} failed: {source}")]
    Preflight {
        /// Specific operation that must be repaired.
        operation: &'static str,
        /// Original SDK diagnostic, including typed HTTP/fee/route errors when available.
        #[source]
        source: eyre::Report,
    },
    /// A durable journal could not be authenticated, locked, read, or committed.
    #[error("deployment journal failed: {0}")]
    Journal(#[source] eyre::Report),
    /// An attempted hash has not been proven `Applied`; resume performs only exact-hash recovery.
    #[error(
        "deployment step `{step}` hash {hash} is unresolved; resume this journal without creating another deployment: {source}"
    )]
    Pending {
        /// Exact native sequence step.
        step: String,
        /// Exact signed transaction hash already recorded before dispatch.
        hash: String,
        /// Submission/finality diagnostic preserved without discarding ambiguity.
        #[source]
        source: eyre::Report,
    },
    /// Authoritative global state proves that this exact attempted transaction failed permanently.
    ///
    /// The evidence is boxed to keep every `DeploymentResult` small.
    #[error("deployment step `{}` hash {} failed: {}", .0.step, .0.hash, .0.proof)]
    Failed(#[source] Box<DeploymentFailure>),
    /// Applied transaction evidence and current authenticated contract reads disagree.
    #[error("deployment readback failed: {0}")]
    Readback(#[source] eyre::Report),
}
/// Result returned by native deployment operations.
pub type DeploymentResult<T> = std::result::Result<T, DeploymentError>;
/// Durable terminal failure of one exact attempted native deployment step.
#[derive(
    Clone, Debug, thiserror::Error, norito::derive::JsonSerialize, norito::derive::JsonDeserialize,
)]
#[error("deployment step `{step}` hash {hash} failed: {proof}")]
#[norito(deny_unknown_fields)]
pub struct DeploymentFailure {
    /// Native sequence step whose signed transaction permanently failed.
    pub step: String,
    /// Canonical exact signed transaction hash.
    pub hash: String,
    /// Canonical SDK global/state rejection or expiry evidence, including its typed reason.
    #[source]
    pub proof: TransactionFinalityFailure,
}
/// Current verified deployment disposition; only fixed failure or completion releases retry gates.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(
    tag = "status",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum JournalDisposition {
    /// An unattempted step, unresolved attempted hash, or final readback still requires resume.
    Pending {
        /// Last unresolved native step when one has been attempted.
        step: Option<String>,
        /// Exact attempted hash; absent if no unresolved transaction has been dispatched.
        hash: Option<String>,
    },
    /// An exact attempted step is conclusively rejected or expired in authoritative state.
    Failed(DeploymentFailure),
    /// Exact commit and all retained finalized evidence have been verified.
    Completed(Box<DeploymentReceipt>),
    /// A fully unattempted exact plan was durably abandoned locally.
    Cancelled(DeploymentCancellation),
}
/// Durable local cancellation of exact signed transactions that were never attempted.
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct DeploymentCancellation {
    /// Exact ordered signed hashes abandoned by this local journal.
    pub transaction_hashes: Vec<String>,
}
/// Immutable caller-selected deployment inputs; credentials live only in the service `Config`.
#[derive(Clone, Debug)]
pub struct DeploymentRequest {
    /// Exact complete `.to` bytes copied from the caller's authenticated build artifact.
    pub artifact: Vec<u8>,
    /// Canonical contract alias selecting the deployment dataspace.
    pub alias: ContractAlias,
    /// Explicit fee payer, sponsor revision, and gas bound, quoted for every exact transaction.
    pub fee_payment: FeePaymentIntent,
    /// Governance approvers require native authenticated evidence; bare identities are rejected.
    pub governance_approvers: Vec<AccountId>,
}
/// Concrete immutable context, artifact, alias-CAS, and quoted-fee evidence for review.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct DeploymentPreflight {
    /// Configured exact genesis identity, bound into every signed transaction.
    pub network_id: NetworkId,
    /// Configured canonical chain identity.
    pub chain_id: String,
    /// Exact account authority used for authenticated reads and signing.
    pub authority: AccountId,
    /// Independently observed account and effective alias permission checks.
    pub authorization: DeploymentAuthorization,
    /// Address codec chain discriminant.
    pub chain_discriminant: u16,
    /// Canonical target alias.
    pub contract_alias: ContractAlias,
    /// Address derived from the authenticated nonce and dataspace.
    pub contract_address: ContractAddress,
    /// Exact dataspace resolved by the authenticated deployment-state read.
    pub dataspace_id: DataSpaceId,
    /// Canonical complete-artifact identity.
    pub code_hash: Hash,
    /// Canonical embedded ABI identity.
    pub abi_hash: Hash,
    /// Exact nonce consumed by the atomic deployment commit.
    pub deploy_nonce: u64,
    /// Alias address expected by the atomic compare-and-swap operation.
    pub previous_contract_address: Option<ContractAddress>,
    /// Ledger height from which the deployment CAS state was read.
    pub observed_block_height: u64,
    /// Canonical block hash of that deployment-state observation.
    pub observed_block_hash: String,
    /// Exact SDK fee quotes, in transaction order.
    pub fee_quotes: Vec<FeeQuoteResponse>,
    /// Ordered native transaction hashes, after applying quoted limits and signing.
    pub transaction_hashes: Vec<String>,
}
impl DeploymentPreflight {
    /// Require the same complete review, including the ordered signed transaction hashes.
    ///
    /// This compares retained evidence; it does not authenticate either plan. Journal readers
    /// must first validate their signed plan with the ordinary deployment validation owner.
    ///
    /// # Errors
    /// Rejects a changed review or evidence that cannot be encoded as canonical Norito JSON.
    pub fn require_same_plan(&self, expected: &Self) -> DeploymentResult<()> {
        let actual = self
            .to_json()
            .map_err(|error| DeploymentError::Journal(error.into()))?;
        let expected = expected
            .to_json()
            .map_err(|error| DeploymentError::Journal(error.into()))?;
        if actual != expected {
            return Err(DeploymentError::InvalidRequest(
                "retained deployment differs from the original reviewed plan".into(),
            ));
        }
        Ok(())
    }

    /// Serialize review evidence using its explicit account-address discriminant.
    ///
    /// # Errors
    /// Returns the canonical Norito JSON encoding error if evidence cannot be encoded.
    pub fn to_json(&self) -> std::result::Result<norito::json::Value, norito::json::Error> {
        let _profile = ChainDiscriminantGuard::enter(self.chain_discriminant);
        norito::json::to_value(self)
    }
}
/// Prepared signed deployment. Private storage prevents construction outside the verified service.
#[derive(Clone, Debug)]
pub struct PreparedDeployment {
    record: PlanRecord,
}
impl PreparedDeployment {
    /// Return the concrete context, artifact, CAS, and quoted transaction review.
    #[must_use]
    pub const fn preflight(&self) -> &DeploymentPreflight {
        &self.record.preflight
    }
}
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PlanRecord {
    version: u8,
    preflight: DeploymentPreflight,
    artifact_hex: String,
    requested_fee: FeePaymentIntent,
    transactions: Vec<TransactionRecord>,
}
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct TransactionRecord {
    name: String,
    hash: String,
    norito_hex: String,
}
/// Exact state-resolved global transaction evidence used by durable deployment recovery.
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct AppliedEvidence {
    /// Canonical exact signed transaction hash.
    pub hash: String,
    /// Fixed successful finality status.
    pub terminal_kind: String,
    /// Canonical ledger height at which the transaction applied.
    pub block_height: u64,
    /// Fixed global transaction-status scope.
    pub scope: String,
    /// Fixed durable state resolution source.
    pub resolved_from: String,
    /// Gas and fee actually settled, read from the transaction's committed fee receipt.
    /// `None` when the node reported no committed fee receipt for the transaction or the
    /// receipt could not be read. It is reporting evidence only and never gates Applied
    /// validation or recovery.
    pub charge: Option<AppliedCharge>,
}
/// Gas and fee one Applied transaction actually settled, from its committed fee receipt.
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct AppliedCharge {
    /// IVM gas units the transaction consumed, as metered for its fee.
    pub gas_used: u64,
    /// Fee asset the settlement charged.
    pub fee_asset: AssetDefinitionId,
    /// Exact fee amount settled.
    pub fee_amount: iroha_primitives::numeric::Quantity,
}
impl AppliedCharge {
    /// Project the committed fee receipt of one transaction result.
    #[must_use]
    pub fn from_result(result: &TransactionResult) -> Option<Self> {
        result.nexus_fee_receipt().map(|receipt| Self {
            gas_used: receipt.schedule.gas_used,
            fee_asset: receipt.fee_asset_id.clone(),
            fee_amount: receipt.fee_amount.clone(),
        })
    }
}
impl AppliedEvidence {
    /// Whether two observations describe the same exact-hash Applied finality.
    ///
    /// The reporting-only [`Self::charge`] is excluded: it is read on a best-effort basis, so a
    /// later observation may lack a charge that the first one retained.
    #[must_use]
    pub fn same_finality(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.terminal_kind == other.terminal_kind
            && self.block_height == other.block_height
            && self.scope == other.scope
            && self.resolved_from == other.resolved_from
    }
}
/// Return the retained Applied observation of journal step `index`, or `current` when none is
/// retained. Nothing is written.
///
/// A retained observation must describe the same finality as `current`; it stays authoritative,
/// including its reporting-only charge, so recovery never rewrites immutable Applied evidence.
///
/// # Errors
/// Returns journal failures or a retained observation with different finality.
pub(crate) fn retained_applied_evidence(
    journal: &Journal,
    index: usize,
    current: AppliedEvidence,
) -> Result<AppliedEvidence> {
    let path = format!("applied-{index:04}.json");
    if !journal.exists(&path)? {
        return Ok(current);
    }
    let retained: AppliedEvidence = journal.read(&path)?;
    if !retained.same_finality(&current) {
        return Err(eyre!(
            "retained Applied evidence differs from current exact-hash evidence"
        ));
    }
    Ok(retained)
}
/// Durably retain the first Applied observation of journal step `index` and return the
/// authoritative one, as [`retained_applied_evidence`] selects it.
///
/// # Errors
/// Returns journal failures or a retained observation with different finality.
pub(crate) fn retain_applied_evidence(
    journal: &Journal,
    index: usize,
    current: AppliedEvidence,
) -> Result<AppliedEvidence> {
    let evidence = retained_applied_evidence(journal, index, current)?;
    journal.put_exact(&format!("applied-{index:04}.json"), &evidence)?;
    Ok(evidence)
}
/// Read the committed gas and fee of one Applied transaction through the authenticated
/// transaction-details query.
///
/// Finality was already established by the transaction-status wait, so the charge is
/// best-effort reporting: a node that does not answer the details query, or answers without a
/// committed fee receipt, yields `None` instead of failing the Applied operation.
pub(crate) fn read_applied_charge(
    client: &Client,
    hash: HashOf<SignedTransaction>,
) -> Option<AppliedCharge> {
    let entrypoint = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::from(hash));
    let details = client
        .client()
        .get_successful_transaction_details(entrypoint)
        .ok()?;
    AppliedCharge::from_result(details.transaction.result())
}
/// Public receipt emitted only after atomic commit reaches `Applied` and contract readback agrees.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct DeploymentReceipt {
    /// Receipt schema version.
    pub version: u8,
    /// Exact genesis identity of all submitted transactions.
    pub network_id: NetworkId,
    /// Canonical chain identity from the immutable client context.
    pub chain_id: String,
    /// Account-address codec discriminant used by the exact runtime client.
    pub chain_discriminant: u16,
    /// Account that authorized deployment.
    pub authority: AccountId,
    /// Canonical deployed alias.
    pub contract_alias: ContractAlias,
    /// Derived deployed address.
    pub contract_address: ContractAddress,
    /// Deployed non-signing contract account.
    pub contract_subject_account: AccountId,
    /// Alias-selected dataspace.
    pub dataspace_id: DataSpaceId,
    /// Verified complete-artifact identity.
    pub code_hash: Hash,
    /// Verified embedded ABI identity.
    pub abi_hash: Hash,
    /// Exact atomic deployment transaction and its canonical `Applied` evidence.
    pub commit: AppliedEvidence,
    /// Applied evidence for every native stage, in order.
    pub stages: Vec<AppliedEvidence>,
    /// Height of the authenticated post-commit alias/deployment-state read.
    pub readback_block_height: u64,
    /// Block hash of the authenticated post-commit read.
    pub readback_block_hash: String,
    /// True only after stored bytes are downloaded and exactly equal the supplied artifact.
    pub stored_artifact_matches: bool,
}
impl DeploymentReceipt {
    /// Serialize public receipt evidence using its explicit account-address discriminant.
    ///
    /// # Errors
    /// Returns the canonical Norito JSON encoding error if evidence cannot be encoded.
    pub fn to_json(&self) -> std::result::Result<norito::json::Value, norito::json::Error> {
        let _profile = ChainDiscriminantGuard::enter(self.chain_discriminant);
        norito::json::to_value(self)
    }
}
/// Shared native contract deployment orchestration using one immutable runtime client authority.
pub struct DeploymentService {
    config: Config,
    client: Client,
}
impl DeploymentService {
    /// Construct a service without reading files or submitting any transaction.
    ///
    /// # Errors
    /// Rejects an invalid immutable SDK context or zero finality timeout.
    pub fn new(config: Config) -> DeploymentResult<Self> {
        let _address_profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        if config.transaction_status_timeout.is_zero() {
            return Err(DeploymentError::InvalidRequest(
                "transaction status timeout must be nonzero".to_owned(),
            ));
        }
        let client = Client::new(config.clone())
            .map_err(|source| preflight_error("client configuration", source))?;
        Ok(Self { config, client })
    }
    /// Prepare exact quoted native transactions without dispatch or journal mutation.
    ///
    /// # Errors
    /// Returns artifact, authenticated state, authority, fee, or signing failures.
    pub fn prepare(&self, request: &DeploymentRequest) -> DeploymentResult<PreparedDeployment> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let verified = verify_request(request)?;
        self.client
            .refresh_capabilities()
            .map_err(|source| preflight_error("network compatibility", source))?;
        authorization::verify_account(&self.client, &self.config.account)
            .map_err(|source| preflight_error("registered deployment authority", source))?;
        let state = read_contract_deployment_state(
            &self.client,
            &self.config.account,
            &request.alias,
            self.config.account_chain_discriminant,
        )
        .map_err(|source| preflight_error("account and alias deployment state", source))?;
        let authorization = authorization::read_authorization(
            &self.client,
            &self.config.account,
            &request.alias,
            state.dataspace_id,
        )
        .map_err(|source| preflight_error("owned alias permissions", source))?;
        let address = ContractAddress::derive(
            &self.config.network_id,
            &self.config.account,
            state.deploy_nonce,
            state.dataspace_id,
        )
        .map_err(|error| DeploymentError::InvalidRequest(error.to_string()))?;
        let mut manifest_budget = ManifestEncodingBudget::new()
            .map_err(|source| preflight_error("contract manifest encoding admission", source))?;
        let signer_backing = manifest_budget
            .reserve_signer(self.config.key_pair.public_key())
            .map_err(|source| preflight_error("contract manifest signer admission", source))?;
        let signing_frame = manifest_budget
            .reserve_frame(&verified.manifest)
            .map_err(|source| preflight_error("contract manifest frame admission", source))?;
        let manifest = verified
            .manifest
            .try_signed(
                manifest_budget.context(),
                signing_frame.remaining_bytes(),
                &self.config.key_pair,
            )
            .map_err(|error| preflight_error("contract manifest signature", eyre!(error)))?;
        // The signing API has destroyed its temporary canonical payload.
        drop(signing_frame);
        let sequence =
            self.sign_native_sequence(request, manifest, verified.code_hash, &state, &address)?;
        let (transactions, quotes) =
            self.quote_transactions(sequence, &request.fee_payment, state.dataspace_id)?;
        // All native drafts and re-signed graphs have been consumed into encoded records.
        drop(signer_backing);
        let preflight = DeploymentPreflight {
            network_id: self.config.network_id,
            chain_id: self.config.chain.to_string(),
            authority: self.config.account.clone(),
            authorization,
            chain_discriminant: self.config.account_chain_discriminant,
            contract_alias: request.alias.clone(),
            contract_address: address,
            dataspace_id: state.dataspace_id,
            code_hash: verified.code_hash,
            abi_hash: verified.abi_hash,
            deploy_nonce: state.deploy_nonce,
            previous_contract_address: state.previous_contract_address,
            observed_block_height: canonical_decimal_u64(
                &state.snapshot.observed_block_height,
                "observed_block_height",
            )
            .map_err(|source| preflight_error("observed ledger height", source))?,
            observed_block_hash: state.snapshot.observed_block_hash,
            fee_quotes: quotes,
            transaction_hashes: transactions
                .iter()
                .map(|transaction| transaction.hash.clone())
                .collect(),
        };
        let prepared = PreparedDeployment {
            record: PlanRecord {
                version: 1,
                preflight,
                artifact_hex: hex::encode(&request.artifact),
                requested_fee: request.fee_payment.clone(),
                transactions,
            },
        };
        validation::validate_plan_with_manifest_budget(
            &prepared.record,
            &self.config,
            &mut manifest_budget,
        )?;
        Ok(prepared)
    }
    /// Return concrete read-only preflight evidence, including every exact fee quote and hash.
    ///
    /// # Errors
    /// Returns the same artifact, state, fee, and signing failures as [`Self::prepare`].
    pub fn preflight(&self, request: &DeploymentRequest) -> DeploymentResult<DeploymentPreflight> {
        self.prepare(request)
            .map(|prepared| prepared.record.preflight)
    }
    /// Atomically publish the exact prepared plan and its journal lock without submitting it.
    ///
    /// # Errors
    /// Rejects a substituted plan, unsafe/busy or incomplete journal, or a different plan
    /// already at that path. An existing destination is never repaired or replaced.
    pub fn persist(
        &self,
        prepared: &PreparedDeployment,
        journal_dir: &Path,
    ) -> DeploymentResult<()> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        self.validate_plan(&prepared.record)?;
        Journal::persist_plan(journal_dir, &prepared.record)
            .map(|_| ())
            .map_err(DeploymentError::Journal)
    }
    /// Persist the signed plan, then execute each unattempted step and recover exact attempted hashes.
    /// The fallible observer receives exact preflight, durable stage progress, and readback events.
    /// Observer refusal stops further work; retained attempts still require exact recovery.
    ///
    /// # Errors
    /// Returns journal, exact-hash pending/failure, and post-commit readback errors. Observer
    /// refusal stops further work and retains the original journal evidence. No attempted
    /// transaction is signed again or blindly resubmitted, including after an ambiguous failure.
    pub fn execute(
        &self,
        prepared: &PreparedDeployment,
        journal_dir: &Path,
        progress: &mut dyn FnMut(DeploymentProgress) -> DeploymentResult<()>,
    ) -> DeploymentResult<DeploymentReceipt> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        self.persist(prepared, journal_dir)?;
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        journal
            .require_exact("plan.json", &prepared.record)
            .map_err(DeploymentError::Journal)?;
        self.execute_record(&prepared.record, &journal, progress)
    }
    /// Recover only the exact signed plan retained in the authenticated journal.
    /// The fallible observer receives the retained preflight and exact-hash recovery progress.
    /// Refusal stops subsequent stages without erasing or replaying retained attempts.
    ///
    /// # Errors
    /// Rejects mismatched client/plan identities or unsafe journal data. Observer refusal stops
    /// further work and retains original evidence; unresolved attempted transactions remain
    /// pending under their original hashes and are never resubmitted.
    pub fn resume(
        &self,
        journal_dir: &Path,
        progress: &mut dyn FnMut(DeploymentProgress) -> DeploymentResult<()>,
    ) -> DeploymentResult<DeploymentReceipt> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        self.validate_plan(&record)?;
        self.execute_record(&record, &journal, progress)
    }
    /// Authenticate retained deployment inputs using the original execution authority.
    /// This performs no network requests, signing, submission or journal writes.
    ///
    /// # Errors
    /// Rejects unsafe storage, altered plans, or a different network, authority or signing key.
    pub fn retained_preflight(&self, journal_dir: &Path) -> DeploymentResult<DeploymentPreflight> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        self.validate_plan(&record)?;
        Ok(record.preflight)
    }

    /// Read optional activation guidance from the original authenticated signed plan.
    ///
    /// This is presentation metadata, not current lifecycle state. It performs no HTTP,
    /// signing or submission. `expected_code_hash` must come from that completed receipt;
    /// an independently valid replacement plan cannot change its guidance. A caller may omit the
    /// guidance when this separate read fails without changing that receipt.
    ///
    /// # Errors
    /// Rejects unsafe custody, changed plan bytes or a different original signing authority.
    pub fn retained_lifecycle_hook(
        &self,
        journal_dir: &Path,
        expected_code_hash: Hash,
    ) -> DeploymentResult<Option<LifecycleHook>> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        self.validate_plan(&record)?;
        if record.preflight.code_hash != expected_code_hash {
            return Err(DeploymentError::InvalidRequest(
                "retained initialization artifact differs from completed deployment".into(),
            ));
        }
        let artifact = hex::decode(&record.artifact_hex).map_err(|error| {
            DeploymentError::Artifact(format!("invalid retained artifact: {error}"))
        })?;
        Ok(LifecycleHook::from_artifact(&artifact))
    }
    /// Verify a completed deployment still names its current alias and exact stored artifact.
    /// The locked plan must match the caller's original review before any network read.
    /// This is the idempotent deployment check; historical receipt inspection remains available
    /// separately through [`Self::completed_receipt`]. No transaction is submitted.
    ///
    /// # Errors
    /// Rejects invalid retained evidence, a changed authority, unresolved finality or changed
    /// alias/artifact state. An uncompleted authenticated plan returns `None`.
    pub fn current_completed_receipt(
        &self,
        journal_dir: &Path,
        expected: &DeploymentPreflight,
    ) -> DeploymentResult<Option<DeploymentReceipt>> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        self.validate_plan(&record)?;
        record.preflight.require_same_plan(expected)?;
        let Some(receipt) = self.verify_completed_receipt(&record, &journal)? else {
            return Ok(None);
        };
        self.read_back(&record, &receipt.commit)?;
        Ok(Some(receipt))
    }
    /// Authenticate a completed current deployment and recover its exact local artifact.
    ///
    /// This read never signs or submits. Both the receipt and bytes come from one exclusively
    /// locked journal after current authenticated alias/artifact readback.
    ///
    /// # Errors
    /// Rejects unsafe custody, changed context, incomplete execution or substituted state.
    pub fn current_completed_contract(
        &self,
        journal_dir: &Path,
    ) -> DeploymentResult<CompletedContract> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        self.validate_plan(&record)?;
        let receipt = self
            .verify_completed_receipt(&record, &journal)?
            .ok_or_else(|| {
                DeploymentError::InvalidRequest("contract deployment is not completed".into())
            })?;
        self.read_back(&record, &receipt.commit)?;
        let artifact = hex::decode(&record.artifact_hex).map_err(|error| {
            DeploymentError::Artifact(format!("invalid retained artifact: {error}"))
        })?;
        Ok(CompletedContract { receipt, artifact })
    }
    /// Authenticate an existing completed journal and recheck its exact commit on this network.
    ///
    /// Returns `None` for a valid plan that has no finalized receipt. This operation never submits
    /// or updates a journal. A later alias update does not invalidate historical completion.
    ///
    /// # Errors
    /// Rejects malformed evidence, a different network/chain/profile, or unresolved finality. The
    /// current read account may differ from the historical deployment authority. The locked plan
    /// must match the caller's original review before any network read.
    pub fn completed_receipt(
        &self,
        journal_dir: &Path,
        expected: &DeploymentPreflight,
    ) -> DeploymentResult<Option<DeploymentReceipt>> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        validate_read_plan(&record, &DeploymentReadContext::from(&self.config))?;
        record.preflight.require_same_plan(expected)?;
        self.verify_completed_receipt(&record, &journal)
    }
    /// Durably abandon a fully unattempted local plan without submitting any transaction.
    ///
    /// Repeated cancellation is idempotent. A different current read account may cancel an owned
    /// journal on the same network, chain, and address profile; attempted ambiguity cannot be
    /// cancelled or represented as transaction expiry.
    ///
    /// # Errors
    /// Rejects a different network/profile, unsafe journal, any execution evidence, or an altered
    /// cancellation record. The journal stays exclusively locked throughout validation and write;
    /// its plan must match the caller's original preflight before cancellation is published.
    pub fn cancel(
        &self,
        journal_dir: &Path,
        expected: &DeploymentPreflight,
    ) -> DeploymentResult<DeploymentCancellation> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        validate_read_plan(&record, &DeploymentReadContext::from(&self.config))?;
        record.preflight.require_same_plan(expected)?;
        journal
            .require_unattempted()
            .map_err(DeploymentError::Journal)?;
        let cancellation = DeploymentCancellation {
            transaction_hashes: record.preflight.transaction_hashes.clone(),
        };
        journal
            .put_exact("cancelled.json", &cancellation)
            .map_err(DeploymentError::Journal)?;
        Ok(cancellation)
    }
    fn verify_completed_receipt(
        &self,
        record: &PlanRecord,
        journal: &Journal,
    ) -> DeploymentResult<Option<DeploymentReceipt>> {
        if !journal
            .exists(RECEIPT_FILE_NAME)
            .map_err(DeploymentError::Journal)?
        {
            return Ok(None);
        }
        self.client
            .refresh_capabilities()
            .map_err(|source| preflight_error("network compatibility", source))?;
        verify_completed_record(record, journal, &LiveTransport { service: self })
    }
    /// Inspect exact attempted hashes without submission, persisting newly proven terminal failure.
    ///
    /// # Errors
    /// Rejects an unsafe journal, changed context, inconsistent retained evidence, or malformed
    /// status. The locked plan must match the caller's original review before any network read or
    /// failure-marker publication. Transport uncertainty remains [`JournalDisposition::Pending`],
    /// never failure.
    pub fn inspect_journal(
        &self,
        journal_dir: &Path,
        expected: &DeploymentPreflight,
    ) -> DeploymentResult<JournalDisposition> {
        let _address_profile =
            ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let journal = Journal::open(journal_dir, false).map_err(DeploymentError::Journal)?;
        let record: PlanRecord = journal
            .read("plan.json")
            .map_err(DeploymentError::Journal)?;
        let context = DeploymentReadContext::from(&self.config);
        validate_read_plan(&record, &context)?;
        record.preflight.require_same_plan(expected)?;
        self.client
            .refresh_capabilities()
            .map_err(|source| preflight_error("network compatibility", source))?;
        inspect_read_record(
            &record,
            &journal,
            &context,
            &LiveTransport { service: self },
        )
    }
    fn execute_record(
        &self,
        record: &PlanRecord,
        journal: &Journal,
        progress: &mut dyn FnMut(DeploymentProgress) -> DeploymentResult<()>,
    ) -> DeploymentResult<DeploymentReceipt> {
        reject_cancelled(record, journal)?;
        progress(DeploymentProgress::Prepared(Box::new(
            record.preflight.clone(),
        )))?;
        if journal
            .exists(RECEIPT_FILE_NAME)
            .map_err(DeploymentError::Journal)?
        {
            // A historical completion rechecks only its immutable commit, never its current alias.
            progress(DeploymentProgress::Recovering(progress::stage(
                record,
                record.transactions.len() - 1,
            )))?;
        }
        if let Some(receipt) = self.verify_completed_receipt(record, journal)? {
            progress(DeploymentProgress::Applied {
                stage: progress::stage(record, record.transactions.len() - 1),
                evidence: receipt.commit.clone(),
            })?;
            return Ok(receipt);
        }
        self.client
            .refresh_capabilities()
            .map_err(|source| preflight_error("network compatibility", source))?;
        let stages =
            execute_transactions(record, journal, &LiveTransport { service: self }, progress)?;
        let commit = stages
            .last()
            .cloned()
            .ok_or_else(|| DeploymentError::InvalidRequest("empty deployment plan".to_owned()))?;
        let preflight = &record.preflight;
        progress(DeploymentProgress::ReadingBack {
            alias: preflight.contract_alias.clone(),
            address: preflight.contract_address.clone(),
        })?;
        let (readback_block_height, readback_block_hash) = self.read_back(record, &commit)?;
        let receipt = DeploymentReceipt {
            version: 1,
            network_id: preflight.network_id,
            chain_id: preflight.chain_id.clone(),
            chain_discriminant: preflight.chain_discriminant,
            authority: preflight.authority.clone(),
            contract_alias: preflight.contract_alias.clone(),
            contract_address: preflight.contract_address.clone(),
            contract_subject_account: preflight.contract_address.subject_id(),
            dataspace_id: preflight.dataspace_id,
            code_hash: preflight.code_hash,
            abi_hash: preflight.abi_hash,
            commit,
            stages,
            readback_block_height,
            readback_block_hash,
            stored_artifact_matches: true,
        };
        if let Some(retained) =
            retained_receipt(record, journal).map_err(DeploymentError::Journal)?
        {
            if retained.stages != receipt.stages {
                return Err(DeploymentError::Readback(eyre!(
                    "retained completed stages disagree with exact-hash recovery"
                )));
            }
            return Ok(retained);
        }
        journal
            .put_exact(RECEIPT_FILE_NAME, &receipt)
            .map_err(DeploymentError::Journal)?;
        Ok(receipt)
    }
    /// Sign the exact native upload, manifest-registration, and atomic commit drafts in order.
    fn sign_native_sequence(
        &self,
        request: &DeploymentRequest,
        manifest: iroha::data_model::smart_contract::manifest::ContractManifest,
        code_hash: Hash,
        state: &ValidatedContractDeploymentState,
        address: &ContractAddress,
    ) -> DeploymentResult<Vec<(String, String, SignedTransaction)>> {
        let metadata = deployment_transaction_metadata(address, &[])
            .map_err(|source| preflight_error("native attribution", source))?;
        let signing = TransactionSigningContext {
            network_id: self.config.network_id,
            authority: &self.config.account,
            private_key: self.config.key_pair.private_key(),
            transaction_ttl: Some(self.config.transaction_ttl),
            fee_payment: &request.fee_payment,
            metadata: &metadata,
        };
        let artifact_id = ContractArtifactId::new(state.dataspace_id, code_hash);
        let upload = build_native_upload_transaction_plan(&signing, artifact_id, &request.artifact)
            .map_err(|source| preflight_error("native upload plan", source))?;
        debug_assert_eq!(upload.chunk_count as usize, upload.pre_stage.len() + 1);
        let mut uploads = upload.pre_stage;
        uploads.push(upload.finalize);
        let register = signing
            .sign([InstructionBox::from(RegisterSmartContractCode {
                artifact_id,
                manifest,
            })])
            .map_err(|source| preflight_error("manifest registration", source))?;
        let commit = build_commit_deployment_transaction(
            &signing,
            state.deploy_nonce,
            address.clone(),
            code_hash,
            request.alias.clone(),
            state.previous_contract_address.clone(),
        )
        .map_err(|source| preflight_error("atomic deployment commit", source))?;
        Ok(deployment_transaction_sequence(
            false, uploads, register, commit,
        ))
    }
    /// Quote and re-sign every exact draft in order, then check cumulative funding.
    fn quote_transactions(
        &self,
        sequence: Vec<(String, String, SignedTransaction)>,
        fee_payment: &FeePaymentIntent,
        expected_dataspace: DataSpaceId,
    ) -> DeploymentResult<(Vec<TransactionRecord>, Vec<FeeQuoteResponse>)> {
        let mut transactions = Vec::with_capacity(sequence.len());
        let mut quotes = Vec::with_capacity(sequence.len());
        for (name, _, draft) in sequence {
            let (signed, quote) =
                quote_and_resign_transaction(&self.client, &draft, fee_payment)
                    .map_err(|source| preflight_error("exact transaction fee quote", source))?;
            native::validate_quote_route(&quote, expected_dataspace)
                .map_err(|source| preflight_error("exact transaction fee route", source))?;
            transactions.push(TransactionRecord {
                name,
                hash: signed.hash().to_string(),
                norito_hex: hex::encode(signed.encode_versioned()),
            });
            quotes.push(quote);
        }
        self.client
            .check_funding(&BTreeMap::default(), &quotes)
            .map_err(|source| preflight_error("cumulative deployment funding", source))?;
        Ok((transactions, quotes))
    }
    /// Authenticate the post-commit alias, nonce, dataspace, height, and stored artifact bytes.
    ///
    /// Returns the authenticated readback block height and block hash.
    fn read_back(
        &self,
        record: &PlanRecord,
        commit: &AppliedEvidence,
    ) -> DeploymentResult<(u64, String)> {
        let preflight = &record.preflight;
        let state = read_contract_deployment_state(
            &self.client,
            &self.config.account,
            &preflight.contract_alias,
            self.config.account_chain_discriminant,
        )
        .map_err(DeploymentError::Readback)?;
        let height = canonical_decimal_u64(
            &state.snapshot.observed_block_height,
            "observed_block_height",
        )
        .map_err(DeploymentError::Readback)?;
        if state.dataspace_id != preflight.dataspace_id
            || state.previous_contract_address.as_ref() != Some(&preflight.contract_address)
            || state.deploy_nonce <= preflight.deploy_nonce
            || height < commit.block_height
        {
            return Err(DeploymentError::Readback(eyre!(
                "authenticated post-commit alias, nonce, dataspace, or ledger height disagrees with the exact Applied deployment"
            )));
        }
        let stored = self
            .client
            .client()
            .get_contract_code_bytes(&ContractArtifactId::new(
                preflight.dataspace_id,
                preflight.code_hash,
            ))
            .map_err(DeploymentError::Readback)?;
        if hex::encode(&stored) != record.artifact_hex {
            return Err(DeploymentError::Readback(eyre!(
                "stored contract bytes differ from the exact deployed artifact"
            )));
        }
        let verified = ivm_artifact_admission::verify_contract_artifact(&stored)
            .map_err(|error| DeploymentError::Readback(eyre!(error)))?;
        if verified.code_hash != preflight.code_hash || verified.abi_hash != preflight.abi_hash {
            return Err(DeploymentError::Readback(eyre!(
                "stored contract code/ABI identity disagrees with the deployment"
            )));
        }
        Ok((height, state.snapshot.observed_block_hash))
    }
    fn validate_plan(&self, record: &PlanRecord) -> DeploymentResult<()> {
        validate_plan(record, &self.config)
    }
}
/// Check fixed request bounds and verify the immutable artifact before any network access.
fn verify_request(
    request: &DeploymentRequest,
) -> DeploymentResult<ivm_artifact_admission::VerifiedContractArtifact> {
    if request.artifact.is_empty() || request.artifact.len() > MAX_DEPLOYMENT_ARTIFACT_BYTES {
        return Err(DeploymentError::Artifact(format!(
            "expected 1..={MAX_DEPLOYMENT_ARTIFACT_BYTES} immutable bytes"
        )));
    }
    if !request.governance_approvers.is_empty() {
        return Err(DeploymentError::InvalidRequest("governance approval identities are not approval evidence; protected deployments require the native authenticated governance workflow".to_owned()));
    }
    request
        .fee_payment
        .validate()
        .map_err(|error| DeploymentError::InvalidRequest(error.to_string()))?;
    ivm_artifact_admission::verify_contract_artifact(&request.artifact)
        .map_err(|error| DeploymentError::Artifact(error.to_string()))
}
fn preflight_error(operation: &'static str, source: eyre::Report) -> DeploymentError {
    DeploymentError::Preflight { operation, source }
}
/// Return the public finalized receipt path without opening the journal.
#[must_use]
pub fn receipt_path(journal_dir: &Path) -> PathBuf {
    journal_dir.join(RECEIPT_FILE_NAME)
}

trait DeploymentTransport {
    fn submit(&self, transaction: &SignedTransaction) -> Result<()>;
    fn wait(&self, hash: HashOf<SignedTransaction>) -> Result<AppliedEvidence>;
}
struct LiveTransport<'a> {
    service: &'a DeploymentService,
}
impl DeploymentTransport for LiveTransport<'_> {
    fn submit(&self, transaction: &SignedTransaction) -> Result<()> {
        self.service
            .client
            .submit_transaction_and_wait(transaction)
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
fn applied_evidence(
    hash: HashOf<SignedTransaction>,
    outcome: TransactionWaitOutcome,
    charge: Option<AppliedCharge>,
) -> Result<AppliedEvidence> {
    let evidence = AppliedEvidence {
        hash: outcome.hash,
        terminal_kind: outcome.terminal_kind,
        block_height: outcome
            .block_height
            .ok_or_else(|| eyre!("Applied deployment has no ledger height"))?,
        scope: outcome.scope,
        resolved_from: outcome.resolved_from,
        charge,
    };
    validate_applied(hash, &evidence)?;
    Ok(evidence)
}
fn validate_applied(hash: HashOf<SignedTransaction>, evidence: &AppliedEvidence) -> Result<()> {
    if evidence.hash != hash.to_string()
        || evidence.terminal_kind != "Applied"
        || evidence.scope != "global"
        || evidence.resolved_from != "state"
        || evidence.block_height == 0
    {
        return Err(eyre!(
            "deployment requires exact-hash global state-resolved Applied evidence with nonzero height"
        ));
    }
    Ok(())
}
fn execute_transactions<T: DeploymentTransport>(
    record: &PlanRecord,
    journal: &Journal,
    transport: &T,
    progress: &mut dyn FnMut(DeploymentProgress) -> DeploymentResult<()>,
) -> DeploymentResult<Vec<AppliedEvidence>> {
    reject_cancelled(record, journal)?;
    let mut stages = Vec::with_capacity(record.transactions.len());
    for (index, step) in record.transactions.iter().enumerate() {
        let signed = decode_transaction(step).map_err(DeploymentError::Journal)?;
        let hash = signed.hash();
        let attempted = format!("attempt-{index:04}.json");
        if journal
            .exists(&attempted)
            .map_err(DeploymentError::Journal)?
        {
            let retained: TransactionAttempt =
                journal.read(&attempted).map_err(DeploymentError::Journal)?;
            if retained.hash != step.hash || retained.name != step.name {
                return Err(DeploymentError::Journal(eyre!(
                    "attempt marker disagrees with exact signed deployment step"
                )));
            }
            progress(DeploymentProgress::Recovering(progress::stage(
                record, index,
            )))?;
        } else {
            journal
                .put_exact(
                    &attempted,
                    &TransactionAttempt {
                        name: step.name.clone(),
                        hash: step.hash.clone(),
                    },
                )
                .map_err(DeploymentError::Journal)?;
            progress(DeploymentProgress::Submitting(progress::stage(
                record, index,
            )))?;
            // The observer is arbitrary caller code. Retain the original journal lock
            // after it returns and before crossing the paid dispatch boundary.
            journal.revalidate().map_err(DeploymentError::Journal)?;
            if let Err(source) = transport.submit(&signed) {
                return Err(record_step_failure(step, index, journal, source));
            }
        }
        // Even a previously recorded Applied marker is revalidated against the current exact network.
        let evidence = transport
            .wait(hash)
            .and_then(|evidence| {
                validate_applied(hash, &evidence)?;
                Ok(evidence)
            })
            .map_err(|source| record_step_failure(step, index, journal, source))?;
        if journal
            .exists(&format!("failed-{index:04}.json"))
            .map_err(DeploymentError::Journal)?
        {
            return Err(DeploymentError::Journal(eyre!(
                "transaction has conflicting retained failure and current Applied evidence"
            )));
        }
        let evidence =
            retain_applied_evidence(journal, index, evidence).map_err(DeploymentError::Journal)?;
        progress(DeploymentProgress::Applied {
            stage: progress::stage(record, index),
            evidence: evidence.clone(),
        })?;
        stages.push(evidence);
    }
    Ok(stages)
}
fn record_step_failure(
    step: &TransactionRecord,
    index: usize,
    journal: &Journal,
    source: eyre::Report,
) -> DeploymentError {
    let proof = source
        .chain()
        .find_map(|cause| cause.downcast_ref::<TransactionFinalityFailure>())
        .cloned();
    if let Some(proof) = proof {
        let result = (|| -> Result<DeploymentFailure> {
            let signed = decode_transaction(step)?;
            proof.validate_for_hash(signed.hash())?;
            if journal.exists(&format!("applied-{index:04}.json"))? {
                return Err(eyre!(
                    "transaction has conflicting retained Applied and current failure evidence"
                ));
            }
            let failure = DeploymentFailure {
                step: step.name.clone(),
                hash: step.hash.clone(),
                proof,
            };
            journal.put_exact(&format!("failed-{index:04}.json"), &failure)?;
            Ok(failure)
        })();
        return result.map_or_else(DeploymentError::Journal, |failure| {
            DeploymentError::Failed(Box::new(failure))
        });
    }
    DeploymentError::Pending {
        step: step.name.clone(),
        hash: step.hash.clone(),
        source,
    }
}

fn inspect_read_record<T: DeploymentTransport>(
    record: &PlanRecord,
    journal: &Journal,
    context: &DeploymentReadContext,
    transport: &T,
) -> DeploymentResult<JournalDisposition> {
    validate_read_plan(record, context)?;
    if let Some(cancellation) = retained_cancellation(record, journal)? {
        return Ok(JournalDisposition::Cancelled(cancellation));
    }
    if let Some(receipt) = verify_completed_record(record, journal, transport)? {
        return Ok(JournalDisposition::Completed(Box::new(receipt)));
    }
    inspect_transactions(record, journal, transport)
}

fn retained_cancellation(
    record: &PlanRecord,
    journal: &Journal,
) -> DeploymentResult<Option<DeploymentCancellation>> {
    if !journal
        .exists("cancelled.json")
        .map_err(DeploymentError::Journal)?
    {
        return Ok(None);
    }
    journal
        .require_unattempted()
        .map_err(DeploymentError::Journal)?;
    let cancellation: DeploymentCancellation = journal
        .read("cancelled.json")
        .map_err(DeploymentError::Journal)?;
    if cancellation.transaction_hashes != record.preflight.transaction_hashes {
        return Err(DeploymentError::Journal(eyre!(
            "retained cancellation disagrees with the exact signed deployment plan"
        )));
    }
    Ok(Some(cancellation))
}

fn reject_cancelled(record: &PlanRecord, journal: &Journal) -> DeploymentResult<()> {
    if retained_cancellation(record, journal)?.is_some() {
        return Err(DeploymentError::InvalidRequest(
            "this unattempted deployment was cancelled locally; prepare a new plan to deploy"
                .to_owned(),
        ));
    }
    Ok(())
}

fn inspect_transactions<T: DeploymentTransport>(
    record: &PlanRecord,
    journal: &Journal,
    transport: &T,
) -> DeploymentResult<JournalDisposition> {
    for (index, step) in record.transactions.iter().enumerate() {
        let attempted = format!("attempt-{index:04}.json");
        if !journal
            .exists(&attempted)
            .map_err(DeploymentError::Journal)?
        {
            for later in index + 1..record.transactions.len() {
                if journal
                    .exists(&format!("attempt-{later:04}.json"))
                    .map_err(DeploymentError::Journal)?
                {
                    return Err(DeploymentError::Journal(eyre!(
                        "attempted deployment stages are not contiguous"
                    )));
                }
            }
            return Ok(JournalDisposition::Pending {
                step: None,
                hash: None,
            });
        }
        let marker: TransactionAttempt =
            journal.read(&attempted).map_err(DeploymentError::Journal)?;
        if marker.name != step.name || marker.hash != step.hash {
            return Err(DeploymentError::Journal(eyre!(
                "attempt marker disagrees with exact native plan"
            )));
        }
        let signed = decode_transaction(step).map_err(DeploymentError::Journal)?;
        match transport.wait(signed.hash()) {
            Ok(evidence) => {
                validate_applied(signed.hash(), &evidence).map_err(DeploymentError::Readback)?;
                if journal
                    .exists(&format!("failed-{index:04}.json"))
                    .map_err(DeploymentError::Journal)?
                {
                    return Err(DeploymentError::Journal(eyre!(
                        "retained terminal failure disagrees with current Applied evidence"
                    )));
                }
                retain_applied_evidence(journal, index, evidence)
                    .map_err(DeploymentError::Journal)?;
            }
            Err(source) => {
                return match record_step_failure(step, index, journal, source) {
                    DeploymentError::Failed(failure) => {
                        for later in index + 1..record.transactions.len() {
                            if journal
                                .exists(&format!("attempt-{later:04}.json"))
                                .map_err(DeploymentError::Journal)?
                            {
                                return Err(DeploymentError::Journal(eyre!(
                                    "deployment continued after a fixed terminal failure"
                                )));
                            }
                        }
                        Ok(JournalDisposition::Failed(*failure))
                    }
                    DeploymentError::Pending { step, hash, .. } => {
                        Ok(JournalDisposition::Pending {
                            step: Some(step),
                            hash: Some(hash),
                        })
                    }
                    error => Err(error),
                };
            }
        }
    }
    let last = record.transactions.last();
    Ok(JournalDisposition::Pending {
        step: last.map(|step| step.name.clone()),
        hash: last.map(|step| step.hash.clone()),
    })
}
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct TransactionAttempt {
    name: String,
    hash: String,
}
fn decode_transaction(record: &TransactionRecord) -> Result<SignedTransaction> {
    let bytes = hex::decode(&record.norito_hex).wrap_err("decode retained signed transaction")?;
    let transaction = SignedTransaction::decode_all_versioned(&bytes)
        .wrap_err("decode canonical signed transaction")?;
    transaction
        .verify_signature()
        .wrap_err("verify retained transaction signature")?;
    if transaction.hash().to_string() != record.hash || transaction.encode_versioned() != bytes {
        return Err(eyre!(
            "retained transaction bytes or hash are not canonical"
        ));
    }
    Ok(transaction)
}

fn verify_completed_record<T: DeploymentTransport>(
    record: &PlanRecord,
    journal: &Journal,
    transport: &T,
) -> DeploymentResult<Option<DeploymentReceipt>> {
    let Some(receipt) = retained_receipt(record, journal).map_err(DeploymentError::Journal)? else {
        return Ok(None);
    };
    let last = record
        .transactions
        .last()
        .ok_or_else(|| DeploymentError::InvalidRequest("empty deployment plan".to_owned()))?;
    let transaction = decode_transaction(last).map_err(DeploymentError::Journal)?;
    let actual = transport
        .wait(transaction.hash())
        .map_err(|source| DeploymentError::Pending {
            step: last.name.clone(),
            hash: last.hash.clone(),
            source,
        })?;
    validate_applied(transaction.hash(), &actual).map_err(DeploymentError::Readback)?;
    if !actual.same_finality(&receipt.commit) {
        return Err(DeploymentError::Readback(eyre!(
            "retained completion disagrees with current exact-hash Applied evidence"
        )));
    }
    Ok(Some(receipt))
}

fn retained_receipt(record: &PlanRecord, journal: &Journal) -> Result<Option<DeploymentReceipt>> {
    if !journal.exists(RECEIPT_FILE_NAME)? {
        return Ok(None);
    }
    if journal.exists("cancelled.json")? {
        return Err(eyre!(
            "finalized receipt conflicts with retained local cancellation"
        ));
    }
    let receipt: DeploymentReceipt = journal.read(RECEIPT_FILE_NAME)?;
    let context = &record.preflight;
    if receipt.version != 1
        || receipt.network_id != context.network_id
        || receipt.chain_id != context.chain_id
        || receipt.chain_discriminant != context.chain_discriminant
        || receipt.authority != context.authority
        || receipt.contract_alias != context.contract_alias
        || receipt.contract_address != context.contract_address
        || receipt.contract_subject_account != context.contract_address.subject_id()
        || receipt.dataspace_id != context.dataspace_id
        || receipt.code_hash != context.code_hash
        || receipt.abi_hash != context.abi_hash
        || !receipt.stored_artifact_matches
        || receipt.stages.len() != record.transactions.len()
        || receipt.readback_block_height < receipt.commit.block_height
        || Hash::from_str(&receipt.readback_block_hash)?.to_string() != receipt.readback_block_hash
    {
        return Err(eyre!(
            "finalized receipt disagrees with its exact signed deployment plan"
        ));
    }
    for (index, (step, evidence)) in record.transactions.iter().zip(&receipt.stages).enumerate() {
        if journal.exists(&format!("failed-{index:04}.json"))? {
            return Err(eyre!(
                "finalized receipt conflicts with retained terminal failure evidence"
            ));
        }
        let signed = decode_transaction(step)?;
        validate_applied(signed.hash(), evidence)?;
        let attempted: TransactionAttempt = journal.read(&format!("attempt-{index:04}.json"))?;
        let retained: AppliedEvidence = journal.read(&format!("applied-{index:04}.json"))?;
        if attempted.hash != step.hash || attempted.name != step.name || retained != *evidence {
            return Err(eyre!(
                "receipt stage disagrees with durable attempted/Applied evidence"
            ));
        }
    }
    if receipt.stages.last() != Some(&receipt.commit) {
        return Err(eyre!(
            "receipt commit is not its final native deployment stage"
        ));
    }
    Ok(Some(receipt))
}

#[cfg(test)]
mod service_tests;
