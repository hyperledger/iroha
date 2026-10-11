//! Deterministic KAGEMUSHA ledger orchestration (§6).
//!
//! Native proof verification is a mandatory injected dependency. Model validation alone never
//! authorizes a transfer. The transaction owner atomically persists transfers and permanent
//! replay indexes. Normal block finality authenticates each retained load receipt.
// TODO(G3/G6): qualify the complete producer catalog and online/offline flow.
// The ledger verifier mounts only the immutable authenticated World installation.

use iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1;
use iroha_data_model::{account::AccountId, asset::AssetBalanceScope, kagemusha::*};
use norito::{Decode, Encode};

pub(crate) mod artifacts;
mod committed;
pub(crate) mod custody;
pub mod enrollment_issuer;
pub mod enrollment_journal;
pub(crate) mod event_evidence;
pub use committed::{CommittedLoadEventEvidenceV1, CommittedLoadReceipts};
pub use event_evidence::KagemushaLoadEventPathV1;
mod ledger;
pub(crate) mod routing;
mod storage;
pub(crate) mod wsv;
pub use ledger::{abandon, activate, close_loads, issue_load, pay_fee, pay_unload};
pub(crate) use storage::validate_snapshot;
pub use storage::{CredentialRecord, validate_row};
#[cfg(test)]
mod tests;

/// Canonical 32-byte identity used by this protocol.
pub type Digest = [u8; 32];
/// Deterministic ledger failure; no failure authorizes a partial payout.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Preserve the canonical asset owner's exact execution or local-deferral failure.
    #[error(transparent)]
    Execution(#[from] iroha_data_model::isi::error::InstructionExecutionError),
    /// Invalid canonical model object or signature.
    #[error(transparent)]
    Model(#[from] KagemushaWalletValidationErrorV1),
    /// The mandatory proof verifier rejected the complete package.
    #[error("native package proof rejected")]
    Proof,
    /// The authenticated artifact set is unavailable.
    #[error("native proof artifacts unavailable")]
    ArtifactsUnavailable,
    /// A scheme, asset, account, or retained source binding differs.
    #[error("ledger source binding differs")]
    Binding,
    /// The permanent key already records a different operation.
    #[error("permanent replay key conflicts")]
    Conflict,
    /// The wallet has not been activated or is permanently closed/abandoned.
    #[error("wallet does not permit this operation")]
    Lifecycle,
    /// Issued receipts have not all been absorbed before closing loads.
    #[error("unabsorbed load receipt")]
    OutstandingLoad,
    /// Arithmetic exceeded the fixed monetary or ordinal range.
    #[error("ledger amount or ordinal overflow")]
    Overflow,
    /// Missing historical ledger record or unavailable storage.
    #[error("ledger record unavailable")]
    Unavailable,
    /// The requested receipt lacks a consistent committed execution source.
    #[error("load receipt has no committed source")]
    NotCommitted,
    /// Ledger accounts cannot fund the whole atomic transfer batch.
    #[error("insufficient ledger balance")]
    InsufficientFunds,
}
/// Result of a deterministic ledger operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A complete native verifier, bound to the scheme's authenticated relation descriptors.
/// Implementations must verify σ, its receipt binding and the required predecessor Ω with the
/// production proof engine. There is deliberately no default or structural-only implementation.
pub trait NativePackageVerifier {
    /// Verify the complete package for this exact credential and scheme.
    ///
    /// # Errors
    /// Return `ArtifactsUnavailable` when no authenticated artifact set can be loaded, and
    /// `Proof` on any invalid or unverified proof. Never translate either into success.
    fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        credential: &KagemushaWalletCredentialV1,
        package: &KagemushaWalletPackageV1,
    ) -> Result<()>;
}

/// Ledger-owned scheme/asset registration; caller supplied registrations are not authority.
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::Registration")]
pub struct Registration {
    /// Scheme root and relation identity recorded by ledger governance.
    pub scheme: KagemushaWalletSchemeV1,
    /// Current asset incarnation and scale from the asset registry.
    pub asset: KagemushaWalletAssetScopeV1,
    /// Segregated reserve account for this scheme and asset.
    pub reserve: AccountId,
    /// Exact balance partition; never inferred from mutable account routing.
    pub balance_scope: AssetBalanceScope,
}
impl Registration {
    fn require(&self, scheme: &Digest, asset: &Digest) -> Result<()> {
        self.scheme.validate()?;
        self.asset.validate()?;
        if self.scheme.scheme_id() != *scheme || self.asset.asset_digest() != *asset {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// Permanent ledger lifecycle; closure or abandonment can never reactivate an incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::Phase")]
pub enum Phase {
    /// Bootstrap accepted, load issuance permitted.
    Active,
    /// Retiring package closed further issuance.
    Closed,
    /// Unused enrollment was irreversibly abandoned.
    Abandoned,
}
/// Constant-size wallet index. It does not retain or scan the receipt history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::WalletRecord")]
pub struct WalletRecord {
    /// Immutable asset binding.
    pub asset: Digest,
    /// Lifecycle.
    pub phase: Phase,
    /// Accepted Bootstrap package digest, or zero after abandonment.
    pub activation: Digest,
    /// First ordinal not issued by the ledger.
    pub next_load: u128,
}
/// Load command identity and pricing; `request_id` identifies the original receipt for recovery.
/// Reusing it in another transaction fails rather than issuing a second successful receipt.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::LoadCommand")]
pub struct LoadCommand {
    /// Scheme registration identity.
    pub scheme: Digest,
    /// Wallet incarnation.
    pub wallet: Digest,
    /// Exact registered asset incarnation committed by the payer's transaction.
    pub asset: Digest,
    /// Expected next ordinal; successful execution authenticates this exact value.
    pub ordinal: u128,
    /// Nonzero client retry identity, scoped by wallet.
    pub request_id: Digest,
    /// Net value deposited in the reserve.
    pub amount: u128,
    /// Explicit signed online charge, separate from the reserve deposit.
    pub charge: Option<LoadCharge>,
}
/// Ledger-recorded signed load quote and fixed beneficiary.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::LoadCharge")]
pub struct LoadCharge {
    /// Displayed quote accepted by the payer.
    pub quote: KagemushaWalletChargeQuoteV1,
    /// Account matching the quote's beneficiary digest.
    pub beneficiary: AccountId,
}
/// Durable load issuance: debit, ordinal and unsigned body are one atomic ledger transition.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::Issuance")]
pub struct Issuance {
    /// Original command used for exact semantic retry comparison.
    pub command: LoadCommand,
    /// Authenticated transaction authority whose account funded the deposit.
    pub payer: AccountId,
    /// Exact normal-transaction receipt; its fields alone do not establish finality.
    pub body: KagemushaWalletLoadReceiptV1,
}
/// One transfer of atomic asset units; reserve movements use the registered asset scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Debited account.
    pub from: AccountId,
    /// Credited account.
    pub to: AccountId,
    /// Exact positive amount.
    pub amount: u128,
}
/// Atomic mutation produced only after verification and all deterministic checks.
#[derive(Debug)]
pub struct Batch {
    /// Scheme whose segregated reserve and permanent indexes are affected.
    scheme: Digest,
    /// Immutable asset scope of every transfer and source binding.
    asset: Digest,
    /// Wallet index replacement, if any.
    wallet: Option<(Digest, WalletRecord)>,
    /// Unique immutable issuance insertion, if any.
    issuance: Option<Issuance>,
    /// Exact-once payout insertion, if any.
    payout: Option<KagemushaWalletPayoutRecordV1>,
    /// Transfers that commit in the same transaction as all indexes.
    transfers: Vec<Transfer>,
}
impl Batch {
    fn new(scheme: Digest, asset: Digest) -> Self {
        Self {
            scheme,
            asset,
            wallet: None,
            issuance: None,
            payout: None,
            transfers: Vec::new(),
        }
    }
}
/// Historical inputs retrieved by digest from immutable ledger records for a fee claim.
pub struct FeeInputs {
    /// Original full Request, including the historical fee schedule and certificates.
    pub request: KagemushaWalletRequestV1,
    /// Credential named by the Payment's payer credential digest.
    pub payer: KagemushaWalletCredentialV1,
    /// Historical certificates validating that credential.
    pub certificates: KagemushaWalletCertificateSetV1,
}
/// Single WSV instruction transaction. Reads and `apply` must share an isolated snapshot.
/// `apply` must commit every transfer/index together or none, enforce account authorization,
/// compare insert-only replay keys, and never turn unavailable data into absence.
/// Its authority/hash/height are derived from authenticated execution, not payload fields.
pub trait Transaction {
    /// Authenticated transaction authority.
    fn authority(&self) -> &AccountId;
    /// Hash of the transaction currently executing.
    fn transaction_hash(&self) -> Digest;
    /// Height of the executing block, later independently checked for finality.
    fn block_height(&self) -> u64;
    /// Read registered scheme and current asset scope.
    fn registration(&self, scheme: &Digest, asset: &Digest) -> Result<Registration>;
    /// Read the permanent wallet lifecycle and next load ordinal.
    fn wallet(&self, scheme: &Digest, wallet: &Digest) -> Result<Option<WalletRecord>>;
    /// Read a retained load by its client retry identity.
    fn issuance(
        &self,
        scheme: &Digest,
        wallet: &Digest,
        request: &Digest,
    ) -> Result<Option<Issuance>>;
    /// Read the original exact-once payout.
    fn payout(
        &self,
        scheme: &Digest,
        key: KagemushaWalletPayoutKeyV1,
    ) -> Result<Option<KagemushaWalletPayoutRecordV1>>;
    /// Read an immutable signer certificate by its object digest.
    fn certificate(
        &self,
        scheme: &Digest,
        digest: &Digest,
    ) -> Result<KagemushaWalletSignerCertificateV1>;
    /// Resolve all historical inputs named by this Payment from ledger records.
    fn fee_inputs(&self, claim: &KagemushaWalletFeeClaimV1) -> Result<FeeInputs>;
    /// Commit the entire verified batch, or leave the transaction unchanged.
    fn apply(&mut self, batch: Batch) -> Result<()>;
}
