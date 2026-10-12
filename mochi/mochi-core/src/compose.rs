//! Transaction composition helpers for the MOCHI UI.
//!
//! The composer utilities provide lightweight building blocks for transaction previews so front
//! ends can offer form-based instruction builders without pulling additional crates.
use iroha_crypto::KeyPair;
use iroha_data_model::{
    NetworkId,
    account::{
        Account, AccountAdmissionMode, AccountAdmissionPolicy, AccountId,
        admission::ImplicitAccountFeeDestination,
    },
    asset::{
        definition::{AssetDefinition, Mintable, NewAssetDefinition, validate_asset_name},
        id::{AssetDefinitionId, AssetId},
    },
    isi::{
        Burn, Grant, InstructionBox, Mint, Register, Revoke, SetParameter, Transfer,
        sorafs::RegisterPinManifest, space_directory::PublishSpaceDirectoryManifest,
    },
    nexus::AssetPermissionManifest,
    parameter::Parameter,
    role::RoleId,
    transaction::{Executable, ExecutableBatchItem, SignedTransaction, TransactionBuilder},
};
use iroha_executor_data_model::isi::multisig::{MultisigProposalNonce, MultisigPropose};
use iroha_primitives::numeric::Quantity;
#[cfg(any(test, feature = "test"))]
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};
use iroha_version::codec::EncodeVersioned;
use norito::json::{self, Map, Value};
use std::{
    collections::BTreeSet,
    fmt,
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
    time::Duration,
};

const RAW_DRAFT_JSON_MAX_BYTES_V1: usize = 256 * 1024;
const RAW_DRAFT_JSON_MAX_NESTING_V1: usize = 32;
const DRAFT_ARRAY_MAX_ITEMS_V1: usize = 128;
const DRAFT_TOTAL_MAX_ITEMS_V1: usize = 512;
const MULTISIG_DRAFT_MAX_DEPTH_V1: usize = 8;
/// Permission categories used to gate high-level instruction templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstructionPermission {
    /// Mint numeric assets.
    MintAsset,
    /// Burn numeric assets.
    BurnAsset,
    /// Transfer numeric assets between accounts.
    TransferAsset,
    /// Register new accounts.
    RegisterAccount,
    /// Register new asset definitions.
    RegisterAssetDefinition,
    /// Publish Space Directory manifests (AXT/AMX policies).
    PublishSpaceDirectoryManifest,
    /// Register SoraFS pin manifests (DA pin intents).
    RegisterPinManifest,
    /// Grant roles to accounts.
    GrantRole,
    /// Revoke roles from accounts.
    RevokeRole,
    /// Propose multisig transactions.
    MultisigPropose,
    /// Set chain parameters, including Nexus lane lifecycle topology.
    SetParameters,
}
impl InstructionPermission {
    /// Return a static list containing every permission variant.
    #[must_use]
    pub const fn all() -> [Self; 11] {
        [
            Self::MintAsset,
            Self::BurnAsset,
            Self::TransferAsset,
            Self::RegisterAccount,
            Self::RegisterAssetDefinition,
            Self::PublishSpaceDirectoryManifest,
            Self::RegisterPinManifest,
            Self::GrantRole,
            Self::RevokeRole,
            Self::MultisigPropose,
            Self::SetParameters,
        ]
    }
    /// Human-readable label used in error messages and tooltips.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MintAsset => "mint assets",
            Self::BurnAsset => "burn assets",
            Self::TransferAsset => "transfer assets",
            Self::RegisterAccount => "register accounts",
            Self::RegisterAssetDefinition => "register asset definitions",
            Self::PublishSpaceDirectoryManifest => "publish space directory manifests",
            Self::RegisterPinManifest => "register pin manifests",
            Self::GrantRole => "grant roles",
            Self::RevokeRole => "revoke roles",
            Self::MultisigPropose => "propose multisig transactions",
            Self::SetParameters => "set chain parameters",
        }
    }
    /// Stable key used for persistence.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::MintAsset => "mint_asset",
            Self::BurnAsset => "burn_asset",
            Self::TransferAsset => "transfer_asset",
            Self::RegisterAccount => "register_account",
            Self::RegisterAssetDefinition => "register_asset_definition",
            Self::PublishSpaceDirectoryManifest => "publish_space_directory_manifest",
            Self::RegisterPinManifest => "register_pin_manifest",
            Self::GrantRole => "grant_role",
            Self::RevokeRole => "revoke_role",
            Self::MultisigPropose => "multisig_propose",
            Self::SetParameters => "set_parameters",
        }
    }
    /// Convert a persisted key back into an [`InstructionPermission`].
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "mint_asset" => Some(Self::MintAsset),
            "burn_asset" => Some(Self::BurnAsset),
            "transfer_asset" => Some(Self::TransferAsset),
            "register_account" => Some(Self::RegisterAccount),
            "register_asset_definition" => Some(Self::RegisterAssetDefinition),
            "publish_space_directory_manifest" => Some(Self::PublishSpaceDirectoryManifest),
            "register_pin_manifest" => Some(Self::RegisterPinManifest),
            "grant_role" => Some(Self::GrantRole),
            "revoke_role" => Some(Self::RevokeRole),
            "multisig_propose" => Some(Self::MultisigPropose),
            "set_parameters" => Some(Self::SetParameters),
            _ => None,
        }
    }
}
impl fmt::Display for InstructionPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
/// Errors that can occur while preparing transaction previews.
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// The provided asset identifier could not be parsed.
    #[error("failed to parse asset id `{asset}`: {reason}")]
    InvalidAssetId {
        /// String representation of the asset identifier that failed to parse.
        asset: String,
        /// Human readable failure reason.
        reason: String,
    },
    /// The provided account identifier could not be parsed.
    #[error("failed to parse account id `{account}`: {reason}")]
    InvalidAccountId {
        /// String representation of the account identifier that failed to parse.
        account: String,
        /// Human readable failure reason.
        reason: String,
    },
    /// The provided numeric quantity could not be parsed or was invalid.
    #[error("failed to parse quantity `{quantity}`: {reason}")]
    InvalidQuantity {
        /// Text entered by the user.
        quantity: String,
        /// Human readable failure reason.
        reason: String,
    },
    /// The provided asset definition identifier could not be parsed.
    #[error("failed to parse asset definition id `{definition}`: {reason}")]
    InvalidAssetDefinitionId {
        /// String representation of the asset definition identifier that failed to parse.
        definition: String,
        /// Human readable failure reason.
        reason: String,
    },
    /// The provided human-readable asset definition name was invalid.
    #[error("invalid asset definition name `{name}`: {reason}")]
    InvalidAssetDefinitionName {
        /// Human-readable name that failed validation.
        name: String,
        /// Human readable failure reason.
        reason: String,
    },
    /// The provided role identifier could not be parsed.
    #[error("failed to parse role id `{role}`: {reason}")]
    InvalidRoleId {
        /// String representation of the role identifier that failed to parse.
        role: String,
        /// Human readable failure reason.
        reason: String,
    },
    /// Raw draft payload contained invalid structure or values.
    #[error("invalid raw instruction draft: {reason}")]
    InvalidRawDraft {
        /// Human readable failure reason.
        reason: String,
    },
    /// No instructions supplied when attempting to compose a transaction.
    #[error("cannot build preview with an empty instruction list")]
    EmptyInstructions,
    /// Selected signing authority lacks permission for the requested instruction.
    #[error("{signer} cannot {action}")]
    UnauthorizedInstruction {
        /// Label of the signing authority.
        signer: String,
        /// Action that was denied.
        action: InstructionPermission,
    },
    /// Transaction signing failed.
    #[error("failed to sign composed transaction: {reason}")]
    Signing {
        /// Human readable failure reason.
        reason: String,
    },
}
/// Named signing authority used to author transactions in local workflows.
#[derive(Debug, Clone)]
pub struct SigningAuthority {
    label: String,
    account: AccountId,
    key_pair: KeyPair,
    allowed: BTreeSet<InstructionPermission>,
    roles: BTreeSet<RoleId>,
}
impl SigningAuthority {
    /// Create a new signing authority entry.
    #[must_use]
    pub fn new(label: impl Into<String>, account: AccountId, key_pair: KeyPair) -> Self {
        Self::with_permissions(label, account, key_pair, InstructionPermission::all())
    }
    /// Create a signing authority with an explicit permission set.
    #[must_use]
    pub fn with_permissions(
        label: impl Into<String>,
        account: AccountId,
        key_pair: KeyPair,
        permissions: impl IntoIterator<Item = InstructionPermission>,
    ) -> Self {
        Self {
            label: label.into(),
            account,
            key_pair,
            allowed: permissions.into_iter().collect(),
            roles: BTreeSet::new(),
        }
    }
    /// Create a signing authority with explicit permissions and roles.
    #[must_use]
    pub fn with_permissions_and_roles(
        label: impl Into<String>,
        account: AccountId,
        key_pair: KeyPair,
        permissions: impl IntoIterator<Item = InstructionPermission>,
        roles: impl IntoIterator<Item = RoleId>,
    ) -> Self {
        Self {
            label: label.into(),
            account,
            key_pair,
            allowed: permissions.into_iter().collect(),
            roles: roles.into_iter().collect(),
        }
    }
    /// Human-readable label suitable for UI selectors.
    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }
    /// Account identifier that will act as the transaction authority.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }
    /// Key pair used for signing.
    #[must_use]
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
    /// Iterator over permission categories allowed for this authority.
    pub fn permissions(&self) -> impl Iterator<Item = InstructionPermission> + '_ {
        self.allowed.iter().copied()
    }
    /// Iterator over configured role identifiers for this authority.
    pub fn roles(&self) -> impl Iterator<Item = &RoleId> + '_ {
        self.roles.iter()
    }
    /// Check whether the authority may execute the provided permission.
    #[must_use]
    pub fn allows_permission(&self, permission: InstructionPermission) -> bool {
        self.allowed.contains(&permission)
    }
    /// Ensure that every draft in the provided slice is authorised for this signer.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::UnauthorizedInstruction`] when a draft requires a
    /// permission the signer does not possess.
    pub fn validate_drafts(&self, drafts: &[InstructionDraft]) -> Result<(), ComposeError> {
        if let Some(denied) = drafts
            .iter()
            .find(|draft| !self.allows_permission(draft.permission()))
        {
            return Err(ComposeError::UnauthorizedInstruction {
                signer: self.label.clone(),
                action: denied.permission(),
            });
        }
        Ok(())
    }
}
#[cfg(any(test, feature = "test"))]
static DEVELOPMENT_AUTHORITIES: std::sync::LazyLock<Vec<SigningAuthority>> =
    std::sync::LazyLock::new(|| {
        let all_permissions = InstructionPermission::all();
        vec![
            SigningAuthority::with_permissions(
                "Alice (dev)",
                ALICE_ID.clone(),
                ALICE_KEYPAIR.clone(),
                all_permissions.into_iter(),
            ),
            SigningAuthority::with_permissions(
                "Bob (dev)",
                BOB_ID.clone(),
                BOB_KEYPAIR.clone(),
                [InstructionPermission::TransferAsset].into_iter(),
            ),
        ]
    });
/// Deterministic mock authorities for tests; managed networks always generate their own keys.
#[cfg(any(test, feature = "test"))]
#[must_use]
pub fn development_signing_authorities() -> &'static [SigningAuthority] {
    DEVELOPMENT_AUTHORITIES.as_slice()
}
/// Optional overrides applied when composing transactions.
#[derive(Debug, Clone, Copy)]
pub struct TransactionComposeOptions {
    ttl: Option<Duration>,
    creation_time: Option<Duration>,
    nonce: Option<NonZeroU32>,
}
impl TransactionComposeOptions {
    /// Create a new options struct with no overrides.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ttl: None,
            creation_time: None,
            nonce: None,
        }
    }
    /// Override the time-to-live field using the supplied duration.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }
    /// Freeze the creation time to a specific timestamp.
    #[must_use]
    pub fn with_creation_time(mut self, creation_time: Duration) -> Self {
        self.creation_time = Some(creation_time);
        self
    }
    /// Override the nonce recorded in the transaction payload.
    #[must_use]
    pub fn with_nonce(mut self, nonce: NonZeroU32) -> Self {
        self.nonce = Some(nonce);
        self
    }
    /// Access the configured TTL override, if any.
    #[must_use]
    pub const fn ttl(&self) -> Option<Duration> {
        self.ttl
    }
    /// Access the configured creation timestamp override, if any.
    #[must_use]
    pub const fn creation_time(&self) -> Option<Duration> {
        self.creation_time
    }
    /// Access the configured nonce override, if any.
    #[must_use]
    pub const fn nonce(&self) -> Option<NonZeroU32> {
        self.nonce
    }
}
impl Default for TransactionComposeOptions {
    fn default() -> Self {
        Self::new()
    }
}
/// Lightweight summary of a composed transaction ready for preview or submission.
#[derive(Debug, Clone)]
pub struct TransactionPreview {
    signed: SignedTransaction,
    encoded_hex: String,
    instructions: Vec<String>,
    hash: String,
    authority: String,
}
impl TransactionPreview {
    /// Canonical transaction hash derived from the signed payload.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }
    /// Hex-encoded Norito payload suitable for Torii submission.
    #[must_use]
    pub fn encoded_hex(&self) -> &str {
        &self.encoded_hex
    }
    /// Versioned Norito payload bytes ready to POST to `/v1/pipeline/transactions`.
    #[must_use]
    pub fn encoded_bytes(&self) -> Vec<u8> {
        self.signed.encode_versioned()
    }
    /// Human-readable list of instruction descriptions contained in the transaction.
    #[must_use]
    pub fn instructions(&self) -> &[String] {
        &self.instructions
    }
    /// Authority account recorded in the transaction payload.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }
    /// Access the underlying signed transaction for advanced consumers.
    #[must_use]
    pub fn signed_transaction(&self) -> &SignedTransaction {
        &self.signed
    }
    /// Time-to-live override expressed as a duration, if present.
    #[must_use]
    pub fn time_to_live(&self) -> Option<Duration> {
        self.signed.time_to_live()
    }
    /// Creation timestamp attached to the transaction payload.
    #[must_use]
    pub fn creation_time(&self) -> Duration {
        self.signed.creation_time()
    }
    /// Nonce recorded in the payload, if supplied.
    #[must_use]
    pub fn nonce(&self) -> Option<NonZeroU32> {
        self.signed.nonce()
    }
}
impl TransactionPreview {
    fn new(signed: SignedTransaction) -> Self {
        let encoded_hex = encode_hex(&signed.encode_versioned());
        let hash = signed.hash().to_string();
        let authority = account_literal(signed.authority());
        let instructions = match signed.instructions() {
            Executable::Instructions(list) => list.iter().map(|instr| format!("{instr}")).collect(),
            Executable::ContractCall(call) => vec![format!(
                "Contract call {}::{}",
                call.contract_address, call.entrypoint
            )],
            Executable::IvmProved(proved) => proved
                .overlay
                .iter()
                .map(|instr| format!("{instr}"))
                .collect(),
            Executable::Ivm(_) => vec!["IVM bytecode executable".to_owned()],
            Executable::Batch(items) => items
                .iter()
                .map(|item| match item {
                    ExecutableBatchItem::Instruction(instruction) => format!("{instruction}"),
                    ExecutableBatchItem::ContractCall(call) => format!(
                        "Contract call {}::{}",
                        call.contract_address, call.entrypoint
                    ),
                })
                .collect(),
        };
        Self {
            signed,
            encoded_hex,
            instructions,
            hash,
            authority,
        }
    }
}
/// Compose an exact-network preview while applying the supplied [`TransactionComposeOptions`].
///
/// # Errors
///
/// Returns [`ComposeError::EmptyInstructions`] when the provided slice is empty.
pub fn compose_preview_with_options(
    network_id: NetworkId,
    drafts: &[InstructionDraft],
    authority: &SigningAuthority,
    options: &TransactionComposeOptions,
) -> Result<TransactionPreview, ComposeError> {
    if drafts.is_empty() {
        return Err(ComposeError::EmptyInstructions);
    }
    authority.validate_drafts(drafts)?;
    let instructions = drafts
        .iter()
        .map(InstructionDraft::instruction)
        .collect::<Vec<_>>();
    let mut builder = TransactionBuilder::new(
        network_id,
        authority.account_id().clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions);
    if let Some(creation_time) = options.creation_time() {
        builder.set_creation_time(creation_time);
    }
    if let Some(ttl) = options.ttl() {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = options.nonce() {
        builder.set_nonce(nonce);
    }
    let signed = builder
        .try_sign(authority.key_pair().private_key())
        .map_err(|err| ComposeError::Signing {
            reason: err.to_string(),
        })?;
    Ok(TransactionPreview::new(signed))
}
/// Declarative specification for a high-level instruction created in the UI.
#[derive(Debug, Clone)]
pub enum InstructionDraft {
    /// Mint a numeric quantity of the specified asset.
    MintAsset {
        /// Identifier of the asset being minted.
        asset: AssetId,
        /// Positive numeric quantity to mint.
        quantity: Quantity,
    },
    /// Burn a numeric quantity of the specified asset.
    BurnAsset {
        /// Identifier of the asset being burned.
        asset: AssetId,
        /// Quantity to burn.
        quantity: Quantity,
    },
    /// Transfer a numeric asset between accounts.
    TransferAsset {
        /// Identifier of the asset (including source account) to transfer.
        asset: AssetId,
        /// Quantity to transfer.
        quantity: Quantity,
        /// Destination account receiving the asset.
        destination: AccountId,
    },
    /// Register a new account.
    RegisterAccount {
        /// Identifier of the account to register.
        account: AccountId,
    },
    /// Register a numeric asset definition.
    RegisterAssetDefinition {
        /// Identifier of the asset definition.
        definition: AssetDefinitionId,
        /// Human-readable name of the asset definition.
        name: String,
        /// Mintability policy for the asset.
        mintable: Mintable,
    },
    /// Publish a Space Directory manifest for AXT/AMX policies.
    PublishSpaceDirectoryManifest {
        /// Manifest payload to publish.
        manifest: AssetPermissionManifest,
    },
    /// Register a SoraFS pin manifest (DA pin intent).
    RegisterPinManifest {
        /// Pin manifest registration payload.
        request: RegisterPinManifest,
    },
    /// Set the chain-global account admission policy.
    SetAccountAdmissionPolicy {
        /// Policy configuration payload.
        policy: AccountAdmissionPolicy,
    },
    /// Grant a role to an account.
    GrantRole {
        /// Identifier of the role to grant.
        role: RoleId,
        /// Target account receiving the role.
        account: AccountId,
    },
    /// Revoke a role from an account.
    RevokeRole {
        /// Identifier of the role to revoke.
        role: RoleId,
        /// Target account losing the role.
        account: AccountId,
    },
    /// Propose a multisig transaction for a multisig account.
    MultisigPropose {
        /// Explicit occurrence nonce retained by the draft across retries.
        proposal_nonce: MultisigProposalNonce,
        /// Multisig account issuing the proposal.
        account: AccountId,
        /// Instruction drafts to include in the proposal.
        instructions: Vec<InstructionDraft>,
        /// Optional TTL override in milliseconds for the proposal.
        transaction_ttl_ms: Option<NonZeroU64>,
    },
}
impl InstructionDraft {
    /// Create a mint draft by parsing textual inputs collected from the UI.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if any field fails to parse.
    pub fn mint_from_input(asset: &str, quantity: &str) -> Result<Self, ComposeError> {
        let asset = parse_asset_id(asset)?;
        let quantity = parse_quantity(quantity)?;
        Ok(Self::MintAsset { asset, quantity })
    }
    /// Create a burn draft by parsing textual inputs collected from the UI.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if any field fails to parse.
    pub fn burn_from_input(asset: &str, quantity: &str) -> Result<Self, ComposeError> {
        let asset = parse_asset_id(asset)?;
        let quantity = parse_quantity(quantity)?;
        Ok(Self::BurnAsset { asset, quantity })
    }
    /// Create a transfer draft by parsing textual inputs collected from the UI.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if any field fails to parse.
    pub fn transfer_from_input(
        asset: &str,
        quantity: &str,
        destination: &str,
    ) -> Result<Self, ComposeError> {
        let asset = parse_asset_id(asset)?;
        let quantity = parse_quantity(quantity)?;
        let destination = parse_account_id(destination)?;
        Ok(Self::TransferAsset {
            asset,
            quantity,
            destination,
        })
    }
    /// Create an account registration draft by parsing textual inputs.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if the account identifier fails to parse.
    pub fn register_account_from_input(account: &str) -> Result<Self, ComposeError> {
        let account = parse_account_id(account)?;
        Ok(Self::RegisterAccount { account })
    }
    /// Create an asset definition registration draft from textual inputs.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if any field fails to parse.
    pub fn register_asset_definition_from_input(
        definition: &str,
        name: &str,
        mintable: Mintable,
    ) -> Result<Self, ComposeError> {
        let definition = parse_asset_definition_id(definition)?;
        if name.trim() != name {
            return Err(ComposeError::InvalidAssetDefinitionName {
                name: name.to_owned(),
                reason: "asset definition name must not contain surrounding whitespace".to_owned(),
            });
        }
        validate_asset_name(name).map_err(|err| ComposeError::InvalidAssetDefinitionName {
            name: name.to_owned(),
            reason: err.to_string(),
        })?;
        Ok(Self::RegisterAssetDefinition {
            definition,
            name: name.to_owned(),
            mintable,
        })
    }
    /// Create a Space Directory manifest publication draft from JSON input.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if the manifest payload fails to decode.
    pub fn publish_space_directory_manifest_from_json(
        manifest_json: &str,
    ) -> Result<Self, ComposeError> {
        validate_raw_json_input(manifest_json)?;
        let value: Value =
            json::from_str(manifest_json).map_err(|err| ComposeError::InvalidRawDraft {
                reason: format!("invalid space directory manifest: {err}"),
            })?;
        let manifest: AssetPermissionManifest =
            json::from_value(value).map_err(|err| ComposeError::InvalidRawDraft {
                reason: format!("invalid space directory manifest: {err}"),
            })?;
        Ok(Self::PublishSpaceDirectoryManifest { manifest })
    }
    /// Create a pin manifest registration draft from JSON input.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if the payload fails to decode.
    pub fn register_pin_manifest_from_json(request_json: &str) -> Result<Self, ComposeError> {
        validate_raw_json_input(request_json)?;
        let value: Value =
            json::from_str(request_json).map_err(|err| ComposeError::InvalidRawDraft {
                reason: format!("invalid pin manifest request: {err}"),
            })?;
        let request = decode_strict_pin_manifest(&value)?;
        Ok(Self::RegisterPinManifest { request })
    }
    /// Create a chain-global account admission policy draft.
    #[must_use]
    pub fn account_admission_policy(policy: AccountAdmissionPolicy) -> Self {
        Self::SetAccountAdmissionPolicy { policy }
    }
    /// Create a grant role draft by parsing textual inputs.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if either identifier fails to parse.
    pub fn grant_role_from_input(role: &str, account: &str) -> Result<Self, ComposeError> {
        let role = parse_role_id(role)?;
        let account = parse_account_id(account)?;
        Ok(Self::GrantRole { role, account })
    }
    /// Create a revoke role draft by parsing textual inputs.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if either identifier fails to parse.
    pub fn revoke_role_from_input(role: &str, account: &str) -> Result<Self, ComposeError> {
        let role = parse_role_id(role)?;
        let account = parse_account_id(account)?;
        Ok(Self::RevokeRole { role, account })
    }
    /// Create a multisig proposal draft from JSON-encoded instruction drafts.
    ///
    /// # Errors
    ///
    /// Returns a [`ComposeError`] if any field fails to parse.
    pub fn multisig_propose_from_json(
        account: &str,
        proposal_nonce: &str,
        instructions_json: &str,
        transaction_ttl_ms: Option<u64>,
    ) -> Result<Self, ComposeError> {
        let account = parse_account_id(account)?;
        let proposal_nonce = proposal_nonce
            .parse::<MultisigProposalNonce>()
            .map_err(|error| ComposeError::InvalidRawDraft {
                reason: format!("invalid proposal_nonce: {error}"),
            })?;
        let instructions = drafts_from_json_str(instructions_json)?;
        if instructions.is_empty() {
            return Err(ComposeError::InvalidRawDraft {
                reason: "multisig proposal instructions must not be empty".to_owned(),
            });
        }
        let transaction_ttl_ms = match transaction_ttl_ms {
            Some(value) => {
                Some(
                    NonZeroU64::new(value).ok_or_else(|| ComposeError::InvalidRawDraft {
                        reason: "multisig transaction TTL must be greater than zero".to_owned(),
                    })?,
                )
            }
            None => None,
        };
        Ok(Self::MultisigPropose {
            account,
            proposal_nonce,
            instructions,
            transaction_ttl_ms,
        })
    }
    /// Permission category associated with this draft.
    #[must_use]
    pub const fn permission(&self) -> InstructionPermission {
        match self {
            InstructionDraft::MintAsset { .. } => InstructionPermission::MintAsset,
            InstructionDraft::BurnAsset { .. } => InstructionPermission::BurnAsset,
            InstructionDraft::TransferAsset { .. } => InstructionPermission::TransferAsset,
            InstructionDraft::RegisterAccount { .. } => InstructionPermission::RegisterAccount,
            InstructionDraft::RegisterAssetDefinition { .. } => {
                InstructionPermission::RegisterAssetDefinition
            }
            InstructionDraft::PublishSpaceDirectoryManifest { .. } => {
                InstructionPermission::PublishSpaceDirectoryManifest
            }
            InstructionDraft::RegisterPinManifest { .. } => {
                InstructionPermission::RegisterPinManifest
            }
            InstructionDraft::SetAccountAdmissionPolicy { .. } => {
                InstructionPermission::SetParameters
            }
            InstructionDraft::GrantRole { .. } => InstructionPermission::GrantRole,
            InstructionDraft::RevokeRole { .. } => InstructionPermission::RevokeRole,
            InstructionDraft::MultisigPropose { .. } => InstructionPermission::MultisigPropose,
        }
    }
    /// Produce a human-readable summary suitable for list views.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            InstructionDraft::MintAsset { asset, quantity } => {
                format!("Mint {quantity} to {asset}")
            }
            InstructionDraft::BurnAsset { asset, quantity } => {
                format!("Burn {quantity} from {asset}")
            }
            InstructionDraft::TransferAsset {
                asset,
                quantity,
                destination,
            } => format!("Transfer {quantity} from {asset} to {destination}"),
            InstructionDraft::RegisterAccount { account } => {
                format!("Register account {account}")
            }
            InstructionDraft::RegisterAssetDefinition {
                definition,
                name,
                mintable,
            } => format!("Register asset definition {name} [{definition}] ({mintable})"),
            InstructionDraft::PublishSpaceDirectoryManifest { manifest } => format!(
                "Publish Space Directory manifest for {} (dataspace {}, {} entr{})",
                manifest.uaid,
                manifest.dataspace,
                manifest.entries.len(),
                if manifest.entries.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ),
            InstructionDraft::RegisterPinManifest { request } => {
                format!(
                    "Register pin manifest ({} payload bytes)",
                    request.manifest_payload.len()
                )
            }
            InstructionDraft::SetAccountAdmissionPolicy { policy } => format!(
                "Set chain-global account admission policy ({})",
                format_admission_policy_summary(policy)
            ),
            InstructionDraft::GrantRole { role, account } => {
                format!("Grant role {role} to {account}")
            }
            InstructionDraft::RevokeRole { role, account } => {
                format!("Revoke role {role} from {account}")
            }
            InstructionDraft::MultisigPropose {
                account,
                instructions,
                ..
            } => format!(
                "Propose multisig transaction for {account} ({} instruction{})",
                instructions.len(),
                if instructions.len() == 1 { "" } else { "s" }
            ),
        }
    }
    fn instruction(&self) -> InstructionBox {
        match self {
            InstructionDraft::MintAsset { asset, quantity } => {
                Mint::asset_quantity(quantity.clone(), asset.clone()).into()
            }
            InstructionDraft::BurnAsset { asset, quantity } => {
                Burn::asset_quantity(quantity.clone(), asset.clone()).into()
            }
            InstructionDraft::TransferAsset {
                asset,
                quantity,
                destination,
            } => Transfer::asset_quantity(asset.clone(), quantity.clone(), destination.clone())
                .into(),
            InstructionDraft::RegisterAccount { account } => {
                Register::account(Account::new(account.clone())).into()
            }
            InstructionDraft::RegisterAssetDefinition {
                definition,
                name,
                mintable,
            } => {
                let builder = apply_mintable(
                    AssetDefinition::numeric(
                        definition.clone(),
                        name.clone(),
                        iroha_data_model::asset::AssetBalancePolicy::Global,
                        None,
                    ),
                    *mintable,
                );
                Register::asset_definition(builder).into()
            }
            InstructionDraft::PublishSpaceDirectoryManifest { manifest } => {
                InstructionBox::from(PublishSpaceDirectoryManifest {
                    manifest: manifest.clone(),
                })
            }
            InstructionDraft::RegisterPinManifest { request } => {
                InstructionBox::from(request.clone())
            }
            InstructionDraft::SetAccountAdmissionPolicy { policy } => {
                SetParameter::new(Parameter::Custom(policy.clone().into_custom_parameter())).into()
            }
            InstructionDraft::GrantRole { role, account } => {
                Grant::account_role(role.clone(), account.clone()).into()
            }
            InstructionDraft::RevokeRole { role, account } => {
                Revoke::account_role(role.clone(), account.clone()).into()
            }
            InstructionDraft::MultisigPropose {
                account,
                proposal_nonce,
                instructions,
                transaction_ttl_ms,
            } => {
                let payload = instructions
                    .iter()
                    .map(InstructionDraft::instruction)
                    .collect::<Vec<_>>();
                InstructionBox::from(MultisigPropose::new(
                    account.clone(),
                    *proposal_nonce,
                    payload,
                    *transaction_ttl_ms,
                ))
            }
        }
    }
    /// Convert the draft into a JSON object suitable for the raw editor.
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        let mut object = Map::new();
        match self {
            InstructionDraft::MintAsset { asset, quantity } => {
                object.insert("kind".to_owned(), Value::String("mint_asset".to_owned()));
                object.insert("asset".to_owned(), Value::String(asset_literal(asset)));
                object.insert("quantity".to_owned(), Value::String(quantity.to_string()));
            }
            InstructionDraft::BurnAsset { asset, quantity } => {
                object.insert("kind".to_owned(), Value::String("burn_asset".to_owned()));
                object.insert("asset".to_owned(), Value::String(asset_literal(asset)));
                object.insert("quantity".to_owned(), Value::String(quantity.to_string()));
            }
            InstructionDraft::TransferAsset {
                asset,
                quantity,
                destination,
            } => {
                object.insert(
                    "kind".to_owned(),
                    Value::String("transfer_asset".to_owned()),
                );
                object.insert("asset".to_owned(), Value::String(asset_literal(asset)));
                object.insert("quantity".to_owned(), Value::String(quantity.to_string()));
                object.insert(
                    "destination".to_owned(),
                    Value::String(account_literal(destination)),
                );
            }
            InstructionDraft::RegisterAccount { account } => {
                object.insert(
                    "kind".to_owned(),
                    Value::String("register_account".to_owned()),
                );
                object.insert("account".to_owned(), Value::String(account.to_string()));
            }
            InstructionDraft::RegisterAssetDefinition {
                definition,
                name,
                mintable,
            } => {
                object.insert(
                    "kind".to_owned(),
                    Value::String("register_asset_definition".to_owned()),
                );
                object.insert(
                    "definition".to_owned(),
                    Value::String(definition.to_string()),
                );
                object.insert("name".to_owned(), Value::String(name.clone()));
                object.insert(
                    "mintable".to_owned(),
                    Value::String(format_mintable(*mintable)),
                );
            }
            InstructionDraft::PublishSpaceDirectoryManifest { manifest } => {
                object.insert(
                    "kind".to_owned(),
                    Value::String("publish_space_directory_manifest".to_owned()),
                );
                let value =
                    json::to_value(manifest).expect("space directory manifest should serialize");
                object.insert("manifest".to_owned(), value);
            }
            InstructionDraft::RegisterPinManifest { request } => {
                object.insert(
                    "kind".to_owned(),
                    Value::String("register_pin_manifest".to_owned()),
                );
                let value = json::to_value(request).expect("pin manifest request should serialize");
                object.insert("request".to_owned(), value);
            }
            InstructionDraft::SetAccountAdmissionPolicy { policy } => {
                object.insert(
                    "kind".to_owned(),
                    Value::String("account_admission_policy".to_owned()),
                );
                let value =
                    json::to_value(policy).expect("account admission policy should serialize");
                object.insert("policy".to_owned(), value);
            }
            InstructionDraft::GrantRole { role, account } => {
                object.insert("kind".to_owned(), Value::String("grant_role".to_owned()));
                object.insert("role".to_owned(), Value::String(role.to_string()));
                object.insert(
                    "account".to_owned(),
                    Value::String(account_literal(account)),
                );
            }
            InstructionDraft::RevokeRole { role, account } => {
                object.insert("kind".to_owned(), Value::String("revoke_role".to_owned()));
                object.insert("role".to_owned(), Value::String(role.to_string()));
                object.insert(
                    "account".to_owned(),
                    Value::String(account_literal(account)),
                );
            }
            InstructionDraft::MultisigPropose {
                account,
                proposal_nonce,
                instructions,
                transaction_ttl_ms,
            } => {
                object.insert(
                    "proposal_nonce".to_owned(),
                    Value::String(proposal_nonce.to_string()),
                );
                object.insert(
                    "kind".to_owned(),
                    Value::String("multisig_propose".to_owned()),
                );
                object.insert(
                    "account".to_owned(),
                    Value::String(account_literal(account)),
                );
                object.insert(
                    "instructions".to_owned(),
                    drafts_to_json_value(instructions),
                );
                if let Some(ttl) = transaction_ttl_ms {
                    object.insert("transaction_ttl_ms".to_owned(), Value::from(ttl.get()));
                }
            }
        }
        Value::Object(object)
    }
    /// Construct a draft by parsing a JSON value emitted by [`Self::to_json_value`].
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::InvalidRawDraft`] if the payload is malformed.
    pub fn from_json_value(value: &Value) -> Result<Self, ComposeError> {
        let mut budget = DraftDecodeBudget::default();
        Self::from_json_value_with_budget(value, 0, &mut budget)
    }
    fn from_json_value_with_budget(
        value: &Value,
        multisig_depth: usize,
        budget: &mut DraftDecodeBudget,
    ) -> Result<Self, ComposeError> {
        if multisig_depth > MULTISIG_DRAFT_MAX_DEPTH_V1 {
            return Err(ComposeError::InvalidRawDraft {
                reason: format!(
                    "multisig nesting exceeds the V1 limit of {MULTISIG_DRAFT_MAX_DEPTH_V1}"
                ),
            });
        }
        budget.consume()?;
        let Value::Object(map) = value else {
            return Err(ComposeError::InvalidRawDraft {
                reason: "expected object".to_owned(),
            });
        };
        let kind = extract_string(map, "kind")?;
        match kind.as_str() {
            "mint_asset" => {
                require_draft_fields(map, &kind, &["kind", "asset", "quantity"], &[])?;
                let asset = extract_string(map, "asset")?;
                let quantity = extract_string(map, "quantity")?;
                InstructionDraft::mint_from_input(&asset, &quantity)
            }
            "burn_asset" => {
                require_draft_fields(map, &kind, &["kind", "asset", "quantity"], &[])?;
                let asset = extract_string(map, "asset")?;
                let quantity = extract_string(map, "quantity")?;
                InstructionDraft::burn_from_input(&asset, &quantity)
            }
            "transfer_asset" => {
                require_draft_fields(
                    map,
                    &kind,
                    &["kind", "asset", "quantity", "destination"],
                    &[],
                )?;
                let asset = extract_string(map, "asset")?;
                let quantity = extract_string(map, "quantity")?;
                let destination = extract_string(map, "destination")?;
                InstructionDraft::transfer_from_input(&asset, &quantity, &destination)
            }
            "register_account" => {
                require_draft_fields(map, &kind, &["kind", "account"], &[])?;
                let account = extract_string(map, "account")?;
                InstructionDraft::register_account_from_input(&account)
            }
            "register_asset_definition" => {
                require_draft_fields(map, &kind, &["kind", "definition", "name", "mintable"], &[])?;
                let definition = extract_string(map, "definition")?;
                let name = extract_string(map, "name")?;
                let mintable = parse_mintable_label(&extract_string(map, "mintable")?)?;
                InstructionDraft::register_asset_definition_from_input(&definition, &name, mintable)
            }
            "publish_space_directory_manifest" => {
                require_draft_fields(map, &kind, &["kind", "manifest"], &[])?;
                let Some(manifest_value) = map.get("manifest") else {
                    return Err(ComposeError::InvalidRawDraft {
                        reason: "field `manifest` is required".to_owned(),
                    });
                };
                let manifest: AssetPermissionManifest = json::from_value(manifest_value.clone())
                    .map_err(|err| ComposeError::InvalidRawDraft {
                        reason: format!("invalid space directory manifest: {err}"),
                    })?;
                Ok(InstructionDraft::PublishSpaceDirectoryManifest { manifest })
            }
            "register_pin_manifest" => {
                require_draft_fields(map, &kind, &["kind", "request"], &[])?;
                let Some(request_value) = map.get("request") else {
                    return Err(ComposeError::InvalidRawDraft {
                        reason: "field `request` is required".to_owned(),
                    });
                };
                let request = decode_strict_pin_manifest(request_value)?;
                Ok(InstructionDraft::RegisterPinManifest { request })
            }
            "account_admission_policy" => {
                require_draft_fields(map, &kind, &["kind", "policy"], &[])?;
                let Some(policy_value) = map.get("policy") else {
                    return Err(ComposeError::InvalidRawDraft {
                        reason: "field `policy` is required".to_owned(),
                    });
                };
                let policy = decode_strict_account_admission_policy(policy_value)?;
                Ok(InstructionDraft::account_admission_policy(policy))
            }
            "grant_role" => {
                require_draft_fields(map, &kind, &["kind", "role", "account"], &[])?;
                let role = extract_string(map, "role")?;
                let account = extract_string(map, "account")?;
                InstructionDraft::grant_role_from_input(&role, &account)
            }
            "revoke_role" => {
                require_draft_fields(map, &kind, &["kind", "role", "account"], &[])?;
                let role = extract_string(map, "role")?;
                let account = extract_string(map, "account")?;
                InstructionDraft::revoke_role_from_input(&role, &account)
            }
            "multisig_propose" => {
                require_draft_fields(
                    map,
                    &kind,
                    &["kind", "account", "proposal_nonce", "instructions"],
                    &["transaction_ttl_ms"],
                )?;
                let account = extract_string(map, "account")?;
                let Some(instructions_value) = map.get("instructions") else {
                    return Err(ComposeError::InvalidRawDraft {
                        reason: "field `instructions` is required".to_owned(),
                    });
                };
                let instructions = drafts_from_json_value_with_budget(
                    instructions_value,
                    multisig_depth + 1,
                    budget,
                )?;
                if instructions.is_empty() {
                    return Err(ComposeError::InvalidRawDraft {
                        reason: "multisig proposal instructions must not be empty".to_owned(),
                    });
                }
                let transaction_ttl_ms = extract_optional_nonzero_u64(map, "transaction_ttl_ms")?;
                Ok(InstructionDraft::MultisigPropose {
                    account: parse_account_id(&account)?,
                    proposal_nonce: extract_string(map, "proposal_nonce")?
                        .parse::<MultisigProposalNonce>()
                        .map_err(|error| ComposeError::InvalidRawDraft {
                            reason: format!("invalid proposal_nonce: {error}"),
                        })?,
                    instructions,
                    transaction_ttl_ms,
                })
            }
            other => Err(ComposeError::InvalidRawDraft {
                reason: format!("unknown instruction kind `{other}`"),
            }),
        }
    }
}
fn format_admission_policy_summary(policy: &AccountAdmissionPolicy) -> String {
    let mode = match policy.mode {
        AccountAdmissionMode::ImplicitReceive => "implicit receive",
        AccountAdmissionMode::ExplicitOnly => "explicit only",
    };
    let mut details = Vec::new();
    if let Some(max) = policy.max_implicit_creations_per_tx {
        details.push(format!("tx cap {max}"));
    }
    if let Some(max) = policy.max_implicit_creations_per_block {
        details.push(format!("block cap {max}"));
    }
    if let Some(fee) = policy.implicit_creation_fee.as_ref() {
        let destination = match &fee.destination {
            ImplicitAccountFeeDestination::Burn => "burn".to_owned(),
            ImplicitAccountFeeDestination::Account(account) => format!("acct {account}"),
        };
        details.push(format!(
            "fee {} {} -> {destination}",
            fee.amount, fee.asset_definition_id
        ));
    }
    if !policy.min_initial_amounts.is_empty() {
        details.push(format!("min amounts {}", policy.min_initial_amounts.len()));
    }
    if let Some(role) = policy.default_role_on_create.as_ref() {
        details.push(format!("default role {role}"));
    }
    if details.is_empty() {
        return mode.to_owned();
    }
    format!("{mode}, {}", details.join(", "))
}
fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0F) as usize] as char);
    }
    out
}
fn account_literal(account_id: &AccountId) -> String {
    account_id.to_string()
}
fn asset_literal(asset_id: &AssetId) -> String {
    asset_id.to_string()
}
fn parse_asset_id(value: &str) -> Result<AssetId, ComposeError> {
    let parsed = AssetId::from_str(value).map_err(|err| ComposeError::InvalidAssetId {
        asset: value.to_owned(),
        reason: err.reason().into(),
    })?;
    if parsed.to_string() != value {
        return Err(ComposeError::InvalidAssetId {
            asset: value.to_owned(),
            reason: "asset id must use its canonical literal".to_owned(),
        });
    }
    Ok(parsed)
}
fn parse_account_id(value: &str) -> Result<AccountId, ComposeError> {
    AccountId::parse_encoded(value).map_err(|err| ComposeError::InvalidAccountId {
        account: value.to_owned(),
        reason: err.to_string(),
    })
}
fn parse_quantity(value: &str) -> Result<Quantity, ComposeError> {
    let parsed = Quantity::from_str(value).map_err(|err| ComposeError::InvalidQuantity {
        quantity: value.to_owned(),
        reason: err.to_string(),
    })?;
    if parsed.to_string() != value {
        return Err(ComposeError::InvalidQuantity {
            quantity: value.to_owned(),
            reason: "quantity must use its canonical decimal literal".to_owned(),
        });
    }
    Ok(parsed)
}
fn parse_asset_definition_id(value: &str) -> Result<AssetDefinitionId, ComposeError> {
    let parsed = AssetDefinitionId::from_str(value).map_err(|err| {
        ComposeError::InvalidAssetDefinitionId {
            definition: value.to_owned(),
            reason: err.to_string(),
        }
    })?;
    if parsed.to_string() != value {
        return Err(ComposeError::InvalidAssetDefinitionId {
            definition: value.to_owned(),
            reason: "asset definition id must use its canonical literal".to_owned(),
        });
    }
    Ok(parsed)
}
fn parse_role_id(value: &str) -> Result<RoleId, ComposeError> {
    RoleId::from_str(value).map_err(|err| ComposeError::InvalidRoleId {
        role: value.to_owned(),
        reason: err.to_string(),
    })
}
fn extract_string(map: &Map, key: &str) -> Result<String, ComposeError> {
    match map.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(ComposeError::InvalidRawDraft {
            reason: format!("field `{key}` must be a string"),
        }),
        None => Err(ComposeError::InvalidRawDraft {
            reason: format!("field `{key}` is required"),
        }),
    }
}
fn require_draft_fields(
    map: &Map,
    kind: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ComposeError> {
    if let Some(field) = required.iter().find(|field| !map.contains_key(**field)) {
        return Err(ComposeError::InvalidRawDraft {
            reason: format!("instruction kind `{kind}` requires field `{field}`"),
        });
    }
    if let Some(field) = map
        .keys()
        .find(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(ComposeError::InvalidRawDraft {
            reason: format!("instruction kind `{kind}` contains unknown field `{field}`"),
        });
    }
    Ok(())
}
fn extract_optional_nonzero_u64(map: &Map, key: &str) -> Result<Option<NonZeroU64>, ComposeError> {
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => {
            let Some(parsed) = number.as_u64() else {
                return Err(ComposeError::InvalidRawDraft {
                    reason: format!("field `{key}` must be a positive JSON integer"),
                });
            };
            NonZeroU64::new(parsed)
                .ok_or_else(|| ComposeError::InvalidRawDraft {
                    reason: format!("field `{key}` must be a positive JSON integer"),
                })
                .map(Some)
        }
        _ => Err(ComposeError::InvalidRawDraft {
            reason: format!("field `{key}` must be a positive JSON integer"),
        }),
    }
}
fn format_mintable(mintable: Mintable) -> String {
    match mintable {
        Mintable::Infinitely => "Infinitely",
        Mintable::Once => "Once",
        Mintable::Not => "Not",
        Mintable::Limited(tokens) => return format!("Limited({})", tokens.value()),
    }
    .to_owned()
}
fn parse_mintable_label(label: &str) -> Result<Mintable, ComposeError> {
    match label {
        "Infinitely" => Ok(Mintable::Infinitely),
        "Once" => Ok(Mintable::Once),
        "Not" => Ok(Mintable::Not),
        _ => {
            let Some(value_str) = label
                .strip_prefix("Limited(")
                .and_then(|value| value.strip_suffix(')'))
            else {
                return Err(ComposeError::InvalidRawDraft {
                    reason: format!("unknown mintable variant `{label}`"),
                });
            };
            let tokens = value_str
                .parse::<u32>()
                .map_err(|_| ComposeError::InvalidRawDraft {
                    reason: format!("invalid canonical mintable value `{label}`"),
                })?;
            let mintable = Mintable::limited_from_u32(tokens).map_err(|err| {
                ComposeError::InvalidRawDraft {
                    reason: err.to_string(),
                }
            })?;
            if format_mintable(mintable) != label {
                return Err(ComposeError::InvalidRawDraft {
                    reason: format!("invalid canonical mintable value `{label}`"),
                });
            }
            Ok(mintable)
        }
    }
}
fn apply_mintable(builder: NewAssetDefinition, mintable: Mintable) -> NewAssetDefinition {
    match mintable {
        Mintable::Infinitely => builder,
        Mintable::Once => builder.mintable_once(),
        Mintable::Limited(tokens) => builder.mintable_limited(tokens),
        other => builder.with_mintable(other),
    }
}
#[derive(Debug)]
struct DraftDecodeBudget {
    remaining: usize,
}
impl Default for DraftDecodeBudget {
    fn default() -> Self {
        Self {
            remaining: DRAFT_TOTAL_MAX_ITEMS_V1,
        }
    }
}
impl DraftDecodeBudget {
    fn consume(&mut self) -> Result<(), ComposeError> {
        self.remaining = self.remaining.checked_sub(1).ok_or_else(|| {
            ComposeError::InvalidRawDraft {
                reason: format!(
                    "draft payload exceeds the V1 total-instruction limit of {DRAFT_TOTAL_MAX_ITEMS_V1}"
                ),
            }
        })?;
        Ok(())
    }
}
fn validate_raw_json_input(input: &str) -> Result<(), ComposeError> {
    if input.len() > RAW_DRAFT_JSON_MAX_BYTES_V1 {
        return Err(ComposeError::InvalidRawDraft {
            reason: format!(
                "raw draft JSON exceeds the V1 limit of {RAW_DRAFT_JSON_MAX_BYTES_V1} bytes"
            ),
        });
    }
    let mut nesting = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in input.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                nesting = nesting
                    .checked_add(1)
                    .ok_or_else(|| ComposeError::InvalidRawDraft {
                        reason: "raw draft JSON nesting overflowed".to_owned(),
                    })?;
                if nesting > RAW_DRAFT_JSON_MAX_NESTING_V1 {
                    return Err(ComposeError::InvalidRawDraft {
                        reason: format!(
                            "raw draft JSON exceeds the V1 nesting limit of {RAW_DRAFT_JSON_MAX_NESTING_V1}"
                        ),
                    });
                }
            }
            b'}' | b']' => nesting = nesting.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
fn reject_unknown_object_fields(
    value: &Value,
    allowed: &[&str],
    context: &str,
) -> Result<(), ComposeError> {
    let object = value
        .as_object()
        .ok_or_else(|| ComposeError::InvalidRawDraft {
            reason: format!("{context} must be an object"),
        })?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(ComposeError::InvalidRawDraft {
            reason: format!("unknown field `{field}` in {context}"),
        });
    }
    Ok(())
}
fn decode_strict_pin_manifest(value: &Value) -> Result<RegisterPinManifest, ComposeError> {
    reject_unknown_object_fields(
        value,
        &["manifest_payload", "alias", "successor_of"],
        "pin manifest request",
    )?;
    if let Some(alias @ Value::Object(_)) = value.as_object().and_then(|object| object.get("alias"))
    {
        reject_unknown_object_fields(alias, &["name", "namespace", "proof"], "pin alias")?;
    }
    json::from_value(value.clone()).map_err(|err| ComposeError::InvalidRawDraft {
        reason: format!("invalid pin manifest request: {err}"),
    })
}
fn decode_strict_account_admission_policy(
    value: &Value,
) -> Result<AccountAdmissionPolicy, ComposeError> {
    reject_unknown_object_fields(
        value,
        &[
            "mode",
            "max_implicit_creations_per_tx",
            "max_implicit_creations_per_block",
            "implicit_creation_fee",
            "min_initial_amounts",
            "default_role_on_create",
        ],
        "account admission policy",
    )?;
    let object = value.as_object().expect("validated object");
    if let Some(mode @ Value::Object(_)) = object.get("mode") {
        reject_unknown_object_fields(mode, &["mode", "value"], "account admission mode")?;
    }
    if let Some(fee @ Value::Object(_)) = object.get("implicit_creation_fee") {
        reject_unknown_object_fields(
            fee,
            &["asset_definition_id", "amount", "destination"],
            "implicit account creation fee",
        )?;
        if let Some(destination @ Value::Object(_)) =
            fee.as_object().and_then(|fee| fee.get("destination"))
        {
            reject_unknown_object_fields(
                destination,
                &["destination", "value"],
                "implicit account fee destination",
            )?;
        }
    }
    json::from_value(value.clone()).map_err(|err| ComposeError::InvalidRawDraft {
        reason: format!("invalid account admission policy: {err}"),
    })
}
/// Serialize a list of drafts to a JSON array representation.
#[must_use]
fn drafts_to_json_value(drafts: &[InstructionDraft]) -> Value {
    Value::Array(drafts.iter().map(|draft| draft.to_json_value()).collect())
}
/// Serialize a list of drafts into a formatted JSON string.
///
/// # Errors
///
/// Returns [`ComposeError::InvalidRawDraft`] when serialization fails.
pub fn drafts_to_pretty_json(drafts: &[InstructionDraft]) -> Result<String, ComposeError> {
    json::to_string_pretty(&drafts_to_json_value(drafts)).map_err(|err| {
        ComposeError::InvalidRawDraft {
            reason: err.to_string(),
        }
    })
}
/// Decode a list of drafts from a JSON array representation.
///
/// # Errors
///
/// Returns [`ComposeError::InvalidRawDraft`] when the payload is malformed.
fn drafts_from_json_value(value: &Value) -> Result<Vec<InstructionDraft>, ComposeError> {
    let mut budget = DraftDecodeBudget::default();
    drafts_from_json_value_with_budget(value, 0, &mut budget)
}
fn drafts_from_json_value_with_budget(
    value: &Value,
    multisig_depth: usize,
    budget: &mut DraftDecodeBudget,
) -> Result<Vec<InstructionDraft>, ComposeError> {
    match value {
        Value::Array(items) => {
            if items.len() > DRAFT_ARRAY_MAX_ITEMS_V1 {
                return Err(ComposeError::InvalidRawDraft {
                    reason: format!(
                        "draft array exceeds the V1 limit of {DRAFT_ARRAY_MAX_ITEMS_V1} instructions"
                    ),
                });
            }
            items
                .iter()
                .map(|item| {
                    InstructionDraft::from_json_value_with_budget(item, multisig_depth, budget)
                })
                .collect()
        }
        _ => Err(ComposeError::InvalidRawDraft {
            reason: "expected array".to_owned(),
        }),
    }
}
/// Parse drafts from a JSON string.
///
/// # Errors
///
/// Returns [`ComposeError::InvalidRawDraft`] when the payload fails to decode.
pub fn drafts_from_json_str(input: &str) -> Result<Vec<InstructionDraft>, ComposeError> {
    validate_raw_json_input(input)?;
    let value: Value = json::from_str(input).map_err(|err| ComposeError::InvalidRawDraft {
        reason: err.to_string(),
    })?;
    drafts_from_json_value(&value)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        account::{AccountAdmissionMode, admission::ImplicitAccountCreationFee},
        asset::prelude::AssetDefinitionId,
        block::BlockHeader,
    };
    use iroha_version::Version;
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroU64},
        time::Duration,
    };
    const FIXTURE_ADMISSION_POLICY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/composer/draft_account_admission_policy.json"
    ));
    const FIXTURE_MULTISIG_PROPOSE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/composer/draft_multisig_propose.json"
    ));
    const FIXTURE_SPACE_MANIFEST_TOUCH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/composer/draft_space_manifest_touch.json"
    ));
    const FIXTURE_SPACE_MANIFEST_HANDLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/composer/draft_space_manifest_handle.json"
    ));
    const FIXTURE_PIN_MANIFEST: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/composer/draft_pin_manifest.json"
    ));
    const RETIRED_RAW_GENESIS_HASH: &str =
        "32c903e5b3497e34c2b844ebfe8a39c19e6cf8f95d44c1ffb8ba9dcb42f91149";
    fn test_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"mochi-compose-test-network",
        )))
    }
    fn draft_from_fixture(fixture: &str) -> InstructionDraft {
        let value: Value = json::from_str(fixture).expect("fixture json");
        InstructionDraft::from_json_value(&value).expect("fixture draft")
    }
    fn compose_for_test(
        drafts: &[InstructionDraft],
        authority: &SigningAuthority,
    ) -> Result<TransactionPreview, ComposeError> {
        compose_preview_with_options(
            test_network_id(),
            drafts,
            authority,
            &TransactionComposeOptions::default(),
        )
    }
    fn compose_with_development_signer_for_test(
        drafts: &[InstructionDraft],
    ) -> Result<TransactionPreview, ComposeError> {
        compose_for_test(
            drafts,
            development_signing_authorities()
                .first()
                .expect("development signer"),
        )
    }
    #[test]
    fn mint_preview_produces_summary() {
        let account = account_literal(&ALICE_ID);
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let asset_id = format!("{asset_def}#{account}");
        let network_id = test_network_id();
        let draft = InstructionDraft::mint_from_input(&asset_id, "5").expect("mint draft");
        let preview = compose_with_development_signer_for_test(&[draft]).expect("preview");
        assert_eq!(preview.authority(), account);
        assert!(
            !preview.instructions().is_empty(),
            "expected human readable instruction summary"
        );
        assert!(
            !preview.encoded_hex().is_empty(),
            "hex encoding must not be empty"
        );
        assert!(!preview.hash().is_empty(), "hash must not be empty");
        assert_eq!(preview.signed_transaction().network_id(), Some(&network_id));
        // Ensure Norito payload roundtrips back to a transaction.
        assert!(
            SignedTransaction::supported_versions().contains(&preview.encoded_bytes()[0]),
            "unexpected signed transaction version"
        );
    }
    #[test]
    fn test_network_id_uses_canonical_checked_literal() {
        let network_id = test_network_id();
        let literal = network_id.to_string();
        assert_eq!(literal.len(), 74);
        assert_eq!(
            literal.parse::<NetworkId>().expect("canonical literal"),
            network_id
        );
        assert!(
            RETIRED_RAW_GENESIS_HASH.parse::<NetworkId>().is_err(),
            "a bare genesis hash is not a first-release network identity"
        );
        assert!(
            format!("0x{RETIRED_RAW_GENESIS_HASH}")
                .parse::<NetworkId>()
                .is_err(),
            "a hexadecimal compatibility prefix must be rejected"
        );
    }
    #[test]
    fn invalid_asset_id_reports_error() {
        let err = InstructionDraft::mint_from_input("invalid-format", "1")
            .expect_err("invalid identifiers should produce compose error");
        matches!(err, ComposeError::InvalidAssetId { .. });
    }
    #[test]
    fn transfer_draft_parses_inputs() {
        let asset_id = AssetId::new(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM".parse().unwrap(),
            ALICE_ID.clone(),
        );
        let asset_str = asset_literal(&asset_id);
        let destination = account_literal(&BOB_ID);
        let draft =
            InstructionDraft::transfer_from_input(&asset_str, "10.5", &destination).expect("draft");
        matches!(draft, InstructionDraft::TransferAsset { .. });
        let summary = draft.summary();
        assert!(
            summary.contains("Transfer"),
            "summary should mention transfer action"
        );
    }
    #[test]
    fn asset_draft_rejects_negative_quantity() {
        let asset_id = AssetId::new(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM".parse().unwrap(),
            ALICE_ID.clone(),
        );
        let error = InstructionDraft::mint_from_input(&asset_literal(&asset_id), "-0.01")
            .expect_err("negative quantity must not enter an asset instruction draft");
        assert!(matches!(error, ComposeError::InvalidQuantity { .. }));
    }
    #[test]
    fn asset_drafts_reject_noncanonical_literals() {
        let definition = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
        let asset_id = AssetId::new(definition.parse().expect("definition id"), ALICE_ID.clone());
        let asset = asset_literal(&asset_id);

        for invalid in [format!(" {asset}"), format!("{asset}#dataspace:01")] {
            let error = InstructionDraft::mint_from_input(&invalid, "1")
                .expect_err("noncanonical asset id must be rejected");
            assert!(matches!(error, ComposeError::InvalidAssetId { .. }));
        }
        for invalid in [" 1 ", "+1", "01", "-0", "1.0"] {
            let error = InstructionDraft::mint_from_input(&asset, invalid)
                .expect_err("noncanonical quantity must be rejected");
            assert!(matches!(error, ComposeError::InvalidQuantity { .. }));
        }
        let error = InstructionDraft::register_asset_definition_from_input(
            &format!(" {definition}"),
            "rose",
            Mintable::Once,
        )
        .expect_err("noncanonical definition id must be rejected");
        assert!(matches!(
            error,
            ComposeError::InvalidAssetDefinitionId { .. }
        ));
        InstructionDraft::register_asset_definition_from_input(
            definition,
            " rose ",
            Mintable::Once,
        )
        .expect_err("asset definition name whitespace must not be normalized");
    }
    #[test]
    fn burn_draft_parses_inputs() {
        let asset_id = AssetId::new(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM".parse().unwrap(),
            ALICE_ID.clone(),
        );
        let asset_str = asset_literal(&asset_id);
        let draft =
            InstructionDraft::burn_from_input(&asset_str, "3").expect("burn draft should parse");
        matches!(draft, InstructionDraft::BurnAsset { .. });
        assert!(
            draft.summary().contains("Burn"),
            "summary should mention burn action"
        );
    }
    #[test]
    fn compose_preview_requires_instructions() {
        let err = compose_with_development_signer_for_test(&[])
            .expect_err("empty instructions should fail");
        matches!(err, ComposeError::EmptyInstructions);
    }
    #[test]
    fn compose_preview_accepts_multiple_instructions() {
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let asset_id = AssetId::new(asset_def, ALICE_ID.clone());
        let mint = InstructionDraft::MintAsset {
            asset: asset_id.clone(),
            quantity: Quantity::from(5_u32),
        };
        let transfer = InstructionDraft::TransferAsset {
            asset: asset_id,
            quantity: Quantity::from(3_u32),
            destination: BOB_ID.clone(),
        };
        let preview = compose_with_development_signer_for_test(&[mint, transfer])
            .expect("compose multi instruction");
        assert_eq!(
            preview.instructions().len(),
            2,
            "preview should include both instructions"
        );
    }
    #[test]
    fn transaction_preview_preserves_mixed_batch_order() {
        let first: InstructionBox = iroha_data_model::isi::Log::new(
            iroha_data_model::Level::INFO,
            "before contract".to_owned(),
        )
        .into();
        let last: InstructionBox = iroha_data_model::isi::Log::new(
            iroha_data_model::Level::INFO,
            "after contract".to_owned(),
        )
        .into();
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &test_network_id(),
            &ALICE_ID,
            1,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let invocation = iroha_data_model::transaction::executable::ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: iroha_crypto::Hash::prehashed([0x42; 32]),
            entrypoint: "apply".to_owned(),
            arguments: None,
        };
        let signed = TransactionBuilder::new(
            test_network_id(),
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                NonZeroU64::new(10_000),
            ),
        )
        .with_executable_batch(vec![
            ExecutableBatchItem::from(first.clone()),
            ExecutableBatchItem::from(invocation),
            ExecutableBatchItem::from(last.clone()),
        ])
        .try_sign(ALICE_KEYPAIR.private_key())
        .expect("sign mixed batch");
        let preview = TransactionPreview::new(signed);
        assert_eq!(
            preview.instructions(),
            [
                format!("{first}"),
                format!("Contract call {contract_address}::apply"),
                format!("{last}"),
            ]
        );
    }
    #[test]
    fn development_signing_authorities_present() {
        let authorities = development_signing_authorities();
        assert!(
            !authorities.is_empty(),
            "expected at least one development signing authority"
        );
        assert!(
            authorities
                .iter()
                .any(|authority| authority.account_id() == &ALICE_ID.clone()),
            "expected Alice development signer to be available"
        );
    }
    #[test]
    fn raw_domain_registration_draft_is_not_supported() {
        let value = norito::json!({
            "kind": "register_domain",
            "domain": "side_garden.universal"
        });
        let err = InstructionDraft::from_json_value(&value)
            .expect_err("raw domain registration must not be composed");
        assert!(
            matches!(err, ComposeError::InvalidRawDraft { ref reason } if reason.contains("unknown instruction kind"))
        );
    }
    #[test]
    fn drafts_json_roundtrip_covers_all_variants() {
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let asset_id = AssetId::new(asset_def.clone(), ALICE_ID.clone());
        let asset_id_str = asset_literal(&asset_id);
        let account = account_literal(&ALICE_ID);
        let mint = InstructionDraft::mint_from_input(&asset_id_str, "10").expect("mint draft");
        let burn = InstructionDraft::burn_from_input(&asset_id_str, "1").expect("burn draft");
        let transfer = InstructionDraft::transfer_from_input(&asset_id_str, "5", &account)
            .expect("transfer draft");
        let register_account =
            InstructionDraft::register_account_from_input(&account).expect("account draft");
        let register_definition = InstructionDraft::register_asset_definition_from_input(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
            "rose",
            Mintable::Once,
        )
        .expect("definition draft");
        let space_manifest = draft_from_fixture(FIXTURE_SPACE_MANIFEST_HANDLE);
        let pin_manifest = draft_from_fixture(FIXTURE_PIN_MANIFEST);
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: Some(3),
            max_implicit_creations_per_block: None,
            implicit_creation_fee: None,
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: None,
        };
        let admission = InstructionDraft::account_admission_policy(policy);
        let grant_role =
            InstructionDraft::grant_role_from_input("council", &account).expect("grant draft");
        let revoke_role =
            InstructionDraft::revoke_role_from_input("council", &account).expect("revoke draft");
        let nested_json =
            drafts_to_pretty_json(&[mint.clone(), transfer.clone()]).expect("nested json");
        let multisig = InstructionDraft::multisig_propose_from_json(
            &account,
            &"07".repeat(32),
            &nested_json,
            Some(60_000),
        )
        .expect("multisig draft");
        let drafts = vec![
            mint,
            burn,
            transfer,
            register_account,
            register_definition,
            space_manifest,
            pin_manifest,
            admission,
            grant_role,
            revoke_role,
            multisig,
        ];
        let json = drafts_to_pretty_json(&drafts).expect("serialize drafts");
        let parsed = drafts_from_json_str(&json).expect("parse drafts");
        assert_eq!(parsed.len(), drafts.len());
        for (expected, actual) in drafts.iter().zip(parsed.iter()) {
            assert_eq!(expected.summary(), actual.summary());

            let mut value = expected.to_json_value();
            value
                .as_object_mut()
                .expect("draft object")
                .insert("unexpected".to_owned(), Value::Bool(true));
            let error = InstructionDraft::from_json_value(&value)
                .expect_err("every first-release draft kind must reject unknown fields");
            assert!(error.to_string().contains("unknown field `unexpected`"));
        }
    }
    #[test]
    fn protocol_drafts_reject_unknown_nested_fields() {
        for (fixture, nested_field) in [
            (FIXTURE_SPACE_MANIFEST_HANDLE, "manifest"),
            (FIXTURE_PIN_MANIFEST, "request"),
            (FIXTURE_ADMISSION_POLICY, "policy"),
        ] {
            let mut value: Value = json::from_str(fixture).expect("fixture JSON");
            value
                .as_object_mut()
                .and_then(|object| object.get_mut(nested_field))
                .and_then(Value::as_object_mut)
                .expect("nested protocol object")
                .insert("legacy".to_owned(), Value::Bool(true));
            InstructionDraft::from_json_value(&value)
                .expect_err("unknown nested protocol fields must fail closed");
        }

        let mut value: Value = json::from_str(FIXTURE_ADMISSION_POLICY).expect("policy fixture");
        value
            .as_object_mut()
            .and_then(|object| object.get_mut("policy"))
            .and_then(Value::as_object_mut)
            .and_then(|policy| policy.get_mut("implicit_creation_fee"))
            .and_then(Value::as_object_mut)
            .expect("implicit creation fee")
            .insert("legacy".to_owned(), Value::Bool(true));
        InstructionDraft::from_json_value(&value)
            .expect_err("unknown nested fee fields must fail closed");
    }
    #[test]
    fn raw_draft_limits_bound_bytes_arrays_totals_and_multisig_depth() {
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let asset = AssetId::new(asset_def, ALICE_ID.clone());
        let leaf = InstructionDraft::mint_from_input(&asset_literal(&asset), "1")
            .expect("mint draft")
            .to_json_value();

        let maximum_array = Value::Array(vec![leaf.clone(); DRAFT_ARRAY_MAX_ITEMS_V1]);
        assert_eq!(
            drafts_from_json_value(&maximum_array)
                .expect("the exact V1 array limit must be accepted")
                .len(),
            DRAFT_ARRAY_MAX_ITEMS_V1
        );
        let oversized_array = Value::Array(vec![leaf.clone(); DRAFT_ARRAY_MAX_ITEMS_V1 + 1]);
        drafts_from_json_value(&oversized_array)
            .expect_err("the first instruction beyond the V1 array limit must fail");

        let account = account_literal(&ALICE_ID);
        let multisig = |instructions: Vec<Value>| {
            norito::json!({
                "kind": "multisig_propose",
                "proposal_nonce": ("07".repeat(32)),
                "account": (account.clone()),
                "instructions": instructions
            })
        };
        let total_overflow = Value::Array(
            (0..4)
                .map(|_| multisig(vec![leaf.clone(); DRAFT_ARRAY_MAX_ITEMS_V1]))
                .collect(),
        );
        let error = drafts_from_json_value(&total_overflow)
            .expect_err("the total instruction budget must span nested arrays");
        assert!(error.to_string().contains("total-instruction limit"));

        let mut maximum_depth = leaf.clone();
        for _ in 0..MULTISIG_DRAFT_MAX_DEPTH_V1 {
            maximum_depth = multisig(vec![maximum_depth]);
        }
        InstructionDraft::from_json_value(&maximum_depth)
            .expect("the exact V1 multisig nesting limit must be accepted");
        let excessive_depth = multisig(vec![maximum_depth]);
        let error = InstructionDraft::from_json_value(&excessive_depth)
            .expect_err("the first multisig depth beyond the V1 limit must fail");
        assert!(error.to_string().contains("multisig nesting"));

        let oversized_input = " ".repeat(RAW_DRAFT_JSON_MAX_BYTES_V1 + 1);
        let error = drafts_from_json_str(&oversized_input)
            .expect_err("the first byte beyond the V1 JSON limit must fail before parsing");
        assert!(error.to_string().contains("bytes"));
        let excessive_json_nesting = "[".repeat(RAW_DRAFT_JSON_MAX_NESTING_V1 + 1);
        let error = drafts_from_json_str(&excessive_json_nesting)
            .expect_err("excessive raw JSON nesting must fail before parsing");
        assert!(error.to_string().contains("nesting limit"));
    }
    #[test]
    fn register_asset_definition_json_requires_canonical_mintable() {
        let draft = InstructionDraft::register_asset_definition_from_input(
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
            "rose",
            Mintable::Infinitely,
        )
        .expect("definition draft");
        let canonical = draft.to_json_value();

        let mut missing = canonical.clone();
        missing
            .as_object_mut()
            .expect("draft object")
            .remove("mintable");
        InstructionDraft::from_json_value(&missing)
            .expect_err("missing first-release mintable must be rejected");

        for invalid in [
            "infinite",
            "infinitely",
            " Infinitely ",
            "Limited 2",
            "Limited(02)",
        ] {
            let mut value = canonical.clone();
            value
                .as_object_mut()
                .expect("draft object")
                .insert("mintable".to_owned(), Value::String(invalid.to_owned()));
            InstructionDraft::from_json_value(&value)
                .expect_err("noncanonical mintable spelling must be rejected");
        }
    }
    #[test]
    fn multisig_json_preserves_required_occurrence_nonce() {
        use iroha_executor_data_model::isi::multisig::MultisigInstructionBox;

        let draft = draft_from_fixture(FIXTURE_MULTISIG_PROPOSE);
        let canonical = draft.to_json_value();
        let parsed = InstructionDraft::from_json_value(&canonical).expect("canonical proposal");
        let instruction = parsed.instruction();
        let MultisigInstructionBox::Propose(proposal) =
            MultisigInstructionBox::try_from(&instruction).expect("native multisig instruction")
        else {
            panic!("native proposal instruction");
        };
        assert_eq!(proposal.proposal_nonce.to_string(), "07".repeat(32));

        let mut missing = canonical.clone();
        missing.as_object_mut().unwrap().remove("proposal_nonce");
        InstructionDraft::from_json_value(&missing)
            .expect_err("a restored draft must retain its original nonce");
        for invalid in [
            Value::Null,
            Value::String("00".repeat(32)),
            Value::String("AB".repeat(32)),
            Value::String("07".repeat(31)),
        ] {
            let mut value = canonical.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert("proposal_nonce".to_owned(), invalid);
            InstructionDraft::from_json_value(&value)
                .expect_err("nonce must be exact nonzero lowercase 32-byte hexadecimal");
        }
    }

    #[test]
    fn multisig_json_accepts_only_positive_integer_ttl() {
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let nested = InstructionDraft::mint_from_input(
            &asset_literal(&AssetId::new(asset_def, ALICE_ID.clone())),
            "1",
        )
        .expect("nested draft");
        let draft = InstructionDraft::MultisigPropose {
            proposal_nonce: MultisigProposalNonce::new([7; 32]).unwrap(),
            account: ALICE_ID.clone(),
            instructions: vec![nested],
            transaction_ttl_ms: NonZeroU64::new(1),
        };
        let canonical = draft.to_json_value();

        let mut omitted = canonical.clone();
        omitted
            .as_object_mut()
            .expect("draft object")
            .remove("transaction_ttl_ms");
        InstructionDraft::from_json_value(&omitted).expect("omitted TTL is canonical absence");

        for invalid in [
            Value::Null,
            Value::String("1".to_owned()),
            Value::from(0_u64),
        ] {
            let mut value = canonical.clone();
            value
                .as_object_mut()
                .expect("draft object")
                .insert("transaction_ttl_ms".to_owned(), invalid);
            InstructionDraft::from_json_value(&value)
                .expect_err("TTL must be a positive JSON integer");
        }
    }
    #[test]
    fn register_account_instruction_uses_canonical_account_id() {
        let account = account_literal(&ALICE_ID);
        let draft = InstructionDraft::register_account_from_input(&account).expect("account draft");
        let instruction = draft.instruction();
        let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*instruction;
        let Some(register_box) = instruction_ref
            .as_any()
            .downcast_ref::<iroha_data_model::isi::RegisterBox>()
        else {
            panic!("expected RegisterBox instruction");
        };
        let iroha_data_model::isi::RegisterBox::Account(register) = register_box else {
            panic!("expected Register<Account> instruction");
        };
        assert_eq!(register.object.id, ALICE_ID.clone());
    }
    #[test]
    fn register_account_instruction_rejects_domain_suffix_literal() {
        let domain_suffixed_account = format!("{}@wonderland", account_literal(&ALICE_ID));
        let err = InstructionDraft::register_account_from_input(&domain_suffixed_account)
            .expect_err("domain-suffixed account literal must be rejected");
        assert!(matches!(err, ComposeError::InvalidAccountId { .. }));
    }
    #[test]
    fn drafts_from_json_str_rejects_non_array() {
        let err = drafts_from_json_str("{\"kind\":\"mint_asset\"}")
            .expect_err("non-array payload should be rejected");
        assert!(matches!(err, ComposeError::InvalidRawDraft { .. }));
    }
    #[test]
    fn grant_role_draft_parses_inputs() {
        let account = account_literal(&ALICE_ID);
        let draft =
            InstructionDraft::grant_role_from_input("council", &account).expect("grant draft");
        let expected_account = ALICE_ID.to_string();
        assert_eq!(
            draft.summary(),
            format!("Grant role council to {expected_account}")
        );
    }
    #[test]
    fn revoke_role_draft_parses_inputs() {
        let account = account_literal(&ALICE_ID);
        let draft =
            InstructionDraft::revoke_role_from_input("auditor", &account).expect("revoke draft");
        let expected_account = ALICE_ID.to_string();
        assert_eq!(
            draft.summary(),
            format!("Revoke role auditor from {expected_account}")
        );
    }
    #[test]
    fn development_signer_permissions_match_expectations() {
        use std::collections::BTreeSet;
        let authorities = development_signing_authorities();
        let alice = authorities
            .iter()
            .find(|auth| auth.label() == "Alice (dev)")
            .expect("Alice signer present");
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let alice_permissions: BTreeSet<_> = alice.permissions().collect();
        assert_eq!(
            alice_permissions,
            InstructionPermission::all().into_iter().collect(),
            "Alice should support every instruction template"
        );
        let bob_permissions: Vec<_> = bob.permissions().collect();
        assert_eq!(
            bob_permissions,
            vec![InstructionPermission::TransferAsset],
            "Bob should default to transfer-only permissions"
        );
    }
    #[test]
    fn account_admission_policy_draft_is_chain_global() {
        let policy = AccountAdmissionPolicy::default();
        let draft = InstructionDraft::account_admission_policy(policy);
        assert!(
            draft.summary().contains("chain-global"),
            "summary should identify the global scope"
        );
    }
    #[test]
    fn account_admission_policy_instruction_sets_canonical_global_parameter() {
        let policy = AccountAdmissionPolicy::default();
        let instruction = InstructionDraft::account_admission_policy(policy.clone()).instruction();
        let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*instruction;
        let set_parameter = instruction_ref
            .as_any()
            .downcast_ref::<SetParameter>()
            .expect("account admission draft must emit SetParameter");
        let Parameter::Custom(custom) = set_parameter.inner() else {
            panic!("account admission draft must emit a custom parameter");
        };
        assert_eq!(custom.id, AccountAdmissionPolicy::parameter_id());
        assert_eq!(
            AccountAdmissionPolicy::from_custom_parameter(custom),
            Some(policy)
        );
    }
    #[test]
    fn account_admission_policy_json_rejects_retired_domain_field() {
        let mut value =
            InstructionDraft::account_admission_policy(AccountAdmissionPolicy::default())
                .to_json_value();
        value.as_object_mut().expect("draft object").insert(
            "domain".to_owned(),
            Value::String("wonderland.universal".to_owned()),
        );
        let error = InstructionDraft::from_json_value(&value)
            .expect_err("retired domain-scoped draft must be rejected");
        assert!(error.to_string().contains("unknown field `domain`"));
    }
    #[test]
    fn multisig_propose_from_json_requires_instructions() {
        let account = account_literal(&ALICE_ID);
        let err =
            InstructionDraft::multisig_propose_from_json(&account, &"07".repeat(32), "[]", None)
                .expect_err("empty proposal should be rejected");
        assert!(matches!(err, ComposeError::InvalidRawDraft { .. }));
    }
    #[test]
    fn space_directory_manifest_from_json_rejects_invalid_payload() {
        let err = InstructionDraft::publish_space_directory_manifest_from_json("{\"bad\":true}")
            .expect_err("invalid manifest should be rejected");
        assert!(matches!(err, ComposeError::InvalidRawDraft { .. }));
    }
    #[test]
    fn pin_manifest_from_json_rejects_invalid_payload() {
        let err = InstructionDraft::register_pin_manifest_from_json("{\"digest\":\"bad\"}")
            .expect_err("invalid pin manifest should be rejected");
        assert!(matches!(err, ComposeError::InvalidRawDraft { .. }));
    }
    #[test]
    fn signing_authority_roles_roundtrip() {
        let role: RoleId = "basic_user".parse().expect("role id");
        let authority = SigningAuthority::with_permissions_and_roles(
            "Carol",
            ALICE_ID.clone(),
            ALICE_KEYPAIR.clone(),
            [InstructionPermission::TransferAsset],
            [role.clone()],
        );
        let roles: Vec<_> = authority.roles().collect();
        assert_eq!(roles, vec![&role]);
    }
    #[test]
    fn instruction_permission_keys_roundtrip() {
        for permission in InstructionPermission::all() {
            let key = permission.key();
            let restored = InstructionPermission::from_key(key)
                .unwrap_or_else(|| panic!("expected key {key} to map back to a permission"));
            assert_eq!(
                restored, permission,
                "roundtrip between key `{key}` and permission should match"
            );
        }
        assert!(
            InstructionPermission::from_key("unknown").is_none(),
            "unknown permission keys should be rejected"
        );
        assert!(
            InstructionPermission::from_key("account_admission_policy").is_none(),
            "retired domain-policy permission key should be rejected"
        );
    }
    #[test]
    fn draft_fixtures_parse_to_expected_variants() {
        let cases = [
            (FIXTURE_ADMISSION_POLICY, "account admission policy"),
            (FIXTURE_MULTISIG_PROPOSE, "multisig proposal"),
            (FIXTURE_SPACE_MANIFEST_TOUCH, "space directory touch"),
            (FIXTURE_SPACE_MANIFEST_HANDLE, "space directory handle"),
            (FIXTURE_PIN_MANIFEST, "pin manifest"),
        ];
        for (fixture, label) in cases {
            let draft = draft_from_fixture(fixture);
            match (label, draft) {
                (
                    "account admission policy",
                    InstructionDraft::SetAccountAdmissionPolicy { .. },
                ) => {}
                ("multisig proposal", InstructionDraft::MultisigPropose { .. }) => {}
                (
                    "space directory touch",
                    InstructionDraft::PublishSpaceDirectoryManifest { .. },
                ) => {}
                (
                    "space directory handle",
                    InstructionDraft::PublishSpaceDirectoryManifest { .. },
                ) => {}
                ("pin manifest", InstructionDraft::RegisterPinManifest { .. }) => {}
                _ => panic!("fixture {label} did not decode to expected draft"),
            }
        }
    }
    #[test]
    fn admission_policy_summary_surfaces_caps_fee_and_role() {
        let policy = AccountAdmissionPolicy {
            mode: AccountAdmissionMode::ImplicitReceive,
            max_implicit_creations_per_tx: Some(3),
            max_implicit_creations_per_block: Some(10),
            implicit_creation_fee: Some(ImplicitAccountCreationFee {
                asset_definition_id: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
                    .parse()
                    .expect("asset definition"),
                amount: Quantity::from(1_u32),
                destination: ImplicitAccountFeeDestination::Burn,
            }),
            min_initial_amounts: BTreeMap::new(),
            default_role_on_create: Some("basic_user".parse().expect("role id")),
        };
        let draft = InstructionDraft::SetAccountAdmissionPolicy { policy };
        let summary = draft.summary();
        assert!(summary.contains("tx cap 3"));
        assert!(summary.contains("block cap 10"));
        assert!(summary.contains("fee 1 62Fk4FPcMuLvW5QjDGNF2a4jAmjM"));
        assert!(summary.contains("default role basic_user"));
    }
    #[test]
    fn compose_preview_rejects_unauthorised_instruction() {
        let authorities = development_signing_authorities();
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let draft = InstructionDraft::register_account_from_input(&account_literal(&ALICE_ID))
            .expect("account draft");
        let err = compose_for_test(&[draft], bob)
            .expect_err("Bob should not be allowed to register accounts");
        match err {
            ComposeError::UnauthorizedInstruction { action, .. } => {
                assert_eq!(action, InstructionPermission::RegisterAccount);
            }
            other => panic!("unexpected compose error: {other:?}"),
        }
    }
    #[test]
    fn compose_preview_rejects_unauthorised_multisig_proposal() {
        let authorities = development_signing_authorities();
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let asset_id = AssetId::new(asset_def, ALICE_ID.clone());
        let asset_id_str = asset_literal(&asset_id);
        let mint = InstructionDraft::mint_from_input(&asset_id_str, "1").expect("mint draft");
        let nested_json = drafts_to_pretty_json(&[mint]).expect("nested json");
        let draft = InstructionDraft::multisig_propose_from_json(
            &account_literal(&ALICE_ID),
            &"07".repeat(32),
            &nested_json,
            None,
        )
        .expect("multisig draft");
        let err = compose_for_test(&[draft], bob)
            .expect_err("Bob should not be allowed to propose multisig transactions");
        match err {
            ComposeError::UnauthorizedInstruction { action, .. } => {
                assert_eq!(action, InstructionPermission::MultisigPropose);
            }
            other => panic!("unexpected compose error: {other:?}"),
        }
    }
    #[test]
    fn compose_preview_rejects_unauthorised_space_manifest() {
        let authorities = development_signing_authorities();
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let draft = draft_from_fixture(FIXTURE_SPACE_MANIFEST_TOUCH);
        let err = compose_for_test(&[draft], bob)
            .expect_err("Bob should not be allowed to publish space directory manifests");
        match err {
            ComposeError::UnauthorizedInstruction { action, .. } => {
                assert_eq!(action, InstructionPermission::PublishSpaceDirectoryManifest);
            }
            other => panic!("unexpected compose error: {other:?}"),
        }
    }
    #[test]
    fn compose_preview_rejects_unauthorised_pin_manifest_json() {
        let authorities = development_signing_authorities();
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let draft = draft_from_fixture(FIXTURE_PIN_MANIFEST);
        let err = compose_for_test(&[draft], bob)
            .expect_err("Bob should not be allowed to register pin manifests");
        match err {
            ComposeError::UnauthorizedInstruction { action, .. } => {
                assert_eq!(action, InstructionPermission::RegisterPinManifest);
            }
            other => panic!("unexpected compose error: {other:?}"),
        }
    }
    #[test]
    fn compose_preview_rejects_unauthorised_space_directory_manifest() {
        let authorities = development_signing_authorities();
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let manifest_json = r#"{
  "version": 1,
  "uaid": "uaid:62af083a61d42ca6c269585b9a33c563f4e0a5c0726614f7a98b6aab6b98f70b",
  "dataspace": 12,
  "issued_ms": 1710000000000,
  "activation_epoch": 500,
  "expiry_epoch": 550,
  "entries": []
}"#;
        let draft = InstructionDraft::publish_space_directory_manifest_from_json(manifest_json)
            .expect("space directory draft");
        let err = compose_for_test(&[draft], bob)
            .expect_err("Bob should not be allowed to publish space directory manifests");
        match err {
            ComposeError::UnauthorizedInstruction { action, .. } => {
                assert_eq!(action, InstructionPermission::PublishSpaceDirectoryManifest);
            }
            other => panic!("unexpected compose error: {other:?}"),
        }
    }
    #[test]
    fn compose_preview_rejects_unauthorised_pin_manifest() {
        let authorities = development_signing_authorities();
        let bob = authorities
            .iter()
            .find(|auth| auth.label() == "Bob (dev)")
            .expect("Bob signer present");
        let pin_manifest_json = r#"{
  "manifest_payload": "TlJUMAAAduKskROcpAXus8dyJtDtlwD5AAAAAAAAAP11VCbJ+r+OAgEBLCQAAAAAAAAAAXEfIGIKrspjqahUS44Ka/oZKH+vxtnoUoM+vR660uOpRn5yCQhxAAAAAAAAAF4FBAEAAAAHBnNvcmFmcwQDc2YxBgUxLjAuMAQAAAEABAAABAAEAAAIAAT//wAACB8AAAAAAAAAJgIAAAAAAAAAERBzb3JhZnMuc2YxQDEuMC4wCwpzb3JhZnMtc2YxCAAAEAAAAAAAIM5QqarfhOV1WSCNOSAWISYv0bGIeuSQylRHDioAFT8nCNwEEAAAAAAAEQIDAAQAAAAACIBRAQAAAAAACQgAAAAAAAAAAAgAAAAAAAAAAAgAAAAAAAAAAA==",
  "alias": null,
  "successor_of": null
}"#;
        let draft = InstructionDraft::register_pin_manifest_from_json(pin_manifest_json)
            .expect("pin manifest draft");
        let err = compose_for_test(&[draft], bob)
            .expect_err("Bob should not be allowed to register pin manifests");
        match err {
            ComposeError::UnauthorizedInstruction { action, .. } => {
                assert_eq!(action, InstructionPermission::RegisterPinManifest);
            }
            other => panic!("unexpected compose error: {other:?}"),
        }
    }
    #[test]
    fn compose_preview_with_options_applies_overrides() {
        let authorities = development_signing_authorities();
        let signer = authorities
            .iter()
            .find(|auth| auth.allows_permission(InstructionPermission::MintAsset))
            .expect("signer with mint permission present");
        let account = account_literal(signer.account_id());
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("definition id");
        let asset_id = format!("{asset_def}#{account}");
        let draft = InstructionDraft::mint_from_input(&asset_id, "5").expect("mint draft");
        let options = TransactionComposeOptions::new()
            .with_ttl(Duration::from_secs(5))
            .with_creation_time(Duration::from_millis(1_234))
            .with_nonce(NonZeroU32::new(42).expect("non-zero nonce"));
        let preview = compose_preview_with_options(test_network_id(), &[draft], signer, &options)
            .expect("compose with overrides");
        assert_eq!(
            preview.time_to_live(),
            Some(Duration::from_secs(5)),
            "expected TTL override to propagate into preview"
        );
        assert_eq!(
            preview.creation_time(),
            Duration::from_millis(1_234),
            "expected creation time override to propagate"
        );
        assert_eq!(
            preview.nonce(),
            NonZeroU32::new(42),
            "nonce override should propagate"
        );
        preview
            .signed_transaction()
            .verify_signature()
            .expect("checked composed transaction signature verifies");
    }
}
