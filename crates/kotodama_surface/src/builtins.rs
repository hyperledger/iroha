//! Shared builtin classification for the stable Kotodama helper surface.
//!
//! The parser still sees raw identifiers, but semantic analysis, lowering, and effect checks should
//! agree on the canonical builtin set through this enum instead of open-coded string matching.
/// Typed pointer ABI constructors recognized by compiler lowering.
///
/// Only constructors whose enclosing [`Builtin`] has a source-visible surface
/// are part of Kotodama V1; the remaining variants are host/compiler plumbing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum PointerConstructor {
    /// Parse an account identity into an `AccountId` pointer.
    #[default]
    AccountId,
    /// Parse an asset definition identity into an `AssetDefinitionId` pointer.
    AssetDefinition,
    /// Parse an asset identity into an `AssetId` pointer.
    AssetId,
    /// Parse an NFT identity into an `NftId` pointer.
    NftId,
    /// Parse a validated ledger `Name` pointer.
    Name,
    /// Parse a `Json` pointer from its string representation.
    Json,
    /// Internal constructor for a `DomainId` pointer.
    Domain,
    /// Parse a domain identity into a `DomainId` pointer.
    DomainId,
    /// Internal constructor for a byte-buffer pointer.
    Blob,
    /// Internal constructor for Norito-encoded bytes.
    NoritoBytes,
    /// Parse a dataspace identity into a `DataSpaceId` pointer.
    DataSpaceId,
    /// Parse an atomic cross-dataspace transaction descriptor.
    AxtDescriptor,
    /// Parse a V1 anchored-spend descriptor for an atomic cross-dataspace transaction.
    AxtAnchoredSpendV1,
    /// Internal constructor for an opaque proof pointer.
    ProofBlob,
    /// Internal constructor for a typed Soracloud host request.
    SoracloudRequest,
    /// Internal constructor for a typed Soracloud host response.
    SoracloudResponse,
}
impl PointerConstructor {
    /// Resolve a pointer constructor by its compiler-internal spelling.
    ///
    /// Source visibility is determined by the enclosing [`Builtin`] registry entry.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "account_id" => Self::AccountId,
            "asset_definition" => Self::AssetDefinition,
            "asset_id" => Self::AssetId,
            "nft_id" => Self::NftId,
            "name" => Self::Name,
            "json" => Self::Json,
            "domain" => Self::Domain,
            "domain_id" => Self::DomainId,
            "blob" => Self::Blob,
            "norito_bytes" => Self::NoritoBytes,
            "dataspace_id" => Self::DataSpaceId,
            "axt_descriptor" => Self::AxtDescriptor,
            "axt_anchored_spend_v1" => Self::AxtAnchoredSpendV1,
            "proof_blob" => Self::ProofBlob,
            "soracloud_request" => Self::SoracloudRequest,
            "soracloud_response" => Self::SoracloudResponse,
            _ => return None,
        })
    }
    /// Return the canonical compiler-internal spelling of this constructor.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AccountId => "account_id",
            Self::AssetDefinition => "asset_definition",
            Self::AssetId => "asset_id",
            Self::NftId => "nft_id",
            Self::Name => "name",
            Self::Json => "json",
            Self::Domain => "domain",
            Self::DomainId => "domain_id",
            Self::Blob => "blob",
            Self::NoritoBytes => "norito_bytes",
            Self::DataSpaceId => "dataspace_id",
            Self::AxtDescriptor => "axt_descriptor",
            Self::AxtAnchoredSpendV1 => "axt_anchored_spend_v1",
            Self::ProofBlob => "proof_blob",
            Self::SoracloudRequest => "soracloud_request",
            Self::SoracloudResponse => "soracloud_response",
        }
    }
    const fn return_type_name(self) -> &'static str {
        match self {
            Self::AccountId => "AccountId",
            Self::AssetDefinition => "AssetDefinitionId",
            Self::AssetId => "AssetId",
            Self::NftId => "NftId",
            Self::Name => "Name",
            Self::Json => "Json",
            Self::Domain | Self::DomainId => "DomainId",
            Self::Blob | Self::NoritoBytes => "bytes",
            Self::DataSpaceId => "DataSpaceId",
            Self::AxtDescriptor => "AxtDescriptor",
            Self::AxtAnchoredSpendV1 => "AxtAnchoredSpendV1",
            Self::ProofBlob => "ProofBlob",
            Self::SoracloudRequest => "SoracloudRequest",
            Self::SoracloudResponse => "SoracloudResponse",
        }
    }
}
/// Security-relevant effects produced by a builtin call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuiltinEffects {
    /// The call can observe or mutate host-managed state beyond ordinary reads.
    pub host_side_effects: bool,
    /// The call submits an Iroha instruction or invokes another contract.
    pub emits_instructions: bool,
    /// The call mutates contract-owned durable state.
    pub mutates_durable_state: bool,
}
impl BuiltinEffects {
    /// No externally visible effects.
    pub const NONE: Self = Self {
        host_side_effects: false,
        emits_instructions: false,
        mutates_durable_state: false,
    };
    /// Host-managed effect requiring kotoage authorization.
    pub const HOST: Self = Self {
        host_side_effects: true,
        ..Self::NONE
    };
    /// Iroha instruction emission requiring kotoage authorization.
    pub const INSTRUCTION: Self = Self {
        emits_instructions: true,
        ..Self::NONE
    };
    /// Seiyaku durable-state mutation requiring kotoage authorization.
    pub const DURABLE_STATE: Self = Self {
        mutates_durable_state: true,
        ..Self::NONE
    };
}
/// Coarse scheduler access class for a builtin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuiltinAccess {
    /// No world or durable-state access.
    #[default]
    None,
    /// Contract durable-state read.
    StateRead,
    /// Contract durable-state write.
    StateWrite,
    /// Ledger read whose exact key is derived separately.
    LedgerRead,
    /// Ledger write whose exact key is derived separately.
    LedgerWrite,
    /// Dynamic access that must conservatively serialize when unresolved.
    Dynamic,
}
/// Execution mode required by a builtin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuiltinMode {
    /// Available to ordinary contracts.
    #[default]
    Any,
    /// Available only when compiler build policy enables ZK mode.
    ZkOnly,
    /// Available only to local test builds or `#[test]` functions.
    TestOnly,
    /// Available only inside a `#[test]` function (never ordinary seiyaku code).
    TestFunctionOnly,
    /// Compiler/runtime implementation detail, not a V1 source API.
    CompilerInternal,
}
/// Coarse gas model used for compiler and host consistency checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuiltinGasClass {
    /// Fixed-cost pure operation.
    #[default]
    Constant,
    /// Cost scales with an input byte or element count.
    LinearInput,
    /// The host quotes the deterministic cost before execution.
    HostQuoted,
}
/// Source-call form admitted for a builtin.
///
/// Method calls are desugared to an internal free-call shape after parsing, so this classification
/// must remain separate from [`BuiltinMode`]. In particular, a method-only helper must never become
/// a source-visible global merely because lowering recognizes its internal name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinSurface {
    /// A canonical namespaced (or language-intrinsic) free function.
    Function,
    /// A receiver method only; the parser rejects the equivalent free call.
    MethodOnly,
    /// Both a canonical namespaced function and a receiver method.
    FunctionOrMethod,
    /// Not callable from V1 source.
    CompilerInternal,
}
/// How a builtin reaches the IVM host boundary.
///
/// The syscall list contains operation syscalls only. Pointer publication is
/// ABI plumbing shared by many calls and is deliberately not repeated here.
/// Keeping direct and derived calls distinct lets security tests prove that a
/// helper cannot hide a privileged operation behind apparently pure lowering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinLowering {
    /// Lowers entirely to deterministic IVM instructions or static data.
    Instructions,
    /// Lowers one-to-one to the single operation syscall in the spec.
    DirectSyscall,
    /// Expands to a compiler-owned sequence that can issue these operation syscalls recorded in the
    /// spec. The list is exhaustive for every control-flow path.
    DerivedSyscalls,
}
/// Machine-readable source signature for a builtin.
///
/// Parameter descriptors use canonical Kotodama type names. `A|B` denotes a
/// closed union, a trailing `?` denotes an optional final parameter, and a
/// trailing `...` denotes a homogeneous variadic tail. Generic relationships
/// such as `K`, `V`, and `same-as-arg0` are resolved by semantic analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinSignature {
    /// Ordered source parameter names used by named calls.
    pub parameter_names: &'static [&'static str],
    /// Ordered parameter type descriptors.
    pub parameters: &'static [&'static str],
    /// Return type descriptor.
    pub return_type: &'static str,
}
impl BuiltinSignature {
    const fn new(parameters: &'static [&'static str], return_type: &'static str) -> Self {
        Self {
            parameter_names: default_parameter_names(parameters.len()),
            parameters,
            return_type,
        }
    }
    const fn with_names(mut self, parameter_names: &'static [&'static str]) -> Self {
        self.parameter_names = parameter_names;
        self
    }
}
const fn default_parameter_names(arity: usize) -> &'static [&'static str] {
    match arity {
        1 => &["value"],
        2 => &["first", "second"],
        3 => &["first", "second", "third"],
        4 => &["first", "second", "third", "fourth"],
        5 => &["first", "second", "third", "fourth", "fifth"],
        6 => &["first", "second", "third", "fourth", "fifth", "sixth"],
        7 => &[
            "first", "second", "third", "fourth", "fifth", "sixth", "seventh",
        ],
        8 => &[
            "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth",
        ],
        _ => &[],
    }
}
/// Source argument policy attached to a builtin declaration.
///
/// Every builtin follows one published rule:
///
/// 1. A label equal to the declared parameter name is always accepted.
/// 2. Single-argument calls, receiver methods and pure helpers (`math::*`,
///    `require`) also accept positional arguments.
/// 3. Every other builtin, including each multi-argument `ledger::*`
///    mutation, requires its labels. A bare identifier whose name equals the
///    label of the slot it fills satisfies that label (label punning), so
///    `ledger::nft::mint(nft, owner)` is the labelled call
///    `ledger::nft::mint(nft: nft, owner: owner)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BuiltinCallPolicy {
    /// Every declared source parameter requires its label; label punning
    /// satisfies the requirement.
    #[default]
    Named,
    /// This many leading declaration parameters may be passed positionally or
    /// with their declared labels; later parameters require labels. An
    /// implicit method receiver consumes the first declaration slot.
    PositionalPrefix(usize),
}
impl BuiltinCallPolicy {
    /// Whether the declaration slot `index` (counting an implicit receiver as
    /// slot zero) requires a label or a punned identifier.
    #[must_use]
    pub const fn label_required(self, index: usize) -> bool {
        match self {
            Self::Named => true,
            Self::PositionalPrefix(prefix) => index >= prefix,
        }
    }
}
/// Canonical security and lowering metadata for one builtin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinSpec {
    /// Canonical source spelling.
    pub name: &'static str,
    /// Security-relevant effects.
    pub effects: BuiltinEffects,
    /// Scheduler access class.
    pub access: BuiltinAccess,
    /// Required execution mode.
    pub mode: BuiltinMode,
    /// Source-call form admitted by the V1 grammar.
    pub surface: BuiltinSurface,
    /// Gas charging class.
    pub gas: BuiltinGasClass,
    /// Exact operation-level lowering classification.
    pub lowering: BuiltinLowering,
    /// Complete set of operation syscalls reachable from the builtin.
    pub operation_syscalls: &'static [u32],
    /// Direct syscall number, when the builtin lowers one-to-one to a syscall.
    pub syscall: Option<u32>,
    /// Canonical parameter and return types.
    pub signature: BuiltinSignature,
    /// Source argument policy.
    pub call_policy: BuiltinCallPolicy,
}
/// Canonical Kotodama helper/builtin calls that are part of the current source
/// surface and are worth classifying centrally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum Builtin {
    /// Construct the selected typed pointer-ABI value from a string.
    PointerConstructor(PointerConstructor),
    /// Check whether a durable state map contains a key.
    Contains,
    /// Return a durable state map value, first writing the supplied default when the key is absent.
    GetOrInsert,
    /// Remove a durable state map entry and return its previous optional value.
    StateMapRemove,
    /// Internal bounded key scan of an integer-keyed state map.
    KeysTake2,
    /// Internal bounded value scan of an integer-valued state map.
    ValuesTake2,
    /// Internal bounded key/value scan of an integer state map.
    KeysValuesTake2,
    /// Read the byte value at a durable state path.
    StateGet,
    /// Write a byte value at a durable state path.
    StateSet,
    /// Delete the value at a durable state path.
    StateDel,
    /// Check whether a durable state path exists.
    StateHas,
    /// Read the length reported by the durable state path syscall.
    StateLen,
    /// Count entries under a durable state path.
    StateCount,
    /// Internal execution of a Norito-encoded host query.
    QueryExecuteNorito,
    /// Query the optional projected view of an account.
    QueryGetAccount,
    /// Query the optional projected view of an asset.
    QueryGetAsset,
    /// Query the optional projected view of an asset definition.
    QueryGetAssetDefinition,
    /// Query the optional projected view of a domain.
    QueryGetDomain,
    /// Query the optional projected view of an NFT.
    QueryGetNft,
    /// Query a bounded page of projected account views.
    QueryPageAccounts,
    /// Query a bounded page of projected asset views.
    QueryPageAssets,
    /// Query a bounded asset page filtered by its exact account owner.
    QueryPageAssetsOf,
    /// Query a bounded page of projected asset definition views.
    QueryPageAssetDefinitions,
    /// Query a bounded page of projected domain views.
    QueryPageDomains,
    /// Query a bounded page of projected NFT views.
    QueryPageNfts,
    /// Query a named ledger parameter.
    QueryGetParameter,
    /// Query an encoded seiyaku manifest.
    QueryGetContractManifest,
    /// Query a named seiyaku instance.
    QueryGetContractInstance,
    /// Internal execution of an encoded smart-contract query.
    ExecuteQuery,
    /// Submit the encoded governance ballot instruction.
    ScExecuteSubmitBallot,
    /// Resolve an account alias to its canonical account identity.
    ResolveAccountAlias,
    /// Bill the active host-managed subscription.
    SubscriptionBill,
    /// Record usage for the active host-managed subscription.
    SubscriptionRecordUsage,
    /// Read the quantity held by an account for an asset definition.
    GetAccountBalance,
    /// Read a named public input as bytes.
    GetPublicInput,
    /// Internal integer debug-output syscall.
    DebugPrint,
    /// Internal string debug-log syscall.
    DebugLog,
    /// Assert a condition in a local test build.
    Assert,
    /// Reject contract execution with a typed error when a condition is false.
    Require,
    /// Emit an informational debug record for a string or integer.
    Info,
    /// Assert that two values of one equality-comparable type are equal in a local test build.
    AssertEq,
    /// Invoke a runtime kotoage from a test using the current caller.
    TestInvokeEntrypoint,
    /// Invoke a runtime kotoage from a test as a fixture actor.
    TestInvokeEntrypointAs,
    /// Require a fixture-actor invocation to produce the expected rejection.
    TestExpectRejectAs,
    /// Require a fixture-actor invocation to reject.
    TestExpectAnyRejectAs,
    /// Read a fixture actor's canonical account identity.
    TestActorAccount,
    /// Read a fixture actor's public key bytes.
    TestActorPublicKey,
    /// Sign a payload with a fixture actor's test key.
    TestActorSign,
    /// Set the block height seen by later seiyaku calls in a local test.
    TestSetBlockHeight,
    /// Advance the block height seen by later seiyaku calls in a local test.
    TestAdvanceBlocks,
    /// Set the transaction time (milliseconds) seen by later seiyaku calls in a local test.
    TestSetTransactionTimeMs,
    /// Set one JSON metadata entry on an account.
    SetAccountMetadata,
    /// Mint an asset quantity for an account.
    MintAsset,
    /// Burn an asset quantity held by an account.
    BurnAsset,
    /// Transfer an asset quantity between accounts, optionally scoped to a dataspace.
    TransferAsset,
    /// Update an account asset's transfer availability at an expected revision.
    SetAssetTransferAvailability,
    /// Set or remove an account asset's daily transfer cap.
    SetAssetTransferDailyLimit,
    /// Set or remove an account asset's holding limit.
    SetAssetHoldingLimit,
    /// Propose an alias account-recovery replacement for a request generation.
    AccountRecoveryPropose,
    /// Approve an alias account-recovery request generation.
    AccountRecoveryApprove,
    /// Cancel an alias account-recovery request generation.
    AccountRecoveryCancel,
    /// Finalize an alias account-recovery request generation.
    AccountRecoveryFinalize,
    /// Mint an NFT for its owner.
    NftMintAsset,
    /// Set one JSON metadata entry on an NFT.
    NftSetMetadata,
    /// Burn an NFT.
    NftBurnAsset,
    /// Transfer an NFT between accounts.
    NftTransferAsset,
    /// Register a ledger domain.
    RegisterDomain,
    /// Unregister a ledger domain.
    UnregisterDomain,
    /// Transfer ownership of a ledger domain between accounts.
    TransferDomain,
    /// Register a canonical account identity.
    RegisterAccount,
    /// Unregister an account.
    UnregisterAccount,
    /// Register an asset definition with its display name, numeric spec and mintability.
    RegisterAsset,
    /// Unregister an asset definition.
    UnregisterAsset,
    /// Register a peer described by JSON.
    RegisterPeer,
    /// Unregister a peer described by JSON.
    UnregisterPeer,
    /// Register a trigger described by JSON.
    RegisterTrigger,
    /// Unregister a named trigger.
    UnregisterTrigger,
    /// Change a named trigger's enabled state.
    SetTriggerEnabled,
    /// Register a named role with a JSON permission set.
    RegisterRole,
    /// Unregister a named role.
    UnregisterRole,
    /// Grant a role to an account.
    GrantRole,
    /// Revoke a role from an account.
    RevokeRole,
    /// Grant a permission to an account.
    GrantPermission,
    /// Revoke a permission from an account.
    RevokePermission,
    /// Grant an account a declared permission of the executing seiyaku instance.
    GrantContractPermission,
    /// Revoke an account's declared permission of the executing seiyaku instance.
    RevokeContractPermission,
    /// Open an escrow offer with an asset quantity and optional evidence.
    EscrowOpenOffer,
    /// Accept a named escrow offer.
    EscrowAccept,
    /// Mark payment as sent for a named escrow offer.
    EscrowMarkPaymentSent,
    /// Release a named escrow offer.
    EscrowRelease,
    /// Cancel a named escrow offer.
    EscrowCancel,
    /// Open a dispute for an escrow offer with optional evidence.
    EscrowOpenDispute,
    /// Resolve an escrow dispute with buyer and seller quantities.
    EscrowResolveDispute,
    /// Read a private numeric input in ZK mode.
    GetPrivateInput,
    /// Commit the current output in ZK mode.
    CommitOutput,
    /// Request host creation of NFTs for all users.
    CreateNftsForAllUsers,
    /// Internal mutation of the host execution-depth limit.
    SetExecutionDepth,
    /// Lower a bounded list of asset transfers to a host-managed batch.
    TransferBatch,
    /// Begin an atomic cross-dataspace transaction using its descriptor.
    AxtBegin,
    /// Declare a dataspace touch and its manifest in an atomic transaction.
    AxtTouch,
    /// Stage a V1 anchored spend in an atomic cross-dataspace transaction.
    StageAnchoredSpend,
    /// Internal verification of a dataspace proof.
    VerifyDsProof,
    /// Commit the active atomic cross-dataspace transaction.
    AxtCommit,
    /// Internal request to deactivate a seiyaku instance.
    DeactivateContractInstance,
    /// Internal request to remove registered seiyaku code bytes.
    RemoveSmartContractBytes,
    /// Internal request to register seiyaku code.
    RegisterSmartContractCode,
    /// Internal request to register seiyaku bytecode.
    RegisterSmartContractBytes,
    /// Internal request to activate a seiyaku instance.
    ActivateContractInstance,
    /// Read encoded roots from the host ZK registry.
    ZkRootsGet,
    /// Read an encoded governance vote tally.
    ZkVoteGetTally,
    /// Ask the host to verify an encoded ZK proof batch.
    ZkVerifyBatch,
    /// Ask the host to verify an encoded governance ballot.
    ZkVoteVerifyBallot,
    /// Ask the host to verify an encoded governance tally.
    ZkVoteVerifyTally,
    /// Build an encoded governance ballot instruction from its proof fields.
    BuildSubmitBallotInline,
    /// Read an encoded VRF epoch seed.
    VrfEpochSeed,
    /// Verify an encoded VRF request and return its response.
    VrfVerify,
    /// Verify an encoded batch of VRF requests and return its response.
    VrfVerifyBatch,
    /// Hash bytes with SM3.
    Sm3Hash,
    /// Hash bytes with SHA-256.
    Sha256Hash,
    /// Hash bytes with SHA-3.
    Sha3Hash,
    /// Hash bytes with BLAKE2b-256.
    Blake2b256Hash,
    /// Hash bytes with Keccak-256.
    Keccak256Hash,
    /// Hash bytes with the canonical Iroha hash operation.
    IrohaHash,
    /// Verify an SM2 signature with an optional distinguishing identifier.
    Sm2Verify,
    /// Verify a signature under a compile-time `SignatureScheme` value.
    VerifySignature,
    /// Seal bytes using SM4-GCM with nonce and associated data.
    Sm4GcmSeal,
    /// Open authenticated bytes using SM4-GCM.
    Sm4GcmOpen,
    /// Seal bytes using SM4-CCM with an optional tag length.
    Sm4CcmSeal,
    /// Open authenticated bytes using SM4-CCM.
    Sm4CcmOpen,
    /// Internal heap allocation helper.
    Alloc,
    /// Read the encoded execution summary.
    ExecutionSummary,
    /// Internal heap-growth helper.
    GrowHeap,
    /// Verify an encoded proof through the host.
    VerifyProof,
    /// Internal memory Merkle-path extraction helper.
    GetMerklePath,
    /// Internal compact memory Merkle-path extraction helper.
    GetMerkleCompact,
    /// Internal compact register Merkle-path extraction helper.
    GetRegisterMerkleCompact,
    /// Internal Soracloud committed-state read request.
    SoracloudReadCommittedState,
    /// Internal Soracloud state-mutation request.
    SoracloudEmitStateMutation,
    /// Internal Soracloud mailbox-message emission request.
    SoracloudEmitMailboxMessage,
    /// Internal Soracloud journal-append request.
    SoracloudAppendJournal,
    /// Internal Soracloud checkpoint-publication request.
    SoracloudPublishCheckpoint,
    /// Internal Soracloud configuration read request.
    SoracloudReadConfig,
    /// Internal Soracloud secret-envelope read request.
    SoracloudReadSecretEnvelope,
    /// Add a signatory to an account.
    AddSignatory,
    /// Remove a signatory from an account.
    RemoveSignatory,
    /// Set an account's signature quorum.
    SetAccountQuorum,
    /// Build a durable state path key through its receiver method.
    Path,
    /// Internal decoding of a ledger `Name` from bytes.
    NameDecode,
    /// Internal equality check of two pointer-ABI values.
    TlvEq,
    /// Internal length query for a pointer-ABI value.
    TlvLen,
    /// Read the length of a byte value.
    BytesLen,
    /// Encode a public value using its canonical typed Norito record.
    ValueEncode,
    /// Concatenate two byte values.
    BytesConcat,
    /// Concatenate two UTF-8 strings.
    StringConcat,
    /// Return the UTF-8 byte length of a string.
    StringLen,
    /// Expose the UTF-8 bytes of a string.
    StringAsBytes,
    /// Validate UTF-8 bytes and return an optional string.
    StringFromBytes,
    /// Render a public scalar as its canonical string.
    StringFrom,

    /// Internal encoding of a pointer-ABI value as Norito bytes.
    PointerToNorito,
    /// Create an empty JSON object.
    JsonObject,
    /// Internal scalar integer setter for a JSON object.
    JsonSetInt,
    /// Set an account identity in a JSON object.
    JsonSetAccountId,
    /// Internal encoding of JSON to bytes.
    EncodeJson,
    /// Internal decoding of JSON from bytes.
    DecodeJson,
    /// Internal encoding of JSON according to a named schema.
    SchemaEncode,
    /// Internal decoding of bytes according to a named schema.
    SchemaDecode,
    /// Internal query of a named schema's JSON description.
    SchemaInfo,
    /// Internal exact conversion of a wide numeric value to an integer.
    NumericToInt,
    /// Internal lowering of integer or decimal negation.
    NumericNeg,
    /// Internal lowering of wide numeric addition.
    NumericAdd,
    /// Internal lowering of wide numeric subtraction.
    NumericSub,
    /// Internal lowering of wide numeric multiplication.
    NumericMul,
    /// Internal lowering of wide numeric division.
    NumericDiv,
    /// Internal lowering of integer remainder.
    NumericRem,
    /// Internal lowering of wide numeric equality.
    NumericEq,
    /// Internal lowering of wide numeric inequality.
    NumericNe,
    /// Internal lowering of wide numeric less-than comparison.
    NumericLt,
    /// Internal lowering of wide numeric less-than-or-equal comparison.
    NumericLe,
    /// Internal lowering of wide numeric greater-than comparison.
    NumericGt,
    /// Internal lowering of wide numeric greater-than-or-equal comparison.
    NumericGe,
    /// Internal instruction-only numeric-to-integer helper.
    NumericToIntDirect,
    /// Internal instruction-only numeric addition helper.
    NumericAddDirect,
    /// Internal instruction-only numeric subtraction helper.
    NumericSubDirect,
    /// Internal instruction-only numeric multiplication helper.
    NumericMulDirect,
    /// Internal instruction-only numeric division helper.
    NumericDivDirect,
    /// Internal instruction-only numeric remainder helper.
    NumericRemDirect,
    /// Internal instruction-only numeric negation helper.
    NumericNegDirect,
    /// Internal instruction-only numeric equality helper.
    NumericEqDirect,
    /// Internal instruction-only numeric inequality helper.
    NumericNeDirect,
    /// Internal instruction-only numeric less-than comparison helper.
    NumericLtDirect,
    /// Internal instruction-only numeric less-than-or-equal comparison helper.
    NumericLeDirect,
    /// Internal instruction-only numeric greater-than comparison helper.
    NumericGtDirect,
    /// Internal instruction-only numeric greater-than-or-equal comparison helper.
    NumericGeDirect,
    /// Explicit modulo-2^512 `int` addition.
    WrappingAdd,
    /// Explicit modulo-2^512 `int` subtraction.
    WrappingSub,
    /// Explicit modulo-2^512 `int` multiplication.
    WrappingMul,
    /// Explicit modulo-2^512 `int` negation.
    WrappingNeg,
    /// Compute the integer square root.
    Isqrt,
    /// Compute an integer's absolute value.
    Abs,
    /// Select the smaller of two integers.
    Min,
    /// Select the larger of two integers.
    Max,
    /// Divide integers with rounding toward positive infinity.
    DivCeil,
    /// Compute the greatest common divisor of two integers.
    Gcd,
    /// Compute the integer mean of two integers.
    Mean,
    /// Internal Poseidon helper over two scalar register values.
    Poseidon2,
    /// Internal Poseidon helper over six scalar register values.
    Poseidon6,
    /// Internal public-key generation helper over a scalar register value.
    Pubkgen,
    /// Commit secret numeric values in ZK mode.
    Valcom,
    /// Internal vector-length selection helper.
    SetVl,
    /// Read an optional integer field from JSON.
    GetInt,
    /// Read an optional decimal field from JSON.
    GetDecimal,
    /// Read an optional quantity field from JSON.
    GetQuantity,
    /// Read an optional nested JSON field.
    GetJson,
    /// Read an optional ledger name field from JSON.
    GetName,
    /// Read an optional account identity field from JSON.
    GetAccountId,
    /// Read an optional asset definition identity field from JSON.
    GetAssetDefinitionId,
    /// Read an optional NFT identity field from JSON.
    GetNftId,
    /// Read an optional byte field encoded as hexadecimal in JSON.
    GetBytesHex,
    /// Read an optional string field from JSON.
    GetString,
    /// Read an optional boolean field from JSON.
    GetBool,
    /// Read the current trigger event as JSON.
    TriggerEvent,
    /// Read the current execution authority.
    Authority,
    /// Read the current seiyaku subject account.
    ContractSubject,
    /// Read the signer-supplied transaction creation time in milliseconds.
    TransactionTimeMs,
    /// Read the current block height.
    BlockHeight,
    /// Internal `SYSVAR_BLOCK_TIME_MS` read; hosts bind it to the same logical
    /// time as [`Self::TransactionTimeMs`], so it is not a source clock.
    BlockTimeMs,
    /// Read the encoded chain identity.
    ChainId,
    /// Read the encoded seiyaku address.
    ContractAddress,
    /// Read the current kotoage name as bytes.
    Entrypoint,
    /// Internal system-variable read of the execution authority.
    SysvarAuthority,
    /// Compile-time `NumericSpec` that accepts any scale.
    NumericSpecUnconstrained,
    /// Compile-time `NumericSpec` that accepts integers only.
    NumericSpecInteger,
    /// Compile-time `NumericSpec` that accepts at most the given decimal scale.
    NumericSpecFractional,
    /// Compile-time `Mintable` value for elastic supply.
    MintableInfinitely,
    /// Compile-time `Mintable` value allowing exactly one mint.
    MintableOnce,
    /// Compile-time `Mintable` value forbidding mints.
    MintableNot,
    /// Compile-time `Mintable` value allowing a limited number of mints.
    MintableLimited,
    /// Compile-time `SignatureScheme` value selecting Ed25519.
    SignatureSchemeEd25519,
    /// Compile-time `SignatureScheme` value selecting secp256k1 ECDSA.
    SignatureSchemeSecp256k1,
    /// Compile-time `SignatureScheme` value selecting ML-DSA.
    SignatureSchemeMlDsa,
}
impl Builtin {
    /// Iterate over every canonical builtin variant.
    ///
    /// Both enums derive their iterators from their declarations, so adding a variant automatically
    /// expands this fail-closed registry. The payload placeholder emitted for `PointerConstructor`
    /// by `EnumIter` is replaced with every pointer-constructor variant.
    pub fn all() -> impl Iterator<Item = Self> {
        use strum::IntoEnumIterator as _;
        PointerConstructor::iter()
            .map(Self::PointerConstructor)
            .chain(Self::iter().filter(|builtin| !matches!(builtin, Self::PointerConstructor(_))))
    }
    /// Iterate over the single exhaustive builtin security registry.
    ///
    /// Every record includes the signature, effects, scheduler access, gas
    /// class, allowed mode, lowering class, and complete operation syscall set.
    pub fn registry() -> impl Iterator<Item = (Self, BuiltinSpec)> {
        Self::all().map(|builtin| (builtin, builtin.spec()))
    }
    /// Resolve a builtin from its canonical compiler-internal spelling.
    ///
    /// Source resolution must use [`Self::from_source_name`] so an internal
    /// lowering name cannot accidentally become a public language feature.
    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(constructor) = PointerConstructor::from_name(name) {
            return Some(Self::PointerConstructor(constructor));
        }
        Some(match name {
            "contains" => Self::Contains,
            "get_or_insert" => Self::GetOrInsert,
            "remove" => Self::StateMapRemove,
            "keys_take2" => Self::KeysTake2,
            "values_take2" => Self::ValuesTake2,
            "keys_values_take2" => Self::KeysValuesTake2,
            "state_get" => Self::StateGet,
            "state_set" => Self::StateSet,
            "state_del" => Self::StateDel,
            "state_has" => Self::StateHas,
            "state_len" => Self::StateLen,
            "state_count" => Self::StateCount,
            "query_execute_norito" => Self::QueryExecuteNorito,
            "query_get_account" => Self::QueryGetAccount,
            "query_get_asset" => Self::QueryGetAsset,
            "query_get_asset_definition" => Self::QueryGetAssetDefinition,
            "query_get_domain" => Self::QueryGetDomain,
            "query_get_nft" => Self::QueryGetNft,
            "query_page_accounts" => Self::QueryPageAccounts,
            "query_page_assets" => Self::QueryPageAssets,
            "query_page_assets_of" => Self::QueryPageAssetsOf,
            "query_page_asset_definitions" => Self::QueryPageAssetDefinitions,
            "query_page_domains" => Self::QueryPageDomains,
            "query_page_nfts" => Self::QueryPageNfts,
            "query_get_parameter" => Self::QueryGetParameter,
            "query_get_contract_manifest" => Self::QueryGetContractManifest,
            "query_get_contract_instance" => Self::QueryGetContractInstance,
            "execute_query" => Self::ExecuteQuery,
            "sc_execute_submit_ballot" => Self::ScExecuteSubmitBallot,
            "resolve_account_alias" => Self::ResolveAccountAlias,
            "subscription_bill" => Self::SubscriptionBill,
            "subscription_record_usage" => Self::SubscriptionRecordUsage,
            "get_account_balance" => Self::GetAccountBalance,
            "get_public_input" => Self::GetPublicInput,
            "debug_print" => Self::DebugPrint,
            "debug_log" => Self::DebugLog,
            "assert" => Self::Assert,
            "require" => Self::Require,
            "info" => Self::Info,
            "assert_eq" => Self::AssertEq,
            "invoke_entrypoint" => Self::TestInvokeEntrypoint,
            "invoke_entrypoint_as" => Self::TestInvokeEntrypointAs,
            "expect_reject_as" => Self::TestExpectRejectAs,
            "expect_any_reject_as" => Self::TestExpectAnyRejectAs,
            "actor_account" => Self::TestActorAccount,
            "actor_public_key" => Self::TestActorPublicKey,
            "actor_sign" => Self::TestActorSign,
            "set_block_height" => Self::TestSetBlockHeight,
            "advance_blocks" => Self::TestAdvanceBlocks,
            "set_transaction_time_ms" => Self::TestSetTransactionTimeMs,
            "set_account_metadata" => Self::SetAccountMetadata,
            "mint_asset" => Self::MintAsset,
            "burn_asset" => Self::BurnAsset,
            "transfer_asset" => Self::TransferAsset,
            "set_asset_transfer_availability" => Self::SetAssetTransferAvailability,
            "set_asset_transfer_daily_limit" => Self::SetAssetTransferDailyLimit,
            "set_asset_holding_limit" => Self::SetAssetHoldingLimit,
            "account_recovery_propose" => Self::AccountRecoveryPropose,
            "account_recovery_approve" => Self::AccountRecoveryApprove,
            "account_recovery_cancel" => Self::AccountRecoveryCancel,
            "account_recovery_finalize" => Self::AccountRecoveryFinalize,
            "nft_mint_asset" => Self::NftMintAsset,
            "nft_set_metadata" => Self::NftSetMetadata,
            "nft_burn_asset" => Self::NftBurnAsset,
            "nft_transfer_asset" => Self::NftTransferAsset,
            "register_domain" => Self::RegisterDomain,
            "unregister_domain" => Self::UnregisterDomain,
            "transfer_domain" => Self::TransferDomain,
            "register_account" => Self::RegisterAccount,
            "unregister_account" => Self::UnregisterAccount,
            "register_asset" => Self::RegisterAsset,
            "unregister_asset" => Self::UnregisterAsset,
            "register_peer" => Self::RegisterPeer,
            "unregister_peer" => Self::UnregisterPeer,
            "register_trigger" => Self::RegisterTrigger,
            "unregister_trigger" => Self::UnregisterTrigger,
            "set_trigger_enabled" => Self::SetTriggerEnabled,
            "register_role" => Self::RegisterRole,
            "unregister_role" => Self::UnregisterRole,
            "grant_role" => Self::GrantRole,
            "revoke_role" => Self::RevokeRole,
            "grant_permission" => Self::GrantPermission,
            "revoke_permission" => Self::RevokePermission,
            "grant_contract_permission" => Self::GrantContractPermission,
            "revoke_contract_permission" => Self::RevokeContractPermission,
            "escrow_open_offer" => Self::EscrowOpenOffer,
            "escrow_accept" => Self::EscrowAccept,
            "escrow_mark_payment_sent" => Self::EscrowMarkPaymentSent,
            "escrow_release" => Self::EscrowRelease,
            "escrow_cancel" => Self::EscrowCancel,
            "escrow_open_dispute" => Self::EscrowOpenDispute,
            "escrow_resolve_dispute" => Self::EscrowResolveDispute,
            "get_private_input" => Self::GetPrivateInput,
            "commit_output" => Self::CommitOutput,
            "create_nfts_for_all_users" => Self::CreateNftsForAllUsers,
            "set_execution_depth" => Self::SetExecutionDepth,
            "transfer_batch" => Self::TransferBatch,
            "axt_begin" => Self::AxtBegin,
            "axt_touch" => Self::AxtTouch,
            "axt_stage_anchored_spend" => Self::StageAnchoredSpend,
            "verify_ds_proof" => Self::VerifyDsProof,
            "axt_commit" => Self::AxtCommit,
            "deactivate_contract_instance" => Self::DeactivateContractInstance,
            "remove_smart_contract_bytes" => Self::RemoveSmartContractBytes,
            "register_smart_contract_code" => Self::RegisterSmartContractCode,
            "register_smart_contract_bytes" => Self::RegisterSmartContractBytes,
            "activate_contract_instance" => Self::ActivateContractInstance,
            "zk_roots_get" => Self::ZkRootsGet,
            "zk_vote_get_tally" => Self::ZkVoteGetTally,
            "zk_verify_batch" => Self::ZkVerifyBatch,
            "zk_vote_verify_ballot" => Self::ZkVoteVerifyBallot,
            "zk_vote_verify_tally" => Self::ZkVoteVerifyTally,
            "build_submit_ballot_inline" => Self::BuildSubmitBallotInline,
            "vrf_epoch_seed" => Self::VrfEpochSeed,
            "vrf_verify" => Self::VrfVerify,
            "vrf_verify_batch" => Self::VrfVerifyBatch,
            "sm3_hash" => Self::Sm3Hash,
            "sha256_hash" => Self::Sha256Hash,
            "sha3_hash" => Self::Sha3Hash,
            "blake2b256_hash" => Self::Blake2b256Hash,
            "keccak256_hash" => Self::Keccak256Hash,
            "iroha_hash" => Self::IrohaHash,
            "sm2_verify" => Self::Sm2Verify,
            "verify_signature" => Self::VerifySignature,
            "sm4_gcm_seal" => Self::Sm4GcmSeal,
            "sm4_gcm_open" => Self::Sm4GcmOpen,
            "sm4_ccm_seal" => Self::Sm4CcmSeal,
            "sm4_ccm_open" => Self::Sm4CcmOpen,
            "alloc" => Self::Alloc,
            "execution_summary" => Self::ExecutionSummary,
            "grow_heap" => Self::GrowHeap,
            "verify_proof" => Self::VerifyProof,
            "get_merkle_path" => Self::GetMerklePath,
            "get_merkle_compact" => Self::GetMerkleCompact,
            "get_register_merkle_compact" => Self::GetRegisterMerkleCompact,
            "soracloud_read_committed_state" => Self::SoracloudReadCommittedState,
            "soracloud_emit_state_mutation" => Self::SoracloudEmitStateMutation,
            "soracloud_emit_mailbox_message" => Self::SoracloudEmitMailboxMessage,
            "soracloud_append_journal" => Self::SoracloudAppendJournal,
            "soracloud_publish_checkpoint" => Self::SoracloudPublishCheckpoint,
            "soracloud_read_config" => Self::SoracloudReadConfig,
            "soracloud_read_secret_envelope" => Self::SoracloudReadSecretEnvelope,
            "add_signatory" => Self::AddSignatory,
            "remove_signatory" => Self::RemoveSignatory,
            "set_account_quorum" => Self::SetAccountQuorum,
            "path" => Self::Path,
            "name_decode" => Self::NameDecode,
            "tlv_eq" => Self::TlvEq,
            "tlv_len" => Self::TlvLen,
            "bytes_len" => Self::BytesLen,
            "value_encode" => Self::ValueEncode,
            "bytes_concat" => Self::BytesConcat,
            "string_concat" => Self::StringConcat,
            "string_len" => Self::StringLen,
            "string_as_bytes" => Self::StringAsBytes,
            "string_from_bytes" => Self::StringFromBytes,
            "string_from" => Self::StringFrom,

            "pointer_to_norito" => Self::PointerToNorito,
            "json_object" => Self::JsonObject,
            "json_set_int" => Self::JsonSetInt,
            "json_set_account_id" => Self::JsonSetAccountId,
            "encode_json" => Self::EncodeJson,
            "decode_json" => Self::DecodeJson,
            "encode_schema" => Self::SchemaEncode,
            "decode_schema" => Self::SchemaDecode,
            "schema_info" => Self::SchemaInfo,
            "numeric_to_int" => Self::NumericToInt,
            "numeric_neg" => Self::NumericNeg,
            "numeric_add" => Self::NumericAdd,
            "numeric_sub" => Self::NumericSub,
            "numeric_mul" => Self::NumericMul,
            "numeric_div" => Self::NumericDiv,
            "numeric_rem" => Self::NumericRem,
            "numeric_eq" => Self::NumericEq,
            "numeric_ne" => Self::NumericNe,
            "numeric_lt" => Self::NumericLt,
            "numeric_le" => Self::NumericLe,
            "numeric_gt" => Self::NumericGt,
            "numeric_ge" => Self::NumericGe,
            "numeric_to_int_direct" => Self::NumericToIntDirect,
            "numeric_add_direct" => Self::NumericAddDirect,
            "numeric_sub_direct" => Self::NumericSubDirect,
            "numeric_mul_direct" => Self::NumericMulDirect,
            "numeric_div_direct" => Self::NumericDivDirect,
            "numeric_rem_direct" => Self::NumericRemDirect,
            "numeric_neg_direct" => Self::NumericNegDirect,
            "numeric_eq_direct" => Self::NumericEqDirect,
            "numeric_ne_direct" => Self::NumericNeDirect,
            "numeric_lt_direct" => Self::NumericLtDirect,
            "numeric_le_direct" => Self::NumericLeDirect,
            "numeric_gt_direct" => Self::NumericGtDirect,
            "numeric_ge_direct" => Self::NumericGeDirect,
            "wrapping_add" => Self::WrappingAdd,
            "wrapping_sub" => Self::WrappingSub,
            "wrapping_mul" => Self::WrappingMul,
            "wrapping_neg" => Self::WrappingNeg,
            "isqrt" => Self::Isqrt,
            "abs" => Self::Abs,
            "min" => Self::Min,
            "max" => Self::Max,
            "div_ceil" => Self::DivCeil,
            "gcd" => Self::Gcd,
            "mean" => Self::Mean,
            "poseidon2" => Self::Poseidon2,
            "poseidon6" => Self::Poseidon6,
            "pubkgen" => Self::Pubkgen,
            "valcom" => Self::Valcom,
            "setvl" => Self::SetVl,
            "get_int" => Self::GetInt,
            "get_decimal" => Self::GetDecimal,
            "get_quantity" => Self::GetQuantity,
            "get_json" => Self::GetJson,
            "get_name" => Self::GetName,
            "get_account_id" => Self::GetAccountId,
            "get_asset_definition_id" => Self::GetAssetDefinitionId,
            "get_nft_id" => Self::GetNftId,
            "get_bytes_hex" => Self::GetBytesHex,
            "get_string" => Self::GetString,
            "get_bool" => Self::GetBool,
            "trigger_event" => Self::TriggerEvent,
            "authority" => Self::Authority,
            "contract_subject" => Self::ContractSubject,
            "transaction_time_ms" => Self::TransactionTimeMs,
            "block_height" => Self::BlockHeight,
            "block_time_ms" => Self::BlockTimeMs,
            "chain_id" => Self::ChainId,
            "contract_address" => Self::ContractAddress,
            "entrypoint" => Self::Entrypoint,
            "sysvar_authority" => Self::SysvarAuthority,
            "numeric_spec_unconstrained" => Self::NumericSpecUnconstrained,
            "numeric_spec_integer" => Self::NumericSpecInteger,
            "numeric_spec_fractional" => Self::NumericSpecFractional,
            "mintable_infinitely" => Self::MintableInfinitely,
            "mintable_once" => Self::MintableOnce,
            "mintable_not" => Self::MintableNot,
            "mintable_limited" => Self::MintableLimited,
            "signature_scheme_ed25519" => Self::SignatureSchemeEd25519,
            "signature_scheme_secp256k1" => Self::SignatureSchemeSecp256k1,
            "signature_scheme_ml_dsa" => Self::SignatureSchemeMlDsa,
            _ => return None,
        })
    }
    /// The canonical compiler-internal spelling used by typed HIR and lowering.
    pub const fn name(self) -> &'static str {
        match self {
            Self::PointerConstructor(constructor) => constructor.name(),
            Self::Contains => "contains",
            Self::GetOrInsert => "get_or_insert",
            Self::StateMapRemove => "remove",
            Self::KeysTake2 => "keys_take2",
            Self::ValuesTake2 => "values_take2",
            Self::KeysValuesTake2 => "keys_values_take2",
            Self::StateGet => "state_get",
            Self::StateSet => "state_set",
            Self::StateDel => "state_del",
            Self::StateHas => "state_has",
            Self::StateLen => "state_len",
            Self::StateCount => "state_count",
            Self::QueryExecuteNorito => "query_execute_norito",
            Self::QueryGetAccount => "query_get_account",
            Self::QueryGetAsset => "query_get_asset",
            Self::QueryGetAssetDefinition => "query_get_asset_definition",
            Self::QueryGetDomain => "query_get_domain",
            Self::QueryGetNft => "query_get_nft",
            Self::QueryPageAccounts => "query_page_accounts",
            Self::QueryPageAssets => "query_page_assets",
            Self::QueryPageAssetsOf => "query_page_assets_of",
            Self::QueryPageAssetDefinitions => "query_page_asset_definitions",
            Self::QueryPageDomains => "query_page_domains",
            Self::QueryPageNfts => "query_page_nfts",
            Self::QueryGetParameter => "query_get_parameter",
            Self::QueryGetContractManifest => "query_get_contract_manifest",
            Self::QueryGetContractInstance => "query_get_contract_instance",
            Self::ExecuteQuery => "execute_query",
            Self::ScExecuteSubmitBallot => "sc_execute_submit_ballot",
            Self::ResolveAccountAlias => "resolve_account_alias",
            Self::SubscriptionBill => "subscription_bill",
            Self::SubscriptionRecordUsage => "subscription_record_usage",
            Self::GetAccountBalance => "get_account_balance",
            Self::GetPublicInput => "get_public_input",
            Self::DebugPrint => "debug_print",
            Self::DebugLog => "debug_log",
            Self::Assert => "assert",
            Self::Require => "require",
            Self::Info => "info",
            Self::AssertEq => "assert_eq",
            Self::TestInvokeEntrypoint => "invoke_entrypoint",
            Self::TestInvokeEntrypointAs => "invoke_entrypoint_as",
            Self::TestExpectRejectAs => "expect_reject_as",
            Self::TestExpectAnyRejectAs => "expect_any_reject_as",
            Self::TestActorAccount => "actor_account",
            Self::TestActorPublicKey => "actor_public_key",
            Self::TestActorSign => "actor_sign",
            Self::TestSetBlockHeight => "set_block_height",
            Self::TestAdvanceBlocks => "advance_blocks",
            Self::TestSetTransactionTimeMs => "set_transaction_time_ms",
            Self::SetAccountMetadata => "set_account_metadata",
            Self::MintAsset => "mint_asset",
            Self::BurnAsset => "burn_asset",
            Self::TransferAsset => "transfer_asset",
            Self::SetAssetTransferAvailability => "set_asset_transfer_availability",
            Self::SetAssetTransferDailyLimit => "set_asset_transfer_daily_limit",
            Self::SetAssetHoldingLimit => "set_asset_holding_limit",
            Self::AccountRecoveryPropose => "account_recovery_propose",
            Self::AccountRecoveryApprove => "account_recovery_approve",
            Self::AccountRecoveryCancel => "account_recovery_cancel",
            Self::AccountRecoveryFinalize => "account_recovery_finalize",
            Self::NftMintAsset => "nft_mint_asset",
            Self::NftSetMetadata => "nft_set_metadata",
            Self::NftBurnAsset => "nft_burn_asset",
            Self::NftTransferAsset => "nft_transfer_asset",
            Self::RegisterDomain => "register_domain",
            Self::UnregisterDomain => "unregister_domain",
            Self::TransferDomain => "transfer_domain",
            Self::RegisterAccount => "register_account",
            Self::UnregisterAccount => "unregister_account",
            Self::RegisterAsset => "register_asset",
            Self::UnregisterAsset => "unregister_asset",
            Self::RegisterPeer => "register_peer",
            Self::UnregisterPeer => "unregister_peer",
            Self::RegisterTrigger => "register_trigger",
            Self::UnregisterTrigger => "unregister_trigger",
            Self::SetTriggerEnabled => "set_trigger_enabled",
            Self::RegisterRole => "register_role",
            Self::UnregisterRole => "unregister_role",
            Self::GrantRole => "grant_role",
            Self::RevokeRole => "revoke_role",
            Self::GrantPermission => "grant_permission",
            Self::RevokePermission => "revoke_permission",
            Self::GrantContractPermission => "grant_contract_permission",
            Self::RevokeContractPermission => "revoke_contract_permission",
            Self::EscrowOpenOffer => "escrow_open_offer",
            Self::EscrowAccept => "escrow_accept",
            Self::EscrowMarkPaymentSent => "escrow_mark_payment_sent",
            Self::EscrowRelease => "escrow_release",
            Self::EscrowCancel => "escrow_cancel",
            Self::EscrowOpenDispute => "escrow_open_dispute",
            Self::EscrowResolveDispute => "escrow_resolve_dispute",
            Self::GetPrivateInput => "get_private_input",
            Self::CommitOutput => "commit_output",
            Self::CreateNftsForAllUsers => "create_nfts_for_all_users",
            Self::SetExecutionDepth => "set_execution_depth",
            Self::TransferBatch => "transfer_batch",
            Self::AxtBegin => "axt_begin",
            Self::AxtTouch => "axt_touch",
            Self::StageAnchoredSpend => "axt_stage_anchored_spend",
            Self::VerifyDsProof => "verify_ds_proof",
            Self::AxtCommit => "axt_commit",
            Self::DeactivateContractInstance => "deactivate_contract_instance",
            Self::RemoveSmartContractBytes => "remove_smart_contract_bytes",
            Self::RegisterSmartContractCode => "register_smart_contract_code",
            Self::RegisterSmartContractBytes => "register_smart_contract_bytes",
            Self::ActivateContractInstance => "activate_contract_instance",
            Self::ZkRootsGet => "zk_roots_get",
            Self::ZkVoteGetTally => "zk_vote_get_tally",
            Self::ZkVerifyBatch => "zk_verify_batch",
            Self::ZkVoteVerifyBallot => "zk_vote_verify_ballot",
            Self::ZkVoteVerifyTally => "zk_vote_verify_tally",
            Self::BuildSubmitBallotInline => "build_submit_ballot_inline",
            Self::VrfEpochSeed => "vrf_epoch_seed",
            Self::VrfVerify => "vrf_verify",
            Self::VrfVerifyBatch => "vrf_verify_batch",
            Self::Sm3Hash => "sm3_hash",
            Self::Sha256Hash => "sha256_hash",
            Self::Sha3Hash => "sha3_hash",
            Self::Blake2b256Hash => "blake2b256_hash",
            Self::Keccak256Hash => "keccak256_hash",
            Self::IrohaHash => "iroha_hash",
            Self::Sm2Verify => "sm2_verify",
            Self::VerifySignature => "verify_signature",
            Self::Sm4GcmSeal => "sm4_gcm_seal",
            Self::Sm4GcmOpen => "sm4_gcm_open",
            Self::Sm4CcmSeal => "sm4_ccm_seal",
            Self::Sm4CcmOpen => "sm4_ccm_open",
            Self::Alloc => "alloc",
            Self::ExecutionSummary => "execution_summary",
            Self::GrowHeap => "grow_heap",
            Self::VerifyProof => "verify_proof",
            Self::GetMerklePath => "get_merkle_path",
            Self::GetMerkleCompact => "get_merkle_compact",
            Self::GetRegisterMerkleCompact => "get_register_merkle_compact",
            Self::SoracloudReadCommittedState => "soracloud_read_committed_state",
            Self::SoracloudEmitStateMutation => "soracloud_emit_state_mutation",
            Self::SoracloudEmitMailboxMessage => "soracloud_emit_mailbox_message",
            Self::SoracloudAppendJournal => "soracloud_append_journal",
            Self::SoracloudPublishCheckpoint => "soracloud_publish_checkpoint",
            Self::SoracloudReadConfig => "soracloud_read_config",
            Self::SoracloudReadSecretEnvelope => "soracloud_read_secret_envelope",
            Self::AddSignatory => "add_signatory",
            Self::RemoveSignatory => "remove_signatory",
            Self::SetAccountQuorum => "set_account_quorum",
            Self::Path => "path",
            Self::NameDecode => "name_decode",
            Self::TlvEq => "tlv_eq",
            Self::TlvLen => "tlv_len",
            Self::BytesLen => "bytes_len",
            Self::ValueEncode => "value_encode",
            Self::BytesConcat => "bytes_concat",
            Self::StringConcat => "string_concat",
            Self::StringLen => "string_len",
            Self::StringAsBytes => "string_as_bytes",
            Self::StringFromBytes => "string_from_bytes",
            Self::StringFrom => "string_from",

            Self::PointerToNorito => "pointer_to_norito",
            Self::JsonObject => "json_object",
            Self::JsonSetInt => "json_set_int",
            Self::JsonSetAccountId => "json_set_account_id",
            Self::EncodeJson => "encode_json",
            Self::DecodeJson => "decode_json",
            Self::SchemaEncode => "encode_schema",
            Self::SchemaDecode => "decode_schema",
            Self::SchemaInfo => "schema_info",
            Self::NumericToInt => "numeric_to_int",
            Self::NumericNeg => "numeric_neg",
            Self::NumericAdd => "numeric_add",
            Self::NumericSub => "numeric_sub",
            Self::NumericMul => "numeric_mul",
            Self::NumericDiv => "numeric_div",
            Self::NumericRem => "numeric_rem",
            Self::NumericEq => "numeric_eq",
            Self::NumericNe => "numeric_ne",
            Self::NumericLt => "numeric_lt",
            Self::NumericLe => "numeric_le",
            Self::NumericGt => "numeric_gt",
            Self::NumericGe => "numeric_ge",
            Self::NumericToIntDirect => "numeric_to_int_direct",
            Self::NumericAddDirect => "numeric_add_direct",
            Self::NumericSubDirect => "numeric_sub_direct",
            Self::NumericMulDirect => "numeric_mul_direct",
            Self::NumericDivDirect => "numeric_div_direct",
            Self::NumericRemDirect => "numeric_rem_direct",
            Self::NumericNegDirect => "numeric_neg_direct",
            Self::NumericEqDirect => "numeric_eq_direct",
            Self::NumericNeDirect => "numeric_ne_direct",
            Self::NumericLtDirect => "numeric_lt_direct",
            Self::NumericLeDirect => "numeric_le_direct",
            Self::NumericGtDirect => "numeric_gt_direct",
            Self::NumericGeDirect => "numeric_ge_direct",
            Self::WrappingAdd => "wrapping_add",
            Self::WrappingSub => "wrapping_sub",
            Self::WrappingMul => "wrapping_mul",
            Self::WrappingNeg => "wrapping_neg",
            Self::Isqrt => "isqrt",
            Self::Abs => "abs",
            Self::Min => "min",
            Self::Max => "max",
            Self::DivCeil => "div_ceil",
            Self::Gcd => "gcd",
            Self::Mean => "mean",
            Self::Poseidon2 => "poseidon2",
            Self::Poseidon6 => "poseidon6",
            Self::Pubkgen => "pubkgen",
            Self::Valcom => "valcom",
            Self::SetVl => "setvl",
            Self::GetInt => "get_int",
            Self::GetDecimal => "get_decimal",
            Self::GetQuantity => "get_quantity",
            Self::GetJson => "get_json",
            Self::GetName => "get_name",
            Self::GetAccountId => "get_account_id",
            Self::GetAssetDefinitionId => "get_asset_definition_id",
            Self::GetNftId => "get_nft_id",
            Self::GetBytesHex => "get_bytes_hex",
            Self::GetString => "get_string",
            Self::GetBool => "get_bool",
            Self::TriggerEvent => "trigger_event",
            Self::Authority => "authority",
            Self::ContractSubject => "contract_subject",
            Self::TransactionTimeMs => "transaction_time_ms",
            Self::BlockHeight => "block_height",
            Self::BlockTimeMs => "block_time_ms",
            Self::ChainId => "chain_id",
            Self::ContractAddress => "contract_address",
            Self::Entrypoint => "entrypoint",
            Self::SysvarAuthority => "sysvar_authority",
            Self::NumericSpecUnconstrained => "numeric_spec_unconstrained",
            Self::NumericSpecInteger => "numeric_spec_integer",
            Self::NumericSpecFractional => "numeric_spec_fractional",
            Self::MintableInfinitely => "mintable_infinitely",
            Self::MintableOnce => "mintable_once",
            Self::MintableNot => "mintable_not",
            Self::MintableLimited => "mintable_limited",
            Self::SignatureSchemeEd25519 => "signature_scheme_ed25519",
            Self::SignatureSchemeSecp256k1 => "signature_scheme_secp256k1",
            Self::SignatureSchemeMlDsa => "signature_scheme_ml_dsa",
        }
    }
    /// Canonical V1 source spelling, including the public namespace.
    pub const fn source_name(self) -> &'static str {
        match self {
            Self::PointerConstructor(constructor) => match constructor {
                PointerConstructor::AccountId => "AccountId::parse",
                PointerConstructor::AssetDefinition => "AssetDefinitionId::parse",
                PointerConstructor::AssetId => "AssetId::parse",
                PointerConstructor::NftId => "NftId::parse",
                PointerConstructor::Name => "Name::parse",
                PointerConstructor::Json => "Json::parse",
                PointerConstructor::DomainId => "DomainId::parse",
                PointerConstructor::DataSpaceId => "DataSpaceId::parse",
                PointerConstructor::AxtDescriptor => "AxtDescriptor::parse",
                PointerConstructor::AxtAnchoredSpendV1 => "AxtAnchoredSpendV1::parse",
                // These constructors are compiler internals. Giving them an
                // internal spelling here does not make them source-visible;
                // `from_source_name` also enforces `BuiltinMode`.
                PointerConstructor::Domain
                | PointerConstructor::Blob
                | PointerConstructor::NoritoBytes
                | PointerConstructor::ProofBlob
                | PointerConstructor::SoracloudRequest
                | PointerConstructor::SoracloudResponse => constructor.name(),
            },
            Self::Contains => "contains",
            Self::GetOrInsert => "get_or_insert",
            Self::StateMapRemove => "remove",
            Self::KeysTake2 => "state::keys_take2",
            Self::ValuesTake2 => "state::values_take2",
            Self::KeysValuesTake2 => "state::entries_take2",
            Self::Authority => "context::authority",
            Self::ContractSubject => "context::seiyaku_subject",
            Self::TransactionTimeMs => "context::transaction_time_ms",
            Self::BlockHeight => "context::block_height",
            Self::BlockTimeMs => "context::block_time_ms",
            Self::ChainId => "context::chain_id",
            Self::ContractAddress => "context::seiyaku_address",
            Self::Entrypoint => "context::kotoage",
            Self::GetPublicInput => "context::public_input",
            Self::TriggerEvent => "context::trigger_event",
            Self::StateGet => "state::get",
            Self::StateSet => "state::set",
            Self::StateDel => "state::delete",
            Self::StateHas => "state::contains",
            Self::StateLen => "state::len",
            Self::StateCount => "state::count",
            Self::QueryGetAccount => "ledger::query::account",
            Self::QueryGetAsset => "ledger::query::asset",
            Self::QueryGetAssetDefinition => "ledger::query::asset_definition",
            Self::QueryGetDomain => "ledger::query::domain",
            Self::QueryGetNft => "ledger::query::nft",
            Self::QueryPageAccounts => "ledger::query::accounts",
            Self::QueryPageAssets => "ledger::query::assets",
            Self::QueryPageAssetsOf => "ledger::query::assets_of",
            Self::QueryPageAssetDefinitions => "ledger::query::asset_definitions",
            Self::QueryPageDomains => "ledger::query::domains",
            Self::QueryPageNfts => "ledger::query::nfts",
            Self::QueryGetParameter => "ledger::query::parameter",
            Self::QueryGetContractManifest => "ledger::query::seiyaku_manifest",
            Self::QueryGetContractInstance => "ledger::query::seiyaku_instance",
            Self::ResolveAccountAlias => "ledger::account::resolve_alias",
            Self::SubscriptionBill => "ledger::subscription::bill",
            Self::SubscriptionRecordUsage => "ledger::subscription::record_usage",
            Self::GetAccountBalance => "ledger::asset::balance",
            // The scalar setter cannot represent Kotodama's adaptive-width
            // `int`; source must use native `json { ... }` construction,
            // which carries the exact pointer-backed value.
            // Typed JSON getters are receiver methods (`value.get_int(key)`);
            // their source spelling is the method name.
            // Operators and the named V1 conversions are the only numeric
            // source surface. These registry entries remain compiler-owned
            // lowering helpers and deliberately have no source alias.
            Self::DebugPrint
            | Self::JsonSetInt
            | Self::GetInt
            | Self::GetDecimal
            | Self::GetQuantity
            | Self::GetJson
            | Self::GetName
            | Self::GetAccountId
            | Self::GetAssetDefinitionId
            | Self::GetNftId
            | Self::GetBytesHex
            | Self::GetString
            | Self::GetBool
            | Self::NumericToInt
            | Self::NumericNeg
            | Self::NumericAdd
            | Self::NumericSub
            | Self::NumericMul
            | Self::NumericDiv
            | Self::NumericRem
            | Self::NumericEq
            | Self::NumericNe
            | Self::NumericLt
            | Self::NumericLe
            | Self::NumericGt
            | Self::NumericGe
            | Self::Alloc
            | Self::QueryExecuteNorito
            | Self::ExecuteQuery
            | Self::GrowHeap
            | Self::GetMerklePath
            | Self::GetMerkleCompact
            | Self::GetRegisterMerkleCompact
            | Self::NumericToIntDirect
            | Self::NumericAddDirect
            | Self::NumericSubDirect
            | Self::NumericMulDirect
            | Self::NumericDivDirect
            | Self::NumericRemDirect
            | Self::NumericNegDirect
            | Self::NumericEqDirect
            | Self::NumericNeDirect
            | Self::NumericLtDirect
            | Self::NumericLeDirect
            | Self::NumericGtDirect
            | Self::NumericGeDirect
            | Self::SysvarAuthority => self.name(),
            Self::DebugLog => "debug::log",
            Self::Assert => "test::assert",
            Self::Require => "require",
            Self::Info => "debug::info",
            Self::AssertEq => "test::assert_eq",
            Self::TestInvokeEntrypoint => "test::invoke_kotoage",
            Self::TestInvokeEntrypointAs => "test::invoke_kotoage_as",
            Self::TestExpectRejectAs => "test::expect_reject_as",
            Self::TestExpectAnyRejectAs => "test::expect_any_reject_as",
            Self::TestActorAccount => "test::actor_account",
            Self::TestActorPublicKey => "test::actor_public_key",
            Self::TestActorSign => "test::actor_sign",
            Self::TestSetBlockHeight => "test::set_block_height",
            Self::TestAdvanceBlocks => "test::advance_blocks",
            Self::TestSetTransactionTimeMs => "test::set_transaction_time_ms",
            Self::MintAsset => "ledger::asset::mint",
            Self::BurnAsset => "ledger::asset::burn",
            Self::TransferAsset => "ledger::asset::transfer",
            Self::SetAssetTransferAvailability => "ledger::asset::set_transfer_availability",
            Self::SetAssetTransferDailyLimit => "ledger::asset::set_transfer_daily_limit",
            Self::SetAssetHoldingLimit => "ledger::asset::set_holding_limit",
            Self::RegisterAsset => "ledger::asset::register",
            Self::UnregisterAsset => "ledger::asset::unregister",
            Self::SetAccountMetadata => "ledger::account::set_metadata",
            Self::RegisterAccount => "ledger::account::register",
            Self::UnregisterAccount => "ledger::account::unregister",
            Self::AddSignatory => "ledger::account::add_signatory",
            Self::RemoveSignatory => "ledger::account::remove_signatory",
            Self::SetAccountQuorum => "ledger::account::set_quorum",
            Self::AccountRecoveryPropose => "ledger::account::recovery::propose",
            Self::AccountRecoveryApprove => "ledger::account::recovery::approve",
            Self::AccountRecoveryCancel => "ledger::account::recovery::cancel",
            Self::AccountRecoveryFinalize => "ledger::account::recovery::finalize",
            Self::NftMintAsset => "ledger::nft::mint",
            Self::NftSetMetadata => "ledger::nft::set_metadata",
            Self::NftBurnAsset => "ledger::nft::burn",
            Self::NftTransferAsset => "ledger::nft::transfer",
            Self::CreateNftsForAllUsers => "ledger::nft::create_for_all_users",
            Self::RegisterDomain => "ledger::domain::register",
            Self::UnregisterDomain => "ledger::domain::unregister",
            Self::TransferDomain => "ledger::domain::transfer",
            Self::RegisterPeer => "ledger::peer::register",
            Self::UnregisterPeer => "ledger::peer::unregister",
            Self::RegisterTrigger => "ledger::trigger::register",
            Self::UnregisterTrigger => "ledger::trigger::unregister",
            Self::SetTriggerEnabled => "ledger::trigger::set_enabled",
            Self::RegisterRole => "ledger::role::register",
            Self::UnregisterRole => "ledger::role::unregister",
            Self::GrantRole => "ledger::role::grant",
            Self::RevokeRole => "ledger::role::revoke",
            Self::GrantPermission => "ledger::permission::grant",
            Self::RevokePermission => "ledger::permission::revoke",
            Self::GrantContractPermission => "ledger::seiyaku::grant_permission",
            Self::RevokeContractPermission => "ledger::seiyaku::revoke_permission",
            Self::EscrowOpenOffer => "ledger::escrow::open_offer",
            Self::EscrowAccept => "ledger::escrow::accept",
            Self::EscrowMarkPaymentSent => "ledger::escrow::mark_payment_sent",
            Self::EscrowRelease => "ledger::escrow::release",
            Self::EscrowCancel => "ledger::escrow::cancel",
            Self::EscrowOpenDispute => "ledger::escrow::open_dispute",
            Self::EscrowResolveDispute => "ledger::escrow::resolve_dispute",
            Self::SetExecutionDepth => "ledger::parameters::set_execution_depth",
            Self::TransferBatch => "ledger::asset::transfer_batch",
            Self::AxtBegin => "axt::begin",
            Self::AxtTouch => "axt::touch",
            Self::StageAnchoredSpend => "axt::stage_anchored_spend",
            Self::VerifyDsProof => "axt::verify_proof",
            Self::AxtCommit => "axt::commit",
            Self::DeactivateContractInstance => "seiyaku::deactivate_instance",
            Self::RemoveSmartContractBytes => "seiyaku::remove_code",
            Self::RegisterSmartContractCode => "seiyaku::register_code",
            Self::RegisterSmartContractBytes => "seiyaku::register_bytes",
            Self::ActivateContractInstance => "seiyaku::activate_instance",
            Self::ScExecuteSubmitBallot => "ledger::governance::submit_ballot",
            Self::ZkRootsGet => "crypto::zk::roots",
            Self::ZkVoteGetTally => "ledger::governance::tally",
            Self::ZkVerifyBatch => "crypto::zk::verify_batch",
            Self::ZkVoteVerifyBallot => "ledger::governance::verify_ballot",
            Self::ZkVoteVerifyTally => "ledger::governance::verify_tally",
            Self::BuildSubmitBallotInline => "ledger::governance::build_submit_ballot",
            Self::VrfEpochSeed => "crypto::vrf::epoch_seed",
            Self::VrfVerify => "crypto::vrf::verify",
            Self::VrfVerifyBatch => "crypto::vrf::verify_batch",
            Self::Sm3Hash => "crypto::sm3",
            Self::JsonObject => "json::object",
            Self::JsonSetAccountId => "json::set_account_id",
            Self::Sha256Hash => "crypto::sha256",
            Self::Sha3Hash => "crypto::sha3",
            Self::Blake2b256Hash => "crypto::blake2b256",
            Self::Keccak256Hash => "crypto::keccak256",
            Self::IrohaHash => "crypto::iroha_hash",
            Self::Sm2Verify => "crypto::sm2::verify",
            Self::VerifySignature => "crypto::verify_signature",
            Self::Sm4GcmSeal => "crypto::sm4_gcm::seal",
            Self::Sm4GcmOpen => "crypto::sm4_gcm::open",
            Self::Sm4CcmSeal => "crypto::sm4_ccm::seal",
            Self::Sm4CcmOpen => "crypto::sm4_ccm::open",
            Self::ExecutionSummary => "crypto::execution_summary",
            Self::VerifyProof => "crypto::verify_proof",
            Self::SoracloudReadCommittedState => "soracloud::read_committed_state",
            Self::SoracloudEmitStateMutation => "soracloud::emit_state_mutation",
            Self::SoracloudEmitMailboxMessage => "soracloud::emit_mailbox_message",
            Self::SoracloudAppendJournal => "soracloud::append_journal",
            Self::SoracloudPublishCheckpoint => "soracloud::publish_checkpoint",
            Self::SoracloudReadConfig => "soracloud::read_config",
            Self::SoracloudReadSecretEnvelope => "soracloud::read_secret_envelope",
            Self::Path => "path",
            Self::NameDecode => "codec::decode_name",
            Self::TlvEq => "codec::tlv_eq",
            Self::TlvLen => "codec::tlv_len",
            Self::BytesLen => "bytes::len",
            Self::ValueEncode => "codec::encode",
            Self::BytesConcat => "bytes::concat",
            Self::StringConcat => "string::concat",
            Self::StringLen => "string::len",
            Self::StringAsBytes => "string::as_bytes",
            Self::StringFromBytes => "string::from_bytes",
            Self::StringFrom => "string::from",
            Self::PointerToNorito => "codec::to_norito",
            Self::EncodeJson => "codec::encode_json",
            Self::DecodeJson => "codec::decode_json",
            Self::SchemaEncode => "codec::schema::encode",
            Self::SchemaDecode => "codec::schema::decode",
            Self::SchemaInfo => "codec::schema::info",
            Self::WrappingAdd => "math::wrapping_add",
            Self::WrappingSub => "math::wrapping_sub",
            Self::WrappingMul => "math::wrapping_mul",
            Self::WrappingNeg => "math::wrapping_neg",
            Self::Isqrt => "math::isqrt",
            Self::Abs => "math::abs",
            Self::Min => "math::min",
            Self::Max => "math::max",
            Self::DivCeil => "math::div_ceil",
            Self::Gcd => "math::gcd",
            Self::Mean => "math::mean",
            Self::Poseidon2 => "crypto::poseidon2",
            Self::Poseidon6 => "crypto::poseidon6",
            Self::Pubkgen => "crypto::pubkgen",
            Self::Valcom => "crypto::valcom",
            Self::GetPrivateInput => "crypto::private_input",
            Self::CommitOutput => "crypto::commit_output",
            Self::SetVl => "runtime::set_vector_length",
            Self::NumericSpecUnconstrained => "NumericSpec::unconstrained",
            Self::NumericSpecInteger => "NumericSpec::integer",
            Self::NumericSpecFractional => "NumericSpec::fractional",
            Self::MintableInfinitely => "Mintable::Infinitely",
            Self::MintableOnce => "Mintable::Once",
            Self::MintableNot => "Mintable::Not",
            Self::MintableLimited => "Mintable::Limited",
            Self::SignatureSchemeEd25519 => "SignatureScheme::Ed25519",
            Self::SignatureSchemeSecp256k1 => "SignatureScheme::Secp256k1",
            Self::SignatureSchemeMlDsa => "SignatureScheme::MlDsa",
        }
    }
    /// Resolve a source-visible builtin by its canonical spelling.
    pub fn from_source_name(name: &str) -> Option<Self> {
        Self::all().find(|builtin| {
            matches!(
                builtin.surface(),
                BuiltinSurface::Function | BuiltinSurface::FunctionOrMethod
            ) && builtin.source_name() == name
        })
    }
    /// Return how V1 source may call this builtin.
    pub const fn surface(self) -> BuiltinSurface {
        match self {
            Self::Contains
            | Self::GetOrInsert
            | Self::StateMapRemove
            | Self::Path
            | Self::GetInt
            | Self::GetDecimal
            | Self::GetQuantity
            | Self::GetJson
            | Self::GetName
            | Self::GetAccountId
            | Self::GetAssetDefinitionId
            | Self::GetNftId
            | Self::GetBytesHex
            | Self::GetString
            | Self::GetBool => BuiltinSurface::MethodOnly,
            builtin if matches!(builtin.mode(), BuiltinMode::CompilerInternal) => {
                BuiltinSurface::CompilerInternal
            }
            _ => BuiltinSurface::Function,
        }
    }
    /// Return the canonical effect classification for this builtin.
    pub const fn effects(self) -> BuiltinEffects {
        match self {
            Self::ScExecuteSubmitBallot => BuiltinEffects::INSTRUCTION,
            Self::GetOrInsert | Self::StateMapRemove | Self::StateSet | Self::StateDel => {
                BuiltinEffects::DURABLE_STATE
            }
            // `debug::info` is diagnostics only: hosts charge gas and the
            // record never reaches ledger or durable state, so views and
            // helpers reachable from views may log.
            Self::SubscriptionBill
            | Self::SubscriptionRecordUsage
            | Self::DebugPrint
            | Self::DebugLog
            | Self::TestInvokeEntrypoint
            | Self::TestInvokeEntrypointAs
            | Self::TestExpectRejectAs
            | Self::TestExpectAnyRejectAs
            | Self::TestActorAccount
            | Self::TestActorPublicKey
            | Self::TestActorSign
            | Self::TestSetBlockHeight
            | Self::TestAdvanceBlocks
            | Self::TestSetTransactionTimeMs
            | Self::SetAccountMetadata
            | Self::MintAsset
            | Self::BurnAsset
            | Self::TransferAsset
            | Self::SetAssetTransferAvailability
            | Self::SetAssetTransferDailyLimit
            | Self::SetAssetHoldingLimit
            | Self::AccountRecoveryPropose
            | Self::AccountRecoveryApprove
            | Self::AccountRecoveryCancel
            | Self::AccountRecoveryFinalize
            | Self::NftMintAsset
            | Self::NftSetMetadata
            | Self::NftBurnAsset
            | Self::NftTransferAsset
            | Self::RegisterDomain
            | Self::UnregisterDomain
            | Self::TransferDomain
            | Self::RegisterAccount
            | Self::UnregisterAccount
            | Self::RegisterAsset
            | Self::UnregisterAsset
            | Self::RegisterPeer
            | Self::UnregisterPeer
            | Self::RegisterTrigger
            | Self::UnregisterTrigger
            | Self::SetTriggerEnabled
            | Self::RegisterRole
            | Self::UnregisterRole
            | Self::GrantRole
            | Self::RevokeRole
            | Self::GrantPermission
            | Self::RevokePermission
            | Self::GrantContractPermission
            | Self::RevokeContractPermission
            | Self::EscrowOpenOffer
            | Self::EscrowAccept
            | Self::EscrowMarkPaymentSent
            | Self::EscrowRelease
            | Self::EscrowCancel
            | Self::EscrowOpenDispute
            | Self::EscrowResolveDispute
            | Self::GetPrivateInput
            | Self::CommitOutput
            | Self::CreateNftsForAllUsers
            | Self::SetExecutionDepth
            | Self::TransferBatch
            | Self::AxtBegin
            | Self::AxtTouch
            | Self::StageAnchoredSpend
            | Self::AxtCommit
            | Self::DeactivateContractInstance
            | Self::RemoveSmartContractBytes
            | Self::RegisterSmartContractCode
            | Self::RegisterSmartContractBytes
            | Self::ActivateContractInstance
            | Self::ZkVerifyBatch
            | Self::ZkVoteVerifyBallot
            | Self::ZkVoteVerifyTally
            | Self::SoracloudReadCommittedState
            | Self::SoracloudEmitStateMutation
            | Self::SoracloudEmitMailboxMessage
            | Self::SoracloudAppendJournal
            | Self::SoracloudPublishCheckpoint
            | Self::SoracloudReadConfig
            | Self::SoracloudReadSecretEnvelope
            | Self::AddSignatory
            | Self::RemoveSignatory
            | Self::SetAccountQuorum => BuiltinEffects::HOST,
            _ => BuiltinEffects::NONE,
        }
    }
    /// Return the scheduler access class for this builtin.
    pub const fn access(self) -> BuiltinAccess {
        match self {
            Self::Contains
            | Self::StateGet
            | Self::StateHas
            | Self::StateLen
            | Self::StateCount => BuiltinAccess::StateRead,
            Self::GetOrInsert | Self::StateMapRemove | Self::StateSet | Self::StateDel => {
                BuiltinAccess::StateWrite
            }
            Self::PointerConstructor(PointerConstructor::AccountId)
            | Self::QueryExecuteNorito
            | Self::QueryGetAccount
            | Self::QueryGetAsset
            | Self::QueryGetAssetDefinition
            | Self::QueryGetDomain
            | Self::QueryGetNft
            | Self::QueryPageAccounts
            | Self::QueryPageAssets
            | Self::QueryPageAssetsOf
            | Self::QueryPageAssetDefinitions
            | Self::QueryPageDomains
            | Self::QueryPageNfts
            | Self::QueryGetParameter
            | Self::QueryGetContractManifest
            | Self::QueryGetContractInstance
            | Self::ExecuteQuery
            | Self::ResolveAccountAlias
            | Self::GetAccountBalance
            | Self::ZkRootsGet
            | Self::ZkVoteGetTally
            | Self::ZkVerifyBatch
            | Self::ZkVoteVerifyBallot
            | Self::ZkVoteVerifyTally
            | Self::VrfEpochSeed => BuiltinAccess::LedgerRead,
            Self::TestInvokeEntrypoint
            | Self::TestInvokeEntrypointAs
            | Self::TestExpectRejectAs
            | Self::TestExpectAnyRejectAs
            | Self::SoracloudReadCommittedState
            | Self::SoracloudEmitStateMutation
            | Self::SoracloudEmitMailboxMessage
            | Self::SoracloudAppendJournal
            | Self::SoracloudPublishCheckpoint
            | Self::SoracloudReadConfig
            | Self::SoracloudReadSecretEnvelope => BuiltinAccess::Dynamic,
            Self::GetPrivateInput
            | Self::CommitOutput
            | Self::SetExecutionDepth
            | Self::DebugPrint
            | Self::DebugLog
            | Self::Info
            | Self::TestActorAccount
            | Self::TestActorPublicKey
            | Self::TestActorSign
            | Self::TestSetBlockHeight
            | Self::TestAdvanceBlocks
            | Self::TestSetTransactionTimeMs => BuiltinAccess::None,
            builtin
                if builtin.effects().host_side_effects || builtin.effects().emits_instructions =>
            {
                BuiltinAccess::LedgerWrite
            }
            _ => BuiltinAccess::None,
        }
    }
    /// Return the execution mode required by this builtin.
    pub const fn mode(self) -> BuiltinMode {
        match self {
            Self::GetPrivateInput | Self::Valcom | Self::CommitOutput => BuiltinMode::ZkOnly,
            Self::Assert | Self::AssertEq => BuiltinMode::TestOnly,
            Self::TestInvokeEntrypoint
            | Self::TestInvokeEntrypointAs
            | Self::TestExpectRejectAs
            | Self::TestExpectAnyRejectAs
            | Self::TestActorAccount
            | Self::TestActorPublicKey
            | Self::TestActorSign
            | Self::TestSetBlockHeight
            | Self::TestAdvanceBlocks
            | Self::TestSetTransactionTimeMs => BuiltinMode::TestFunctionOnly,
            Self::PointerConstructor(
                PointerConstructor::Domain
                | PointerConstructor::Blob
                | PointerConstructor::NoritoBytes
                | PointerConstructor::ProofBlob
                | PointerConstructor::SoracloudRequest
                | PointerConstructor::SoracloudResponse,
            )
            | Self::KeysTake2
            | Self::ValuesTake2
            | Self::KeysValuesTake2
            | Self::Alloc
            | Self::QueryExecuteNorito
            | Self::ExecuteQuery
            | Self::DebugPrint
            | Self::DebugLog
            | Self::GrowHeap
            | Self::GetMerklePath
            | Self::GetMerkleCompact
            | Self::GetRegisterMerkleCompact
            | Self::VerifyDsProof
            | Self::SoracloudReadCommittedState
            | Self::SoracloudEmitStateMutation
            | Self::SoracloudEmitMailboxMessage
            | Self::SoracloudAppendJournal
            | Self::SoracloudPublishCheckpoint
            | Self::SoracloudReadConfig
            | Self::SoracloudReadSecretEnvelope
            | Self::PointerToNorito
            | Self::JsonSetInt
            | Self::NameDecode
            | Self::TlvEq
            | Self::TlvLen
            | Self::EncodeJson
            | Self::DecodeJson
            | Self::SchemaEncode
            | Self::SchemaDecode
            | Self::SchemaInfo
            | Self::NumericToInt
            | Self::NumericNeg
            | Self::NumericAdd
            | Self::NumericSub
            | Self::NumericMul
            | Self::NumericDiv
            | Self::NumericRem
            | Self::NumericEq
            | Self::NumericNe
            | Self::NumericLt
            | Self::NumericLe
            | Self::NumericGt
            | Self::NumericGe
            | Self::NumericToIntDirect
            | Self::NumericAddDirect
            | Self::NumericSubDirect
            | Self::NumericMulDirect
            | Self::NumericDivDirect
            | Self::NumericRemDirect
            | Self::NumericNegDirect
            | Self::NumericEqDirect
            | Self::NumericNeDirect
            | Self::NumericLtDirect
            | Self::NumericLeDirect
            | Self::NumericGtDirect
            | Self::NumericGeDirect
            | Self::Poseidon2
            | Self::Poseidon6
            | Self::Pubkgen
            | Self::SetExecutionDepth
            | Self::DeactivateContractInstance
            | Self::RemoveSmartContractBytes
            | Self::RegisterSmartContractCode
            | Self::RegisterSmartContractBytes
            | Self::ActivateContractInstance
            | Self::SetVl
            | Self::SysvarAuthority
            // Every host binds SYSVAR_BLOCK_TIME_MS to the same logical time as
            // CURRENT_TIME_MS (transaction creation time for transaction calls),
            // so a second source clock would only suggest a trust difference
            // that does not exist. `context::transaction_time_ms` is the clock.
            | Self::BlockTimeMs => BuiltinMode::CompilerInternal,
            _ => BuiltinMode::Any,
        }
    }
    /// Return the gas charging class for this builtin.
    pub const fn gas_class(self) -> BuiltinGasClass {
        match self {
            Self::Sm3Hash
            | Self::Sha256Hash
            | Self::Sha3Hash
            | Self::Blake2b256Hash
            | Self::Keccak256Hash
            | Self::IrohaHash
            | Self::VerifySignature
            | Self::VrfVerifyBatch
            | Self::EncodeJson
            | Self::DecodeJson
            | Self::SchemaEncode
            | Self::SchemaDecode => BuiltinGasClass::LinearInput,
            _ if !self.operation_syscalls().is_empty() => BuiltinGasClass::HostQuoted,
            _ => BuiltinGasClass::Constant,
        }
    }
    /// Return every operation syscall reachable from this builtin's lowering.
    ///
    /// This deliberately excludes `INPUT_PUBLISH_TLV`, which is pointer-ABI
    /// transport rather than the operation being authorized and scheduled.
    pub const fn operation_syscalls(self) -> &'static [u32] {
        use ivm_abi::syscalls as s;
        match self {
            Self::PointerConstructor(PointerConstructor::AccountId) | Self::ResolveAccountAlias => {
                &[s::SYSCALL_RESOLVE_ACCOUNT_ALIAS]
            }
            Self::PointerConstructor(_)
            | Self::KeysTake2
            | Self::ValuesTake2
            | Self::KeysValuesTake2
            | Self::BuildSubmitBallotInline
            | Self::StringAsBytes
            | Self::NumericToIntDirect
            | Self::NumericAddDirect
            | Self::NumericSubDirect
            | Self::NumericMulDirect
            | Self::NumericDivDirect
            | Self::NumericRemDirect
            | Self::NumericNegDirect
            | Self::NumericEqDirect
            | Self::NumericNeDirect
            | Self::NumericLtDirect
            | Self::NumericLeDirect
            | Self::NumericGtDirect
            | Self::NumericGeDirect
            | Self::WrappingAdd
            | Self::WrappingSub
            | Self::WrappingMul
            | Self::WrappingNeg
            | Self::Poseidon2
            | Self::Poseidon6
            | Self::Pubkgen
            | Self::SetVl
            | Self::NumericSpecUnconstrained
            | Self::NumericSpecInteger
            | Self::NumericSpecFractional
            | Self::MintableInfinitely
            | Self::MintableOnce
            | Self::MintableNot
            | Self::MintableLimited
            | Self::SignatureSchemeEd25519
            | Self::SignatureSchemeSecp256k1
            | Self::SignatureSchemeMlDsa => &[],
            Self::Contains => &[
                s::SYSCALL_STATE_VALUE_ENCODE,
                s::SYSCALL_BUILD_PATH_KEY_NORITO,
                s::SYSCALL_STATE_GET,
            ],
            Self::GetOrInsert => &[
                s::SYSCALL_BUILD_PATH_KEY_NORITO,
                s::SYSCALL_STATE_GET,
                s::SYSCALL_STATE_VALUE_DECODE,
                s::SYSCALL_STATE_VALUE_ENCODE,
                s::SYSCALL_STATE_SET,
            ],
            Self::StateMapRemove => &[
                s::SYSCALL_STATE_VALUE_ENCODE,
                s::SYSCALL_BUILD_PATH_KEY_NORITO,
                s::SYSCALL_STATE_GET,
                s::SYSCALL_STATE_VALUE_DECODE,
                s::SYSCALL_STATE_DEL,
            ],
            Self::StateGet => &[s::SYSCALL_STATE_GET],
            Self::StateSet => &[s::SYSCALL_STATE_SET],
            Self::StateDel => &[s::SYSCALL_STATE_DEL],
            Self::StateHas => &[s::SYSCALL_STATE_HAS],
            Self::StateLen => &[s::SYSCALL_STATE_LEN],
            Self::StateCount => &[s::SYSCALL_STATE_COUNT],
            Self::QueryExecuteNorito => &[s::SYSCALL_QUERY_EXECUTE_NORITO],
            Self::QueryGetAccount
            | Self::QueryGetAsset
            | Self::QueryGetAssetDefinition
            | Self::QueryGetDomain
            | Self::QueryGetNft => &[s::SYSCALL_CORE_QUERY_GET],
            Self::QueryPageAccounts
            | Self::QueryPageAssets
            | Self::QueryPageAssetsOf
            | Self::QueryPageAssetDefinitions
            | Self::QueryPageDomains
            | Self::QueryPageNfts => &[s::SYSCALL_CORE_QUERY_PAGE],
            Self::QueryGetParameter => &[s::SYSCALL_QUERY_GET_PARAMETER],
            Self::QueryGetContractManifest => &[s::SYSCALL_QUERY_GET_CONTRACT_MANIFEST],
            Self::QueryGetContractInstance => &[s::SYSCALL_QUERY_GET_CONTRACT_INSTANCE],
            Self::ScExecuteSubmitBallot => &[s::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION],
            Self::ExecuteQuery => &[s::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY],
            Self::SubscriptionBill => &[s::SYSCALL_SUBSCRIPTION_BILL],
            Self::SubscriptionRecordUsage => &[s::SYSCALL_SUBSCRIPTION_RECORD_USAGE],
            Self::GetAccountBalance => &[s::SYSCALL_GET_ACCOUNT_BALANCE],
            Self::GetPublicInput | Self::TriggerEvent => &[s::SYSCALL_GET_PUBLIC_INPUT],
            Self::DebugPrint => &[s::SYSCALL_DEBUG_PRINT],
            Self::DebugLog => &[s::SYSCALL_DEBUG_LOG],
            Self::Info => &[s::SYSCALL_POINTER_TO_NORITO, s::SYSCALL_DEBUG_LOG],
            Self::Assert | Self::AssertEq => {
                &[s::SYSCALL_KOTO_TEST_ASSERT_FAILED, s::SYSCALL_ABORT]
            }
            Self::Require => &[s::SYSCALL_CONTRACT_ABORT],
            Self::TestInvokeEntrypoint | Self::TestInvokeEntrypointAs => {
                &[s::SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS]
            }
            Self::TestExpectRejectAs | Self::TestExpectAnyRejectAs => {
                &[s::SYSCALL_KOTO_TEST_EXPECT_REJECT_AS]
            }
            Self::TestActorAccount => &[s::SYSCALL_KOTO_TEST_ACTOR_ACCOUNT],
            Self::TestActorPublicKey => &[s::SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY],
            Self::TestActorSign => &[s::SYSCALL_KOTO_TEST_ACTOR_SIGN],
            Self::TestSetBlockHeight => &[s::SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT],
            Self::TestAdvanceBlocks => &[s::SYSCALL_KOTO_TEST_ADVANCE_BLOCKS],
            Self::TestSetTransactionTimeMs => &[s::SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS],
            Self::SetAccountMetadata => &[s::SYSCALL_SET_ACCOUNT_DETAIL],
            Self::MintAsset => &[s::SYSCALL_MINT_ASSET],
            Self::BurnAsset => &[s::SYSCALL_BURN_ASSET],
            Self::TransferAsset => &[s::SYSCALL_TRANSFER_ASSET_SCOPED],
            Self::SetAssetTransferAvailability => &[s::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY],
            Self::SetAssetTransferDailyLimit => &[s::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT],
            Self::SetAssetHoldingLimit => &[s::SYSCALL_SET_ASSET_HOLDING_LIMIT],
            Self::AccountRecoveryPropose => &[s::SYSCALL_ACCOUNT_RECOVERY_PROPOSE],
            Self::AccountRecoveryApprove => &[s::SYSCALL_ACCOUNT_RECOVERY_APPROVE],
            Self::AccountRecoveryCancel => &[s::SYSCALL_ACCOUNT_RECOVERY_CANCEL],
            Self::AccountRecoveryFinalize => &[s::SYSCALL_ACCOUNT_RECOVERY_FINALIZE],
            Self::NftMintAsset => &[s::SYSCALL_NFT_MINT_ASSET],
            Self::NftSetMetadata => &[s::SYSCALL_NFT_SET_METADATA],
            Self::NftBurnAsset => &[s::SYSCALL_NFT_BURN_ASSET],
            Self::NftTransferAsset => &[s::SYSCALL_NFT_TRANSFER_ASSET],
            Self::RegisterDomain => &[s::SYSCALL_REGISTER_DOMAIN],
            Self::UnregisterDomain => &[s::SYSCALL_UNREGISTER_DOMAIN],
            Self::TransferDomain => &[s::SYSCALL_TRANSFER_DOMAIN],
            Self::RegisterAccount => &[s::SYSCALL_REGISTER_ACCOUNT],
            Self::UnregisterAccount => &[s::SYSCALL_UNREGISTER_ACCOUNT],
            Self::RegisterAsset => &[s::SYSCALL_REGISTER_ASSET],
            Self::UnregisterAsset => &[s::SYSCALL_UNREGISTER_ASSET],
            Self::RegisterPeer => &[s::SYSCALL_REGISTER_PEER],
            Self::UnregisterPeer => &[s::SYSCALL_UNREGISTER_PEER],
            Self::RegisterTrigger => &[s::SYSCALL_CREATE_TRIGGER],
            Self::UnregisterTrigger => &[s::SYSCALL_REMOVE_TRIGGER],
            Self::SetTriggerEnabled => &[s::SYSCALL_SET_TRIGGER_ENABLED],
            Self::RegisterRole => &[s::SYSCALL_CREATE_ROLE],
            Self::UnregisterRole => &[s::SYSCALL_DELETE_ROLE],
            Self::GrantRole => &[s::SYSCALL_GRANT_ROLE],
            Self::RevokeRole => &[s::SYSCALL_REVOKE_ROLE],
            Self::GrantPermission => &[s::SYSCALL_GRANT_PERMISSION],
            Self::RevokePermission => &[s::SYSCALL_REVOKE_PERMISSION],
            Self::GrantContractPermission => &[s::SYSCALL_GRANT_CONTRACT_PERMISSION],
            Self::RevokeContractPermission => &[s::SYSCALL_REVOKE_CONTRACT_PERMISSION],
            Self::EscrowOpenOffer => &[s::SYSCALL_ESCROW_OPEN_OFFER],
            Self::EscrowAccept => &[s::SYSCALL_ESCROW_ACCEPT],
            Self::EscrowMarkPaymentSent => &[s::SYSCALL_ESCROW_MARK_PAYMENT_SENT],
            Self::EscrowRelease => &[s::SYSCALL_ESCROW_RELEASE],
            Self::EscrowCancel => &[s::SYSCALL_ESCROW_CANCEL],
            Self::EscrowOpenDispute => &[s::SYSCALL_ESCROW_OPEN_DISPUTE],
            Self::EscrowResolveDispute => &[s::SYSCALL_ESCROW_RESOLVE_DISPUTE],
            Self::GetPrivateInput => &[s::SYSCALL_GET_PRIVATE_INPUT],
            Self::CommitOutput => &[s::SYSCALL_COMMIT_OUTPUT],
            Self::CreateNftsForAllUsers => &[s::SYSCALL_CREATE_NFTS_FOR_ALL_USERS],
            Self::SetExecutionDepth => &[s::SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH],
            Self::TransferBatch => &[
                s::SYSCALL_TRANSFER_V1_BATCH_BEGIN,
                s::SYSCALL_TRANSFER_V1,
                s::SYSCALL_TRANSFER_V1_BATCH_END,
            ],
            Self::AxtBegin => &[s::SYSCALL_AXT_BEGIN],
            Self::AxtTouch => &[s::SYSCALL_AXT_TOUCH],
            Self::StageAnchoredSpend => &[s::SYSCALL_AXT_STAGE_ANCHORED_SPEND],
            Self::VerifyDsProof => &[s::SYSCALL_VERIFY_DS_PROOF],
            Self::AxtCommit => &[s::SYSCALL_AXT_COMMIT],
            Self::DeactivateContractInstance => &[s::SYSCALL_DEACTIVATE_CONTRACT_INSTANCE],
            Self::RemoveSmartContractBytes => &[s::SYSCALL_REMOVE_SMART_CONTRACT_BYTES],
            Self::RegisterSmartContractCode => &[s::SYSCALL_REGISTER_SMART_CONTRACT_CODE],
            Self::RegisterSmartContractBytes => &[s::SYSCALL_REGISTER_SMART_CONTRACT_BYTES],
            Self::ActivateContractInstance => &[s::SYSCALL_ACTIVATE_CONTRACT_INSTANCE],
            Self::ZkRootsGet => &[s::SYSCALL_ZK_ROOTS_GET],
            Self::ZkVoteGetTally => &[s::SYSCALL_ZK_VOTE_GET_TALLY],
            Self::ZkVerifyBatch => &[s::SYSCALL_ZK_VERIFY_BATCH],
            Self::ZkVoteVerifyBallot => &[s::SYSCALL_ZK_VOTE_VERIFY_BALLOT],
            Self::ZkVoteVerifyTally => &[s::SYSCALL_ZK_VOTE_VERIFY_TALLY],
            Self::VrfEpochSeed => &[s::SYSCALL_VRF_EPOCH_SEED],
            Self::VrfVerify => &[s::SYSCALL_VRF_VERIFY],
            Self::VrfVerifyBatch => &[s::SYSCALL_VRF_VERIFY_BATCH],
            Self::Sm3Hash => &[s::SYSCALL_SM3_HASH],
            Self::Sha256Hash => &[s::SYSCALL_SHA256_HASH],
            Self::Sha3Hash => &[s::SYSCALL_SHA3_HASH],
            Self::Blake2b256Hash => &[s::SYSCALL_BLAKE2B256_HASH],
            Self::Keccak256Hash => &[s::SYSCALL_KECCAK256_HASH],
            Self::IrohaHash => &[s::SYSCALL_IROHA_HASH],
            Self::Sm2Verify => &[s::SYSCALL_SM2_VERIFY],
            Self::VerifySignature => &[s::SYSCALL_VERIFY_SIGNATURE],
            Self::Sm4GcmSeal => &[s::SYSCALL_SM4_GCM_SEAL],
            Self::Sm4GcmOpen => &[s::SYSCALL_SM4_GCM_OPEN],
            Self::Sm4CcmSeal => &[s::SYSCALL_SM4_CCM_SEAL],
            Self::Sm4CcmOpen => &[s::SYSCALL_SM4_CCM_OPEN],
            Self::Alloc => &[s::SYSCALL_ALLOC],
            Self::ExecutionSummary => &[s::SYSCALL_EXECUTION_SUMMARY],
            Self::GrowHeap => &[s::SYSCALL_GROW_HEAP],
            Self::VerifyProof => &[s::SYSCALL_VERIFY_PROOF],
            Self::GetMerklePath => &[s::SYSCALL_GET_MERKLE_PATH],
            Self::GetMerkleCompact => &[s::SYSCALL_GET_MERKLE_COMPACT],
            Self::GetRegisterMerkleCompact => &[s::SYSCALL_GET_REGISTER_MERKLE_COMPACT],
            Self::SoracloudReadCommittedState => &[s::SYSCALL_SORACLOUD_READ_COMMITTED_STATE],
            Self::SoracloudEmitStateMutation => &[s::SYSCALL_SORACLOUD_EMIT_STATE_MUTATION],
            Self::SoracloudEmitMailboxMessage => &[s::SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE],
            Self::SoracloudAppendJournal => &[s::SYSCALL_SORACLOUD_APPEND_JOURNAL],
            Self::SoracloudPublishCheckpoint => &[s::SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT],
            Self::SoracloudReadConfig => &[s::SYSCALL_SORACLOUD_READ_CONFIG],
            Self::SoracloudReadSecretEnvelope => &[s::SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE],
            Self::AddSignatory => &[s::SYSCALL_ADD_SIGNATORY],
            Self::RemoveSignatory => &[s::SYSCALL_REMOVE_SIGNATORY],
            Self::SetAccountQuorum => &[s::SYSCALL_SET_ACCOUNT_QUORUM],
            Self::Path => &[
                s::SYSCALL_STATE_VALUE_ENCODE,
                s::SYSCALL_BUILD_PATH_KEY_NORITO,
            ],
            Self::NameDecode => &[s::SYSCALL_NAME_DECODE],
            Self::TlvEq => &[s::SYSCALL_TLV_EQ],
            Self::TlvLen | Self::BytesLen | Self::StringLen => &[s::SYSCALL_TLV_LEN],
            Self::ValueEncode => &[s::SYSCALL_VALUE_ENCODE],
            Self::BytesConcat | Self::StringConcat => &[s::SYSCALL_BLOB_CONCAT],
            Self::StringFromBytes => &[s::SYSCALL_UTF8_VALIDATE],
            Self::StringFrom => &[s::SYSCALL_VALUE_TO_STRING],
            Self::PointerToNorito => &[s::SYSCALL_POINTER_TO_NORITO],
            Self::JsonObject => &[s::SYSCALL_JSON_OBJECT],
            Self::JsonSetInt => &[s::SYSCALL_JSON_SET_I64],
            Self::JsonSetAccountId => &[s::SYSCALL_JSON_SET_ACCOUNT_ID],
            Self::EncodeJson => &[s::SYSCALL_JSON_ENCODE],
            Self::DecodeJson => &[s::SYSCALL_JSON_DECODE],
            Self::SchemaEncode => &[s::SYSCALL_SCHEMA_ENCODE],
            Self::SchemaDecode => &[s::SYSCALL_SCHEMA_DECODE],
            Self::SchemaInfo => &[s::SYSCALL_SCHEMA_INFO],
            Self::NumericToInt => &[s::SYSCALL_DECIMAL_TO_INT_EXACT],
            Self::NumericNeg => &[s::SYSCALL_INT_NEG, s::SYSCALL_DECIMAL_NEG],
            Self::NumericAdd => &[
                s::SYSCALL_INT_ADD,
                s::SYSCALL_DECIMAL_ADD,
                s::SYSCALL_QUANTITY_ADD,
            ],
            Self::NumericSub => &[
                s::SYSCALL_INT_SUB,
                s::SYSCALL_DECIMAL_SUB,
                s::SYSCALL_QUANTITY_SUB,
            ],
            Self::NumericMul => &[
                s::SYSCALL_INT_MUL,
                s::SYSCALL_DECIMAL_MUL,
                s::SYSCALL_QUANTITY_MUL_DECIMAL,
            ],
            Self::NumericDiv => &[
                s::SYSCALL_INT_DIV,
                s::SYSCALL_DECIMAL_DIV_EXACT,
                s::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
                s::SYSCALL_QUANTITY_RATIO_EXACT,
            ],
            Self::NumericRem => &[s::SYSCALL_INT_REM],
            Self::NumericEq => &[
                s::SYSCALL_INT_EQ,
                s::SYSCALL_DECIMAL_EQ,
                s::SYSCALL_QUANTITY_EQ,
            ],
            Self::NumericNe => &[
                s::SYSCALL_INT_NE,
                s::SYSCALL_DECIMAL_NE,
                s::SYSCALL_QUANTITY_NE,
            ],
            Self::NumericLt => &[
                s::SYSCALL_INT_LT,
                s::SYSCALL_DECIMAL_LT,
                s::SYSCALL_QUANTITY_LT,
            ],
            Self::NumericLe => &[
                s::SYSCALL_INT_LE,
                s::SYSCALL_DECIMAL_LE,
                s::SYSCALL_QUANTITY_LE,
            ],
            Self::NumericGt => &[
                s::SYSCALL_INT_GT,
                s::SYSCALL_DECIMAL_GT,
                s::SYSCALL_QUANTITY_GT,
            ],
            Self::NumericGe => &[
                s::SYSCALL_INT_GE,
                s::SYSCALL_DECIMAL_GE,
                s::SYSCALL_QUANTITY_GE,
            ],
            Self::Isqrt => &[s::SYSCALL_INT_ISQRT],
            Self::Abs => &[
                s::SYSCALL_INT_ABS,
                s::SYSCALL_DECIMAL_LT,
                s::SYSCALL_DECIMAL_NEG,
            ],
            Self::Min => &[
                s::SYSCALL_INT_MIN,
                s::SYSCALL_DECIMAL_LT,
                s::SYSCALL_QUANTITY_LT,
            ],
            Self::Max => &[
                s::SYSCALL_INT_MAX,
                s::SYSCALL_DECIMAL_LT,
                s::SYSCALL_QUANTITY_LT,
            ],
            Self::DivCeil => &[s::SYSCALL_INT_DIV_CEIL],
            Self::Gcd => &[s::SYSCALL_INT_GCD],
            Self::Mean => &[s::SYSCALL_INT_MEAN],
            Self::Valcom => &[s::SYSCALL_PRIVATE_NUMERIC_VALCOM],
            Self::GetInt => &[s::SYSCALL_JSON_GET_INT],
            Self::GetDecimal => &[s::SYSCALL_JSON_GET_DECIMAL],
            Self::GetQuantity => &[s::SYSCALL_JSON_GET_QUANTITY],
            Self::GetJson => &[s::SYSCALL_JSON_GET_JSON],
            Self::GetName => &[s::SYSCALL_JSON_GET_NAME],
            Self::GetAccountId => &[s::SYSCALL_JSON_GET_ACCOUNT_ID],
            Self::GetAssetDefinitionId => &[s::SYSCALL_JSON_GET_ASSET_DEFINITION_ID],
            Self::GetNftId => &[s::SYSCALL_JSON_GET_NFT_ID],
            Self::GetBytesHex => &[s::SYSCALL_JSON_GET_BLOB_HEX],
            Self::GetString => &[s::SYSCALL_JSON_GET_STRING],
            Self::GetBool => &[s::SYSCALL_JSON_GET_BOOL],
            Self::Authority => &[s::SYSCALL_GET_AUTHORITY],
            Self::TransactionTimeMs => &[s::SYSCALL_CURRENT_TIME_MS],
            Self::ContractSubject => &[s::SYSCALL_SYSVAR_CONTRACT_SUBJECT],
            Self::BlockHeight => &[s::SYSCALL_SYSVAR_BLOCK_HEIGHT],
            Self::BlockTimeMs => &[s::SYSCALL_SYSVAR_BLOCK_TIME_MS],
            Self::ChainId => &[s::SYSCALL_SYSVAR_CHAIN_ID],
            Self::ContractAddress => &[s::SYSCALL_SYSVAR_CONTRACT_ADDRESS],
            Self::Entrypoint => &[s::SYSCALL_SYSVAR_ENTRYPOINT],
            Self::SysvarAuthority => &[s::SYSCALL_SYSVAR_AUTHORITY],
        }
    }
    /// Return whether syscall emission is direct or compiler-derived.
    pub const fn lowering(self) -> BuiltinLowering {
        let syscalls = self.operation_syscalls();
        if syscalls.is_empty() {
            return BuiltinLowering::Instructions;
        }
        if matches!(
            self,
            Self::PointerConstructor(PointerConstructor::AccountId)
                | Self::Contains
                | Self::GetOrInsert
                | Self::StateMapRemove
                | Self::TransferBatch
                | Self::Min
                | Self::Max
                | Self::Abs
                | Self::Path
                | Self::Info
                | Self::Valcom
                | Self::Assert
                | Self::AssertEq
                | Self::TestInvokeEntrypoint
                | Self::NumericToInt
                | Self::NumericNeg
                | Self::NumericAdd
                | Self::NumericSub
                | Self::NumericMul
                | Self::NumericDiv
                | Self::NumericRem
                | Self::NumericEq
                | Self::NumericNe
                | Self::NumericLt
                | Self::NumericLe
                | Self::NumericGt
                | Self::NumericGe
        ) {
            BuiltinLowering::DerivedSyscalls
        } else {
            BuiltinLowering::DirectSyscall
        }
    }
    /// Return a direct syscall number when lowering is one-to-one.
    pub const fn syscall(self) -> Option<u32> {
        if !matches!(self.lowering(), BuiltinLowering::DirectSyscall) {
            return None;
        }
        let syscalls = self.operation_syscalls();
        if syscalls.len() == 1 {
            Some(syscalls[0])
        } else {
            None
        }
    }
    /// Return the canonical source-level parameter and return types.
    ///
    /// This match is intentionally exhaustive: adding a builtin without an
    /// explicit signature is a compile error rather than an implicit `any`.
    pub const fn signature(self) -> BuiltinSignature {
        use BuiltinSignature as S;
        let signature = match self {
            Self::PointerConstructor(constructor) => {
                S::new(&["string"], constructor.return_type_name())
            }
            Self::Contains => S::new(&["StateMap<K,V>", "K"], "bool"),
            Self::GetOrInsert => S::new(&["StateMap<K,V>", "K", "V"], "V"),
            Self::StateMapRemove => S::new(&["StateMap<K,V>", "K"], "Option<V>"),
            Self::KeysTake2 | Self::ValuesTake2 => {
                S::new(&["StateMap<int,int>", "int", "int"], "int")
            }
            Self::KeysValuesTake2 => S::new(&["StateMap<int,int>", "int", "int"], "(int,int)"),
            Self::StateGet
            | Self::QueryExecuteNorito
            | Self::QueryGetContractManifest
            | Self::ZkRootsGet
            | Self::ZkVoteGetTally
            | Self::ExecuteQuery
            | Self::VrfVerify
            | Self::VrfVerifyBatch
            | Self::Sm3Hash
            | Self::Sha256Hash
            | Self::Sha3Hash
            | Self::Blake2b256Hash
            | Self::Keccak256Hash
            | Self::IrohaHash => S::new(&["bytes"], "bytes"),
            Self::StateSet => S::new(&["bytes", "bytes"], "()"),
            Self::StateDel
            | Self::ScExecuteSubmitBallot
            | Self::DeactivateContractInstance
            | Self::RemoveSmartContractBytes
            | Self::RegisterSmartContractCode
            | Self::RegisterSmartContractBytes
            | Self::ActivateContractInstance
            | Self::ZkVerifyBatch
            | Self::ZkVoteVerifyBallot
            | Self::ZkVoteVerifyTally => S::new(&["bytes"], "()"),
            Self::StateHas | Self::VerifyProof => S::new(&["bytes"], "bool"),
            Self::StateLen | Self::StateCount | Self::BytesLen => S::new(&["bytes"], "int"),
            Self::VrfEpochSeed => S::new(&["int"], "Option<bytes>"),
            Self::QueryGetAccount => S::new(&["AccountId"], "Option<AccountView>"),
            Self::QueryGetAsset => S::new(&["AssetId"], "Option<AssetView>"),
            Self::QueryGetAssetDefinition => {
                S::new(&["AssetDefinitionId"], "Option<AssetDefinitionView>")
            }
            Self::QueryGetDomain => S::new(&["DomainId"], "Option<DomainView>"),
            Self::QueryGetNft => S::new(&["NftId"], "Option<NftView>"),
            Self::QueryPageAccounts => S::new(&["int", "int"], "QueryPage<AccountView>"),
            Self::QueryPageAssets => S::new(&["int", "int"], "QueryPage<AssetView>"),
            Self::QueryPageAssetsOf => S::new(&["AccountId", "int", "int"], "QueryPage<AssetView>"),
            Self::QueryPageAssetDefinitions => {
                S::new(&["int", "int"], "QueryPage<AssetDefinitionView>")
            }
            Self::QueryPageDomains => S::new(&["int", "int"], "QueryPage<DomainView>"),
            Self::QueryPageNfts => S::new(&["int", "int"], "QueryPage<NftView>"),
            Self::QueryGetParameter | Self::QueryGetContractInstance => {
                S::new(&["Name|bytes"], "bytes")
            }
            Self::BuildSubmitBallotInline => S::new(
                &["string", "bytes", "bytes", "string", "bytes", "bytes"],
                "bytes",
            ),
            Self::ResolveAccountAlias => S::new(&["string|bytes"], "AccountId"),
            Self::SubscriptionBill
            | Self::SubscriptionRecordUsage
            | Self::CommitOutput
            | Self::CreateNftsForAllUsers
            | Self::AxtCommit => S::new(&[], "()"),
            Self::GetAccountBalance => S::new(&["AccountId", "AssetDefinitionId"], "quantity"),
            Self::GetPublicInput => S::new(&["Name"], "bytes"),
            Self::DebugPrint
            | Self::TestSetBlockHeight
            | Self::TestAdvanceBlocks
            | Self::TestSetTransactionTimeMs
            | Self::SetExecutionDepth
            | Self::SetVl => S::new(&["int"], "()"),
            Self::DebugLog => S::new(&["string"], "()"),
            Self::Assert => S::new(&["bool", "string|int?"], "()"),
            Self::Require => S::new(&["bool", "ErrorEnum::Variant"], "()"),
            Self::Info => S::new(&["string|int"], "()"),
            Self::AssertEq => S::new(&["T", "T", "string|int?"], "()"),
            Self::TestInvokeEntrypoint => S::new(&["string", "{parameters}"], "T"),
            Self::TestInvokeEntrypointAs => S::new(&["string", "string", "{parameters}"], "T"),
            Self::TestExpectRejectAs => S::new(
                &[
                    "string",
                    "string",
                    "{parameters}",
                    "ErrorEnum::Variant|test::Rejection",
                ],
                "()",
            ),
            Self::TestExpectAnyRejectAs => S::new(&["string", "string", "{parameters}"], "()"),
            Self::TestActorAccount => S::new(&["string"], "AccountId"),
            Self::TestActorPublicKey | Self::StringAsBytes => S::new(&["string"], "bytes"),
            Self::TestActorSign => S::new(&["string", "bytes"], "bytes"),
            // TODO: add `ledger::domain::set_metadata` and
            // `ledger::asset_definition::set_metadata` with the same shape once the
            // IVM ABI gains domain and asset-definition metadata syscalls.
            Self::SetAccountMetadata => S::new(&["AccountId", "Name", "Json"], "()"),
            Self::MintAsset | Self::BurnAsset => {
                S::new(&["AccountId", "AssetDefinitionId", "quantity"], "()")
            }
            Self::TransferAsset => S::new(
                &[
                    "AccountId",
                    "AccountId",
                    "AssetDefinitionId",
                    "quantity",
                    "DataSpaceId?",
                ],
                "()",
            ),
            Self::SetAssetTransferAvailability => S::new(
                &[
                    "AccountId",
                    "AssetDefinitionId",
                    "int",
                    "bool",
                    "bool",
                    "Option<string>",
                ],
                "()",
            ),
            Self::SetAssetTransferDailyLimit | Self::SetAssetHoldingLimit => S::new(
                &["AccountId", "AssetDefinitionId", "Option<quantity>"],
                "()",
            ),
            Self::AccountRecoveryPropose => S::new(&["string", "AccountId", "int"], "()"),
            Self::AccountRecoveryApprove
            | Self::AccountRecoveryCancel
            | Self::AccountRecoveryFinalize => S::new(&["string", "int"], "()"),
            Self::NftMintAsset => S::new(&["NftId", "AccountId"], "()"),
            Self::NftSetMetadata => S::new(&["NftId", "Name", "Json"], "()"),
            Self::NftBurnAsset => S::new(&["NftId"], "()"),
            Self::NftTransferAsset => S::new(&["AccountId", "NftId", "AccountId"], "()"),
            Self::RegisterDomain | Self::UnregisterDomain => S::new(&["DomainId"], "()"),
            Self::TransferDomain => S::new(&["AccountId", "DomainId|Name", "AccountId"], "()"),
            Self::RegisterAccount | Self::UnregisterAccount => S::new(&["AccountId"], "()"),
            Self::RegisterAsset => S::new(
                &["AssetDefinitionId", "string", "NumericSpec", "Mintable"],
                "()",
            ),
            Self::UnregisterAsset => S::new(&["AssetDefinitionId"], "()"),
            // TODO: replace the Json admin payloads of peer, trigger, signatory
            // and permission builtins with compiler-declared records once their
            // host decoders accept a typed Norito frame instead of Json.
            Self::RegisterPeer | Self::UnregisterPeer | Self::RegisterTrigger => {
                S::new(&["Json"], "()")
            }
            Self::UnregisterTrigger
            | Self::UnregisterRole
            | Self::EscrowAccept
            | Self::EscrowMarkPaymentSent
            | Self::EscrowRelease
            | Self::EscrowCancel => S::new(&["Name"], "()"),
            Self::SetTriggerEnabled => S::new(&["Name", "bool"], "()"),
            Self::RegisterRole => S::new(&["Name", "Json"], "()"),
            Self::GrantRole | Self::RevokeRole => S::new(&["AccountId", "Name"], "()"),
            Self::GrantPermission | Self::RevokePermission => {
                S::new(&["AccountId", "Name|Json"], "()")
            }
            Self::GrantContractPermission | Self::RevokeContractPermission => {
                S::new(&["AccountId", "Permission"], "()")
            }
            Self::EscrowOpenOffer => {
                S::new(&["Name", "AssetDefinitionId", "quantity", "bytes?"], "()")
            }
            Self::EscrowOpenDispute => S::new(&["Name", "bytes?"], "()"),
            Self::EscrowResolveDispute => S::new(&["Name", "quantity", "quantity", "bytes?"], "()"),
            Self::GetPrivateInput => S::new(&["int"], "contextual Secret<numeric>"),
            Self::TransferBatch => S::new(
                &["List<(AccountId,AccountId,AssetDefinitionId,quantity),N>"],
                "()",
            ),
            Self::AxtBegin => S::new(&["AxtDescriptor"], "()"),
            Self::AxtTouch => S::new(&["DataSpaceId", "bytes"], "()"),
            Self::StageAnchoredSpend => S::new(&["AxtAnchoredSpendV1"], "()"),
            Self::VerifyDsProof => S::new(&["DataSpaceId", "ProofBlob"], "bool"),
            Self::Sm2Verify => S::new(&["bytes", "bytes", "bytes", "bytes?"], "bool"),
            Self::VerifySignature => {
                S::new(&["bytes", "bytes", "bytes", "SignatureScheme"], "bool")
            }
            Self::Sm4GcmSeal | Self::Sm4GcmOpen => {
                S::new(&["bytes", "bytes", "bytes", "bytes"], "bytes")
            }
            Self::Sm4CcmSeal | Self::Sm4CcmOpen => {
                S::new(&["bytes", "bytes", "bytes", "bytes", "int?"], "bytes")
            }
            Self::Alloc | Self::GrowHeap | Self::WrappingNeg | Self::Isqrt | Self::Pubkgen => {
                S::new(&["int"], "int")
            }
            Self::ExecutionSummary | Self::ChainId | Self::ContractAddress | Self::Entrypoint => {
                S::new(&[], "bytes")
            }
            Self::GetMerklePath => S::new(&["int", "int", "int?"], "int"),
            Self::GetMerkleCompact | Self::GetRegisterMerkleCompact => {
                S::new(&["int", "int", "int?", "int?"], "int")
            }
            Self::SoracloudReadCommittedState
            | Self::SoracloudEmitStateMutation
            | Self::SoracloudEmitMailboxMessage
            | Self::SoracloudAppendJournal
            | Self::SoracloudPublishCheckpoint
            | Self::SoracloudReadConfig
            | Self::SoracloudReadSecretEnvelope => {
                S::new(&["SoracloudRequest"], "SoracloudResponse")
            }
            Self::AddSignatory | Self::RemoveSignatory => S::new(&["AccountId", "Json"], "()"),
            Self::SetAccountQuorum => S::new(&["AccountId", "int"], "()"),
            Self::Path => S::new(&["Name", "K"], "bytes"),
            Self::NameDecode => S::new(&["bytes"], "Name"),
            Self::TlvEq => S::new(&["pointer-ABI", "pointer-ABI"], "bool"),
            Self::TlvLen => S::new(&["pointer-ABI"], "int"),
            Self::ValueEncode => S::new(&["T"], "bytes"),
            Self::BytesConcat => S::new(&["bytes", "bytes"], "bytes"),
            Self::StringConcat => S::new(&["string", "string"], "string"),
            Self::StringLen => S::new(&["string"], "int"),
            Self::StringFromBytes => S::new(&["bytes"], "Option<string>"),
            Self::StringFrom => S::new(&["bool|int|decimal|quantity|string|Name"], "string"),
            Self::PointerToNorito => S::new(&["pointer-ABI"], "bytes"),
            Self::JsonObject | Self::TriggerEvent => S::new(&[], "Json"),
            Self::JsonSetInt => S::new(&["Json", "Name", "int"], "Json"),
            Self::JsonSetAccountId => S::new(&["Json", "Name", "AccountId"], "Json"),
            Self::EncodeJson => S::new(&["Json"], "bytes"),
            Self::DecodeJson => S::new(&["bytes"], "Json"),
            Self::GetInt => S::new(&["Json", "Name"], "Option<int>"),
            Self::GetDecimal => S::new(&["Json", "Name"], "Option<decimal>"),
            Self::GetQuantity => S::new(&["Json", "Name"], "Option<quantity>"),
            Self::GetJson => S::new(&["Json", "Name"], "Option<Json>"),
            Self::GetName => S::new(&["Json", "Name"], "Option<Name>"),
            Self::GetAccountId => S::new(&["Json", "Name"], "Option<AccountId>"),
            Self::GetAssetDefinitionId => S::new(&["Json", "Name"], "Option<AssetDefinitionId>"),
            Self::GetNftId => S::new(&["Json", "Name"], "Option<NftId>"),
            Self::GetBytesHex => S::new(&["Json", "Name"], "Option<bytes>"),
            Self::GetString => S::new(&["Json", "Name"], "Option<string>"),
            Self::GetBool => S::new(&["Json", "Name"], "Option<bool>"),
            Self::SchemaEncode => S::new(&["Name", "Json"], "bytes"),
            Self::SchemaDecode => S::new(&["Name", "bytes"], "Json"),
            Self::SchemaInfo => S::new(&["Name"], "Json"),
            Self::NumericToInt | Self::NumericToIntDirect => S::new(&["wide-numeric"], "int"),
            Self::NumericNeg | Self::NumericNegDirect => S::new(&["int|decimal"], "same-as-arg0"),
            Self::NumericAdd
            | Self::NumericSub
            | Self::NumericMul
            | Self::NumericDiv
            | Self::NumericRem
            | Self::NumericAddDirect
            | Self::NumericSubDirect
            | Self::NumericMulDirect
            | Self::NumericDivDirect
            | Self::NumericRemDirect => S::new(&["wide-numeric", "same-as-arg0"], "same-as-arg0"),
            Self::NumericEq
            | Self::NumericNe
            | Self::NumericLt
            | Self::NumericLe
            | Self::NumericGt
            | Self::NumericGe
            | Self::NumericEqDirect
            | Self::NumericNeDirect
            | Self::NumericLtDirect
            | Self::NumericLeDirect
            | Self::NumericGtDirect
            | Self::NumericGeDirect => S::new(&["wide-numeric", "same-as-arg0"], "bool"),
            Self::Abs => S::new(&["int|decimal|quantity"], "int|decimal|quantity"),
            Self::WrappingAdd
            | Self::WrappingSub
            | Self::WrappingMul
            | Self::DivCeil
            | Self::Gcd
            | Self::Mean
            | Self::Poseidon2 => S::new(&["int", "int"], "int"),
            Self::Min | Self::Max => S::new(
                &["int|decimal|quantity", "int|decimal|quantity"],
                "int|decimal|quantity",
            ),
            Self::Valcom => S::new(
                &[
                    "Secret<int|decimal|quantity>",
                    "Secret<int|decimal|quantity>",
                ],
                "int",
            ),
            Self::Poseidon6 => S::new(&["int", "int", "int", "int", "int", "int"], "int"),
            Self::Authority | Self::SysvarAuthority | Self::ContractSubject => {
                S::new(&[], "AccountId")
            }
            Self::TransactionTimeMs | Self::BlockHeight | Self::BlockTimeMs => S::new(&[], "int"),
            Self::NumericSpecUnconstrained | Self::NumericSpecInteger => S::new(&[], "NumericSpec"),
            Self::NumericSpecFractional => S::new(&["int"], "NumericSpec"),
            Self::MintableInfinitely | Self::MintableOnce | Self::MintableNot => {
                S::new(&[], "Mintable")
            }
            Self::MintableLimited => S::new(&["int"], "Mintable"),
            Self::SignatureSchemeEd25519
            | Self::SignatureSchemeSecp256k1
            | Self::SignatureSchemeMlDsa => S::new(&[], "SignatureScheme"),
        };
        match self {
            Self::PointerConstructor(_) => signature.with_names(&["value"]),
            Self::Contains | Self::StateMapRemove => signature.with_names(&["map", "key"]),
            Self::GetOrInsert => signature.with_names(&["map", "key", "default"]),
            Self::KeysTake2 | Self::ValuesTake2 | Self::KeysValuesTake2 => {
                signature.with_names(&["map", "offset", "limit"])
            }
            Self::StateGet
            | Self::StateDel
            | Self::StateHas
            | Self::StateLen
            | Self::StateCount => signature.with_names(&["path"]),
            Self::StateSet => signature.with_names(&["path", "value"]),
            Self::QueryGetAccount
            | Self::QueryGetAsset
            | Self::QueryGetAssetDefinition
            | Self::QueryGetDomain
            | Self::QueryGetNft => signature.with_names(&["id"]),
            Self::QueryPageAccounts
            | Self::QueryPageAssets
            | Self::QueryPageAssetDefinitions
            | Self::QueryPageDomains
            | Self::QueryPageNfts => signature.with_names(&["offset", "limit"]),
            Self::QueryPageAssetsOf => signature.with_names(&["account", "offset", "limit"]),
            Self::QueryGetParameter | Self::QueryGetContractInstance | Self::GetPublicInput => {
                signature.with_names(&["name"])
            }
            Self::QueryExecuteNorito | Self::QueryGetContractManifest | Self::ExecuteQuery => {
                signature.with_names(&["query"])
            }
            Self::BuildSubmitBallotInline => signature.with_names(&[
                "election_id",
                "ciphertext",
                "nullifier",
                "backend",
                "proof",
                "verification_key",
            ]),
            Self::ResolveAccountAlias => signature.with_names(&["alias"]),
            Self::GetAccountBalance => signature.with_names(&["account", "asset_definition"]),
            Self::Assert => signature.with_names(&["condition", "message"]),
            Self::Require => signature.with_names(&["condition", "error"]),
            Self::AssertEq => signature.with_names(&["actual", "expected", "message"]),
            Self::TestInvokeEntrypoint => signature.with_names(&["kotoage", "arguments"]),
            Self::TestInvokeEntrypointAs | Self::TestExpectAnyRejectAs => {
                signature.with_names(&["actor", "kotoage", "arguments"])
            }
            Self::TestExpectRejectAs => {
                signature.with_names(&["actor", "kotoage", "arguments", "expected"])
            }
            Self::TestActorAccount | Self::TestActorPublicKey => signature.with_names(&["actor"]),
            Self::TestActorSign => signature.with_names(&["actor", "payload"]),
            Self::TestSetBlockHeight => signature.with_names(&["height"]),
            Self::TestAdvanceBlocks => signature.with_names(&["count"]),
            Self::TestSetTransactionTimeMs => signature.with_names(&["time_ms"]),
            Self::SetAccountMetadata => signature.with_names(&["account", "key", "value"]),
            Self::MintAsset | Self::BurnAsset => {
                signature.with_names(&["account", "asset_definition", "amount"])
            }
            Self::TransferAsset => signature.with_names(&[
                "source",
                "destination",
                "asset_definition",
                "amount",
                "dataspace",
            ]),
            Self::SetAssetTransferAvailability => signature.with_names(&[
                "account",
                "asset_definition",
                "expected_revision",
                "incoming",
                "outgoing",
                "reason",
            ]),
            Self::SetAssetTransferDailyLimit => {
                signature.with_names(&["account", "asset_definition", "cap"])
            }
            Self::SetAssetHoldingLimit => {
                signature.with_names(&["account", "asset_definition", "limit"])
            }
            Self::AccountRecoveryPropose => {
                signature.with_names(&["alias", "replacement", "request_generation"])
            }
            Self::AccountRecoveryApprove
            | Self::AccountRecoveryCancel
            | Self::AccountRecoveryFinalize => {
                signature.with_names(&["alias", "request_generation"])
            }
            Self::NftMintAsset => signature.with_names(&["nft", "owner"]),
            Self::NftSetMetadata => signature.with_names(&["nft", "key", "value"]),
            Self::NftBurnAsset => signature.with_names(&["nft"]),
            Self::NftTransferAsset => signature.with_names(&["source", "nft", "destination"]),
            Self::RegisterDomain | Self::UnregisterDomain => signature.with_names(&["domain"]),
            Self::TransferDomain => signature.with_names(&["source", "domain", "destination"]),
            Self::RegisterAccount | Self::UnregisterAccount => signature.with_names(&["account"]),
            Self::RegisterAsset => {
                signature.with_names(&["asset_definition", "name", "spec", "mintable"])
            }
            Self::UnregisterAsset => signature.with_names(&["asset_definition"]),
            Self::RegisterPeer | Self::UnregisterPeer => signature.with_names(&["peer"]),
            // The Json trigger specification and the Name of a registered
            // trigger carry different labels so the two cannot be confused.
            Self::RegisterTrigger => signature.with_names(&["trigger_spec"]),
            Self::UnregisterTrigger => signature.with_names(&["trigger"]),
            Self::SetTriggerEnabled => signature.with_names(&["trigger", "enabled"]),
            Self::RegisterRole => signature.with_names(&["role", "permissions"]),
            Self::UnregisterRole => signature.with_names(&["role"]),
            Self::AddSignatory | Self::RemoveSignatory => {
                signature.with_names(&["account", "signatory"])
            }
            Self::SetAccountQuorum => signature.with_names(&["account", "quorum"]),
            Self::GrantRole | Self::RevokeRole => signature.with_names(&["account", "role"]),
            Self::GrantPermission
            | Self::RevokePermission
            | Self::GrantContractPermission
            | Self::RevokeContractPermission => signature.with_names(&["account", "permission"]),
            Self::EscrowOpenOffer => {
                signature.with_names(&["offer", "asset_definition", "amount", "evidence"])
            }
            Self::EscrowOpenDispute => signature.with_names(&["offer", "evidence"]),
            Self::EscrowAccept
            | Self::EscrowMarkPaymentSent
            | Self::EscrowRelease
            | Self::EscrowCancel => signature.with_names(&["offer"]),
            Self::EscrowResolveDispute => {
                signature.with_names(&["offer", "buyer_amount", "seller_amount", "evidence"])
            }
            Self::TransferBatch => signature.with_names(&["transfers"]),
            Self::SetExecutionDepth => signature.with_names(&["depth"]),
            Self::AxtBegin => signature.with_names(&["descriptor"]),
            Self::AxtTouch => signature.with_names(&["dataspace", "manifest"]),
            Self::StageAnchoredSpend => signature.with_names(&["spend"]),
            Self::VerifyDsProof => signature.with_names(&["dataspace", "proof"]),
            Self::VrfEpochSeed => signature.with_names(&["epoch"]),
            Self::VrfVerify
            | Self::DeactivateContractInstance
            | Self::RemoveSmartContractBytes
            | Self::RegisterSmartContractCode
            | Self::RegisterSmartContractBytes
            | Self::ActivateContractInstance
            | Self::ZkVerifyBatch
            | Self::ZkVoteVerifyBallot
            | Self::ZkVoteVerifyTally
            | Self::VrfVerifyBatch
            | Self::SoracloudReadCommittedState
            | Self::SoracloudEmitStateMutation
            | Self::SoracloudEmitMailboxMessage
            | Self::SoracloudAppendJournal
            | Self::SoracloudPublishCheckpoint
            | Self::SoracloudReadConfig
            | Self::SoracloudReadSecretEnvelope => signature.with_names(&["request"]),
            Self::GetPrivateInput => signature.with_names(&["index"]),
            Self::Path => signature.with_names(&["path", "key"]),
            Self::Sm2Verify => {
                signature.with_names(&["message", "signature", "public_key", "distid"])
            }
            Self::VerifySignature => {
                signature.with_names(&["message", "signature", "public_key", "scheme"])
            }
            Self::Sm4GcmSeal | Self::Sm4GcmOpen => {
                signature.with_names(&["key", "nonce", "aad", "payload"])
            }
            Self::Sm4CcmSeal | Self::Sm4CcmOpen => {
                signature.with_names(&["key", "nonce", "aad", "payload", "tag_length"])
            }
            Self::GetMerklePath => signature.with_names(&["address", "output", "root_output"]),
            Self::GetMerkleCompact | Self::GetRegisterMerkleCompact => {
                signature.with_names(&["address_or_register", "output", "max_depth", "root_output"])
            }
            Self::TlvEq
            | Self::NumericAdd
            | Self::NumericSub
            | Self::NumericMul
            | Self::NumericDiv
            | Self::NumericRem
            | Self::NumericEq
            | Self::NumericNe
            | Self::NumericLt
            | Self::NumericLe
            | Self::NumericGt
            | Self::NumericGe
            | Self::NumericAddDirect
            | Self::NumericSubDirect
            | Self::NumericMulDirect
            | Self::NumericDivDirect
            | Self::NumericRemDirect
            | Self::NumericEqDirect
            | Self::NumericNeDirect
            | Self::NumericLtDirect
            | Self::NumericLeDirect
            | Self::NumericGtDirect
            | Self::NumericGeDirect
            | Self::WrappingAdd
            | Self::WrappingSub
            | Self::WrappingMul
            | Self::Min
            | Self::Max
            | Self::Gcd
            | Self::Mean
            | Self::Poseidon2
            | Self::Valcom => signature.with_names(&["left", "right"]),
            Self::JsonSetInt | Self::JsonSetAccountId => {
                signature.with_names(&["object", "key", "value"])
            }
            Self::GetInt
            | Self::GetDecimal
            | Self::GetQuantity
            | Self::GetJson
            | Self::GetName
            | Self::GetAccountId
            | Self::GetAssetDefinitionId
            | Self::GetNftId
            | Self::GetBytesHex
            | Self::GetString
            | Self::GetBool => signature.with_names(&["object", "key"]),
            Self::NumericSpecFractional => signature.with_names(&["scale"]),
            Self::MintableLimited => signature.with_names(&["tokens"]),
            Self::DivCeil => signature.with_names(&["dividend", "divisor"]),
            Self::Poseidon6 => signature.with_names(&["a", "b", "c", "d", "e", "f"]),
            _ => signature,
        }
    }
    /// Return the source argument policy attached to this builtin.
    ///
    /// See [`BuiltinCallPolicy`] for the published rule. `test::` entries keep
    /// the policies the test runner documents.
    pub const fn call_policy(self) -> BuiltinCallPolicy {
        use BuiltinCallPolicy::{Named, PositionalPrefix};
        let arity = self.signature().parameters.len();
        match self {
            Self::Assert => PositionalPrefix(1),
            Self::AssertEq
            | Self::TestInvokeEntrypoint
            | Self::TestInvokeEntrypointAs
            | Self::TestExpectRejectAs
            | Self::TestExpectAnyRejectAs
            | Self::TestActorSign => Named,
            // Pure helpers whose operands read naturally in order.
            Self::Require
            | Self::BytesConcat
            | Self::StringConcat
            | Self::WrappingAdd
            | Self::WrappingSub
            | Self::WrappingMul
            | Self::Min
            | Self::Max
            | Self::DivCeil
            | Self::Gcd
            | Self::Mean => PositionalPrefix(arity),
            _ if arity == 1 => PositionalPrefix(1),
            _ if matches!(self.surface(), BuiltinSurface::MethodOnly) => PositionalPrefix(arity),
            _ => Named,
        }
    }
    /// Return the canonical builtin registry record.
    pub const fn spec(self) -> BuiltinSpec {
        BuiltinSpec {
            name: self.source_name(),
            effects: self.effects(),
            access: self.access(),
            mode: self.mode(),
            surface: self.surface(),
            gas: self.gas_class(),
            lowering: self.lowering(),
            operation_syscalls: self.operation_syscalls(),
            syscall: self.syscall(),
            signature: self.signature(),
            call_policy: self.call_policy(),
        }
    }
    /// Render the Markdown table of production builtins whose call policy
    /// requires labels, in source-name order.
    ///
    /// `specs/kotodama_grammar.md` embeds this table between the
    /// `kotodama-v1-builtin-call-policy` generated markers; a registry test
    /// keeps the two identical. Every builtin absent from the table accepts
    /// positional arguments.
    pub fn render_label_required_table() -> String {
        use core::fmt::Write as _;
        let mut rows = Self::registry()
            .filter(|(_, spec)| {
                spec.surface != BuiltinSurface::CompilerInternal
                    && spec.mode != BuiltinMode::TestFunctionOnly
                    && spec.mode != BuiltinMode::TestOnly
            })
            .filter_map(|(_, spec)| {
                let labels = spec
                    .signature
                    .parameter_names
                    .iter()
                    .zip(spec.signature.parameters)
                    .enumerate()
                    .filter(|(index, _)| spec.call_policy.label_required(*index))
                    .map(|(_, (name, parameter))| {
                        if parameter.ends_with('?') {
                            format!("`{name}:` (optional)")
                        } else {
                            format!("`{name}:`")
                        }
                    })
                    .collect::<Vec<_>>();
                (!labels.is_empty()).then(|| (spec.name, labels.join(", ")))
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|(name, _)| *name);
        let mut table = String::from("| Builtin | Required labels |\n| --- | --- |\n");
        for (name, labels) in rows {
            writeln!(table, "| `{name}` | {labels} |").expect("writing to a String cannot fail");
        }
        table
    }
    /// Whether the builtin denotes a compile-time `NumericSpec`, `Mintable` or
    /// `SignatureScheme` value.
    ///
    /// These values exist only as arguments to the registry parameters of the
    /// same type. `Mintable` and `SignatureScheme` are compiler-owned nominal
    /// enums spelled like `ListError::IndexOutOfBounds`: payloadless variants
    /// are paths (`Mintable::Once`, `SignatureScheme::Ed25519`) and the payload
    /// variant is a call (`Mintable::Limited(3)`). `NumericSpec` values are the
    /// data model's constructor calls (`NumericSpec::integer()`,
    /// `NumericSpec::fractional(2)`). The compiler folds every one into a
    /// register word and never materializes a runtime value.
    pub const fn is_compile_time_nominal(self) -> bool {
        matches!(
            self,
            Self::NumericSpecUnconstrained
                | Self::NumericSpecInteger
                | Self::NumericSpecFractional
                | Self::MintableInfinitely
                | Self::MintableOnce
                | Self::MintableNot
                | Self::MintableLimited
                | Self::SignatureSchemeEd25519
                | Self::SignatureSchemeSecp256k1
                | Self::SignatureSchemeMlDsa
        )
    }
    /// The compile-time nominal value spelled `path`, such as
    /// `Mintable::Once` or `NumericSpec::fractional`.
    pub fn nominal_value(path: &str) -> Option<Self> {
        Self::from_source_name(path).filter(|builtin| builtin.is_compile_time_nominal())
    }
    /// Whether this compile-time nominal value is written as a bare path
    /// (`Mintable::Once`) rather than a call (`NumericSpec::integer()`,
    /// `Mintable::Limited(3)`).
    pub const fn is_nominal_path(self) -> bool {
        matches!(
            self,
            Self::MintableInfinitely
                | Self::MintableOnce
                | Self::MintableNot
                | Self::SignatureSchemeEd25519
                | Self::SignatureSchemeSecp256k1
                | Self::SignatureSchemeMlDsa
        )
    }
    /// Scheme code a `SignatureScheme` value passes to `VERIFY_SIGNATURE` in
    /// `r13`; the codes are the IVM host's `1` Ed25519, `2` secp256k1 and
    /// `3` ML-DSA.
    pub const fn signature_scheme_code(self) -> Option<u8> {
        match self {
            Self::SignatureSchemeEd25519 => Some(1),
            Self::SignatureSchemeSecp256k1 => Some(2),
            Self::SignatureSchemeMlDsa => Some(3),
            _ => None,
        }
    }
    /// Whether the builtin is a JSON payload helper that public/view entrypoints
    /// must reject in favor of typed parameters.
    pub const fn is_payload_helper(self) -> bool {
        matches!(
            self,
            Self::GetInt
                | Self::GetDecimal
                | Self::GetQuantity
                | Self::GetJson
                | Self::GetName
                | Self::GetAccountId
                | Self::GetAssetDefinitionId
                | Self::GetNftId
                | Self::GetBytesHex
                | Self::GetString
                | Self::GetBool
                | Self::TriggerEvent
        )
    }
}
#[cfg(test)]
mod tests {
    use super::{
        Builtin, BuiltinAccess, BuiltinCallPolicy, BuiltinEffects, BuiltinGasClass,
        BuiltinLowering, BuiltinMode, BuiltinSurface, PointerConstructor,
    };
    use std::collections::HashSet;
    #[test]
    fn release_mutators_are_effectful_in_canonical_registry() {
        for name in [
            "transfer_asset",
            "register_asset",
            "create_nfts_for_all_users",
            "transfer_batch",
            "axt_begin",
            "axt_touch",
            "axt_stage_anchored_spend",
            "axt_commit",
        ] {
            let builtin = Builtin::from_name(name).expect("registered builtin");
            assert_eq!(builtin.effects(), BuiltinEffects::HOST, "{name}");
            assert_eq!(builtin.access(), BuiltinAccess::LedgerWrite, "{name}");
            assert!(!builtin.spec().name.is_empty());
        }
    }
    #[test]
    fn retired_reusable_handle_builtin_is_unregistered() {
        assert!(Builtin::from_name("use_asset_handle").is_none());
        assert!(Builtin::from_name("axt::use_asset_handle").is_none());
    }
    #[test]
    fn raw_and_private_builtins_have_restricted_modes() {
        assert_eq!(Builtin::Alloc.mode(), BuiltinMode::CompilerInternal);
        assert_eq!(Builtin::DebugPrint.mode(), BuiltinMode::CompilerInternal);
        assert_eq!(Builtin::DebugLog.mode(), BuiltinMode::CompilerInternal);
        assert_eq!(
            Builtin::SetExecutionDepth.mode(),
            BuiltinMode::CompilerInternal
        );
        assert_eq!(Builtin::SetVl.mode(), BuiltinMode::CompilerInternal);
        assert_eq!(
            Builtin::NumericAddDirect.mode(),
            BuiltinMode::CompilerInternal
        );
        assert_eq!(Builtin::GetPrivateInput.mode(), BuiltinMode::ZkOnly);
        assert_eq!(Builtin::Assert.mode(), BuiltinMode::TestOnly);
        assert_eq!(Builtin::AssertEq.mode(), BuiltinMode::TestOnly);
        for builtin in [
            Builtin::TestInvokeEntrypoint,
            Builtin::TestInvokeEntrypointAs,
            Builtin::TestExpectRejectAs,
            Builtin::TestActorAccount,
            Builtin::TestActorPublicKey,
            Builtin::TestActorSign,
            Builtin::TestSetBlockHeight,
            Builtin::TestAdvanceBlocks,
            Builtin::TestSetTransactionTimeMs,
        ] {
            assert_eq!(builtin.mode(), BuiltinMode::TestFunctionOnly, "{builtin:?}");
            assert!(builtin.source_name().starts_with("test::"), "{builtin:?}");
            assert_eq!(
                Builtin::from_source_name(builtin.name()),
                None,
                "{builtin:?}"
            );
        }
        for builtin in [
            Builtin::PointerConstructor(PointerConstructor::Domain),
            Builtin::PointerConstructor(PointerConstructor::Blob),
            Builtin::PointerConstructor(PointerConstructor::NoritoBytes),
            Builtin::PointerConstructor(PointerConstructor::ProofBlob),
            Builtin::PointerConstructor(PointerConstructor::SoracloudRequest),
            Builtin::PointerConstructor(PointerConstructor::SoracloudResponse),
            Builtin::PointerToNorito,
            Builtin::EncodeJson,
            Builtin::DecodeJson,
            Builtin::SchemaEncode,
            Builtin::SchemaDecode,
            Builtin::DebugPrint,
            Builtin::DebugLog,
            Builtin::SetExecutionDepth,
            Builtin::DeactivateContractInstance,
            Builtin::RemoveSmartContractBytes,
            Builtin::RegisterSmartContractCode,
            Builtin::RegisterSmartContractBytes,
            Builtin::ActivateContractInstance,
            Builtin::SetVl,
            Builtin::VerifyDsProof,
            Builtin::SoracloudReadCommittedState,
            Builtin::SoracloudEmitStateMutation,
            Builtin::SoracloudEmitMailboxMessage,
            Builtin::SoracloudAppendJournal,
            Builtin::SoracloudPublishCheckpoint,
            Builtin::SoracloudReadConfig,
            Builtin::SoracloudReadSecretEnvelope,
        ] {
            assert_eq!(builtin.mode(), BuiltinMode::CompilerInternal, "{builtin:?}");
            assert_eq!(builtin.surface(), BuiltinSurface::CompilerInternal);
            assert_eq!(Builtin::from_source_name(builtin.source_name()), None);
        }
        assert_eq!(
            Builtin::GetPrivateInput.syscall(),
            Some(ivm_abi::syscalls::SYSCALL_GET_PRIVATE_INPUT)
        );
    }
    #[test]
    fn vm_local_host_operations_do_not_claim_ledger_access() {
        for builtin in [Builtin::CommitOutput, Builtin::SetExecutionDepth] {
            assert_eq!(builtin.effects(), BuiltinEffects::HOST, "{builtin:?}");
            assert_eq!(builtin.spec().access, BuiltinAccess::None, "{builtin:?}");
        }
    }
    #[test]
    fn public_pointer_constructors_have_one_typed_canonical_spelling() {
        for (constructor, canonical) in [
            (PointerConstructor::AccountId, "AccountId::parse"),
            (
                PointerConstructor::AssetDefinition,
                "AssetDefinitionId::parse",
            ),
            (PointerConstructor::AssetId, "AssetId::parse"),
            (PointerConstructor::NftId, "NftId::parse"),
            (PointerConstructor::Name, "Name::parse"),
            (PointerConstructor::Json, "Json::parse"),
            (PointerConstructor::DomainId, "DomainId::parse"),
            (PointerConstructor::DataSpaceId, "DataSpaceId::parse"),
            (PointerConstructor::AxtDescriptor, "AxtDescriptor::parse"),
            (
                PointerConstructor::AxtAnchoredSpendV1,
                "AxtAnchoredSpendV1::parse",
            ),
        ] {
            let builtin = Builtin::PointerConstructor(constructor);
            assert_eq!(builtin.source_name(), canonical);
            assert_eq!(Builtin::from_source_name(canonical), Some(builtin));
            assert_eq!(Builtin::from_source_name(constructor.name()), None);
            assert_eq!(builtin.signature().parameters, &["string"]);
        }
    }
    #[test]
    fn canonical_names_support_constant_evaluation() {
        const DATASPACE: &str = PointerConstructor::DataSpaceId.name();
        const REMOVE: &str = Builtin::StateMapRemove.name();
        const ANCHORED_SPEND: &str = Builtin::StageAnchoredSpend.name();
        const POINTER: &str =
            Builtin::PointerConstructor(PointerConstructor::AssetDefinition).name();
        assert_eq!(DATASPACE, "dataspace_id");
        assert_eq!(REMOVE, "remove");
        assert_eq!(ANCHORED_SPEND, "axt_stage_anchored_spend");
        assert_eq!(POINTER, "asset_definition");
    }
    #[test]
    fn registry_is_exhaustive_and_canonical_names_round_trip() {
        let mut variants = HashSet::new();
        let mut internal_names = HashSet::new();
        let mut source_names = HashSet::new();
        for (builtin, spec) in Builtin::registry() {
            assert!(
                variants.insert(builtin),
                "duplicate registry variant {builtin:?}"
            );
            assert!(
                internal_names.insert(builtin.name()),
                "duplicate internal builtin spelling `{}`",
                builtin.name()
            );
            assert_eq!(
                Builtin::from_name(builtin.name()),
                Some(builtin),
                "internal builtin spelling must resolve uniquely for {builtin:?}"
            );
            assert!(!spec.name.is_empty(), "{builtin:?}");
            assert!(!spec.signature.return_type.is_empty(), "{builtin:?}");
            assert!(
                spec.signature
                    .parameters
                    .iter()
                    .all(|parameter| !parameter.is_empty()),
                "{builtin:?}"
            );
            if matches!(
                spec.surface,
                BuiltinSurface::Function | BuiltinSurface::FunctionOrMethod
            ) {
                assert!(
                    source_names.insert(spec.name),
                    "duplicate source spelling `{}`",
                    spec.name
                );
                assert_eq!(
                    Builtin::from_source_name(builtin.source_name()),
                    Some(builtin),
                    "canonical source spelling must resolve uniquely for {builtin:?}"
                );
            }
            if matches!(
                spec.surface,
                BuiltinSurface::Function | BuiltinSurface::FunctionOrMethod
            ) && (builtin.effects() != BuiltinEffects::NONE
                || builtin.access() != BuiltinAccess::None)
            {
                assert!(
                    builtin.source_name().contains("::"),
                    "effectful builtin {builtin:?} must use a capability namespace"
                );
            }
        }
    }
    #[test]
    fn wrapping_arithmetic_is_explicit_and_pure() {
        for (name, source_name) in [
            ("wrapping_add", "math::wrapping_add"),
            ("wrapping_sub", "math::wrapping_sub"),
            ("wrapping_mul", "math::wrapping_mul"),
            ("wrapping_neg", "math::wrapping_neg"),
        ] {
            let builtin = Builtin::from_name(name).expect("registered wrapping builtin");
            assert_eq!(builtin.name(), name);
            assert_eq!(builtin.source_name(), source_name);
            assert_eq!(Builtin::from_source_name(source_name), Some(builtin));
            assert_eq!(Builtin::from_source_name(name), None);
            assert_eq!(builtin.effects(), BuiltinEffects::NONE);
            assert_eq!(builtin.access(), BuiltinAccess::None);
            assert_eq!(builtin.mode(), BuiltinMode::Any);
            assert_eq!(builtin.syscall(), None);
        }
    }
    #[test]
    fn signatures_publish_named_call_metadata_without_arity_drift() {
        for builtin in Builtin::all() {
            let signature = builtin.signature();
            assert_eq!(
                signature.parameter_names.len(),
                signature.parameters.len(),
                "{builtin:?}"
            );
            let mut unique = std::collections::BTreeSet::new();
            for name in signature.parameter_names {
                assert!(!name.is_empty(), "{builtin:?}");
                assert!(
                    unique.insert(name),
                    "duplicate parameter name on {builtin:?}"
                );
            }
        }
        assert_eq!(
            Builtin::TransferAsset.signature().parameter_names,
            &[
                "source",
                "destination",
                "asset_definition",
                "amount",
                "dataspace"
            ]
        );
        assert_eq!(Builtin::StateSet.call_policy(), BuiltinCallPolicy::Named);
        assert_eq!(
            Builtin::TransferAsset.signature().parameters.last(),
            Some(&"DataSpaceId?")
        );
        for builtin in Builtin::all() {
            if builtin.source_name().starts_with("ledger::")
                && builtin.call_policy() == BuiltinCallPolicy::Named
            {
                assert!(
                    builtin
                        .signature()
                        .parameter_names
                        .iter()
                        .all(|name| !matches!(*name, "first" | "second" | "third" | "fourth")),
                    "ledger operation {builtin:?} must publish meaningful labels"
                );
            }
        }
        for (builtin, names) in [
            (Builtin::AddSignatory, &["account", "signatory"][..]),
            (Builtin::SetAccountQuorum, &["account", "quorum"][..]),
        ] {
            assert_eq!(builtin.signature().parameter_names, names);
            assert_eq!(builtin.call_policy(), BuiltinCallPolicy::Named);
        }
        for (builtin, names) in [
            (Builtin::RegisterTrigger, &["trigger_spec"][..]),
            (Builtin::UnregisterTrigger, &["trigger"][..]),
            (Builtin::UnregisterRole, &["role"][..]),
            (Builtin::RegisterPeer, &["peer"][..]),
        ] {
            assert_eq!(builtin.signature().parameter_names, names);
            assert_eq!(
                builtin.call_policy(),
                BuiltinCallPolicy::PositionalPrefix(1)
            );
        }
        assert_eq!(
            Builtin::BytesLen.call_policy(),
            BuiltinCallPolicy::PositionalPrefix(1)
        );
        assert_eq!(
            Builtin::GetInt.call_policy(),
            BuiltinCallPolicy::PositionalPrefix(2)
        );
        assert_eq!(
            Builtin::GetOrInsert.call_policy(),
            BuiltinCallPolicy::PositionalPrefix(3)
        );
        assert_eq!(Builtin::AssertEq.call_policy(), BuiltinCallPolicy::Named);
    }
    #[test]
    fn native_transfer_control_and_recovery_registry_is_exact() {
        use ivm_abi::syscalls as s;
        for (builtin, name, source_name, syscall, parameters, parameter_names) in [
            (
                Builtin::SetAssetTransferAvailability,
                "set_asset_transfer_availability",
                "ledger::asset::set_transfer_availability",
                s::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
                &[
                    "AccountId",
                    "AssetDefinitionId",
                    "int",
                    "bool",
                    "bool",
                    "Option<string>",
                ][..],
                &[
                    "account",
                    "asset_definition",
                    "expected_revision",
                    "incoming",
                    "outgoing",
                    "reason",
                ][..],
            ),
            (
                Builtin::SetAssetTransferDailyLimit,
                "set_asset_transfer_daily_limit",
                "ledger::asset::set_transfer_daily_limit",
                s::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT,
                &["AccountId", "AssetDefinitionId", "Option<quantity>"][..],
                &["account", "asset_definition", "cap"][..],
            ),
            (
                Builtin::SetAssetHoldingLimit,
                "set_asset_holding_limit",
                "ledger::asset::set_holding_limit",
                s::SYSCALL_SET_ASSET_HOLDING_LIMIT,
                &["AccountId", "AssetDefinitionId", "Option<quantity>"][..],
                &["account", "asset_definition", "limit"][..],
            ),
            (
                Builtin::AccountRecoveryPropose,
                "account_recovery_propose",
                "ledger::account::recovery::propose",
                s::SYSCALL_ACCOUNT_RECOVERY_PROPOSE,
                &["string", "AccountId", "int"][..],
                &["alias", "replacement", "request_generation"][..],
            ),
            (
                Builtin::AccountRecoveryApprove,
                "account_recovery_approve",
                "ledger::account::recovery::approve",
                s::SYSCALL_ACCOUNT_RECOVERY_APPROVE,
                &["string", "int"][..],
                &["alias", "request_generation"][..],
            ),
            (
                Builtin::AccountRecoveryCancel,
                "account_recovery_cancel",
                "ledger::account::recovery::cancel",
                s::SYSCALL_ACCOUNT_RECOVERY_CANCEL,
                &["string", "int"][..],
                &["alias", "request_generation"][..],
            ),
            (
                Builtin::AccountRecoveryFinalize,
                "account_recovery_finalize",
                "ledger::account::recovery::finalize",
                s::SYSCALL_ACCOUNT_RECOVERY_FINALIZE,
                &["string", "int"][..],
                &["alias", "request_generation"][..],
            ),
        ] {
            assert_eq!(builtin.name(), name);
            assert_eq!(builtin.source_name(), source_name);
            assert_eq!(Builtin::from_name(name), Some(builtin));
            assert_eq!(Builtin::from_source_name(source_name), Some(builtin));
            assert_eq!(builtin.operation_syscalls(), &[syscall]);
            assert_eq!(builtin.syscall(), Some(syscall));
            assert_eq!(builtin.lowering(), BuiltinLowering::DirectSyscall);
            assert_eq!(builtin.effects(), BuiltinEffects::HOST);
            assert_eq!(builtin.access(), BuiltinAccess::LedgerWrite);
            let signature = builtin.signature();
            assert_eq!(signature.parameters, parameters);
            assert_eq!(signature.parameter_names, parameter_names);
            assert_eq!(signature.return_type, "()");
        }
    }
    #[test]
    fn seiyaku_permission_registry_is_exact_and_namespaced() {
        use ivm_abi::syscalls as s;
        for (builtin, internal_name, source_name, syscall) in [
            (
                Builtin::GrantContractPermission,
                "grant_contract_permission",
                "ledger::seiyaku::grant_permission",
                s::SYSCALL_GRANT_CONTRACT_PERMISSION,
            ),
            (
                Builtin::RevokeContractPermission,
                "revoke_contract_permission",
                "ledger::seiyaku::revoke_permission",
                s::SYSCALL_REVOKE_CONTRACT_PERMISSION,
            ),
        ] {
            assert_eq!(builtin.name(), internal_name);
            assert_eq!(builtin.source_name(), source_name);
            assert_eq!(Builtin::from_name(internal_name), Some(builtin));
            assert_eq!(Builtin::from_source_name(source_name), Some(builtin));
            assert_eq!(Builtin::from_source_name(internal_name), None);
            assert_eq!(builtin.operation_syscalls(), &[syscall]);
            assert_eq!(builtin.syscall(), Some(syscall));
            assert_eq!(builtin.lowering(), BuiltinLowering::DirectSyscall);
            assert_eq!(builtin.effects(), BuiltinEffects::HOST);
            assert_eq!(builtin.access(), BuiltinAccess::LedgerWrite);
            let signature = builtin.signature();
            assert_eq!(signature.parameters, &["AccountId", "Permission"]);
            assert_eq!(signature.parameter_names, &["account", "permission"]);
            assert_eq!(signature.return_type, "()");
        }
    }
    #[test]
    fn escrow_open_offer_registry_matches_the_lowered_host_abi() {
        let spec = Builtin::EscrowOpenOffer.spec();
        assert_eq!(
            spec.signature.parameters,
            &["Name", "AssetDefinitionId", "quantity", "bytes?"]
        );
        assert_eq!(spec.signature.return_type, "()");
        assert_eq!(
            spec.operation_syscalls,
            &[ivm_abi::syscalls::SYSCALL_ESCROW_OPEN_OFFER]
        );
        assert_eq!(
            spec.syscall,
            Some(ivm_abi::syscalls::SYSCALL_ESCROW_OPEN_OFFER)
        );
    }
    #[test]
    fn projected_core_query_registry_is_typed_and_pages_are_named_only() {
        for (singular, plural, id, view) in [
            (
                Builtin::QueryGetAccount,
                Builtin::QueryPageAccounts,
                "AccountId",
                "AccountView",
            ),
            (
                Builtin::QueryGetAsset,
                Builtin::QueryPageAssets,
                "AssetId",
                "AssetView",
            ),
            (
                Builtin::QueryGetAssetDefinition,
                Builtin::QueryPageAssetDefinitions,
                "AssetDefinitionId",
                "AssetDefinitionView",
            ),
            (
                Builtin::QueryGetDomain,
                Builtin::QueryPageDomains,
                "DomainId",
                "DomainView",
            ),
            (
                Builtin::QueryGetNft,
                Builtin::QueryPageNfts,
                "NftId",
                "NftView",
            ),
        ] {
            assert_eq!(singular.signature().parameters, &[id]);
            assert_eq!(singular.signature().return_type, format!("Option<{view}>"));
            assert_eq!(
                singular.operation_syscalls(),
                &[ivm_abi::syscalls::SYSCALL_CORE_QUERY_GET]
            );
            assert_eq!(plural.signature().parameters, &["int", "int"]);
            assert_eq!(plural.signature().parameter_names, &["offset", "limit"]);
            assert_eq!(plural.signature().return_type, format!("QueryPage<{view}>"));
            assert_eq!(plural.call_policy(), BuiltinCallPolicy::Named);
            assert_eq!(
                plural.operation_syscalls(),
                &[ivm_abi::syscalls::SYSCALL_CORE_QUERY_PAGE]
            );
        }
    }
    #[test]
    fn trigger_registry_exposes_only_canonical_lifecycle_operations() {
        assert_eq!(
            Builtin::from_source_name("ledger::trigger::register"),
            Some(Builtin::RegisterTrigger)
        );
        assert_eq!(
            Builtin::from_source_name("ledger::trigger::unregister"),
            Some(Builtin::UnregisterTrigger)
        );
        assert_eq!(Builtin::from_source_name("ledger::trigger::create"), None);
        assert_eq!(Builtin::from_source_name("ledger::trigger::remove"), None);
        assert_eq!(Builtin::from_name("create_trigger"), None);
        assert_eq!(Builtin::from_name("remove_trigger"), None);
        assert_eq!(
            Builtin::RegisterTrigger.operation_syscalls(),
            &[ivm_abi::syscalls::SYSCALL_CREATE_TRIGGER]
        );
        assert_eq!(
            Builtin::UnregisterTrigger.operation_syscalls(),
            &[ivm_abi::syscalls::SYSCALL_REMOVE_TRIGGER]
        );
    }
    #[test]
    fn typed_json_getter_registry_returns_active_only_options() {
        for (getter, payload) in [
            (Builtin::GetInt, "int"),
            (Builtin::GetQuantity, "quantity"),
            (Builtin::GetJson, "Json"),
            (Builtin::GetName, "Name"),
            (Builtin::GetAccountId, "AccountId"),
            (Builtin::GetAssetDefinitionId, "AssetDefinitionId"),
            (Builtin::GetNftId, "NftId"),
            (Builtin::GetBytesHex, "bytes"),
            (Builtin::GetString, "string"),
            (Builtin::GetBool, "bool"),
        ] {
            let expected = format!("Option<{payload}>");
            assert_eq!(getter.signature().return_type, expected);
            assert_eq!(getter.surface(), BuiltinSurface::MethodOnly, "{getter:?}");
            assert_eq!(getter.source_name(), getter.name(), "{getter:?}");
            assert_eq!(
                getter.call_policy(),
                BuiltinCallPolicy::PositionalPrefix(2),
                "{getter:?}"
            );
        }
        assert_eq!(Builtin::GetQuantity.source_name(), "get_quantity");
        assert_eq!(Builtin::GetBytesHex.name(), "get_bytes_hex");
        for retired in ["json::get_int", "json::get_bytes_hex", "get_blob_hex"] {
            assert_eq!(Builtin::from_source_name(retired), None, "{retired}");
            assert_eq!(Builtin::from_name(retired), None, "{retired}");
        }
    }
    #[test]
    fn source_visible_helpers_are_namespaced_except_language_intrinsics() {
        for builtin in Builtin::all() {
            if builtin.surface() == BuiltinSurface::CompilerInternal {
                continue;
            }
            let source_name = builtin.source_name();
            let is_method = matches!(
                builtin.surface(),
                BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
            );
            assert!(
                source_name.contains("::") || is_method || source_name == "require",
                "source builtin {builtin:?} must be namespaced"
            );
        }
    }
    #[test]
    fn bytes_len_is_a_narrow_pure_source_capability() {
        let builtin = Builtin::BytesLen;
        assert_eq!(Builtin::from_source_name("bytes::len"), Some(builtin));
        assert_eq!(Builtin::from_source_name("bytes_len"), None);
        assert_eq!(builtin.signature().parameters, &["bytes"]);
        assert_eq!(builtin.signature().return_type, "int");
        assert_eq!(builtin.effects(), BuiltinEffects::NONE);
        assert_eq!(builtin.access(), BuiltinAccess::None);
        assert_eq!(builtin.mode(), BuiltinMode::Any);
        assert_eq!(builtin.surface(), BuiltinSurface::Function);
        assert_eq!(
            builtin.operation_syscalls(),
            &[ivm_abi::syscalls::SYSCALL_TLV_LEN]
        );
        assert_eq!(builtin.syscall(), Some(ivm_abi::syscalls::SYSCALL_TLV_LEN));
        assert_eq!(builtin.gas_class(), BuiltinGasClass::HostQuoted);
    }
    #[test]
    fn lowering_registry_is_fail_closed_and_gas_classified() {
        for (builtin, spec) in Builtin::registry() {
            match spec.lowering {
                BuiltinLowering::Instructions => {
                    assert!(spec.operation_syscalls.is_empty(), "{builtin:?}");
                    assert_eq!(spec.syscall, None, "{builtin:?}");
                }
                BuiltinLowering::DirectSyscall => {
                    assert_eq!(spec.operation_syscalls.len(), 1, "{builtin:?}");
                    assert_eq!(
                        spec.syscall,
                        Some(spec.operation_syscalls[0]),
                        "{builtin:?}"
                    );
                }
                BuiltinLowering::DerivedSyscalls => {
                    assert!(!spec.operation_syscalls.is_empty(), "{builtin:?}");
                    assert_eq!(spec.syscall, None, "{builtin:?}");
                }
            }
            if !spec.operation_syscalls.is_empty() {
                assert_ne!(spec.gas, BuiltinGasClass::Constant, "{builtin:?}");
            }
            if matches!(
                spec.access,
                BuiltinAccess::StateWrite | BuiltinAccess::LedgerWrite | BuiltinAccess::Dynamic
            ) {
                assert!(
                    spec.effects.host_side_effects
                        || spec.effects.emits_instructions
                        || spec.effects.mutates_durable_state,
                    "privileged builtin {builtin:?} must not under-report its effects"
                );
            }
        }
    }
    #[test]
    fn state_map_and_path_helpers_are_method_only() {
        for builtin in [
            Builtin::Contains,
            Builtin::GetOrInsert,
            Builtin::StateMapRemove,
            Builtin::Path,
        ] {
            assert_eq!(builtin.surface(), BuiltinSurface::MethodOnly, "{builtin:?}");
            assert_eq!(
                Builtin::from_source_name(builtin.name()),
                None,
                "{builtin:?}"
            );
        }
        // The documented StateMap read surface is `get(key)` returning
        // `Option<V>`; the implicit-default helpers are not builtins.
        for retired in ["get_or", "get_or_default", "ensure"] {
            assert_eq!(Builtin::from_name(retired), None, "{retired}");
        }
        assert_eq!(
            Builtin::GetOrInsert.effects(),
            BuiltinEffects::DURABLE_STATE
        );
        assert_eq!(Builtin::GetOrInsert.access(), BuiltinAccess::StateWrite);
        assert_eq!(
            Builtin::GetOrInsert.signature().parameters,
            &["StateMap<K,V>", "K", "V"]
        );
    }
    #[test]
    fn public_input_registry_matches_the_typed_bytes_surface() {
        let signature = Builtin::GetPublicInput.signature();
        assert_eq!(signature.parameters, &["Name"]);
        assert_eq!(signature.return_type, "bytes");
        assert_eq!(
            Builtin::GetPublicInput.source_name(),
            "context::public_input"
        );
    }
    #[test]
    fn compiler_internal_seiyaku_lifecycle_names_are_branded_but_not_source_visible() {
        for (builtin, branded, english) in [
            (
                Builtin::DeactivateContractInstance,
                "seiyaku::deactivate_instance",
                "contract::deactivate_instance",
            ),
            (
                Builtin::RemoveSmartContractBytes,
                "seiyaku::remove_code",
                "contract::remove_code",
            ),
            (
                Builtin::RegisterSmartContractCode,
                "seiyaku::register_code",
                "contract::register_code",
            ),
            (
                Builtin::RegisterSmartContractBytes,
                "seiyaku::register_bytes",
                "contract::register_bytes",
            ),
            (
                Builtin::ActivateContractInstance,
                "seiyaku::activate_instance",
                "contract::activate_instance",
            ),
        ] {
            assert_eq!(builtin.source_name(), branded);
            assert_eq!(builtin.surface(), BuiltinSurface::CompilerInternal);
            assert_eq!(Builtin::from_source_name(branded), None, "{branded}");
            assert_eq!(Builtin::from_source_name(english), None, "{english}");
        }
    }
    #[test]
    fn truncated_scalar_crypto_and_removed_nullifier_are_not_source_features() {
        for (builtin, source_name) in [
            (Builtin::Poseidon2, "crypto::poseidon2"),
            (Builtin::Poseidon6, "crypto::poseidon6"),
            (Builtin::Pubkgen, "crypto::pubkgen"),
        ] {
            assert_eq!(builtin.source_name(), source_name);
            assert_eq!(builtin.mode(), BuiltinMode::CompilerInternal);
            assert_eq!(builtin.surface(), BuiltinSurface::CompilerInternal);
            assert_eq!(Builtin::from_source_name(source_name), None);
            // Internal lowering identifiers must not accidentally resolve as
            // source spellings either.
            assert_eq!(Builtin::from_source_name(builtin.name()), None);
        }
        assert_eq!(Builtin::from_name("use_nullifier"), None);
        assert_eq!(Builtin::from_source_name("crypto::use_nullifier"), None);
        let commitment = Builtin::Valcom.signature();
        assert_eq!(
            commitment.parameters,
            &[
                "Secret<int|decimal|quantity>",
                "Secret<int|decimal|quantity>",
            ]
        );
        assert_eq!(commitment.return_type, "int");
        assert_eq!(Builtin::Valcom.mode(), BuiltinMode::ZkOnly);
        assert_eq!(
            Builtin::from_source_name("crypto::valcom"),
            Some(Builtin::Valcom)
        );
    }
    #[test]
    fn retired_anonymous_escrow_helpers_are_not_source_features() {
        for (name, source_name) in [
            (
                "anonymous_escrow_open_offer",
                "ledger::escrow::anonymous::open_offer",
            ),
            (
                "anonymous_escrow_accept",
                "ledger::escrow::anonymous::accept",
            ),
            (
                "anonymous_escrow_mark_payment_sent",
                "ledger::escrow::anonymous::mark_payment_sent",
            ),
            (
                "anonymous_escrow_release",
                "ledger::escrow::anonymous::release",
            ),
            (
                "anonymous_escrow_cancel",
                "ledger::escrow::anonymous::cancel",
            ),
            (
                "anonymous_escrow_open_dispute",
                "ledger::escrow::anonymous::open_dispute",
            ),
            (
                "anonymous_escrow_resolve_dispute",
                "ledger::escrow::anonymous::resolve_dispute",
            ),
        ] {
            assert_eq!(Builtin::from_name(name), None, "{name}");
            assert_eq!(
                Builtin::from_source_name(source_name),
                None,
                "{source_name}"
            );
        }
    }
    #[test]
    fn cross_chain_transfers_have_no_contract_builtin() {
        // SCCP v1 sends are signed `RecordSccpMessage` instructions only (specs/sccp.md §4.4);
        // contracts cannot record cross-chain messages.
        for builtin in Builtin::all() {
            let source_name = builtin.source_name();
            assert!(
                !source_name.split("::").any(|segment| segment == "sccp"),
                "{builtin:?} exposes the retired cross-chain source name {source_name}"
            );
            assert_ne!(
                builtin.name(),
                "record_sccp_message",
                "{builtin:?} keeps the retired cross-chain builtin"
            );
        }
        assert_eq!(Builtin::from_name("record_sccp_message"), None);
        assert_eq!(
            Builtin::ScExecuteSubmitBallot.operation_syscalls(),
            &[ivm_abi::syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION]
        );
    }
    #[test]
    fn compiler_internal_numeric_negation_registry_excludes_quantity() {
        for builtin in [Builtin::NumericNeg, Builtin::NumericNegDirect] {
            let signature = builtin.signature();
            assert_eq!(signature.parameters, &["int|decimal"], "{builtin:?}");
            assert_eq!(signature.return_type, "same-as-arg0", "{builtin:?}");
            assert_eq!(builtin.mode(), BuiltinMode::CompilerInternal);
            assert_eq!(builtin.surface(), BuiltinSurface::CompilerInternal);
            assert_eq!(Builtin::from_source_name(builtin.source_name()), None);
        }
    }
    #[test]
    fn source_feature_concepts_use_seiyaku_and_kotoage_names_only() {
        for (builtin, branded, retired_english) in [
            (
                Builtin::ContractSubject,
                "context::seiyaku_subject",
                "context::contract_subject",
            ),
            (
                Builtin::ContractAddress,
                "context::seiyaku_address",
                "context::contract_address",
            ),
            (
                Builtin::Entrypoint,
                "context::kotoage",
                "context::entrypoint",
            ),
            (
                Builtin::QueryGetContractManifest,
                "ledger::query::seiyaku_manifest",
                "ledger::query::contract_manifest",
            ),
            (
                Builtin::QueryGetContractInstance,
                "ledger::query::seiyaku_instance",
                "ledger::query::contract_instance",
            ),
            (
                Builtin::TestInvokeEntrypoint,
                "test::invoke_kotoage",
                "test::invoke_entrypoint",
            ),
            (
                Builtin::TestInvokeEntrypointAs,
                "test::invoke_kotoage_as",
                "test::invoke_entrypoint_as",
            ),
            (
                Builtin::GrantContractPermission,
                "ledger::seiyaku::grant_permission",
                "ledger::contract::grant_entrypoint",
            ),
            (
                Builtin::RevokeContractPermission,
                "ledger::seiyaku::revoke_permission",
                "ledger::contract::revoke_entrypoint",
            ),
        ] {
            assert_eq!(builtin.source_name(), branded);
            assert_eq!(Builtin::from_source_name(branded), Some(builtin));
            assert_eq!(Builtin::from_source_name(retired_english), None);
        }
        assert_eq!(
            Builtin::TestInvokeEntrypoint.signature().parameter_names,
            &["kotoage", "arguments"]
        );
        assert_eq!(
            Builtin::TestInvokeEntrypointAs.signature().parameter_names,
            &["actor", "kotoage", "arguments"]
        );
        assert_eq!(
            Builtin::TestExpectRejectAs.signature().parameter_names,
            &["actor", "kotoage", "arguments", "expected"]
        );
    }
    #[test]
    fn call_policy_follows_the_published_label_rule() {
        for (builtin, spec) in Builtin::registry() {
            if spec.surface == BuiltinSurface::CompilerInternal || spec.name.starts_with("test::") {
                continue;
            }
            let arity = spec.signature.parameters.len();
            let label_optional = (0..arity).all(|index| !spec.call_policy.label_required(index));
            if arity == 1 || spec.surface == BuiltinSurface::MethodOnly {
                assert!(
                    label_optional,
                    "{builtin:?} must accept positional arguments"
                );
            }
            if spec.name.starts_with("math::") || spec.name == "require" {
                assert!(
                    label_optional,
                    "pure helper {builtin:?} must accept positional arguments"
                );
            }
            if arity > 1
                && spec.name.starts_with("ledger::")
                && spec.access == BuiltinAccess::LedgerWrite
            {
                assert_eq!(
                    spec.call_policy,
                    BuiltinCallPolicy::Named,
                    "multi-argument ledger mutation {builtin:?} must require labels"
                );
            }
        }
        assert!(BuiltinCallPolicy::Named.label_required(0));
        assert!(!BuiltinCallPolicy::PositionalPrefix(2).label_required(1));
        assert!(BuiltinCallPolicy::PositionalPrefix(2).label_required(2));
        assert_eq!(
            Builtin::DivCeil.signature().parameter_names,
            &["dividend", "divisor"]
        );
    }
    #[test]
    fn asset_registration_takes_typed_spec_and_mintability() {
        let spec = Builtin::RegisterAsset.spec();
        assert_eq!(
            spec.signature.parameters,
            &["AssetDefinitionId", "string", "NumericSpec", "Mintable"]
        );
        assert_eq!(
            spec.signature.parameter_names,
            &["asset_definition", "name", "spec", "mintable"]
        );
        assert_eq!(
            spec.operation_syscalls,
            &[ivm_abi::syscalls::SYSCALL_REGISTER_ASSET]
        );
        assert_eq!(Builtin::from_source_name("ledger::asset::create"), None);
        assert_eq!(Builtin::from_name("create_new_asset"), None);
        for (builtin, source_name, parameters, return_type) in [
            (
                Builtin::NumericSpecUnconstrained,
                "NumericSpec::unconstrained",
                &[][..],
                "NumericSpec",
            ),
            (
                Builtin::NumericSpecInteger,
                "NumericSpec::integer",
                &[][..],
                "NumericSpec",
            ),
            (
                Builtin::NumericSpecFractional,
                "NumericSpec::fractional",
                &["int"][..],
                "NumericSpec",
            ),
            (
                Builtin::MintableInfinitely,
                "Mintable::Infinitely",
                &[][..],
                "Mintable",
            ),
            (Builtin::MintableOnce, "Mintable::Once", &[][..], "Mintable"),
            (Builtin::MintableNot, "Mintable::Not", &[][..], "Mintable"),
            (
                Builtin::MintableLimited,
                "Mintable::Limited",
                &["int"][..],
                "Mintable",
            ),
        ] {
            assert_eq!(builtin.source_name(), source_name);
            assert_eq!(Builtin::from_source_name(source_name), Some(builtin));
            assert_eq!(Builtin::nominal_value(source_name), Some(builtin));
            assert_eq!(builtin.signature().parameters, parameters);
            assert_eq!(builtin.signature().return_type, return_type);
            assert_eq!(builtin.effects(), BuiltinEffects::NONE);
            assert_eq!(builtin.access(), BuiltinAccess::None);
            assert_eq!(builtin.lowering(), BuiltinLowering::Instructions);
            assert!(builtin.is_compile_time_nominal());
        }
        assert!(!Builtin::RegisterAsset.is_compile_time_nominal());
        assert!(Builtin::MintableOnce.is_nominal_path());
        assert!(!Builtin::MintableLimited.is_nominal_path());
        assert!(!Builtin::NumericSpecInteger.is_nominal_path());
    }
    #[test]
    fn signature_verification_takes_a_compile_time_scheme() {
        let verify = Builtin::VerifySignature.spec();
        assert_eq!(verify.name, "crypto::verify_signature");
        assert_eq!(
            verify.signature.parameters,
            &["bytes", "bytes", "bytes", "SignatureScheme"]
        );
        assert_eq!(
            verify.signature.parameter_names,
            &["message", "signature", "public_key", "scheme"]
        );
        assert_eq!(verify.call_policy, BuiltinCallPolicy::Named);
        assert_eq!(
            verify.operation_syscalls,
            &[ivm_abi::syscalls::SYSCALL_VERIFY_SIGNATURE]
        );
        for (builtin, path, code) in [
            (
                Builtin::SignatureSchemeEd25519,
                "SignatureScheme::Ed25519",
                1,
            ),
            (
                Builtin::SignatureSchemeSecp256k1,
                "SignatureScheme::Secp256k1",
                2,
            ),
            (Builtin::SignatureSchemeMlDsa, "SignatureScheme::MlDsa", 3),
        ] {
            assert_eq!(builtin.source_name(), path);
            assert_eq!(Builtin::nominal_value(path), Some(builtin));
            assert_eq!(builtin.signature_scheme_code(), Some(code));
            assert!(builtin.is_nominal_path());
            assert!(builtin.signature().parameters.is_empty());
            assert_eq!(builtin.signature().return_type, "SignatureScheme");
            assert_eq!(builtin.effects(), BuiltinEffects::NONE);
            assert!(builtin.is_compile_time_nominal());
        }
        assert_eq!(Builtin::Sm2Verify.signature_scheme_code(), None);
        assert_eq!(Builtin::VerifySignature.signature_scheme_code(), None);
        assert_eq!(Builtin::nominal_value("crypto::verify_signature"), None);
        for retired in [
            "crypto::ed25519::verify",
            "crypto::secp256k1::verify",
            "crypto::ml_dsa::verify",
        ] {
            assert_eq!(Builtin::from_source_name(retired), None, "{retired}");
        }
    }
    #[test]
    fn ledger_vocabulary_uses_register_unregister_and_metadata() {
        for (builtin, source_name) in [
            (Builtin::RegisterRole, "ledger::role::register"),
            (Builtin::UnregisterRole, "ledger::role::unregister"),
            (Builtin::SetAccountMetadata, "ledger::account::set_metadata"),
            (Builtin::NftSetMetadata, "ledger::nft::set_metadata"),
        ] {
            assert_eq!(builtin.source_name(), source_name);
            assert_eq!(Builtin::from_source_name(source_name), Some(builtin));
        }
        for retired in [
            "ledger::role::create",
            "ledger::role::delete",
            "ledger::account::set_detail",
        ] {
            assert_eq!(Builtin::from_source_name(retired), None, "{retired}");
        }
        assert_eq!(
            Builtin::SetTriggerEnabled.signature().parameters,
            &["Name", "bool"]
        );
    }
    #[test]
    fn clock_accessors_name_their_trust_source() {
        assert_eq!(
            Builtin::TransactionTimeMs.source_name(),
            "context::transaction_time_ms"
        );
        assert_eq!(
            Builtin::TransactionTimeMs.operation_syscalls(),
            &[ivm_abi::syscalls::SYSCALL_CURRENT_TIME_MS]
        );
        assert_eq!(
            Builtin::BlockTimeMs.surface(),
            BuiltinSurface::CompilerInternal
        );
        assert_eq!(Builtin::from_source_name("context::block_time_ms"), None);
        assert_eq!(Builtin::from_source_name("context::current_time_ms"), None);
        assert_eq!(Builtin::from_name("current_time_ms"), None);
    }
    #[test]
    fn debug_info_is_diagnostics_only() {
        let spec = Builtin::Info.spec();
        assert_eq!(spec.effects, BuiltinEffects::NONE);
        assert_eq!(spec.access, BuiltinAccess::None);
        assert_eq!(spec.mode, BuiltinMode::Any);
        assert_eq!(
            spec.operation_syscalls,
            &[
                ivm_abi::syscalls::SYSCALL_POINTER_TO_NORITO,
                ivm_abi::syscalls::SYSCALL_DEBUG_LOG
            ]
        );
    }
    #[test]
    fn spec_label_table_is_generated_from_the_call_policy() {
        let spec = include_str!("../../../specs/kotodama_grammar.md");
        let start = "<!-- BEGIN GENERATED: kotodama-v1-builtin-call-policy -->\n";
        let end = "<!-- END GENERATED: kotodama-v1-builtin-call-policy -->";
        let begin = spec.find(start).expect("call-policy start marker") + start.len();
        let finish = spec[begin..].find(end).expect("call-policy end marker") + begin;
        let expected = Builtin::render_label_required_table();
        assert_eq!(
            &spec[begin..finish],
            expected,
            "regenerate the spec's builtin label table:\n{expected}"
        );
        assert!(expected.contains("| `ledger::asset::transfer` | `source:`"));
        assert!(!expected.contains("`math::min`"));
        assert!(
            expected.find("| `ledger::query::assets` |").unwrap()
                < expected.find("| `ledger::query::assets_of` |").unwrap(),
            "source names, rather than Markdown delimiters, determine prefix ordering"
        );
    }
    #[test]
    fn forbidden_raw_surfaces_do_not_resolve() {
        for name in [
            "call",
            "call_contract",
            "contract::call",
            "seiyaku::call",
            "ledger::asset::batch::begin",
            "ledger::asset::batch::apply",
            "ledger::asset::batch::end",
            "execute_instruction",
            "execute_query",
            "query_execute_norito",
            "alloc",
            "grow_heap",
            "runtime::set_vector_length",
            "setvl",
            "debug_print",
            "debug_log",
            "debug::print_i64",
            "debug::log",
        ] {
            assert_eq!(Builtin::from_source_name(name), None, "{name}");
        }
    }
}
